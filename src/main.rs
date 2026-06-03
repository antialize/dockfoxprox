use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use reqwest::Client;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tasks::{RunToken, TaskBuilder, cancelable, run_tasks, shutdown};
use tower::{ServiceBuilder, service_fn};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{Instrument, debug, error, info, info_span, instrument};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod aligned_atomic;
mod config;
mod digest;
mod docker;
mod eviction;
mod metrics;
mod redis;
mod size;
mod snapshot;
mod state;

use docker::ProxyBody;
use state::State;

/// Build a tower layer that adds `name: value` to every response, unless the
/// handler already set that header.
fn static_header(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

/// Top-level router shared by the HTTP and HTTPS listeners. Routes:
///   * `/v2/...`  - Docker registry API (see `docker::handle_request`).
///   * `/metrics` - Prometheus text exposition of `state::Metrics`.
///   * anything else - 404.
#[instrument(skip_all, fields(method = %req.method(), uri = %req.uri(), version = ?req.version()))]
async fn handle(
    ctx: &'static State,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<ProxyBody>, std::convert::Infallible> {
    if req.uri().path().starts_with("/v2/") {
        docker::handle_request(ctx, req).await
    } else if req.uri().path() == "/metrics" {
        let body = metrics::render(ctx);
        let len = body.len();
        Ok(Response::builder()
            .status(hyper::StatusCode::OK)
            .header(
                hyper::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )
            .header(hyper::header::CONTENT_LENGTH, len)
            .body(Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed())
            .expect("build metrics response"))
    } else {
        Ok(Response::builder()
            .status(hyper::StatusCode::NOT_FOUND)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(
                Full::new(Bytes::from_static(b"not found"))
                    .map_err(|n| match n {})
                    .boxed(),
            )
            .expect("build 404 response"))
    }
}

/// Install the global tracing subscriber. `RUST_LOG` (if set) wins over the
/// `default_filter` derived from `--verbosity`.
fn init_tracing(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .init();
}

/// Build a rustls `ServerConfig` for the HTTPS listener. Currently always a
/// freshly generated self-signed `localhost` cert; clients must trust it (or
/// disable verification). ALPN advertises both h2 and http/1.1.
fn build_tls_config() -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| anyhow!("key error: {e}"))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Build the tower service stack (security response headers + the routing
/// handler) and run a single connection through hyper's auto HTTP/1+HTTP/2
/// switcher. Used by both the HTTPS and the plaintext HTTP listeners.
///
/// `tls` controls whether the HSTS header is attached - RFC 6797 §7.2
/// requires user agents to ignore `Strict-Transport-Security` received over
/// plain HTTP, so emitting it there is just noise.
async fn serve_connection<I>(ctx: &'static State, io: I, tls: bool)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = ServiceBuilder::new()
        .option_layer(if tls {
            Some(static_header(
                header::STRICT_TRANSPORT_SECURITY,
                "max-age=63072000; includeSubDomains",
            ))
        } else {
            None
        })
        .layer(static_header(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(static_header(header::X_FRAME_OPTIONS, "DENY"))
        .layer(static_header(header::REFERRER_POLICY, "no-referrer"))
        .layer(static_header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ))
        .layer(static_header(
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ))
        .layer(static_header(
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ))
        .layer(static_header(
            HeaderName::from_static("permissions-policy"),
            "accelerometer=(), camera=(), geolocation=(), microphone=()",
        ))
        .service(service_fn(move |req| handle(ctx, req)));
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(e) = builder
        .serve_connection(io, TowerToHyperService::new(svc))
        .await
    {
        error!(error = %e, "connection error");
    }
}

/// Plaintext HTTP accept loop. Each accepted connection is handed to a fresh
/// tokio task running `serve_connection`. Returns when `rt` is cancelled.
async fn serve_http(listener: TcpListener, ctx: &'static State, rt: RunToken) -> Result<()> {
    loop {
        let (tcp, peer) = match cancelable(&rt, listener.accept()).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                error!(error = %e, "http accept error");
                continue;
            }
            Err(_) => {
                info!("http server shutting down");
                break;
            }
        };
        let span = info_span!("http", %peer);
        tokio::spawn(
            async move {
                debug!("http tcp accepted");
                serve_connection(ctx, TokioIo::new(tcp), false).await;
            }
            .instrument(span),
        );
    }
    Ok(())
}

/// HTTPS accept loop. Performs the TLS handshake on the spawned per-connection
/// task (so a slow handshake can't block other clients) and then hands the
/// TLS stream to `serve_connection`. Returns when `rt` is cancelled.
async fn serve_https(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    ctx: &'static State,
    rt: RunToken,
) -> Result<()> {
    loop {
        let (tcp, peer) = match cancelable(&rt, listener.accept()).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                error!(error = %e, "accept error");
                continue;
            }
            Err(_) => {
                info!("https server shutting down");
                break;
            }
        };
        let acceptor = acceptor.clone();
        let span = info_span!("conn", %peer);
        tokio::spawn(
            async move {
                debug!("tcp accepted");
                let tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "tls handshake failed");
                        return;
                    }
                };
                let alpn = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .unwrap_or_else(|| "none".to_string());
                debug!(%alpn, "tls established");

                serve_connection(ctx, TokioIo::new(tls), true).await;
            }
            .instrument(span),
        );
    }

    Ok(())
}

/// Command-line arguments. Parsed by clap.
#[derive(clap::Parser)]
struct Args {
    #[clap(short, long, default_value = "config.toml")]
    config: String,

    /// Log verbosity. Overridden by the RUST_LOG environment variable.
    #[clap(short, long, value_enum, default_value_t = Verbosity::Info)]
    verbosity: Verbosity,
}

/// Logging verbosity selectable via `--verbosity`. `Debug` and `Trace` only
/// crank up our own crate so we don't drown in hyper/rustls noise.
#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum Verbosity {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Verbosity {
    /// Map the enum to an `EnvFilter` directive string.
    fn as_filter(self) -> &'static str {
        match self {
            Verbosity::Error => "error",
            Verbosity::Warn => "warn",
            Verbosity::Info => "info",
            Verbosity::Debug => "info,dockfoxprox=debug",
            Verbosity::Trace => "info,dockfoxprox=trace",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::try_parse()?;

    let config: config::Config = {
        let s = std::fs::read_to_string(&args.config)?;
        toml::from_str(&s)?
    };

    init_tracing(args.verbosity.as_filter());

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("failed to install rustls crypto provider"))?;

    let client = Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .connect_timeout(Duration::from_secs(15))
        .pool_idle_timeout(Some(Duration::from_secs(60)))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let ctx = State::new(config, client);

    // Try to repopulate from the previous run's snapshot. On any failure the
    // on-disk blob cache is wiped - those files are useless without the
    // metadata that points at them.
    snapshot::load_or_wipe(ctx).await?;

    TaskBuilder::new("eviction loop")
        .main()
        .create(|rt| eviction::evict_loop(ctx, rt));

    if let Some(port) = ctx.config.redis_port {
        let addr = format!("0.0.0.0:{port}");
        let listener = TcpListener::bind(&addr).await?;
        info!(%addr, "redis listening");
        TaskBuilder::new("redis server")
            .main()
            .create(|rt| redis::serve(ctx, listener, rt));
    }

    if let Some(port) = ctx.config.http_port {
        let http_addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        let http_listener = TcpListener::bind(http_addr).await?;
        info!(%http_addr, "http listening");
        TaskBuilder::new("http server")
            .main()
            .create(|rt| serve_http(http_listener, ctx, rt));
    }

    if let Some(port) = ctx.config.https_port {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        let listener = TcpListener::bind(addr).await?;
        let acceptor = TlsAcceptor::from(Arc::new(build_tls_config()?));
        info!(%addr, "https listening");
        TaskBuilder::new("https server")
            .main()
            .create(|rt| serve_https(listener, acceptor, ctx, rt));
    }

    tokio::spawn(async {
        tokio::signal::ctrl_c().await.unwrap();
        shutdown("ctrl+c".to_string());
    });

    tokio::spawn(async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap()
            .recv()
            .await;
        shutdown("terminate".to_string());
    });

    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);

    run_tasks().await;

    // All listeners and background tasks have shut down; the maps are quiet.
    // Safe to walk them and write the snapshot.
    if let Err(e) = snapshot::save(ctx).await {
        error!(error = %e, "failed to write snapshot");
    }

    Ok(())
}
