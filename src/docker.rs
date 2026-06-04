use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::task::{Context as TaskContext, Poll};

use crate::config::DockerRegistry;
use crate::digest::Digest;
use crate::state::{Blob, Manifest, State, TokenKey, Upload, UploadInner};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::{Body as HyperBody, Frame, Incoming};
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Method, Request, Response, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::{Mutex as TMutex, mpsc};
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;
pub type ProxyBody = BoxBody<Bytes, std::io::Error>;

#[derive(Error, Debug)]
enum DockerError {
    #[error("Invalid auth")]
    InvalidAuth,
    #[error("Not found")]
    NotFound,
    #[error("Invalid method: {0}")]
    MethodNotAllowed(Method),
    #[error("Invalid host: {0}")]
    InvalidHost(String),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Hyper HTTP error: {0}")]
    HyperHttp(#[from] hyper::http::Error),
    #[error("Upstream error: {0}")]
    Upstream(String),
}

/// Check the Authorization header against the configured users, if any.
fn check_auth(state: &'static State, req: &Request<Incoming>) -> Result<(), DockerError> {
    if state.config.docker_user.is_empty() {
        return Ok(());
    }
    let Some(auth) = req.headers().get(AUTHORIZATION) else {
        return Err(DockerError::InvalidAuth);
    };
    let auth = auth.to_str().map_err(|_| DockerError::InvalidAuth)?;
    let Some(basic) = auth.strip_prefix("Basic ") else {
        return Err(DockerError::InvalidAuth);
    };
    let decoded = STANDARD
        .decode(basic)
        .map_err(|_| DockerError::InvalidAuth)?;
    let decoded = String::from_utf8(decoded).map_err(|_| DockerError::InvalidAuth)?;
    let (username, password) = decoded.split_once(':').ok_or(DockerError::InvalidAuth)?;
    for user in &state.config.docker_user {
        let u_match = user.username.as_bytes().ct_eq(username.as_bytes());
        let p_match = user.password.as_bytes().ct_eq(password.as_bytes());
        if bool::from(u_match & p_match) {
            return Ok(());
        }
    }
    state
        .metrics
        .docker_auth_failures
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Err(DockerError::InvalidAuth)
}

/// Top-level Docker v2 dispatcher. Catches every `DockerError`, logs it, and
/// maps it to the appropriate HTTP status - the surrounding hyper service
/// never sees an error.
#[instrument(skip_all, fields(method = %req.method(), uri = %req.uri()))]
pub async fn handle_request(
    state: &'static State,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, Infallible> {
    let is_head = req.method() == Method::HEAD;
    match handle_request_inner(state, req).await {
        Ok(r) => Ok(r),
        Err(e) => match e {
            DockerError::InvalidAuth => {
                warn!(error = %e, "invalid auth");
                let body = Full::new(Bytes::from_static(b"Unauthorized"))
                    .map_err(|never| match never {})
                    .boxed();
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header(WWW_AUTHENTICATE, "Basic realm=\"dockfoxprox\"")
                    .body(body)
                    .expect("static response"));
            }
            DockerError::NotFound => {
                if !is_head {
                    warn!(error = %e, "not found");
                }
                return Ok(error_response(StatusCode::NOT_FOUND, "Not found"));
            }
            DockerError::InvalidHost(_) => {
                warn!(error = %e, "invalid host");
                return Ok(error_response(StatusCode::BAD_REQUEST, "Invalid host"));
            }
            DockerError::Hyper(e) => {
                error!(error = %format!("{e:#}"), "hyper error");
                return Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                ));
            }
            DockerError::HyperHttp(e) => {
                error!(error = %format!("{e:#}"), "hyper HTTP error");
                return Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                ));
            }
            DockerError::Upstream(msg) => {
                error!(%msg, "upstream error");
                return Ok(error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"));
            }
            DockerError::MethodNotAllowed(method) => {
                error!(error = %format!("method not allowed: {}", method), "method not allowed");
                return Ok(error_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Method Not Allowed",
                ));
            }
        },
    }
}

/// Inner dispatcher. Parses the `/v2/<host>/<name>/<{manifests,blobs,blobs/uploads}>/<ref>`
/// shape and routes to the per-verb handler, bumping the matching metric.
/// Returns typed `DockerError`s which are translated to HTTP responses by
/// `handle_request`.
async fn handle_request_inner(
    state: &'static State,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, DockerError> {
    check_auth(state, &req)?;

    let path = req.uri().path();

    if path == "/v2" || path == "/v2/" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Distribution-Api-Version", "registry/2.0")
            .body(empty())?);
    }

    let Some(suffix) = path.strip_prefix("/v2/") else {
        return Err(DockerError::NotFound);
    };

    let (host, rest) = suffix.split_once('/').ok_or(DockerError::NotFound)?;
    if host.is_empty() || rest.is_empty() {
        return Err(DockerError::NotFound);
    }
    validate_host(host)?;
    let upstream_host = alias_host(state, host);

    let (rest, tail) = rest.rsplit_once('/').ok_or(DockerError::NotFound)?;
    let (rest, tag) = rest.rsplit_once('/').ok_or(DockerError::NotFound)?;

    if tag == "manifests" {
        let name = rest.to_string();
        let reference = tail.to_string();
        match *req.method() {
            Method::GET => {
                state
                    .metrics
                    .docker_manifest_get
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                get_head_manifest(state, req, upstream_host, name, reference, false).await
            }
            Method::HEAD => {
                state
                    .metrics
                    .docker_manifest_head
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                get_head_manifest(state, req, upstream_host, name, reference, true).await
            }
            Method::PUT => {
                state
                    .metrics
                    .docker_manifest_put
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                put_manifest(state, req, upstream_host, name, reference).await
            }
            _ => Err(DockerError::MethodNotAllowed(req.method().clone())),
        }
    } else if tag == "uploads" {
        let name = rest
            .strip_suffix("/blobs")
            .ok_or(DockerError::NotFound)?
            .to_string();
        let uuid_str = tail.to_string();
        match *req.method() {
            Method::POST => {
                state
                    .metrics
                    .docker_blob_upload_post
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                post_blob_upload(state, req, upstream_host, name).await
            }
            Method::PATCH => {
                state
                    .metrics
                    .docker_blob_upload_patch
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                patch_blob_upload(state, req, upstream_host, name, uuid_str).await
            }
            Method::PUT => {
                state
                    .metrics
                    .docker_blob_upload_put
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                put_blob_upload(state, req, upstream_host, name, uuid_str).await
            }
            Method::DELETE => {
                state
                    .metrics
                    .docker_blob_upload_delete
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                delete_blob_upload(state, upstream_host, name, uuid_str).await
            }
            Method::GET => get_blob_upload_status(state, upstream_host, name, uuid_str).await,
            _ => Err(DockerError::MethodNotAllowed(req.method().clone())),
        }
    } else if tag == "blobs" {
        let name = rest.to_string();
        let digest = tail.to_string();
        match *req.method() {
            Method::GET => {
                state
                    .metrics
                    .docker_blob_get
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                get_head_blob(state, req, upstream_host, name, digest, false).await
            }
            Method::HEAD => {
                state
                    .metrics
                    .docker_blob_head
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                get_head_blob(state, req, upstream_host, name, digest, true).await
            }
            _ => Err(DockerError::MethodNotAllowed(req.method().clone())),
        }
    } else {
        Err(DockerError::NotFound)
    }
}

/// GET/HEAD a manifest, serving from cache when possible. For a tag
/// reference we always HEAD upstream first to learn the current digest, so
/// `latest` and friends track the source registry. For a digest reference we
/// trust it and look up directly.
async fn get_head_manifest(
    state: &'static State,
    req: Request<Incoming>,
    upstream_host: String,
    name: String,
    reference: String,
    head: bool,
) -> Result<Response<ProxyBody>, DockerError> {
    use std::sync::atomic::Ordering;

    // Forward the client's Accept header so the registry returns the manifest
    // flavor the client actually understands (OCI index vs docker v2, etc).
    let accept = req
        .headers()
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Resolve `<reference>` to a content digest. If the client already gave us
    // a digest we trust it; otherwise it's a tag and we HEAD upstream to learn
    // the current digest for that tag (with the client's Accept honoured).
    let digest = match reference.parse::<Digest>() {
        Ok(d) => d,
        Err(_) => {
            if upstream_host == "self" {
                // Self host: no upstream - look up the tag locally.
                match state.tags.get(&(name.clone(), reference.clone())) {
                    Some(d) => d.clone(),
                    None => return Err(DockerError::NotFound),
                }
            } else {
                debug!(%name, %reference, "resolving tag via HEAD");
                let resp = upstream_pull_request(
                    state,
                    &upstream_host,
                    &name,
                    reqwest::Method::HEAD,
                    &format!("manifests/{reference}"),
                    accept.as_deref(),
                )
                .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = upstream_error_snippet(resp).await;
                    warn!(%status, %name, %reference, body = %body, "upstream HEAD failed");
                    return Ok(error_response(
                        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                        format!("upstream returned {status}"),
                    ));
                }
                let Some(d) = resp
                    .headers()
                    .get("docker-content-digest")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<Digest>().ok())
                else {
                    return Err(DockerError::Upstream(
                        "HEAD response missing Docker-Content-Digest".into(),
                    ));
                };
                d
            }
        }
    };

    // Cache hit: bump last_used and serve.
    if let Some(entry) = state.manifests.get(&digest) {
        let now = state.now.load(Ordering::Relaxed);
        entry.last_used.store(now, Ordering::Relaxed);
        state
            .metrics
            .docker_manifest_cache_hit
            .fetch_add(1, Ordering::Relaxed);
        debug!(%digest, "manifest cache hit");
        return Ok(serve_manifest(&entry, head, &digest));
    }

    if upstream_host == "self" {
        return Err(DockerError::NotFound);
    }

    // Cache miss: GET upstream by digest and store.
    state
        .metrics
        .docker_manifest_cache_miss
        .fetch_add(1, Ordering::Relaxed);
    debug!(%digest, "manifest cache miss");
    let resp = upstream_pull_request(
        state,
        &upstream_host,
        &name,
        reqwest::Method::GET,
        &format!("manifests/{digest}"),
        accept.as_deref(),
    )
    .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = upstream_error_snippet(resp).await;
        warn!(%status, %name, %digest, body = %body, "upstream manifest GET failed");
        return Ok(error_response(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("upstream returned {status}"),
        ));
    }
    let media_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = resp
        .bytes()
        .await
        .map_err(|e| DockerError::Upstream(format!("read manifest body: {e}")))?;

    let now = state.now.load(Ordering::Relaxed);
    let entry = Arc::new(Manifest {
        content: body,
        media_type,
        last_used: AtomicU64::new(now),
    });
    state.insert_manifest(digest.clone(), entry.clone());

    Ok(serve_manifest(&entry, head, &digest))
}

/// Build a 200 response wrapping a cached manifest.
fn serve_manifest(m: &Manifest, head: bool, digest: &Digest) -> Response<ProxyBody> {
    let body: ProxyBody = if head {
        empty()
    } else {
        Full::new(m.content.clone())
            .map_err(|never| match never {})
            .boxed()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", &m.media_type)
        .header("docker-content-digest", digest.to_string())
        .header("content-length", m.content.len().to_string())
        .body(body)
        .expect("build manifest response")
}

/// Send a pull request to upstream (manifest or blob), transparently handling
/// both Basic and Bearer auth:
///   * If `docker_registries` has credentials for this host, `Authorization:
///     Basic ...` is sent preemptively from the very first request.
///   * On 401 with a `WWW-Authenticate: Bearer ...` challenge we fetch a
///     token from the realm endpoint (using the basic creds as bootstrap if
///     configured), cache it under (registry, scope), and retry.
///   * Any other 401 - e.g. a `Basic` challenge we have no creds for - is
///     propagated to the caller.
///
/// `sub_path` is the part after `/v2/<name>/`, e.g. `manifests/latest` or
/// `blobs/sha256:…`.
async fn upstream_pull_request(
    state: &'static State,
    upstream_host: &str,
    name: &str,
    method: reqwest::Method,
    sub_path: &str,
    accept: Option<&str>,
) -> Result<reqwest::Response, DockerError> {
    let url = format!("https://{upstream_host}/v2/{name}/{sub_path}");
    let scope = format!("repository:{name}:pull");
    let token_key = TokenKey {
        registry: upstream_host.to_string(),
        scope: scope.clone(),
    };

    let basic_creds = registry_for_host(state, upstream_host).and_then(|r| {
        match (r.username.as_deref(), r.password.as_deref()) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        }
    });

    let mut token: Option<Arc<String>> = state.tokens.get(&token_key).map(|t| t.clone());
    let mut had_cached = token.is_some();

    for attempt in 0..3u32 {
        let auth_kind = if token.is_some() {
            "bearer"
        } else if basic_creds.is_some() {
            "basic"
        } else {
            "none"
        };
        debug!(%url, %method, attempt, auth = auth_kind, "upstream request");
        state
            .metrics
            .docker_upstream_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut rb = state.reqwest_client.request(method.clone(), &url);
        if let Some(a) = accept {
            rb = rb.header(reqwest::header::ACCEPT, a);
        }
        // Prefer a bearer token if we have one; otherwise fall back to
        // preemptive basic when creds are configured.
        if let Some(t) = &token {
            rb = rb.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        } else if let Some((u, p)) = basic_creds {
            rb = rb.header(reqwest::header::AUTHORIZATION, basic_auth_header(u, p));
        }
        let resp = rb.send().await.map_err(|e| {
            state
                .metrics
                .docker_upstream_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            DockerError::Upstream(format!("send to {upstream_host}: {e}"))
        })?;

        let status = resp.status();
        let www = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        debug!(%url, %status, www_authenticate = www.as_deref().unwrap_or(""), "upstream response");

        if status != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // The cached token didn't work - evict it and try the challenge flow.
        if had_cached {
            state.tokens.remove(&token_key);
            had_cached = false;
        }

        let Some(www) = www else {
            return Ok(resp);
        };
        // Only the bearer challenge triggers the token dance. A Basic
        // challenge we couldn't satisfy preemptively means the configured
        // creds (or lack thereof) are simply wrong - propagate the 401.
        let Some(ch) = parse_bearer_challenge(&www) else {
            return Ok(resp);
        };

        debug!(realm = %ch.realm, service = ch.service.as_deref().unwrap_or(""), scope = ch.scope.as_deref().unwrap_or(""), bootstrap_auth = basic_creds.is_some(), "fetching bearer token");
        let fresh = fetch_token(&state.reqwest_client, &ch, basic_creds).await?;
        let arc = Arc::new(fresh);
        state.tokens.insert(token_key.clone(), arc.clone());
        token = Some(arc);
    }

    Err(DockerError::Upstream("exceeded auth retry budget".into()))
}

/// A parsed `WWW-Authenticate: Bearer ...` challenge.
#[derive(Debug)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

/// Parse a `WWW-Authenticate: Bearer realm="...", service="...", scope="..."`
/// header. Returns `None` if the scheme isn't `Bearer` or if `realm` is
/// missing.
fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let rest = header.trim();
    let rest = rest
        .strip_prefix("Bearer")
        .or_else(|| rest.strip_prefix("bearer"))?
        .trim_start();
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for (k, v) in iter_challenge_params(rest) {
        match k.as_str() {
            "realm" => realm = Some(v),
            "service" => service = Some(v),
            "scope" => scope = Some(v),
            _ => {}
        }
    }
    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

/// Walk a `key=value` challenge parameter list, handling quoted strings and
/// backslash escapes. Returns `(lowercased_key, raw_value)` pairs in order.
fn iter_challenge_params(input: &str) -> Vec<(String, String)> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            break;
        }
        let k = input[key_start..i].trim().to_ascii_lowercase();
        i += 1;
        let v = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let v = input[start..i].to_string();
            if i < bytes.len() {
                i += 1;
            }
            v
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            input[start..i].trim().to_string()
        };
        out.push((k, v));
    }
    out
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

/// Exchange a bearer challenge for an access token by GETting the realm URL
/// with `service` and `scope` appended. `basic_creds` are sent as
/// `Authorization: Basic` to bootstrap private-registry token issuance.
async fn fetch_token(
    client: &Client,
    ch: &BearerChallenge,
    basic_creds: Option<(&str, &str)>,
) -> Result<String, DockerError> {
    let mut url = ch.realm.clone();
    let mut sep = if url.contains('?') { '&' } else { '?' };
    if let Some(s) = &ch.service {
        url.push(sep);
        url.push_str("service=");
        url.push_str(&urlencode(s));
        sep = '&';
    }
    if let Some(s) = &ch.scope {
        url.push(sep);
        url.push_str("scope=");
        url.push_str(&urlencode(s));
    }
    let mut rb = client.get(&url);
    if let Some((u, p)) = basic_creds {
        rb = rb.header(reqwest::header::AUTHORIZATION, basic_auth_header(u, p));
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| DockerError::Upstream(format!("token request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(DockerError::Upstream(format!(
            "token endpoint {status}: {body}"
        )));
    }
    let parsed: TokenResponse = resp
        .json()
        .await
        .map_err(|e| DockerError::Upstream(format!("decode token response: {e}")))?;
    parsed
        .token
        .or(parsed.access_token)
        .ok_or_else(|| DockerError::Upstream("token response missing token field".into()))
}

/// Percent-encode everything that isn't ASCII alphanumeric.
fn urlencode(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Drain a request body into a single `Vec<u8>`. Everything is kept in memory
/// for now - per the design, the cache is the only storage tier.
async fn read_body(req: Request<Incoming>) -> Result<Vec<u8>, DockerError> {
    let collected = req
        .into_body()
        .collect()
        .await
        .map_err(|e| DockerError::Upstream(format!("read body: {e}")))?;
    Ok(collected.to_bytes().to_vec())
}

/// Guard for write endpoints: only the in-process `self` registry accepts
/// PUT/PATCH/POST. Pull-through caches are read-only towards their upstream.
fn ensure_self(upstream_host: &str, method: &Method) -> Result<(), DockerError> {
    if upstream_host != "self" {
        // Push to upstream registries is not supported - we are a pull-through
        // cache for everything except the `self` namespace.
        return Err(DockerError::MethodNotAllowed(method.clone()));
    }
    Ok(())
}

/// Parse the `digest=<sha256:...>` query parameter from a URI.
fn digest_from_query(req: &Request<Incoming>) -> Option<String> {
    let q = req.uri().query()?;
    for kv in q.split('&') {
        if let Some(v) = kv.strip_prefix("digest=") {
            return Some(urldecode(v));
        }
    }
    None
}

/// Percent-decode a URI component (lossy on invalid UTF-8).
fn urldecode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// PUT /v2/self/<name>/manifests/<reference> - store a manifest by digest and
/// (if `<reference>` is a tag) also map the tag to the manifest digest.
async fn put_manifest(
    state: &'static State,
    req: Request<Incoming>,
    upstream_host: String,
    name: String,
    reference: String,
) -> Result<Response<ProxyBody>, DockerError> {
    ensure_self(&upstream_host, req.method())?;

    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    let body = read_body(req).await?;
    let hash = Sha256::digest(&body);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&hash);
    let digest = Digest(digest_bytes);

    let now = state.now.load(std::sync::atomic::Ordering::Relaxed);
    let manifest = Arc::new(Manifest {
        content: Bytes::from(body),
        media_type: content_type,
        last_used: AtomicU64::new(now),
    });
    let len = manifest.content.len();
    state.insert_manifest(digest.clone(), manifest);

    // If the reference is a tag (not itself a digest), record the mapping.
    if reference.parse::<Digest>().is_err() {
        state
            .tags
            .insert((name.clone(), reference.clone()), digest.clone());
    }
    // Always allow lookup by digest too.
    state
        .tags
        .insert((name.clone(), digest.to_string()), digest.clone());

    info!(%name, %reference, %digest, bytes = len, "manifest stored");

    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/self/{name}/manifests/{digest}"))
        .header("Docker-Content-Digest", digest.to_string())
        .header("Content-Length", "0")
        .body(empty())
        .map_err(Into::into)
}

/// POST /v2/self/<name>/blobs/uploads/ - initiate a resumable upload, or, if
/// `?digest=...` is set, accept the body as a single-shot mono-chunk upload.
async fn post_blob_upload(
    state: &'static State,
    req: Request<Incoming>,
    upstream_host: String,
    name: String,
) -> Result<Response<ProxyBody>, DockerError> {
    ensure_self(&upstream_host, req.method())?;

    // Single-shot variant: body is the full blob, digest is in the query.
    if let Some(digest_str) = digest_from_query(&req) {
        let Ok(expected) = digest_str.parse::<Digest>() else {
            return Ok(error_response(StatusCode::BAD_REQUEST, "invalid digest"));
        };
        let body = read_body(req).await?;
        let hash = Sha256::digest(&body);
        let mut got_bytes = [0u8; 32];
        got_bytes.copy_from_slice(&hash);
        let got = Digest(got_bytes);
        if got != expected {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                format!("digest mismatch: expected {expected} got {got}"),
            ));
        }
        let media_type = "application/octet-stream".to_string();
        let now = state.now.load(std::sync::atomic::Ordering::Relaxed);
        let blob = Arc::new(Blob::InMemory {
            content: Bytes::from(body),
            media_type,
            last_accessed: AtomicU64::new(now),
            id: state
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        });
        state.insert_blob(got.clone(), blob);
        info!(%name, digest = %got, "blob stored (single-shot)");
        return Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", format!("/v2/self/{name}/blobs/{got}"))
            .header("Docker-Content-Digest", got.to_string())
            .header("Content-Length", "0")
            .body(empty())
            .map_err(Into::into);
    }

    // Resumable: hand out a uuid and create empty upload state.
    let uuid = Uuid::new_v4();
    state.uploads.insert(
        uuid,
        Arc::new(Upload {
            inner: TMutex::new(UploadInner {
                buf: Vec::new(),
                hasher: Sha256::new(),
            }),
        }),
    );
    debug!(%name, %uuid, "blob upload created");

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", format!("/v2/self/{name}/blobs/uploads/{uuid}"))
        .header("Range", "0-0")
        .header("Content-Length", "0")
        .header("Docker-Upload-UUID", uuid.to_string())
        .body(empty())
        .map_err(Into::into)
}

/// PATCH /v2/self/<name>/blobs/uploads/<uuid> - append a chunk to a resumable
/// upload.
async fn patch_blob_upload(
    state: &'static State,
    req: Request<Incoming>,
    upstream_host: String,
    name: String,
    uuid_str: String,
) -> Result<Response<ProxyBody>, DockerError> {
    ensure_self(&upstream_host, req.method())?;

    let Ok(uuid) = Uuid::parse_str(&uuid_str) else {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid upload id"));
    };
    let Some(upload) = state.uploads.get(&uuid).map(|v| v.clone()) else {
        return Ok(error_response(StatusCode::NOT_FOUND, "unknown upload"));
    };

    let chunk = read_body(req).await?;
    let mut inner = upload.inner.lock().await;
    inner.hasher.update(&chunk);
    inner.buf.extend_from_slice(&chunk);
    let end = inner.buf.len();
    debug!(%name, %uuid, chunk = chunk.len(), total = end, "blob upload chunk");

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", format!("/v2/self/{name}/blobs/uploads/{uuid}"))
        .header("Range", format!("0-{}", end.saturating_sub(1)))
        .header("Content-Length", "0")
        .header("Docker-Upload-UUID", uuid.to_string())
        .body(empty())
        .map_err(Into::into)
}

/// PUT /v2/self/<name>/blobs/uploads/<uuid>?digest=... - finalize a resumable
/// upload, optionally with one last body chunk appended.
async fn put_blob_upload(
    state: &'static State,
    req: Request<Incoming>,
    upstream_host: String,
    name: String,
    uuid_str: String,
) -> Result<Response<ProxyBody>, DockerError> {
    ensure_self(&upstream_host, req.method())?;

    let Ok(uuid) = Uuid::parse_str(&uuid_str) else {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid upload id"));
    };
    let Some(expected_str) = digest_from_query(&req) else {
        return Ok(error_response(StatusCode::BAD_REQUEST, "missing ?digest"));
    };
    let Ok(expected) = expected_str.parse::<Digest>() else {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid digest"));
    };

    // Peek the upload without removing it - a digest mismatch must leave the
    // upload state intact so the client can PATCH more bytes and retry.
    let Some(upload) = state.uploads.get(&uuid).map(|v| v.clone()) else {
        return Ok(error_response(StatusCode::NOT_FOUND, "unknown upload"));
    };

    let chunk = read_body(req).await?;
    let mut inner = upload.inner.lock().await;
    if !chunk.is_empty() {
        inner.hasher.update(&chunk);
        inner.buf.extend_from_slice(&chunk);
    }
    let hash = inner.hasher.clone().finalize();
    let mut got_bytes = [0u8; 32];
    got_bytes.copy_from_slice(&hash);
    let got = Digest(got_bytes);
    if got != expected {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            format!("digest mismatch: expected {expected} got {got}"),
        ));
    }

    // Hash matches - now it's safe to consume the upload state.
    let buf = std::mem::take(&mut inner.buf);
    let size = buf.len();
    drop(inner);
    state.uploads.remove(&uuid);
    let now = state.now.load(std::sync::atomic::Ordering::Relaxed);
    let blob = Arc::new(Blob::InMemory {
        content: Bytes::from(buf),
        media_type: "application/octet-stream".to_string(),
        last_accessed: AtomicU64::new(now),
        id: state
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    });
    state.insert_blob(got.clone(), blob);
    info!(%name, %uuid, digest = %got, bytes = size, "blob stored (resumable)");

    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/self/{name}/blobs/{got}"))
        .header("Docker-Content-Digest", got.to_string())
        .header("Content-Length", "0")
        .body(empty())
        .map_err(Into::into)
}

/// GET /v2/self/<name>/blobs/uploads/<uuid> - report current upload offset.
async fn get_blob_upload_status(
    state: &'static State,
    upstream_host: String,
    name: String,
    uuid_str: String,
) -> Result<Response<ProxyBody>, DockerError> {
    ensure_self(&upstream_host, &Method::GET)?;

    let Ok(uuid) = Uuid::parse_str(&uuid_str) else {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid upload id"));
    };
    let Some(upload) = state.uploads.get(&uuid).map(|v| v.clone()) else {
        return Ok(error_response(StatusCode::NOT_FOUND, "unknown upload"));
    };
    let end = upload.inner.lock().await.buf.len();

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Location", format!("/v2/self/{name}/blobs/uploads/{uuid}"))
        .header("Range", format!("0-{}", end.saturating_sub(1)))
        .header("Docker-Upload-UUID", uuid.to_string())
        .body(empty())
        .map_err(Into::into)
}

/// DELETE /v2/self/<name>/blobs/uploads/<uuid> - cancel a resumable upload.
/// Per the OCI distribution spec this returns 204 No Content; clients such as
/// buildah call it after a HEAD hit on the target blob or on any error path.
async fn delete_blob_upload(
    state: &'static State,
    upstream_host: String,
    name: String,
    uuid_str: String,
) -> Result<Response<ProxyBody>, DockerError> {
    ensure_self(&upstream_host, &Method::DELETE)?;

    let Ok(uuid) = Uuid::parse_str(&uuid_str) else {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid upload id"));
    };
    let removed = state.uploads.remove(&uuid).is_some();
    debug!(%name, %uuid, removed, "blob upload cancelled");

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Content-Length", "0")
        .body(empty())
        .map_err(Into::into)
}

/// GET/HEAD a blob. Cache layout: in-memory (served directly), on-disk
/// (streamed from the file), or miss (streamed from upstream while a parallel
/// task fills the cache).
async fn get_head_blob(
    state: &'static State,
    _req: Request<Incoming>,
    upstream_host: String,
    name: String,
    digest: String,
    head: bool,
) -> Result<Response<ProxyBody>, DockerError> {
    let Ok(d) = digest.parse::<Digest>() else {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid digest"));
    };

    // Cache hit.
    if let Some(entry) = state.blobs.get(&d) {
        let now = state.now.load(std::sync::atomic::Ordering::Relaxed);
        entry
            .last_accessed()
            .store(now, std::sync::atomic::Ordering::Relaxed);
        match entry.as_ref() {
            Blob::InMemory {
                content,
                media_type,
                ..
            } => {
                state
                    .metrics
                    .docker_blob_cache_hit_memory
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(digest = %d, "blob cache hit (mem)");
                return Ok(serve_blob_bytes(content.clone(), media_type, &d, head));
            }
            Blob::OnDisk {
                size,
                media_type,
                id,
                ..
            } => {
                state
                    .metrics
                    .docker_blob_cache_hit_disk
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(digest = %d, "blob cache hit (disk)");
                return serve_disk_blob(state, &d, *id, *size, media_type.clone(), head).await;
            }
        }
    }

    if upstream_host == "self" {
        return Err(DockerError::NotFound);
    }

    state
        .metrics
        .docker_blob_cache_miss
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // HEAD on a cache miss: ask upstream HEAD only, return its headers. We
    // deliberately do not trigger a body fetch - clients use HEAD to probe
    // existence, not to warm the cache.
    if head {
        debug!(digest = %d, %name, "blob HEAD miss → upstream HEAD");
        let resp = upstream_pull_request(
            state,
            &upstream_host,
            &name,
            reqwest::Method::HEAD,
            &format!("blobs/{d}"),
            None,
        )
        .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = upstream_error_snippet(resp).await;
            warn!(%status, %name, digest = %d, body = %body, "upstream blob HEAD failed");
            return Ok(error_response(
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                format!("upstream returned {status}"),
            ));
        }
        let media_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let content_length = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0")
            .to_string();
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", media_type)
            .header("docker-content-digest", d.to_string())
            .header("content-length", content_length)
            .body(empty())
            .expect("build blob HEAD response"));
    }

    // GET on a cache miss: pull from upstream, streaming the body to the
    // client while a background task simultaneously fills an in-memory buffer
    // which is inserted into the cache on successful completion. A client
    // disconnect does not abort the fill task - we keep draining upstream so
    // the cache still gets populated.
    debug!(digest = %d, %name, "blob cache miss");
    let resp = upstream_pull_request(
        state,
        &upstream_host,
        &name,
        reqwest::Method::GET,
        &format!("blobs/{d}"),
        None,
    )
    .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = upstream_error_snippet(resp).await;
        warn!(%status, %name, digest = %d, body = %body, "upstream blob fetch failed");
        return Ok(error_response(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("upstream returned {status}"),
        ));
    }
    let media_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let content_length = resp
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let body = spawn_blob_fill(state, d.clone(), media_type.clone(), resp);

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", &media_type)
        .header("docker-content-digest", d.to_string());
    if let Some(len) = content_length {
        builder = builder.header("content-length", len.to_string());
    }
    Ok(builder.body(body).expect("build blob response"))
}

/// Body backed by a tokio mpsc channel. A spawned task pushes `Result<Bytes, _>`
/// frames into the sender; this body polls the receiver. Dropping the body
/// (e.g. client disconnect) drops the receiver - the sender side observes a
/// closed channel via its `send` error and can choose to stop talking to the
/// client while continuing to do background work (cache fill).
struct StreamingBody {
    rx: mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl HyperBody for StreamingBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        this.rx
            .poll_recv(cx)
            .map(|opt| opt.map(|res| res.map(Frame::data)))
    }
}

/// Spawn a task that streams the upstream response body into both the client
/// (via an mpsc-backed `StreamingBody`) and an in-memory buffer that lands in
/// the cache on successful completion. Returns the body to hand to hyper.
///
/// Concurrent misses for the same digest are not coalesced - each request
/// spawns its own fill task and races to `state.blobs.insert(...)`. Last writer
/// wins; both copies of the bytes are byte-identical so it doesn't matter.
fn spawn_blob_fill(
    state: &'static State,
    digest: Digest,
    media_type: String,
    resp: reqwest::Response,
) -> ProxyBody {
    // Bounded channel gives us backpressure: a slow client slows the upstream
    // pull (via `send().await`) instead of letting `buf` balloon unboundedly.
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);

    let content_length_hint = resp
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::with_capacity(content_length_hint);
        let mut hasher = Sha256::new();
        let mut stream = resp.bytes_stream();
        let mut client_alive = true;

        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    hasher.update(&chunk);
                    buf.extend_from_slice(&chunk);
                    if client_alive && tx.send(Ok(chunk)).await.is_err() {
                        // Client gone - keep draining upstream for the cache.
                        client_alive = false;
                        debug!(
                            %digest,
                            "client disconnected; continuing fill for cache"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        %digest,
                        error = %e,
                        "upstream blob stream error; aborting fill"
                    );
                    if client_alive {
                        let _ = tx.send(Err(std::io::Error::other(e))).await;
                    }
                    return; // do NOT cache a partial body
                }
            }
        }

        // Stream completed cleanly. Drop tx so the client side sees EOF.
        drop(tx);

        // Verify the bytes we just streamed actually hash to the digest the
        // client asked for. A mismatched body must never enter the cache -
        // we'd serve it to every future request without rechecking.
        let hash = hasher.finalize();
        let mut got_bytes = [0u8; 32];
        got_bytes.copy_from_slice(&hash);
        let got = Digest(got_bytes);
        if got != digest {
            warn!(
                expected = %digest,
                %got,
                bytes = buf.len(),
                "upstream blob digest mismatch; not caching"
            );
            return;
        }

        debug!(
            %digest,
            bytes = buf.len(),
            "blob fill complete; inserting into cache"
        );
        let now = state.now.load(std::sync::atomic::Ordering::Relaxed);
        state.insert_blob(
            digest,
            Arc::new(Blob::InMemory {
                content: Bytes::from(buf),
                media_type,
                last_accessed: AtomicU64::new(now),
                id: state
                    .next_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            }),
        );
    });

    StreamingBody { rx }.boxed()
}

/// Stream an on-disk blob to the client via the `StreamingBody` mpsc plumbing.
async fn serve_disk_blob(
    state: &'static State,
    digest: &Digest,
    id: u64,
    size: u64,
    media_type: String,
    head: bool,
) -> Result<Response<ProxyBody>, DockerError> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", &media_type)
        .header("docker-content-digest", digest.to_string())
        .header("content-length", size.to_string());

    if head {
        return Ok(builder.body(empty()).expect("build blob HEAD response"));
    }

    let path = state.cache_path(id);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            error!(%digest, path=%path.display(), error=%e, "missing on-disk blob; cache inconsistent");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "blob unavailable",
            ));
        }
    };

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    let digest_for_task = digest.clone();
    tokio::spawn(async move {
        let mut stream = ReaderStream::new(file);
        while let Some(item) = stream.next().await {
            match item {
                Ok(bytes) => {
                    if tx.send(Ok(bytes)).await.is_err() {
                        debug!(digest=%digest_for_task, "client disconnected during disk blob read");
                        return;
                    }
                }
                Err(e) => {
                    warn!(digest=%digest_for_task, error=%e, "disk read error");
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    });

    Ok(builder
        .body(StreamingBody { rx }.boxed())
        .expect("build disk blob response"))
}

/// Build a 200 response wrapping an in-memory blob body.
fn serve_blob_bytes(
    content: Bytes,
    media_type: &str,
    digest: &Digest,
    head: bool,
) -> Response<ProxyBody> {
    let len = content.len();
    let body: ProxyBody = if head {
        empty()
    } else {
        Full::new(content).map_err(|never| match never {}).boxed()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", media_type)
        .header("docker-content-digest", digest.to_string())
        .header("content-length", len.to_string())
        .body(body)
        .expect("build blob response")
}

/// Reject URI-path "hosts" containing characters that would let a client
/// smuggle path components, credentials, or whitespace into the upstream URL.
fn validate_host(host: &str) -> Result<(), DockerError> {
    if host.contains('/') || host.contains('@') || host.contains(' ') {
        return Err(DockerError::InvalidHost(host.to_string()));
    }
    Ok(())
}

/// Resolve the URL-path host segment to a real upstream hostname.
///
/// Order: `self` is reserved for the in-process registry, then configured
/// `docker_registries` aliases (keyed by alias name), then the built-in
/// `docker.io` shortcut, then the host is used verbatim.
fn alias_host(state: &State, host: &str) -> String {
    if host == "self" {
        return "self".to_string();
    }
    if let Some(reg) = state.config.docker_registry.get(host) {
        return reg.url.clone();
    }
    match host {
        "docker.io" | "index.docker.io" => "registry-1.docker.io".to_string(),
        other => other.to_string(),
    }
}

/// Find configured credentials for an upstream by its resolved hostname.
/// Matches against `DockerRegistry.url`, so creds attached to the `sadmin`
/// alias also apply when something hits `sadmin.scalgo.com` directly.
fn registry_for_host<'a>(state: &'a State, host: &str) -> Option<&'a DockerRegistry> {
    state
        .config
        .docker_registry
        .values()
        .find(|r| r.url == host)
}

/// Format an `Authorization: Basic` header value from a username/password pair.
fn basic_auth_header(user: &str, pass: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
}

/// An empty `ProxyBody` for HEAD responses and bodyless successes.
fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Plain-text error response with the given status and body.
fn error_response(status: StatusCode, msg: impl Into<String>) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(msg.into()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(body)
        .expect("static response")
}

/// Consume an upstream error response and return its body as a short string
/// suitable for logging. Truncated to keep log lines bounded; whitespace is
/// collapsed so multi-line JSON errors print on one line.
async fn upstream_error_snippet(resp: reqwest::Response) -> String {
    const MAX: usize = 512;
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return format!("<body read error: {e}>"),
    };
    let mut compact = String::with_capacity(text.len().min(MAX));
    let mut last_ws = false;
    for c in text.chars() {
        if c.is_whitespace() {
            if !last_ws {
                compact.push(' ');
                last_ws = true;
            }
        } else {
            compact.push(c);
            last_ws = false;
        }
        if compact.len() >= MAX {
            compact.push('\u{2026}');
            break;
        }
    }
    compact.trim().to_string()
}
