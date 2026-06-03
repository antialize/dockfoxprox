//! Minimal RESP (Redis Serialization Protocol) server. Implements only the
//! commands that ccache's redis backend (and similar simple clients) exercise:
//! PING, AUTH, GET, SET, DEL, EXISTS, FLUSHDB/FLUSHALL, SELECT, CLIENT, INFO,
//! HELLO (rejected so the client falls back to RESP2), COMMAND, QUIT. Anything
//! else returns -ERR. Entries are kept in `State::redis_entries` and counted
//! against the same memory budget as docker blobs/manifests.
use anyhow::Result;
use std::io;
use std::sync::atomic::Ordering::Relaxed;

use bytes::Bytes;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio_tasks::{RunToken, TaskBuilder, cancelable};
use tracing::{Instrument, debug, error, info, info_span, trace, warn};

use crate::state::State;

/// Accept loop for the Redis-protocol server. Each accepted connection is
/// handed to an aborting per-connection task. Returns when `rt` is cancelled.
pub async fn serve(state: &'static State, listener: TcpListener, rt: RunToken) -> Result<()> {
    loop {
        let (sock, peer) = match cancelable(&rt, listener.accept()).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                error!(error = %e, "redis accept error");
                continue;
            }
            Err(_) => {
                info!("redis server shutting down");
                break;
            }
        };
        let span = info_span!("redis", %peer);
        state.metrics.redis_connections.fetch_add(1, Relaxed);

        TaskBuilder::new("redis_connection").abort().create(|_| {
            async move {
                debug!("redis tcp accepted");
                if let Err(e) = handle_conn(state, sock).await
                    && e.kind() != std::io::ErrorKind::UnexpectedEof
                    && e.kind() != std::io::ErrorKind::ConnectionReset
                {
                    warn!(error = %e, "redis connection error");
                }
                Ok::<(), io::Error>(())
            }
            .instrument(span)
        });
    }
    Ok(())
}

/// Per-connection RESP loop. Reads one command at a time, dispatches on the
/// (uppercased) verb, and writes the RESP-encoded reply. Disconnects on EOF or
/// protocol error.
async fn handle_conn(state: &'static State, sock: TcpStream) -> io::Result<()> {
    sock.set_nodelay(true).ok();
    let (r, w) = sock.into_split();
    let mut r = BufReader::with_capacity(64 * 1024, r);
    let mut w = BufWriter::with_capacity(64 * 1024, w);
    let mut authed = state.config.redis_password.is_none();

    while let Some(args) = read_command(&mut r).await? {
        if args.is_empty() {
            continue;
        }
        let cmd = std::str::from_utf8(&args[0])
            .unwrap_or("")
            .to_ascii_uppercase();
        // Log the command, arg count, and (for keyed ops) the key + value size.
        // Values themselves aren't logged - ccache payloads are binary object
        // files and would just spam.
        let key_field = match cmd.as_str() {
            "GET" | "SET" | "DEL" | "UNLINK" | "EXISTS" if args.len() >= 2 => {
                Some(String::from_utf8_lossy(&args[1]).into_owned())
            }
            _ => None,
        };
        let value_len: Option<usize> = if cmd == "SET" && args.len() >= 3 {
            Some(args[2].len())
        } else {
            None
        };
        trace!(
            command = %cmd,
            argc = args.len(),
            key = key_field.as_deref().unwrap_or(""),
            value_bytes = value_len.unwrap_or(0),
            "redis command"
        );
        state.metrics.redis_commands.fetch_add(1, Relaxed);
        match cmd.as_str() {
            "PING" => {
                if args.len() >= 2 {
                    write_bulk(&mut w, &args[1]).await?;
                } else {
                    write_simple(&mut w, "PONG").await?;
                }
            }
            "QUIT" => {
                write_simple(&mut w, "OK").await?;
                w.flush().await?;
                return Ok(());
            }
            // We don't speak RESP3; force the client to downgrade.
            "HELLO" => write_error(&mut w, "ERR NOPROTO unsupported protocol").await?,
            "COMMAND" => w.write_all(b"*0\r\n").await?,
            "AUTH" => {
                let expected = state.config.redis_password.as_deref();
                let given: &[u8] = match args.len() {
                    2 => &args[1],
                    // AUTH <user> <password> - ignore the username.
                    3 => &args[2],
                    _ => {
                        write_error(&mut w, "ERR wrong number of arguments for 'auth'").await?;
                        w.flush().await?;
                        continue;
                    }
                };
                match expected {
                    None => {
                        write_error(&mut w, "ERR Client sent AUTH, but no password is set").await?;
                    }
                    Some(p) if bool::from(given.ct_eq(p.as_bytes())) => {
                        authed = true;
                        debug!("redis auth ok");
                        write_simple(&mut w, "OK").await?;
                    }
                    Some(_) => {
                        warn!("redis auth failed");
                        state.metrics.redis_auth_failures.fetch_add(1, Relaxed);
                        write_error(&mut w, "WRONGPASS invalid username-password pair").await?;
                    }
                }
            }
            _ if !authed => {
                warn!(command = %cmd, "redis command rejected: not authenticated");
                write_error(&mut w, "NOAUTH Authentication required.").await?;
            }
            "GET" => {
                if args.len() != 2 {
                    write_error(&mut w, "ERR wrong number of arguments for 'get'").await?;
                } else {
                    let key: &[u8] = &args[1];
                    let now = state.now.load(Relaxed);
                    let hit = state.redis_entries.get(key).map(|e| {
                        e.value().last_accessed.store(now, Relaxed);
                        e.value().value.clone()
                    });
                    match hit {
                        Some(v) => {
                            state.metrics.redis_get_hit.fetch_add(1, Relaxed);
                            debug!(key = %String::from_utf8_lossy(key), bytes = v.len(), "redis GET hit");
                            write_bulk(&mut w, &v).await?;
                        }
                        None => {
                            state.metrics.redis_get_miss.fetch_add(1, Relaxed);
                            debug!(key = %String::from_utf8_lossy(key), "redis GET miss");
                            w.write_all(b"$-1\r\n").await?;
                        }
                    }
                }
            }
            "SET" => {
                // We deliberately ignore optional flags (EX/PX/NX/XX/KEEPTTL):
                // this cache has no TTL concept; eviction is LRU on the shared
                // memory budget.
                if args.len() < 3 {
                    write_error(&mut w, "ERR wrong number of arguments for 'set'").await?;
                } else {
                    let key_dbg = String::from_utf8_lossy(&args[1]).into_owned();
                    let val_len = args[2].len();
                    state.insert_redis(args[1].clone(), args[2].clone());
                    state.metrics.redis_set.fetch_add(1, Relaxed);
                    debug!(key = %key_dbg, bytes = val_len, "redis SET");
                    write_simple(&mut w, "OK").await?;
                }
            }
            "DEL" | "UNLINK" => {
                let mut n: i64 = 0;
                for k in &args[1..] {
                    if state.remove_redis(k) {
                        n += 1;
                    }
                }
                state.metrics.redis_del.fetch_add(n as u64, Relaxed);
                debug!(removed = n, requested = args.len() - 1, "redis DEL");
                write_integer(&mut w, n).await?;
            }
            "EXISTS" => {
                let mut n: i64 = 0;
                for k in &args[1..] {
                    if state.redis_entries.contains_key(k.as_ref()) {
                        n += 1;
                    }
                }
                write_integer(&mut w, n).await?;
            }
            "FLUSHDB" | "FLUSHALL" => {
                let before = state.redis_entries.len();
                state.flush_redis();
                info!(removed = before, "redis FLUSH");
                write_simple(&mut w, "OK").await?;
            }
            // Single logical DB; accept and ignore.
            "SELECT" | "CLIENT" => write_simple(&mut w, "OK").await?,
            "INFO" => write_bulk(&mut w, b"").await?,
            "DBSIZE" => write_integer(&mut w, state.redis_entries.len() as i64).await?,
            other => {
                debug!(command = %other, "redis unknown command");
                write_error(&mut w, &format!("ERR unknown command '{other}'")).await?;
            }
        }
        w.flush().await?;
    }
    debug!("redis connection closed");
    Ok(())
}

/// Read a single RESP command - either an array of bulk strings (`*N\r\n...`)
/// or an inline whitespace-separated command (used by telnet-style clients).
/// Returns `Ok(None)` on clean EOF.
async fn read_command<R: AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<Bytes>>> {
    let Some(line) = read_header_line(r).await? else {
        return Ok(None);
    };
    if line.is_empty() {
        return Ok(Some(Vec::new()));
    }
    if line[0] != b'*' {
        // Inline command: whitespace-separated tokens. Useful for `PING` over telnet.
        let s = std::str::from_utf8(&line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad inline command"))?;
        return Ok(Some(
            s.split_whitespace()
                .map(|p| Bytes::copy_from_slice(p.as_bytes()))
                .collect(),
        ));
    }
    let n = parse_len(&line[1..])?;
    let mut args = Vec::with_capacity(n);
    for _ in 0..n {
        let Some(h) = read_header_line(r).await? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof inside array",
            ));
        };
        if h.first() != Some(&b'$') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected bulk string",
            ));
        }
        let len = parse_len(&h[1..])?;
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).await?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing CRLF after bulk",
            ));
        }
        args.push(Bytes::from(buf));
    }
    Ok(Some(args))
}

/// Parse the integer payload of a RESP length prefix (`$N` or `*N`).
fn parse_len(b: &[u8]) -> io::Result<usize> {
    std::str::from_utf8(b)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad length prefix"))
}

/// Read one CRLF-terminated header line (e.g. `*3` or `$5`). Returns
/// `Ok(None)` on clean EOF, error if the framing is malformed.
async fn read_header_line<R: AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(32);
    let n = r.read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no newline"));
    }
    if buf.len() < 2 || buf[buf.len() - 2] != b'\r' {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad CRLF"));
    }
    buf.truncate(buf.len() - 2);
    Ok(Some(buf))
}

/// Write a RESP simple string (`+OK\r\n`).
async fn write_simple<W: AsyncWriteExt + Unpin>(w: &mut W, s: &str) -> io::Result<()> {
    w.write_all(b"+").await?;
    w.write_all(s.as_bytes()).await?;
    w.write_all(b"\r\n").await
}

/// Write a RESP error string (`-ERR ...\r\n`).
async fn write_error<W: AsyncWriteExt + Unpin>(w: &mut W, s: &str) -> io::Result<()> {
    w.write_all(b"-").await?;
    w.write_all(s.as_bytes()).await?;
    w.write_all(b"\r\n").await
}

/// Write a RESP integer (`:42\r\n`).
async fn write_integer<W: AsyncWriteExt + Unpin>(w: &mut W, n: i64) -> io::Result<()> {
    w.write_all(format!(":{n}\r\n").as_bytes()).await
}

/// Write a RESP bulk string (`$N\r\n<bytes>\r\n`).
async fn write_bulk<W: AsyncWriteExt + Unpin>(w: &mut W, b: &[u8]) -> io::Result<()> {
    w.write_all(format!("${}\r\n", b.len()).as_bytes()).await?;
    w.write_all(b).await?;
    w.write_all(b"\r\n").await
}
