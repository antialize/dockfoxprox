# dockfoxprox

A small, single-binary pull-through cache for Docker / OCI registries, with a
bonus Redis-protocol cache endpoint for things like
[ccache](https://ccache.dev/) sharing a single memory budget with the registry
cache.

It is designed for a fairly specific niche: a CI environment that already runs
a TLS reverse proxy, needs to cache image layers from one or more upstream
registries, and would like a cheap shared key/value cache for compiler output
on the side. Everything lives in one process, with one memory and one disk
budget across all caches.

## Features

- **Pull-through Docker registry cache** speaking the Docker Registry HTTP API
  v2. Caches manifests and blobs from arbitrary upstreams, including ones
  behind Basic auth or token (`WWW-Authenticate: Bearer`) auth.
- **Built-in `self` registry** that accepts pushes (manifests + resumable blob
  uploads) for storing artifacts produced inside the CI.
- **Two-tier cache**: hot entries in memory, cold blobs spilled to disk by an
  LRU eviction loop. Both tiers share a single configured memory and disk
  budget.
- **Redis-protocol server** implementing the subset of RESP2 that ccache and
  similar simple clients use (`PING`, `AUTH`, `GET`, `SET`, `DEL`, `UNLINK`,
  `EXISTS`, `FLUSHDB`/`FLUSHALL`, `SELECT`, `CLIENT`, `INFO`, `COMMAND`,
  `DBSIZE`, `QUIT`). Entries count against the same memory budget.
- **Prometheus metrics** on `/metrics` (text exposition format).
- **Persistent state**: cache contents and counters are snapshotted to a
  self-describing CBOR file on shutdown and restored on startup. A corrupt or
  incompatible snapshot causes the on-disk blob directory to be wiped - the
  files are useless without the metadata that points at them.
- **Constant-time password comparison** for both the Docker Basic-auth check
  and the Redis `AUTH` command, via the `subtle` crate.
- **HTTPS** (self-signed for now) with HTTP/1 and HTTP/2 via ALPN, plus an
  optional plaintext HTTP port for unauthenticated `/metrics` scraping.


## Installation

```sh
cargo install --path .
# or
cargo build --release
```

The result is a single `dockfoxprox` binary with no runtime dependencies
beyond glibc.

## Configuration

Configuration is a TOML file (default: `./config.toml`):

```toml
# HTTPS listener. Always enabled. Self-signed cert is generated at startup.
https_port = 8443

# Optional plaintext HTTP listener. Same routes as HTTPS, no HSTS header.
# Convenient for /metrics scraping.
http_port = 8080

# Where on-disk blobs and the persistence snapshot live.
data_folder = "/var/lib/dockfoxprox"

# Memory and disk budgets. Accepts B/KB/MB/GB/TB (binary multipliers).
memory_limit = "16GB"
disk_limit   = "100GB"

# Optional Redis-protocol server. Disabled if redis_port is unset.
redis_port     = 6379
redis_password = "use-something-real"

# Clients authenticating to the Docker endpoint. Empty = no auth required.
[[docker_user]]
username = "ci"
password = "use-something-real"

# Named upstream registries. Anything not matched here is hit directly with
# the URL path host segment as the hostname.
[docker_registry.dockerhub]
url      = "registry-1.docker.io"

[docker_registry.private]
url      = "registry.example.com"
username = "robot"
password = "use-something-real"
```

`docker.io` and `index.docker.io` are recognised as aliases for
`registry-1.docker.io` even without a configured entry. The host `self`
is reserved for the in-process registry that accepts pushes.

## Usage

### As a Docker mirror

Configure your Docker daemon to use the proxy. Image references through the
proxy look like `<proxy-host>/<upstream-host>/<image>:<tag>`:

```sh
docker pull dockfoxprox.local:8443/docker.io/library/alpine:3.20
docker pull dockfoxprox.local:8443/registry.example.com/team/service:v1.2.3
```

With Docker user auth configured:

```sh
docker login dockfoxprox.local:8443
```

### Pushing to the `self` registry

```sh
docker tag myimage:latest dockfoxprox.local:8443/self/myimage:latest
docker push dockfoxprox.local:8443/self/myimage:latest
```

### Using the Redis endpoint with ccache

```sh
export CCACHE_REMOTE_STORAGE="redis://:use-something-real@dockfoxprox.local:6379"
```

### Metrics

```sh
curl http://dockfoxprox.local:8080/metrics
```

## Command-line flags

```text
USAGE:
    dockfoxprox [OPTIONS]

OPTIONS:
    -c, --config <CONFIG>        Path to the TOML config file [default: config.toml]
    -v, --verbosity <VERBOSITY>  Log verbosity [error|warn|info|debug|trace] [default: info]
    -h, --help                   Print help
```

`RUST_LOG` overrides `--verbosity` when set. `debug` and `trace` only
crank up `dockfoxprox` itself; other crates stay at `info` to avoid
hyper/rustls noise.

## How it caches

- **Manifests** are always cached by content digest. For tag references (e.g.
  `:latest`) the proxy HEADs upstream first to learn the current digest, so
  tags stay fresh and clients don't see stale images.
- **Blobs** are streamed from upstream to the client *and* to an in-memory
  buffer in parallel. The buffer's SHA-256 is verified against the requested
  digest before insertion; a truncated or corrupt upstream body is never
  cached. A client disconnect mid-stream does not abort the cache fill.
- **Eviction** runs every 30s when memory usage exceeds the configured
  budget. The oldest disk-tier manifest is dropped first (cascading to its
  blobs); then the oldest memory-tier manifest's blobs are spilled to disk;
  Redis entries compete with manifests for memory-tier eviction. Blobs
  younger than 5h are protected to avoid races with concurrent uploads.

## Snapshots

On clean shutdown, the proxy writes `<data_folder>/snapshot.cbor` containing
the full cache metadata (tags, manifest bytes, blob metadata, Redis entries,
metric counters). In-memory blobs are spilled to disk first so the bytes
survive across restart.

On startup the snapshot is loaded and the cache is repopulated. If the file
is missing, corrupt, or has a different schema version, the blob directory is
wiped and the cache starts cold.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
