//! Define the configuration format and defaults.

use std::collections::HashMap;

use serde::Deserialize;

use crate::size::Size;

/// A single Docker registry user, with username and password.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerUser {
    pub username: String,
    pub password: String,
}

/// Configuration for the proxy, deserialized from a TOML file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerRegistry {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// The main configuration struct for the proxy, deserialized from a TOML file.
/// This includes settings for the HTTPS server, Redis cache, and Docker registry credentials.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub https_port: Option<u16>,

    /// Plaintext HTTP port. Optional; intended for `/metrics` scraping by
    /// Prometheus without TLS hassle. Serves the same handler as `https_port`.
    #[serde(default)]
    pub http_port: Option<u16>,

    #[serde(default = "default_data_folder")]
    pub data_folder: String,

    #[serde(default = "default_memory_limit")]
    pub memory_limit: Size,

    /// Sub-budget within `memory_limit` reserved for small in-memory items
    /// (blobs and redis values at or below `state::MEMORY_TIER_THRESHOLD`).
    /// The remainder, `memory_limit - small_memory_limit`, is available to
    /// large in-memory items and manifests. Defaults to `memory_limit / 8`.
    #[serde(default)]
    pub small_memory_limit: Option<Size>,

    #[serde(default = "default_disk_limit")]
    pub disk_limit: Size,

    #[serde(default)]
    pub docker_user: Vec<DockerUser>,

    #[serde(default)]
    pub docker_registry: HashMap<String, DockerRegistry>,

    /// TCP port for the Redis-protocol cache server. `None` disables it.
    #[serde(default)]
    pub redis_port: Option<u16>,

    /// Shared password required via `AUTH`. `None` disables auth.
    #[serde(default)]
    pub redis_password: Option<String>,
}

fn default_data_folder() -> String {
    "/data/dockfoxprox".to_string()
}

fn default_memory_limit() -> Size {
    Size(1024 * 1024 * 1024 * 16)
}

fn default_disk_limit() -> Size {
    Size(1024 * 1024 * 1024 * 100)
}

impl Config {
    /// Effective small-items sub-budget: `small_memory_limit` if set,
    /// otherwise `memory_limit / 8`.
    pub fn small_memory_limit(&self) -> u64 {
        self.small_memory_limit
            .map(|s| s.0)
            .unwrap_or(self.memory_limit.0 / 8)
    }
}
