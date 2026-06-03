//! State management for the proxy. This is where we keep track of tokens, manifests, blobs, tags, and in-progress uploads.
use bytes::Bytes;
use dashmap::DashMap;
use reqwest::Client;
use sha2::Sha256;
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};
use tokio::sync::Mutex;
use tokio_tasks::{RunToken, TaskBuilder};
use uuid::Uuid;

use crate::{aligned_atomic::AlignedAtomicU64, config::Config, digest::Digest, metrics::Metrics};

/// Key for the token cache. We store tokens by registry+scope, since that's what the client sends us.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TokenKey {
    pub registry: String,
    pub scope: String,
}

/// Manifest content and media type, plus last-used timestamp for LRU eviction.
pub struct Manifest {
    /// The raw manifest content, as bytes.
    pub content: Bytes,
    /// The media type of the manifest, e.g. "application/vnd.docker.distribution.manifest.v2+json".
    pub media_type: String,
    /// Last-used timestamp, as seconds since the Unix epoch. Updated on every access, used for LRU eviction.
    pub last_used: AtomicU64,
}

/// Blob content or on-disk metadata, plus last-used timestamp for LRU eviction.
pub enum Blob {
    /// On-disk blob metadata. We don't want to keep the whole blob content in memory, but we do want to track its size and media type for eviction and content-type responses.
    OnDisk {
        size: u64,
        media_type: String,
        last_accessed: AtomicU64,
    },
    /// In-memory blob content. We keep the whole content in memory for fast access, along with its media type and last-accessed timestamp for eviction.
    InMemory {
        content: Bytes,
        media_type: String,
        last_accessed: AtomicU64,
    },
}

impl Blob {
    /// Get the last-accessed timestamp for this blob, for eviction purposes.
    pub fn last_accessed(&self) -> &AtomicU64 {
        match self {
            Blob::InMemory { last_accessed, .. } | Blob::OnDisk { last_accessed, .. } => {
                last_accessed
            }
        }
    }
}

/// A single Redis-protocol cache entry, stored only in memory.
pub struct RedisEntry {
    pub value: Bytes,
    pub last_accessed: AtomicU64,
}

/// Resumable upload state. Bytes accumulate in `buf`, hashed incrementally.
/// Wrapped in a `TMutex` so we can hold it across `await` points while the
/// request body streams in.
pub struct Upload {
    pub inner: Mutex<UploadInner>,
}

pub struct UploadInner {
    pub buf: Vec<u8>,
    pub hasher: Sha256,
}

/// The main state struct, containing all the caches and configuration for the proxy.
pub struct State {
    /// (registry, scope) -> token, for authentication to upstream registries.
    pub tokens: DashMap<TokenKey, Arc<String>>,

    /// manifest digest -> manifest content for all cached data including the `self` host.
    pub manifests: DashMap<Digest, Arc<Manifest>>,

    /// blob digest -> blob content or on-disk metadata for all cached data including the `self` host.
    pub blobs: DashMap<Digest, Arc<Blob>>,

    /// (repo_name, tag-or-digest) -> manifest digest, for the `self` host.
    pub tags: DashMap<(String, String), Digest>,

    /// In-progress uploads for the `self` host.
    pub uploads: DashMap<Uuid, Arc<Upload>>,

    /// Configuration loaded from the config file.
    pub config: Config,

    /// Reqwest client for making requests to upstream registries.
    pub reqwest_client: Client,

    /// Current time, as seconds since the Unix epoch. Updated every second by a background task, used for eviction.
    pub now: AlignedAtomicU64,

    /// Approximate total memory usage of in-memory blobs and manifests, for eviction purposes.
    pub approx_memory_usage: AlignedAtomicU64,

    /// Approximate total disk usage of on-disk blobs
    pub disk_usage: AlignedAtomicU64,

    /// In-memory cache entries served via the Redis protocol (for ccache et al).
    pub redis_entries: DashMap<Bytes, Arc<RedisEntry>>,

    /// Counters and gauges exposed at `/metrics`.
    pub metrics: Metrics,
}

/// Background task that updates `state.now` every second. Spawned by
/// `State::new`. Aborted (not awaited) on shutdown - losing a second of clock
/// at the very end of the process lifetime is fine.
async fn time_updater(state: &'static State) -> Result<(), ()> {
    loop {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        state.now.store(time, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

impl State {
    /// Create a new `State` from the given configuration and reqwest client.
    /// This leaks the `State` so it can be safely shared as a `'static` reference across the application.
    pub fn new(config: Config, reqwest_client: Client) -> &'static Self {
        let state = Box::leak(Box::new(Self {
            tokens: DashMap::new(),
            manifests: DashMap::new(),
            blobs: DashMap::new(),
            tags: DashMap::new(),
            uploads: DashMap::new(),
            config,
            reqwest_client,
            now: AlignedAtomicU64::new(0),
            approx_memory_usage: AlignedAtomicU64::new(0),
            disk_usage: AlignedAtomicU64::new(0),
            redis_entries: DashMap::new(),
            metrics: Metrics::default(),
        }));

        TaskBuilder::new("time updater")
            .main()
            .abort()
            .create(|_: RunToken| time_updater(state));

        state
    }

    /// Insert a blob into the cache, updating memory usage if it's an in-memory blob.
    pub fn insert_blob(&self, digest: Digest, blob: Arc<Blob>) {
        if let Blob::InMemory { content, .. } = blob.as_ref() {
            self.approx_memory_usage
                .fetch_add(content.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        self.blobs.insert(digest, blob);
    }

    /// Insert a manifest into the cache, updating memory usage.
    pub fn insert_manifest(&self, digest: Digest, m: Arc<Manifest>) {
        self.approx_memory_usage
            .fetch_add(m.content.len() as u64, std::sync::atomic::Ordering::Relaxed);
        self.manifests.insert(digest, m);
    }

    /// Path on disk where the bytes of `digest` live (when evicted to disk).
    /// Sharded by the first two hex chars to avoid huge flat directories.
    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        let s = digest.to_string(); // "sha256:<hex>"
        let hex = s.strip_prefix("sha256:").unwrap_or(&s);
        let (shard, _) = hex.split_at(2);
        PathBuf::from(&self.config.data_folder)
            .join("blobs")
            .join(shard)
            .join(hex)
    }

    /// Insert or replace a Redis-protocol cache entry, adjusting the shared
    /// memory accounting by the net byte delta.
    pub fn insert_redis(&self, key: Bytes, value: Bytes) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = self.now.load(Relaxed);
        let key_len = key.len() as u64;
        let new_value_len = value.len() as u64;
        let entry = Arc::new(RedisEntry {
            value,
            last_accessed: AtomicU64::new(now),
        });
        match self.redis_entries.insert(key, entry) {
            Some(prev) => {
                let old_value_len = prev.value.len() as u64;
                if new_value_len >= old_value_len {
                    self.approx_memory_usage
                        .fetch_add(new_value_len - old_value_len, Relaxed);
                } else {
                    self.approx_memory_usage
                        .fetch_sub(old_value_len - new_value_len, Relaxed);
                }
            }
            None => {
                self.approx_memory_usage
                    .fetch_add(key_len + new_value_len, Relaxed);
            }
        }
    }

    /// Remove a Redis entry by key, returning whether it existed.
    pub fn remove_redis(&self, key: &[u8]) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if let Some((k, v)) = self.redis_entries.remove(key) {
            self.approx_memory_usage
                .fetch_sub(k.len() as u64 + v.value.len() as u64, Relaxed);
            true
        } else {
            false
        }
    }

    /// Drop every Redis entry, reclaiming the bytes from the memory counter.
    pub fn flush_redis(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let mut total: u64 = 0;
        self.redis_entries.retain(|k, v| {
            total += k.len() as u64 + v.value.len() as u64;
            false
        });
        self.approx_memory_usage.fetch_sub(total, Relaxed);
    }
}
