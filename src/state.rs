//! State management for the proxy. This is where we keep track of tokens, manifests, blobs, tags, and in-progress uploads.
use bytes::Bytes;
use dashmap::DashMap;
use reqwest::Client;
use sha2::Sha256;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};
use tokio::sync::Mutex;
use tokio_tasks::{RunToken, TaskBuilder};
use uuid::Uuid;

use crate::{
    aligned_atomic::{AlignedAtomicI64, AlignedAtomicU64},
    config::Config,
    digest::Digest,
    metrics::Metrics,
};

/// Boundary between small and large items. Items at or below this size are
/// considered "small" and accounted into the `small_*_memory_usage`
/// buckets; items above are considered "large" and accounted into the
/// `large_*_memory_usage` buckets.
pub const MEMORY_TIER_THRESHOLD: usize = 1024;

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
    pub evicted: AtomicBool,
}

/// Blob content or on-disk metadata, plus last-used timestamp for LRU eviction.
pub enum Blob {
    /// On-disk blob metadata. We don't want to keep the whole blob content in memory, but we do want to track its size and media type for eviction and content-type responses.
    OnDisk {
        id: u64,
        size: u64,
        media_type: String,
        last_accessed: AtomicU64,
    },
    /// In-memory blob content. We keep the whole content in memory for fast access, along with its media type and last-accessed timestamp for eviction.
    InMemory {
        id: u64,
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
pub enum RedisEntry {
    InMemory {
        value: Bytes,
        id: u64,
        last_accessed: AtomicU64,
    },
    OnDisk {
        size: u64,
        id: u64,
        last_accessed: AtomicU64,
    },
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

    // -- Usage breakdown -----------------------------------------------------
    //
    // Seven mutually-exclusive buckets that together account for every byte
    // the cache holds. Maintained incrementally by the `insert_*`/`remove_*`
    // helpers below; the eviction loop reads them and updates its own local
    // accumulators as it works.
    //
    // The buckets feed three budgets enforced by `eviction::evict`:
    //
    //   * `small_used <= config.small_memory_limit()` - the reservation for
    //     items that can only be reclaimed by dropping whole manifests
    //     (manifests, small blobs, small redis entries).
    //   * `small_used + large_used <= config.memory_limit` - total memory
    //     ceiling. There is no separate "large memory limit"; large items
    //     simply get whatever portion of `memory_limit` the small pool is
    //     not currently using.
    //   * `disk_used <= config.disk_limit` - on-disk ceiling for spilled
    //     blobs and on-disk redis entries.
    //
    // The split exists so a flood of small items can never starve large
    // blob caching: even at maximum small-pool usage there is still
    // `memory_limit - small_memory_limit` available for large blobs and
    // large redis entries.
    /// Bytes of manifest content held in memory.
    pub manifest_memory_usage: AlignedAtomicI64,
    /// In-memory blob content `<= MEMORY_TIER_THRESHOLD` bytes. Freed only
    /// when its owning manifest is dropped.
    pub small_blob_memory_usage: AlignedAtomicI64,
    /// In-memory blob content `> MEMORY_TIER_THRESHOLD` bytes. Eligible to
    /// be spilled to disk when the total-memory budget is exceeded.
    pub large_blob_memory_usage: AlignedAtomicI64,
    /// In-memory redis entries (key+value) where the value is
    /// `<= MEMORY_TIER_THRESHOLD`. Counted toward the small reservation.
    pub small_redis_memory_usage: AlignedAtomicI64,
    /// In-memory redis entries (key+value) where the value is
    /// `> MEMORY_TIER_THRESHOLD`. Dropped outright when the total-memory
    /// budget is exceeded.
    pub large_redis_memory_usage: AlignedAtomicI64,
    /// On-disk blob bytes.
    pub blob_disk_usage: AlignedAtomicI64,
    /// On-disk redis entry bytes.
    pub redis_disk_usage: AlignedAtomicI64,

    /// In-memory cache entries served via the Redis protocol (for ccache et al).
    pub redis_entries: DashMap<Bytes, Arc<RedisEntry>>,

    /// Counters and gauges exposed at `/metrics`.
    pub metrics: Metrics,

    /// Next ID to use for uploads and Redis on-disk entries.
    pub next_id: AlignedAtomicU64,
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
            manifest_memory_usage: AlignedAtomicI64::new(0),
            small_blob_memory_usage: AlignedAtomicI64::new(0),
            large_blob_memory_usage: AlignedAtomicI64::new(0),
            small_redis_memory_usage: AlignedAtomicI64::new(0),
            large_redis_memory_usage: AlignedAtomicI64::new(0),
            blob_disk_usage: AlignedAtomicI64::new(0),
            redis_disk_usage: AlignedAtomicI64::new(0),
            redis_entries: DashMap::new(),
            metrics: Metrics::default(),
            next_id: AlignedAtomicU64::new(0),
        }));

        TaskBuilder::new("time updater")
            .main()
            .abort()
            .create(|_: RunToken| time_updater(state));

        state
    }

    /// Insert a blob into the cache, updating the per-bucket usage counter.
    /// If a blob with the same digest already existed its charge is moved
    /// out of its bucket first, so replacements (e.g. an in-memory -
    /// on-disk transition during eviction) keep the counters accurate.
    pub fn insert_blob(&self, digest: Digest, blob: Arc<Blob>) {
        let (new_bucket, new_bytes) = blob_bucket(self, &blob);
        new_bucket.fetch_add(new_bytes as i64, Relaxed);
        if let Some(old) = self.blobs.insert(digest, blob) {
            let (old_bucket, old_bytes) = blob_bucket(self, &old);
            old_bucket.fetch_sub(old_bytes as i64, Relaxed);
        }
    }

    /// Remove a blob from the cache, returning the removed value (if any)
    /// and decrementing its bucket. This does not delete the object on disk
    pub fn remove_blob(&self, digest: &Digest) -> Option<Arc<Blob>> {
        let (_, b) = self.blobs.remove(digest)?;
        let (bucket, bytes) = blob_bucket(self, &b);
        bucket.fetch_sub(bytes as i64, Relaxed);
        Some(b)
    }

    /// Insert a manifest into the cache, updating `manifest_memory_usage`.
    /// Subtracts the replaced manifest's bytes if one was present.
    pub fn insert_manifest(&self, digest: Digest, m: Arc<Manifest>) {
        let new_len = m.content.len() as i64;
        let old_len = self
            .manifests
            .insert(digest, m)
            .map(|o| o.content.len() as i64)
            .unwrap_or(0);
        self.manifest_memory_usage
            .fetch_add(new_len - old_len, Relaxed);
    }

    /// Remove a manifest from the cache, returning the removed value (if any)
    /// and decrementing `manifest_memory_usage`.
    pub fn remove_manifest(&self, digest: &Digest) -> Option<Arc<Manifest>> {
        let (_, m) = self.manifests.remove(digest)?;
        self.manifest_memory_usage
            .fetch_sub(m.content.len() as i64, Relaxed);
        Some(m)
    }

    /// Path on disk where the blob with the given digest is cached.
    /// This is where we write blobs when we evict them from memory, and where we read blobs from disk on cache hits.
    pub fn cache_path(&self, id: u64) -> PathBuf {
        let hex = format!("{:016x}", id);
        let shard = &hex[14..];
        PathBuf::from(&self.config.data_folder)
            .join("blobs")
            .join(shard)
            .join(hex)
    }

    /// Insert or replace a Redis-protocol cache entry, adjusting the
    /// small/large redis memory counters by the net byte delta. If the
    /// replaced entry was on disk, the backing file is removed.
    pub fn insert_redis(&self, key: Bytes, value: Bytes) -> Arc<RedisEntry> {
        let now = self.now.load(Relaxed);
        let key_len = key.len() as u64;
        let entry = Arc::new(RedisEntry::InMemory {
            id: self.next_id.fetch_add(1, Relaxed),
            last_accessed: AtomicU64::new(now),
            value,
        });
        let (new_bucket, new_bytes) = redis_bucket(self, &entry, key_len);
        new_bucket.fetch_add(new_bytes as i64, Relaxed);

        if let Some(old) = self.redis_entries.insert(key, entry.clone()) {
            // Same key, so the replaced entry's key charge equals `key_len`.
            let (old_bucket, old_bytes) = redis_bucket(self, &old, key_len);
            old_bucket.fetch_sub(old_bytes as i64, Relaxed);
            if let RedisEntry::OnDisk { id, .. } = old.as_ref() {
                let path = self.cache_path(*id);
                tokio::spawn(tokio::fs::remove_file(path));
            }
        }
        entry
    }

    /// Remove a Redis entry by key, returning whether it existed.
    pub fn remove_redis(&self, key: &[u8]) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if let Some((k, v)) = self.redis_entries.remove(key) {
            let (bucket, bytes) = redis_bucket(self, &v, k.len() as u64);
            bucket.fetch_sub(bytes as i64, Relaxed);
            if let RedisEntry::OnDisk { id, .. } = v.as_ref() {
                let path = self.cache_path(*id);
                tokio::spawn(tokio::fs::remove_file(path));
            }
            true
        } else {
            false
        }
    }

    /// Drop every Redis entry, reclaiming the bytes from the redis counters
    /// and unlinking any on-disk backing files.
    pub fn flush_redis(&'static self) {
        let mut delete = Vec::new();
        self.redis_entries.retain(|_, v| {
            if let RedisEntry::OnDisk { id, .. } = v.as_ref() {
                delete.push(*id);
            }
            false
        });
        self.small_redis_memory_usage.store(0, Relaxed);
        self.large_blob_memory_usage.store(0, Relaxed);
        self.redis_disk_usage.store(0, Relaxed);
        tokio::spawn(async move {
            for id in delete {
                let path = self.cache_path(id);
                tokio::fs::remove_file(path).await.ok();
            }
        });
    }

    /// Sum of every bucket that counts against `config.memory_limit`.
    #[inline(always)]
    pub fn total_memory_usage(&self) -> i64 {
        self.large_memory_usage() + self.small_memory_usage()
    }

    /// Bytes in the "large memory" portion: large blobs in memory + large
    /// redis entries in memory. There is no dedicated "large memory limit"
    /// in the config - this is just the slice of `config.memory_limit`
    /// available to large items after the small reservation is satisfied.
    /// Reported for telemetry.
    #[inline(always)]
    pub fn large_memory_usage(&self) -> i64 {
        self.large_blob_memory_usage.load(Relaxed) + self.large_redis_memory_usage.load(Relaxed)
    }

    /// Bytes in the "small memory" pool: manifests + small in-memory blobs +
    /// small in-memory redis entries. Reclaimed only by dropping whole
    /// manifests (cascading to their blobs) and small redis entries.
    /// Compared against `config.small_memory_limit()`.
    #[inline(always)]
    pub fn small_memory_usage(&self) -> i64 {
        self.manifest_memory_usage.load(Relaxed)
            + self.small_blob_memory_usage.load(Relaxed)
            + self.small_redis_memory_usage.load(Relaxed)
    }

    /// Sum of every bucket that counts against `config.disk_limit`.
    #[inline(always)]
    pub fn total_disk_usage(&self) -> i64 {
        self.blob_disk_usage.load(Relaxed) + self.redis_disk_usage.load(Relaxed)
    }
}

/// Returns the bucket the given blob is charged to and its byte size.
fn blob_bucket<'a>(state: &'a State, blob: &Blob) -> (&'a AlignedAtomicI64, u64) {
    match blob {
        Blob::InMemory { content, .. } if content.len() > MEMORY_TIER_THRESHOLD => {
            (&state.large_blob_memory_usage, content.len() as u64)
        }
        Blob::InMemory { content, .. } => (&state.small_blob_memory_usage, content.len() as u64),
        Blob::OnDisk { size, .. } => (&state.blob_disk_usage, *size),
    }
}

/// Returns the bucket the given redis entry is charged to and its byte
/// size (key + value for in-memory entries).
fn redis_bucket<'a>(
    state: &'a State,
    entry: &RedisEntry,
    key_len: u64,
) -> (&'a AlignedAtomicI64, u64) {
    match entry {
        RedisEntry::InMemory { value, .. } if value.len() > MEMORY_TIER_THRESHOLD => (
            &state.large_redis_memory_usage,
            value.len() as u64 + key_len,
        ),
        RedisEntry::InMemory { value, .. } => (
            &state.small_redis_memory_usage,
            value.len() as u64 + key_len,
        ),
        RedisEntry::OnDisk { size, .. } => (&state.redis_disk_usage, *size),
    }
}
