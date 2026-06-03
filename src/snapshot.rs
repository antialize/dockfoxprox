//! Persistent snapshot of cache state. Written on shutdown, loaded on startup.
//!
//! Format: CBOR (RFC 8949) - a self-describing binary format. Each value
//! carries its own type tag, so future versions can ignore unknown fields and
//! detect schema mismatches at decode time. The top-level struct carries an
//! explicit `version` so we can refuse incompatible payloads even when CBOR
//! would happily decode them.
//!
//! Contents:
//!   - `tags`           - `(repo, ref) -> digest` for the `self` host.
//!   - `manifests`      - full manifest bytes by digest (small, cheap to keep).
//!   - `blobs`          - metadata only; the bytes live in `<data_folder>/blobs/`.
//!     In-memory blobs at shutdown are first spilled to disk.
//!   - `redis_entries`  - full key/value pairs.
//!   - `metrics`         counter snapshot, so values are monotonic across restart.
//!
//! On load failure (corrupt file, version mismatch, schema drift) the entire
//! `<data_folder>/blobs/` directory is removed: those files only mean something
//! with the metadata that points at them.
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::digest::Digest;
use crate::state::{Blob, Manifest, RedisEntry, State};

/// Bump this when the snapshot schema changes in a way that can't be handled
/// by serde's `#[serde(default)]` forward-compatibility.
const SNAPSHOT_VERSION: u32 = 1;

const SNAPSHOT_FILENAME: &str = "snapshot.cbor";
const SNAPSHOT_TMP: &str = "snapshot.cbor.tmp";

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    #[serde(default)]
    tags: Vec<TagEntry>,
    #[serde(default)]
    manifests: Vec<ManifestEntry>,
    #[serde(default)]
    blobs: Vec<BlobEntry>,
    #[serde(default)]
    redis_entries: Vec<RedisEntryEntry>,
    #[serde(default)]
    metrics: MetricsSnapshot,
}

#[derive(Serialize, Deserialize)]
struct TagEntry {
    repo: String,
    reference: String,
    digest: String,
}

#[derive(Serialize, Deserialize)]
struct ManifestEntry {
    digest: String,
    media_type: String,
    last_used: i64,
    content: Bytes,
}

/// Blobs in the snapshot are always disk-resident. In-memory blobs are
/// spilled to disk before serialization.
#[derive(Serialize, Deserialize)]
struct BlobEntry {
    digest: String,
    media_type: String,
    size: u64,
    last_accessed: i64,
}

#[derive(Serialize, Deserialize)]
struct RedisEntryEntry {
    key: Bytes,
    value: Bytes,
    last_accessed: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct MetricsSnapshot {
    #[serde(default)]
    docker_manifest_get: u64,
    #[serde(default)]
    docker_manifest_head: u64,
    #[serde(default)]
    docker_manifest_put: u64,
    #[serde(default)]
    docker_manifest_cache_hit: u64,
    #[serde(default)]
    docker_manifest_cache_miss: u64,
    #[serde(default)]
    docker_blob_get: u64,
    #[serde(default)]
    docker_blob_head: u64,
    #[serde(default)]
    docker_blob_cache_hit_memory: u64,
    #[serde(default)]
    docker_blob_cache_hit_disk: u64,
    #[serde(default)]
    docker_blob_cache_miss: u64,
    #[serde(default)]
    docker_blob_upload_post: u64,
    #[serde(default)]
    docker_blob_upload_patch: u64,
    #[serde(default)]
    docker_blob_upload_put: u64,
    #[serde(default)]
    docker_auth_failures: u64,
    #[serde(default)]
    docker_upstream_requests: u64,
    #[serde(default)]
    docker_upstream_errors: u64,
    #[serde(default)]
    redis_connections: u64,
    #[serde(default)]
    redis_commands: u64,
    #[serde(default)]
    redis_get_hit: u64,
    #[serde(default)]
    redis_get_miss: u64,
    #[serde(default)]
    redis_set: u64,
    #[serde(default)]
    redis_del: u64,
    #[serde(default)]
    redis_auth_failures: u64,
    #[serde(default)]
    eviction_runs: u64,
    #[serde(default)]
    eviction_blobs_to_disk: u64,
    #[serde(default)]
    eviction_blobs_deleted: u64,
    #[serde(default)]
    eviction_manifests_deleted: u64,
    #[serde(default)]
    eviction_redis_entries: u64,
}

fn snapshot_path(state: &State) -> PathBuf {
    PathBuf::from(&state.config.data_folder).join(SNAPSHOT_FILENAME)
}

fn snapshot_tmp_path(state: &State) -> PathBuf {
    PathBuf::from(&state.config.data_folder).join(SNAPSHOT_TMP)
}

fn blobs_dir(state: &State) -> PathBuf {
    PathBuf::from(&state.config.data_folder).join("blobs")
}

/// Serialize the cache state to `<data_folder>/snapshot.cbor`. In-memory blobs
/// are spilled to disk first so the snapshot only carries metadata. Writes go
/// to a `.tmp` file and are renamed in place to make the swap atomic.
pub async fn save(state: &State) -> Result<()> {
    let mut spilled = 0u64;
    let mut blob_entries: Vec<BlobEntry> = Vec::with_capacity(state.blobs.len());
    for entry in state.blobs.iter() {
        let digest = entry.key().clone();
        let blob = entry.value().clone();
        let (size, media_type, last_accessed) = match blob.as_ref() {
            Blob::OnDisk {
                size,
                media_type,
                last_accessed,
            } => (*size, media_type.clone(), last_accessed.load(Relaxed)),
            Blob::InMemory {
                content,
                media_type,
                last_accessed,
            } => {
                // Make sure the bytes survive across restart by writing them
                // out. This reuses the same on-disk layout as the eviction
                // tier.
                let path = state.blob_path(&digest);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("create dir for spill {}", parent.display()))?;
                }
                tokio::fs::write(&path, content)
                    .await
                    .with_context(|| format!("spill blob {digest} to {}", path.display()))?;
                spilled += content.len() as u64;
                (
                    content.len() as u64,
                    media_type.clone(),
                    last_accessed.load(Relaxed),
                )
            }
        };
        blob_entries.push(BlobEntry {
            digest: digest.to_string(),
            media_type,
            size,
            last_accessed,
        });
    }

    let manifests: Vec<ManifestEntry> = state
        .manifests
        .iter()
        .map(|e| ManifestEntry {
            digest: e.key().to_string(),
            media_type: e.value().media_type.clone(),
            last_used: e.value().last_used.load(Relaxed),
            content: e.value().content.clone(),
        })
        .collect();

    let tags: Vec<TagEntry> = state
        .tags
        .iter()
        .map(|e| TagEntry {
            repo: e.key().0.clone(),
            reference: e.key().1.clone(),
            digest: e.value().to_string(),
        })
        .collect();

    let redis_entries: Vec<RedisEntryEntry> = state
        .redis_entries
        .iter()
        .map(|e| RedisEntryEntry {
            key: e.key().clone(),
            value: e.value().value.clone(),
            last_accessed: e.value().last_accessed.load(Relaxed),
        })
        .collect();

    let snap = Snapshot {
        version: SNAPSHOT_VERSION,
        tags,
        manifests,
        blobs: blob_entries,
        redis_entries,
        metrics: snapshot_metrics(state),
    };

    let path = snapshot_path(state);
    let tmp = snapshot_tmp_path(state);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create snapshot dir {}", parent.display()))?;
    }
    let buf = tokio::task::spawn_blocking(move || {
        let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
        ciborium::into_writer(&snap, &mut buf).map(|()| buf)
    })
    .await
    .map_err(|e| anyhow!("snapshot serialize task: {e}"))?
    .map_err(|e| anyhow!("snapshot serialize: {e}"))?;

    let buf_len = buf.len();
    tokio::fs::write(&tmp, &buf)
        .await
        .with_context(|| format!("write snapshot {}", tmp.display()))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("rename snapshot {}", path.display()))?;

    info!(
        bytes = buf_len,
        blobs = state.blobs.len(),
        manifests = state.manifests.len(),
        tags = state.tags.len(),
        redis_entries = state.redis_entries.len(),
        spilled_bytes = spilled,
        path = %path.display(),
        "snapshot written"
    );
    Ok(())
}

/// Try to load a previously written snapshot. On any failure (no file,
/// corrupt, version mismatch) wipe `<data_folder>/blobs/` and the snapshot
/// file itself, then return Ok: the cache is allowed to start cold.
pub async fn load_or_wipe(state: &State) -> Result<()> {
    let path = snapshot_path(state);
    match load(state, &path).await {
        Ok(stats) => {
            info!(
                blobs = stats.blobs,
                blobs_pruned = stats.blobs_pruned,
                manifests = stats.manifests,
                tags = stats.tags,
                redis_entries = stats.redis_entries,
                path = %path.display(),
                "snapshot loaded"
            );
            Ok(())
        }
        Err(LoadError::Missing) => {
            // Nothing on disk to begin with - wipe any orphan blob files
            // that may have been left behind by a crash mid-write.
            wipe_cache(state).await;
            Ok(())
        }
        Err(LoadError::Other(e)) => {
            warn!(error = %e, path = %path.display(), "snapshot load failed; wiping cache files");
            wipe_cache(state).await;
            let _ = tokio::fs::remove_file(&path).await;
            Ok(())
        }
    }
}

#[derive(Default)]
struct LoadStats {
    blobs: usize,
    blobs_pruned: usize,
    manifests: usize,
    tags: usize,
    redis_entries: usize,
}

enum LoadError {
    Missing,
    Other(anyhow::Error),
}

async fn load(state: &State, path: &PathBuf) -> Result<LoadStats, LoadError> {
    let buf = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(LoadError::Missing),
        Err(e) => return Err(LoadError::Other(anyhow!("read snapshot: {e}"))),
    };
    let snap: Snapshot =
        tokio::task::spawn_blocking(move || ciborium::from_reader::<Snapshot, _>(&buf[..]))
            .await
            .map_err(|e| LoadError::Other(anyhow!("decode task: {e}")))?
            .map_err(|e| LoadError::Other(anyhow!("decode cbor: {e}")))?;

    if snap.version != SNAPSHOT_VERSION {
        return Err(LoadError::Other(anyhow!(
            "snapshot version {} != expected {SNAPSHOT_VERSION}",
            snap.version
        )));
    }

    let mut stats = LoadStats::default();
    let mut memory_usage: u64 = 0;
    let mut disk_usage: u64 = 0;

    for m in snap.manifests {
        let Ok(d) = m.digest.parse::<Digest>() else {
            continue;
        };
        memory_usage += m.content.len() as u64;
        state.manifests.insert(
            d,
            Arc::new(Manifest {
                content: m.content,
                media_type: m.media_type,
                last_used: AtomicI64::new(m.last_used),
            }),
        );
        stats.manifests += 1;
    }

    for b in snap.blobs {
        let Ok(d) = b.digest.parse::<Digest>() else {
            continue;
        };
        // Verify the backing file exists; otherwise the metadata is a lie.
        let path = state.blob_path(&d);
        let on_disk = tokio::fs::metadata(&path).await.ok();
        match on_disk {
            Some(meta) if meta.len() == b.size => {
                disk_usage += b.size;
                state.blobs.insert(
                    d,
                    Arc::new(Blob::OnDisk {
                        size: b.size,
                        media_type: b.media_type,
                        last_accessed: AtomicI64::new(b.last_accessed),
                    }),
                );
                stats.blobs += 1;
            }
            _ => {
                stats.blobs_pruned += 1;
            }
        }
    }

    for t in snap.tags {
        let Ok(d) = t.digest.parse::<Digest>() else {
            continue;
        };
        state.tags.insert((t.repo, t.reference), d);
        stats.tags += 1;
    }

    for r in snap.redis_entries {
        memory_usage += r.key.len() as u64 + r.value.len() as u64;
        state.redis_entries.insert(
            r.key,
            Arc::new(RedisEntry {
                value: r.value,
                last_accessed: AtomicI64::new(r.last_accessed),
            }),
        );
        stats.redis_entries += 1;
    }

    restore_metrics(state, &snap.metrics);

    state.approx_memory_usage.store(memory_usage, Relaxed);
    state.disk_usage.store(disk_usage, Relaxed);
    Ok(stats)
}

async fn wipe_cache(state: &State) {
    let dir = blobs_dir(state);
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => info!(path = %dir.display(), "wiped blob cache"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(error = %e, path = %dir.display(), "failed to wipe blob cache"),
    }
    // Reset accounting; nothing is loaded.
    state.blobs.clear();
    state.manifests.clear();
    state.tags.clear();
    state.redis_entries.clear();
    state.approx_memory_usage.store(0, Relaxed);
    state.disk_usage.store(0, Relaxed);
}

fn snapshot_metrics(state: &State) -> MetricsSnapshot {
    let m = &state.metrics;
    MetricsSnapshot {
        docker_manifest_get: m.docker_manifest_get.load(Relaxed),
        docker_manifest_head: m.docker_manifest_head.load(Relaxed),
        docker_manifest_put: m.docker_manifest_put.load(Relaxed),
        docker_manifest_cache_hit: m.docker_manifest_cache_hit.load(Relaxed),
        docker_manifest_cache_miss: m.docker_manifest_cache_miss.load(Relaxed),
        docker_blob_get: m.docker_blob_get.load(Relaxed),
        docker_blob_head: m.docker_blob_head.load(Relaxed),
        docker_blob_cache_hit_memory: m.docker_blob_cache_hit_memory.load(Relaxed),
        docker_blob_cache_hit_disk: m.docker_blob_cache_hit_disk.load(Relaxed),
        docker_blob_cache_miss: m.docker_blob_cache_miss.load(Relaxed),
        docker_blob_upload_post: m.docker_blob_upload_post.load(Relaxed),
        docker_blob_upload_patch: m.docker_blob_upload_patch.load(Relaxed),
        docker_blob_upload_put: m.docker_blob_upload_put.load(Relaxed),
        docker_auth_failures: m.docker_auth_failures.load(Relaxed),
        docker_upstream_requests: m.docker_upstream_requests.load(Relaxed),
        docker_upstream_errors: m.docker_upstream_errors.load(Relaxed),
        redis_connections: m.redis_connections.load(Relaxed),
        redis_commands: m.redis_commands.load(Relaxed),
        redis_get_hit: m.redis_get_hit.load(Relaxed),
        redis_get_miss: m.redis_get_miss.load(Relaxed),
        redis_set: m.redis_set.load(Relaxed),
        redis_del: m.redis_del.load(Relaxed),
        redis_auth_failures: m.redis_auth_failures.load(Relaxed),
        eviction_runs: m.eviction_runs.load(Relaxed),
        eviction_blobs_to_disk: m.eviction_blobs_to_disk.load(Relaxed),
        eviction_blobs_deleted: m.eviction_blobs_deleted.load(Relaxed),
        eviction_manifests_deleted: m.eviction_manifests_deleted.load(Relaxed),
        eviction_redis_entries: m.eviction_redis_entries.load(Relaxed),
    }
}

fn restore_metrics(state: &State, snap: &MetricsSnapshot) {
    let m = &state.metrics;
    fn set(a: &AtomicU64, v: u64) {
        a.store(v, Relaxed);
    }
    set(&m.docker_manifest_get, snap.docker_manifest_get);
    set(&m.docker_manifest_head, snap.docker_manifest_head);
    set(&m.docker_manifest_put, snap.docker_manifest_put);
    set(&m.docker_manifest_cache_hit, snap.docker_manifest_cache_hit);
    set(
        &m.docker_manifest_cache_miss,
        snap.docker_manifest_cache_miss,
    );
    set(&m.docker_blob_get, snap.docker_blob_get);
    set(&m.docker_blob_head, snap.docker_blob_head);
    set(
        &m.docker_blob_cache_hit_memory,
        snap.docker_blob_cache_hit_memory,
    );
    set(
        &m.docker_blob_cache_hit_disk,
        snap.docker_blob_cache_hit_disk,
    );
    set(&m.docker_blob_cache_miss, snap.docker_blob_cache_miss);
    set(&m.docker_blob_upload_post, snap.docker_blob_upload_post);
    set(&m.docker_blob_upload_patch, snap.docker_blob_upload_patch);
    set(&m.docker_blob_upload_put, snap.docker_blob_upload_put);
    set(&m.docker_auth_failures, snap.docker_auth_failures);
    set(&m.docker_upstream_requests, snap.docker_upstream_requests);
    set(&m.docker_upstream_errors, snap.docker_upstream_errors);
    set(&m.redis_connections, snap.redis_connections);
    set(&m.redis_commands, snap.redis_commands);
    set(&m.redis_get_hit, snap.redis_get_hit);
    set(&m.redis_get_miss, snap.redis_get_miss);
    set(&m.redis_set, snap.redis_set);
    set(&m.redis_del, snap.redis_del);
    set(&m.redis_auth_failures, snap.redis_auth_failures);
    set(&m.eviction_runs, snap.eviction_runs);
    set(&m.eviction_blobs_to_disk, snap.eviction_blobs_to_disk);
    set(&m.eviction_blobs_deleted, snap.eviction_blobs_deleted);
    set(
        &m.eviction_manifests_deleted,
        snap.eviction_manifests_deleted,
    );
    set(&m.eviction_redis_entries, snap.eviction_redis_entries);
}
