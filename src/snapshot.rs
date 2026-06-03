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
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::digest::Digest;
use crate::state::{Blob, Manifest, RedisEntry, State};

/// Bump this when the snapshot schema changes in a way that can't be handled
/// by serde's `#[serde(default)]` forward-compatibility.
const SNAPSHOT_VERSION: u32 = 2;

const SNAPSHOT_FILENAME: &str = "snapshot.cbor";
const SNAPSHOT_TMP: &str = "snapshot.cbor.tmp";

/// Maximum size for entries we inline into the snapshot itself instead of
/// spilling them to a separate file under `<data_folder>/blobs/`. Small
/// entries are cheap to keep in the snapshot CBOR and avoid the per-file
/// I/O cost on save and on startup load.
const SNAPSHOT_INLINE_THRESHOLD: usize = 1024;

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
    next_id: u64,
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
    last_used: u64,
    content: Bytes,
}

/// Blobs in the snapshot are always disk-resident. In-memory blobs are
/// spilled to disk before serialization.
#[derive(Serialize, Deserialize)]
struct BlobEntry {
    digest: String,
    media_type: String,
    size: u64,
    last_accessed: u64,
    id: u64,
    // Only present for small blobs that we do not spill
    content: Option<Bytes>,
}

#[derive(Serialize, Deserialize)]
struct RedisEntryEntry {
    key: Bytes,
    id: u64,
    // Only present for small entries that we do not spill
    value: Option<Bytes>,
    last_accessed: u64,
    size: u64,
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
        let (size, media_type, last_accessed, id, content) = match blob.as_ref() {
            Blob::OnDisk {
                size,
                media_type,
                last_accessed,
                id,
            } => (
                *size,
                media_type.clone(),
                last_accessed.load(Relaxed),
                *id,
                None,
            ),
            Blob::InMemory {
                id,
                content,
                media_type,
                last_accessed,
            } if content.len() <= SNAPSHOT_INLINE_THRESHOLD => {
                // Small blobs are cheap to keep in memory, so we can avoid the overhead of spilling them out and reading them back on startup.
                (
                    content.len() as u64,
                    media_type.clone(),
                    last_accessed.load(Relaxed),
                    *id,
                    Some(content.clone()),
                )
            }
            Blob::InMemory {
                content,
                media_type,
                last_accessed,
                id,
            } => {
                // Make sure the bytes survive across restart by writing them
                // out. This reuses the same on-disk layout as the eviction
                // tier.
                let path = state.cache_path(*id);
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
                    *id,
                    None,
                )
            }
        };
        blob_entries.push(BlobEntry {
            digest: digest.to_string(),
            media_type,
            size,
            last_accessed,
            id,
            content,
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

    let mut redis_entries: Vec<RedisEntryEntry> = Vec::with_capacity(state.redis_entries.len());
    for entry in &state.redis_entries {
        let key = entry.key().clone();
        let entry = entry.value().as_ref();

        match entry {
            RedisEntry::InMemory {
                value,
                id,
                last_accessed,
            } if value.len() <= SNAPSHOT_INLINE_THRESHOLD => {
                // Small entries are cheap to keep in memory, so we can avoid the overhead of spilling them out and reading them back on startup.
                redis_entries.push(RedisEntryEntry {
                    key,
                    value: Some(value.clone()),
                    last_accessed: last_accessed.load(Relaxed),
                    id: *id,
                    size: value.len() as u64,
                });
            }
            RedisEntry::InMemory {
                value,
                id,
                last_accessed,
            } => {
                // Make sure the bytes survive across restart by writing them
                // out. This reuses the same on-disk layout as the eviction
                // tier.
                let path = state.cache_path(*id);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("create dir for spill {}", parent.display()))?;
                }
                tokio::fs::write(&path, &value).await.with_context(|| {
                    format!(
                        "spill redis entry {} to {}",
                        String::from_utf8_lossy(&key),
                        path.display()
                    )
                })?;
                spilled += value.len() as u64;
                redis_entries.push(RedisEntryEntry {
                    key,
                    value: None,
                    last_accessed: last_accessed.load(Relaxed),
                    id: *id,
                    size: value.len() as u64,
                });
            }
            RedisEntry::OnDisk {
                size,
                id,
                last_accessed,
            } => {
                redis_entries.push(RedisEntryEntry {
                    key,
                    value: None,
                    last_accessed: last_accessed.load(Relaxed),
                    id: *id,
                    size: *size,
                });
            }
        }
    }

    let snap = Snapshot {
        version: SNAPSHOT_VERSION,
        tags,
        manifests,
        blobs: blob_entries,
        redis_entries,
        next_id: state.next_id.load(Relaxed),
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
            // We need to clear the snapshot file on disk to avoid confusion on the next startup after crash.
            tokio::fs::remove_file(&path).await?;
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
                last_used: AtomicU64::new(m.last_used),
            }),
        );
        stats.manifests += 1;
    }

    for b in snap.blobs {
        let Ok(d) = b.digest.parse::<Digest>() else {
            continue;
        };
        // Small blobs are inlined directly in the snapshot; restore them as
        // in-memory entries without touching the disk.
        if let Some(content) = b.content {
            memory_usage += content.len() as u64;
            state.blobs.insert(
                d,
                Arc::new(Blob::InMemory {
                    id: b.id,
                    content,
                    media_type: b.media_type,
                    last_accessed: AtomicU64::new(b.last_accessed),
                }),
            );
            stats.blobs += 1;
            continue;
        }
        // Verify the backing file exists; otherwise the metadata is a lie.
        let path = state.cache_path(b.id);
        let on_disk = tokio::fs::metadata(&path).await.ok();
        match on_disk {
            Some(meta) if meta.len() == b.size => {
                disk_usage += b.size;
                state.blobs.insert(
                    d,
                    Arc::new(Blob::OnDisk {
                        size: b.size,
                        media_type: b.media_type,
                        last_accessed: AtomicU64::new(b.last_accessed),
                        id: b.id,
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
        if let Some(value) = r.value {
            memory_usage += r.key.len() as u64 + value.len() as u64;
            state.redis_entries.insert(
                r.key,
                Arc::new(RedisEntry::InMemory {
                    value,
                    id: r.id,
                    last_accessed: AtomicU64::new(r.last_accessed),
                }),
            );
        } else {
            disk_usage += r.size;
            state.redis_entries.insert(
                r.key,
                Arc::new(RedisEntry::OnDisk {
                    id: r.id,
                    last_accessed: AtomicU64::new(r.last_accessed),
                    size: r.size,
                }),
            );
        }
        stats.redis_entries += 1;
    }

    state.approx_memory_usage.store(memory_usage, Relaxed);
    state.disk_usage.store(disk_usage, Relaxed);
    state.next_id.store(snap.next_id, Relaxed);
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
    state.next_id.store(0, Relaxed);
}
