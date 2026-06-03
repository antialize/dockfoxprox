use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};

use bytes::Bytes;
use tokio_tasks::{RunToken, cancelable};
use tracing::{debug, info, warn};

use crate::{
    digest::Digest,
    state::{Blob, RedisEntry, State},
};

/// Blobs younger than this are never deleted by eviction. Covers the
/// upload-then-PUT-manifest race on the `self` registry and HEAD-then-PUT
/// probes against pull-through cached blobs.
const BLOB_GRACE_SECONDS: u64 = 5 * 3600;

/// Walk a manifest body (JSON) collecting every `"digest": "sha256:..."` value.
/// Covers image manifests (config + layers) and indexes/manifest-lists
/// (child manifests). Non-JSON or unparseable bodies yield an empty list.
fn referenced_digests(content: &Bytes) -> Vec<Digest> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    fn walk(v: &serde_json::Value, out: &mut Vec<Digest>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, vv) in m {
                    if k == "digest"
                        && let Some(s) = vv.as_str()
                        && let Ok(d) = s.parse::<Digest>()
                    {
                        out.push(d);
                    }
                    walk(vv, out);
                }
            }
            serde_json::Value::Array(a) => {
                for vv in a {
                    walk(vv, out);
                }
            }
            _ => {}
        }
    }
    walk(&v, &mut out);
    out
}

/// Write a blob's bytes to its canonical on-disk path, creating the shard
/// directory if needed. Returns the path written.
async fn write_blob_to_disk(state: &State, id: u64, content: &Bytes) -> std::io::Result<PathBuf> {
    let path = state.cache_path(id);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, content).await?;
    Ok(path)
}

/// Remove a blob's on-disk file. NotFound is silently ignored; other errors
/// are logged but not propagated.
async fn delete_disk_blob(state: &State, id: u64) {
    let path = state.cache_path(id);
    if let Err(e) = tokio::fs::remove_file(&path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(%id, error=%e, path=%path.display(), "failed to remove on-disk blob");
    }
}

/// One full eviction pass.
///
/// Strategy (run in order until under both budgets):
///   1. Drop the oldest disk-tier manifest if `disk_usage > disk_target`,
///      cascading to its blobs whose refcount falls to zero.
///   2. Pick the oldest memory-tier item (manifest or redis entry) and
///      reclaim it: manifests get demoted to disk-tier (their blobs spilled
///      to disk); redis entries are removed outright.
///   3. Sweep unreferenced blobs (older than `BLOB_GRACE_SECONDS`).
async fn evict(state: &'static State) {
    use std::sync::atomic::Ordering::Relaxed;

    state.metrics.eviction_runs.fetch_add(1, Relaxed);

    // Reclaming memory from eviction is a balancing act. We want to evict enough to get back under the limit,
    // but evicting just barely enough means we'll likely have to run eviction
    let memory_target = state.config.memory_limit.0 - state.config.memory_limit.0 / 4;

    // Per-blob bookkeeping: (in_memory, size, disk_refs, memory_refs, last_accessed).
    let mut disk_usage: u64 = 0;
    let mut memory_usage: u64 = 0;
    let mut blobs: HashMap<Digest, (bool, u64, u32, u32, u64)> = HashMap::new();
    for blob in state.blobs.iter() {
        let (in_memory, size) = match blob.value().as_ref() {
            Blob::InMemory { content, .. } => {
                memory_usage += content.len() as u64;
                (true, content.len() as u64)
            }
            Blob::OnDisk { size, .. } => {
                disk_usage += *size;
                (false, *size)
            }
        };
        let last_accessed = blob.value().last_accessed().load(Relaxed);
        blobs.insert(blob.key().clone(), (in_memory, size, 0, 0, last_accessed));
    }

    // Manifests classified by whether any of their blobs is already on disk.
    let mut disk_manifests: Vec<(u64, Digest)> = Vec::new();
    let mut memory_manifests: Vec<(u64, Digest)> = Vec::new();
    for manifest in state.manifests.iter() {
        let digest = manifest.key();
        let content = &manifest.value().content;
        memory_usage += content.len() as u64;
        let mut on_disk = false;
        for r in referenced_digests(content) {
            if let Some((in_memory, _size, disk_refs, memory_refs, _last)) = blobs.get_mut(&r) {
                if *in_memory {
                    *memory_refs += 1;
                } else {
                    *disk_refs += 1;
                }
                on_disk |= !*in_memory;
            } else {
                // Referenced blob not in cache - likely a foreign layer or
                // already evicted by another manifest in this same pass.
                debug!(%digest, %r, "manifest references missing blob");
            }
        }
        let last_used = manifest.value().last_used.load(Relaxed);
        if on_disk {
            disk_manifests.push((last_used, digest.clone()));
        } else {
            memory_manifests.push((last_used, digest.clone()));
        }
    }

    let mut disk_redis_entries = Vec::new();
    let mut memory_redis_entries = Vec::new();
    for entry in &state.redis_entries {
        match entry.value().as_ref() {
            RedisEntry::InMemory {
                value,
                last_accessed,
                ..
            } => {
                memory_usage += value.len() as u64 + entry.key().len() as u64;
                memory_redis_entries.push((
                    last_accessed.load(Relaxed),
                    entry.key().clone(),
                    value.len() as u64,
                ));
            }
            RedisEntry::OnDisk {
                last_accessed,
                size,
                ..
            } => {
                disk_usage += size;
                // Push the on-disk byte count so the eviction loop below
                // subtracts the right amount from `disk_usage` when this
                // entry is reclaimed.
                disk_redis_entries.push((last_accessed.load(Relaxed), entry.key().clone(), *size));
            }
        }
    }

    // Sort newest first; we `pop()` the oldest from the back.
    disk_manifests.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    memory_manifests.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    disk_redis_entries.sort_by_key(|(t, _, _)| std::cmp::Reverse(*t));
    memory_redis_entries.sort_by_key(|(t, _, _)| std::cmp::Reverse(*t));

    // Evict more aggressively than strictly necessary so we don't thrash on
    // every insert when we're hovering near the limit.
    let disk_target = state.config.disk_limit.0 - state.config.disk_limit.0 / 4;
    let now = state.now.load(Relaxed);

    loop {
        if disk_usage > disk_target {
            if let Some((time, key, size)) = disk_redis_entries.last()
                && disk_manifests
                    .last()
                    .map(|(t, _)| *t > *time)
                    .unwrap_or(true)
            {
                if state.remove_redis(key) {
                    disk_usage = disk_usage.saturating_sub(*size);
                    state.metrics.eviction_redis_entries.fetch_add(1, Relaxed);
                }
                disk_redis_entries.pop();
                continue;
            }
            if let Some((_, victim)) = disk_manifests.pop() {
                // Drop the oldest disk-tier manifest entirely. Any blob whose
                // refcount falls to zero is removed from the cache (and its file
                // deleted if on disk).
                let Some((_, m)) = state.manifests.remove(&victim) else {
                    continue;
                };
                state
                    .metrics
                    .eviction_manifests_deleted
                    .fetch_add(1, Relaxed);
                memory_usage = memory_usage.saturating_sub(m.content.len() as u64);

                for r in referenced_digests(&m.content) {
                    let Some(entry) = blobs.get_mut(&r) else {
                        continue;
                    };
                    let (in_memory, _size, disk_refs, memory_refs, last_accessed) = entry;
                    if *in_memory {
                        *memory_refs = memory_refs.saturating_sub(1);
                    } else {
                        *disk_refs = disk_refs.saturating_sub(1);
                    }
                    if *disk_refs != 0 || *memory_refs != 0 {
                        continue;
                    }
                    if now.saturating_sub(*last_accessed) < BLOB_GRACE_SECONDS {
                        continue;
                    }
                    if let Some((_, b)) = state.blobs.remove(&r) {
                        state.metrics.eviction_blobs_deleted.fetch_add(1, Relaxed);
                        match b.as_ref() {
                            Blob::InMemory { content, .. } => {
                                memory_usage = memory_usage.saturating_sub(content.len() as u64);
                            }
                            Blob::OnDisk { size, id, .. } => {
                                disk_usage = disk_usage.saturating_sub(*size);
                                delete_disk_blob(state, *id).await;
                            }
                        }
                    }
                }
                state.tags.retain(|_, d| d != &victim);
                info!(%victim, memory_usage, disk_usage, "evicted disk-tier manifest");
                continue;
            }
        }

        if memory_usage < memory_target {
            break;
        }

        if let Some((time, key, size)) = memory_redis_entries.last()
            && memory_manifests
                .last()
                .map(|(t, _)| *t > *time)
                .unwrap_or_default()
        {
            if state.remove_redis(key) {
                memory_usage = memory_usage.saturating_sub(*size);
                state.metrics.eviction_redis_entries.fetch_add(1, Relaxed);
            }
            memory_redis_entries.pop();
            continue;
        }

        let Some((_, victim)) = memory_manifests.pop() else {
            break;
        };

        // Push the oldest fully-in-memory manifest's blobs to disk. The
        // manifest itself stays cached; it just gets reclassified.
        let Some(m) = state.manifests.get(&victim).map(|e| e.clone()) else {
            continue;
        };
        let refs = referenced_digests(&m.content);
        let mut moved = 0u64;
        for r in refs {
            let Some(entry) = blobs.get_mut(&r) else {
                continue;
            };
            let (in_memory, size, _disk_refs, memory_refs, _last) = entry;
            if !*in_memory {
                continue;
            }
            // We're evicting `victim` from the in-memory set, so its
            // reference no longer counts towards keeping the blob in RAM.
            *memory_refs = memory_refs.saturating_sub(1);
            // Other in-memory manifests still reference this blob so leave
            // it in RAM so they don't have to hit disk.
            if *memory_refs > 0 {
                continue;
            }
            let Some(cur) = state.blobs.get(&r).map(|e| e.clone()) else {
                continue;
            };
            let Blob::InMemory {
                content,
                media_type,
                last_accessed,
                id,
            } = cur.as_ref()
            else {
                continue;
            };
            let path = match write_blob_to_disk(state, *id, content).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(digest=%r, error=%e, "failed to write blob to disk; keeping in memory");
                    continue;
                }
            };
            let on_disk = Arc::new(Blob::OnDisk {
                size: *size,
                media_type: media_type.clone(),
                last_accessed: AtomicU64::new(last_accessed.load(Relaxed)),
                id: *id,
            });
            state.blobs.insert(r.clone(), on_disk);
            state.metrics.eviction_blobs_to_disk.fetch_add(1, Relaxed);
            memory_usage = memory_usage.saturating_sub(*size);
            disk_usage += *size;
            moved += *size;
            *in_memory = false;
            debug!(digest=%r, bytes=*size, path=%path.display(), "blob moved to disk");
        }
        // We do not put stuff into disk manifests here, so we don't have to resort
        // We can live with more data on disk until the next eviction pass.
        info!(%victim, bytes_moved=moved, memory_usage, disk_usage, "pushed memory manifest to disk");
    }

    // Find unreferenced blobs and remove them from the cache (and disk if applicable).
    // Blobs within the grace window are left alone - they may be a freshly
    // uploaded blob whose manifest hasn't been PUT yet, or a blob a client just
    // HEAD-probed before pushing a referring manifest.
    for (digest, (_, _, disk_refs, memory_refs, last_accessed)) in &blobs {
        if *disk_refs != 0 || *memory_refs != 0 {
            continue;
        }
        if now.saturating_sub(*last_accessed) < BLOB_GRACE_SECONDS {
            continue;
        }
        if let Some((_, b)) = state.blobs.remove(digest) {
            state.metrics.eviction_blobs_deleted.fetch_add(1, Relaxed);
            warn!("blob {} has zero refs but still in cache; removing", digest);
            match b.as_ref() {
                Blob::InMemory { content, .. } => {
                    memory_usage = memory_usage.saturating_sub(content.len() as u64);
                }
                Blob::OnDisk { size, id, .. } => {
                    disk_usage = disk_usage.saturating_sub(*size);
                    delete_disk_blob(state, *id).await;
                }
            }
        }
    }

    state.approx_memory_usage.store(memory_usage, Relaxed);
    state.disk_usage.store(disk_usage, Relaxed);
}

/// Periodic eviction loop. Runs every 30s and triggers `evict` whenever
/// in-memory usage exceeds the configured limit. Returns when `rt` is
/// cancelled.
pub async fn evict_loop(state: &'static State, rt: RunToken) -> Result<(), ()> {
    use std::sync::atomic::Ordering::Relaxed;
    while cancelable(&rt, tokio::time::sleep(std::time::Duration::from_secs(30)))
        .await
        .is_ok()
    {
        let limit = state.config.memory_limit.0;
        let usage = state.approx_memory_usage.load(Relaxed);
        if usage > limit {
            debug!(usage, limit, "running eviction");
            evict(state).await;
        }
    }
    Ok(())
}
