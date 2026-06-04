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
    snapshot::SNAPSHOT_INLINE_THRESHOLD,
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
pub(crate) async fn evict(state: &'static State) {
    use std::sync::atomic::Ordering::Relaxed;

    state.metrics.eviction_runs.fetch_add(1, Relaxed);

    // Reclaming memory from eviction is a balancing act. We want to evict enough to get back under the limit,
    // but evicting just barely enough means we'll likely have to run eviction
    let memory_target = state.config.memory_limit.0 - state.config.memory_limit.0 / 4;

    // Per-blob bookkeeping: (in_memory, size, disk_refs, memory_refs, last_accessed).
    //
    // `in_memory` here means "counts toward the memory budget AND is eligible
    // to be spilled to disk under memory pressure". Small `Blob::InMemory`
    // entries (<= SNAPSHOT_INLINE_THRESHOLD) are intentionally classified as
    // `in_memory = false`: writing them out as tiny files is wasteful, so we
    // instead account their bytes against `disk_usage` and let the disk-tier
    // manifest eviction path delete them in place when they age out.
    let mut disk_usage: u64 = 0;
    let mut memory_usage: u64 = 0;
    // Per-component breakdown and per-tier oldest touch-time, observed at
    // the start of this pass. We don't try to keep these accurate as items
    // get evicted below - we just snapshot them onto `state.metrics` at the
    // very end. `u64::MAX` is the "no items observed" sentinel for oldest.
    let mut memory_docker_bytes: u64 = 0;
    let mut memory_redis_bytes: u64 = 0;
    let mut disk_docker_bytes: u64 = 0;
    let mut disk_redis_bytes: u64 = 0;
    let mut oldest_memory: u64 = u64::MAX;
    let mut oldest_disk: u64 = u64::MAX;
    let mut blobs: HashMap<Digest, (bool, u64, u32, u32, u64)> = HashMap::new();
    for blob in state.blobs.iter() {
        let last_accessed = blob.value().last_accessed().load(Relaxed);
        let (in_memory, size) = match blob.value().as_ref() {
            Blob::InMemory { content, .. } if content.len() > SNAPSHOT_INLINE_THRESHOLD => {
                memory_usage += content.len() as u64;
                memory_docker_bytes += content.len() as u64;
                oldest_memory = oldest_memory.min(last_accessed);
                (true, content.len() as u64)
            }
            Blob::InMemory { content, .. } => {
                // Small in-memory blob: treat as virtually on-disk.
                disk_usage += content.len() as u64;
                disk_docker_bytes += content.len() as u64;
                oldest_disk = oldest_disk.min(last_accessed);
                (false, content.len() as u64)
            }
            Blob::OnDisk { size, .. } => {
                disk_usage += *size;
                disk_docker_bytes += *size;
                oldest_disk = oldest_disk.min(last_accessed);
                (false, *size)
            }
        };
        blobs.insert(blob.key().clone(), (in_memory, size, 0, 0, last_accessed));
    }

    // Manifests classified by whether any of their blobs is already on disk.
    let mut disk_manifests: Vec<(u64, Digest)> = Vec::new();
    let mut memory_manifests: Vec<(u64, Digest)> = Vec::new();
    for manifest in state.manifests.iter() {
        let digest = manifest.key();
        let content = &manifest.value().content;
        memory_usage += content.len() as u64;
        memory_docker_bytes += content.len() as u64;
        let last_used = manifest.value().last_used.load(Relaxed);
        oldest_memory = oldest_memory.min(last_used);
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
            } if value.len() > SNAPSHOT_INLINE_THRESHOLD => {
                let bytes = value.len() as u64 + entry.key().len() as u64;
                memory_usage += bytes;
                memory_redis_bytes += bytes;
                let t = last_accessed.load(Relaxed);
                oldest_memory = oldest_memory.min(t);
                memory_redis_entries.push((t, entry.key().clone(), value.len() as u64));
            }
            RedisEntry::InMemory {
                value,
                last_accessed,
                ..
            } => {
                // Small in-memory redis entry: too small to be worth spilling
                // to disk under memory pressure. Account it against the disk
                // budget so the disk-tier eviction path ages it out.
                let bytes = value.len() as u64 + entry.key().len() as u64;
                disk_usage += bytes;
                disk_redis_bytes += bytes;
                let t = last_accessed.load(Relaxed);
                oldest_disk = oldest_disk.min(t);
                disk_redis_entries.push((t, entry.key().clone(), bytes));
            }
            RedisEntry::OnDisk {
                last_accessed,
                size,
                ..
            } => {
                disk_usage += size;
                disk_redis_bytes += size;
                let t = last_accessed.load(Relaxed);
                oldest_disk = oldest_disk.min(t);
                // Push the on-disk byte count so the eviction loop below
                // subtracts the right amount from `disk_usage` when this
                // entry is reclaimed.
                disk_redis_entries.push((t, entry.key().clone(), *size));
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
                    // Snapshot which budget this blob was charged to before
                    // we move it out of the bookkeeping map.
                    let booked_in_memory = *in_memory;
                    if let Some((_, b)) = state.blobs.remove(&r) {
                        state.metrics.eviction_blobs_deleted.fetch_add(1, Relaxed);
                        match b.as_ref() {
                            Blob::InMemory { content, .. } => {
                                let bytes = content.len() as u64;
                                if booked_in_memory {
                                    memory_usage = memory_usage.saturating_sub(bytes);
                                } else {
                                    // Small in-memory blob accounted as disk.
                                    disk_usage = disk_usage.saturating_sub(bytes);
                                }
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
                .unwrap_or(true)
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
            let (in_memory, size, disk_refs, memory_refs, _last) = entry;
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
            // Victim still lives in `state.manifests` and now references an
            // on-disk blob; record that as a disk-ref so the unreferenced
            // sweep below doesn't immediately delete the blob we just spilled.
            *disk_refs = disk_refs.saturating_add(1);
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
    for (digest, (in_memory, _, disk_refs, memory_refs, last_accessed)) in &blobs {
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
                    let bytes = content.len() as u64;
                    if *in_memory {
                        memory_usage = memory_usage.saturating_sub(bytes);
                    } else {
                        disk_usage = disk_usage.saturating_sub(bytes);
                    }
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

    // Snapshot the per-component breakdown and the oldest touch-times
    // observed at the start of this pass onto the metrics. We don't try to
    // keep these in sync with the evictions that happened in the loop
    // above - same trade-off as `disk_usage`.
    state
        .metrics
        .memory_usage_docker_bytes
        .store(memory_docker_bytes, Relaxed);
    state
        .metrics
        .memory_usage_redis_bytes
        .store(memory_redis_bytes, Relaxed);
    state
        .metrics
        .disk_usage_docker_bytes
        .store(disk_docker_bytes, Relaxed);
    state
        .metrics
        .disk_usage_redis_bytes
        .store(disk_redis_bytes, Relaxed);
    state.metrics.oldest_memory_touch_time.store(
        if oldest_memory == u64::MAX {
            0
        } else {
            oldest_memory
        },
        Relaxed,
    );
    state.metrics.oldest_disk_touch_time.store(
        if oldest_disk == u64::MAX {
            0
        } else {
            oldest_disk
        },
        Relaxed,
    );
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

#[cfg(test)]
mod tests {
    //! Unit tests for the eviction logic.
    //!
    //! These tests construct a self-contained `State` (no background time
    //! updater, no real network) directly via [`make_state`] and drive
    //! [`evict`] synchronously. `state.now` is set manually so the
    //! `BLOB_GRACE_SECONDS` window is deterministic.
    //!
    //! The tests cover three areas:
    //!   * `referenced_digests` JSON-walking (reachability).
    //!   * Redis-only eviction, for both the small-as-disk and large-as-memory
    //!     classifications.
    //!   * Docker blob/manifest eviction, including the in-memory → disk
    //!     spill, the grace window, the multi-manifest refcount, and the
    //!     small-blob "delete in place, no file spill" path.
    use super::*;
    use crate::{
        aligned_atomic::AlignedAtomicU64,
        config::Config,
        digest::Digest,
        metrics::Metrics,
        size::Size,
        snapshot::SNAPSHOT_INLINE_THRESHOLD,
        state::{Blob, Manifest, RedisEntry, State},
    };
    use bytes::Bytes;
    use dashmap::DashMap;
    use sha2::Digest as _;
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering::Relaxed},
        },
    };

    const NOW: u64 = 10_000_000;
    /// Comfortably outside the grace window.
    const OLD: u64 = NOW - BLOB_GRACE_SECONDS - 1;
    /// Comfortably inside the grace window.
    const FRESH: u64 = NOW - 1;

    fn digest_of(bytes: &[u8]) -> Digest {
        let out: [u8; 32] = sha2::Sha256::digest(bytes).into();
        Digest(out)
    }

    fn temp_data_folder(label: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("dockfoxprox-test-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Build a `&'static State` for tests, with no background time updater.
    /// `state.now` is initialised to [`NOW`] and never moves.
    fn make_state(memory_limit: u64, disk_limit: u64, label: &str) -> &'static State {
        let data_folder = temp_data_folder(label);
        let config = Config {
            https_port: None,
            http_port: None,
            data_folder: data_folder.to_string_lossy().into_owned(),
            memory_limit: Size(memory_limit),
            disk_limit: Size(disk_limit),
            docker_user: Vec::new(),
            docker_registry: HashMap::new(),
            redis_port: None,
            redis_password: None,
        };
        Box::leak(Box::new(State {
            tokens: DashMap::new(),
            manifests: DashMap::new(),
            blobs: DashMap::new(),
            tags: DashMap::new(),
            uploads: DashMap::new(),
            config,
            reqwest_client: reqwest::Client::new(),
            now: AlignedAtomicU64::new(NOW),
            approx_memory_usage: AlignedAtomicU64::new(0),
            disk_usage: AlignedAtomicU64::new(0),
            redis_entries: DashMap::new(),
            metrics: Metrics::default(),
            next_id: AlignedAtomicU64::new(0),
        }))
    }

    fn insert_blob_in_memory(state: &'static State, content: Bytes, last_accessed: u64) -> Digest {
        let d = digest_of(&content);
        let id = state.next_id.fetch_add(1, Relaxed);
        state.insert_blob(
            d.clone(),
            Arc::new(Blob::InMemory {
                id,
                content,
                media_type: "application/octet-stream".into(),
                last_accessed: AtomicU64::new(last_accessed),
            }),
        );
        d
    }

    /// Write a blob's bytes to disk and register it as `Blob::OnDisk`.
    async fn insert_blob_on_disk(
        state: &'static State,
        content: Bytes,
        last_accessed: u64,
    ) -> Digest {
        let d = digest_of(&content);
        let id = state.next_id.fetch_add(1, Relaxed);
        let path = state.cache_path(id);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, &content).await.unwrap();
        state.disk_usage.fetch_add(content.len() as u64, Relaxed);
        state.blobs.insert(
            d.clone(),
            Arc::new(Blob::OnDisk {
                id,
                size: content.len() as u64,
                media_type: "application/octet-stream".into(),
                last_accessed: AtomicU64::new(last_accessed),
            }),
        );
        d
    }

    /// Build a v2 image manifest that references `layers` (and a dummy config).
    fn manifest_body(layers: &[&Digest]) -> Bytes {
        let layers_json: Vec<_> = layers
            .iter()
            .map(|d| {
                serde_json::json!({
                    "mediaType": "application/octet-stream",
                    "size": 0,
                    "digest": d.to_string(),
                })
            })
            .collect();
        let v = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            },
            "layers": layers_json,
        });
        Bytes::from(serde_json::to_vec(&v).unwrap())
    }

    fn insert_manifest_(state: &'static State, content: Bytes, last_used: u64) -> Digest {
        let d = digest_of(&content);
        state.insert_manifest(
            d.clone(),
            Arc::new(Manifest {
                content,
                media_type: "application/vnd.docker.distribution.manifest.v2+json".into(),
                last_used: AtomicU64::new(last_used),
            }),
        );
        d
    }

    fn insert_redis(state: &'static State, key: &[u8], value: &[u8], last_accessed: u64) {
        let key = Bytes::copy_from_slice(key);
        let value = Bytes::copy_from_slice(value);
        state.insert_redis(key.clone(), value);
        // Backdate `last_accessed` so eviction sees it as old.
        if let Some(e) = state.redis_entries.get(&key)
            && let RedisEntry::InMemory {
                last_accessed: la, ..
            } = e.value().as_ref()
        {
            la.store(last_accessed, Relaxed);
        }
    }

    fn list_blob_files(state: &State) -> Vec<PathBuf> {
        let dir = PathBuf::from(&state.config.data_folder).join("blobs");
        let mut out = Vec::new();
        fn walk(p: &Path, out: &mut Vec<PathBuf>) {
            let Ok(rd) = std::fs::read_dir(p) else {
                return;
            };
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        walk(&dir, &mut out);
        out
    }

    // ---------------- referenced_digests ----------------

    #[test]
    fn referenced_digests_empty_on_non_json() {
        let out = referenced_digests(&Bytes::from_static(b"not json {{{"));
        assert!(out.is_empty());
    }

    #[test]
    fn referenced_digests_finds_config_and_layers() {
        let l1 = digest_of(b"layer-1");
        let l2 = digest_of(b"layer-2");
        let body = manifest_body(&[&l1, &l2]);
        let out = referenced_digests(&body);
        // Includes the dummy config digest plus the two layers.
        let zero: Digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();
        assert!(out.contains(&l1));
        assert!(out.contains(&l2));
        assert!(out.contains(&zero));
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn referenced_digests_walks_nested_manifest_list() {
        let child1 = digest_of(b"child-1");
        let child2 = digest_of(b"child-2");
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [
                { "digest": child1.to_string(), "platform": { "architecture": "amd64", "os": "linux" }},
                { "digest": child2.to_string(), "platform": { "architecture": "arm64", "os": "linux" }},
            ],
        });
        let body = Bytes::from(serde_json::to_vec(&body).unwrap());
        let out = referenced_digests(&body);
        assert!(out.contains(&child1));
        assert!(out.contains(&child2));
        assert_eq!(out.len(), 2);
    }

    // ---------------- Redis eviction ----------------

    #[tokio::test]
    async fn redis_large_entries_evicted_oldest_first_on_memory_pressure() {
        // Large values (above SNAPSHOT_INLINE_THRESHOLD) are tracked against
        // the memory budget. With memory_limit = 4*big, the 25% slack means
        // target = 3*big, so we expect at least the oldest to be dropped.
        let big_size = SNAPSHOT_INLINE_THRESHOLD + 1024;
        let state = make_state((big_size as u64) * 4, 1024 * 1024 * 1024, "redis-large");
        let big = vec![b'x'; big_size];
        insert_redis(state, b"oldest", &big, OLD);
        insert_redis(state, b"older", &big, OLD + 1);
        insert_redis(state, b"newer", &big, OLD + 2);
        insert_redis(state, b"newest", &big, OLD + 3);
        evict(state).await;
        assert!(!state.redis_entries.contains_key(b"oldest".as_ref()));
        assert!(state.redis_entries.contains_key(b"newest".as_ref()));
    }

    #[tokio::test]
    async fn redis_small_entries_evicted_via_disk_path() {
        // Small values (<= SNAPSHOT_INLINE_THRESHOLD) are virtually-on-disk;
        // they age out through the disk-budget path, not the memory one.
        let small = vec![b'y'; 32];
        let entry_size = (small.len() + b"k_old".len()) as u64;
        let state = make_state(1024 * 1024 * 1024, entry_size * 4, "redis-small");
        insert_redis(state, b"k_old", &small, OLD);
        insert_redis(state, b"k_med", &small, OLD + 1);
        insert_redis(state, b"k_new", &small, OLD + 2);
        insert_redis(state, b"k_now", &small, OLD + 3);
        evict(state).await;
        assert!(!state.redis_entries.contains_key(b"k_old".as_ref()));
        assert!(state.redis_entries.contains_key(b"k_now".as_ref()));
        // No file should have been written - small entries are never spilled.
        assert!(
            list_blob_files(state).is_empty(),
            "small redis entries must not be spilled to disk"
        );
    }

    #[tokio::test]
    async fn redis_on_disk_entry_evicted_deletes_file() {
        // Manually plant an OnDisk redis entry with a real file beneath it,
        // then verify eviction removes both the metadata and the file.
        let state = make_state(1024 * 1024, 8, "redis-ondisk");
        let value = vec![b'z'; 4096];
        let key = Bytes::from_static(b"big-disk-key");
        let id = state.next_id.fetch_add(1, Relaxed);
        let path = state.cache_path(id);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, &value).await.unwrap();
        state.redis_entries.insert(
            key.clone(),
            Arc::new(RedisEntry::OnDisk {
                id,
                size: value.len() as u64,
                last_accessed: AtomicU64::new(OLD),
            }),
        );
        evict(state).await;
        // Give the spawn'd unlink task a moment to run.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!state.redis_entries.contains_key(key.as_ref()));
        assert!(!path.exists(), "on-disk redis file must be unlinked");
    }

    // ---------------- Docker blob / manifest eviction ----------------

    #[tokio::test]
    async fn large_in_memory_blob_spilled_to_disk_under_memory_pressure() {
        let big_size = SNAPSHOT_INLINE_THRESHOLD + 4096;
        let state = make_state(big_size as u64, 1024 * 1024 * 1024, "spill");
        let blob_content = Bytes::from(vec![b'a'; big_size]);
        let blob_digest = insert_blob_in_memory(state, blob_content.clone(), OLD);
        let manifest_body = manifest_body(&[&blob_digest]);
        insert_manifest_(state, manifest_body, OLD);

        evict(state).await;

        // The blob should have been demoted to OnDisk and the bytes written.
        let entry = state.blobs.get(&blob_digest).unwrap();
        let Blob::OnDisk { id, size, .. } = entry.value().as_ref() else {
            panic!("blob was not spilled to disk");
        };
        assert_eq!(*size, blob_content.len() as u64);
        let path = state.cache_path(*id);
        assert!(path.exists(), "spilled blob file must exist on disk");
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, blob_content.as_ref());
    }

    #[tokio::test]
    async fn disk_tier_manifest_aged_out_deletes_blob_file() {
        // 1KB blob already on disk + manifest referencing it. With disk_limit
        // tiny, the disk-tier manifest is dropped, cascading to the blob.
        let state = make_state(1024 * 1024 * 1024, 8, "drop-disk-tier");
        let content = Bytes::from(vec![b'b'; 4096]);
        let blob_digest = insert_blob_on_disk(state, content, OLD).await;
        let blob_path = {
            let entry = state.blobs.get(&blob_digest).unwrap();
            let Blob::OnDisk { id, .. } = entry.value().as_ref() else {
                unreachable!()
            };
            state.cache_path(*id)
        };
        let manifest_body = manifest_body(&[&blob_digest]);
        insert_manifest_(state, manifest_body, OLD);

        assert!(blob_path.exists());
        evict(state).await;

        assert!(!state.blobs.contains_key(&blob_digest));
        assert!(!blob_path.exists(), "on-disk blob file must be unlinked");
    }

    #[tokio::test]
    async fn grace_window_protects_recent_blobs() {
        // Same setup as the disk-tier test, but the blob's last_accessed is
        // inside the grace window. The manifest is still dropped, but the
        // blob must remain.
        let state = make_state(1024 * 1024 * 1024, 8, "grace");
        let content = Bytes::from(vec![b'c'; 4096]);
        let blob_digest = insert_blob_on_disk(state, content, FRESH).await;
        let manifest_body = manifest_body(&[&blob_digest]);
        let manifest_digest = insert_manifest_(state, manifest_body, OLD);

        evict(state).await;

        assert!(
            !state.manifests.contains_key(&manifest_digest),
            "disk-tier manifest should be evicted"
        );
        assert!(
            state.blobs.contains_key(&blob_digest),
            "blob inside grace window must be retained even when unreferenced"
        );
    }

    #[tokio::test]
    async fn shared_blob_kept_while_any_manifest_references_it() {
        // Two in-memory manifests share an in-memory blob. Memory pressure
        // pops them one at a time; while the blob still has memory-refs from
        // the not-yet-popped manifest it must stay in RAM, and once the last
        // ref is popped the blob is spilled (not deleted) and stays in cache
        // courtesy of the disk-ref bookkeeping for the just-popped manifest.
        let big_size = SNAPSHOT_INLINE_THRESHOLD + 4096;
        let state = make_state(big_size as u64, 1024 * 1024 * 1024, "shared");
        let blob_content = Bytes::from(vec![b'd'; big_size]);
        let blob_digest = insert_blob_in_memory(state, blob_content, OLD);
        let m1 = insert_manifest_(state, manifest_body(&[&blob_digest]), OLD);
        let m2 = insert_manifest_(state, manifest_body(&[&blob_digest]), OLD + 1);

        evict(state).await;

        // Both manifests are still in the cache (memory eviction only spills
        // their blobs; it does not delete manifests).
        assert!(state.manifests.contains_key(&m1));
        assert!(state.manifests.contains_key(&m2));
        // The shared blob has been spilled, not deleted.
        let entry = state.blobs.get(&blob_digest).expect("blob must survive");
        assert!(
            matches!(entry.value().as_ref(), Blob::OnDisk { .. }),
            "blob should have been demoted to disk"
        );
    }

    #[tokio::test]
    async fn small_in_memory_blob_not_spilled_but_deleted_in_place() {
        // Below the inline threshold the eviction code must NOT write the
        // blob out as a tiny file; instead it accounts against the disk
        // budget and deletes the blob from RAM when its manifest ages out.
        let state = make_state(1024 * 1024 * 1024, 8, "tiny");
        let blob_content = Bytes::from(vec![b'e'; 64]); // well below threshold
        let blob_digest = insert_blob_in_memory(state, blob_content, OLD);
        let manifest_body = manifest_body(&[&blob_digest]);
        insert_manifest_(state, manifest_body, OLD);

        evict(state).await;

        assert!(
            !state.blobs.contains_key(&blob_digest),
            "small blob should be deleted alongside its disk-tier manifest"
        );
        assert!(
            list_blob_files(state).is_empty(),
            "small in-memory blob must not be spilled to a file"
        );
    }
}
