use std::{
    collections::{BinaryHeap, HashMap},
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio_tasks::{RunToken, cancelable};
use tracing::{debug, warn};

use crate::{
    digest::Digest,
    state::{Blob, MEMORY_TIER_THRESHOLD, RedisEntry, State},
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
/// Three budgets are enforced, in priority order:
///
///   * **Small pool** (`small_memory_limit`): the sum of in-memory small
///     items - manifests, small blobs, small redis entries - must fit
///     under the small reservation. Freed by dropping whole manifests
///     (cascading to their referenced blobs) or dropping small redis
///     entries.
///   * **Total memory** (`memory_limit`): the sum of every in-memory item
///     must fit under the total memory budget. The "large pool" is just
///     `memory_limit - small_used`; there is no fixed large reservation.
///     Freed by spilling a memory-tier manifest's large blobs to disk
///     (the manifest itself stays cached) or by dropping large redis
///     entries. If the small pool overruns and cannot be reduced, large
///     blobs will eventually get spilled to keep the total under budget.
///   * **Disk** (`disk_limit`): on-disk blobs plus on-disk redis entries
///     must fit. Freed by dropping a disk-tier manifest (cascading) or an
///     on-disk redis entry.
///
/// All three checks share a single eviction loop: each iteration picks
/// the most-overrun budget, pops the oldest candidate eligible for that
/// budget, and either drops (manifests + redis) or spills (large blobs of
/// a memory-tier manifest). A manifest may appear in more than one
/// candidate heap; the heaps are independent and stale entries are
/// skipped on pop.
///
/// After the loop, a final sweep deletes any blobs whose refcount fell
/// to zero (provided they're outside `BLOB_GRACE_SECONDS`).
pub(crate) async fn evict(state: &'static State) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    state.metrics.eviction_runs.fetch_add(1, Relaxed);
    let now = state.now.load(Relaxed);

    let mut small_blob_memory = 0;
    let mut large_blob_memory = 0;
    let mut blob_disk = 0;
    let mut small_redis_memory = 0;
    let mut large_redis_memory = 0;
    let mut redis_disk = 0;
    let mut manifest_memory = 0;

    enum EvictionCandidate {
        Manifest {
            last_accesses: u64,
            digest: Digest,
        },
        Redis {
            key: Bytes,
            last_accessed: u64,
            size: u64,
        },
    }

    impl EvictionCandidate {
        fn last_access_time(&self) -> u64 {
            match self {
                EvictionCandidate::Manifest { last_accesses, .. } => *last_accesses,
                EvictionCandidate::Redis { last_accessed, .. } => *last_accessed,
            }
        }
    }

    impl PartialEq for EvictionCandidate {
        fn eq(&self, other: &Self) -> bool {
            self.last_access_time() == other.last_access_time()
        }
    }
    impl Eq for EvictionCandidate {}
    /// Compare newest first so the BinaryHeap pops the oldest candidate.
    impl Ord for EvictionCandidate {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            other.last_access_time().cmp(&self.last_access_time())
        }
    }
    impl PartialOrd for EvictionCandidate {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    let mut small_memory_candidates = BinaryHeap::new();
    let mut large_memory_candidates = BinaryHeap::new();
    let mut disk_candidates = BinaryHeap::new();

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    enum BlobTier {
        SmallMem,
        LargeMem,
        Disk,
    }

    /// Per-blob bookkeeping for a single eviction pass.
    struct BlobBk {
        tier: BlobTier,
        refs: u32,
        unevicted_refs: u32,
        last_accessed: u64,
    }

    // We do not reap blobs directly, instead manifests
    // can be evicted or spilled, and the blobs they reference are decref'd and
    let mut blobs: HashMap<Digest, BlobBk> = HashMap::with_capacity(state.blobs.len());
    for b in state.blobs.iter() {
        let last_accessed = b.value().last_accessed().load(Relaxed);
        let (tier, size) = match b.value().as_ref() {
            Blob::InMemory { content, .. } if content.len() > MEMORY_TIER_THRESHOLD => {
                (BlobTier::LargeMem, content.len() as u64)
            }
            Blob::InMemory { content, .. } => (BlobTier::SmallMem, content.len() as u64),
            Blob::OnDisk { size, .. } => (BlobTier::Disk, *size),
        };
        match tier {
            BlobTier::SmallMem => small_blob_memory += size,
            BlobTier::LargeMem => large_blob_memory += size,
            BlobTier::Disk => blob_disk += size,
        }
        blobs.insert(
            b.key().clone(),
            BlobBk {
                tier,
                refs: 0,
                unevicted_refs: 0,
                last_accessed,
            },
        );
    }

    for m in state.manifests.iter() {
        let content = &m.value().content;
        let size = content.len() as u64;
        let last_used = m.value().last_used.load(Relaxed);
        let refs = referenced_digests(content);
        let mut some_in_large_memory = false;
        let mut some_on_disk = false;
        let evicted = m.value().evicted.load(Relaxed);
        for r in &refs {
            if let Some(bb) = blobs.get_mut(r) {
                bb.refs += 1;
                if !evicted {
                    bb.unevicted_refs += 1;
                }
                some_on_disk |= bb.tier == BlobTier::Disk;
                some_in_large_memory |= bb.tier == BlobTier::LargeMem;
            } else {
                debug!(digest=%m.key(), %r, "manifest references missing blob");
            }
        }
        // We can always evict a manifest completely
        small_memory_candidates.push(EvictionCandidate::Manifest {
            last_accesses: last_used,
            digest: m.key().clone(),
        });
        // If a manifest references any large-memory blobs, it can be spilled to disk under large-pool pressure; if so, track it as a candidate.
        if some_in_large_memory {
            large_memory_candidates.push(EvictionCandidate::Manifest {
                last_accesses: last_used,
                digest: m.key().clone(),
            });
        }
        // If a manifest references any on-disk blobs, it can be dropped under disk-pool pressure; if so, track it as a candidate.
        if some_on_disk {
            disk_candidates.push(EvictionCandidate::Manifest {
                last_accesses: last_used,
                digest: m.key().clone(),
            });
        }
        manifest_memory += size;
    }

    for e in state.redis_entries.iter() {
        // We always keep the key in memory, so count its size against the memory pools.
        small_redis_memory += e.key().len() as u64;
        match e.value().as_ref() {
            RedisEntry::InMemory {
                value,
                last_accessed,
                id,
            } if value.len() > MEMORY_TIER_THRESHOLD => {
                large_memory_candidates.push(EvictionCandidate::Redis {
                    key: e.key().clone(),
                    last_accessed: last_accessed.load(Relaxed),
                    size: value.len() as u64,
                });
                large_redis_memory += value.len() as u64;
            }
            RedisEntry::InMemory {
                value,
                last_accessed,
                ..
            } => {
                small_memory_candidates.push(EvictionCandidate::Redis {
                    key: e.key().clone(),
                    last_accessed: last_accessed.load(Relaxed),
                    size: value.len() as u64,
                });
                small_redis_memory += value.len() as u64;
            }
            RedisEntry::OnDisk {
                size,
                last_accessed,
                ..
            } => {
                disk_candidates.push(EvictionCandidate::Redis {
                    key: e.key().clone(),
                    last_accessed: last_accessed.load(Relaxed),
                    size: *size,
                });
                redis_disk += *size;
            }
        };
    }

    // Lets evict to 75% of each pool limit so we don't immediately re-trip the threshold on the very next insert.
    let small_target = state.config.small_memory_limit() - state.config.small_memory_limit() / 4;
    let memory_target = state.config.memory_limit.0 - state.config.memory_limit.0 / 4;
    let disk_target = state.config.disk_limit.0 - state.config.disk_limit.0 / 4;

    loop {
        let drop_manifest_digest = if small_blob_memory + small_redis_memory + manifest_memory
            > small_target
            && let Some(candidate) = small_memory_candidates.pop()
        {
            match candidate {
                EvictionCandidate::Manifest { digest, .. } => digest,
                EvictionCandidate::Redis { key, size, .. } => {
                    if state.remove_redis(&key) {
                        small_redis_memory = small_redis_memory.saturating_sub(size);
                        state.metrics.eviction_redis_entries.fetch_add(1, Relaxed);
                    }
                    continue;
                }
            }
        } else if large_blob_memory
            + large_redis_memory
            + manifest_memory
            + small_blob_memory
            + small_redis_memory
            > memory_target
            && let Some(candidate) = large_memory_candidates.pop()
        {
            match candidate {
                EvictionCandidate::Manifest {
                    last_accesses,
                    digest,
                } => {
                    let Some(mb) = state.manifests.get(&digest) else {
                        continue;
                    };
                    let old = mb.evicted.swap(true, Relaxed);
                    for r in referenced_digests(&mb.content) {
                        let Some(bb) = blobs.get_mut(&r) else {
                            continue;
                        };
                        if !old {
                            // This manifest has not yet been evicted, so this blob's unevicted_refs is still accurate and must be decremented.
                            bb.unevicted_refs = bb.unevicted_refs.saturating_sub(1);
                        }
                        // Only spill blobs that are exclusively reachable
                        // from already-evicted manifests, and only the
                        // large in-memory ones (small blobs would just
                        // produce wasteful tiny files; on-disk ones are
                        // already where we want them). The grace window
                        // does not apply here: spilling preserves the
                        // bytes, it just moves them to disk.
                        if bb.unevicted_refs != 0 || bb.tier != BlobTier::LargeMem {
                            continue;
                        }
                        let Some(blob) = state.blobs.get(&r).map(|e| e.value().clone()) else {
                            continue;
                        };
                        let Blob::InMemory {
                            content,
                            media_type,
                            id,
                            last_accessed,
                        } = blob.as_ref()
                        else {
                            continue;
                        };
                        let size = content.len() as u64;
                        write_blob_to_disk(state, *id, content)
                            .await
                            .with_context(|| format!("Failed to write blob {} to disk", r))?;
                        let on_disk = Arc::new(Blob::OnDisk {
                            size,
                            media_type: media_type.clone(),
                            last_accessed: AtomicU64::new(last_accessed.load(Relaxed)),
                            id: *id,
                        });
                        state.insert_blob(r.clone(), on_disk);
                        state.metrics.eviction_blobs_to_disk.fetch_add(1, Relaxed);
                        large_blob_memory = large_blob_memory.saturating_sub(size);
                        blob_disk = blob_disk.saturating_add(size);
                    }
                    // The manifest can now possible be evicted from disk
                    disk_candidates.push(EvictionCandidate::Manifest {
                        last_accesses,
                        digest,
                    });
                }
                EvictionCandidate::Redis {
                    key,
                    size,
                    last_accessed,
                } => {
                    // Large redis entries are spilled to disk.
                    let Some(val) = state.redis_entries.get(&key).map(|e| e.value().clone()) else {
                        continue;
                    };
                    let RedisEntry::InMemory { value, id, .. } = val.as_ref() else {
                        continue;
                    };
                    write_blob_to_disk(state, *id, value)
                        .await
                        .with_context(|| {
                            format!("Failed to write redis entry {:?} to disk", key)
                        })?;
                    state.redis_entries.insert(
                        key.clone(),
                        Arc::new(RedisEntry::OnDisk {
                            size,
                            last_accessed: AtomicU64::new(last_accessed),
                            id: *id,
                        }),
                    );
                    large_redis_memory = large_redis_memory.saturating_sub(size);
                    redis_disk = redis_disk.saturating_add(size);
                    state.metrics.eviction_redis_entries.fetch_add(1, Relaxed);
                    // Now eligible to be reaped under disk pressure.
                    disk_candidates.push(EvictionCandidate::Redis {
                        key,
                        size,
                        last_accessed,
                    });
                }
            }
            continue;
        } else if blob_disk + redis_disk > disk_target
            && let Some(candidate) = disk_candidates.pop()
        {
            match candidate {
                EvictionCandidate::Manifest { digest, .. } => digest,
                EvictionCandidate::Redis { key, size, .. } => {
                    if state.remove_redis(&key) {
                        redis_disk = redis_disk.saturating_sub(size);
                        state.metrics.eviction_redis_entries.fetch_add(1, Relaxed);
                    }
                    continue;
                }
            }
        } else {
            // There is nothing left to evict
            break;
        };

        // Drop the manifest, cascading to any blob whose last referrer it
        // was. We go through `state.remove_manifest`/`state.remove_blob`
        // so the seven incremental buckets on `State` stay in sync; the
        // local accumulators above are only used to drive the loop's
        // over-target checks.
        let Some(manifest) = state.remove_manifest(&drop_manifest_digest) else {
            continue;
        };
        state
            .metrics
            .eviction_manifests_deleted
            .fetch_add(1, Relaxed);
        manifest_memory = manifest_memory.saturating_sub(manifest.content.len() as u64);
        state.tags.retain(|_, d| d != &drop_manifest_digest);
        let old = manifest.evicted.swap(true, Relaxed);
        for r in referenced_digests(&manifest.content) {
            let Some(bb) = blobs.get_mut(&r) else {
                continue;
            };
            if !old {
                // This manifest has not yet been evicted, so this blob's unevicted_refs is still accurate and must be decremented.
                bb.unevicted_refs = bb.unevicted_refs.saturating_sub(1);
            }
            bb.refs = bb.refs.saturating_sub(1);
            if bb.refs != 0 || bb.last_accessed > now.saturating_sub(BLOB_GRACE_SECONDS) {
                continue;
            }
            let Some(blob) = state.remove_blob(&r) else {
                continue;
            };
            state.metrics.eviction_blobs_deleted.fetch_add(1, Relaxed);
            match blob.as_ref() {
                Blob::InMemory { content, .. } => {
                    if content.len() > MEMORY_TIER_THRESHOLD {
                        large_blob_memory = large_blob_memory.saturating_sub(content.len() as u64);
                    } else {
                        small_blob_memory = small_blob_memory.saturating_sub(content.len() as u64);
                    }
                }
                Blob::OnDisk { size, id, .. } => {
                    blob_disk = blob_disk.saturating_sub(*size);
                    delete_disk_blob(state, *id).await;
                }
            }
        }
    }

    // Unreferenced sweep. Picks up blobs that lost all refs without
    // being directly dropped - the typical case is a freshly-uploaded
    // blob whose only manifest was inside the grace window when it got
    // dropped, so the cascade intentionally kept the blob behind.
    for (digest, bb) in &blobs {
        if bb.refs != 0 || now.saturating_sub(bb.last_accessed) < BLOB_GRACE_SECONDS {
            continue;
        }
        if let Some(b) = state.remove_blob(digest) {
            state.metrics.eviction_blobs_deleted.fetch_add(1, Relaxed);
            warn!("blob {} has zero refs but still in cache; removing", digest);
            if let Blob::OnDisk { id, .. } = b.as_ref() {
                delete_disk_blob(state, *id).await;
            }
        }
    }

    // The remaining candidates in each heap are still cached items the
    // loop chose not to evict. Their oldest entry is, by construction,
    // the oldest live item in that pool - publish it for observability.
    state.metrics.oldest_small_memory_touch_time.store(
        small_memory_candidates
            .pop()
            .map(|c| c.last_access_time())
            .unwrap_or(now),
        Relaxed,
    );
    state.metrics.oldest_large_memory_touch_time.store(
        large_memory_candidates
            .pop()
            .map(|c| c.last_access_time())
            .unwrap_or(now),
        Relaxed,
    );
    state.metrics.oldest_disk_touch_time.store(
        disk_candidates
            .pop()
            .map(|c| c.last_access_time())
            .unwrap_or(now),
        Relaxed,
    );

    state
        .small_blob_memory_usage
        .store(small_blob_memory as i64, Relaxed);
    state
        .large_blob_memory_usage
        .store(large_blob_memory as i64, Relaxed);
    state.blob_disk_usage.store(blob_disk as i64, Relaxed);
    state
        .small_redis_memory_usage
        .store(small_redis_memory as i64, Relaxed);
    state
        .large_redis_memory_usage
        .store(large_redis_memory as i64, Relaxed);
    state.redis_disk_usage.store(redis_disk as i64, Relaxed);

    Ok(())
}

/// Periodic eviction loop. Wakes on `state.eviction_notify` (signalled by
/// every `insert_*` helper) or every 30s as a backstop, runs `evict`
/// whenever any of the three pools is over its limit, then sleeps a short
/// cool-down period so a burst of follow-up inserts coalesces into the
/// next pass instead of spinning. Returns when `rt` is cancelled.
pub async fn evict_loop(state: &'static State, rt: RunToken) -> Result<()> {
    /// How long to wait after an eviction pass before consulting the
    /// notify again. Without this, a flood of `insert_*` calls right
    /// after we finish would re-trigger us immediately.
    const COOLDOWN: std::time::Duration = std::time::Duration::from_secs(1);
    /// Backstop timeout - we always re-check the limits at least this
    /// often even when nothing notifies us, so manual snapshot loads or
    /// clock-driven changes still get reacted to.
    const BACKSTOP: std::time::Duration = std::time::Duration::from_secs(30);

    loop {
        let wait = async {
            tokio::select! {
                _ = state.eviction_notify.notified() => {}
                _ = tokio::time::sleep(BACKSTOP) => {}
            }
        };
        if cancelable(&rt, wait).await.is_err() {
            break;
        }
        let small = state.small_memory_usage();
        let total = state.total_memory_usage();
        let disk = state.total_disk_usage();
        let small_limit = state.config.small_memory_limit();
        let memory_limit = state.config.memory_limit.0;
        let disk_limit = state.config.disk_limit.0;
        if small > small_limit as i64 || total > memory_limit as i64 || disk > disk_limit as i64 {
            debug!(
                small,
                total, disk, small_limit, memory_limit, disk_limit, "running eviction"
            );
            evict(state).await.context("Evict")?;
        }
        if cancelable(&rt, tokio::time::sleep(COOLDOWN)).await.is_err() {
            break;
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
        aligned_atomic::{AlignedAtomicI64, AlignedAtomicU64},
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
            atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
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
        make_state_full(memory_limit, None, disk_limit, label)
    }

    /// Like [`make_state`] but lets the test override `small_memory_limit`
    /// directly (rather than the default of `memory_limit / 8`).
    fn make_state_full(
        memory_limit: u64,
        small_memory_limit: Option<u64>,
        disk_limit: u64,
        label: &str,
    ) -> &'static State {
        let data_folder = temp_data_folder(label);
        let config = Config {
            https_port: None,
            http_port: None,
            data_folder: data_folder.to_string_lossy().into_owned(),
            memory_limit: Size(memory_limit),
            small_memory_limit: small_memory_limit.map(Size),
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
            eviction_notify: tokio::sync::Notify::new(),
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
        state.insert_blob(
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
                evicted: AtomicBool::new(false),
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
    async fn redis_large_entries_spilled_to_disk_under_memory_pressure() {
        // Large values (above MEMORY_TIER_THRESHOLD) are tracked against
        // the large-memory pool. With memory_limit = 4*big the 25% slack
        // gives target = 3*big, so we expect at least the oldest to move
        // to disk. The entries themselves remain in `redis_entries` -
        // they just transition from `InMemory` to `OnDisk`, with the
        // value bytes written to `cache_path(id)`.
        let big_size = SNAPSHOT_INLINE_THRESHOLD + 1024;
        let state = make_state((big_size as u64) * 4, 1024 * 1024 * 1024, "redis-large");
        let big = vec![b'x'; big_size];
        insert_redis(state, b"oldest", &big, OLD);
        insert_redis(state, b"older", &big, OLD + 1);
        insert_redis(state, b"newer", &big, OLD + 2);
        insert_redis(state, b"newest", &big, OLD + 3);
        evict(state).await.unwrap();

        // All four keys are still present; the oldest one has been spilled.
        let entry = state
            .redis_entries
            .get(b"oldest".as_ref())
            .expect("oldest key must still be in the map after spill");
        let RedisEntry::OnDisk { id, size, .. } = entry.value().as_ref() else {
            panic!("oldest large redis entry should have been spilled to disk");
        };
        assert_eq!(*size, big_size as u64);
        let path = state.cache_path(*id);
        assert!(path.exists(), "spilled redis value must exist on disk");
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, big);

        // The newest entry stays in memory.
        let newest = state.redis_entries.get(b"newest".as_ref()).unwrap();
        assert!(matches!(
            newest.value().as_ref(),
            RedisEntry::InMemory { .. }
        ));
    }

    #[tokio::test]
    async fn redis_large_entries_dropped_when_disk_also_tight() {
        // Same shape as the spill test but with a tiny disk budget: the
        // spilled entry should immediately be reaped under disk pressure
        // in the same eviction pass, so the oldest key disappears from
        // the map entirely (and its on-disk file is unlinked).
        let big_size = SNAPSHOT_INLINE_THRESHOLD + 1024;
        let state = make_state((big_size as u64) * 4, 8, "redis-large-tight-disk");
        let big = vec![b'x'; big_size];
        insert_redis(state, b"oldest", &big, OLD);
        insert_redis(state, b"older", &big, OLD + 1);
        insert_redis(state, b"newer", &big, OLD + 2);
        insert_redis(state, b"newest", &big, OLD + 3);
        evict(state).await.unwrap();
        // Give the spawn'd unlink from `remove_redis` a moment to run.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!state.redis_entries.contains_key(b"oldest".as_ref()));
        assert!(state.redis_entries.contains_key(b"newest".as_ref()));
        // No leftover spill files for the dropped entry.
        let files = list_blob_files(state);
        assert!(
            files.is_empty(),
            "spilled-then-reaped redis files should be unlinked, got {files:?}"
        );
    }

    #[tokio::test]
    async fn redis_small_entries_evicted_under_small_pool_pressure() {
        // Small values (<= MEMORY_TIER_THRESHOLD) are charged to the
        // in-memory small pool. They age out when the small pool
        // overruns; they are never written to disk.
        let small = vec![b'y'; 32];
        let entry_size = (small.len() + b"k_old".len()) as u64;
        let state = make_state_full(
            1024 * 1024 * 1024,
            Some(entry_size * 3),
            1024 * 1024 * 1024,
            "redis-small",
        );
        insert_redis(state, b"k_old", &small, OLD);
        insert_redis(state, b"k_med", &small, OLD + 1);
        insert_redis(state, b"k_new", &small, OLD + 2);
        insert_redis(state, b"k_now", &small, OLD + 3);
        evict(state).await.unwrap();
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
        evict(state).await.unwrap();
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

        evict(state).await.unwrap();

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
        evict(state).await.unwrap();

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

        evict(state).await.unwrap();

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

        evict(state).await.unwrap();

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
        // blob out as a tiny file; instead it is reclaimed by dropping its
        // manifest under small-pool pressure, and removed from RAM as
        // part of the cascade.
        let blob_content = Bytes::from(vec![b'e'; 64]); // well below threshold
        let state = make_state_full(1024 * 1024 * 1024, Some(64), 1024 * 1024 * 1024, "tiny");
        let blob_digest = insert_blob_in_memory(state, blob_content, OLD);
        let manifest_body = manifest_body(&[&blob_digest]);
        insert_manifest_(state, manifest_body, OLD);

        evict(state).await.unwrap();

        assert!(
            !state.blobs.contains_key(&blob_digest),
            "small blob should be deleted when its manifest is dropped"
        );
        assert!(
            list_blob_files(state).is_empty(),
            "small in-memory blob must not be spilled to a file"
        );
    }
}
