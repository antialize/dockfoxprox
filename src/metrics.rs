//! Hand-rolled Prometheus-style metrics. We don't pull in a metrics crate
//! because the set of counters is small and label-free: one `AtomicU64` per
//! concept, rendered as text on `/metrics`.
use std::sync::atomic::Ordering::Relaxed;

use crate::{aligned_atomic::AlignedAtomicU64, state::State};

#[derive(Default)]
pub struct Metrics {
    // -- Docker registry endpoints -------------------------------------------
    pub docker_manifest_get: AlignedAtomicU64,
    pub docker_manifest_head: AlignedAtomicU64,
    pub docker_manifest_put: AlignedAtomicU64,
    pub docker_manifest_cache_hit: AlignedAtomicU64,
    pub docker_manifest_cache_miss: AlignedAtomicU64,

    pub docker_blob_get: AlignedAtomicU64,
    pub docker_blob_head: AlignedAtomicU64,
    pub docker_blob_cache_hit_memory: AlignedAtomicU64,
    pub docker_blob_cache_hit_disk: AlignedAtomicU64,
    pub docker_blob_cache_miss: AlignedAtomicU64,

    pub docker_blob_upload_post: AlignedAtomicU64,
    pub docker_blob_upload_patch: AlignedAtomicU64,
    pub docker_blob_upload_put: AlignedAtomicU64,
    pub docker_blob_upload_delete: AlignedAtomicU64,

    pub docker_auth_failures: AlignedAtomicU64,
    pub docker_upstream_requests: AlignedAtomicU64,
    pub docker_upstream_errors: AlignedAtomicU64,

    // -- Redis protocol server -----------------------------------------------
    pub redis_connections: AlignedAtomicU64,
    pub redis_commands: AlignedAtomicU64,
    pub redis_get_hit: AlignedAtomicU64,
    pub redis_get_miss: AlignedAtomicU64,
    pub redis_set: AlignedAtomicU64,
    pub redis_del: AlignedAtomicU64,
    pub redis_auth_failures: AlignedAtomicU64,

    // -- Eviction ------------------------------------------------------------
    pub eviction_runs: AlignedAtomicU64,
    pub eviction_blobs_to_disk: AlignedAtomicU64,
    pub eviction_blobs_deleted: AlignedAtomicU64,
    pub eviction_manifests_deleted: AlignedAtomicU64,
    pub eviction_redis_entries: AlignedAtomicU64,

    // -- Usage breakdown (refreshed only by the eviction pass) ---------------
    //
    // The seven bytes-per-bucket gauges live on `State` and are updated
    // incrementally on every insert/remove, so they're always live. The
    // three `oldest_*_touch_time` gauges below are snapshots taken at
    // the end of every `evict()` and may lag reality between passes.
    /// Unix seconds. Oldest `last_accessed` across small-pool items
    /// (manifests, small in-memory blobs, small in-memory redis). 0 = none.
    pub oldest_small_memory_touch_time: AlignedAtomicU64,
    /// Unix seconds. Oldest `last_accessed` across large-pool items
    /// (large in-memory blobs, large in-memory redis). 0 = none.
    pub oldest_large_memory_touch_time: AlignedAtomicU64,
    /// Unix seconds. Oldest `last_accessed` across disk-pool items
    /// (on-disk blobs, on-disk redis). 0 = none.
    pub oldest_disk_touch_time: AlignedAtomicU64,
}

/// Render the metrics in Prometheus text exposition format.
pub fn render(state: &State) -> String {
    let m = &state.metrics;
    let mut out = String::with_capacity(4096);

    // Gauges sourced from the live bucket counters on `State`. These are
    // maintained incrementally on every insert/remove plus reconciled at
    // the end of every eviction pass.
    gauge(
        &mut out,
        "dockfoxprox_memory_usage_bytes",
        "Total in-memory cache size (manifests + blobs + redis entries).",
        state.total_memory_usage().max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_small_memory_usage_bytes",
        "Small-pool memory usage (manifests + small blobs + small redis entries).",
        state.small_memory_usage().max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_large_memory_usage_bytes",
        "Large-pool memory usage (large in-memory blobs + large redis entries).",
        state.large_memory_usage().max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_disk_usage_bytes",
        "Total on-disk cache size (blobs + redis entries).",
        state.total_disk_usage().max(0) as u64,
    );
    // Per-bucket breakdown of all seven mutually-exclusive accounting buckets.
    gauge(
        &mut out,
        "dockfoxprox_manifest_memory_usage_bytes",
        "Bytes of manifest content held in memory.",
        state.manifest_memory_usage.load(Relaxed).max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_small_blob_memory_usage_bytes",
        "Bytes of small in-memory blob content (at or below the small/large threshold).",
        state.small_blob_memory_usage.load(Relaxed).max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_large_blob_memory_usage_bytes",
        "Bytes of large in-memory blob content (above the small/large threshold).",
        state.large_blob_memory_usage.load(Relaxed).max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_small_redis_memory_usage_bytes",
        "Bytes of small in-memory redis entries (key + value, value at or below the threshold).",
        state.small_redis_memory_usage.load(Relaxed).max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_large_redis_memory_usage_bytes",
        "Bytes of large in-memory redis entries (key + value, value above the threshold).",
        state.large_redis_memory_usage.load(Relaxed).max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_blob_disk_usage_bytes",
        "Bytes of blob content stored on disk.",
        state.blob_disk_usage.load(Relaxed).max(0) as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_redis_disk_usage_bytes",
        "Bytes of redis-protocol entries stored on disk.",
        state.redis_disk_usage.load(Relaxed).max(0) as u64,
    );
    // Oldest touch-time across each pool. 0 means no items in that pool
    // at the most recent eviction pass.
    gauge(
        &mut out,
        "dockfoxprox_oldest_small_memory_touch_time_seconds",
        "Unix time of the oldest last_accessed across small-pool items (0 if none).",
        m.oldest_small_memory_touch_time.load(Relaxed),
    );
    gauge(
        &mut out,
        "dockfoxprox_oldest_large_memory_touch_time_seconds",
        "Unix time of the oldest last_accessed across large-pool items (0 if none).",
        m.oldest_large_memory_touch_time.load(Relaxed),
    );
    gauge(
        &mut out,
        "dockfoxprox_oldest_disk_touch_time_seconds",
        "Unix time of the oldest last_accessed across disk-pool items (0 if none).",
        m.oldest_disk_touch_time.load(Relaxed),
    );
    gauge(
        &mut out,
        "dockfoxprox_memory_limit_bytes",
        "Configured total memory budget.",
        state.config.memory_limit.0,
    );
    gauge(
        &mut out,
        "dockfoxprox_small_memory_limit_bytes",
        "Configured small-pool reservation within the memory budget.",
        state.config.small_memory_limit(),
    );
    gauge(
        &mut out,
        "dockfoxprox_disk_limit_bytes",
        "Configured on-disk budget.",
        state.config.disk_limit.0,
    );
    gauge(
        &mut out,
        "dockfoxprox_blobs_cached",
        "Number of blobs currently in the cache (memory + disk).",
        state.blobs.len() as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_manifests_cached",
        "Number of manifests currently in the cache.",
        state.manifests.len() as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_tags_cached",
        "Number of `self`-host tag mappings.",
        state.tags.len() as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_uploads_in_progress",
        "Number of in-flight blob uploads.",
        state.uploads.len() as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_redis_entries",
        "Number of entries in the Redis-protocol cache.",
        state.redis_entries.len() as u64,
    );
    gauge(
        &mut out,
        "dockfoxprox_upstream_tokens_cached",
        "Number of cached upstream bearer tokens.",
        state.tokens.len() as u64,
    );

    counter(
        &mut out,
        "dockfoxprox_docker_manifest_get_total",
        "Manifest GET requests served.",
        m.docker_manifest_get.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_manifest_head_total",
        "Manifest HEAD requests served.",
        m.docker_manifest_head.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_manifest_put_total",
        "Manifest PUT requests served.",
        m.docker_manifest_put.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_manifest_cache_hit_total",
        "Manifest lookups served from cache.",
        m.docker_manifest_cache_hit.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_manifest_cache_miss_total",
        "Manifest lookups that required an upstream fetch.",
        m.docker_manifest_cache_miss.load(Relaxed),
    );

    counter(
        &mut out,
        "dockfoxprox_docker_blob_get_total",
        "Blob GET requests served.",
        m.docker_blob_get.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_blob_head_total",
        "Blob HEAD requests served.",
        m.docker_blob_head.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_blob_cache_hit_memory_total",
        "Blob lookups served from the in-memory tier.",
        m.docker_blob_cache_hit_memory.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_blob_cache_hit_disk_total",
        "Blob lookups served from the on-disk tier.",
        m.docker_blob_cache_hit_disk.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_blob_cache_miss_total",
        "Blob lookups that required an upstream fetch.",
        m.docker_blob_cache_miss.load(Relaxed),
    );

    counter(
        &mut out,
        "dockfoxprox_docker_blob_upload_post_total",
        "Blob upload sessions started (POST).",
        m.docker_blob_upload_post.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_blob_upload_patch_total",
        "Blob upload chunks received (PATCH).",
        m.docker_blob_upload_patch.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_blob_upload_put_total",
        "Blob upload sessions finalised (PUT).",
        m.docker_blob_upload_put.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_blob_upload_delete_total",
        "Blob upload sessions cancelled (DELETE).",
        m.docker_blob_upload_delete.load(Relaxed),
    );

    counter(
        &mut out,
        "dockfoxprox_docker_auth_failures_total",
        "Authentication failures against the docker endpoint.",
        m.docker_auth_failures.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_upstream_requests_total",
        "Requests sent to upstream registries.",
        m.docker_upstream_requests.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_docker_upstream_errors_total",
        "Upstream requests that failed at the transport layer.",
        m.docker_upstream_errors.load(Relaxed),
    );

    counter(
        &mut out,
        "dockfoxprox_redis_connections_total",
        "Redis-protocol connections accepted.",
        m.redis_connections.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_redis_commands_total",
        "Redis-protocol commands processed.",
        m.redis_commands.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_redis_get_hit_total",
        "Redis GET commands that returned a value.",
        m.redis_get_hit.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_redis_get_miss_total",
        "Redis GET commands that returned nil.",
        m.redis_get_miss.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_redis_set_total",
        "Redis SET commands served.",
        m.redis_set.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_redis_del_total",
        "Keys removed via DEL/UNLINK.",
        m.redis_del.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_redis_auth_failures_total",
        "Redis AUTH attempts with the wrong password.",
        m.redis_auth_failures.load(Relaxed),
    );

    counter(
        &mut out,
        "dockfoxprox_eviction_runs_total",
        "Eviction passes executed.",
        m.eviction_runs.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_eviction_blobs_to_disk_total",
        "Blobs demoted from memory to disk by eviction.",
        m.eviction_blobs_to_disk.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_eviction_blobs_deleted_total",
        "Blobs deleted (from memory or disk) by eviction.",
        m.eviction_blobs_deleted.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_eviction_manifests_deleted_total",
        "Manifests deleted by eviction.",
        m.eviction_manifests_deleted.load(Relaxed),
    );
    counter(
        &mut out,
        "dockfoxprox_eviction_redis_entries_total",
        "Redis entries dropped by eviction.",
        m.eviction_redis_entries.load(Relaxed),
    );

    out
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    write_metric(out, name, help, "counter", value);
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    write_metric(out, name, help, "gauge", value);
}

fn write_metric(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}
