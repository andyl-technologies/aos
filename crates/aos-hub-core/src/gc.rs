//! Cache garbage collection: mark/sweep over the `cache_objects` closure graph.
//!
//! RFC-0004 "11-caches". A managed cache reclaims storage by retaining only the
//! closures reachable from its GC roots and deleting the rest. Roots are:
//!
//! - **manual pins** ([`Database::list_cache_roots`]) whose `expires_at` has not
//!   passed (an expired pin stops rooting and is itself reaped), and
//! - **derived roots** — for each linked registry with `roots_packages`, every
//!   store path the registry indexes ([`Database::registry_store_hashes`]), so a
//!   published package's closure is never collected.
//!
//! [`sweep_cache`] is the single implementation both shells run via
//! `RpcService::run_cache_gc` — the native hub over a filesystem writer, and the
//! Cloudflare Worker over an R2 writer (the worker mounts the same router, so
//! the `RunCacheGc` RPC is reachable there; a scheduled Cron driver is not yet
//! wired). It is policy-driven — with no
//! [`CacheGcPolicy`](crate::db::CacheGcPolicy) it never sweeps on age (only a
//! `ttl_unreferenced_secs` grace enables age sweeps); `max_bytes`/`max_objects`
//! drive LRU eviction of *unrooted* objects (a rooted closure is never evicted —
//! breaking a published package is worse than overrunning a soft cap, which is
//! surfaced as a logged quota breach instead).
//!
//! NAR deletion resolves the on-disk object via `cache_objects.nar_url` (the
//! real surface key), not by reconstructing a name from `file_hash`; a NAR is
//! removed only once no remaining narinfo on the same binding+prefix references
//! it (the content-addressed [`Database::nar_refcount`]).

use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::db::{Cache, Database};
use crate::surface_write::SurfaceWriteProvider;

/// The outcome of a [`sweep_cache`] run.
#[derive(Debug, Clone, Default)]
pub struct GcStats {
    /// Objects examined.
    pub scanned: i64,
    /// Objects retained (reachable from a live root).
    pub retained: i64,
    /// Objects deleted (or, for a dry run, that would be deleted).
    pub deleted_objects: i64,
    /// Bytes reclaimed (or, for a dry run, that would be reclaimed).
    pub freed_bytes: i64,
}

/// An owned snapshot of an object marked for deletion (so the async deletion
/// loop holds no borrow into the loaded object list across `.await`s).
struct Doomed {
    store_hash: String,
    nar_url: String,
    file_hash: String,
    file_size: i64,
}

/// Garbage-collect a managed cache, returning what was (or would be) reclaimed.
///
/// Computes the live root set, marks the reachable closure over
/// `cache_objects.refs`, and sweeps the rest subject to the cache's GC policy
/// (age grace + soft size/object caps). When `dry_run` is set, nothing is
/// deleted and the stats report what a real run would reclaim.
///
/// # Errors
///
/// Returns an error on database failure or when the cache's writable surface
/// cannot be resolved. Individual surface deletes are best-effort (a missing
/// object is not an error); a failure to delete a narinfo/NAR file is logged and
/// the row is still removed (the index stays consistent with the next re-scan).
pub async fn sweep_cache(
    db: &Database,
    writers: &dyn SurfaceWriteProvider,
    cache: &Cache,
    dry_run: bool,
    now: i64,
) -> Result<GcStats> {
    let policy = db.cache_gc_policy(cache.id).await?;
    let ttl = policy.as_ref().and_then(|p| p.ttl_unreferenced_secs);
    let max_bytes = policy.as_ref().and_then(|p| p.max_bytes);
    let max_objects = policy.as_ref().and_then(|p| p.max_objects);

    // Roots: live manual pins + derived roots from linked registries.
    let mut roots: HashSet<String> = HashSet::new();
    for root in db.list_cache_roots(cache.id).await? {
        if root.expires_at.is_none_or(|e| e > now) {
            roots.insert(root.store_hash);
        }
    }
    for link in db.list_cache_links(cache.id).await? {
        if link.roots_packages {
            for hash in db.registry_store_hashes(link.registry_id).await? {
                roots.insert(hash);
            }
        }
    }

    // Load every object once; index by store hash for the closure walk. `-1`
    // means "no LIMIT" — the sweep must see every object, and a huge sentinel
    // like `i64::MAX` is not a valid `LIMIT` bind on the D1 backend (`f64`).
    let objects = db.list_cache_objects(cache.id, -1).await?;
    let by_hash: HashMap<&str, usize> = objects
        .iter()
        .enumerate()
        .map(|(i, o)| (o.store_hash.as_str(), i))
        .collect();

    // Mark: closure over `refs` from the roots that exist in this cache.
    let mut marked: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = roots
        .into_iter()
        .filter(|h| by_hash.contains_key(h.as_str()))
        .collect();
    while let Some(h) = stack.pop() {
        if !marked.insert(h.clone()) {
            continue;
        }
        if let Some(&i) = by_hash.get(h.as_str()) {
            for r in &objects[i].refs {
                if by_hash.contains_key(r.as_str()) && !marked.contains(r) {
                    stack.push(r.clone());
                }
            }
        }
    }

    // Sweep candidates are the unmarked objects, in LRU order (least-recently
    // accessed first; never-accessed sorts oldest) for size-cap eviction.
    let mut unmarked: Vec<&_> = objects
        .iter()
        .filter(|o| !marked.contains(&o.store_hash))
        .collect();
    unmarked.sort_by_key(|o| (o.last_accessed_at.unwrap_or(0), o.uploaded_at));

    let mut remaining_bytes: i64 = objects.iter().map(|o| o.file_size).sum();
    let mut remaining_objects: i64 = objects.len() as i64;
    let mut doomed: Vec<Doomed> = Vec::new();
    for o in &unmarked {
        let aged_out = ttl.is_some_and(|t| now - o.uploaded_at >= t);
        let over_bytes = max_bytes.is_some_and(|m| remaining_bytes > m);
        let over_objects = max_objects.is_some_and(|m| remaining_objects > m);
        if aged_out || over_bytes || over_objects {
            remaining_bytes -= o.file_size;
            remaining_objects -= 1;
            doomed.push(Doomed {
                store_hash: o.store_hash.clone(),
                nar_url: o.nar_url.clone(),
                file_hash: o.file_hash.clone(),
                file_size: o.file_size,
            });
        }
    }
    // Fully-rooted yet over cap: a rooted closure is never evicted, so report the
    // breach rather than corrupting a published package's closure.
    if let Some(m) = max_bytes {
        if remaining_bytes > m {
            tracing::warn!(
                cache = %cache.slug, used = remaining_bytes, cap = m,
                "cache over its byte cap after GC: the rooted closure alone exceeds it"
            );
        }
    }

    let scanned = objects.len() as i64;
    let retained = marked.len() as i64;
    if dry_run {
        // `freed_bytes` is an upper bound here: it counts every doomed object's
        // NAR, whereas a real run frees a deduplicated NAR's bytes only once (and
        // not at all while a surviving object still references it).
        return Ok(GcStats {
            scanned,
            retained,
            deleted_objects: doomed.len() as i64,
            freed_bytes: doomed.iter().map(|d| d.file_size).sum(),
        });
    }

    let writer = writers.cache_writer(cache).await?;
    let mut deleted_objects = 0i64;
    let mut freed_bytes = 0i64;
    for d in &doomed {
        // Drop the index row first so `nar_refcount` reflects the deletion.
        db.delete_cache_object(cache.id, &d.store_hash).await?;
        if let Err(err) = writer.delete(&format!("{}.narinfo", d.store_hash)).await {
            tracing::warn!(cache = %cache.slug, hash = %d.store_hash, error = %format!("{err:#}"), "narinfo delete failed");
        }
        // Remove the NAR only when no surviving narinfo references it; count the
        // reclaimed bytes only when the NAR is actually deleted (a deduplicated
        // NAR still referenced by a surviving object frees nothing).
        if db
            .nar_refcount(cache.storage_binding_id, &cache.prefix, &d.file_hash)
            .await?
            == 0
        {
            if let Err(err) = writer.delete(&d.nar_url).await {
                tracing::warn!(cache = %cache.slug, nar = %d.nar_url, error = %format!("{err:#}"), "nar delete failed");
            }
            freed_bytes += d.file_size;
        }
        deleted_objects += 1;
    }
    db.refresh_cache_usage(cache.id).await?;

    Ok(GcStats {
        scanned,
        retained,
        deleted_objects,
        freed_bytes,
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::db::{CacheGcPolicy, CacheObject, RegistryRecord};
    use crate::surface_write::SurfaceWrite;

    /// A write provider whose deletes are no-ops (the test asserts the DB side).
    struct NoopWriters;
    struct NoopWrite;

    #[async_trait::async_trait]
    impl SurfaceWrite for NoopWrite {
        async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _path: &str) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl SurfaceWriteProvider for NoopWriters {
        async fn writer(&self, _registry: &RegistryRecord) -> Result<Box<dyn SurfaceWrite>> {
            Ok(Box::new(NoopWrite))
        }
        async fn cache_writer(&self, _cache: &Cache) -> Result<Box<dyn SurfaceWrite>> {
            Ok(Box::new(NoopWrite))
        }
    }

    fn obj(cache_id: i64, hash: &str, refs: &[&str]) -> CacheObject {
        CacheObject {
            cache_id,
            store_hash: hash.to_string(),
            store_name: format!("{hash}-x"),
            nar_url: format!("nar/{hash}.nar"),
            nar_hash: String::new(),
            nar_size: 0,
            file_hash: hash.to_string(),
            file_size: 10,
            compression: "none".to_string(),
            deriver: None,
            refs: refs.iter().map(|s| s.to_string()).collect(),
            sig: None,
            ca: None,
            uploaded_at: 0,
            last_accessed_at: None,
        }
    }

    async fn fixture() -> (Database, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let binding = db
            .create_storage_binding(org, "b", "local_fs", "/srv")
            .await
            .unwrap();
        let cache = db
            .create_cache(
                Some(org),
                "c",
                "C",
                Some(binding),
                "p",
                None,
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        (db, cache)
    }

    #[tokio::test]
    async fn sweeps_unrooted_and_keeps_the_rooted_closure() {
        let (db, cache) = fixture().await;
        // root -> a -> b ; plus an unreferenced orphan `o`.
        for o in [
            obj(cache, "root", &["a"]),
            obj(cache, "a", &["b"]),
            obj(cache, "b", &[]),
            obj(cache, "o", &[]),
        ] {
            db.upsert_cache_object(&o).await.unwrap();
        }
        db.pin_cache_path(cache, "root", None).await.unwrap();
        db.set_cache_gc_policy(&CacheGcPolicy {
            cache_id: cache,
            max_bytes: None,
            max_objects: None,
            ttl_unreferenced_secs: Some(0), // immediate age sweep
            keep_release_versions: None,
            keep_channel_frontier: true,
            schedule_secs: None,
            updated_at: 0,
        })
        .await
        .unwrap();
        let c = db.cache_by_id(cache).await.unwrap().unwrap();

        let stats = sweep_cache(&db, &NoopWriters, &c, false, 1000)
            .await
            .unwrap();
        assert_eq!(stats.scanned, 4);
        assert_eq!(stats.retained, 3); // root, a, b
        assert_eq!(stats.deleted_objects, 1); // o
        assert!(db.cache_object(cache, "o").await.unwrap().is_none());
        assert!(db.cache_object(cache, "root").await.unwrap().is_some());
        assert!(db.cache_object(cache, "b").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn expired_pin_stops_rooting() {
        let (db, cache) = fixture().await;
        db.upsert_cache_object(&obj(cache, "x", &[])).await.unwrap();
        // A pin that expired at t=500 no longer roots at now=1000.
        db.pin_cache_path(cache, "x", Some(500)).await.unwrap();
        db.set_cache_gc_policy(&CacheGcPolicy {
            cache_id: cache,
            max_bytes: None,
            max_objects: None,
            ttl_unreferenced_secs: Some(0),
            keep_release_versions: None,
            keep_channel_frontier: true,
            schedule_secs: None,
            updated_at: 0,
        })
        .await
        .unwrap();
        let c = db.cache_by_id(cache).await.unwrap().unwrap();
        let stats = sweep_cache(&db, &NoopWriters, &c, false, 1000)
            .await
            .unwrap();
        assert_eq!(stats.deleted_objects, 1);
        assert!(db.cache_object(cache, "x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn no_policy_is_a_noop() {
        // With no GC policy (no ttl, no caps) nothing is swept, even unrooted.
        let (db, cache) = fixture().await;
        db.upsert_cache_object(&obj(cache, "o", &[])).await.unwrap();
        let c = db.cache_by_id(cache).await.unwrap().unwrap();
        let stats = sweep_cache(&db, &NoopWriters, &c, false, 1000)
            .await
            .unwrap();
        assert_eq!(stats.deleted_objects, 0);
        assert!(db.cache_object(cache, "o").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn dry_run_reports_without_deleting() {
        let (db, cache) = fixture().await;
        db.upsert_cache_object(&obj(cache, "o", &[])).await.unwrap();
        db.set_cache_gc_policy(&CacheGcPolicy {
            cache_id: cache,
            max_bytes: None,
            max_objects: None,
            ttl_unreferenced_secs: Some(0),
            keep_release_versions: None,
            keep_channel_frontier: true,
            schedule_secs: None,
            updated_at: 0,
        })
        .await
        .unwrap();
        let c = db.cache_by_id(cache).await.unwrap().unwrap();
        let stats = sweep_cache(&db, &NoopWriters, &c, true, 1000)
            .await
            .unwrap();
        assert_eq!(stats.deleted_objects, 1);
        assert!(db.cache_object(cache, "o").await.unwrap().is_some()); // not deleted
    }

    #[tokio::test]
    async fn size_cap_evicts_unrooted_least_recently_accessed_first() {
        let (db, cache) = fixture().await;
        // Three unrooted 10-byte objects with distinct access times.
        for (h, accessed) in [("old", 100i64), ("mid", 200), ("new", 300)] {
            let mut o = obj(cache, h, &[]);
            o.last_accessed_at = Some(accessed);
            db.upsert_cache_object(&o).await.unwrap();
        }
        // No age sweep; a 20-byte cap over 30 bytes must evict exactly one — the
        // least-recently-accessed ("old").
        db.set_cache_gc_policy(&CacheGcPolicy {
            cache_id: cache,
            max_bytes: Some(20),
            max_objects: None,
            ttl_unreferenced_secs: None,
            keep_release_versions: None,
            keep_channel_frontier: true,
            schedule_secs: None,
            updated_at: 0,
        })
        .await
        .unwrap();
        let c = db.cache_by_id(cache).await.unwrap().unwrap();
        let stats = sweep_cache(&db, &NoopWriters, &c, false, 1000)
            .await
            .unwrap();
        assert_eq!(stats.deleted_objects, 1);
        assert_eq!(stats.freed_bytes, 10);
        assert!(db.cache_object(cache, "old").await.unwrap().is_none());
        assert!(db.cache_object(cache, "mid").await.unwrap().is_some());
        assert!(db.cache_object(cache, "new").await.unwrap().is_some());
    }
}
