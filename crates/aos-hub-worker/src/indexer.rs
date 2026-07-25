//! The Cron-triggered indexer over R2 surfaces, writing the D1 index
//! (wasm32-only).
//!
//! RFC-0004 drives the Worker's indexer from a **Cron Trigger** ("Cron
//! Triggers/Queues drive the indexer, validator, and mirror jobs"). The
//! `scheduled` handler walks every public registry's surface — read from the
//! R2 bucket rather than over HTTP — and replaces its D1 index by calling the
//! **shared core indexer** ([`aos_hub_core::indexer::index_and_record`]),
//! the exact same fetch → verify → load → index orchestration the native hub
//! runs. One indexer, two shells: the Worker's eventual index is byte-identical
//! to the native hub's.
//!
//! # How it wires up
//!
//! 1. List the public registries from D1 through the shared
//!    [`Database`](aos_hub_core::db::Database), projecting each to a core
//!    [`RegistryRecord`](aos_hub_core::db::RegistryRecord) (not a bespoke
//!    worker model).
//! 2. For each registry, resolve its R2-backed
//!    [`SurfaceFetch`](aos_hub_core::fetch::SurfaceFetch) through the
//!    [`R2SurfaceProvider`](crate::surface::R2SurfaceProvider) — the same
//!    provider the read facade and the RPC `GitService` use — so the Cron read
//!    of the surface cannot drift from the rest of AOS.
//! 3. Call [`index_and_record`](aos_hub_core::indexer::index_and_record),
//!    which fetches `HEAD`/`info/refs`, verifies the commit and every release
//!    tag and channel partition (fail closed under `require_signatures`), walks
//!    the committed tree for `registry.toml`/`keys.toml`/packages/closures,
//!    enforces the anti-rollback floor, and writes the whole snapshot — failure
//!    classification, the index snapshot row, and the floor frontier raise all
//!    shared with the native hub.
//!
//! Each registry is indexed independently; one registry's failure is logged by
//! [`index_and_record`] (which records it as the registry's index state) and
//! does not abort the rest of the run.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use worker::Bucket;

use aos_hub_core::auth::seal::SecretSealer;
use aos_hub_core::db::Database;
use aos_hub_core::fetch::SurfaceProvider as _;

use crate::surface::{R2SurfaceProvider, R2SurfaceWriteProvider};

/// Index every public registry from R2 into D1 via the shared core indexer.
///
/// Called from the `scheduled` handler. The D1 access goes through the shared
/// [`Database`](aos_hub_core::db::Database) over the [`D1Backend`] (the same
/// engine the read path uses); the surface read goes through the
/// [`R2SurfaceProvider`]. Each registry is indexed independently — one
/// registry's failure is recorded as its index state and logged, never aborting
/// the run.
///
/// `sealer` resolves a managed registry's external S3/R2 storage binding
/// credentials (the same AES-GCM sealer the request path uses); a registry with
/// no external binding reads from the hub R2 bucket.
///
/// # Errors
///
/// Returns an error only if the registry list cannot be read from D1.
pub async fn index_all(
    backend: Box<dyn aos_hub_core::backend::Backend>,
    bucket: Bucket,
    sealer: Arc<dyn SecretSealer>,
) -> Result<()> {
    let db = Arc::new(Database::attach(backend));
    let provider = R2SurfaceProvider::new(bucket, Arc::clone(&db), sealer);

    // The Worker serves only `public` registries (RFC-0004 multi-tenancy): the
    // Cron indexes exactly that subset of the non-tombstoned registries.
    let registries = db.list_registries().await.context("listing registries")?;
    for registry in registries
        .into_iter()
        .filter(|registry| registry.visibility == "public")
    {
        let fetch = match provider.fetcher(&registry).await {
            Ok(fetch) => fetch,
            Err(err) => {
                worker::console_log!(
                    "index {}: resolving R2 surface failed: {err:#}",
                    registry.slug
                );
                continue;
            }
        };
        if let Err(err) =
            aos_hub_core::indexer::index_and_record(&db, fetch.as_ref(), &registry).await
        {
            // `index_and_record` already persisted the failure as the registry's
            // index state (stale/failed); this just surfaces it in the Cron log.
            worker::console_log!("index {} failed: {err:#}", registry.slug);
        }
    }
    Ok(())
}

/// Re-scan every managed cache, reconciling its D1 index against its surface.
///
/// The Cron counterpart to the registry indexer, for caches: each cache's
/// `cache_objects` index is a derived view of its surface (the source of
/// truth), so this walks each cache's surface through the [`R2SurfaceProvider`]
/// and runs the shared [`rescan_cache`](aos_hub_core::cache_scan::rescan_cache)
/// to add narinfos that drifted in via a direct presigned upload (which bypasses
/// the facade write-through) and prune rows whose narinfo is gone. Steady state
/// is one `list` per cache and no object reads. Each cache is independent — one
/// failure is logged, never aborting the pass.
///
/// `sealer` resolves a cache's external S3/R2 storage binding credentials when
/// its surface lives off the hub R2 bucket.
///
/// # Errors
///
/// Returns an error only if the cache list cannot be read from D1.
pub async fn rescan_all(
    backend: Box<dyn aos_hub_core::backend::Backend>,
    bucket: Bucket,
    sealer: Arc<dyn SecretSealer>,
) -> Result<()> {
    let db = Arc::new(Database::attach(backend));
    let provider = R2SurfaceProvider::new(bucket, Arc::clone(&db), sealer);

    let caches = db.list_caches().await.context("listing caches")?;
    for cache in caches {
        if cache.deleted_at.is_some() {
            continue;
        }
        let fetch = match provider.cache_fetcher(&cache).await {
            Ok(fetch) => fetch,
            Err(err) => {
                worker::console_log!("rescan {}: resolving surface failed: {err:#}", cache.slug);
                continue;
            }
        };
        match aos_hub_core::cache_scan::rescan_cache(&db, fetch.as_ref(), &cache).await {
            Ok(stats) => {
                if stats.added > 0 || stats.removed > 0 {
                    worker::console_log!(
                        "rescan {}: +{} added -{} pruned ={} unchanged",
                        cache.slug,
                        stats.added,
                        stats.removed,
                        stats.unchanged
                    );
                }
            }
            Err(err) => worker::console_log!("rescan {} failed: {err:#}", cache.slug),
        }
    }
    Ok(())
}

/// Garbage-collect every GC-policied managed cache from D1+R2 via the shared
/// sweep.
///
/// The worker half of cache GC: the Cron-driven counterpart to the native hub's
/// `aos-hub cache gc`. Drives the *same* [`sweep_cache`](aos_hub_core::gc::sweep_cache)
/// the native path and the `RunCacheGc` RPC use, over the shared
/// [`Database`](aos_hub_core::db::Database) (D1) and the R2 write surface,
/// recording each sweep as a `cache_gc_runs` row. Only caches that have opted in
/// with a GC policy are swept; each cache is independent — one cache's failure is
/// recorded on its run row and logged, never aborting the pass. `now` is the
/// Cron tick's Unix time (seconds), supplied by the caller since wasm has no
/// ambient clock.
///
/// `sealer` resolves a cache's external S3/R2 storage binding credentials (the
/// same AES-GCM sealer the request path uses) when its surface lives off the
/// hub R2 bucket.
///
/// # Errors
///
/// Returns an error only if the cache list cannot be read from D1.
pub async fn gc_all(
    backend: Box<dyn aos_hub_core::backend::Backend>,
    bucket: Bucket,
    now: i64,
    sealer: Arc<dyn SecretSealer>,
) -> Result<()> {
    let db = Arc::new(Database::attach(backend));
    let writers = R2SurfaceWriteProvider::new(bucket, Arc::clone(&db), sealer);

    let caches = db.list_caches().await.context("listing caches")?;
    for cache in caches {
        // Scheduled GC is opt-in per cache: only sweep those with a GC policy.
        match db.cache_gc_policy(cache.id).await {
            Ok(Some(_)) => {}
            Ok(None) => continue,
            Err(err) => {
                worker::console_log!("gc {}: loading policy failed: {err:#}", cache.slug);
                continue;
            }
        }
        let run_id = match db.start_cache_gc_run(cache.id).await {
            Ok(id) => id,
            Err(err) => {
                worker::console_log!("gc {}: opening run failed: {err:#}", cache.slug);
                continue;
            }
        };
        match aos_hub_core::gc::sweep_cache(&db, &writers, &cache, false, now).await {
            Ok(stats) => {
                let _ = db
                    .finish_cache_gc_run(
                        run_id,
                        "ok",
                        None,
                        stats.scanned,
                        stats.retained,
                        stats.deleted_objects,
                        stats.freed_bytes,
                    )
                    .await;
                worker::console_log!(
                    "gc {}: scanned {} retained {} deleted {} freed {}B",
                    cache.slug,
                    stats.scanned,
                    stats.retained,
                    stats.deleted_objects,
                    stats.freed_bytes
                );
            }
            Err(err) => {
                let _ = db
                    .finish_cache_gc_run(run_id, "failed", Some(format!("{err:#}")), 0, 0, 0, 0)
                    .await;
                worker::console_log!("gc {} failed: {err:#}", cache.slug);
            }
        }
    }
    Ok(())
}
