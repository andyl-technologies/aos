//! Queue-triggered registry and cache reconciliation over the shared database.
//!
//! RFC-0004 drives the Worker's indexer from a **Cron Trigger** ("Cron
//! Triggers/Queues drive the indexer, validator, and mirror jobs"). The
//! maintenance dispatcher schedules each public registry's surface — read from the
//! R2 bucket rather than over HTTP — and replaces its derived SQL index by calling the
//! **shared core indexer** ([`aos_hub_core::indexer::index_and_record`]),
//! the exact same fetch → verify → load → index orchestration the native hub
//! runs. One indexer, two shells: the Worker's eventual index is byte-identical
//! to the native hub's.
//!
//! # How it wires up
//!
//! 1. List live registries from the Durable Object's shared
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

use aos_hub_core::db::{Database, SurfaceTarget};
use aos_hub_core::fetch::SurfaceProvider as _;
use aos_hub_core::secret_version::SecretVersionResolver;

use crate::consoleports::WorkerEgressClient;
use crate::surface::{R2SurfaceProvider, R2SurfaceWriteProvider};

/// Index every live registry from its selected placement.
///
/// Database access goes through the supplied shared
/// [`Database`](aos_hub_core::db::Database) backend; the surface read goes through the
/// [`R2SurfaceProvider`]. Each registry is indexed independently — one
/// registry's failure is recorded as its index state and logged, never aborting
/// the run.
///
/// `secrets` resolves a managed registry's external S3/R2 binding
/// credentials by immutable provider reference; a registry with
/// no external binding reads from the hub R2 bucket.
///
/// # Errors
///
/// Returns an error only if the registry inventory cannot be read.
pub async fn index_all(
    backend: Box<dyn aos_hub_core::backend::Backend>,
    bucket: Bucket,
    secrets: Arc<dyn SecretVersionResolver>,
    egress: Arc<WorkerEgressClient>,
) -> Result<()> {
    let db = Arc::new(Database::attach(backend));
    let provider = R2SurfaceProvider::new(bucket, Arc::clone(&db), secrets, egress);

    // Index every live registry. Private registries still need a fresh derived
    // index for retention and GC even when no unauthenticated route serves them.
    let registries = db.list_registries().await.context("listing registries")?;
    for registry in registries {
        let placement = match db
            .reconciled_surface_reader(SurfaceTarget::Registry(registry.id))
            .await
        {
            Ok(placement) => placement,
            Err(err) => {
                worker::console_log!(
                    "index {}: resolving authoritative reader failed: {err:#}",
                    registry.slug
                );
                continue;
            }
        };
        let fetch = match provider.placement_fetcher(&placement).await {
            Ok(fetch) => fetch,
            Err(err) => {
                worker::console_log!(
                    "index {} placement {}: resolving surface failed: {err:#}",
                    registry.slug,
                    placement.id
                );
                continue;
            }
        };
        if let Err(err) = aos_hub_core::indexer::index_and_record_from_placement(
            &db,
            fetch.as_ref(),
            &registry,
            Some(placement.id),
        )
        .await
        {
            worker::console_log!(
                "index {} authoritative placement {} failed: {err:#}",
                registry.slug,
                placement.id
            );
        }
    }
    Ok(())
}

/// Re-scan every managed cache, reconciling its derived index against its surface.
///
/// The Cron counterpart to the registry indexer, for caches: each cache's
/// `cache_objects` index is a derived view of its surface (the source of
/// truth), so this walks each cache's surface through the [`R2SurfaceProvider`]
/// and runs the shared [`rescan_cache`](aos_hub_core::cache_scan::rescan_cache)
/// to add narinfos that drifted in via a direct presigned upload and prune rows
/// whose narinfo is gone. Steady state
/// is one `list` per cache and no object reads. Each cache is independent — one
/// failure is logged, never aborting the pass.
///
/// `secrets` resolves a cache's external S3/R2 binding credentials when
/// its surface lives off the hub R2 bucket.
///
/// # Errors
///
/// Returns an error only if the cache inventory cannot be read from HubDb.
pub async fn rescan_all(
    backend: Box<dyn aos_hub_core::backend::Backend>,
    bucket: Bucket,
    secrets: Arc<dyn SecretVersionResolver>,
    egress: Arc<WorkerEgressClient>,
) -> Result<()> {
    let db = Arc::new(Database::attach(backend));
    let provider = R2SurfaceProvider::new(
        bucket.clone(),
        Arc::clone(&db),
        Arc::clone(&secrets),
        Arc::clone(&egress),
    );
    let writers = R2SurfaceWriteProvider::new(bucket, Arc::clone(&db), secrets, egress);
    aos_hub_core::cache_scan::reap_due_cache_tombstones(&db, aos_hub_core::clock::now_unix_secs())
        .await
        .context("reaping cache tombstones")?;
    aos_hub_core::cache_scan::recover_expired_cache_writes(
        &db,
        &provider,
        &writers,
        aos_hub_core::clock::now_unix_secs(),
        aos_hub_core::cache_scan::MAX_CLEANUP_ITEMS_PER_PASS,
    )
    .await
    .context("recovering expired cache writes")?;

    let caches = db.list_binary_caches().await.context("listing caches")?;
    for cache in caches {
        if cache.deleted_at.is_some() {
            continue;
        }
        match aos_hub_core::cache_scan::rescan_cache(&db, &provider, &cache).await {
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
