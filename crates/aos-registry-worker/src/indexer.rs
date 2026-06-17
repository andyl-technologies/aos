//! The Cron-triggered indexer over R2 surfaces, writing the D1 index
//! (wasm32-only).
//!
//! RFC-0004 drives the Worker's indexer from a **Cron Trigger** ("Cron
//! Triggers/Queues drive the indexer, validator, and mirror jobs"). The
//! `scheduled` handler walks every public registry's surface — read from the
//! R2 bucket rather than over HTTP — and replaces its D1 index by calling the
//! **shared core indexer** ([`aos_registry_core::indexer::index_and_record`]),
//! the exact same fetch → verify → load → index orchestration the native hub
//! runs. One indexer, two shells: the Worker's eventual index is byte-identical
//! to the native hub's.
//!
//! # How it wires up
//!
//! 1. List the public registries from D1 through the shared
//!    [`Database`](aos_registry_core::db::Database), projecting each to a core
//!    [`RegistryRecord`](aos_registry_core::db::RegistryRecord) (not a bespoke
//!    worker model).
//! 2. For each registry, resolve its R2-backed
//!    [`SurfaceFetch`](aos_registry_core::fetch::SurfaceFetch) through the
//!    [`R2SurfaceProvider`](crate::surface::R2SurfaceProvider) — the same
//!    provider the read facade and the RPC `GitService` use — so the Cron read
//!    of the surface cannot drift from the rest of AOS.
//! 3. Call [`index_and_record`](aos_registry_core::indexer::index_and_record),
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

use anyhow::{Context as _, Result};
use worker::Bucket;

use aos_registry_core::db::Database;
use aos_registry_core::fetch::SurfaceProvider as _;

use crate::d1backend::D1Backend;
use crate::surface::R2SurfaceProvider;

/// Index every public registry from R2 into D1 via the shared core indexer.
///
/// Called from the `scheduled` handler. The D1 access goes through the shared
/// [`Database`](aos_registry_core::db::Database) over the [`D1Backend`] (the same
/// engine the read path uses); the surface read goes through the
/// [`R2SurfaceProvider`]. Each registry is indexed independently — one
/// registry's failure is recorded as its index state and logged, never aborting
/// the run.
///
/// # Errors
///
/// Returns an error only if the registry list cannot be read from D1.
pub async fn index_all(backend: D1Backend, bucket: Bucket) -> Result<()> {
    let db = Database::attach(Box::new(backend));
    let provider = R2SurfaceProvider::new(bucket);

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
            aos_registry_core::indexer::index_and_record(&db, fetch.as_ref(), &registry).await
        {
            // `index_and_record` already persisted the failure as the registry's
            // index state (stale/failed); this just surfaces it in the Cron log.
            worker::console_log!("index {} failed: {err:#}", registry.slug);
        }
    }
    Ok(())
}
