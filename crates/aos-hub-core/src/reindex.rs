//! The reindex port: refresh a registry's index after a publish completes.
//!
//! A successful mutable-pointer write that *completes* a publish (`info/refs` for
//! the git surface, `nix-cache-info` for the cache surface) re-indexes the
//! registry so the publish is visible on the browse pages and the read facade
//! without an external poll. The shared facade-write handler runs that re-index
//! through this port, so the index-after-flip logic is single-sourced across the
//! native hub and the Cloudflare Worker.
//!
//! - [`Reindexer`] — `reindex(registry)`, run inline by the write handler for a
//!   completing pointer write.
//!
//! # Deployment mapping
//!
//! - The **native hub** re-indexes inline from the registry's local surface (a
//!   `LocalFsFetch` over the storage-binding root) and records an `index` audit
//!   row, so the index is consistent the instant the final pointer write returns
//!   `200`. This is the relocated behavior of the hub's prior facade `reindex`.
//! - The **Cloudflare Worker** *defers* re-indexing to its Cron-trigger indexer,
//!   which already re-walks every registry's R2 surface on a schedule
//!   (`index_all`). The Worker's single-registry indexer is tightly coupled to
//!   its concrete HubDb/R2/`model::Registry` types and is not cleanly callable from
//!   a core port over a [`RegistryRecord`], so the Worker's [`Reindexer`] is a
//!   no-op that logs the deferral and returns `Ok(None)` (no inline commit).
//!   **Consistency implication:** a Worker publish
//!   becomes browse-visible only at the next Cron run, not synchronously on the
//!   final `PUT` (the read *facade* is already fresh — it streams the new bytes
//!   straight from R2 — only the derived HubDb index lags). The native hub keeps the
//!   synchronous guarantee; the Worker is eventually consistent on the index.
//!
//! The port carries the same target-conditional bound as the rest of the core
//! ports ([`BackendBounds`]): `Send + Sync` natively, unbounded on the
//! single-threaded wasm32 Worker.

use anyhow::Result;

use crate::backend::BackendBounds;
use crate::db::RegistryRecord;

/// Re-indexes a registry after a publish-completing pointer write.
///
/// Run inline by the shared facade-write handler when a mutable-pointer write
/// [`triggers a reindex`](crate::service). The native hub indexes synchronously
/// from the local surface; the Worker defers to its Cron indexer (a logged
/// no-op).
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Reindexer: BackendBounds {
    /// Re-index `registry` from its surface, returning the indexed commit oid.
    ///
    /// Called only after the bytes of a publish-completing pointer have landed,
    /// so by the time it runs the objects the pointer references are present. A
    /// failure is logged by the caller and does not fail the upload — the bytes
    /// are already written and the index is left marked stale/failed.
    ///
    /// A synchronous implementation (the native hub) returns `Some(commit)`, the
    /// oid the fresh index was built from — used to cross-reference the audit row
    /// for the publication operation that triggered the re-index.
    /// A *deferring* implementation (the Worker) returns `Ok(None)`: the index is
    /// reconciled later by the Cron indexer, so no commit is available inline and
    /// the deferred-advance audit row carries no index commit reference.
    ///
    /// # Errors
    ///
    /// Returns an error on an indexing, surface-read, or database failure. A
    /// deferring implementation (the Worker) returns `Ok(None)` unconditionally.
    async fn reindex(&self, registry: &RegistryRecord) -> Result<Option<String>>;
}
