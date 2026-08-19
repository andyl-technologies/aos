//! The reindex port: refresh a registry's index after a publish completes.
//!
//! A successful mutable-pointer write that *completes* a publish (`info/refs` for
//! the git surface, `nix-cache-info` for the cache surface) re-indexes the
//! registry so the publish is visible on the browse pages and the read facade
//! without an external poll. The shared facade-write handler runs that re-index
//! through this port, so the index-after-flip logic is single-sourced across the
//! native hub and the Cloudflare Worker.
//!
//! - [`Reindexer`] — `reindex(registry)`, invoked by the write handler after a
//!   completing pointer write.
//! - [`QueuedReindexer`] — the production adapter for deployments where a full
//!   index walk must not extend an already-committed mutation request.
//!
//! # Deployment mapping
//!
//! - The **native hub** re-indexes inline from the registry's local surface (a
//!   `LocalFsFetch` over the storage-binding root) and records an `index` audit
//!   row, so the index is consistent the instant the final pointer write returns
//!   `200`. This is the relocated behavior of the hub's prior facade `reindex`.
//! - The **Cloudflare Worker** uses [`QueuedReindexer`] to submit one
//!   registry-scoped job. Its queue consumer runs the same indexer over R2, and
//!   the periodic all-registry pass remains the recovery path if queue admission
//!   fails. The published read surface is immediately current; only the derived
//!   browse index is eventually consistent. The native hub keeps its synchronous
//!   index guarantee.
//!
//! The port carries the same target-conditional bound as the rest of the core
//! ports ([`BackendBounds`]): `Send + Sync` natively, unbounded on the
//! single-threaded wasm32 Worker.

use std::sync::Arc;

use anyhow::Result;

use crate::backend::BackendBounds;
use crate::db::RegistryRecord;
use crate::jobs::{Job, Queue};

/// Re-indexes a registry after a publish-completing pointer write.
///
/// Invoked by the shared facade-write handler when a mutable-pointer write
/// [`triggers a reindex`](crate::service). Implementations may index
/// synchronously or durably schedule the work.
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
    /// A deferring implementation returns `Ok(None)`: no indexed commit is
    /// available inline, so the deferred-advance audit row carries no index
    /// commit reference.
    ///
    /// # Errors
    ///
    /// Returns an error on an indexing, surface-read, database, or queue
    /// admission failure.
    async fn reindex(&self, registry: &RegistryRecord) -> Result<Option<String>>;
}

/// Defers registry indexing to the shared durable job queue.
///
/// The enqueue is deliberately the only synchronous work performed after the
/// caller's publication or configuration transaction commits. Queue consumers
/// may safely retry [`Job::Reindex`], while the periodic index reconciler
/// remains the recovery path if enqueueing itself fails.
pub struct QueuedReindexer {
    queue: Arc<dyn Queue>,
}

impl QueuedReindexer {
    /// Builds a reindex scheduler backed by `queue`.
    #[must_use]
    pub fn new(queue: Arc<dyn Queue>) -> Self {
        Self { queue }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Reindexer for QueuedReindexer {
    async fn reindex(&self, registry: &RegistryRecord) -> Result<Option<String>> {
        self.queue
            .enqueue(&Job::Reindex {
                registry_id: registry.id,
            })
            .await?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{QueuedReindexer, Reindexer};
    use crate::db::RegistryRecord;
    use crate::jobs::{InMemoryQueue, Job};
    use std::sync::Arc;

    #[tokio::test]
    async fn queued_reindexer_schedules_the_exact_registry() {
        let queue = Arc::new(InMemoryQueue::new());
        let reindexer = QueuedReindexer::new(queue.clone());
        let registry = RegistryRecord {
            id: 41,
            stable_id: "registry:queued".into(),
            scope_key: "registry:queued".into(),
            owner_scope_key: "instance".into(),
            slug: "queued".into(),
            trust_keys: Vec::new(),
            require_signatures: false,
            org_id: None,
            project_path: String::new(),
            visibility: "private".into(),
            crawl_policy: "deny_all".into(),
            llms_txt_body: None,
            resource_version: 1,
            updated_at: 0,
        };

        assert_eq!(reindexer.reindex(&registry).await.unwrap(), None);
        assert_eq!(
            queue.drain(),
            vec![Job::Reindex {
                registry_id: registry.id
            }]
        );
    }
}
