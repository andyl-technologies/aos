//! Index helpers in the registries capability.

use super::*;

impl RpcService {
    /// Reconciles the derived registry index after a publication is visible.
    ///
    /// Publication readiness is the durable source of truth. Indexing is a
    /// recoverable derived-state update, so failure is logged without making a
    /// completed publication ambiguous to its producer.
    pub(in crate::service) async fn refresh_registry_index_after_publication(
        &self,
        registry: &crate::db::RegistryRecord,
        publication_id: &str,
    ) {
        if let Err(error) = self.reindexer.reindex(registry).await {
            tracing::warn!(
                registry = %registry.slug,
                publication_id,
                error = %format!("{error:#}"),
                "registry publication could not schedule index reconciliation"
            );
        }
    }
}
