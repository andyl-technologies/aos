//! Index helpers in the registries capability.

use super::*;

impl RpcService {
    /// Reconciles the derived registry index after a publication is visible.
    ///
    /// Publication readiness is the durable source of truth. Hybrid returns
    /// after that commit and refreshes the derived index independently, so a
    /// full remote index walk cannot outlive the producer's control timeout.
    /// The Native periodic reindex pass recovers a canceled background task.
    pub(in crate::service) async fn refresh_registry_index_after_publication(
        &self,
        registry: &aos_hub_db::db::RegistryRecord,
        publication_id: &str,
    ) {
        #[cfg(not(target_arch = "wasm32"))]
        if self.hybrid_delivery {
            let reindexer = Arc::clone(&self.reindexer);
            let registry = registry.clone();
            let publication_id = publication_id.to_owned();

            tokio::spawn(async move {
                if let Err(error) = reindexer.reindex(&registry).await {
                    tracing::warn!(
                        registry = %registry.slug,
                        publication_id,
                        error = %format!("{error:#}"),
                        "hybrid publication index refresh failed"
                    );
                }
            });
            return;
        }

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
