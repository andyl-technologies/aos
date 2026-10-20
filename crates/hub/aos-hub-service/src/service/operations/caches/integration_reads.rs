//! Integration reads in the caches capability.

use super::*;

impl RpcService {
    /// Returns the signed consumer-cache stack projection for one registry.
    ///
    /// # Errors
    ///
    /// Returns an authorization, projection, or database error.
    pub async fn get_consumer_cache_stack(
        &self,
        auth: Option<&str>,
        req: pb::GetConsumerCacheStackRequest,
    ) -> Result<pb::ConsumerCacheStackResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry_id).await?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::Read,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        Ok(pb::ConsumerCacheStackResponse {
            stack: Some(self.consumer_cache_stack_message(&registry).await?),
        })
    }

    /// Returns the independent publication, retention, and population facts for one pair.
    ///
    /// # Errors
    ///
    /// Returns an authorization, not-found, ambiguity, or database error.
    pub async fn get_cache_registry_integration(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheRegistryIntegrationRequest,
    ) -> Result<pb::CacheIntegrationResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, false)
            .await?;
        let publications = self
            .db
            .registry_cache_stack_entries(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let integration = self
            .cache_integration_message(&cache, &registry, &publications)
            .await?;
        if integration.publications.is_empty()
            && integration.retention.is_none()
            && integration.population.is_none()
        {
            return Err(RpcError::not_found("cache integration"));
        }
        Ok(pb::CacheIntegrationResponse {
            integration: Some(integration),
        })
    }
}
