//! Configuration reads in the caches capability.

use super::*;

impl RpcService {
    /// `BinaryCacheService.SearchCache` — search a cache's objects.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn search_cache(
        &self,
        auth: Option<&str>,
        req: pb::SearchCacheRequest,
    ) -> Result<pb::SearchCacheResponse, RpcError> {
        let c = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_read(auth, &c).await?;
        let objects = self
            .db
            .search_normalized_cache_objects(c.id, &req.query, -1)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(cache_object_message)
            .collect::<Vec<_>>();
        let (objects, next_page_token) = paginate(objects, req.page_size, &req.page_token)?;
        Ok(pb::SearchCacheResponse {
            objects,
            next_page_token,
        })
    }

    /// Lists visible binary caches using deterministic slug ordering.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, or database error.
    pub async fn list_binary_caches(
        &self,
        auth: Option<&str>,
        req: pb::ListBinaryCachesRequest,
    ) -> Result<pb::ListBinaryCachesResponse, RpcError> {
        let caches = self
            .db
            .list_binary_caches()
            .await
            .map_err(RpcError::internal)?;
        let mut output = Vec::new();
        for cache in caches {
            if !req.owner_scope_key.is_empty()
                && self.binary_cache_owner_scope(&cache).await? != req.owner_scope_key
            {
                continue;
            }
            if self.require_cache_read(auth, &cache).await.is_ok() {
                output.push(self.binary_cache_message(&cache, false).await?);
            }
        }
        let (output, next_page_token) = paginate(output, req.page_size, &req.page_token)?;
        Ok(pb::ListBinaryCachesResponse {
            caches: output,
            next_page_token,
        })
    }

    /// Returns one visible binary cache.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, not-found, or database error.
    pub async fn get_binary_cache(
        &self,
        auth: Option<&str>,
        req: pb::GetBinaryCacheRequest,
    ) -> Result<pb::BinaryCacheResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_read(auth, &cache).await?;
        Ok(pb::BinaryCacheResponse {
            cache: Some(self.binary_cache_message(&cache, true).await?),
        })
    }

    /// Lists every concrete cache relationship for one registry.
    ///
    /// # Errors
    ///
    /// Returns an authorization, projection, or database error.
    pub async fn list_registry_cache_integrations(
        &self,
        auth: Option<&str>,
        req: pb::ListRegistryCacheIntegrationsRequest,
    ) -> Result<pb::ListCacheIntegrationsResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry_id).await?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::Read,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        let publications = self
            .db
            .registry_cache_stack_entries(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let retentions = self
            .db
            .list_registry_retention_subscriptions_topology(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let populations = self
            .db
            .list_registry_population_targets(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let mut cache_ids = std::collections::BTreeSet::new();
        cache_ids.extend(publications.iter().filter_map(|entry| entry.cache_id));
        cache_ids.extend(retentions.iter().map(|record| record.cache_id));
        cache_ids.extend(populations.iter().map(|record| record.cache_id));
        let mut integrations = Vec::new();
        for cache_id in cache_ids {
            let cache = self
                .db
                .binary_cache_by_id(cache_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("binary cache"))?;
            self.require_cache_read(auth, &cache).await?;
            integrations.push(
                self.cache_integration_message(&cache, &registry, &publications)
                    .await?,
            );
        }
        let (integrations, next_page_token) =
            paginate(integrations, req.page_size, &req.page_token)?;
        Ok(pb::ListCacheIntegrationsResponse {
            integrations,
            next_page_token,
        })
    }

    /// Lists every concrete registry relationship for one binary cache.
    ///
    /// # Errors
    ///
    /// Returns an authorization, projection, or database error.
    pub async fn list_cache_registry_integrations(
        &self,
        auth: Option<&str>,
        req: pb::ListCacheRegistryIntegrationsRequest,
    ) -> Result<pb::ListCacheIntegrationsResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_read(auth, &cache).await?;
        let publications = self
            .db
            .cache_registry_stack_entries(cache.id)
            .await
            .map_err(RpcError::internal)?;
        let retentions = self
            .db
            .list_cache_retention_subscriptions_topology(cache.id)
            .await
            .map_err(RpcError::internal)?;
        let populations = self
            .db
            .list_cache_population_targets(cache.id)
            .await
            .map_err(RpcError::internal)?;
        let mut registry_ids = std::collections::BTreeSet::new();
        registry_ids.extend(publications.iter().map(|entry| entry.registry_id));
        registry_ids.extend(retentions.iter().map(|record| record.registry_id));
        registry_ids.extend(populations.iter().map(|record| record.registry_id));
        let mut integrations = Vec::new();
        for registry_id in registry_ids {
            let registry = self
                .db
                .registry_by_id(registry_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("registry"))?;
            let claims = self.require_claims(auth)?;
            self.require_permission(
                &claims,
                Permission::Read,
                &self.registry_scope(&registry).await?,
            )
            .await?;
            integrations.push(
                self.cache_integration_message(&cache, &registry, &publications)
                    .await?,
            );
        }
        let (integrations, next_page_token) =
            paginate(integrations, req.page_size, &req.page_token)?;
        Ok(pb::ListCacheIntegrationsResponse {
            integrations,
            next_page_token,
        })
    }
}
