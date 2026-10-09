//! Retention reads in the caches capability.

use super::*;

impl RpcService {
    /// Explains whether and why one cache object is currently retained.
    ///
    /// # Errors
    ///
    /// Returns an authorization, registry-resolution, or database error.
    pub async fn explain_retention(
        &self,
        auth: Option<&str>,
        req: pb::ExplainRetentionRequest,
    ) -> Result<pb::ExplainRetentionResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let records = self
            .db
            .active_cache_root_reasons(cache.id, clock::now_unix_secs())
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .filter(|reason| reason.store_hash == req.store_hash)
            .collect::<Vec<_>>();
        let mut reasons = Vec::with_capacity(records.len());
        for record in records {
            reasons.push(self.root_reason_message(&cache.slug, &record).await?);
        }
        Ok(pb::ExplainRetentionResponse {
            retained: !reasons.is_empty(),
            reasons,
        })
    }

    /// Returns one cache/registry retention subscription.
    ///
    /// # Errors
    ///
    /// Returns an authorization, not-found, decoding, or database error.
    pub async fn get_retention_subscription(
        &self,
        auth: Option<&str>,
        req: pb::GetRetentionSubscriptionRequest,
    ) -> Result<pb::RetentionSubscriptionResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_retention_pair(auth, &req.cache_id, &req.registry_id, false)
            .await?;
        let record = self
            .db
            .cache_retention_subscription_topology(cache.id, registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("retention subscription"))?;
        Ok(pb::RetentionSubscriptionResponse {
            subscription: Some(Self::retention_subscription_message(
                &record,
                &cache.slug,
                &registry.slug,
            )?),
        })
    }

    /// Lists retention subscriptions owned by one cache.
    ///
    /// # Errors
    ///
    /// Returns an authorization, decoding, or database error.
    pub async fn list_retention_subscriptions(
        &self,
        auth: Option<&str>,
        req: pb::ListRetentionSubscriptionsRequest,
    ) -> Result<pb::ListRetentionSubscriptionsResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let records = self
            .db
            .list_cache_retention_subscriptions_topology(cache.id)
            .await
            .map_err(RpcError::internal)?;
        let mut subscriptions = Vec::new();
        for record in &records {
            let registry = self
                .db
                .registry_by_id(record.registry_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("registry"))?;
            subscriptions.push(Self::retention_subscription_message(
                record,
                &cache.slug,
                &registry.slug,
            )?);
        }
        let (subscriptions, next_page_token) =
            paginate(subscriptions, req.page_size, &req.page_token)?;
        Ok(pb::ListRetentionSubscriptionsResponse {
            subscriptions,
            next_page_token,
        })
    }

    /// Returns one manual retention root, including its current lease head.
    pub async fn get_retention_root(
        &self,
        auth: Option<&str>,
        req: pb::GetRetentionRootRequest,
    ) -> Result<pb::RetentionRootResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let include_actor = self
            .require_cache_permission(auth, &cache, Permission::AuditRead)
            .await
            .is_ok();
        let root = self
            .db
            .manual_retention_root(cache.id, &req.root_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("manual retention root"))?;
        Ok(pb::RetentionRootResponse {
            root: Some(
                self.manual_retention_root_message(&cache.slug, &root, include_actor)
                    .await?,
            ),
        })
    }

    /// Lists manual retention roots with opaque cursor pagination.
    pub async fn list_retention_roots(
        &self,
        auth: Option<&str>,
        req: pb::ListRetentionRootsRequest,
    ) -> Result<pb::ListRetentionRootsResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let include_actor = self
            .require_cache_permission(auth, &cache, Permission::AuditRead)
            .await
            .is_ok();
        let roots = self
            .db
            .list_manual_retention_roots_topology(cache.id)
            .await
            .map_err(RpcError::internal)?;
        let mut messages = Vec::with_capacity(roots.len());
        for root in &roots {
            messages.push(
                self.manual_retention_root_message(&cache.slug, root, include_actor)
                    .await?,
            );
        }
        let (roots, next_page_token) = paginate(messages, req.page_size, &req.page_token)?;
        Ok(pb::ListRetentionRootsResponse {
            roots,
            next_page_token,
        })
    }
}
