//! Integration plans in the caches capability.

use super::*;

impl RpcService {
    /// Produces independent, durable plans for selected integration dimensions.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, ambiguity, or database error.
    pub async fn preview_cache_integration(
        &self,
        auth: Option<&str>,
        req: pb::PreviewCacheIntegrationRequest,
    ) -> Result<pb::PreviewCacheIntegrationResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(RpcError::internal)?,
        ));
        let publication_plan = if let Some(change) = req.publication.clone() {
            let stack = self.consumer_cache_stack_message(&registry).await?;
            self.plan_create_consumer_cache_changeset(
                auth,
                pb::PlanCreateConsumerCacheChangesetRequest {
                    registry_id: registry.slug.clone(),
                    change: Some(change),
                    expected_resource_version: stack.resource_version,
                    idempotency_key: format!("preview:{digest}:publication"),
                },
            )
            .await?
            .plan
        } else {
            None
        };
        let retention_plan = if let Some(retention) = req.retention.clone() {
            let expected = self
                .db
                .cache_retention_subscription_topology(cache.id, registry.id)
                .await
                .map_err(RpcError::internal)?
                .map(|record| record.resource_version.to_string())
                .unwrap_or_default();
            self.plan_set_retention_subscription(
                auth,
                pb::PlanRetentionSubscriptionRequest {
                    cache_id: cache.slug.clone(),
                    registry_id: registry.slug.clone(),
                    desired: Some(retention),
                    expected_resource_version: expected,
                    idempotency_key: format!("preview:{digest}:retention"),
                },
            )
            .await?
            .plan
        } else {
            None
        };
        let population_plan = if let Some(population) = req.population.clone() {
            let expected = self
                .population_target_for_pair(cache.id, registry.id)
                .await?
                .map(|record| record.resource_version.to_string())
                .unwrap_or_default();
            self.plan_set_population_target(
                auth,
                pb::PlanPopulationTargetRequest {
                    cache_id: cache.slug,
                    registry_id: registry.slug,
                    desired: Some(population),
                    expected_resource_version: expected,
                    idempotency_key: format!("preview:{digest}:population"),
                },
            )
            .await?
            .plan
        } else {
            None
        };
        Ok(pb::PreviewCacheIntegrationResponse {
            publication_plan,
            retention_plan,
            population_plan,
        })
    }

    /// Plans one structural edit to a registry's signed consumer-cache stack.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or database error.
    pub async fn plan_create_consumer_cache_changeset(
        &self,
        auth: Option<&str>,
        req: pb::PlanCreateConsumerCacheChangesetRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry_id).await?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        let stack = self.consumer_cache_stack_message(&registry).await?;
        if req.expected_resource_version != stack.resource_version {
            return Err(RpcError::FailedPrecondition(
                "consumer-cache stack resource version is stale".to_string(),
            ));
        }
        let change = req
            .change
            .as_ref()
            .ok_or_else(|| RpcError::invalid("change is required"))?;
        self.validate_consumer_cache_change(auth, &registry, &stack, change)
            .await?;
        let entries = Self::mutated_consumer_cache_entries(&stack, change)?;
        let mut ready_routes = std::collections::BTreeMap::new();
        for entry in &entries {
            if let Some(pb::consumer_cache_stack_entry::Source::BinaryCacheId(cache_id)) =
                entry.source.as_ref()
            {
                let cache = self.binary_cache_or_not_found(cache_id).await?;
                self.require_cache_read(auth, &cache).await?;
                let identity = self
                    .db
                    .ready_cache_route_advertisement_identity(cache.id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::FailedPrecondition(
                            "managed cache canonical Nix-cache route is not ready".to_string(),
                        )
                    })?;
                ready_routes.insert(entry.entry_id.clone(), identity);
            }
        }
        let planned = PlannedConsumerCacheChange {
            request: req.clone(),
            ready_routes,
        };
        let effect = format!(
            "draft a signed registry.toml consumer-cache stack {}",
            change.operation
        );
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&planned).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "consumer_cache_change",
            self.registry_scope(&registry).await?.as_str(),
            &planned,
            &req.idempotency_key,
            vec![effect],
            vec![
                "the relationship is not live until the draft is merged and re-indexed".to_string(),
            ],
            Some(confirmation_hash),
        )
        .await
    }
}
