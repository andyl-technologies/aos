//! Integration mutations in the caches capability.

use super::*;

impl RpcService {
    /// Resolves the canonical Nix-cache delivery URL for a binary cache.
    ///
    /// Direct, CDN, and Hub-proxied delivery are all explicit routes. An absent
    /// canonical selection is a topology precondition failure rather than an
    /// instruction to synthesize an implicit Hub URL.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when the cache has no canonical
    /// Nix-cache route.
    pub async fn cache_consumer_url(
        &self,
        cache: &aos_hub_db::db::BinaryCache,
    ) -> Result<String, RpcError> {
        self.db
            .ready_cache_canonical_url(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "cache canonical Nix-cache route is not ready".to_owned(),
                )
            })
    }

    /// Applies a reviewed consumer-stack plan by creating a signed Git changeset.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-plan, validation, storage, or signing error.
    pub async fn create_consumer_cache_changeset(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::ConsumerCacheChangesetResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "consumer_cache_change",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            "consumer_cache_change",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, planned): (_, PlannedConsumerCacheChange) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "consumer_cache_change",
                Some(&req.confirmation_hash),
            )
            .await?;
        let PlannedConsumerCacheChange {
            request: input,
            ready_routes,
        } = planned;
        let registry = self.registry_or_not_found(&input.registry_id).await?;
        let claims = self.require_claims(auth)?;
        let registry_scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::RegistryConfigure, &registry_scope)
            .await?;

        if let Some(existing) = self
            .db
            .changeset(&plan.plan_id)
            .await
            .map_err(RpcError::internal)?
        {
            if existing.scope != registry_scope.as_str() || existing.git_ref.is_none() {
                return Err(RpcError::FailedPrecondition(
                    "plan id collides with another changeset".to_string(),
                ));
            }
            if let Some(change) = input.change.as_ref() {
                self.record_consumer_publication_intent(
                    &registry,
                    &existing.change_id,
                    change,
                    &ready_routes,
                )
                .await?;
            }
            let response = pb::ConsumerCacheChangesetResponse {
                change_id: existing.change_id,
                state: existing.status,
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        }

        let stack = self.consumer_cache_stack_message(&registry).await?;
        if stack.resource_version != input.expected_resource_version {
            return Err(RpcError::FailedPrecondition(
                "consumer-cache stack changed after planning".to_string(),
            ));
        }
        let change = input
            .change
            .as_ref()
            .ok_or_else(|| RpcError::invalid("planned change is missing"))?;
        self.validate_consumer_cache_change(auth, &registry, &stack, change)
            .await?;
        for (entry_id, planned_identity) in &ready_routes {
            let entry = Self::mutated_consumer_cache_entries(&stack, change)?
                .into_iter()
                .find(|entry| entry.entry_id == *entry_id)
                .ok_or_else(|| {
                    RpcError::FailedPrecondition("planned cache entry disappeared".to_string())
                })?;
            let Some(pb::consumer_cache_stack_entry::Source::BinaryCacheId(cache_id)) =
                entry.source
            else {
                return Err(RpcError::FailedPrecondition(
                    "planned managed cache entry changed source".to_string(),
                ));
            };
            let cache = self.binary_cache_or_not_found(&cache_id).await?;
            let current = self
                .db
                .ready_cache_route_advertisement_identity(cache.id)
                .await
                .map_err(RpcError::internal)?;
            if current.as_ref() != Some(planned_identity) {
                return Err(RpcError::FailedPrecondition(
                    "planned ready cache route changed before rendering".to_string(),
                ));
            }
        }
        let new_contents = self
            .apply_consumer_cache_change_to_toml(auth, &registry, &stack, change, &ready_routes)
            .await?;
        let sealer = self.sealer.as_ref().ok_or_else(|| {
            RpcError::FailedPrecondition(
                "Hub draft signing is unavailable; configure HUB_SEAL_KEY".to_string(),
            )
        })?;
        let fetch = self.topology_surface_fetcher(SurfaceTarget::Registry(registry.id));
        let placement = self
            .effective_surface_writer(SurfaceTarget::Registry(registry.id))
            .await?;
        let writer = self
            .surface_write
            .placement_writer(&placement)
            .await
            .map_err(RpcError::internal)?;
        let proposed = crate::gitwrite::propose_config_change_with_id(
            &self.db,
            sealer.as_ref(),
            fetch.as_ref(),
            writer.as_ref(),
            &registry,
            crate::config::ChangeId(plan.plan_id.clone()),
            "registry.toml",
            &new_contents,
            &claims.owner_kind,
            Some(claims.owner_id),
            &claims.sub,
            clock::now_unix_secs(),
            crate::gitwrite::ProposeMeta {
                title: Some("Update consumer cache stack".to_string()),
                body: Some("Topology-reviewed signed registry configuration change".to_string()),
            },
        )
        .await
        .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.record_consumer_publication_intent(
            &registry,
            proposed.change_id.as_str(),
            change,
            &ready_routes,
        )
        .await?;
        let response = pb::ConsumerCacheChangesetResponse {
            change_id: proposed.change_id.to_string(),
            state: "draft".to_string(),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Validates the indexed stack's closed sources and exact managed-route pins.
    ///
    /// # Errors
    ///
    /// Returns an authorization or database error.
    pub async fn validate_consumer_cache_stack(
        &self,
        auth: Option<&str>,
        req: pb::GetConsumerCacheStackRequest,
    ) -> Result<pb::ConsumerCacheStackValidationResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry_id).await?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::Read,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        let rows = self
            .db
            .registry_cache_stack_entries(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut paths = std::collections::BTreeSet::new();
        for row in &rows {
            if !paths.insert(row.stack_path.as_str()) {
                errors.push(format!("duplicate stack entry id '{}'", row.stack_path));
            }
            if let Some(cache_id) = row.cache_id {
                if row.route_id.is_none()
                    || row.route_configuration_generation.is_none()
                    || row.route_configuration_digest.is_none()
                {
                    errors.push(format!(
                        "managed entry '{}' lacks an exact route generation pin",
                        row.stack_path
                    ));
                }
                if self
                    .db
                    .binary_cache_by_id(cache_id)
                    .await
                    .map_err(RpcError::internal)?
                    .is_none()
                {
                    errors.push(format!(
                        "managed entry '{}' references a missing binary cache",
                        row.stack_path
                    ));
                }
            } else if let Err(error) =
                aos_hub_model::url_guard::is_safe_remote_url(&row.committed_url)
            {
                errors.push(format!(
                    "external entry '{}' has an unsafe URL: {error:#}",
                    row.stack_path
                ));
            }
        }
        if rows.is_empty() {
            warnings.push("the registry has no signed consumer-cache entries".to_string());
        }
        Ok(pb::ConsumerCacheStackValidationResponse {
            valid: errors.is_empty(),
            errors,
            warnings,
        })
    }
}
