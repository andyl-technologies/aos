//! Retention mutations in the caches capability.

use super::*;

impl RpcService {
    /// Applies a reviewed retention-subscription replacement.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-plan, stale-version, validation, or database error.
    pub async fn set_retention_subscription(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::RetentionSubscriptionResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "set_retention_subscription",
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
            "set_retention_subscription",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, pb::PlanRetentionSubscriptionRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "set_retention_subscription",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (cache, registry) = self
            .authorized_cache_registry_retention_pair(
                auth,
                &input.cache_id,
                &input.registry_id,
                true,
            )
            .await?;
        let mut desired = input
            .desired
            .ok_or_else(|| RpcError::invalid("plan desired state is missing"))?;
        Self::canonicalize_retention_spec(&mut desired)?;
        let selector = desired
            .selector
            .as_ref()
            .ok_or_else(|| RpcError::invalid("selector is required"))?;
        // The database binds the digest to the canonical JSON object form.
        // Protobuf structs serialize in declaration order, which is not
        // necessarily the map-key order produced when that document is read
        // back as JSON. Normalize through `Value` before hashing and storing.
        let selector_value = serde_json::to_value(selector).map_err(RpcError::internal)?;
        let selector_json = serde_json::to_string(&selector_value).map_err(RpcError::internal)?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let record = self
            .db
            .set_cache_retention_subscription_topology(
                &aos_hub_db::db::SetCacheRetentionSubscriptionTopology {
                    cache_id: cache.id,
                    registry_id: registry.id,
                    selector_digest: hex::encode(Sha256::digest(selector_json.as_bytes())),
                    selector_json,
                    removal_grace_secs: desired.removal_grace_seconds,
                    exposure_acknowledged_at: None,
                    enabled: true,
                    expected_resource_version: input.expected_resource_version.parse::<i64>().ok(),
                    expected_cache_epoch: state.epoch,
                    mutation_id: plan.plan_id.clone(),
                    now: clock::now_unix_secs(),
                },
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::RetentionSubscriptionResponse {
            subscription: Some(Self::retention_subscription_message(
                &record,
                &cache.slug,
                &registry.slug,
            )?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies retirement of one retention subscription.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-plan, stale-version, or database error.
    pub async fn delete_retention_subscription(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_retention_subscription",
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
            "delete_retention_subscription",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, pb::PlanDeleteRetentionSubscriptionRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_retention_subscription",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (cache, registry) = self
            .authorized_cache_registry_retention_pair(
                auth,
                &input.cache_id,
                &input.registry_id,
                true,
            )
            .await?;
        let current = self
            .db
            .cache_retention_subscription_topology(cache.id, registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("retention subscription"))?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        self.db
            .retire_cache_retention_subscription_topology(
                current.id,
                cache.id,
                parse_resource_version(&input.expected_resource_version, current.resource_version)?,
                state.epoch,
                &plan.plan_id,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies a reviewed manual-retention-root creation.
    pub async fn create_manual_retention_root(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::RetentionRootResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_manual_retention_root",
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
            "create_manual_retention_root",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanManualRetentionRootRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_manual_retention_root",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&planned.cache_id).await?;
        let claims = self
            .require_retention_root_creation_authority(auth, &cache, planned.lease_until.is_some())
            .await?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let root_id = uuid::Uuid::new_v4().to_string();
        let lease_id = planned
            .lease_until
            .map(|_| uuid::Uuid::new_v4().to_string());
        let root = self
            .db
            .create_manual_retention_root_topology(&aos_hub_db::db::CreateManualRetentionRoot {
                root_id,
                reason_id: uuid::Uuid::new_v4().to_string(),
                cache_id: cache.id,
                store_hash: planned.store_hash,
                reason: planned.reason,
                actor: claims.sub.clone(),
                actor_kind: claims.owner_kind.clone(),
                actor_id: claims.owner_id,
                lease_id,
                lease_expires_at: planned.lease_until,
                expected_epoch: state.epoch,
                mutation_id: uuid::Uuid::new_v4().to_string(),
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::RetentionRootResponse {
            root: Some(
                self.manual_retention_root_message(
                    &cache.slug,
                    &root,
                    self.require_cache_permission(auth, &cache, Permission::AuditRead)
                        .await
                        .is_ok(),
                )
                .await?,
            ),
        };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies a reviewed retention-lease renewal.
    pub async fn renew_retention_lease(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::RetentionLeaseResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "renew_retention_lease",
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
            "renew_retention_lease",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanRetentionLeaseRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "renew_retention_lease",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&planned.cache_id).await?;
        let root = self
            .db
            .manual_retention_root(cache.id, &planned.root_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("manual retention root"))?;
        let claims = self
            .require_retention_lease_authority(auth, &cache, &root)
            .await?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let lease = self
            .db
            .renew_retention_lease_topology(&aos_hub_db::db::RenewRetentionLease {
                root_id: planned.root_id,
                lease_id: if planned.lease_id.is_empty() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    planned.lease_id
                },
                reason_id: uuid::Uuid::new_v4().to_string(),
                cache_id: cache.id,
                expected_root_version: parse_resource_version(
                    &planned.expected_resource_version,
                    0,
                )?,
                expires_at: planned
                    .expires_at
                    .ok_or_else(|| RpcError::invalid("expires_at is required"))?,
                actor: claims.sub,
                expected_epoch: state.epoch,
                mutation_id: uuid::Uuid::new_v4().to_string(),
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::RetentionLeaseResponse {
            lease: Some(Self::retention_lease_message(
                lease,
                self.require_cache_permission(auth, &cache, Permission::AuditRead)
                    .await
                    .is_ok(),
            )),
        };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies reviewed retention-lease revocation.
    pub async fn revoke_retention_lease(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::RetentionLeaseResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "revoke_retention_lease",
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
            "revoke_retention_lease",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanRevokeRetentionLeaseRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "revoke_retention_lease",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&planned.cache_id).await?;
        let lease = self
            .db
            .retention_lease(&planned.lease_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("retention lease"))?;
        let root = self
            .db
            .manual_retention_root(cache.id, &lease.manual_retention_root_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("manual retention root"))?;
        let claims = self
            .require_retention_lease_authority(auth, &cache, &root)
            .await?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let lease = self
            .db
            .revoke_retention_lease_topology(
                cache.id,
                &lease.id,
                parse_resource_version(&planned.expected_resource_version, 0)?,
                state.epoch,
                &uuid::Uuid::new_v4().to_string(),
                &claims.sub,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::RetentionLeaseResponse {
            lease: Some(Self::retention_lease_message(
                lease,
                self.require_cache_permission(auth, &cache, Permission::AuditRead)
                    .await
                    .is_ok(),
            )),
        };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies reviewed manual-root deletion.
    pub async fn delete_manual_retention_root(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_manual_retention_root",
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
            "delete_manual_retention_root",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanDeleteManualRetentionRootRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_manual_retention_root",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&planned.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheRetentionManage)
            .await?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let claims = self.require_claims(auth)?;
        self.db
            .delete_manual_retention_root_topology(
                cache.id,
                &planned.root_id,
                parse_resource_version(&planned.expected_resource_version, 0)?,
                state.epoch,
                &uuid::Uuid::new_v4().to_string(),
                &claims.sub,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
