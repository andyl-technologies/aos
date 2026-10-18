//! Retention plans in the caches capability.

use super::*;

impl RpcService {
    /// Plans a typed retention-subscription replacement.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or database error.
    pub async fn plan_set_retention_subscription(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanRetentionSubscriptionRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_retention_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let desired = req
            .desired
            .as_mut()
            .ok_or_else(|| RpcError::invalid("desired is required"))?;
        Self::canonicalize_retention_spec(desired)?;
        let current = self
            .db
            .cache_retention_subscription_topology(cache.id, registry.id)
            .await
            .map_err(RpcError::internal)?;
        let expected = req.expected_resource_version.parse::<i64>().ok();
        if expected != current.as_ref().map(|record| record.resource_version) {
            return Err(RpcError::FailedPrecondition(
                "retention subscription resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "set_retention_subscription",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec![
                "replace the cache/registry retention selector and mark its materialization stale"
                    .to_string(),
            ],
            vec!["publication and population remain unchanged".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans retirement of one retention subscription.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-version, not-found, or database error.
    pub async fn plan_delete_retention_subscription(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteRetentionSubscriptionRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_retention_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let current = self
            .db
            .cache_retention_subscription_topology(cache.id, registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("retention subscription"))?;
        if parse_resource_version(&req.expected_resource_version, current.resource_version)?
            != current.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "retention subscription resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_retention_subscription",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec![
                "retire the subscription; prior reasons remain live through their recorded grace"
                    .to_string(),
            ],
            vec!["publication and population remain unchanged".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans creation of an indefinite or leased manual retention root.
    pub async fn plan_create_manual_retention_root(
        &self,
        auth: Option<&str>,
        req: pb::PlanManualRetentionRootRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_retention_root_creation_authority(auth, &cache, req.lease_until.is_some())
            .await?;
        if req.store_hash.trim().is_empty()
            || req.reason.trim().is_empty()
            || req
                .lease_until
                .is_some_and(|expiry| expiry <= clock::now_unix_secs())
        {
            return Err(RpcError::invalid(
                "store_hash/reason are required and lease_until must be in the future",
            ));
        }
        let claims = self.require_claims(auth)?;
        self.create_control_plan(
            &claims,
            "create_manual_retention_root",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec![format!("protect store object {}", req.store_hash)],
            Vec::new(),
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&req).map_err(RpcError::internal)?,
            ))),
        )
        .await
    }

    /// Plans append-only renewal of a current manual-retention lease.
    pub async fn plan_renew_retention_lease(
        &self,
        auth: Option<&str>,
        req: pb::PlanRetentionLeaseRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        let root = self
            .db
            .manual_retention_root(cache.id, &req.root_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("manual retention root"))?;
        let claims = self
            .require_retention_lease_authority(auth, &cache, &root)
            .await?;
        if parse_resource_version(&req.expected_resource_version, 0)? != root.resource_version
            || req.expires_at.is_none()
        {
            return Err(RpcError::FailedPrecondition(
                "retention root version is stale or expires_at is missing".to_string(),
            ));
        }
        self.create_control_plan(
            &claims,
            "renew_retention_lease",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["append a new lease generation and supersede the current head".to_string()],
            Vec::new(),
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&req).map_err(RpcError::internal)?,
            ))),
        )
        .await
    }

    /// Plans revocation of the exact current retention lease.
    pub async fn plan_revoke_retention_lease(
        &self,
        auth: Option<&str>,
        req: pb::PlanRevokeRetentionLeaseRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        let lease = self
            .db
            .retention_lease(&req.lease_id)
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
        if parse_resource_version(&req.expected_resource_version, 0)? != root.resource_version {
            return Err(RpcError::FailedPrecondition(
                "retention root resource version is stale".to_string(),
            ));
        }
        self.create_control_plan(
            &claims,
            "revoke_retention_lease",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["revoke the exact current lease head".to_string()],
            Vec::new(),
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&req).map_err(RpcError::internal)?,
            ))),
        )
        .await
    }

    /// Plans logical deletion of a manual retention root.
    pub async fn plan_delete_manual_retention_root(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteManualRetentionRootRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheRetentionManage)
            .await?;
        let root = self
            .db
            .manual_retention_root(cache.id, &req.root_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("manual retention root"))?;
        if parse_resource_version(&req.expected_resource_version, 0)? != root.resource_version {
            return Err(RpcError::FailedPrecondition(
                "manual retention root resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        self.create_control_plan(
            &claims,
            "delete_manual_retention_root",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["retire the manual root and revoke its current lease".to_string()],
            vec!["the object remains protected by any independent root reason".to_string()],
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&req).map_err(RpcError::internal)?,
            ))),
        )
        .await
    }
}
