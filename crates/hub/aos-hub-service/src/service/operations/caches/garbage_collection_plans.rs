//! Garbage collection plans in the caches capability.

use super::*;

impl RpcService {
    /// Plans an exact cache-global garbage-collection policy replacement.
    pub async fn plan_set_cache_gc_policy(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetCacheGcPolicyRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheRetentionManage)
            .await?;
        let current = self
            .db
            .cache_gc_policy_topology(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC policy"))?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected != current.resource_version || req.desired.is_none() {
            return Err(RpcError::FailedPrecondition(
                "cache GC policy version is stale or desired policy is missing".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        self.create_control_plan(
            &claims,
            "set_cache_gc_policy",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["replace cache-global retention and sweep mechanics".to_string()],
            vec!["all complete mark generations and unapplied plans become stale".to_string()],
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&req).map_err(RpcError::internal)?,
            ))),
        )
        .await
    }

    /// Builds a complete immutable mark generation and physical GC plan.
    pub async fn plan_run_cache_gc(
        &self,
        auth: Option<&str>,
        req: pb::PlanRunCacheGcRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcPlan)
            .await?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        if parse_resource_version(&req.expected_resource_version, 0)? != state.resource_version {
            return Err(RpcError::FailedPrecondition(
                "cache GC state resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let scope = cache.scope_key.clone();
        let now = clock::now_unix_secs();
        let request_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(RpcError::internal)?,
        ));
        let plan = self
            .db
            .build_cache_gc_plan_topology(
                cache.id,
                &Self::cache_gc_actor_scope_digest(&scope, &claims),
                &claims.sub,
                &req.idempotency_key,
                &request_digest,
                now,
                now + TOPOLOGY_PLAN_TTL_SECS,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let details = Self::cache_gc_plan_message(&cache.slug, &plan);
        Ok(pb::TopologyPlanResponse {
            plan: Some(pb::TopologyPlan {
                plan_id: details.plan_id,
                expires_at: details.expires_at,
                input_versions: vec![
                    format!("cache_gc_epoch={}", details.gc_epoch),
                    format!("cache_gc_policy={}", details.policy_version),
                    format!("cache_root_set={}", details.root_set_version),
                    format!("cache_object_set={}", details.object_set_version),
                    format!("cache_topology={}", details.topology_version),
                ],
                effects: vec![
                    format!("delete {} unretained objects", details.candidates.len()),
                    format!(
                        "execute {} placement actions",
                        details.placement_actions.len()
                    ),
                ],
                warnings: details.coverage_failures,
                confirmation_hash: details.confirmation_hash,
                pin_impacts: Vec::new(),
            }),
        })
    }

    /// Plans the one explicit acknowledgement that opens destructive GC.
    pub async fn plan_acknowledge_cache_gc_first_sweep(
        &self,
        auth: Option<&str>,
        req: pb::PlanAcknowledgeCacheGcFirstSweepRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcExecute)
            .await?;
        let plan = self
            .db
            .cache_gc_plan_view(cache.id, &req.gc_plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC plan"))?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        if parse_resource_version(&req.expected_resource_version, 0)? != state.resource_version {
            return Err(RpcError::FailedPrecondition(
                "cache GC state resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        self.create_control_plan(
            &claims,
            "acknowledge_cache_gc_first_sweep",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["open destructive GC and invalidate the reviewed bootstrap plan".to_string()],
            vec!["a fresh GC plan must be built and reviewed before deletion".to_string()],
            Some(plan.confirmation_hash),
        )
        .await
    }

    /// Plans reviewed abandonment of an exhausted or deliberately leaked job.
    pub async fn plan_abandon_cache_gc_deletion_job(
        &self,
        auth: Option<&str>,
        req: pb::PlanAbandonCacheGcDeletionJobRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcExecute)
            .await?;
        let job = self
            .db
            .object_deletion_job(cache.id, &req.job_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC deletion job"))?;
        if parse_resource_version(&req.expected_resource_version, 0)? != job.resource_version {
            return Err(RpcError::FailedPrecondition(
                "cache GC deletion job resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        self.create_control_plan(
            &claims,
            "abandon_cache_gc_deletion_job",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["stop retries and account expected bytes as possibly leaked".to_string()],
            vec!["abandonment does not count bytes as confirmed reclaimed".to_string()],
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&req).map_err(RpcError::internal)?,
            ))),
        )
        .await
    }
}
