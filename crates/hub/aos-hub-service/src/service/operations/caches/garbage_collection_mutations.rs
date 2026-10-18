//! Garbage collection mutations in the caches capability.

use super::*;

impl RpcService {
    /// Applies a reviewed cache-GC policy plan under policy and epoch CAS.
    pub async fn set_cache_gc_policy(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::GetCacheGcPolicyResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "set_cache_gc_policy",
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
            "set_cache_gc_policy",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanSetCacheGcPolicyRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "set_cache_gc_policy",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&planned.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheRetentionManage)
            .await?;
        let desired = planned
            .desired
            .ok_or_else(|| RpcError::invalid("desired policy is required"))?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let schedule_secs = if desired.schedule.is_empty() {
            None
        } else {
            Some(
                desired
                    .schedule
                    .parse::<i64>()
                    .map_err(|_| RpcError::invalid("schedule must be integer seconds"))?,
            )
        };
        let policy = aos_hub_db::db::CacheGcPolicyRecord {
            cache_id: cache.id,
            unreferenced_grace_secs: desired.unreferenced_grace_seconds,
            soft_max_bytes: desired
                .soft_max_bytes
                .and_then(|value| i64::try_from(value).ok()),
            soft_max_objects: desired
                .soft_max_objects
                .and_then(|value| i64::try_from(value).ok()),
            schedule_secs,
            deletion_concurrency: i64::from(desired.deletion_concurrency),
            retry_initial_secs: desired.retry_initial_seconds,
            retry_max_secs: desired.retry_max_seconds,
            retry_max_attempts: i64::from(desired.retry_max_attempts),
            tombstone_retention_secs: desired.tombstone_retention_seconds,
            resource_version: parse_resource_version(&planned.expected_resource_version, 0)?,
        };
        self.db
            .set_cache_gc_policy_topology(
                &policy,
                state.epoch,
                &uuid::Uuid::new_v4().to_string(),
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let current = self
            .db
            .cache_gc_policy_topology(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC policy"))?;
        let current_state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let response = pb::GetCacheGcPolicyResponse {
            policy: Some(Self::cache_gc_policy_message(&current)),
            generation: Some(Self::cache_gc_generation_message(
                &cache.slug,
                &current_state,
            )),
        };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies a complete GC plan; the first sweep cannot use this endpoint.
    pub async fn run_cache_gc(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let plan_cache_id = self
            .db
            .cache_gc_plan_view_by_id(&req.plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC plan"))?;
        let cache = self
            .db
            .binary_cache_by_id(plan_cache_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binary cache"))?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcExecute)
            .await?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let claims = self.require_claims(auth)?;
        let scope = cache.scope_key.clone();
        let operation_id = hex::encode(Sha256::digest(
            format!("gc:{}:{}", req.plan_id, req.idempotency_key).as_bytes(),
        ));
        self.db
            .apply_cache_gc_plan_topology(&aos_hub_db::db::ApplyCacheGcPlan {
                plan_id: req.plan_id,
                claim_id: hex::encode(Sha256::digest(format!("claim:{operation_id}").as_bytes())),
                operation_id: operation_id.clone(),
                actor_scope_digest: Self::cache_gc_actor_scope_digest(&scope, &claims),
                confirmation_hash: req.confirmation_hash,
                now: clock::now_unix_secs(),
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let operation = self
            .db
            .topology_operation(&operation_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC operation"))?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        })
    }

    /// Opens destructive GC and invalidates the acknowledged bootstrap plan.
    pub async fn acknowledge_cache_gc_first_sweep(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::CacheGcGenerationResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "acknowledge_cache_gc_first_sweep",
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
            "acknowledge_cache_gc_first_sweep",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanAcknowledgeCacheGcFirstSweepRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "acknowledge_cache_gc_first_sweep",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&planned.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcExecute)
            .await?;
        let gc_plan = self
            .db
            .cache_gc_plan_view(cache.id, &planned.gc_plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC plan"))?;
        let claims = self.require_claims(auth)?;
        let now = clock::now_unix_secs();
        let acknowledgement_id = hex::encode(Sha256::digest(
            format!("ack:{}:{}", planned.gc_plan_id, req.idempotency_key).as_bytes(),
        ));
        self.db
            .create_cache_gc_first_sweep_acknowledgement(
                &acknowledgement_id,
                cache.id,
                &planned.gc_plan_id,
                gc_plan.expected_epoch,
                gc_plan.policy_version,
                &gc_plan.manifest_digest,
                &gc_plan.confirmation_hash,
                &claims.sub,
                now,
                gc_plan.expires_at,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let scope = cache.scope_key.clone();
        self.db
            .apply_cache_gc_first_sweep_acknowledgement(
                &acknowledgement_id,
                &hex::encode(Sha256::digest(
                    format!("first-sweep-claim:{acknowledgement_id}").as_bytes(),
                )),
                &Self::cache_gc_actor_scope_digest(&scope, &claims),
                &gc_plan.confirmation_hash,
                &claims.sub,
                now,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let current = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        let response = pb::CacheGcGenerationResponse {
            generation: Some(pb::CacheGcGeneration {
                cache_id: cache.slug,
                epoch: current.epoch,
                state: "applied".to_string(),
                resource_version: current.resource_version.to_string(),
            }),
        };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies reviewed deletion-job abandonment.
    pub async fn abandon_cache_gc_deletion_job(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::CacheGcDeletionJobResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "abandon_cache_gc_deletion_job",
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
            "abandon_cache_gc_deletion_job",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanAbandonCacheGcDeletionJobRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "abandon_cache_gc_deletion_job",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&planned.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcExecute)
            .await?;
        let job = self
            .db
            .abandon_cache_gc_deletion_job(
                cache.id,
                &planned.job_id,
                parse_resource_version(&planned.expected_resource_version, 0)?,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::CacheGcDeletionJobResponse {
            job: Some(self.cache_gc_deletion_job_message(cache.id, &job).await?),
        };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
