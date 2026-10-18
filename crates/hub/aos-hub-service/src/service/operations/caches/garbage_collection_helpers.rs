//! Garbage collection helpers in the caches capability.

use super::*;

impl RpcService {
    pub(in crate::service) fn cache_gc_policy_message(
        policy: &aos_hub_db::db::CacheGcPolicyRecord,
    ) -> pb::CacheGcPolicy {
        pb::CacheGcPolicy {
            unreferenced_grace_seconds: policy.unreferenced_grace_secs,
            soft_max_bytes: policy
                .soft_max_bytes
                .and_then(|value| u64::try_from(value).ok()),
            soft_max_objects: policy
                .soft_max_objects
                .and_then(|value| u64::try_from(value).ok()),
            schedule: policy
                .schedule_secs
                .map(|value| value.to_string())
                .unwrap_or_default(),
            deletion_concurrency: u32::try_from(policy.deletion_concurrency).unwrap_or_default(),
            retry_initial_seconds: policy.retry_initial_secs,
            retry_max_seconds: policy.retry_max_secs,
            retry_max_attempts: u32::try_from(policy.retry_max_attempts).unwrap_or_default(),
            tombstone_retention_seconds: policy.tombstone_retention_secs,
            policy_version: policy.resource_version,
            resource_version: policy.resource_version.to_string(),
        }
    }

    pub(in crate::service) fn cache_gc_generation_message(
        cache_id: &str,
        state: &aos_hub_db::db::CacheGcStateRecord,
    ) -> pb::CacheGcGeneration {
        pb::CacheGcGeneration {
            cache_id: cache_id.to_string(),
            epoch: state.epoch,
            state: if state.destructive_enabled {
                "enabled"
            } else {
                "first_sweep_required"
            }
            .to_string(),
            resource_version: state.resource_version.to_string(),
        }
    }

    pub(in crate::service) fn cache_gc_plan_message(
        cache_id: &str,
        plan: &aos_hub_db::db::CacheGcPlanView,
    ) -> pb::CacheGcPlan {
        pb::CacheGcPlan {
            plan_id: plan.plan_id.clone(),
            cache_id: cache_id.to_string(),
            expires_at: plan.expires_at,
            gc_epoch: plan.expected_epoch,
            policy_version: plan.policy_version,
            root_set_version: plan.root_generation.to_string(),
            object_set_version: plan.object_graph_generation.to_string(),
            topology_version: plan.topology_generation.to_string(),
            candidates: plan
                .objects
                .iter()
                .map(|object| pb::CacheGcCandidate {
                    store_hash: object.store_hash.clone(),
                    logical_bytes: u64::try_from(object.logical_bytes).unwrap_or_default(),
                    blocking_reasons: Vec::new(),
                })
                .collect(),
            placement_actions: plan
                .actions
                .iter()
                .map(|action| pb::CacheGcPlacementAction {
                    placement_id: action.placement_id.to_string(),
                    store_hash: action.store_hash.clone(),
                    action: format!("delete_{}", action.phase),
                    inventory_version: action.inventory_generation.to_string(),
                })
                .collect(),
            coverage_failures: Vec::new(),
            candidate_manifest_hash: plan.manifest_digest.clone(),
            confirmation_hash: plan.confirmation_hash.clone(),
        }
    }

    pub(in crate::service) fn cache_gc_actor_scope_digest(scope: &str, claims: &Claims) -> String {
        hex::encode(Sha256::digest(
            format!(
                "scope={scope};actor={}:{}",
                claims.owner_kind, claims.owner_id
            )
            .as_bytes(),
        ))
    }

    pub(in crate::service) async fn cache_gc_run_message(
        &self,
        cache: &aos_hub_db::db::BinaryCache,
        operation: &aos_hub_db::db::TopologyOperationRecord,
    ) -> Result<pb::CacheGcRun, RpcError> {
        let plan_id = self
            .db
            .cache_gc_operation_plan_id(cache.id, &operation.operation_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC operation plan"))?;
        let _plan = self
            .db
            .cache_gc_plan_view(cache.id, &plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC plan"))?;
        let (scanned, retained, tombstoned, logical_bytes) = self
            .db
            .cache_gc_plan_accounting(cache.id, &plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC accounting"))?;
        Ok(pb::CacheGcRun {
            operation_id: operation.operation_id.clone(),
            cache_id: cache.slug.clone(),
            plan_id,
            state: operation.state.clone(),
            scanned_objects: u64::try_from(scanned).map_err(RpcError::internal)?,
            retained_objects: u64::try_from(retained).map_err(RpcError::internal)?,
            tombstoned_objects: u64::try_from(tombstoned).map_err(RpcError::internal)?,
            logical_bytes_reclaimed: u64::try_from(logical_bytes).map_err(RpcError::internal)?,
            error: operation.error.clone().unwrap_or_default(),
            created_at: operation.created_at,
            finished_at: operation.finished_at,
        })
    }

    pub(in crate::service) async fn cache_gc_deletion_job_message(
        &self,
        cache_id: i64,
        job: &aos_hub_db::db::ObjectDeletionJobRecord,
    ) -> Result<pb::CacheGcDeletionJob, RpcError> {
        Ok(pb::CacheGcDeletionJob {
            job_id: job.job_id.clone(),
            operation_id: job.operation_id.clone(),
            placement_id: job.placement_id.to_string(),
            store_hash: self
                .db
                .cache_gc_deletion_job_store_hash(cache_id, &job.job_id)
                .await
                .map_err(RpcError::internal)?
                .unwrap_or_default(),
            state: job.state.clone(),
            attempts: u32::try_from(job.attempt_count).unwrap_or_default(),
            last_error: job.error.clone().unwrap_or_default(),
            next_attempt_at: job.next_attempt_at.unwrap_or_default(),
            resource_version: job.resource_version.to_string(),
        })
    }

    /// Requeues an exact failed deletion job version.
    pub(in crate::service) async fn execute_retry_cache_gc_deletion_job(
        &self,
        auth: Option<&str>,
        req: pb::PlanRetryCacheGcDeletionJobRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcExecute)
            .await?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        let version = parse_resource_version(&req.expected_resource_version, 0)?;
        self.db
            .object_deletion_job(cache.id, &req.job_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC deletion job"))?;
        let job = self
            .db
            .retry_cache_gc_deletion_job(
                cache.id,
                &req.job_id,
                version,
                &req.idempotency_key,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let operation = self
            .db
            .topology_operation(&job.operation_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC operation"))?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        })
    }
}
