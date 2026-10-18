//! Garbage collection reads in the caches capability.

use super::*;

impl RpcService {
    /// Returns a cache's global garbage-collection policy.
    pub async fn get_cache_gc_policy(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheGcPolicyRequest,
    ) -> Result<pb::GetCacheGcPolicyResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let policy = self
            .db
            .cache_gc_policy_topology(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC policy"))?;
        let state = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC state"))?;
        Ok(pb::GetCacheGcPolicyResponse {
            policy: Some(Self::cache_gc_policy_message(&policy)),
            generation: Some(Self::cache_gc_generation_message(&cache.slug, &state)),
        })
    }

    /// Returns a persisted cache-GC plan.
    pub async fn get_cache_gc_plan(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheGcPlanRequest,
    ) -> Result<pb::CacheGcPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let plan = self
            .db
            .cache_gc_plan_view(cache.id, &req.plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC plan"))?;
        Ok(pb::CacheGcPlanResponse {
            plan: Some(Self::cache_gc_plan_message(&cache.slug, &plan)),
        })
    }

    /// Returns one cache-GC operation projection.
    pub async fn get_cache_gc_run(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheOperationRequest,
    ) -> Result<pb::CacheGcRunResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let operation = self
            .db
            .topology_operation(&req.operation_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|operation| operation.operation_kind == "cache_gc")
            .ok_or_else(|| RpcError::not_found("cache GC operation"))?;
        let targets = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await
            .map_err(RpcError::internal)?;
        if !targets.iter().any(|target| {
            target.target_kind == "binary_cache" && target.stable_id == cache.stable_id
        }) {
            return Err(RpcError::not_found("cache GC operation"));
        }
        Ok(pb::CacheGcRunResponse {
            run: Some(self.cache_gc_run_message(&cache, &operation).await?),
        })
    }

    /// Lists cache-GC operations with opaque cursor pagination.
    pub async fn list_cache_gc_runs(
        &self,
        auth: Option<&str>,
        req: pb::ListCacheGcRunsRequest,
    ) -> Result<pb::ListCacheGcRunsResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let operations = self
            .db
            .list_topology_operations("binary_cache", &cache.stable_id)
            .await
            .map_err(RpcError::internal)?;
        let mut runs = Vec::new();
        for operation in operations
            .iter()
            .filter(|operation| operation.operation_kind == "cache_gc")
        {
            runs.push(self.cache_gc_run_message(&cache, operation).await?);
        }
        let (runs, next_page_token) = paginate(runs, req.page_size, &req.page_token)?;
        Ok(pb::ListCacheGcRunsResponse {
            runs,
            next_page_token,
        })
    }

    /// Returns one placement-scoped cache-GC deletion job.
    pub async fn get_cache_gc_deletion_job(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheGcDeletionJobRequest,
    ) -> Result<pb::CacheGcDeletionJobResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let job = self
            .db
            .object_deletion_job(cache.id, &req.job_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache GC deletion job"))?;
        Ok(pb::CacheGcDeletionJobResponse {
            job: Some(self.cache_gc_deletion_job_message(cache.id, &job).await?),
        })
    }

    /// Lists deletion jobs for a cache or one GC operation.
    pub async fn list_cache_gc_deletion_jobs(
        &self,
        auth: Option<&str>,
        req: pb::ListCacheGcDeletionJobsRequest,
    ) -> Result<pb::ListCacheGcDeletionJobsResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let jobs = self
            .db
            .list_cache_gc_deletion_jobs_topology(
                cache.id,
                (!req.operation_id.is_empty()).then_some(req.operation_id.as_str()),
            )
            .await
            .map_err(RpcError::internal)?;
        let mut messages = Vec::with_capacity(jobs.len());
        for job in &jobs {
            messages.push(self.cache_gc_deletion_job_message(cache.id, job).await?);
        }
        let (jobs, next_page_token) = paginate(messages, req.page_size, &req.page_token)?;
        Ok(pb::ListCacheGcDeletionJobsResponse {
            jobs,
            next_page_token,
        })
    }
}
