//! Configuration mutations in the administration capability.

use super::*;

impl RpcService {
    /// Applies one reviewed instance-settings plan exactly once.
    pub async fn apply_set_instance_settings(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::GetInstanceSettingsResponse, RpcError> {
        const PLAN_KIND: &str = "set_instance_settings";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                PLAN_KIND,
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
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, InstanceSettingsPlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let current = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        if instance_settings_digest(&current)? != input.baseline_digest {
            return Err(RpcError::FailedPrecondition(
                "instance settings changed after planning".to_string(),
            ));
        }
        for (key, value) in &input.writes {
            self.db
                .replace_instance_setting_value(key, value.as_deref())
                .await
                .map_err(RpcError::internal)?;
        }

        let actor_id = claims_principal(&claims).map(|principal| principal.id);
        let touched: Vec<&str> = input.writes.iter().map(|(key, _)| key.as_str()).collect();
        let detail = touched.join(", ");
        if let Err(err) = self
            .db
            .record_audit(
                &claims.owner_kind,
                actor_id,
                &claims.sub,
                "instance.settings",
                "",
                Some(&plan.plan_id),
                None,
                None,
                Some(&detail),
            )
            .await
        {
            tracing::warn!(error = %format!("{err:#}"), "recording instance.settings audit");
        }

        let settings = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        crate::web::console_render::apply_instance_settings(&settings);
        let response = pb::GetInstanceSettingsResponse {
            resource_version: instance_settings_digest(&settings)?,
            settings: Some(instance_settings_to_pb(&settings)),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// The instance settings, read-through cached in KV when one is attached
    /// (RFC-0004 ch.14 Phase C, the `cfg:instance` singleton).
    ///
    /// A short-TTL cache off the database; the eventual-consistency contract
    /// (≤ [`HOT_TTL_SECS`](crate::cache::HOT_TTL_SECS) staleness) is acceptable
    /// for site chrome / signup policy. Falls back to the database with no `kv`.
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read or database failure.
    pub async fn instance_settings_cached(&self) -> anyhow::Result<crate::db::InstanceSettings> {
        let Some(kv) = &self.kv else {
            return self.db.instance_settings().await;
        };
        let db = &self.db;
        let cached = crate::cache::read_through(
            kv.as_ref(),
            "cfg:instance",
            Some(crate::cache::HOT_TTL_SECS),
            || async move { db.instance_settings().await.map(Some) },
        )
        .await?;
        // `instance_settings` always yields a value (defaults), so a `None` here
        // can only be a transient miss; fall back to a direct read.
        match cached {
            Some(settings) => Ok(settings),
            None => self.db.instance_settings().await,
        }
    }

    /// Enqueues one scheduled maintenance job immediately.
    ///
    /// Maintenance normally runs on the deployment's tick. Registry
    /// retirement and incident response need the probe, inventory, GC, and
    /// recovery jobs between reviewed steps, so an instance administrator may
    /// run any scheduled job on demand. Each job still applies its own durable
    /// fences and bounded page size; the OCI jobs additionally require the
    /// garbage-collection rollout.
    ///
    /// # Errors
    ///
    /// Returns authentication or authorization errors, an invalid-argument
    /// error for an unknown job, an unavailable error when the runtime has no
    /// durable queue or the job's rollout is disabled, and an internal error
    /// when the queue rejects the job.
    pub async fn trigger_instance_maintenance(
        &self,
        auth: Option<&str>,
        req: pb::TriggerInstanceMaintenanceRequest,
    ) -> Result<pb::InstanceMaintenanceTriggerResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
            .await?;
        let job = match req.job.as_str() {
            "dispatch_maintenance" => Job::DispatchMaintenance,
            "run_topology_probes" => Job::RunTopologyProbes,
            "recover_cache_writes" => Job::RecoverCacheWrites,
            "recover_oci_uploads" => Job::RecoverOciUploads,
            "run_cache_gc" => Job::RunCacheGc,
            "rebuild_directory" => Job::RebuildDirectory,
            "inventory_oci_providers" => Job::InventoryOciProviders,
            "probe_oci_conditional_deletes" => Job::ProbeOciConditionalDeletes,
            "run_oci_gc" => Job::RunOciGc,
            _ => {
                return Err(RpcError::invalid(
                    "job must name one scheduled maintenance job (see TriggerInstanceMaintenanceRequest)",
                ));
            }
        };
        if !job.enabled_for(self.container_rollout) {
            return Err(RpcError::Unavailable(
                "this deployment has not enabled OCI garbage collection".into(),
            ));
        }
        let queue = self.maintenance_jobs.as_ref().ok_or_else(|| {
            RpcError::Unavailable("this deployment cannot schedule maintenance on demand".into())
        })?;
        queue.enqueue(&job).await.map_err(RpcError::internal)?;
        Ok(pb::InstanceMaintenanceTriggerResponse { job: req.job })
    }
}
