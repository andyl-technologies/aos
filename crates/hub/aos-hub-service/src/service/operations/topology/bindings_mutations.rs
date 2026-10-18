//! Bindings mutations in the topology capability.

use super::*;

impl RpcService {
    /// `BindingService.CreateBinding` applies a create plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, conflict, or persistence error.
    pub async fn apply_create_binding(
        &self,
        auth: Option<&str>,
        req: pb::ApplyBindingMutationRequest,
    ) -> Result<pb::BindingResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_binding",
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
            "create_binding",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, BindingMutationPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_binding",
                Some(&req.confirmation_hash),
            )
            .await?;
        if self
            .writable_storage_owner(auth, &input.request.owner_scope_key)
            .await?
            != input.org_id
        {
            return Err(RpcError::FailedPrecondition(
                "binding owner changed after planning".to_string(),
            ));
        }
        if let Some(existing) = self
            .db
            .binding_by_stable_id(&input.request.stable_id)
            .await
            .map_err(RpcError::internal)?
        {
            let expected =
                input.request.spec.as_ref().ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("binding plan has no spec"))
                })?;
            if existing.owner_scope_key == input.request.owner_scope_key
                && Self::binding_spec_from_record(&existing)? == *expected
            {
                let response = pb::BindingResponse {
                    binding: Some(self.binding_message(existing).await?),
                };
                self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                    .await?;
                return Ok(response);
            }
            return Err(RpcError::AlreadyExists(
                "binding stable id has different state".to_string(),
            ));
        }
        let spec = input
            .request
            .spec
            .as_ref()
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("binding plan has no spec")))?;
        let (scheme, host_kind, host_bytes, port) = Self::storage_endpoint_parts(spec);
        let (kind, local_root_path, object_bucket, object_prefix, signing_region, access_mode) =
            match spec.provider.as_ref() {
                Some(pb::binding_spec::Provider::LocalFilesystem(provider)) => (
                    "local_fs",
                    Some(provider.root_path.as_str()),
                    None,
                    None,
                    None,
                    None,
                ),
                Some(pb::binding_spec::Provider::S3(provider)) => (
                    "s3",
                    None,
                    Some(provider.bucket.as_str()),
                    Some(provider.prefix.as_str()),
                    Some(provider.signing_region.as_str()),
                    Some(provider.access_mode.as_str()),
                ),
                Some(pb::binding_spec::Provider::R2(provider)) => (
                    "r2",
                    None,
                    Some(provider.bucket.as_str()),
                    Some(provider.prefix.as_str()),
                    Some(provider.signing_region.as_str()),
                    Some(provider.access_mode.as_str()),
                ),
                Some(pb::binding_spec::Provider::DeploymentR2(provider)) => (
                    "deployment_r2",
                    None,
                    Some(provider.bucket_binding.as_str()),
                    Some(""),
                    None,
                    None,
                ),
                None => {
                    return Err(RpcError::internal(anyhow::anyhow!(
                        "binding plan has no provider"
                    )));
                }
            };
        self.db
            .create_topology_binding(
                input.org_id,
                &input.request.stable_id,
                &input.request.owner_scope_key,
                &spec.name,
                kind,
                local_root_path,
                object_bucket,
                object_prefix,
                scheme,
                host_kind,
                host_bytes,
                port,
                signing_region,
                access_mode,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let record = self
            .db
            .binding_by_stable_id(&input.request.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("created binding disappeared")))?;
        if matches!(record.kind.as_str(), "local_fs" | "deployment_r2") {
            self.db
                .ensure_deployment_owned_write_revision(&record)
                .await
                .map_err(RpcError::internal)?;
        }
        let response = pb::BindingResponse {
            binding: Some(self.binding_message(record).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// `BindingService.DeleteBinding` applies a deletion plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, stale-version, blocker, or persistence error.
    pub async fn apply_delete_binding(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_binding",
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
            "delete_binding",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, BindingDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_binding",
                Some(&req.confirmation_hash),
            )
            .await?;
        if self
            .writable_storage_owner(auth, &input.owner_scope_key)
            .await?
            != input.org_id
        {
            return Err(RpcError::FailedPrecondition(
                "binding deletion plan target changed".to_string(),
            ));
        }
        let Some(binding) = self
            .db
            .binding_by_stable_id(&input.stable_id)
            .await
            .map_err(RpcError::internal)?
        else {
            let response = pb::DeleteTopologyResourceResponse { deleted: true };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        };
        if binding.id != input.binding_db_id
            || binding.resource_version != input.baseline_resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "binding changed after deletion was planned".to_string(),
            ));
        }
        let blockers = self
            .db
            .binding_delete_blockers(binding.id)
            .await
            .map_err(RpcError::internal)?;
        if !blockers.is_empty() {
            return Err(RpcError::FailedPrecondition(format!(
                "binding acquired live references: {}",
                blockers.join(", ")
            )));
        }
        if !self
            .db
            .delete_topology_binding(binding.id, input.baseline_resource_version)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::FailedPrecondition(
                "binding changed while deletion was applied".to_string(),
            ));
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies a consumer-scope grant.
    pub async fn apply_grant_binding_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_binding_grant(auth, req, false).await
    }

    /// Applies a consumer-scope revocation.
    pub async fn apply_revoke_binding_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_binding_grant(auth, req, true).await
    }

    /// Reconciles a write revision's validation observation under a CAS.
    pub async fn report_binding_write_revision(
        &self,
        auth: Option<&str>,
        req: pb::ReportBindingWriteRevisionRequest,
    ) -> Result<pb::BindingWriteRevisionResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let binding = self
            .db
            .binding_by_stable_id(&req.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        self.writable_storage_owner(auth, &binding.owner_scope_key)
            .await?;
        let observation = self
            .db
            .binding_write_observation(binding.id, req.revision)
            .await
            .map_err(RpcError::internal)?;
        let current_version = observation
            .as_ref()
            .map_or(0, |observation| observation.observation_version);
        if observation.as_ref().is_some_and(|observation| {
            observation.state == req.state
                && observation.error.as_deref()
                    == (!req.validation_error.is_empty()).then_some(req.validation_error.as_str())
        }) {
            let revision = self
                .db
                .binding_write_revision(binding.id, req.revision)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("binding write revision"))?;
            return Ok(pb::BindingWriteRevisionResponse {
                revision: Some(
                    self.binding_write_revision_message(&req.binding_id, revision)
                        .await?,
                ),
            });
        }
        let expected = parse_resource_version(&req.expected_observation_version, current_version)?;
        let expected = (current_version > 0).then_some(expected);
        self.db
            .observe_binding_write_revision(
                binding.id,
                req.revision,
                &req.state,
                (!req.validation_error.is_empty()).then_some(req.validation_error.as_str()),
                expected,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let revision = self
            .db
            .binding_write_revision(binding.id, req.revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding write revision"))?;
        Ok(pb::BindingWriteRevisionResponse {
            revision: Some(
                self.binding_write_revision_message(&req.binding_id, revision)
                    .await?,
            ),
        })
    }
}
