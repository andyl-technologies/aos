//! Endpoints mutations in the topology capability.

use super::*;

impl RpcService {
    /// Queues controller observation for the exact desired endpoint generation.
    pub async fn complete_endpoint_probe(
        &self,
        auth: Option<&str>,
        req: pb::CompleteEndpointProbeRequest,
    ) -> Result<pb::EndpointResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let record = self
            .managed_endpoint(auth, &req.stable_id, Permission::EndpointManage)
            .await?;
        let generation = record.desired_generation.ok_or_else(|| {
            RpcError::FailedPrecondition("endpoint has no desired generation".to_string())
        })?;
        let revision = self
            .db
            .endpoint_revision(&record.id, generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint generation"))?;
        let operation_id = hex::encode(Sha256::digest(
            format!(
                "delivery-endpoint-probe-v1\0{}\0{}\0{}",
                record.id, generation, revision.content_digest
            )
            .as_bytes(),
        ));
        self.topology_probes
            .schedule(
                &operation_id,
                crate::topology_probe::TopologyProbe::Endpoint {
                    stable_id: record.id.clone(),
                    generation,
                    configuration_digest: revision.content_digest,
                },
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!("schedule endpoint probe: {error:#}"))
            })?;
        Ok(pb::EndpointResponse {
            endpoint: Some(self.endpoint_message(record).await?),
        })
    }

    /// Records controller-owned endpoint evidence under exact generation CAS.
    pub async fn report_endpoint(
        &self,
        auth: Option<&str>,
        req: pb::ReportEndpointRequest,
    ) -> Result<pb::EndpointResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let record = self
            .managed_endpoint(auth, &req.stable_id, Permission::EndpointManage)
            .await?;
        let observation = req
            .observation
            .ok_or_else(|| RpcError::invalid("observation is required"))?;
        let expected = parse_resource_version(&req.expected_observation_version, 0)?;
        if expected <= 0 || expected != record.resource_version {
            return Err(RpcError::FailedPrecondition(
                "endpoint resource version is required and must be current".to_string(),
            ));
        }
        self.db
            .reconcile_endpoint(
                &record.id,
                observation.observed_generation,
                observation.boundary_revision,
                &observation.state,
                observation.listener_observed,
                observation.tls_observed,
                (!observation.error.is_empty()).then_some(observation.error.as_str()),
                expected,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let updated = self
            .db
            .endpoint(&record.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint"))?;
        Ok(pb::EndpointResponse {
            endpoint: Some(self.endpoint_message(updated).await?),
        })
    }

    /// Applies an endpoint creation plan exactly once.
    pub async fn apply_create_endpoint(
        &self,
        auth: Option<&str>,
        req: pb::ApplyEndpointMutationRequest,
    ) -> Result<pb::EndpointResponse, RpcError> {
        self.apply_endpoint_creation(auth, req).await
    }

    /// Applies an append-only endpoint generation staging plan exactly once.
    pub async fn stage_endpoint_generation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyEndpointGenerationRequest,
    ) -> Result<pb::EndpointGenerationResponse, RpcError> {
        let plan_kind = "stage_endpoint_generation";
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                plan_kind,
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
            plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, EndpointMutationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        let endpoint = self
            .managed_endpoint(auth, &input.request.stable_id, Permission::EndpointManage)
            .await?;
        self.require_cloaked_delivery_scope(
            auth,
            &input.request.owner_scope_key,
            Permission::EndpointGrant,
            "endpoint",
        )
        .await?;
        let claims = self.require_claims(auth)?;
        for seal in &input.carried_grants {
            self.require_permission(
                &claims,
                Permission::EndpointGrant,
                &parse_authorization_scope(&seal.consumer_scope_key)?,
            )
            .await?;
        }
        if !input.affected_resources.is_empty() {
            return Err(RpcError::internal(anyhow::anyhow!(
                "endpoint stage plan contains activation impacts"
            )));
        }
        for sealed in input
            .old_boundary_revision
            .iter()
            .chain(std::iter::once(&input.new_boundary_revision))
        {
            let current = self
                .db
                .network_policy_revision(&sealed.boundary_id, sealed.revision)
                .await
                .map_err(RpcError::internal)?
                .map(Self::delivery_boundary_revision_plan_seal)
                .ok_or_else(|| RpcError::not_found("network policy revision"))?;
            if current != *sealed {
                return Err(RpcError::FailedPrecondition(
                    "boundary revision changed after endpoint planning".to_string(),
                ));
            }
        }
        let owner = input.owner_grant.ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("stage plan has no owner grant seal"))
        })?;
        let owner = aos_hub_db::db::EndpointGrantCarryForward {
            consumer_scope_key: owner.consumer_scope_key,
            grant_generation: owner.grant_generation,
            resource_version: owner.resource_version,
        };
        let carried = input
            .carried_grants
            .into_iter()
            .map(|seal| aos_hub_db::db::EndpointGrantCarryForward {
                consumer_scope_key: seal.consumer_scope_key,
                grant_generation: seal.grant_generation,
                resource_version: seal.resource_version,
            })
            .collect::<Vec<_>>();
        let revision = Self::endpoint_revision_spec(input.request.revision)?;
        let staged = self
            .db
            .stage_endpoint_generation(
                &endpoint.id,
                &revision,
                &owner,
                &carried,
                &claims.sub,
                &req.idempotency_key,
                input.expected_resource_version.ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("stage plan has no resource version"))
                })?,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let endpoint = self
            .db
            .endpoint(&endpoint.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint"))?;
        let response = pb::EndpointGenerationResponse {
            generation: Some(self.endpoint_generation_message(&endpoint, staged).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one exact staged endpoint-generation selection plan.
    pub async fn activate_endpoint_generation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyEndpointGenerationRequest,
    ) -> Result<pb::EndpointResponse, RpcError> {
        let plan_kind = "activate_endpoint_generation";
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                plan_kind,
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
            plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, EndpointActivationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        let endpoint = self
            .managed_endpoint(auth, &input.endpoint_id, Permission::EndpointManage)
            .await?;
        let source = self
            .db
            .endpoint_revision(&input.endpoint_id, input.source_generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("selected endpoint generation"))?;
        let target = self
            .db
            .endpoint_revision(&input.endpoint_id, input.target_generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("staged endpoint generation"))?;
        let impacts = self
            .db
            .endpoint_generation_impacts(&input.endpoint_id, input.source_generation)
            .await
            .map_err(RpcError::internal)?;
        if endpoint.resource_version != input.expected_resource_version
            || endpoint.desired_generation != Some(input.source_generation)
            || source.content_digest != input.source_content_digest
            || target.content_digest != input.target_content_digest
            || impacts != input.affected_resources
        {
            return Err(RpcError::FailedPrecondition(
                "endpoint generation state changed after activation planning".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let updated = self
            .db
            .activate_staged_endpoint_generation(
                &input.endpoint_id,
                input.target_generation,
                input.expected_resource_version,
                false,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::EndpointResponse {
            endpoint: Some(self.endpoint_message(updated).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies an endpoint grant plan exactly once.
    pub async fn apply_grant_endpoint_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_endpoint_scope_grant(auth, req, false).await
    }

    /// Applies endpoint grant revocation exactly once.
    pub async fn apply_revoke_endpoint_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_endpoint_scope_grant(auth, req, true).await
    }

    /// Applies endpoint deletion exactly once.
    pub async fn delete_endpoint(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_endpoint",
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
            "delete_endpoint",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, EndpointDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_endpoint",
                Some(&req.confirmation_hash),
            )
            .await?;
        let endpoint = self
            .managed_endpoint(auth, &input.request.stable_id, Permission::EndpointManage)
            .await?;
        if endpoint.owner_scope_key != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "endpoint owner changed after planning".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        self.db
            .delete_endpoint(
                &endpoint.id,
                input.expected_resource_version,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
