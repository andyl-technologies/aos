//! Networks mutations in the topology capability.

use super::*;

impl RpcService {
    /// Queues a controller-owned probe for an exact immutable boundary revision.
    pub async fn complete_network_policy_revision_probe(
        &self,
        auth: Option<&str>,
        req: pb::CompleteNetworkPolicyRevisionProbeRequest,
    ) -> Result<pb::NetworkPolicyRevisionResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let boundary = self
            .db
            .network_policy(&req.boundary_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &boundary.owner_scope_key,
            Permission::NetworkPolicyManage,
            "network policy",
        )
        .await?;
        let revision = self
            .db
            .network_policy_revision(&req.boundary_id, req.revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy revision"))?;
        let operation_id = hex::encode(Sha256::digest(
            format!(
                "network-boundary-probe-v1\0{}\0{}\0{}",
                revision.boundary_id, revision.revision, revision.content_digest
            )
            .as_bytes(),
        ));
        self.topology_probes
            .schedule(
                &operation_id,
                crate::topology_probe::TopologyProbe::NetworkPolicy {
                    stable_id: revision.boundary_id.clone(),
                    revision: revision.revision,
                    configuration_digest: revision.content_digest.clone(),
                },
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!("schedule boundary probe: {error:#}"))
            })?;
        Ok(pb::NetworkPolicyRevisionResponse {
            revision: Some(Self::network_policy_revision_message(revision)?),
            coordination_operation: None,
        })
    }

    /// Records a controller-owned observation under lifecycle CAS.
    pub async fn report_network_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::ReportNetworkPolicyRevisionRequest,
    ) -> Result<pb::NetworkPolicyRevisionResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let boundary = self
            .db
            .network_policy(&req.boundary_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &boundary.owner_scope_key,
            Permission::NetworkPolicyManage,
            "network policy",
        )
        .await?;
        let observation = req
            .observation
            .ok_or_else(|| RpcError::invalid("observation is required"))?;
        let expected = parse_resource_version(&req.expected_observation_version, 0)?;
        if expected <= 0 {
            return Err(RpcError::invalid("expectedResourceVersion is required"));
        }
        let record = self
            .db
            .reconcile_network_policy_revision(
                &req.boundary_id,
                req.revision,
                &observation.state,
                observation.protected_transport_observed,
                &observation.trusted_ingress_observed,
                (!observation.error.is_empty()).then_some(observation.error.as_str()),
                expected,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::NetworkPolicyRevisionResponse {
            revision: Some(Self::network_policy_revision_message(record)?),
            coordination_operation: None,
        })
    }

    /// Applies a reviewed network-boundary creation plan exactly once.
    pub async fn create_network_policy(
        &self,
        auth: Option<&str>,
        req: pb::ApplyNetworkPolicyMutationRequest,
    ) -> Result<pb::NetworkPolicyResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_network_policy",
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
            "create_network_policy",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, NetworkPolicyCreatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_network_policy",
                Some(&req.confirmation_hash),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.require_delivery_scope(
            auth,
            &input.request.owner_scope_key,
            Permission::NetworkPolicyManage,
        )
        .await?;
        let identity =
            Self::network_policy_identity_spec(&input.request.kind, input.request.identity)?;
        let revision = Self::network_policy_revision_spec(input.request.initial_revision)?;
        let claims = self.require_claims(auth)?;
        let record = self
            .db
            .create_network_policy(
                &input.request.stable_id,
                &input.request.owner_scope_key,
                input.org_id,
                &input.request.name,
                &identity,
                &revision,
                &claims.sub,
                &req.idempotency_key,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::NetworkPolicyResponse {
            network_policy: Some(self.network_policy_message(record).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies an append-only boundary revision plan exactly once.
    pub async fn revise_network_policy(
        &self,
        auth: Option<&str>,
        req: pb::ApplyNetworkPolicyRevisionRequest,
    ) -> Result<pb::NetworkPolicyRevisionResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "revise_network_policy",
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
            "revise_network_policy",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, NetworkPolicyRevisionPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "revise_network_policy",
                Some(&req.confirmation_hash),
            )
            .await?;
        self.managed_network_policy(auth, &input.request.boundary_id)
            .await?;
        let spec = Self::network_policy_revision_spec(input.request.spec)?;
        let claims = self.require_claims(auth)?;
        let record = self
            .db
            .revise_network_policy(
                &input.request.boundary_id,
                &spec,
                &claims.sub,
                input.expected_boundary_version,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::NetworkPolicyRevisionResponse {
            revision: Some(Self::network_policy_revision_message(record)?),
            coordination_operation: None,
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies an activation plan exactly once.
    pub async fn activate_network_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::ApplyNetworkPolicyLifecycleRequest,
    ) -> Result<pb::NetworkPolicyRevisionResponse, RpcError> {
        self.apply_network_policy_lifecycle(auth, req, true).await
    }

    /// Applies one retirement transition exactly once.
    pub async fn retire_network_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::ApplyNetworkPolicyLifecycleRequest,
    ) -> Result<pb::NetworkPolicyRevisionResponse, RpcError> {
        self.apply_network_policy_lifecycle(auth, req, false).await
    }

    /// Applies a boundary grant plan exactly once.
    pub async fn apply_grant_network_policy_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_network_policy_grant(auth, req, false).await
    }

    /// Applies a boundary grant-revocation plan exactly once.
    pub async fn apply_revoke_network_policy_scope(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        self.apply_network_policy_grant(auth, req, true).await
    }

    /// Applies deletion of an unreferenced network policy exactly once.
    pub async fn delete_network_policy(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_network_policy",
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
            "delete_network_policy",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, NetworkPolicyDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_network_policy",
                Some(&req.confirmation_hash),
            )
            .await?;
        let boundary = self
            .managed_network_policy(auth, &input.request.stable_id)
            .await?;
        if boundary.owner_scope_key != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "network policy owner changed after planning".to_string(),
            ));
        }
        self.db
            .delete_network_policy(&boundary.id, input.expected_resource_version)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
