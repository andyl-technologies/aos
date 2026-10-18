//! Endpoints plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans creation of an immutable endpoint identity and generation one.
    pub async fn plan_create_endpoint(
        &self,
        auth: Option<&str>,
        req: pb::PlanEndpointMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_endpoint_mutation(auth, req, false).await
    }

    /// Plans append-only staging of an immutable endpoint generation.
    pub async fn plan_stage_endpoint_generation(
        &self,
        auth: Option<&str>,
        req: pb::PlanStageEndpointGenerationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let endpoint = self
            .managed_endpoint(auth, &req.endpoint_id, Permission::EndpointManage)
            .await?;
        let host = Self::endpoint_host_message(&endpoint)?;
        self.plan_endpoint_mutation(
            auth,
            pb::PlanEndpointMutationRequest {
                stable_id: endpoint.id,
                owner_scope_key: endpoint.owner_scope_key,
                scheme: endpoint.scheme,
                host: Some(host),
                effective_port: u32::try_from(endpoint.effective_port).unwrap_or_default(),
                network_policy_id: endpoint.network_policy_id,
                revision: req.revision,
                carry_forward_consumer_scopes: req.carry_forward_consumer_scopes,
                expected_resource_version: req.expected_resource_version,
                idempotency_key: req.idempotency_key,
                update_mask: req.update_mask,
            },
            true,
        )
        .await
    }

    /// Plans selection of one exact staged endpoint generation.
    pub async fn plan_activate_endpoint_generation(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanActivateEndpointGenerationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        if req.generation <= 0 {
            return Err(RpcError::invalid("generation must be positive"));
        }
        let endpoint = self
            .managed_endpoint(auth, &req.endpoint_id, Permission::EndpointManage)
            .await?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || expected != endpoint.resource_version {
            return Err(RpcError::FailedPrecondition(
                "endpoint resource version is required and must be current".to_string(),
            ));
        }
        let source_generation = endpoint.desired_generation.ok_or_else(|| {
            RpcError::FailedPrecondition("endpoint has no selected generation".to_string())
        })?;
        if source_generation == req.generation {
            return Err(RpcError::FailedPrecondition(
                "endpoint generation is already selected".to_string(),
            ));
        }
        let source = self
            .db
            .endpoint_revision(&endpoint.id, source_generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("selected endpoint generation"))?;
        let target = self
            .db
            .endpoint_revision(&endpoint.id, req.generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("staged endpoint generation"))?;
        let boundary = self
            .db
            .network_policy_revision(&target.network_policy_id, target.boundary_revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy revision"))?;
        if boundary.lifecycle_state != "active" || boundary.observation_state != "verified" {
            return Err(RpcError::FailedPrecondition(
                "public endpoint activation requires an active verified boundary revision"
                    .to_string(),
            ));
        }
        let affected_resources = self
            .db
            .endpoint_generation_impacts(&endpoint.id, source_generation)
            .await
            .map_err(RpcError::internal)?;
        if !affected_resources.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "move dependent routes, gateways, and defaults before selecting the generation"
                    .to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = EndpointActivationPlanInput {
            endpoint_id: endpoint.id.clone(),
            source_generation,
            source_content_digest: source.content_digest,
            target_generation: target.generation,
            target_content_digest: target.content_digest,
            expected_resource_version: expected,
            affected_resources,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &self.require_claims(auth)?,
            "activate_endpoint_generation",
            &endpoint.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "select endpoint '{}' generation {}",
                endpoint.id, target.generation
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans an explicit consumer grant on one exact endpoint generation.
    pub async fn plan_grant_endpoint_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_endpoint_scope_grant(auth, req, false).await
    }

    /// Plans revocation of an unpinned endpoint-generation grant.
    pub async fn plan_revoke_endpoint_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_endpoint_scope_grant(auth, req, true).await
    }

    /// Plans deletion of an unused endpoint under CAS.
    pub async fn plan_delete_endpoint(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let endpoint = self
            .managed_endpoint(auth, &req.stable_id, Permission::EndpointManage)
            .await?;
        let expected = req
            .expected_resource_version
            .as_deref()
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))
            .and_then(|value| parse_resource_version(value, 0))?;
        if expected <= 0 || expected != endpoint.resource_version {
            return Err(RpcError::FailedPrecondition(
                "endpoint resource version is stale".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = EndpointDeletePlanInput {
            request: req,
            owner_scope_key: endpoint.owner_scope_key.clone(),
            expected_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_endpoint",
            &endpoint.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!("delete endpoint '{}'", endpoint.id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
