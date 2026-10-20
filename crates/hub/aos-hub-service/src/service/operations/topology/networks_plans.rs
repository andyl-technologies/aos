//! Networks plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans creation of a stable boundary identity and staged revision one.
    pub async fn plan_create_network_policy(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanNetworkPolicyMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        self.require_delivery_scope(auth, &req.owner_scope_key, Permission::NetworkPolicyManage)
            .await?;
        if req.stable_id.is_empty() || req.name.is_empty() {
            return Err(RpcError::invalid("stableId and name are required"));
        }
        let identity = Self::network_policy_identity_spec(&req.kind, req.identity.clone())?;
        if identity.kind() != req.kind {
            return Err(RpcError::invalid("kind does not match identity"));
        }
        Self::network_policy_revision_spec(req.initial_revision.clone())?;
        if self
            .db
            .network_policy(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "network policy already exists".to_string(),
            ));
        }
        let (_scope_kind, org_id, _project_id) = self
            .db
            .authorization_scope_owner(&req.owner_scope_key)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("owner scope"))?;
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = NetworkPolicyCreatePlanInput {
            request: req,
            org_id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_network_policy",
            &input.request.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "create network policy '{}' with staged revision 1",
                input.request.stable_id
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans one append-only boundary protection revision under identity CAS.
    pub async fn plan_revise_network_policy(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanNetworkPolicyRevisionRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let boundary = self.managed_network_policy(auth, &req.boundary_id).await?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || expected != boundary.resource_version {
            return Err(RpcError::FailedPrecondition(
                "network policy resource version is required and must be current".to_string(),
            ));
        }
        const FIELDS: &[&str] = &[
            "protected_transport_required",
            "trusted_ingress",
            "source_allowlist_cidrs",
            "probe_location_configuration_ref",
        ];
        let mask = req
            .update_mask
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if mask.is_empty()
            || mask.len() != req.update_mask.len()
            || mask.iter().any(|field| !FIELDS.contains(field))
        {
            return Err(RpcError::invalid(
                "updateMask must contain unique boundary revision fields",
            ));
        }
        let base_revision = if let Some(revision) = boundary.default_revision {
            self.db
                .network_policy_revision(&boundary.id, revision)
                .await
                .map_err(RpcError::internal)?
        } else {
            self.db
                .latest_network_policy_revision(&boundary.id)
                .await
                .map_err(RpcError::internal)?
        }
        .ok_or_else(|| RpcError::not_found("base boundary revision"))?;
        let current_spec = Self::network_policy_revision_spec_message(&base_revision.spec)?;
        let desired = req
            .spec
            .as_mut()
            .ok_or_else(|| RpcError::invalid("spec is required"))?;
        if !mask.contains("protected_transport_required") {
            desired.protected_transport_required = current_spec.protected_transport_required;
        }
        if !mask.contains("trusted_ingress") {
            desired.trusted_ingress = current_spec.trusted_ingress;
        }
        if !mask.contains("source_allowlist_cidrs") {
            desired.source_allowlist_cidrs = current_spec.source_allowlist_cidrs;
        }
        if !mask.contains("probe_location_configuration_ref") {
            desired.probe_location_configuration_ref =
                current_spec.probe_location_configuration_ref;
        }
        Self::network_policy_revision_spec(req.spec.clone())?;
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = NetworkPolicyRevisionPlanInput {
            request: req,
            expected_boundary_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "revise_network_policy",
            &boundary.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "append a staged revision to network policy '{}'",
                input.request.boundary_id
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans activation of a verified staged boundary revision.
    pub async fn plan_activate_network_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::PlanNetworkPolicyLifecycleRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_network_policy_lifecycle(auth, req, true).await
    }

    /// Plans one active-to-retiring or retiring-to-retired transition.
    pub async fn plan_retire_network_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::PlanNetworkPolicyLifecycleRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_network_policy_lifecycle(auth, req, false).await
    }

    /// Plans an explicit consumer-scope grant on a stable network policy.
    pub async fn plan_grant_network_policy_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_network_policy_grant(auth, req, false).await
    }

    /// Plans revocation of an unpinned explicit boundary grant.
    pub async fn plan_revoke_network_policy_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_network_policy_grant(auth, req, true).await
    }

    /// Plans deletion of an unused network-boundary identity under CAS.
    pub async fn plan_delete_network_policy(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let boundary = self.managed_network_policy(auth, &req.stable_id).await?;
        let expected = req
            .expected_resource_version
            .as_deref()
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))
            .and_then(|value| parse_resource_version(value, 0))?;
        if expected <= 0 || expected != boundary.resource_version {
            return Err(RpcError::FailedPrecondition(
                "network policy resource version is stale".to_string(),
            ));
        }
        if boundary.id == "instance:public" {
            return Err(RpcError::FailedPrecondition(
                "the deployment public boundary cannot be deleted".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = NetworkPolicyDeletePlanInput {
            request: req,
            owner_scope_key: boundary.owner_scope_key.clone(),
            expected_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_network_policy",
            &boundary.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!("delete network policy '{}'", boundary.id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
