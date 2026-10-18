//! Bindings plans in the topology capability.

use super::*;

impl RpcService {
    /// `BindingService.PlanCreateBinding` persists an immutable create plan.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, conflict, or persistence error.
    pub async fn plan_create_binding(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanBindingMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.stable_id.trim().is_empty() || !req.expected_resource_version.is_empty() {
            return Err(RpcError::invalid(
                "create requires stableId and forbids expectedResourceVersion",
            ));
        }
        if !req.update_mask.is_empty() {
            return Err(RpcError::invalid("create forbids updateMask"));
        }
        let org_id = self
            .writable_storage_owner(auth, &req.owner_scope_key)
            .await?;
        req.stable_id = req.stable_id.trim().to_string();
        let spec = req
            .spec
            .as_mut()
            .ok_or_else(|| RpcError::invalid("spec is required"))?;
        Self::canonicalize_binding_spec(spec)?;
        if org_id.is_some()
            && matches!(
                spec.provider.as_ref(),
                Some(pb::binding_spec::Provider::LocalFilesystem(_))
                    | Some(pb::binding_spec::Provider::DeploymentR2(_))
            )
        {
            return Err(RpcError::invalid(
                "organization bindings must use an external s3 or r2 provider",
            ));
        }
        if self
            .db
            .binding_by_stable_id(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "binding stable id already exists".to_string(),
            ));
        }
        if self
            .db
            .list_bindings_by_scope(&req.owner_scope_key)
            .await
            .map_err(RpcError::internal)?
            .iter()
            .any(|binding| binding.name == spec.name)
        {
            return Err(RpcError::AlreadyExists(
                "binding name already exists in owner scope".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = BindingMutationPlanInput {
            request: req,
            org_id,
            binding_db_id: None,
            baseline_resource_version: None,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_binding",
            &input.request.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!("create binding '{}'", input.request.stable_id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// `BindingService.PlanDeleteBinding` persists reviewed blockers and CAS.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-version, blocker, or persistence error.
    pub async fn plan_delete_binding(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let binding = self
            .db
            .binding_by_stable_id(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        let owner_scope_key = binding.owner_scope_key.clone();
        let org_id = self.writable_storage_owner(auth, &owner_scope_key).await?;
        if binding.is_instance_default {
            return Err(RpcError::FailedPrecondition(
                "the instance-default binding cannot be deleted".to_string(),
            ));
        }
        let expected = parse_resource_version(
            req.expected_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
            binding.resource_version,
        )?;
        if expected != binding.resource_version {
            return Err(RpcError::FailedPrecondition(
                "binding resource version is stale".to_string(),
            ));
        }
        let blockers = self
            .db
            .binding_delete_blockers(binding.id)
            .await
            .map_err(RpcError::internal)?;
        if !blockers.is_empty() {
            return Err(RpcError::FailedPrecondition(format!(
                "binding is still referenced by {}",
                blockers.join(", ")
            )));
        }
        let input = BindingDeletePlanInput {
            stable_id: req.stable_id,
            owner_scope_key: owner_scope_key.clone(),
            org_id,
            binding_db_id: binding.id,
            baseline_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_binding",
            &owner_scope_key,
            &input,
            &req.idempotency_key,
            vec![format!("delete binding '{}'", input.stable_id)],
            vec!["credential revisions are deleted with the binding".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans a consumer-scope grant.
    pub async fn plan_grant_binding_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_binding_grant(auth, req, false).await
    }

    /// Plans a consumer-scope revocation.
    pub async fn plan_revoke_binding_scope(
        &self,
        auth: Option<&str>,
        req: pb::PlanConsumerScopeGrantRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_binding_grant(auth, req, true).await
    }
}
