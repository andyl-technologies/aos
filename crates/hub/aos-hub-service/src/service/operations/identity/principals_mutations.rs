//! Principals mutations in the identity capability.

use super::*;

impl RpcService {
    /// Applies one reviewed OIDC identity-provider replacement exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when the reviewed baseline changed, authority is lost,
    /// or the atomic mutation cannot be committed.
    pub async fn apply_set_identity_provider(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::IdentityProviderResponse, RpcError> {
        const KIND: &str = "set_identity_provider";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                KIND,
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
            KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, IdentityProviderSetPlanInput) = self
            .load_control_plan(auth, &req.plan_id, KIND, Some(&req.confirmation_hash))
            .await?;
        let org = self
            .db
            .org_by_slug(&input.org_slug)
            .await
            .map_err(RpcError::internal)?
            .filter(|org| org.id == input.org_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("organization changed after planning".into())
            })?;
        let scope = Scope::parse(&org.stable_id);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        let version = input.baseline_resource_version.unwrap_or(0) + 1;
        let config = idp_record_from_plan(&input, version);
        let response = pb::IdentityProviderResponse {
            identity_provider: Some(identity_provider_message(&org.slug, config.clone())),
        };
        let result_json = serde_json::to_string(&response).map_err(RpcError::internal)?;
        let event_id = control_audit_event_id("idp:set", &plan.plan_id);
        self.db
            .apply_identity_provider_set_plan(
                &config,
                input.baseline_resource_version,
                input.baseline_incarnation_id.as_deref(),
                scope.as_str(),
                &plan.plan_id,
                &req.idempotency_key,
                &result_json,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                &event_id,
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!(
                    "identity provider changed after planning: {error:#}"
                ))
            })?;
        Ok(response)
    }

    /// Applies one reviewed OIDC identity-provider removal exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision changed or atomic apply fails.
    pub async fn apply_remove_identity_provider(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        const KIND: &str = "remove_identity_provider";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                KIND,
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
            KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, IdentityProviderRemovePlanInput) = self
            .load_control_plan(auth, &req.plan_id, KIND, Some(&req.confirmation_hash))
            .await?;
        let org = self
            .db
            .org_by_slug(&input.org_slug)
            .await
            .map_err(RpcError::internal)?
            .filter(|org| org.id == input.org_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("organization changed after planning".into())
            })?;
        let scope = Scope::parse(&org.stable_id);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        let result_json = serde_json::to_string(&response).map_err(RpcError::internal)?;
        let event_id = control_audit_event_id("idp:remove", &plan.plan_id);
        self.db
            .apply_identity_provider_remove_plan(
                org.id,
                input.baseline_resource_version,
                input.baseline_incarnation_id.as_deref(),
                scope.as_str(),
                &plan.plan_id,
                &req.idempotency_key,
                &result_json,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                &event_id,
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!(
                    "identity provider changed after planning: {error:#}"
                ))
            })?;
        Ok(response)
    }
}
