//! Principals helpers in the identity capability.

use super::*;

impl RpcService {
    /// Resolves a principal reference to its numeric id.
    ///
    /// A `"user"` ref is an existing email and a `"service_account"` ref is
    /// `"<org>/<name>"`. Planning never creates a principal as a side effect.
    ///
    /// # Errors
    ///
    /// [`RpcError::InvalidArgument`] for an unknown kind, a malformed
    /// service-account ref, or an unknown org/service account; [`RpcError::Internal`]
    /// on database failure.
    pub(in crate::service) async fn resolve_existing_principal_id(
        &self,
        kind: &str,
        principal_ref: &str,
    ) -> Result<i64, RpcError> {
        match kind {
            "user" => self
                .db
                .user_by_email(principal_ref)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("user principal")),
            "service_account" => {
                let (org_slug, name) = principal_ref.split_once('/').ok_or_else(|| {
                    RpcError::invalid("service_account ref must be '<org>/<name>'")
                })?;
                let org = self
                    .db
                    .org_by_slug(org_slug)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::invalid(format!("no org '{org_slug}'")))?;
                self.db
                    .service_account_by_name(org.id, name)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::invalid(format!("no service account '{principal_ref}'"))
                    })
            }
            other => Err(RpcError::invalid(format!(
                "unknown principal kind '{other}'"
            ))),
        }
    }

    pub(in crate::service) async fn replayed_identity_provider_remove_plan(
        &self,
        claims: &Claims,
        request: &pb::PlanRemoveIdentityProviderRequest,
    ) -> Result<Option<pb::TopologyPlanResponse>, RpcError> {
        let Some((plan, input)) = self
            .replayed_control_plan_input::<IdentityProviderRemovePlanInput>(
                claims,
                "remove_identity_provider",
                &request.idempotency_key,
            )
            .await?
        else {
            return Ok(None);
        };
        let expected_version = identity_resource_version(
            input.baseline_resource_version,
            input.baseline_incarnation_id.as_deref(),
        );
        if input.org_slug != request.org_slug
            || expected_version != request.expected_resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "plan idempotency key was already used for different input".into(),
            ));
        }
        Self::control_plan_response(plan).map(Some)
    }

    pub(in crate::service) async fn replayed_identity_provider_plan(
        &self,
        claims: &Claims,
        request: &pb::PlanSetIdentityProviderRequest,
    ) -> Result<Option<pb::TopologyPlanResponse>, RpcError> {
        let Some(plan) = self
            .db
            .topology_plan_for_request(
                &claims.owner_kind,
                Some(claims.owner_id),
                "set_identity_provider",
                &request.idempotency_key,
            )
            .await
            .map_err(RpcError::internal)?
        else {
            return Ok(None);
        };
        let input: IdentityProviderSetPlanInput =
            serde_json::from_str(&plan.input_versions_json).map_err(RpcError::internal)?;
        let role_map = if request.role_map_json.trim().is_empty() {
            "{}"
        } else {
            request.role_map_json.trim()
        };
        let expected_version = input.baseline_resource_version.map_or_else(
            || "absent".to_string(),
            |version| identity_resource_version(version, input.baseline_incarnation_id.as_deref()),
        );
        let requested_action = if !request.replace_client_secret {
            "preserve"
        } else if request.client_secret.is_empty() {
            "clear"
        } else {
            "replace"
        };
        let public_input_matches = input.org_slug == request.org_slug
            && input.issuer == request.issuer.trim()
            && input.authorization_endpoint == request.authorization_endpoint.trim()
            && input.token_endpoint == request.token_endpoint.trim()
            && input.jwks_uri == request.jwks_uri.trim()
            && input.client_id == request.client_id.trim()
            && input.client_secret_action == requested_action
            && input.scopes == request.scopes.trim()
            && input.groups_claim.as_deref().unwrap_or_default() == request.groups_claim.trim()
            && input.role_map_json == role_map
            && input.allow_jit == request.allow_jit
            && input.enforce_sso == request.enforce_sso
            && input.default_role == request.default_role.trim()
            && expected_version == request.expected_resource_version;
        let credential_matches = match requested_action {
            "replace" => {
                let sealed = input.client_secret_enc.as_deref().ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!(
                        "identity-provider replacement plan omitted its sealed credential"
                    ))
                })?;
                self.sealer
                    .as_ref()
                    .ok_or_else(|| {
                        RpcError::FailedPrecondition(
                            "identity-provider credentials require durable secret sealing".into(),
                        )
                    })?
                    .unseal(sealed)
                    .map_err(RpcError::internal)?
                    == request.client_secret
            }
            "clear" => input.client_secret_enc.is_none(),
            "preserve" => true,
            _ => false,
        };
        if !public_input_matches || !credential_matches {
            return Err(RpcError::FailedPrecondition(
                "plan idempotency key was already used for different input".into(),
            ));
        }
        Self::control_plan_response(plan).map(Some)
    }
}
