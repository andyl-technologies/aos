//! Principals plans in the identity capability.

use super::*;

impl RpcService {
    /// Plans an exact-version OIDC identity-provider replacement.
    ///
    /// Plaintext client credentials are sealed before the plan is serialized.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, a stale baseline, unavailable
    /// secret sealing, insufficient authority, or persistence failure.
    pub async fn plan_set_identity_provider(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetIdentityProviderRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        let scope = Scope::parse(&org.stable_id);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
        if !req.replace_client_secret && !req.client_secret.is_empty() {
            return Err(RpcError::invalid(
                "client_secret requires replace_client_secret=true",
            ));
        }
        if let Some(replayed) = self.replayed_identity_provider_plan(&claims, &req).await? {
            return Ok(replayed);
        }
        let existing = self
            .db
            .idp_config(org.id)
            .await
            .map_err(RpcError::internal)?;
        let baseline_resource_version = require_exact_identity_version(
            &req.expected_resource_version,
            existing
                .as_ref()
                .map(|record| (record.resource_version, record.incarnation_id.as_deref())),
        )?;
        let baseline_incarnation_id = existing
            .as_ref()
            .and_then(|record| record.incarnation_id.clone());
        let incarnation_id = baseline_incarnation_id
            .clone()
            .unwrap_or_else(|| format!("idp-incarnation-{}", uuid::Uuid::new_v4()));
        let client_secret_action = if !req.replace_client_secret {
            "preserve"
        } else if req.client_secret.is_empty() {
            "clear"
        } else {
            "replace"
        };
        let client_secret_enc = if req.replace_client_secret {
            if req.client_secret.is_empty() {
                None
            } else {
                Some(
                    self.sealer
                        .as_ref()
                        .ok_or_else(|| {
                            RpcError::FailedPrecondition(
                                "identity-provider credentials require durable secret sealing"
                                    .into(),
                            )
                        })?
                        .seal(&req.client_secret)
                        .map_err(RpcError::internal)?,
                )
            }
        } else {
            existing
                .as_ref()
                .and_then(|record| record.client_secret_enc.clone())
        };
        let input = IdentityProviderSetPlanInput {
            org_id: org.id,
            org_slug: org.slug,
            issuer: req.issuer.trim().to_string(),
            authorization_endpoint: req.authorization_endpoint.trim().to_string(),
            token_endpoint: req.token_endpoint.trim().to_string(),
            jwks_uri: req.jwks_uri.trim().to_string(),
            client_id: req.client_id.trim().to_string(),
            client_secret_enc,
            client_secret_action: client_secret_action.to_string(),
            scopes: req.scopes.trim().to_string(),
            groups_claim: (!req.groups_claim.trim().is_empty())
                .then(|| req.groups_claim.trim().to_string()),
            role_map_json: if req.role_map_json.trim().is_empty() {
                "{}".to_string()
            } else {
                req.role_map_json.trim().to_string()
            },
            allow_jit: req.allow_jit,
            enforce_sso: req.enforce_sso,
            default_role: req.default_role.trim().to_string(),
            baseline_resource_version,
            baseline_incarnation_id,
            incarnation_id,
        };
        let candidate =
            idp_record_from_plan(&input, input.baseline_resource_version.unwrap_or(0) + 1);
        crate::auth::oidc::validate_idp_config_record(&candidate)
            .map_err(|error| RpcError::invalid(format!("invalid identity provider: {error:#}")))?;
        self.create_control_plan(
            &claims,
            "set_identity_provider",
            scope.as_str(),
            &input,
            &req.idempotency_key,
            vec![format!("set OIDC identity provider for {}", input.org_slug)],
            vec!["SSO login behavior may change immediately after apply".to_string()],
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }

    /// Plans removal of one exact OIDC identity-provider revision.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, lookup, version, or persistence error.
    pub async fn plan_remove_identity_provider(
        &self,
        auth: Option<&str>,
        req: pb::PlanRemoveIdentityProviderRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        let scope = Scope::parse(&org.stable_id);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        if let Some(replayed) = self
            .replayed_identity_provider_remove_plan(&claims, &req)
            .await?
        {
            return Ok(replayed);
        }
        let current = self
            .db
            .idp_config(org.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("identity provider"))?;
        if req.expected_resource_version
            != identity_resource_version(
                current.resource_version,
                current.incarnation_id.as_deref(),
            )
        {
            return Err(RpcError::FailedPrecondition(
                "identity-provider revision changed".into(),
            ));
        }
        let input = IdentityProviderRemovePlanInput {
            org_id: org.id,
            org_slug: org.slug,
            baseline_resource_version: current.resource_version,
            baseline_incarnation_id: current.incarnation_id,
        };
        self.create_control_plan(
            &claims,
            "remove_identity_provider",
            scope.as_str(),
            &input,
            &req.idempotency_key,
            vec![format!(
                "remove OIDC identity provider for {}",
                input.org_slug
            )],
            vec!["SSO login for captured domains will stop".to_string()],
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }
}
