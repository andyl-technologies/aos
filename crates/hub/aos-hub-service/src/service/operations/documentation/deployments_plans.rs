//! Deployments plans in the documentation capability.

use super::*;

impl RpcService {
    /// Plans creation, replacement, revocation, or re-enablement of a reporter slot.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, validation, stale-version, or
    /// database errors.
    pub async fn plan_configure_ability_deployment_reporter(
        &self,
        auth: Option<&str>,
        req: pb::PlanConfigureAbilityDeploymentReporterRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope_key = self
            .db
            .registry_authorization_scope(registry.id)
            .await
            .map_err(RpcError::internal)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&scope_key),
        )
        .await?;
        aos_module_format::LocalKey::new(req.deployment.clone())
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let current = self
            .db
            .ability_deployment_reporter(registry.id, &req.deployment)
            .await
            .map_err(RpcError::internal)?;
        let current_version = current
            .as_ref()
            .map_or(0, |reporter| reporter.resource_version);
        if current_version != req.expected_resource_version {
            return Err(RpcError::FailedPrecondition(
                "ability deployment reporter resource version is stale".into(),
            ));
        }
        let principal_id = if req.enabled {
            let principal_id = self
                .resolve_existing_principal_id(&req.principal_kind, &req.principal_ref)
                .await?;
            if !self
                .db
                .principal_is_live(&req.principal_kind, principal_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::FailedPrecondition(
                    "deployment reporter principal is not active".into(),
                ));
            }
            principal_id
        } else {
            let reporter = current.ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "cannot revoke a deployment reporter that does not exist".into(),
                )
            })?;
            if reporter.principal_kind != req.principal_kind
                || reporter.principal_ref != req.principal_ref
            {
                return Err(RpcError::FailedPrecondition(
                    "reporter revocation must name the enrolled principal".into(),
                ));
            }
            reporter.principal_id
        };

        let input = AbilityDeploymentReporterPlanInput {
            registry_id: registry.id,
            registry_slug: registry.slug,
            scope_key,
            deployment: req.deployment,
            principal_kind: req.principal_kind,
            principal_id,
            principal_ref: req.principal_ref,
            enabled: req.enabled,
            baseline_resource_version: req.expected_resource_version,
        };
        let confirmation_hash = control_confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            "configure_ability_deployment_reporter",
            &input.scope_key,
            &input,
            &req.idempotency_key,
            vec![format!(
                "replace deployment reporter enrollment '{}' in registry '{}'",
                input.deployment, input.registry_slug
            )],
            vec!["the prior live deployment overlay will be discarded".to_string()],
            Some(confirmation_hash),
        )
        .await
    }
}
