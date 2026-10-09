//! Deployments mutations in the documentation capability.

use super::*;

impl RpcService {
    /// Applies a reviewed reporter enrollment change exactly once.
    ///
    /// Any change increments the slot version and discards its prior overlay.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, plan, stale-version, principal,
    /// or database errors.
    pub async fn configure_ability_deployment_reporter(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::AbilityDeploymentReporter, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "configure_ability_deployment_reporter",
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
            "configure_ability_deployment_reporter",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, AbilityDeploymentReporterPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "configure_ability_deployment_reporter",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&input.scope_key),
        )
        .await?;
        let applied_version = input
            .baseline_resource_version
            .checked_add(1)
            .ok_or_else(|| RpcError::FailedPrecondition("reporter version overflow".into()))?;
        let already_applied = self
            .db
            .ability_deployment_reporter_matches_plan(
                input.registry_id,
                &input.deployment,
                &input.principal_kind,
                input.principal_id,
                &input.principal_ref,
                input.enabled,
                applied_version,
                &plan.plan_id,
            )
            .await
            .map_err(RpcError::internal)?;
        let response = if already_applied {
            // Reconstruct the original result from sealed plan input. A second
            // slot read could observe a later enrollment after the exact match.
            pb::AbilityDeploymentReporter {
                registry: input.registry_slug.clone(),
                deployment: input.deployment.clone(),
                principal_kind: input.principal_kind.clone(),
                principal_ref: input.principal_ref.clone(),
                enabled: input.enabled,
                resource_version: applied_version,
            }
        } else {
            if input.enabled
                && !self
                    .db
                    .principal_is_live(&input.principal_kind, input.principal_id)
                    .await
                    .map_err(RpcError::internal)?
            {
                return Err(RpcError::FailedPrecondition(
                    "deployment reporter principal is not active".into(),
                ));
            }
            let reporter = self
                .db
                .configure_ability_deployment_reporter(
                    input.registry_id,
                    &input.deployment,
                    &input.principal_kind,
                    input.principal_id,
                    &input.principal_ref,
                    input.enabled,
                    input.baseline_resource_version,
                    &plan.plan_id,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;

            pb::AbilityDeploymentReporter {
                registry: input.registry_slug.clone(),
                deployment: reporter.deployment,
                principal_kind: reporter.principal_kind,
                principal_ref: reporter.principal_ref,
                enabled: reporter.active,
                resource_version: reporter.resource_version,
            }
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Accepts one newer bounded assertion from an enrolled deployment reporter.
    ///
    /// Hub authenticates the bearer and exact package reference, records its own
    /// receipt time, bounds expiry, and performs the enrollment/sequence update
    /// atomically. Hub does not invoke handlers from the assertion.
    ///
    /// # Errors
    ///
    /// Returns authentication, enrollment, freshness, package-reference,
    /// replay, validation, or database errors.
    pub async fn report_package_ability_deployment(
        &self,
        auth: Option<&str>,
        req: pb::ReportPackageAbilityDeploymentRequest,
    ) -> Result<pb::PackageAbilityDeploymentResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let principal = claims_principal(&claims)
            .ok_or_else(|| RpcError::PermissionDenied("active principal required".into()))?;
        if !self
            .db
            .principal_is_live(principal.kind.as_str(), principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::PermissionDenied(
                "active principal required".into(),
            ));
        }
        let registry = self.registry_or_not_found(&req.registry).await?;
        let reporter = self
            .db
            .ability_deployment_reporter(registry.id, &req.deployment)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::PermissionDenied("active deployment reporter enrollment required".into())
            })?;
        if !reporter.active
            || reporter.principal_kind != principal.kind.as_str()
            || reporter.principal_id != principal.id
            || reporter.resource_version != req.reporter_resource_version
        {
            return Err(RpcError::PermissionDenied(
                "active deployment reporter enrollment required".into(),
            ));
        }
        let overlay = aos_module_docs::runtime::deployment::NativeDeploymentReport::decode(
            &req.canonical_json,
        )
        .map_err(|error| RpcError::invalid(error.to_string()))?;
        if overlay.deployment != req.deployment || overlay.valid_for_seconds > 300 {
            return Err(RpcError::invalid(
                "native report slot differs or validity exceeds 300 seconds",
            ));
        }
        let (locator, reference) = self
            .load_exact_package_ability_reference(
                registry.id,
                &overlay.package.registry_commit,
                &overlay.package.package,
                &overlay.package.version,
                &overlay.package.platform,
            )
            .await?;
        overlay
            .validate_reference(&reference)
            .map_err(|error| RpcError::invalid(error.to_string()))?;

        let now = clock::now_unix_secs();
        let reported_at = i64::try_from(overlay.reported_at_unix_seconds)
            .map_err(|_| RpcError::invalid("deployment report time is out of range"))?;
        if reported_at > now.saturating_add(ABILITY_DEPLOYMENT_MAX_FUTURE_SKEW_SECS) {
            return Err(RpcError::invalid(
                "deployment report time exceeds the allowed future clock skew",
            ));
        }
        let validity = i64::try_from(overlay.valid_for_seconds)
            .map_err(|_| RpcError::invalid("deployment validity is out of range"))?;
        let expires_at = now
            .saturating_add(validity)
            .min(reported_at.saturating_add(validity));
        if expires_at <= now {
            return Err(RpcError::FailedPrecondition(
                "deployment report was already stale when received".into(),
            ));
        }

        let document_sha256 = reference.identity.document_sha256.to_string();
        let transaction_sha256 = aos_core::Sha256Digest::of_bytes(
            aos_core::json::to_vec(&overlay.graph).map_err(RpcError::internal)?,
        )
        .to_string();
        self.db
            .accept_package_ability_deployment_overlay(
                registry.id,
                &req.deployment,
                principal.kind.as_str(),
                principal.id,
                req.reporter_resource_version,
                overlay.sequence,
                &locator.commit,
                &locator.package,
                &locator.version,
                &locator.platform,
                &document_sha256,
                &transaction_sha256,
                &req.canonical_json,
                overlay.reported_at_unix_seconds,
                now,
                expires_at,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;

        Ok(pb::PackageAbilityDeploymentResponse {
            canonical_json: req.canonical_json,
            authority: format!(
                "reporter-bearer:{}:{}",
                reporter.principal_kind, reporter.principal_ref
            ),
            received_at: now,
            expires_at,
            reporter_resource_version: req.reporter_resource_version,
        })
    }

    pub(crate) async fn verify_stored_package_ability_deployment(
        &self,
        stored: &aos_hub_db::db::StoredAbilityDeploymentOverlay,
        reference: &aos_module_docs::runtime::deployment::ReleasedReference,
    ) -> Result<(), RpcError> {
        if !self
            .db
            .principal_is_live(&stored.principal_kind, stored.principal_id)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::not_found("fresh native deployment assertion"));
        }
        decode_stored_package_ability_deployment(stored, reference)
            .map(|_| ())
            .map_err(RpcError::internal)
    }
}
