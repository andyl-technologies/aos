//! Deployments reads in the documentation capability.

use super::*;

impl RpcService {
    /// Returns one exact fresh private native deployment assertion.
    ///
    /// The caller must hold `audit.read` at the registry scope. The read
    /// rechecks enrollment, principal liveness, expiry, canonical bytes, and the
    /// exact authenticated package reference.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, not-found, integrity, or database
    /// errors.
    pub async fn get_package_ability_deployment(
        &self,
        auth: Option<&str>,
        req: pb::GetPackageAbilityDeploymentRequest,
    ) -> Result<pb::PackageAbilityDeploymentResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope_key = self
            .db
            .registry_authorization_scope(registry.id)
            .await
            .map_err(RpcError::internal)?;
        self.require_permission(&claims, Permission::AuditRead, &Scope::parse(&scope_key))
            .await?;
        let (locator, reference) = self
            .load_exact_package_ability_reference(
                registry.id,
                &req.registry_commit,
                &req.package,
                &req.version,
                &req.platform,
            )
            .await?;
        let stored = self
            .db
            .package_ability_deployment_overlay(
                registry.id,
                &req.deployment,
                &locator.commit,
                &locator.package,
                &locator.version,
                &locator.platform,
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("fresh package ability deployment overlay"))?;
        self.verify_stored_package_ability_deployment(&stored, &reference)
            .await?;
        Ok(stored_ability_deployment_response(stored))
    }
}
