//! Authorization helpers in the identity capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn require_control_plan_permission(
        &self,
        auth: Option<&str>,
        plan_id: &str,
        permission: Permission,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        let plan = self
            .db
            .topology_plan(plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("topology plan"))?;
        self.require_permission(&claims, permission, &Scope::parse(&plan.scope))
            .await?;
        Ok(claims)
    }

    pub(in crate::service) async fn authorized_operation(
        &self,
        auth: Option<&str>,
        operation_id: &str,
    ) -> Result<aos_hub_db::db::TopologyOperationRecord, RpcError> {
        let claims = self.require_claims(auth)?;
        let operation = self
            .db
            .topology_operation(operation_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("operation"))?;
        let scope = Scope::try_parse(&operation.authorization_scope_key).ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!(
                "operation has non-canonical authorization scope"
            ))
        })?;
        let permission = topology_target_read_permission(&operation.primary_target_kind);
        if let Err(error) = self.require_permission(&claims, permission, &scope).await {
            return match error {
                RpcError::Unauthenticated(_) => Err(error),
                _ => Err(RpcError::not_found("operation")),
            };
        }
        let targets = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await
            .map_err(RpcError::internal)?;
        for target in targets
            .into_iter()
            .filter(|target| target.role != "primary")
        {
            let secondary_scope =
                Scope::try_parse(&target.authorization_scope_key).ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!(
                        "operation secondary target has non-canonical authorization scope"
                    ))
                })?;
            if self
                .require_permission(
                    &claims,
                    topology_target_read_permission(&target.target_kind),
                    &secondary_scope,
                )
                .await
                .is_err()
            {
                return Err(RpcError::not_found("operation"));
            }
        }
        Ok(operation)
    }

    pub(in crate::service) async fn authorized_operation_admin(
        &self,
        auth: Option<&str>,
        operation_id: &str,
    ) -> Result<aos_hub_db::db::TopologyOperationRecord, RpcError> {
        let operation = self.authorized_operation(auth, operation_id).await?;
        let claims = self.require_claims(auth)?;
        let scope = Scope::try_parse(&operation.authorization_scope_key).ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!(
                "operation has non-canonical authorization scope"
            ))
        })?;
        let permission = aos_hub_model::auth::permission_from_str(&operation.control_permission)
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!(
                    "operation has unknown persisted control permission"
                ))
            })?;
        if let Err(error) = self.require_permission(&claims, permission, &scope).await {
            return match error {
                RpcError::Unauthenticated(_) => Err(error),
                _ => Err(RpcError::not_found("operation")),
            };
        }
        let targets = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await
            .map_err(RpcError::internal)?;
        for target in targets
            .into_iter()
            .filter(|target| target.role != "primary")
        {
            let secondary_scope =
                Scope::try_parse(&target.authorization_scope_key).ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!(
                        "operation secondary target has non-canonical authorization scope"
                    ))
                })?;
            if self
                .require_permission(&claims, target.control_permission, &secondary_scope)
                .await
                .is_err()
            {
                return Err(RpcError::not_found("operation"));
            }
        }
        Ok(operation)
    }

    /// Non-erroring form of [`Self::require_permission`] for list filters.
    ///
    /// Applies the same two-sided test but returns `false` (fail-closed) on any
    /// denial, database failure, unknown principal, or anonymous caller — so a
    /// "list what I can see" call drops, rather than rejects, hidden records.
    pub(in crate::service) async fn claims_allow(
        &self,
        claims: Option<&Claims>,
        perm: Permission,
        scope: &Scope,
    ) -> bool {
        let Some(claims) = claims else {
            return false;
        };
        let Ok(Some(context)) = self.db.authorization_context(scope.as_str()).await else {
            return false;
        };
        if !token_allows(claims, perm, &context) {
            return false;
        }
        let Some(principal) = claims_principal(claims) else {
            return false;
        };
        match self.db.effective_scopes(principal).await {
            Ok(grants) => iam::allow(&grants, perm, &context),
            Err(_) => false,
        }
    }

    /// Authorize a registry machine read while rechecking registry liveness.
    pub(in crate::service) async fn require_registry_stream_read(
        &self,
        auth: ReadAuthorization<'_>,
        registry: &RegistryRecord,
    ) -> Result<(), RpcError> {
        match auth {
            ReadAuthorization::AuthorizationHeader(header) => {
                self.require_read(header, registry).await
            }
            ReadAuthorization::SessionCookie(secret) => {
                if let Some(org_id) = registry.org_id {
                    if !self
                        .db
                        .org_is_active(org_id)
                        .await
                        .map_err(RpcError::internal)?
                    {
                        return Err(RpcError::not_found("registry"));
                    }
                }
                if registry.visibility == "public" || registry.org_id.is_none() {
                    return Ok(());
                }
                let session = self
                    .resolve_session_cached(secret)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::Unauthenticated("invalid session".into()))?;
                let scope = self.registry_scope(registry).await?;
                let grants = self
                    .db
                    .effective_scopes(Principal::user(session.auth.user_id))
                    .await
                    .map_err(RpcError::internal)?;
                let context = self
                    .db
                    .authorization_context(scope.as_str())
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("registry scope"))?;
                if iam::allow(&grants, Permission::Read, &context) {
                    Ok(())
                } else {
                    Err(RpcError::PermissionDenied(
                        "read permission required".into(),
                    ))
                }
            }
            ReadAuthorization::PreauthorizedSession => {
                if let Some(org_id) = registry.org_id {
                    if !self
                        .db
                        .org_is_active(org_id)
                        .await
                        .map_err(RpcError::internal)?
                    {
                        return Err(RpcError::not_found("registry"));
                    }
                }
                Ok(())
            }
        }
    }

    pub(in crate::service) async fn require_delivery_scope(
        &self,
        auth: Option<&str>,
        owner_scope_key: &str,
        permission: Permission,
    ) -> Result<(), RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::try_parse(owner_scope_key)
            .ok_or_else(|| RpcError::invalid("owner_scope_key is not a canonical stable scope"))?;
        self.require_permission(&claims, permission, &scope).await
    }

    /// Enforces a permission on an already-resolved stable resource without
    /// exposing whether that resource exists to an unauthorized principal.
    pub(in crate::service) async fn require_cloaked_delivery_scope(
        &self,
        auth: Option<&str>,
        owner_scope_key: &str,
        permission: Permission,
        resource: &str,
    ) -> Result<(), RpcError> {
        if Scope::try_parse(owner_scope_key).is_none() {
            return Err(RpcError::internal(anyhow::anyhow!(
                "persisted {resource} has invalid owner scope"
            )));
        }
        match self
            .require_delivery_scope(auth, owner_scope_key, permission)
            .await
        {
            Ok(()) => Ok(()),
            Err(error @ (RpcError::Unauthenticated(_) | RpcError::Internal)) => Err(error),
            Err(_) => Err(RpcError::not_found(resource)),
        }
    }

    /// Erroring access gate for single-registry reads.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for a registry under a soft-deleted org,
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] when a
    /// non-public registry is read without authority, and [`RpcError::Internal`]
    /// on database failure.
    pub(in crate::service) async fn require_read(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
    ) -> Result<(), RpcError> {
        if let Some(org_id) = registry.org_id {
            if !self
                .db
                .org_is_active(org_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::not_found("registry"));
            }
        }
        if registry.visibility == "public" || registry.org_id.is_none() {
            return Ok(());
        }
        let claims = self.require_claims(auth)?;
        let scope = self.registry_scope(registry).await?;
        self.require_permission(&claims, Permission::Read, &scope)
            .await
    }

    /// Authenticates and validates the common controller observation fence.
    pub(in crate::service) fn require_controller_fence(
        &self,
        auth: Option<&str>,
        controller_lease_id: &str,
        controller_generation: i64,
        expected_observation_version: &str,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        if claims.owner_kind != PrincipalKind::ServiceAccount.as_str() {
            return Err(RpcError::PermissionDenied(
                "controller observations require a service-account token".to_string(),
            ));
        }
        if controller_lease_id.trim().is_empty() {
            return Err(RpcError::invalid("controllerLeaseId is required"));
        }
        if controller_generation <= 0 {
            return Err(RpcError::invalid("controllerGeneration must be positive"));
        }
        let observation_version = expected_observation_version.parse::<i64>().map_err(|_| {
            RpcError::invalid("expectedObservationVersion must be a non-negative opaque version")
        })?;
        if observation_version < 0 {
            return Err(RpcError::invalid(
                "expectedObservationVersion must be a non-negative opaque version",
            ));
        }
        Ok(claims)
    }
}
