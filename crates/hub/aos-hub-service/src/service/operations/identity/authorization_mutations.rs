//! Authorization mutations in the identity capability.

use super::*;

impl RpcService {
    /// Verify the bearer JWT carried in a raw `Authorization` header value.
    ///
    /// `auth` is the verbatim header (e.g. `"Bearer eyJ…"`); the caller's
    /// transport supplies it. Mirrors the native hub's `require_claims`.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] when the header is absent, is not a
    /// `Bearer` token, or fails JWT verification.
    pub fn require_claims(&self, auth: Option<&str>) -> Result<Claims, RpcError> {
        let header =
            auth.ok_or_else(|| RpcError::Unauthenticated("missing Authorization header".into()))?;
        let token = header.strip_prefix("Bearer ").ok_or_else(|| {
            RpcError::Unauthenticated("Authorization header must start with Bearer".into())
        })?;
        self.jwt_keys
            .verify(token)
            .map_err(|e| RpcError::Unauthenticated(e.to_string()))
    }

    /// Verify an *optional* bearer JWT.
    ///
    /// A wholly absent `Authorization` header yields `Ok(None)` (an anonymous
    /// caller); a header that is present but malformed or fails verification
    /// still errors, so a bad token is never silently downgraded to anonymous.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] when a header is present but is not
    /// a valid `Bearer` JWT.
    pub fn optional_claims(&self, auth: Option<&str>) -> Result<Option<Claims>, RpcError> {
        match auth {
            None => Ok(None),
            Some(_) => self.require_claims(auth).map(Some),
        }
    }

    /// Requires an authenticated Hub principal with current registry read access.
    ///
    /// Unlike [`Self::require_read`], this gate does not make public registries
    /// anonymous. Delivery routes with an explicit `hub_auth` posture use it
    /// before minting a repository-scoped protocol token.
    ///
    /// # Errors
    ///
    /// Returns not-found for an inactive owner, authentication or permission
    /// errors for an invalid caller, and internal errors for database failures.
    pub(crate) async fn require_authenticated_registry_read(
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
        let claims = self.require_claims(auth)?;
        let scope = self.registry_scope(registry).await?;
        self.require_permission(&claims, Permission::Read, &scope)
            .await
    }

    /// Requires an authenticated Hub principal with current registry publish access.
    ///
    /// Distribution push-token exchange uses this gate before minting a
    /// protocol token. Registry visibility never makes writes anonymous.
    ///
    /// # Errors
    ///
    /// Returns not-found for an inactive owner, authentication or permission
    /// errors for an invalid caller, and internal errors for database failures.
    pub(crate) async fn require_authenticated_registry_publish(
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
        let claims = self.require_claims(auth)?;
        let scope = self.registry_scope(registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await
    }

    /// Require that a verified caller holds `perm` on `scope`.
    ///
    /// Two-sided: both the token's own grant *and* the principal's *current*
    /// memberships must cover the action, so a revoked role denies immediately
    /// even on an unexpired token.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::PermissionDenied`] when either check fails, and
    /// [`RpcError::Internal`] on a database failure loading memberships.
    pub async fn require_permission(
        &self,
        claims: &Claims,
        perm: Permission,
        scope: &Scope,
    ) -> Result<(), RpcError> {
        let denied =
            || RpcError::PermissionDenied(format!("{} permission required", perm.as_str()));
        let context = self
            .db
            .authorization_context(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(denied)?;
        if !token_allows(claims, perm, &context) {
            return Err(denied());
        }
        let principal = claims_principal(claims).ok_or_else(denied)?;
        let grants = self
            .db
            .effective_scopes(principal)
            .await
            .map_err(RpcError::internal)?;
        if iam::allow(&grants, perm, &context) {
            Ok(())
        } else {
            Err(denied())
        }
    }
}
