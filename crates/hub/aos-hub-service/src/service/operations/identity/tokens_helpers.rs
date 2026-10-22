//! Shared authorization checks for access-token issuance.

use super::*;

impl RpcService {
    /// Checks the caller and selected owner's current authority for issuance.
    pub(in crate::service) async fn authorize_access_token_issue(
        &self,
        claims: &Claims,
        owner: Principal,
        scope: &Scope,
        permissions: &[Permission],
    ) -> Result<Vec<(Scope, Role)>, RpcError> {
        let actor = claims_principal(claims)
            .ok_or_else(|| RpcError::PermissionDenied("active token owner required".to_string()))?;
        let control_permission = if actor == owner {
            Permission::TokensSelf
        } else if owner.kind == PrincipalKind::ServiceAccount {
            Permission::TokensManage
        } else {
            return Err(RpcError::PermissionDenied(
                "human access tokens may only be issued by their owner".to_string(),
            ));
        };
        self.require_permission(claims, control_permission, scope)
            .await?;

        for permission in permissions {
            if let Err(error) = self.require_permission(claims, *permission, scope).await {
                return Err(match error {
                    RpcError::PermissionDenied(_) => RpcError::PermissionDenied(
                        "token permissions exceed the caller's current authority".to_string(),
                    ),
                    other => other,
                });
            }
        }

        let context = self
            .db
            .authorization_context(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("authorization scope"))?;
        let owner_grants = self
            .db
            .effective_scopes(owner)
            .await
            .map_err(RpcError::internal)?;
        if permissions
            .iter()
            .any(|permission| !iam::allow(&owner_grants, *permission, &context))
        {
            return Err(RpcError::PermissionDenied(
                "token permissions exceed the owner's current authority".to_string(),
            ));
        }

        Ok(owner_grants)
    }
}
