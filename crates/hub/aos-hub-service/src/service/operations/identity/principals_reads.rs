//! Principals reads in the identity capability.

use super::*;

impl RpcService {
    /// Reads an organization's redacted OIDC identity-provider configuration.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, lookup, or persistence error.
    pub async fn get_identity_provider(
        &self,
        auth: Option<&str>,
        req: pb::GetIdentityProviderRequest,
    ) -> Result<pb::IdentityProviderResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        let record = self
            .db
            .idp_config(org.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("identity provider"))?;
        Ok(pb::IdentityProviderResponse {
            identity_provider: Some(identity_provider_message(&org.slug, record)),
        })
    }
}
