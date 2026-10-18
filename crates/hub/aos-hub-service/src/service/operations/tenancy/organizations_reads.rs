//! Organizations reads in the tenancy capability.

use super::*;

impl RpcService {
    /// `OrganizationService.GetOrganization` — looks up an organization by slug.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug and
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_organization(
        &self,
        _auth: Option<&str>,
        req: pb::GetOrganizationRequest,
    ) -> Result<pb::OrganizationResponse, RpcError> {
        let org = self.org_or_not_found(&req.slug).await?;
        Ok(pb::OrganizationResponse {
            organization: Some(organization_message(&org)),
        })
    }
}
