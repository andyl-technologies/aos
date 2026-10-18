//! Membership reads in the identity capability.

use super::*;

impl RpcService {
    /// Reads one direct membership grant and its exact revision.
    pub async fn get_membership(
        &self,
        auth: Option<&str>,
        req: pb::GetMembershipRequest,
    ) -> Result<pb::MembershipResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope)?;
        self.require_permission(&claims, Permission::MembersManage, &scope)
            .await?;
        let principal_id = self
            .resolve_existing_principal_id(&req.principal_kind, &req.principal_ref)
            .await?;
        let role = self
            .db
            .list_memberships_for(&req.principal_kind, principal_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find_map(|(candidate_scope, role)| {
                (candidate_scope == scope.as_str()).then_some(role)
            });
        Ok(pb::MembershipResponse {
            principal_kind: req.principal_kind,
            principal_ref: req.principal_ref,
            scope: scope.as_str().to_string(),
            role: role.clone().unwrap_or_default(),
            resource_version: role.unwrap_or_else(|| "absent".to_string()),
        })
    }

    /// Lists invitation history for one organization.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error when the caller cannot
    /// manage members, [`RpcError::NotFound`] for an unknown organization, and
    /// [`RpcError::Internal`] on persistence failure.
    pub async fn list_invitations(
        &self,
        auth: Option<&str>,
        req: pb::ListInvitationsRequest,
    ) -> Result<pb::ListInvitationsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        let invitations = self
            .db
            .list_invitations(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|record| invitation_message(&org.slug, record))
            .collect::<Result<Vec<_>, _>>()?;
        let (invitations, next_page_token) = paginate(invitations, req.page_size, &req.page_token)?;
        Ok(pb::ListInvitationsResponse {
            invitations,
            next_page_token,
        })
    }

    /// Reads one invitation without exposing its acceptance secret.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error when the caller cannot
    /// manage members, [`RpcError::NotFound`] for an unknown resource, and
    /// [`RpcError::Internal`] on persistence failure.
    pub async fn get_invitation(
        &self,
        auth: Option<&str>,
        req: pb::GetInvitationRequest,
    ) -> Result<pb::InvitationResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        let record = self
            .db
            .invitation_record(org.id, req.invitation_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("invitation"))?;
        Ok(pb::InvitationResponse {
            invitation: Some(invitation_message(&org.slug, record)?),
            secret: String::new(),
        })
    }
}
