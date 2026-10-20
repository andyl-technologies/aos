//! Projects reads in the tenancy capability.

use super::*;

impl RpcService {
    /// `ProjectService.ListProjects` — an org's projects, ordered by path.
    ///
    /// The project tree is org-internal: the caller must present a bearer JWT
    /// granting [`Permission::Read`] on the org scope. An anonymous or
    /// non-member caller is denied, so the project layout never leaks across
    /// tenants.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::PermissionDenied`] when the caller lacks `Read` on the org
    /// scope, and [`RpcError::Internal`] on database failure.
    pub async fn list_projects(
        &self,
        auth: Option<&str>,
        req: pb::ListProjectsRequest,
    ) -> Result<pb::ListProjectsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(&claims, Permission::Read, &Scope::parse(&org.stable_id))
            .await?;
        let projects: Vec<pb::Project> = self
            .db
            .list_projects(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|project| project_message(org.slug.clone(), project))
            .collect();
        let (projects, next_page_token) = paginate(projects, req.page_size, &req.page_token)?;
        Ok(pb::ListProjectsResponse {
            projects,
            next_page_token,
        })
    }

    /// Reads one organization-owned service account.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error when the caller cannot
    /// manage organization members, [`RpcError::NotFound`] when either resource
    /// does not exist, and [`RpcError::Internal`] on database failure.
    pub async fn get_service_account(
        &self,
        auth: Option<&str>,
        req: pb::GetServiceAccountRequest,
    ) -> Result<pb::ServiceAccountResponse, RpcError> {
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
            .service_account_record(org.id, &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("service account"))?;
        Ok(pb::ServiceAccountResponse {
            service_account: Some(service_account_message(&org.slug, record)?),
        })
    }

    /// Returns one project by exact materialized path.
    pub async fn get_project(
        &self,
        auth: Option<&str>,
        req: pb::GetProjectRequest,
    ) -> Result<pb::ProjectResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(&claims, Permission::Read, &Scope::parse(&org.stable_id))
            .await?;
        let path = req.path.trim_matches('/');
        let project = self
            .db
            .project_by_path(org.id, path)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("project"))?;
        Ok(pb::ProjectResponse {
            project: Some(project_message(org.slug, project)),
        })
    }
}
