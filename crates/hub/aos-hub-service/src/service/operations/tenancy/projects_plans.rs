//! Projects plans in the tenancy capability.

use super::*;

impl RpcService {
    /// Persists an immutable plan for creating a service account.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::InvalidArgument`] for an invalid name or organization,
    /// an authentication or authorization error when the caller cannot manage
    /// organization IAM, [`RpcError::AlreadyExists`] for a conflicting account,
    /// and [`RpcError::Internal`] on persistence failure.
    pub async fn plan_create_service_account(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanCreateServiceAccountRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        req.name = normalize_service_account_name(&req.name)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::invalid(format!("no org '{}'", req.org_slug)))?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        let baseline_principal_id = self
            .db
            .service_account_by_name(org.id, &req.name)
            .await
            .map_err(RpcError::internal)?;
        if baseline_principal_id.is_some() || !req.expected_resource_version.is_empty() {
            return Err(RpcError::AlreadyExists(
                "service account already exists or creation version is not empty".into(),
            ));
        }
        let input = ServiceAccountCreatePlanInput {
            org_id: org.id,
            org_slug: req.org_slug,
            name: req.name,
            baseline_principal_id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_service_account",
            &org.stable_id,
            &input,
            &req.idempotency_key,
            vec![format!(
                "create service account {}/{}",
                input.org_slug, input.name
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Persists an immutable plan for renaming one service account.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error when the caller cannot
    /// manage organization IAM, [`RpcError::NotFound`] for a missing resource,
    /// [`RpcError::FailedPrecondition`] for a stale resource version,
    /// [`RpcError::AlreadyExists`] for a name conflict, and
    /// [`RpcError::Internal`] on persistence failure.
    pub async fn plan_update_service_account(
        &self,
        auth: Option<&str>,
        req: pb::PlanUpdateServiceAccountRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let new_name = normalize_service_account_name(&req.new_name)?;
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
            .service_account_record(org.id, &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("service account"))?;
        let current_version = service_account_resource_version(&record)?;
        if req.expected_resource_version != current_version {
            return Err(RpcError::FailedPrecondition(
                "service-account resource version is stale".into(),
            ));
        }
        if new_name != record.name
            && self
                .db
                .service_account_by_name(org.id, &new_name)
                .await
                .map_err(RpcError::internal)?
                .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "service account already exists".into(),
            ));
        }
        let input = ServiceAccountUpdatePlanInput {
            org_id: org.id,
            org_slug: org.slug,
            service_account_id: record.id,
            current_name: record.name,
            new_name,
            baseline_resource_version: current_version,
        };
        self.create_control_plan(
            &claims,
            "update_service_account",
            &org.stable_id,
            &input,
            &req.idempotency_key,
            vec![format!(
                "rename service account {}/{} to {}",
                input.org_slug, input.current_name, input.new_name
            )],
            Vec::new(),
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }

    /// Persists an immutable plan for deleting one service account.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error when the caller cannot
    /// manage organization IAM, [`RpcError::NotFound`] for a missing resource,
    /// [`RpcError::FailedPrecondition`] for a stale resource version, and
    /// [`RpcError::Internal`] on persistence failure.
    pub async fn plan_delete_service_account(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteServiceAccountRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
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
            .service_account_record(org.id, &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("service account"))?;
        let current_version = service_account_resource_version(&record)?;
        if req.expected_resource_version != current_version {
            return Err(RpcError::FailedPrecondition(
                "service-account resource version is stale".into(),
            ));
        }
        let input = ServiceAccountDeletePlanInput {
            org_id: org.id,
            org_slug: org.slug,
            service_account_id: record.id,
            name: record.name,
            baseline_resource_version: current_version,
        };
        self.create_control_plan(
            &claims,
            "delete_service_account",
            &org.stable_id,
            &input,
            &req.idempotency_key,
            vec![format!(
                "delete service account {}/{} and its memberships",
                input.org_slug, input.name
            )],
            Vec::new(),
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }

    /// Plans creation of one project identity.
    pub async fn plan_create_project(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanCreateProjectRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        req.path = req.path.trim_matches('/').to_string();
        req.name = req.name.trim().to_string();
        if req.name.is_empty() {
            return Err(RpcError::invalid("project name is required"));
        }
        if self
            .db
            .project_by_path(org.id, &req.path)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "project path already exists".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = ProjectCreatePlanInput {
            request: req,
            org_id: org.id,
            owner_scope_key: org.stable_id.clone(),
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_project",
            &org.stable_id,
            &input,
            &idempotency_key,
            vec![format!("create project path '{}'", input.request.path)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans deletion of one empty project identity.
    pub async fn plan_delete_project(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteProjectRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        req.path = req.path.trim_matches('/').to_string();
        let project = self
            .db
            .project_by_path(org.id, &req.path)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("project"))?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&project.scope_key),
        )
        .await?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || expected != project.resource_version {
            return Err(RpcError::FailedPrecondition(
                "project resource version is required and must be current".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let project_scope_key = project.scope_key.clone();
        let input = ProjectDeletePlanInput {
            org_slug: org.slug.clone(),
            org_id: org.id,
            project_id: project.id,
            stable_id: project.stable_id.clone(),
            path: project.path.clone(),
            expected_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_project",
            &project_scope_key,
            &input,
            &idempotency_key,
            vec![format!("delete empty project path '{}'", input.path)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
