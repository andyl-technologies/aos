//! Projects mutations in the tenancy capability.

use super::*;

impl RpcService {
    /// Applies one reviewed service-account creation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error for an invalid caller,
    /// [`RpcError::FailedPrecondition`] when the reviewed baseline changed, and
    /// an internal or plan-lifecycle error when the operation cannot be applied.
    pub async fn apply_create_service_account(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::ServiceAccountResponse, RpcError> {
        const PLAN_KIND: &str = "create_service_account";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                PLAN_KIND,
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
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, ServiceAccountCreatePlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let org = self
            .db
            .org_by_slug(&input.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        if org.id != input.org_id {
            return Err(RpcError::FailedPrecondition(
                "organization identity changed after planning".into(),
            ));
        }
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        if self
            .db
            .service_account_by_name(org.id, &input.name)
            .await
            .map_err(RpcError::internal)?
            != input.baseline_principal_id
        {
            return Err(RpcError::FailedPrecondition(
                "service account changed after planning".into(),
            ));
        }
        let id = self
            .db
            .create_service_account(org.id, &input.name)
            .await
            .map_err(RpcError::internal)?;
        let record = self
            .db
            .service_account_record(org.id, &input.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("created service account disappeared"))
            })?;
        debug_assert_eq!(record.id, id);
        let response = pb::ServiceAccountResponse {
            service_account: Some(service_account_message(&input.org_slug, record)?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one reviewed service-account update plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error for an invalid caller,
    /// [`RpcError::FailedPrecondition`] when the reviewed baseline changed, and
    /// an internal or plan-lifecycle error when the operation cannot be applied.
    pub async fn apply_update_service_account(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::ServiceAccountResponse, RpcError> {
        const PLAN_KIND: &str = "update_service_account";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                PLAN_KIND,
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
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, ServiceAccountUpdatePlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let org = self
            .db
            .org_by_slug(&input.org_slug)
            .await
            .map_err(RpcError::internal)?
            .filter(|org| org.id == input.org_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("organization changed after planning".into())
            })?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        let current = self
            .db
            .service_account_record(org.id, &input.current_name)
            .await
            .map_err(RpcError::internal)?
            .filter(|record| record.id == input.service_account_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("service account changed after planning".into())
            })?;
        if service_account_resource_version(&current)? != input.baseline_resource_version {
            return Err(RpcError::FailedPrecondition(
                "service account changed after planning".into(),
            ));
        }
        if !self
            .db
            .rename_service_account(current.id, &input.current_name, &input.new_name)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::FailedPrecondition(
                "service account changed during apply".into(),
            ));
        }
        let updated = self
            .db
            .service_account_record(org.id, &input.new_name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("updated service account disappeared"))
            })?;
        let response = pb::ServiceAccountResponse {
            service_account: Some(service_account_message(&org.slug, updated)?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one reviewed service-account deletion plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error for an invalid caller,
    /// [`RpcError::FailedPrecondition`] when the reviewed baseline changed, and
    /// an internal or plan-lifecycle error when the operation cannot be applied.
    pub async fn apply_delete_service_account(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        const PLAN_KIND: &str = "delete_service_account";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                PLAN_KIND,
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
            PLAN_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, ServiceAccountDeletePlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let org = self
            .db
            .org_by_slug(&input.org_slug)
            .await
            .map_err(RpcError::internal)?
            .filter(|org| org.id == input.org_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("organization changed after planning".into())
            })?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        let current = self
            .db
            .service_account_record(org.id, &input.name)
            .await
            .map_err(RpcError::internal)?
            .filter(|record| record.id == input.service_account_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("service account changed after planning".into())
            })?;
        if service_account_resource_version(&current)? != input.baseline_resource_version {
            return Err(RpcError::FailedPrecondition(
                "service account changed after planning".into(),
            ));
        }
        self.db
            .delete_service_account(current.id, &input.name)
            .await
            .map_err(RpcError::internal)?;
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one project creation plan exactly once.
    pub async fn apply_create_project(
        &self,
        auth: Option<&str>,
        req: pb::ApplyProjectMutationRequest,
    ) -> Result<pb::ProjectResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_project",
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
            "create_project",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, ProjectCreatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_project",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&input.request.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&input.owner_scope_key),
        )
        .await?;
        if org.id != input.org_id || org.stable_id != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "project owner identity changed after planning".to_string(),
            ));
        }
        let project = if let Some(project) = self
            .db
            .project_by_path(org.id, &input.request.path)
            .await
            .map_err(RpcError::internal)?
        {
            if !self
                .db
                .project_matches_creation_plan(project.id, &plan.plan_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::FailedPrecondition(
                    "project path was claimed after planning".to_string(),
                ));
            }
            project
        } else {
            let project_id = self
                .db
                .create_project_from_plan(
                    org.id,
                    &input.request.path,
                    &input.request.name,
                    &plan.plan_id,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await
                .map_err(|error| RpcError::AlreadyExists(format!("{error:#}")))?;
            self.db
                .project_by_path(org.id, &input.request.path)
                .await
                .map_err(RpcError::internal)?
                .filter(|project| project.id == project_id)
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("created project disappeared")))?
        };
        let response = pb::ProjectResponse {
            project: Some(project_message(org.slug, project)),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one empty-project deletion plan exactly once.
    pub async fn apply_delete_project(
        &self,
        auth: Option<&str>,
        req: pb::ApplyProjectMutationRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_project",
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
            "delete_project",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, ProjectDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_project",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&input.org_slug).await?;
        if org.id != input.org_id {
            return Err(RpcError::FailedPrecondition(
                "project owner identity changed after planning".to_string(),
            ));
        }
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&input.stable_id),
        )
        .await?;
        if let Some(project) = self
            .db
            .project_by_path(input.org_id, &input.path)
            .await
            .map_err(RpcError::internal)?
        {
            if project.id != input.project_id || project.stable_id != input.stable_id {
                return Err(RpcError::FailedPrecondition(
                    "project identity changed after planning".to_string(),
                ));
            }
            if !self
                .db
                .delete_project_at_version(
                    input.org_id,
                    project.id,
                    input.expected_resource_version,
                    &plan.plan_id,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?
            {
                return Err(RpcError::FailedPrecondition(
                    "project changed after planning".to_string(),
                ));
            }
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
