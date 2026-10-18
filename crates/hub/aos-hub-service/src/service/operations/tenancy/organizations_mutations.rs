//! Organizations mutations in the tenancy capability.

use super::*;

impl RpcService {
    /// Applies an organization-creation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication, confirmation, signup-policy, quota, conflict,
    /// or persistence error.
    pub async fn apply_create_organization(
        &self,
        auth: Option<&str>,
        req: pb::ApplyOrganizationMutationRequest,
    ) -> Result<pb::OrganizationResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_organization",
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
            "create_organization",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, OrganizationCreatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_organization",
                Some(&req.confirmation_hash),
            )
            .await?;
        let response = if let Some(org) = self
            .db
            .org_by_slug_including_deleted(&input.request.slug)
            .await
            .map_err(RpcError::internal)?
        {
            if org.name != input.request.display_name
                || !self
                    .db
                    .org_matches_creation_plan(org.id, &plan.plan_id)
                    .await
                    .map_err(RpcError::internal)?
            {
                return Err(RpcError::FailedPrecondition(
                    "organization identity was claimed after planning".to_string(),
                ));
            }
            let claims = self.require_claims(auth)?;
            if let Some(principal) = claims_principal(&claims) {
                if principal.kind == PrincipalKind::User {
                    self.db
                        .grant_membership(
                            principal.kind.as_str(),
                            principal.id,
                            &org.stable_id,
                            Role::Owner.as_str(),
                        )
                        .await
                        .map_err(RpcError::internal)?;
                }
            }
            pb::OrganizationResponse {
                organization: Some(organization_message(&org)),
            }
        } else {
            self.create_organization_from_plan(auth, input.request, &plan.plan_id)
                .await?
        };
        let claims = self.require_claims(auth)?;
        if let Some(organization) = response.organization.as_ref() {
            if let Err(error) = self
                .db
                .record_audit(
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                    "topology.organization.create",
                    &organization.stable_id,
                    None,
                    None,
                    None,
                    Some(&organization.slug),
                )
                .await
            {
                tracing::warn!(error = %format!("{error:#}"), "recording organization creation audit");
            }
        }
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies an organization profile update exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication, confirmation, authorization, stale-plan, or
    /// persistence error.
    pub async fn apply_update_organization(
        &self,
        auth: Option<&str>,
        req: pb::ApplyOrganizationMutationRequest,
    ) -> Result<pb::OrganizationResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "update_organization",
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
            "update_organization",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, OrganizationUpdatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "update_organization",
                Some(&req.confirmation_hash),
            )
            .await?;
        let mut org = self.org_or_not_found(&input.request.slug).await?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        if org.id != input.org_id {
            return Err(RpcError::FailedPrecondition(
                "organization identity changed after planning".to_string(),
            ));
        }
        let exact_recovery = org.resource_version == input.baseline_resource_version + 1
            && org.name == input.request.display_name
            && self
                .db
                .org_matches_mutation_plan(org.id, &plan.plan_id)
                .await
                .map_err(RpcError::internal)?;
        if !exact_recovery {
            if org.resource_version != input.baseline_resource_version
                || !self
                    .db
                    .update_org_profile(
                        org.id,
                        &input.request.display_name,
                        input.baseline_resource_version,
                        &plan.plan_id,
                    )
                    .await
                    .map_err(RpcError::internal)?
            {
                return Err(RpcError::FailedPrecondition(
                    "organization changed after planning".to_string(),
                ));
            }
            org = self.org_or_not_found(&input.request.slug).await?;
        }
        let response = pb::OrganizationResponse {
            organization: Some(organization_message(&org)),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies organization offboarding exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication, confirmation, authorization, stale-plan, or
    /// persistence error.
    pub async fn apply_delete_organization(
        &self,
        auth: Option<&str>,
        req: pb::ApplyOrganizationMutationRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_organization",
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
            "delete_organization",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, OrganizationDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_organization",
                Some(&req.confirmation_hash),
            )
            .await?;
        let org = self
            .db
            .org_by_slug_including_deleted(&input.request.slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        if org.id != input.org_id {
            return Err(RpcError::FailedPrecondition(
                "organization identity changed after planning".to_string(),
            ));
        }
        let exact_recovery = org.resource_version == input.baseline_resource_version + 1
            && self
                .db
                .org_matches_mutation_plan(org.id, &plan.plan_id)
                .await
                .map_err(RpcError::internal)?;
        if !exact_recovery
            && (org.resource_version != input.baseline_resource_version
                || !self
                    .db
                    .soft_delete_org_at_version(
                        org.id,
                        ORGANIZATION_DELETE_GRACE_SECS,
                        input.baseline_resource_version,
                        &plan.plan_id,
                    )
                    .await
                    .map_err(RpcError::internal)?)
        {
            return Err(RpcError::FailedPrecondition(
                "organization changed after planning".to_string(),
            ));
        }
        if let Err(error) = self
            .db
            .record_audit(
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                "topology.organization.delete",
                &org.stable_id,
                None,
                None,
                None,
                Some(&org.slug),
            )
            .await
        {
            tracing::warn!(error = %format!("{error:#}"), "recording organization deletion audit");
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
