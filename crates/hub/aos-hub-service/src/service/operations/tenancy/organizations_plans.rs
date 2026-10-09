//! Organizations plans in the tenancy capability.

use super::*;

impl RpcService {
    /// Plans creation of an organization and initial owner grant.
    ///
    /// # Errors
    ///
    /// Returns an authentication, signup-policy, validation, conflict, or
    /// persistence error.
    pub async fn plan_create_organization(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanCreateOrganizationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        req.display_name = req.display_name.trim().to_string();
        if req.display_name.is_empty() {
            return Err(RpcError::invalid("displayName is required"));
        }
        iam::validate_org_slug(&req.slug)
            .map_err(|error| RpcError::invalid(format!("organization slug: {error}")))?;
        if self.db.signup_policy().await.map_err(RpcError::internal)?
            == crate::db::SignupPolicy::InviteOnly
            && !self.signup_permitted(&claims).await?
        {
            return Err(RpcError::PermissionDenied(
                "organization creation is invite-only on this instance".to_string(),
            ));
        }
        self.enforce_signup_domain(&claims).await?;
        if self
            .db
            .org_by_slug_including_deleted(&req.slug)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "organization slug already exists".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = OrganizationCreatePlanInput { request: req };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_organization",
            "instance",
            &input,
            &idempotency_key,
            vec![format!(
                "create organization '{}' and grant its creating user Owner",
                input.request.slug
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans an organization profile update under an exact resource version.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, stale-version, or
    /// persistence error.
    pub async fn plan_update_organization(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanUpdateOrganizationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.slug).await?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        req.display_name = req.display_name.trim().to_string();
        if req.display_name.is_empty() || req.expected_resource_version.is_empty() {
            return Err(RpcError::invalid(
                "displayName and expectedResourceVersion are required",
            ));
        }
        if parse_resource_version(&req.expected_resource_version, org.resource_version)?
            != org.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "organization resource version is stale".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = OrganizationUpdatePlanInput {
            request: req,
            org_id: org.id,
            baseline_resource_version: org.resource_version,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "update_organization",
            &org.stable_id,
            &input,
            &idempotency_key,
            vec![format!("update organization '{}' profile", org.slug)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans organization offboarding under an exact resource version.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, stale-version, or persistence
    /// error.
    pub async fn plan_delete_organization(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteOrganizationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.slug).await?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        if req.expected_resource_version.is_empty()
            || parse_resource_version(&req.expected_resource_version, org.resource_version)?
                != org.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "organization resource version is required and must be current".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = OrganizationDeletePlanInput {
            request: req,
            org_id: org.id,
            baseline_resource_version: org.resource_version,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_organization",
            &org.stable_id,
            &input,
            &idempotency_key,
            vec![format!(
                "soft-delete organization '{}' and begin its 30-day purge grace",
                org.slug
            )],
            vec!["serving stops immediately; external storage purge is separate".to_string()],
            Some(confirmation_hash),
        )
        .await
    }
}
