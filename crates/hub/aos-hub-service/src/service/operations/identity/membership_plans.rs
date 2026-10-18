//! Membership plans in the identity capability.

use super::*;

impl RpcService {
    /// Persists an immutable plan replacing one direct membership grant.
    pub async fn plan_set_membership(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetMembershipRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope)?;
        self.require_permission(&claims, Permission::MembersManage, &scope)
            .await?;
        let desired_role = if req.role.is_empty() {
            None
        } else {
            Some(
                Role::parse(&req.role)
                    .ok_or_else(|| RpcError::invalid(format!("unknown role '{}'", req.role)))?,
            )
        };
        let principal_id = self
            .resolve_existing_principal_id(&req.principal_kind, &req.principal_ref)
            .await?;
        let baseline_role = self
            .db
            .list_memberships_for(&req.principal_kind, principal_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find_map(|(candidate_scope, role)| {
                (candidate_scope == scope.as_str()).then_some(role)
            });
        self.require_membership_grant_ceiling(
            &claims,
            &scope,
            baseline_role.as_deref().and_then(Role::parse),
            desired_role,
        )
        .await?;
        let baseline_version = baseline_role.as_deref().unwrap_or("absent");
        if req.expected_resource_version != baseline_version {
            return Err(RpcError::FailedPrecondition(
                "membership resource version is stale".into(),
            ));
        }
        let input = MembershipPlanInput {
            principal_kind: req.principal_kind,
            principal_ref: req.principal_ref,
            principal_id,
            scope: scope.as_str().to_string(),
            desired_role: desired_role.map(|role| role.as_str().to_string()),
            baseline_role,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "set_membership",
            &input.scope,
            &input,
            &req.idempotency_key,
            vec![format!(
                "replace direct membership for {} at {}",
                input.principal_ref, input.scope
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Persists an immutable plan for creating one invitation.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::InvalidArgument`] for invalid invitation contents,
    /// an authentication or authorization error when the caller cannot manage
    /// members at the target scope, [`RpcError::AlreadyExists`] for a duplicate
    /// pending invitation, and [`RpcError::Internal`] on persistence failure.
    pub async fn plan_create_invitation(
        &self,
        auth: Option<&str>,
        req: pb::PlanCreateInvitationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        require_absent_resource_version(&req.expected_resource_version)?;
        let email = normalize_invitation_email(&req.email)?;
        let role = Role::parse(&req.role)
            .ok_or_else(|| RpcError::invalid(format!("unknown role '{}'", req.role)))?;
        let ttl_secs = if req.ttl_secs == 0 {
            INVITATION_DEFAULT_TTL_SECS
        } else {
            req.ttl_secs
        };
        if !(1..=INVITATION_MAX_TTL_SECS).contains(&ttl_secs) {
            return Err(RpcError::invalid(format!(
                "ttl_secs must be 0 or between 1 and {INVITATION_MAX_TTL_SECS}"
            )));
        }
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        let scope = parse_authorization_scope(&req.scope)?;
        let context = self
            .db
            .authorization_context(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("authorization scope"))?;
        if !context.is_covered_by(&Scope::parse(&org.stable_id))
            || (role == Role::Owner && scope.as_str() != org.stable_id)
        {
            return Err(RpcError::invalid(
                "invitation scope and role must belong to the organization",
            ));
        }
        self.require_permission(&claims, Permission::MembersManage, &scope)
            .await?;
        self.require_membership_grant_ceiling(&claims, &scope, None, Some(role))
            .await?;
        if self
            .db
            .pending_invitation_for(org.id, &email, scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "a pending invitation already exists for this email and scope".into(),
            ));
        }
        if let Some(user_id) = self
            .db
            .user_by_email(&email)
            .await
            .map_err(RpcError::internal)?
        {
            let already_member = self
                .db
                .list_memberships_for("user", user_id)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .any(|(candidate, _)| candidate == scope.as_str());
            if already_member {
                return Err(RpcError::AlreadyExists(
                    "the invited user already has a direct membership at this scope".into(),
                ));
            }
        }
        let input = InvitationCreatePlanInput {
            org_id: org.id,
            org_slug: org.slug,
            email,
            scope: scope.as_str().to_string(),
            role: role.as_str().to_string(),
            ttl_secs,
        };
        self.create_control_plan(
            &claims,
            "create_invitation",
            &input.scope,
            &input,
            &req.idempotency_key,
            vec![format!(
                "invite {} as {} at {}",
                input.email, input.role, input.scope
            )],
            Vec::new(),
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }

    /// Persists an immutable plan for cancelling one pending invitation.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error when the caller cannot
    /// manage members, [`RpcError::NotFound`] for an unknown resource,
    /// [`RpcError::FailedPrecondition`] for a terminal or stale invitation, and
    /// [`RpcError::Internal`] on persistence failure.
    pub async fn plan_cancel_invitation(
        &self,
        auth: Option<&str>,
        req: pb::PlanCancelInvitationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        let record = self
            .db
            .invitation_record(org.id, req.invitation_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("invitation"))?;
        let scope = parse_authorization_scope(&record.scope)?;
        self.require_permission(&claims, Permission::MembersManage, &scope)
            .await?;
        let version = invitation_resource_version(&record)?;
        if req.expected_resource_version != version {
            return Err(RpcError::FailedPrecondition(
                "invitation resource version is stale".into(),
            ));
        }
        if record.accepted_at.is_some()
            || record.cancelled_at.is_some()
            || record.expires_at <= clock::now_unix_secs()
        {
            return Err(RpcError::FailedPrecondition(
                "only a pending invitation may be cancelled".into(),
            ));
        }
        let input = InvitationCancelPlanInput {
            org_id: org.id,
            org_slug: org.slug,
            invitation_id: record.id,
            baseline_resource_version: version,
            baseline_created_at: record.created_at,
        };
        self.create_control_plan(
            &claims,
            "cancel_invitation",
            &record.scope,
            &input,
            &req.idempotency_key,
            vec![format!("cancel invitation {}", record.id)],
            Vec::new(),
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }
}
