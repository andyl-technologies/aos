//! Membership mutations in the identity capability.

use super::*;

impl RpcService {
    /// Applies one reviewed membership replacement exactly once.
    pub async fn apply_set_membership(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::MembershipResponse, RpcError> {
        const PLAN_KIND: &str = "set_membership";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::MembersManage)
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
        let (plan, input): (_, MembershipPlanInput) = self
            .load_control_plan(auth, &req.plan_id, PLAN_KIND, Some(&req.confirmation_hash))
            .await?;
        let scope = parse_authorization_scope(&input.scope)?;
        self.require_permission(&claims, Permission::MembersManage, &scope)
            .await?;
        self.require_membership_grant_ceiling(
            &claims,
            &scope,
            input.baseline_role.as_deref().and_then(Role::parse),
            input.desired_role.as_deref().and_then(Role::parse),
        )
        .await?;
        let principal_id = self
            .resolve_existing_principal_id(&input.principal_kind, &input.principal_ref)
            .await?;
        if principal_id != input.principal_id {
            return Err(RpcError::FailedPrecondition(
                "principal identity changed after planning".into(),
            ));
        }
        let current_role = self
            .db
            .list_memberships_for(&input.principal_kind, principal_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find_map(|(candidate_scope, role)| (candidate_scope == input.scope).then_some(role));
        if current_role != input.baseline_role {
            return Err(RpcError::FailedPrecondition(
                "membership changed after planning".into(),
            ));
        }
        let result = if let Some(role) = input.desired_role.as_deref() {
            self.db
                .set_membership_role_owner_safe(
                    &input.principal_kind,
                    principal_id,
                    &input.scope,
                    role,
                )
                .await
        } else {
            self.db
                .revoke_membership_owner_safe(&input.principal_kind, principal_id, &input.scope)
                .await
        };
        result.map_err(|error| {
            if crate::db::is_last_owner_error(&error) {
                RpcError::FailedPrecondition(
                    "an organization must retain at least one human owner".to_string(),
                )
            } else {
                RpcError::internal(error)
            }
        })?;
        let actor_id = claims_principal(&claims).map(|principal| principal.id);
        let action = if input.desired_role.is_some() {
            "membership.grant"
        } else {
            "membership.revoke"
        };
        let detail = input.desired_role.as_deref().map_or_else(
            || format!("{}:{}", input.principal_kind, input.principal_ref),
            |role| {
                format!(
                    "{}:{} role={role}",
                    input.principal_kind, input.principal_ref
                )
            },
        );
        if let Err(error) = self
            .db
            .record_audit(
                &claims.owner_kind,
                actor_id,
                &claims.sub,
                action,
                &input.scope,
                Some(&plan.plan_id),
                None,
                None,
                Some(&detail),
            )
            .await
        {
            tracing::warn!(error = %format!("{error:#}"), "recording membership audit");
        }
        let response = pb::MembershipResponse {
            principal_kind: input.principal_kind,
            principal_ref: input.principal_ref,
            scope: input.scope,
            role: input.desired_role.clone().unwrap_or_default(),
            resource_version: input.desired_role.unwrap_or_else(|| "absent".to_string()),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one reviewed invitation-creation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error for an invalid caller,
    /// [`RpcError::FailedPrecondition`] when the reviewed baseline changed, and
    /// an internal or plan-lifecycle error when creation cannot be committed.
    pub async fn apply_create_invitation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::InvitationResponse, RpcError> {
        const PLAN_KIND: &str = "create_invitation";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::MembersManage)
            .await?;
        if let Some(mut response) = self
            .replayed_control_result::<pb::InvitationResponse>(
                auth,
                &req.plan_id,
                PLAN_KIND,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            let invitation_id = response
                .invitation
                .as_ref()
                .map(|invitation| invitation.invitation_id)
                .ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!(
                        "applied invitation plan omitted its resource"
                    ))
                })?;
            let sealed = self
                .db
                .recoverable_invitation_sealed_secret(invitation_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "the invitation is terminal and its recovery secret was erased".into(),
                    )
                })?;
            let sealer = self.sealer.as_ref().ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "invitation creation requires durable secret sealing".into(),
                )
            })?;
            response.secret = sealer.unseal(&sealed).map_err(RpcError::internal)?;
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
        let (plan, input): (_, InvitationCreatePlanInput) = self
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
        let scope = parse_authorization_scope(&input.scope)?;
        self.require_permission(&claims, Permission::MembersManage, &scope)
            .await?;
        let role = Role::parse(&input.role).ok_or_else(|| {
            RpcError::FailedPrecondition("reviewed invitation role is invalid".into())
        })?;
        self.require_membership_grant_ceiling(&claims, &scope, None, Some(role))
            .await?;
        let (secret, token_hash) = crate::auth::token::generate_invitation_token();
        let sealer = self.sealer.as_ref().ok_or_else(|| {
            RpcError::FailedPrecondition(
                "invitation creation requires durable secret sealing".into(),
            )
        })?;
        let sealed_secret = sealer.seal(&secret).map_err(RpcError::internal)?;
        if self
            .db
            .pending_invitation_for(org.id, &input.email, &input.scope)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::FailedPrecondition(
                "a pending invitation appeared after planning".into(),
            ));
        }
        if let Some(user_id) = self
            .db
            .user_by_email(&input.email)
            .await
            .map_err(RpcError::internal)?
        {
            let already_member = self
                .db
                .list_memberships_for("user", user_id)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .any(|(candidate, _)| candidate == input.scope);
            if already_member {
                return Err(RpcError::FailedPrecondition(
                    "the invitee gained a direct membership after planning".into(),
                ));
            }
        }
        let plan_uuid = uuid::Uuid::parse_str(&plan.plan_id).map_err(RpcError::internal)?;
        let created_at = clock::now_unix_secs();
        let record = crate::db::InvitationRecord {
            id: crate::db::portable_relational_id(plan_uuid),
            org_id: org.id,
            email: input.email,
            scope: input.scope,
            role: input.role,
            created_at,
            accepted_at: None,
            cancelled_at: None,
            expires_at: created_at.saturating_add(input.ttl_secs),
        };
        let event_id = hex::encode(Sha256::digest(
            format!("invitation:create:{}", plan.plan_id).as_bytes(),
        ));
        let response = pb::InvitationResponse {
            invitation: Some(invitation_message(&org.slug, record.clone())?),
            secret,
        };
        let persisted = pb::InvitationResponse {
            invitation: response.invitation.clone(),
            secret: String::new(),
        };
        let result_json = serde_json::to_string(&persisted).map_err(RpcError::internal)?;
        self.db
            .apply_invitation_creation_plan(
                &record,
                &token_hash,
                &sealed_secret,
                &plan.plan_id,
                &req.idempotency_key,
                &result_json,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                &event_id,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(response)
    }

    /// Applies one reviewed invitation-cancellation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error for an invalid caller,
    /// [`RpcError::FailedPrecondition`] when the reviewed invitation changed,
    /// and an internal or plan-lifecycle error when cancellation cannot commit.
    pub async fn apply_cancel_invitation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::InvitationResponse, RpcError> {
        const PLAN_KIND: &str = "cancel_invitation";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::MembersManage)
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
        let (plan, input): (_, InvitationCancelPlanInput) = self
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
        let current = self
            .db
            .invitation_record(org.id, input.invitation_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::FailedPrecondition("invitation disappeared".into()))?;
        let scope = parse_authorization_scope(&current.scope)?;
        self.require_permission(&claims, Permission::MembersManage, &scope)
            .await?;
        if invitation_resource_version(&current)? != input.baseline_resource_version {
            return Err(RpcError::FailedPrecondition(
                "invitation changed after planning".into(),
            ));
        }
        let cancelled_at = clock::now_unix_secs();
        if current.accepted_at.is_some()
            || current.cancelled_at.is_some()
            || current.expires_at <= cancelled_at
        {
            return Err(RpcError::FailedPrecondition(
                "invitation changed after planning".into(),
            ));
        }
        let mut cancelled = current;
        cancelled.cancelled_at = Some(cancelled_at);
        let event_id = hex::encode(Sha256::digest(
            format!("invitation:cancel:{}", plan.plan_id).as_bytes(),
        ));
        let response = pb::InvitationResponse {
            invitation: Some(invitation_message(&org.slug, cancelled.clone())?),
            secret: String::new(),
        };
        let result_json = serde_json::to_string(&response).map_err(RpcError::internal)?;
        self.db
            .apply_invitation_cancellation_plan(
                cancelled.id,
                input.baseline_created_at,
                cancelled_at,
                &cancelled.scope,
                &plan.plan_id,
                &req.idempotency_key,
                &result_json,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                &event_id,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(response)
    }

    /// Accepts an invitation for the authenticated matching user.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a non-user caller,
    /// [`RpcError::FailedPrecondition`] for an invalid, terminal, expired, or
    /// conflicting invitation, and [`RpcError::Internal`] on persistence failure.
    pub async fn accept_invitation(
        &self,
        auth: Option<&str>,
        req: pb::AcceptInvitationRequest,
    ) -> Result<pb::AcceptInvitationResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let principal = claims_principal(&claims)
            .filter(|principal| principal.kind == PrincipalKind::User)
            .ok_or_else(|| {
                RpcError::PermissionDenied("a human user must accept invitations".into())
            })?;
        let email = self
            .db
            .user_email(principal.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::PermissionDenied("authenticated user is not live".into()))?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        if req.secret.is_empty() {
            return Err(RpcError::invalid("invitation secret is required"));
        }
        let token_hash = crate::auth::token::sha256_hex(&req.secret);
        let event_id = hex::encode(Sha256::digest(
            format!("invitation:accept:{token_hash}").as_bytes(),
        ));
        let accepted = self
            .db
            .accept_invitation_audited(
                &token_hash,
                org.id,
                principal.id,
                &email,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                &event_id,
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!("invitation could not be accepted: {error:#}"))
            })?
            .ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "invitation is invalid, terminal, expired, or belongs to another user".into(),
                )
            })?;
        Ok(pb::AcceptInvitationResponse {
            membership: Some(pb::MembershipResponse {
                principal_kind: "user".to_string(),
                principal_ref: email,
                scope: accepted.scope.clone(),
                role: accepted.role.clone(),
                resource_version: accepted.role.clone(),
            }),
            invitation: Some(invitation_message(&org.slug, accepted)?),
        })
    }
}
