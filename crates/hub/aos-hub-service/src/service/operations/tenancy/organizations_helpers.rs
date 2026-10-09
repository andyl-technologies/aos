//! Organizations helpers in the tenancy capability.

use super::*;

impl RpcService {
    /// Creates an organization attributed to an already-reserved control plan.
    ///
    /// The bootstrap exception: any authenticated principal may create an org.
    /// A user caller is granted `Owner` at the new org's scope; a
    /// service-account caller creates the org without an auto-grant. Bounded two
    /// ways against namespace pollution (sec L-3): a per-principal creation rate
    /// limit ([`RateClass::CreateOrg`]) and a per-owner total cap
    /// ([`MAX_ORGS_PER_OWNER`]).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the instance is `invite_only` and the
    /// caller is not permitted, [`RpcError::ResourceExhausted`] when the caller
    /// exceeds the creation rate or owns [`MAX_ORGS_PER_OWNER`] orgs,
    /// [`RpcError::InvalidArgument`] for an empty name or invalid slug,
    /// [`RpcError::AlreadyExists`] when the slug is taken, and
    /// [`RpcError::Internal`] on database failure.
    pub(in crate::service) async fn create_organization_from_plan(
        &self,
        auth: Option<&str>,
        req: pb::PlanCreateOrganizationRequest,
        plan_id: &str,
    ) -> Result<pb::OrganizationResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.display_name.is_empty() {
            return Err(RpcError::invalid("org name is required"));
        }
        // Validate the slug before creating the org or granting any membership:
        // a slug like "/" or "/victimorg" would otherwise normalize (via
        // `Scope::parse`) into an unintended ancestor scope and hand the caller
        // Owner over the instance root or a victim org (sec CR-2).
        iam::validate_org_slug(&req.slug)
            .map_err(|e| RpcError::invalid(format!("org slug: {e}")))?;
        // Instance signup policy: `invite_only` requires the caller to already
        // be a member, hold a live invitation, or be an instance admin.
        if self.db.signup_policy().await.map_err(RpcError::internal)?
            == crate::db::SignupPolicy::InviteOnly
            && !self.signup_permitted(&claims).await?
        {
            return Err(RpcError::PermissionDenied(
                "org creation is invite-only on this instance".into(),
            ));
        }
        // Instance email-domain allowlist: when set, a *new* user signing up
        // (creating their first org) must have an allowlisted email domain.
        // Existing members and instance admins are exempt — the allowlist gates
        // the signup moment, not established tenants.
        self.enforce_signup_domain(&claims).await?;
        // Bound the creation rate per authenticated principal (the JWT owner),
        // after the cheap input/policy gates so a rejected request does not
        // consume the caller's creation budget.
        let rl_key = format!("{}:{}", claims.owner_kind, claims.owner_id);
        if let RateDecision::Limited { retry_after } = self
            .ratelimit
            .check(RateClass::CreateOrg, &rl_key, clock::now_unix_secs())
            .await
        {
            return Err(RpcError::ResourceExhausted(format!(
                "org creation rate limit exceeded; retry after {retry_after}s"
            )));
        }
        // Per-owner total cap: a user principal may own only so many orgs, so a
        // slow loop cannot accumulate past the burst the rate limit blunts.
        if let Some(principal) = claims_principal(&claims) {
            if principal.kind == PrincipalKind::User
                && self
                    .db
                    .count_user_owned_orgs(principal.id)
                    .await
                    .map_err(RpcError::internal)?
                    >= MAX_ORGS_PER_OWNER
            {
                return Err(RpcError::ResourceExhausted(format!(
                    "owned-org limit reached ({MAX_ORGS_PER_OWNER} max); contact an instance admin"
                )));
            }
        }
        let id = self
            .db
            .create_org_from_plan(&req.slug, &req.display_name, plan_id)
            .await
            .map_err(|e| RpcError::AlreadyExists(format!("{e:#}")))?;
        let org = self
            .db
            .org_by_id(id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("org {id} vanished after creation"))
            })?;
        // Auto-grant the creating user Owner on the new org.
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
        Ok(pb::OrganizationResponse {
            organization: Some(organization_message(&org)),
        })
    }

    /// Resolve an org by slug or map a miss to `NotFound`.
    pub(in crate::service) async fn org_or_not_found(
        &self,
        slug: &str,
    ) -> Result<crate::db::OrgRecord, RpcError> {
        self.db
            .org_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("org"))
    }

    /// Resolves a canonical storage owner scope and requires an exact permission.
    pub(in crate::service) async fn storage_owner(
        &self,
        auth: Option<&str>,
        owner_scope_key: &str,
        permission: Permission,
    ) -> Result<Option<i64>, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::try_parse(owner_scope_key)
            .ok_or_else(|| RpcError::invalid("owner scope is not canonical"))?;
        let (kind, org_id, _project_id) = self
            .db
            .authorization_scope_owner(owner_scope_key)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("owner scope"))?;
        if kind == "instance" {
            self.require_permission(&claims, permission, &Scope::root())
                .await?;
            return Ok(None);
        }
        self.require_permission(&claims, permission, &scope).await?;
        Ok(org_id)
    }

    /// Resolves a canonical storage owner scope for read-only operations.
    pub(in crate::service) async fn readable_storage_owner(
        &self,
        auth: Option<&str>,
        owner_scope_key: &str,
    ) -> Result<Option<i64>, RpcError> {
        self.storage_owner(auth, owner_scope_key, Permission::BindingRead)
            .await
    }

    /// Resolves a canonical storage owner scope for mutating operations.
    pub(in crate::service) async fn writable_storage_owner(
        &self,
        auth: Option<&str>,
        owner_scope_key: &str,
    ) -> Result<Option<i64>, RpcError> {
        self.storage_owner(auth, owner_scope_key, Permission::BindingManage)
            .await
    }
}
