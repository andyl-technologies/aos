//! IAM principal, invitation, membership, and token lifecycle contracts.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::canonical;
use super::plan::HeadSeal;
use super::primitives::{ContentDigest, ControlError, Revision, StableId};

/// The supported IAM principal kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A human user.
    User,
    /// An organization-owned automation identity.
    ServiceAccount,
}

/// A stable typed reference to an IAM principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrincipalRef {
    /// Principal kind.
    kind: PrincipalKind,
    /// Stable principal identity, never an email or mutable display name.
    stable_id: StableId,
}

impl<'de> Deserialize<'de> for PrincipalRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PrincipalRefWire {
            kind: PrincipalKind,
            stable_id: StableId,
        }

        let wire = PrincipalRefWire::deserialize(deserializer)?;
        let principal = Self {
            kind: wire.kind,
            stable_id: wire.stable_id,
        };
        principal.validate().map_err(serde::de::Error::custom)?;
        Ok(principal)
    }
}

impl PrincipalRef {
    /// Constructs a typed principal reference.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the identity kind and stable-id
    /// kind differ.
    pub fn new(kind: PrincipalKind, stable_id: StableId) -> Result<Self, ControlError> {
        let principal = Self { kind, stable_id };
        principal.validate()?;
        Ok(principal)
    }

    /// Validates that the stable-id kind agrees with the typed principal kind.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when a user does not carry a `user:`
    /// id or a service account does not carry a `service-account:` id.
    pub fn validate(&self) -> Result<(), ControlError> {
        let expected = match self.kind {
            PrincipalKind::User => "user",
            PrincipalKind::ServiceAccount => "service-account",
        };
        if self.stable_id.kind() != expected {
            return Err(invalid(
                "principal",
                "principal kind and stable-id kind must agree",
            ));
        }
        Ok(())
    }

    /// Returns the typed principal kind.
    #[must_use]
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Returns the stable principal identity.
    #[must_use]
    pub fn stable_id(&self) -> &StableId {
        &self.stable_id
    }
}

/// The canonical Hub roles in increasing privilege order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read-only access.
    Viewer,
    /// Publish and development access.
    Developer,
    /// Registry maintenance access.
    Maintainer,
    /// Resource administration access.
    Admin,
    /// Full ownership, including owner-grant authority.
    Owner,
}

/// Explicit authority granted to an actor by the IAM policy evaluator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IamCapability {
    /// Creates, changes, revokes, or restores membership grants.
    ManageMemberships,
}

/// Exact authoritative actor-authorization result used by a membership apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActorAuthorizationSnapshot {
    /// Exact actor receiving evaluated authority.
    pub actor: PrincipalRef,
    /// Exact scope at which policy was evaluated.
    pub scope: StableId,
    /// Exact current membership revision from which authority was derived.
    pub actor_membership_head: HeadSeal,
    /// Explicit capabilities derived by policy.
    pub capabilities: Vec<IamCapability>,
    /// Maximum role the actor may grant to another principal.
    pub target_role_ceiling: Role,
    /// Authoritative current head of this exact policy-evaluation result.
    pub authorization_head: HeadSeal,
}

/// Lifecycle state of a service-account identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccountState {
    /// The principal may authenticate and receive grants.
    Active,
    /// The principal is permanently retired.
    Retired,
}

/// Immutable service-account revision contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceAccountContents {
    /// Owning organization scope stable identity.
    pub organization_scope: StableId,
    /// Stable human-facing name within the organization.
    pub name: String,
    /// Current lifecycle state.
    pub state: ServiceAccountState,
}

/// One immutable service-account identity revision.
pub type ServiceAccountRevision = Revision<ServiceAccountContents>;

impl ServiceAccountContents {
    /// Validates a service-account revision.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when `name` is not a canonical slug.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.organization_scope.kind() != "org" {
            return Err(invalid(
                "organization_scope",
                "service accounts must belong to an organization",
            ));
        }
        validate_slug("service_account_name", &self.name)
    }

    /// Produces the only valid retirement transition.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] if the account is already retired.
    pub fn retire(&self) -> Result<Self, ControlError> {
        if self.state == ServiceAccountState::Retired {
            return Err(invalid(
                "state",
                "retired service accounts cannot transition",
            ));
        }
        let mut next = self.clone();
        next.state = ServiceAccountState::Retired;
        Ok(next)
    }
}

/// Whether a membership grant is active or permanently revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    /// The grant participates in authorization.
    Active,
    /// The grant no longer participates in authorization.
    Revoked,
}

/// Immutable membership-grant revision contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MembershipContents {
    /// Principal receiving the grant.
    pub principal: PrincipalRef,
    /// Exact authorization scope stable identity.
    pub scope: StableId,
    /// Granted role.
    pub role: Role,
    /// Grant lifecycle state.
    pub state: MembershipState,
}

/// One immutable principal/scope membership revision.
pub type MembershipRevision = Revision<MembershipContents>;

/// One exact current membership revision retained in an IAM authorization snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MembershipSnapshotEntry {
    /// Stable membership relationship identity.
    pub membership_id: StableId,
    /// Exact current revision head.
    pub head: HeadSeal,
    /// Exact current immutable membership contents.
    pub contents: MembershipContents,
}

impl MembershipSnapshotEntry {
    /// Validates identity and digest binding for one retained snapshot entry.
    ///
    /// # Errors
    ///
    /// Returns an identity, contents, or digest error when the head and exact
    /// membership contents do not describe the same relationship revision.
    pub fn validate(&self) -> Result<(), ControlError> {
        self.contents.validate()?;
        if self.contents.stable_id()? != self.membership_id
            || self.head.stable_id != self.membership_id
        {
            return Err(invalid(
                "membership_snapshot",
                "entry id, head, and contents must name the same membership",
            ));
        }
        if self.head.content_digest != ContentDigest::of_value(&self.contents)? {
            return Err(ControlError::DigestMismatch);
        }
        Ok(())
    }
}

/// Transaction-wide IAM facts sealed before a membership mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MembershipApplyGate {
    /// Complete actor principal.
    pub actor: PrincipalRef,
    /// Exact authorization scope being changed.
    pub scope: StableId,
    /// Target principal.
    pub target: PrincipalRef,
    /// Stable identity of the principal/scope relationship.
    pub membership_id: StableId,
    /// Current membership head, absent only for creation.
    pub expected_head: Option<HeadSeal>,
    /// Exact membership contents proposed for commit.
    pub proposed: MembershipContents,
    /// Complete current scope membership snapshot, strictly ordered by id.
    pub membership_snapshot: Vec<MembershipSnapshotEntry>,
    /// Digest of the complete current membership snapshot.
    pub membership_snapshot_digest: ContentDigest,
    /// Authoritative current head of the scope's complete membership index.
    pub scope_membership_head: HeadSeal,
    /// Exact policy-evaluator result for the applying actor.
    pub actor_authorization: ActorAuthorizationSnapshot,
}

impl MembershipApplyGate {
    /// Enforces privilege ceiling, self-escalation, and human-owner invariants.
    ///
    /// The persistence adapter must recompute every field under the same write
    /// transaction before committing the membership revision.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] if no human owner exists before/after,
    /// the actor grants above their effective role, a non-owner grants Owner,
    /// or a principal promotes itself.
    pub fn validate(&self) -> Result<(), ControlError> {
        self.actor.validate()?;
        self.target.validate()?;
        self.proposed.validate()?;
        if self.proposed.principal != self.target || self.proposed.scope != self.scope {
            return Err(invalid(
                "proposed",
                "proposed membership must target the exact sealed principal and scope",
            ));
        }
        if self.proposed.stable_id()? != self.membership_id {
            return Err(invalid(
                "membership_id",
                "relationship identity must match the proposal",
            ));
        }
        if self.membership_snapshot.len() > 4_096
            || self
                .membership_snapshot
                .windows(2)
                .any(|pair| pair[0].membership_id >= pair[1].membership_id)
        {
            return Err(invalid(
                "membership_snapshot",
                "must be bounded, strictly ordered, and duplicate-free",
            ));
        }
        for entry in &self.membership_snapshot {
            entry.validate()?;
            if entry.contents.scope != self.scope {
                return Err(invalid(
                    "membership_snapshot",
                    "snapshot may contain only the exact target scope",
                ));
            }
        }
        if ContentDigest::of_value(&self.membership_snapshot)? != self.membership_snapshot_digest {
            return Err(ControlError::DigestMismatch);
        }
        if self.scope_membership_head.stable_id != membership_index_id(&self.scope)?
            || self.scope_membership_head.content_digest != self.membership_snapshot_digest
        {
            return Err(invalid(
                "scope_membership_head",
                "must be the authoritative head of the exact scope snapshot",
            ));
        }
        let current = self
            .membership_snapshot
            .iter()
            .find(|entry| entry.membership_id == self.membership_id);
        match (current, &self.expected_head) {
            (None, None) if self.proposed.state == MembershipState::Active => {}
            (Some(entry), Some(expected)) if entry.head == *expected => {}
            _ => {
                return Err(invalid(
                    "expected_head",
                    "must equal the exact current target membership snapshot head",
                ));
            }
        }
        if current.is_some_and(|entry| entry.contents.state == MembershipState::Revoked) {
            return Err(invalid(
                "proposed",
                "revoked membership relationships are immutable",
            ));
        }
        if self.proposed.state == MembershipState::Revoked
            && current.is_some_and(|entry| entry.contents.role != self.proposed.role)
        {
            return Err(invalid(
                "proposed",
                "revocation must preserve the exact current historical role",
            ));
        }
        if self.proposed.state == MembershipState::Revoked && current.is_none() {
            return Err(invalid("proposed", "cannot revoke an absent membership"));
        }
        let actor_entry = self
            .membership_snapshot
            .iter()
            .find(|entry| {
                entry.contents.principal == self.actor
                    && entry.contents.scope == self.scope
                    && entry.contents.state == MembershipState::Active
            })
            .ok_or_else(|| invalid("actor", "actor has no active membership at the scope"))?;
        let actor_role = actor_entry.contents.role;
        let expected_capabilities = if actor_role >= Role::Admin {
            vec![IamCapability::ManageMemberships]
        } else {
            Vec::new()
        };
        let authorization_contents = (
            &self.actor_authorization.actor,
            &self.actor_authorization.scope,
            &self.actor_authorization.actor_membership_head,
            &self.actor_authorization.capabilities,
            self.actor_authorization.target_role_ceiling,
            &self.scope_membership_head,
        );
        if self.actor_authorization.actor != self.actor
            || self.actor_authorization.scope != self.scope
            || self.actor_authorization.actor_membership_head != actor_entry.head
            || self.actor_authorization.capabilities != expected_capabilities
            || self.actor_authorization.target_role_ceiling != actor_role
            || self.actor_authorization.authorization_head.stable_id
                != actor_authorization_id(&self.actor, &self.scope)?
            || self.actor_authorization.authorization_head.content_digest
                != ContentDigest::of_value(&authorization_contents)?
            || !self
                .actor_authorization
                .capabilities
                .contains(&IamCapability::ManageMemberships)
        {
            return Err(invalid(
                "actor_authorization",
                "must be the exact authoritative IAM-manage result for the current actor snapshot",
            ));
        }
        if self.proposed.role > self.actor_authorization.target_role_ceiling
            || (self.proposed.role == Role::Owner && actor_role != Role::Owner)
        {
            return Err(invalid(
                "proposed_role",
                "a principal cannot grant authority it does not hold",
            ));
        }
        if current.is_some_and(|entry| entry.contents.role == Role::Owner)
            && actor_role != Role::Owner
        {
            return Err(invalid(
                "proposed_role",
                "only an Owner may modify, demote, or revoke an Owner grant",
            ));
        }
        let current_role = current.map(|entry| entry.contents.role);
        let self_escalation = self.actor == self.target
            && self.proposed.state == MembershipState::Active
            && current_role.map_or(true, |role| self.proposed.role > role);
        if self_escalation {
            return Err(invalid(
                "proposed_role",
                "a principal cannot promote itself",
            ));
        }
        let owners_before = self
            .membership_snapshot
            .iter()
            .filter(|entry| is_active_human_owner(&entry.contents))
            .count();
        let owners_after = self
            .membership_snapshot
            .iter()
            .filter(|entry| entry.membership_id != self.membership_id)
            .filter(|entry| is_active_human_owner(&entry.contents))
            .count()
            + usize::from(is_active_human_owner(&self.proposed));
        if owners_before == 0 || owners_after == 0 {
            return Err(invalid(
                "membership_snapshot",
                "an organization must retain at least one human owner",
            ));
        }
        Ok(())
    }
}

fn is_active_human_owner(contents: &MembershipContents) -> bool {
    contents.principal.kind == PrincipalKind::User
        && contents.role == Role::Owner
        && contents.state == MembershipState::Active
}

/// Derives the authoritative membership-index identity for one scope.
///
/// # Errors
///
/// Returns a canonical serialization or stable-identity validation error.
pub(crate) fn membership_index_id(scope: &StableId) -> Result<StableId, ControlError> {
    let digest = ContentDigest::of_value(scope)?;
    StableId::new(format!("membership-index:{}", digest.as_str()))
}

fn actor_authorization_id(
    actor: &PrincipalRef,
    scope: &StableId,
) -> Result<StableId, ControlError> {
    let digest = ContentDigest::of_value(&(actor, scope))?;
    StableId::new(format!("iam-authorization:{}", digest.as_str()))
}

impl MembershipContents {
    /// Validates the typed subject and supported authorization scope.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the principal kind is mismatched
    /// or the scope is not an organization or registry identity.
    pub fn validate(&self) -> Result<(), ControlError> {
        self.principal.validate()?;
        if !matches!(self.scope.kind(), "org" | "registry") {
            return Err(invalid(
                "scope",
                "membership scope must be an organization or registry",
            ));
        }
        if self.role == Role::Owner && self.principal.kind != PrincipalKind::User {
            return Err(invalid("role", "only human users may hold Owner"));
        }
        Ok(())
    }

    /// Derives the stable identity of this principal/scope relationship.
    ///
    /// # Errors
    ///
    /// Returns a canonical serialization or stable-id validation error.
    pub fn stable_id(&self) -> Result<StableId, ControlError> {
        self.validate()?;
        let digest = ContentDigest::of_value(&(&self.principal, &self.scope))?;
        StableId::new(format!("membership:{}", digest.as_str()))
    }

    /// Changes the role of an active membership.
    ///
    /// Last-owner and privilege-ceiling checks require a transaction-wide IAM
    /// snapshot and therefore remain apply gates, not local object checks.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the grant is already revoked.
    pub fn with_role(&self, role: Role) -> Result<Self, ControlError> {
        if self.state != MembershipState::Active {
            return Err(invalid("state", "a revoked membership is immutable"));
        }
        let mut next = self.clone();
        next.role = role;
        Ok(next)
    }

    /// Revokes an active membership.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the grant is already revoked.
    pub fn revoke(&self) -> Result<Self, ControlError> {
        if self.state != MembershipState::Active {
            return Err(invalid("state", "a revoked membership is immutable"));
        }
        let mut next = self.clone();
        next.state = MembershipState::Revoked;
        Ok(next)
    }
}

/// Invitation lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationState {
    /// The invitation may be accepted.
    Pending,
    /// Acceptance created the associated membership.
    Accepted,
    /// An administrator cancelled the invitation.
    Cancelled,
    /// The invitation expired without acceptance.
    Expired,
}

/// Immutable invitation revision contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InvitationContents {
    /// Owning organization scope.
    pub organization_scope: StableId,
    /// Canonical lowercase invited email address.
    pub email: String,
    /// Scope granted on acceptance.
    pub membership_scope: StableId,
    /// Role granted on acceptance.
    pub role: Role,
    /// Unix expiration timestamp.
    pub expires_at: i64,
    /// Invitation lifecycle state.
    pub state: InvitationState,
}

/// One immutable invitation lifecycle revision.
pub type InvitationRevision = Revision<InvitationContents>;

/// Lifecycle state of a captured organization identity domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDomainState {
    /// The domain is captured but has not started verification.
    Captured,
    /// A reviewed operation is checking the exact DNS challenge.
    VerificationPending,
    /// A fenced controller verified the exact DNS challenge.
    Verified,
    /// The organization released the domain while retaining history.
    Released,
}

/// Immutable identity-domain lifecycle contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityDomainContents {
    /// Owning organization stable identity.
    pub organization_scope: StableId,
    /// Canonical lowercase DNS name.
    pub domain: String,
    /// Digest of the exact DNS verification challenge.
    pub challenge_digest: ContentDigest,
    /// Current lifecycle state.
    pub state: IdentityDomainState,
}

/// One immutable identity-domain lifecycle revision.
pub type IdentityDomainRevision = Revision<IdentityDomainContents>;

impl IdentityDomainContents {
    /// Validates the typed owner, canonical DNS name, and lifecycle contents.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for a non-organization owner or a
    /// malformed/non-canonical DNS name.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.organization_scope.kind() != "org" {
            return Err(invalid(
                "organization_scope",
                "identity domains must belong to an organization",
            ));
        }
        validate_dns_name(&self.domain)
    }

    /// Derives the stable identity from immutable organization/domain identity.
    ///
    /// # Errors
    ///
    /// Returns validation, canonical serialization, or stable-id errors.
    pub fn stable_id(&self) -> Result<StableId, ControlError> {
        self.validate()?;
        let digest = ContentDigest::of_value(&(&self.organization_scope, &self.domain))?;
        StableId::new(format!("identity-domain:{}", digest.as_str()))
    }
}

/// Exact desired-state gate for a reviewed identity-domain verification operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityDomainVerificationGate {
    /// Exact identity-domain relationship identity.
    pub domain_id: StableId,
    /// Current immutable domain head sealed by the plan.
    pub expected_head: HeadSeal,
    /// Exact current contents read under the apply transaction.
    pub current: IdentityDomainContents,
    /// Exact pending-verification contents to commit before external work.
    pub proposed: IdentityDomainContents,
    /// Digest of DNS resolver, quorum, and timeout policy sealed by the plan.
    pub verification_policy_digest: ContentDigest,
}

impl IdentityDomainVerificationGate {
    /// Validates the exact reviewed transition before scheduling external DNS work.
    ///
    /// # Errors
    ///
    /// Returns an identity, digest, or transition error unless the current head
    /// and proposed contents describe `captured -> verification_pending` for the
    /// same organization, DNS name, and challenge.
    pub fn validate(&self) -> Result<(), ControlError> {
        self.current.validate()?;
        self.proposed.validate()?;
        if self.domain_id.kind() != "identity-domain"
            || self.current.stable_id()? != self.domain_id
            || self.proposed.stable_id()? != self.domain_id
            || self.expected_head.stable_id != self.domain_id
        {
            return Err(invalid(
                "domain_id",
                "head, current contents, and proposal must name the same domain",
            ));
        }
        if self.expected_head.content_digest != ContentDigest::of_value(&self.current)? {
            return Err(ControlError::DigestMismatch);
        }
        if self.current.organization_scope != self.proposed.organization_scope
            || self.current.domain != self.proposed.domain
            || self.current.challenge_digest != self.proposed.challenge_digest
            || self.current.state != IdentityDomainState::Captured
            || self.proposed.state != IdentityDomainState::VerificationPending
        {
            return Err(invalid(
                "proposed",
                "verification must preserve identity and challenge while entering pending state",
            ));
        }
        Ok(())
    }
}

impl InvitationContents {
    /// Validates an invitation at creation time.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless the email is canonical, expiry
    /// is in the future, and the initial state is pending.
    pub fn validate_new(&self, now: i64) -> Result<(), ControlError> {
        if self.organization_scope.kind() != "org"
            || !matches!(self.membership_scope.kind(), "org" | "registry")
            || (self.role == Role::Owner && self.membership_scope.kind() != "org")
        {
            return Err(invalid(
                "invitation_scope",
                "invitation owner, membership scope, and role must be compatible",
            ));
        }
        validate_email_address(&self.email)?;
        let lifetime = self.expires_at.checked_sub(now);
        if !matches!(lifetime, Some(seconds) if seconds > 0 && seconds <= 30 * 24 * 60 * 60) {
            return Err(invalid(
                "expires_at",
                "must be within thirty days after issuance",
            ));
        }
        if self.state != InvitationState::Pending {
            return Err(invalid("state", "new invitations must be pending"));
        }
        Ok(())
    }

    /// Transitions a pending invitation to a terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for a non-pending source or a pending
    /// destination.
    pub fn finish(&self, state: InvitationState) -> Result<Self, ControlError> {
        if self.state != InvitationState::Pending || state == InvitationState::Pending {
            return Err(invalid(
                "state",
                "only a pending invitation may enter a terminal state",
            ));
        }
        let mut next = self.clone();
        next.state = state;
        Ok(next)
    }
}

/// Token lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenState {
    /// The token credential may authenticate.
    Active,
    /// The token credential is permanently revoked.
    Revoked,
}

/// Immutable token credential-generation contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenCredentialContents {
    /// Principal that owns the credential.
    pub(super) owner: PrincipalRef,
    /// Maximum authorization scope.
    pub(super) scope: StableId,
    /// Strictly sorted, duplicate-free permission verbs.
    pub(super) permissions: Vec<String>,
    /// SHA-256 fingerprint of the credential; never the token or its verifier hash.
    pub(super) credential_fingerprint: ContentDigest,
    /// Optional Unix expiration timestamp.
    pub(super) expires_at: Option<i64>,
    /// Credential lifecycle state.
    pub(super) state: TokenState,
}

/// One immutable token credential generation.
pub type TokenCredentialRevision = Revision<TokenCredentialContents>;

impl TokenCredentialContents {
    /// Creates a new active token generation from secret-free metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an invalid owner, scope,
    /// permission set, or expiration.
    pub fn new(
        owner: PrincipalRef,
        scope: StableId,
        permissions: Vec<String>,
        credential_fingerprint: ContentDigest,
        expires_at: Option<i64>,
        issued_at: i64,
    ) -> Result<Self, ControlError> {
        let credential = Self {
            owner,
            scope,
            permissions,
            credential_fingerprint,
            expires_at,
            state: TokenState::Active,
        };
        credential.validate_new(issued_at)?;
        Ok(credential)
    }

    /// Validates token metadata without accepting secret material.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an empty, duplicate, unordered, or
    /// malformed permission list, or an expiration not after issuance.
    pub fn validate_new(&self, issued_at: i64) -> Result<(), ControlError> {
        self.validate_common()?;
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= issued_at)
        {
            return Err(invalid("expires_at", "must be after issuance"));
        }
        if self.state != TokenState::Active {
            return Err(invalid("state", "new token credentials must be active"));
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), ControlError> {
        self.owner.validate()?;
        if !matches!(self.scope.kind(), "org" | "registry") {
            return Err(invalid(
                "scope",
                "token scope must be an organization or registry",
            ));
        }
        if self.permissions.is_empty()
            || self.permissions.len() > 128
            || self.permissions.windows(2).any(|pair| pair[0] >= pair[1])
            || !canonical_permissions(&self.permissions)
            || self.permissions.iter().any(|permission| {
                role_permissions(self.scope.kind(), Role::Owner)
                    .binary_search(&permission.as_str())
                    .is_err()
            })
        {
            return Err(invalid(
                "permissions",
                "must be a non-empty canonical subset of the scope permission vocabulary",
            ));
        }
        Ok(())
    }

    /// Revokes an active credential generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when already revoked.
    pub fn revoke(&self) -> Result<Self, ControlError> {
        self.validate_common()?;
        if self.state != TokenState::Active {
            return Err(invalid("state", "a revoked token is immutable"));
        }
        let mut next = self.clone();
        next.state = TokenState::Revoked;
        Ok(next)
    }
}

/// Authorization snapshot sealed before minting or rotating a token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenPermissionGate {
    /// Exact token identity being created or rotated.
    pub credential_id: StableId,
    /// Current credential head, absent only when minting a new token.
    pub expected_head: Option<HeadSeal>,
    /// Exact current credential contents, absent only for first mint.
    pub current: Option<TokenCredentialContents>,
    /// Exact owner whose authority is being delegated.
    pub owner: PrincipalRef,
    /// Exact authorization scope being delegated.
    pub scope: StableId,
    /// Exact proposed token credential contents.
    pub proposed: TokenCredentialContents,
    /// Unix timestamp used to validate the proposed credential lifetime.
    pub issued_at: i64,
    /// Complete current scope membership snapshot from which authority is derived.
    pub membership_snapshot: Vec<MembershipSnapshotEntry>,
    /// Digest of the complete current scope membership snapshot.
    pub membership_snapshot_digest: ContentDigest,
    /// Authoritative current head of the scope's complete membership index.
    pub scope_membership_head: HeadSeal,
}

impl TokenPermissionGate {
    /// Ensures the token cannot exceed its owner's current authority.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when either permission list is not
    /// strictly sorted and duplicate-free, the request is empty, or a requested
    /// permission is absent from the owner's effective permissions.
    pub fn validate(&self) -> Result<(), ControlError> {
        self.owner.validate()?;
        self.proposed.validate_new(self.issued_at)?;
        if self.credential_id.kind() != "token"
            || self
                .expected_head
                .as_ref()
                .is_some_and(|head| head.stable_id != self.credential_id)
        {
            return Err(invalid(
                "credential_id",
                "credential and current-head identities must name the same token",
            ));
        }
        match (&self.expected_head, &self.current) {
            (None, None) => {}
            (Some(head), Some(current)) => {
                current.validate_common()?;
                if head.content_digest != ContentDigest::of_value(current)?
                    || current.state != TokenState::Active
                    || current.owner != self.owner
                    || current.scope != self.scope
                    || current.credential_fingerprint == self.proposed.credential_fingerprint
                {
                    return Err(invalid(
                        "current",
                        "rotation must bind the exact active current credential and mint a distinct generation",
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    "current",
                    "current contents and expected head must both be present only for rotation",
                ));
            }
        }
        if self.proposed.owner != self.owner || self.proposed.scope != self.scope {
            return Err(invalid(
                "proposed",
                "proposed credential must match the sealed owner and scope",
            ));
        }
        if self.membership_snapshot.len() > 4_096
            || self
                .membership_snapshot
                .windows(2)
                .any(|pair| pair[0].membership_id >= pair[1].membership_id)
        {
            return Err(invalid(
                "membership_snapshot",
                "must be bounded, strictly ordered, and duplicate-free",
            ));
        }
        for entry in &self.membership_snapshot {
            entry.validate()?;
            if entry.contents.scope != self.scope {
                return Err(invalid(
                    "membership_snapshot",
                    "every retained grant must name the exact token scope",
                ));
            }
        }
        if ContentDigest::of_value(&self.membership_snapshot)? != self.membership_snapshot_digest {
            return Err(ControlError::DigestMismatch);
        }
        if self.scope_membership_head.stable_id != membership_index_id(&self.scope)?
            || self.scope_membership_head.content_digest != self.membership_snapshot_digest
        {
            return Err(invalid(
                "scope_membership_head",
                "must be the authoritative head of the exact scope snapshot",
            ));
        }
        let owner_role = self
            .membership_snapshot
            .iter()
            .filter(|entry| {
                entry.contents.principal == self.owner
                    && entry.contents.state == MembershipState::Active
            })
            .map(|entry| entry.contents.role)
            .max()
            .ok_or_else(|| invalid("owner", "token owner has no active grant at the scope"))?;
        let owner_effective_permissions = role_permissions(self.scope.kind(), owner_role);
        if self.proposed.permissions.iter().any(|requested| {
            owner_effective_permissions
                .binary_search(&requested.as_str())
                .is_err()
        }) {
            return Err(invalid(
                "permissions",
                "token permissions must be a subset of owner authority",
            ));
        }
        Ok(())
    }
}

fn role_permissions(scope_kind: &str, role: Role) -> &'static [&'static str] {
    match (scope_kind, role) {
        ("org", Role::Viewer) => &["org.read"],
        ("org", Role::Developer) => &["org.project.write", "org.read"],
        ("org", Role::Maintainer) => &["org.manage", "org.project.write", "org.read"],
        ("org", Role::Admin) => &[
            "org.iam.manage",
            "org.manage",
            "org.project.write",
            "org.read",
        ],
        ("org", Role::Owner) => &[
            "org.iam.manage",
            "org.manage",
            "org.owner",
            "org.project.write",
            "org.read",
        ],
        ("registry", Role::Viewer) => &["registry.read"],
        ("registry", Role::Developer) => &["registry.publish", "registry.read"],
        ("registry", Role::Maintainer) => &["registry.manage", "registry.publish", "registry.read"],
        ("registry", Role::Admin) => &[
            "registry.admin",
            "registry.manage",
            "registry.publish",
            "registry.read",
        ],
        ("registry", Role::Owner) => &[
            "registry.admin",
            "registry.manage",
            "registry.owner",
            "registry.publish",
            "registry.read",
        ],
        _ => &[],
    }
}

/// A one-time secret response that redacts itself from debug output.
#[must_use = "token secrets must be deliberately delivered exactly once"]
pub struct SecretDisclosure(zeroize::Zeroizing<String>);

impl SecretDisclosure {
    /// Wraps a freshly generated secret for one-time delivery.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an empty or oversized secret.
    pub fn new(secret: impl Into<String>) -> Result<Self, ControlError> {
        let secret = secret.into();
        if secret.is_empty() || secret.len() > 4096 {
            return Err(invalid("secret", "must contain 1-4096 bytes"));
        }
        Ok(Self(zeroize::Zeroizing::new(secret)))
    }

    /// Consumes the wrapper and returns the secret for its single response.
    #[must_use]
    pub fn expose_once(self) -> zeroize::Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for SecretDisclosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretDisclosure([REDACTED])")
    }
}

fn validate_slug(field: &'static str, value: &str) -> Result<(), ControlError> {
    if !canonical::is_slug(value, 64) {
        return Err(invalid(field, "must be a canonical lowercase slug"));
    }
    Ok(())
}

fn canonical_permissions(permissions: &[String]) -> bool {
    permissions.windows(2).all(|pair| pair[0] < pair[1])
        && permissions
            .iter()
            .all(|permission| canonical::is_permission(permission))
}

/// Validates one canonical lowercase IDNA A-label DNS name.
///
/// # Errors
///
/// Returns [`ControlError::Invalid`] for a non-canonical hostname, IP address,
/// explicit trailing root label, or unconverted Unicode IDNA input.
pub(crate) fn validate_dns_name(value: &str) -> Result<(), ControlError> {
    if canonical::is_dns_name(value) {
        Ok(())
    } else {
        Err(invalid(
            "domain",
            "must be a canonical lowercase ASCII DNS name, not an IP address",
        ))
    }
}

fn validate_email_address(value: &str) -> Result<(), ControlError> {
    if value.len() > 254 || value.trim() != value || value != value.to_ascii_lowercase() {
        return Err(invalid(
            "email",
            "must be a canonical lowercase email address",
        ));
    }
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"!#$%&'*+-/=?^_`{|}~.".contains(&byte)
        })
    {
        return Err(invalid("email", "must use canonical dot-atom syntax"));
    }
    validate_dns_name(domain).map_err(|_| invalid("email", "must contain a valid DNS domain"))
}

fn invalid(field: &'static str, reason: &str) -> ControlError {
    ControlError::Invalid {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::primitives::{Generation, ResourceVersion};
    use super::*;

    fn principal() -> PrincipalRef {
        PrincipalRef {
            kind: PrincipalKind::User,
            stable_id: StableId::new("user:alice").unwrap(),
        }
    }

    fn named_principal(name: &str) -> PrincipalRef {
        PrincipalRef::new(
            PrincipalKind::User,
            StableId::new(format!("user:{name}")).unwrap(),
        )
        .unwrap()
    }

    fn membership_entry(contents: MembershipContents) -> MembershipSnapshotEntry {
        let membership_id = contents.stable_id().unwrap();
        MembershipSnapshotEntry {
            head: HeadSeal {
                stable_id: membership_id.clone(),
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_value(&contents).unwrap(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            membership_id,
            contents,
        }
    }

    fn snapshot_digest(entries: &[MembershipSnapshotEntry]) -> ContentDigest {
        ContentDigest::of_value(entries).unwrap()
    }

    fn membership_index_head(scope: &StableId, entries: &[MembershipSnapshotEntry]) -> HeadSeal {
        HeadSeal {
            stable_id: membership_index_id(scope).unwrap(),
            generation: Generation::new(1).unwrap(),
            content_digest: snapshot_digest(entries),
            resource_version: ResourceVersion::new(1).unwrap(),
        }
    }

    fn actor_authorization(
        actor: &PrincipalRef,
        scope: &StableId,
        entries: &[MembershipSnapshotEntry],
    ) -> ActorAuthorizationSnapshot {
        let actor_entry = entries
            .iter()
            .find(|entry| entry.contents.principal == *actor)
            .unwrap();
        let capabilities = if actor_entry.contents.role >= Role::Admin {
            vec![IamCapability::ManageMemberships]
        } else {
            Vec::new()
        };
        let scope_head = membership_index_head(scope, entries);
        let mut snapshot = ActorAuthorizationSnapshot {
            actor: actor.clone(),
            scope: scope.clone(),
            actor_membership_head: actor_entry.head.clone(),
            capabilities,
            target_role_ceiling: actor_entry.contents.role,
            authorization_head: HeadSeal {
                stable_id: actor_authorization_id(actor, scope).unwrap(),
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_bytes("pending-authorization"),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
        };
        snapshot.authorization_head.content_digest = ContentDigest::of_value(&(
            &snapshot.actor,
            &snapshot.scope,
            &snapshot.actor_membership_head,
            &snapshot.capabilities,
            snapshot.target_role_ceiling,
            &scope_head,
        ))
        .unwrap();
        snapshot
    }

    #[test]
    fn membership_identity_is_relationship_identity() {
        let first = MembershipContents {
            principal: principal(),
            scope: StableId::new("org:acme").unwrap(),
            role: Role::Viewer,
            state: MembershipState::Active,
        };
        let changed = first.with_role(Role::Admin).unwrap();
        assert_eq!(first.stable_id().unwrap(), changed.stable_id().unwrap());
    }

    #[test]
    fn invitation_is_not_a_membership_until_acceptance() {
        let invitation = InvitationContents {
            organization_scope: StableId::new("org:acme").unwrap(),
            email: "new@example.test".into(),
            membership_scope: StableId::new("org:acme").unwrap(),
            role: Role::Viewer,
            expires_at: 100,
            state: InvitationState::Pending,
        };
        invitation.validate_new(1).unwrap();
        assert_eq!(
            invitation.finish(InvitationState::Accepted).unwrap().state,
            InvitationState::Accepted
        );
    }

    #[test]
    fn token_secret_is_not_debuggable_or_serializable() {
        let disclosure = SecretDisclosure::new("sensitive-token").unwrap();
        assert_eq!(format!("{disclosure:?}"), "SecretDisclosure([REDACTED])");
        assert_eq!(disclosure.expose_once().as_str(), "sensitive-token");
    }

    #[test]
    fn membership_gate_rejects_last_owner_and_self_escalation() {
        let scope = StableId::new("org:acme").unwrap();
        let current = membership_entry(MembershipContents {
            principal: principal(),
            scope: scope.clone(),
            role: Role::Viewer,
            state: MembershipState::Active,
        });
        let owner = named_principal("owner");
        let owner_entry = membership_entry(MembershipContents {
            principal: owner,
            scope: scope.clone(),
            role: Role::Owner,
            state: MembershipState::Active,
        });
        let mut membership_snapshot = vec![current.clone(), owner_entry];
        membership_snapshot.sort_by(|left, right| left.membership_id.cmp(&right.membership_id));
        let proposed = MembershipContents {
            role: Role::Admin,
            ..current.contents.clone()
        };
        let gate = MembershipApplyGate {
            actor: principal(),
            scope: scope.clone(),
            target: principal(),
            membership_id: proposed.stable_id().unwrap(),
            expected_head: Some(current.head.clone()),
            proposed,
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(&scope, &membership_snapshot),
            actor_authorization: actor_authorization(&principal(), &scope, &membership_snapshot),
            membership_snapshot,
        };
        assert!(gate.validate().is_err());

        let last_owner_principal = named_principal("last-owner");
        let last_owner_entry = membership_entry(MembershipContents {
            principal: last_owner_principal.clone(),
            scope: scope.clone(),
            role: Role::Owner,
            state: MembershipState::Active,
        });
        let membership_snapshot = vec![last_owner_entry.clone()];
        let last_owner = MembershipApplyGate {
            actor: last_owner_principal.clone(),
            scope: scope.clone(),
            target: last_owner_principal.clone(),
            membership_id: last_owner_entry.membership_id.clone(),
            expected_head: Some(last_owner_entry.head),
            proposed: MembershipContents {
                state: MembershipState::Revoked,
                ..last_owner_entry.contents
            },
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(&scope, &membership_snapshot),
            actor_authorization: actor_authorization(
                &last_owner_principal,
                &scope,
                &membership_snapshot,
            ),
            membership_snapshot,
        };
        assert!(last_owner.validate().is_err());
    }

    #[test]
    fn token_permissions_are_bounded_by_owner_authority() {
        let proposed = TokenCredentialContents {
            owner: principal(),
            scope: StableId::new("registry:main").unwrap(),
            permissions: vec!["registry.publish".into(), "registry.read".into()],
            credential_fingerprint: ContentDigest::of_bytes("token"),
            expires_at: Some(100),
            state: TokenState::Active,
        };
        let owner_grant = membership_entry(MembershipContents {
            principal: principal(),
            scope: StableId::new("registry:main").unwrap(),
            role: Role::Developer,
            state: MembershipState::Active,
        });
        let membership_snapshot = vec![owner_grant];
        let gate = TokenPermissionGate {
            credential_id: StableId::new("token:one").unwrap(),
            expected_head: None,
            current: None,
            owner: principal(),
            scope: StableId::new("registry:main").unwrap(),
            proposed,
            issued_at: 1,
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(
                &StableId::new("registry:main").unwrap(),
                &membership_snapshot,
            ),
            membership_snapshot,
        };
        gate.validate().unwrap();
        let mut denied = gate;
        denied.proposed.permissions = vec!["registry.admin".into()];
        assert!(denied.validate().is_err());
    }

    #[test]
    fn apply_gates_reject_subject_scope_and_proposal_substitution() {
        let proposed_membership = MembershipContents {
            principal: principal(),
            scope: StableId::new("org:acme").unwrap(),
            role: Role::Viewer,
            state: MembershipState::Active,
        };
        let actor = named_principal("admin");
        let actor_entry = membership_entry(MembershipContents {
            principal: actor.clone(),
            scope: StableId::new("org:acme").unwrap(),
            role: Role::Owner,
            state: MembershipState::Active,
        });
        let membership_snapshot = vec![actor_entry];
        let mut membership_gate = MembershipApplyGate {
            actor: actor.clone(),
            scope: StableId::new("org:acme").unwrap(),
            target: principal(),
            membership_id: proposed_membership.stable_id().unwrap(),
            expected_head: None,
            proposed: proposed_membership,
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(
                &StableId::new("org:acme").unwrap(),
                &membership_snapshot,
            ),
            actor_authorization: actor_authorization(
                &actor,
                &StableId::new("org:acme").unwrap(),
                &membership_snapshot,
            ),
            membership_snapshot,
        };
        membership_gate.proposed.scope = StableId::new("org:other").unwrap();
        assert!(membership_gate.validate().is_err());

        let proposed_token = TokenCredentialContents {
            owner: principal(),
            scope: StableId::new("registry:main").unwrap(),
            permissions: vec!["registry.read".into()],
            credential_fingerprint: ContentDigest::of_bytes("credential"),
            expires_at: Some(100),
            state: TokenState::Active,
        };
        let membership_snapshot = vec![membership_entry(MembershipContents {
            principal: principal(),
            scope: StableId::new("registry:main").unwrap(),
            role: Role::Viewer,
            state: MembershipState::Active,
        })];
        let mut token_gate = TokenPermissionGate {
            credential_id: StableId::new("token:one").unwrap(),
            expected_head: None,
            current: None,
            owner: principal(),
            scope: StableId::new("registry:main").unwrap(),
            proposed: proposed_token,
            issued_at: 1,
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(
                &StableId::new("registry:main").unwrap(),
                &membership_snapshot,
            ),
            membership_snapshot,
        };
        token_gate.proposed.owner = PrincipalRef {
            kind: PrincipalKind::User,
            stable_id: StableId::new("user:other").unwrap(),
        };
        assert!(token_gate.validate().is_err());
    }

    #[test]
    fn iam_snapshots_reject_head_digest_and_authority_substitution() {
        let scope = StableId::new("org:acme").unwrap();
        let actor = named_principal("owner");
        let target = principal();
        let actor_entry = membership_entry(MembershipContents {
            principal: actor.clone(),
            scope: scope.clone(),
            role: Role::Owner,
            state: MembershipState::Active,
        });
        let target_entry = membership_entry(MembershipContents {
            principal: target.clone(),
            scope: scope.clone(),
            role: Role::Viewer,
            state: MembershipState::Active,
        });
        let mut membership_snapshot = vec![actor_entry, target_entry.clone()];
        membership_snapshot.sort_by(|left, right| left.membership_id.cmp(&right.membership_id));
        let make_gate = || MembershipApplyGate {
            actor: actor.clone(),
            scope: scope.clone(),
            target: target.clone(),
            membership_id: target_entry.membership_id.clone(),
            expected_head: Some(target_entry.head.clone()),
            proposed: MembershipContents {
                role: Role::Developer,
                ..target_entry.contents.clone()
            },
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(&scope, &membership_snapshot),
            actor_authorization: actor_authorization(&actor, &scope, &membership_snapshot),
            membership_snapshot: membership_snapshot.clone(),
        };
        make_gate().validate().unwrap();

        let mut stale_head = make_gate();
        stale_head.expected_head.as_mut().unwrap().resource_version =
            ResourceVersion::new(2).unwrap();
        assert!(stale_head.validate().is_err());

        let mut forged_contents = make_gate();
        let actor_index = forged_contents
            .membership_snapshot
            .iter()
            .position(|entry| entry.contents.principal == actor)
            .unwrap();
        forged_contents.membership_snapshot[actor_index]
            .contents
            .role = Role::Viewer;
        forged_contents.membership_snapshot_digest =
            snapshot_digest(&forged_contents.membership_snapshot);
        assert!(forged_contents.validate().is_err());

        let proposed = TokenCredentialContents {
            owner: target.clone(),
            scope: StableId::new("registry:main").unwrap(),
            permissions: vec!["registry.publish".into(), "registry.read".into()],
            credential_fingerprint: ContentDigest::of_bytes("credential"),
            expires_at: Some(100),
            state: TokenState::Active,
        };
        let membership_snapshot = vec![membership_entry(MembershipContents {
            principal: target.clone(),
            scope: StableId::new("registry:main").unwrap(),
            role: Role::Developer,
            state: MembershipState::Active,
        })];
        let mut token_gate = TokenPermissionGate {
            credential_id: StableId::new("token:one").unwrap(),
            expected_head: None,
            current: None,
            owner: target,
            scope: StableId::new("registry:main").unwrap(),
            proposed,
            issued_at: 1,
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(
                &StableId::new("registry:main").unwrap(),
                &membership_snapshot,
            ),
            membership_snapshot,
        };
        token_gate.validate().unwrap();
        token_gate.membership_snapshot[0].contents.role = Role::Viewer;
        token_gate.membership_snapshot_digest = snapshot_digest(&token_gate.membership_snapshot);
        assert!(token_gate.validate().is_err());
    }

    #[test]
    fn membership_authority_is_capability_exact_and_owner_changes_are_owner_only() {
        let scope = StableId::new("org:acme").unwrap();
        let actor = named_principal("admin");
        let target = principal();
        let actor_entry = membership_entry(MembershipContents {
            principal: actor.clone(),
            scope: scope.clone(),
            role: Role::Admin,
            state: MembershipState::Active,
        });
        let target_entry = membership_entry(MembershipContents {
            principal: target.clone(),
            scope: scope.clone(),
            role: Role::Viewer,
            state: MembershipState::Active,
        });
        let owner_entry = membership_entry(MembershipContents {
            principal: named_principal("owner"),
            scope: scope.clone(),
            role: Role::Owner,
            state: MembershipState::Active,
        });
        let second_owner_entry = membership_entry(MembershipContents {
            principal: named_principal("second-owner"),
            scope: scope.clone(),
            role: Role::Owner,
            state: MembershipState::Active,
        });
        let mut membership_snapshot = vec![
            actor_entry,
            target_entry.clone(),
            owner_entry,
            second_owner_entry,
        ];
        membership_snapshot.sort_by(|left, right| left.membership_id.cmp(&right.membership_id));
        let mut gate = MembershipApplyGate {
            actor: actor.clone(),
            scope: scope.clone(),
            target,
            membership_id: target_entry.membership_id.clone(),
            expected_head: Some(target_entry.head.clone()),
            proposed: MembershipContents {
                role: Role::Developer,
                ..target_entry.contents
            },
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(&scope, &membership_snapshot),
            actor_authorization: actor_authorization(&actor, &scope, &membership_snapshot),
            membership_snapshot,
        };
        gate.validate().unwrap();

        gate.actor_authorization.capabilities.clear();
        let authorization_contents = (
            &gate.actor_authorization.actor,
            &gate.actor_authorization.scope,
            &gate.actor_authorization.actor_membership_head,
            &gate.actor_authorization.capabilities,
            gate.actor_authorization.target_role_ceiling,
            &gate.scope_membership_head,
        );
        gate.actor_authorization.authorization_head.content_digest =
            ContentDigest::of_value(&authorization_contents).unwrap();
        assert!(gate.validate().is_err());

        let owner_target = gate
            .membership_snapshot
            .iter()
            .find(|entry| entry.contents.role == Role::Owner)
            .unwrap()
            .clone();
        let mut owner_change = MembershipApplyGate {
            actor: actor.clone(),
            scope: scope.clone(),
            target: owner_target.contents.principal.clone(),
            membership_id: owner_target.membership_id.clone(),
            expected_head: Some(owner_target.head),
            proposed: MembershipContents {
                role: Role::Owner,
                state: MembershipState::Revoked,
                ..owner_target.contents
            },
            membership_snapshot_digest: snapshot_digest(&gate.membership_snapshot),
            scope_membership_head: membership_index_head(&scope, &gate.membership_snapshot),
            actor_authorization: actor_authorization(&actor, &scope, &gate.membership_snapshot),
            membership_snapshot: gate.membership_snapshot,
        };
        assert!(owner_change.validate().is_err());
        owner_change.proposed.role = Role::Admin;
        owner_change.proposed.state = MembershipState::Active;
        assert!(owner_change.validate().is_err());
    }

    #[test]
    fn token_rotation_binds_exact_active_current_contents() {
        let scope = StableId::new("registry:main").unwrap();
        let owner = principal();
        let membership_snapshot = vec![membership_entry(MembershipContents {
            principal: owner.clone(),
            scope: scope.clone(),
            role: Role::Developer,
            state: MembershipState::Active,
        })];
        let current = TokenCredentialContents {
            owner: owner.clone(),
            scope: scope.clone(),
            permissions: vec!["registry.publish".into(), "registry.read".into()],
            credential_fingerprint: ContentDigest::of_bytes("old-credential"),
            expires_at: Some(90),
            state: TokenState::Active,
        };
        let credential_id = StableId::new("token:one").unwrap();
        let expected_head = HeadSeal {
            stable_id: credential_id.clone(),
            generation: Generation::new(1).unwrap(),
            content_digest: ContentDigest::of_value(&current).unwrap(),
            resource_version: ResourceVersion::new(1).unwrap(),
        };
        let mut gate = TokenPermissionGate {
            credential_id,
            expected_head: Some(expected_head),
            current: Some(current),
            owner,
            scope: scope.clone(),
            proposed: TokenCredentialContents {
                owner: principal(),
                scope: scope.clone(),
                permissions: vec!["registry.read".into()],
                credential_fingerprint: ContentDigest::of_bytes("new-credential"),
                expires_at: Some(100),
                state: TokenState::Active,
            },
            issued_at: 1,
            membership_snapshot_digest: snapshot_digest(&membership_snapshot),
            scope_membership_head: membership_index_head(&scope, &membership_snapshot),
            membership_snapshot,
        };
        gate.validate().unwrap();

        gate.current.as_mut().unwrap().state = TokenState::Revoked;
        gate.expected_head.as_mut().unwrap().content_digest =
            ContentDigest::of_value(gate.current.as_ref().unwrap()).unwrap();
        assert!(gate.validate().is_err());
    }

    #[test]
    fn typed_principals_and_real_email_domains_fail_closed() {
        let mismatched = PrincipalRef {
            kind: PrincipalKind::User,
            stable_id: StableId::new("service-account:robot").unwrap(),
        };
        assert!(mismatched.validate().is_err());
        assert!(serde_json::from_str::<PrincipalRef>(
            r#"{"kind":"user","stable_id":"service-account:robot"}"#
        )
        .is_err());

        for email in [
            "missing-at.example.test",
            "a@localhost",
            "a@127.0.0.1",
            "a..b@example.test",
        ] {
            let invitation = InvitationContents {
                organization_scope: StableId::new("org:acme").unwrap(),
                email: email.into(),
                membership_scope: StableId::new("org:acme").unwrap(),
                role: Role::Viewer,
                expires_at: 100,
                state: InvitationState::Pending,
            };
            assert!(invitation.validate_new(1).is_err(), "accepted {email}");
        }
    }

    #[test]
    fn identity_domain_verification_is_an_exact_reviewed_transition() {
        let current = IdentityDomainContents {
            organization_scope: StableId::new("org:acme").unwrap(),
            domain: "example.test".into(),
            challenge_digest: ContentDigest::of_bytes("challenge"),
            state: IdentityDomainState::Captured,
        };
        let domain_id = current.stable_id().unwrap();
        let proposed = IdentityDomainContents {
            state: IdentityDomainState::VerificationPending,
            ..current.clone()
        };
        let gate = IdentityDomainVerificationGate {
            domain_id: domain_id.clone(),
            expected_head: HeadSeal {
                stable_id: domain_id,
                generation: super::super::primitives::Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_value(&current).unwrap(),
                resource_version: super::super::primitives::ResourceVersion::new(1).unwrap(),
            },
            current,
            proposed,
            verification_policy_digest: ContentDigest::of_bytes("dns-policy"),
        };
        gate.validate().unwrap();

        let mut substituted = gate;
        substituted.proposed.challenge_digest = ContentDigest::of_bytes("other-challenge");
        assert!(substituted.validate().is_err());
    }
}
