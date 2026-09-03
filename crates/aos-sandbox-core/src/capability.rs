//! Controller-resolved, channel-bound capability records and attenuation.
//!
//! These records are not offline bearer tokens. The online controller looks
//! them up by unpredictable handle, authenticates the holder channel, checks
//! current revocation state, and evaluates a closed grant set. Descendant
//! issuance creates a new record whose authority is provably no broader than
//! a delegable parent grant.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::selector::{ObjectDigest, Operation, OperationSet, ResourceKind, Selector};
use crate::{
    AssignmentEpoch, AuditId, CapabilityId, GrantId, IncarnationId, PrincipalId, ProjectId,
    ResourceVector, Revision, RevocationScopeId, SandboxId,
};

const MAX_GRANTS: usize = 1_024;

/// Binds a capability record to one authenticated transport or local channel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ChannelBinding(ObjectDigest);

impl ChannelBinding {
    /// Constructs a binding from the transport's domain-separated 32-byte hash.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(ObjectDigest::from_bytes(bytes))
    }

    /// Returns the exact binding hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Defines one normalized allowlist grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Grant {
    id: GrantId,
    resource_kind: ResourceKind,
    operations: OperationSet,
    selector: Selector,
    delegable: bool,
}

impl Grant {
    /// Constructs a nonempty grant.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidGrant::EmptyOperations`] when no operation is allowed.
    pub fn new(
        id: GrantId,
        resource_kind: ResourceKind,
        operations: OperationSet,
        selector: Selector,
        delegable: bool,
    ) -> Result<Self, InvalidGrant> {
        if operations.is_empty() {
            Err(InvalidGrant::EmptyOperations)
        } else {
            Ok(Self {
                id,
                resource_kind,
                operations,
                selector,
                delegable,
            })
        }
    }

    /// Returns the stable grant identity.
    #[must_use]
    pub const fn id(&self) -> GrantId {
        self.id
    }

    /// Returns the closed resource kind.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Returns the allowed operation set.
    #[must_use]
    pub const fn operations(&self) -> OperationSet {
        self.operations
    }

    /// Returns the immutable logical selector.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Reports whether the controller may derive a narrower grant from this one.
    #[must_use]
    pub const fn delegable(&self) -> bool {
        self.delegable
    }

    fn covers(&self, child: &Self) -> bool {
        self.delegable
            && self.resource_kind == child.resource_kind
            && child.operations.is_subset_of(self.operations)
            && self.selector.contains(&child.selector)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantWire {
    id: GrantId,
    resource_kind: ResourceKind,
    operations: OperationSet,
    selector: Selector,
    delegable: bool,
}

impl<'de> Deserialize<'de> for Grant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = GrantWire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.resource_kind,
            wire.operations,
            wire.selector,
            wire.delegable,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Reports a malformed normalized grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidGrant {
    /// An empty bitmap would never authorize a request and is noncanonical.
    #[error("capability grant operation set must not be empty")]
    EmptyOperations,
}

/// Caps further delegation independently from individual grants.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLimits {
    remaining_depth: u32,
    maximum_fanout: u32,
    resources: ResourceVector,
}

impl DelegationLimits {
    /// Constructs explicit delegation ceilings.
    #[must_use]
    pub const fn new(remaining_depth: u32, maximum_fanout: u32, resources: ResourceVector) -> Self {
        Self {
            remaining_depth,
            maximum_fanout,
            resources,
        }
    }

    /// Returns the number of additional delegation edges permitted.
    #[must_use]
    pub const fn remaining_depth(self) -> u32 {
        self.remaining_depth
    }

    /// Returns the maximum direct child capability count.
    #[must_use]
    pub const fn maximum_fanout(self) -> u32 {
        self.maximum_fanout
    }

    /// Returns the maximum resource envelope that may be carved for descendants.
    #[must_use]
    pub const fn resources(self) -> ResourceVector {
        self.resources
    }
}

/// Supplies fully resolved fields for controller capability issuance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDraft {
    /// New unpredictable record identity.
    pub id: CapabilityId,
    /// Authenticated principal authorizing issuance.
    pub issuer: PrincipalId,
    /// Service principal at which the record is valid.
    pub audience: PrincipalId,
    /// Authenticated principal permitted to exercise the record.
    pub holder: PrincipalId,
    /// Proof-of-possession channel binding for the holder.
    pub channel_binding: ChannelBinding,
    /// Original authenticated authority root retained through delegation.
    pub root_subject: PrincipalId,
    /// Project authority domain.
    pub project: ProjectId,
    /// Runtime-bound sandbox, absent only for project/pre-creation authority.
    pub sandbox: Option<SandboxId>,
    /// Runtime incarnation paired with `sandbox` when authority is incarnation-bound.
    pub incarnation: Option<IncarnationId>,
    /// Closed normalized allowlist grants.
    pub grants: Vec<Grant>,
    /// Effective immutable policy digest.
    pub policy_digest: ObjectDigest,
    /// Node assignment fence for placement-specific authority.
    pub assignment_epoch: Option<AssignmentEpoch>,
    /// Inclusive Unix second at which use begins.
    pub not_before: i64,
    /// Exclusive Unix second at which new use ends.
    pub expires_at: i64,
    /// Revocation namespace queried on every use.
    pub revocation_scope: RevocationScopeId,
    /// Exact revocation generation accepted at issuance.
    pub revocation_generation: Revision,
    /// Aggregate delegation ceilings.
    pub delegation: DelegationLimits,
    /// Durable decision that produced this record.
    pub parent_decision: AuditId,
}

/// Stores one validated online capability record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CapabilityRecord {
    draft: CapabilityDraft,
}

impl CapabilityRecord {
    /// Validates and issues a controller-resolved record.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityValidationError`] for an invalid time interval,
    /// partially bound runtime scope, empty or oversized grant set, duplicate
    /// grant identity, or delegable authority with no remaining depth.
    pub fn issue(draft: CapabilityDraft) -> Result<Self, CapabilityValidationError> {
        validate_draft(&draft)?;
        Ok(Self { draft })
    }

    /// Returns the capability handle identity.
    #[must_use]
    pub const fn id(&self) -> CapabilityId {
        self.draft.id
    }

    /// Returns the complete validated resolved claims.
    #[must_use]
    pub const fn claims(&self) -> &CapabilityDraft {
        &self.draft
    }

    /// Authorizes one operation after validating all dynamic bindings.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError`] on time, holder, channel, audience,
    /// project, runtime, assignment, or revocation mismatch, or when no grant
    /// includes the requested kind, operation, and selector.
    pub fn authorize(
        &self,
        context: &AuthorizationContext,
        resource_kind: ResourceKind,
        operation: Operation,
        selector: &Selector,
    ) -> Result<(), AuthorizationError> {
        validate_context(&self.draft, context)?;

        if self.draft.grants.iter().any(|grant| {
            grant.resource_kind == resource_kind
                && grant.operations.contains(operation)
                && grant.selector.contains(selector)
        }) {
            Ok(())
        } else {
            Err(AuthorizationError::Denied)
        }
    }

    /// Issues a strictly attenuated child record after authorizing delegation.
    ///
    /// # Errors
    ///
    /// Returns [`AttenuationError`] when the parent cannot currently be used
    /// for delegation or any child time, assignment, grant, resource, depth,
    /// fanout, or scope property would widen parent authority.
    pub fn attenuate(
        &self,
        context: &AuthorizationContext,
        request: AttenuationRequest,
    ) -> Result<Self, AttenuationError> {
        self.authorize(
            context,
            ResourceKind::ChildDelegation,
            Operation::Delegate,
            &request.delegation_selector,
        )
        .map_err(AttenuationError::ParentAuthorization)?;

        let parent = &self.draft;
        if parent.delegation.remaining_depth == 0
            || request.delegation.remaining_depth >= parent.delegation.remaining_depth
        {
            return Err(AttenuationError::DelegationDepthWidened);
        }
        if request.delegation.maximum_fanout > parent.delegation.maximum_fanout {
            return Err(AttenuationError::FanoutWidened);
        }
        if !request
            .delegation
            .resources
            .is_within(parent.delegation.resources)
        {
            return Err(AttenuationError::ResourceEnvelopeWidened);
        }
        if request.not_before < parent.not_before || request.not_before < context.now {
            return Err(AttenuationError::ValidityWidened);
        }
        if request.expires_at > parent.expires_at || request.expires_at <= request.not_before {
            return Err(AttenuationError::ValidityWidened);
        }
        if parent.assignment_epoch.is_some() && request.assignment_epoch != parent.assignment_epoch
        {
            return Err(AttenuationError::AssignmentWidened);
        }
        if request.sandbox.is_some() != request.incarnation.is_some() {
            return Err(AttenuationError::PartialRuntimeScope);
        }
        for child in &request.grants {
            if !parent.grants.iter().any(|grant| grant.covers(child)) {
                return Err(AttenuationError::GrantWidened { grant: child.id });
            }
        }

        let draft = CapabilityDraft {
            id: request.id,
            issuer: parent.holder,
            audience: request.audience,
            holder: request.holder,
            channel_binding: request.channel_binding,
            root_subject: parent.root_subject,
            project: parent.project,
            sandbox: request.sandbox,
            incarnation: request.incarnation,
            grants: request.grants,
            policy_digest: parent.policy_digest,
            assignment_epoch: request.assignment_epoch,
            not_before: request.not_before,
            expires_at: request.expires_at,
            revocation_scope: parent.revocation_scope,
            revocation_generation: parent.revocation_generation,
            delegation: request.delegation,
            parent_decision: request.parent_decision,
        };
        Self::issue(draft).map_err(AttenuationError::InvalidChild)
    }
}

impl<'de> Deserialize<'de> for CapabilityRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        CapabilityDraft::deserialize(deserializer)
            .and_then(|draft| Self::issue(draft).map_err(serde::de::Error::custom))
    }
}

/// Supplies dynamic authenticated state for one capability use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    /// Current trusted controller Unix time.
    pub now: i64,
    /// Service principal receiving the request.
    pub audience: PrincipalId,
    /// Authenticated request principal.
    pub holder: PrincipalId,
    /// Proof-of-possession binding of the authenticated channel.
    pub channel_binding: ChannelBinding,
    /// Project in which the request is being evaluated.
    pub project: ProjectId,
    /// Target sandbox scope, if any.
    pub sandbox: Option<SandboxId>,
    /// Target runtime incarnation, if any.
    pub incarnation: Option<IncarnationId>,
    /// Target assignment epoch for node-specific work.
    pub assignment_epoch: Option<AssignmentEpoch>,
    /// Current generation of the record's revocation scope.
    pub revocation_generation: Revision,
}

/// Supplies the controller-selected fields of a delegated child record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttenuationRequest {
    /// New unpredictable child capability identity.
    pub id: CapabilityId,
    /// Child record audience.
    pub audience: PrincipalId,
    /// Child authenticated holder.
    pub holder: PrincipalId,
    /// Child proof-of-possession channel binding.
    pub channel_binding: ChannelBinding,
    /// Child sandbox scope, if runtime-bound.
    pub sandbox: Option<SandboxId>,
    /// Child incarnation paired with `sandbox`.
    pub incarnation: Option<IncarnationId>,
    /// Child grant set, each covered by one delegable parent grant.
    pub grants: Vec<Grant>,
    /// Optional node assignment scope.
    pub assignment_epoch: Option<AssignmentEpoch>,
    /// Inclusive child validity start.
    pub not_before: i64,
    /// Exclusive child expiry no later than the parent expiry.
    pub expires_at: i64,
    /// Strictly smaller descendant delegation ceilings.
    pub delegation: DelegationLimits,
    /// Parent selector used to authorize this delegation operation.
    pub delegation_selector: Selector,
    /// Durable controller decision for this attenuation.
    pub parent_decision: AuditId,
}

/// Reports malformed controller issuance input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CapabilityValidationError {
    /// Expiry does not strictly follow the validity start.
    #[error("capability expiry must be later than not-before")]
    InvalidValidity,
    /// Sandbox and incarnation bindings were not both present or both absent.
    #[error("sandbox and incarnation capability bindings must appear together")]
    PartialRuntimeScope,
    /// A capability must contain at least one and at most 1024 grants.
    #[error("capability grant count must be in 1..=1024")]
    InvalidGrantCount,
    /// Two normalized grants use one identity.
    #[error("capability contains duplicate grant identity {grant}")]
    DuplicateGrant {
        /// Repeated grant identity.
        grant: GrantId,
    },
    /// A grant is delegable even though no delegation edge remains.
    #[error("delegable grant requires a nonzero remaining delegation depth")]
    DelegableAtDepthZero,
}

/// Reports why dynamic capability validation or grant evaluation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorizationError {
    /// Trusted time precedes the inclusive validity start.
    #[error("capability is not yet valid")]
    NotYetValid,
    /// Trusted time reached or exceeded exclusive expiry.
    #[error("capability has expired")]
    Expired,
    /// Receiving service is not the record audience.
    #[error("capability audience mismatch")]
    AudienceMismatch,
    /// Authenticated principal is not the bound holder.
    #[error("capability holder mismatch")]
    HolderMismatch,
    /// Proof-of-possession channel binding differs.
    #[error("capability channel binding mismatch")]
    ChannelMismatch,
    /// Request is evaluated in another project.
    #[error("capability project mismatch")]
    ProjectMismatch,
    /// Sandbox or incarnation differs from the bound runtime scope.
    #[error("capability runtime scope mismatch")]
    RuntimeScopeMismatch,
    /// Assignment epoch differs from node-scoped authority.
    #[error("capability assignment epoch mismatch")]
    AssignmentMismatch,
    /// Current revocation generation differs from issuance.
    #[error("capability revocation generation mismatch")]
    Revoked,
    /// No normalized grant contains the request.
    #[error("capability denies the requested operation")]
    Denied,
}

/// Reports a child property that is not strict attenuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AttenuationError {
    /// Parent record is not currently authorized to delegate this selector.
    #[error("parent cannot authorize delegation: {0}")]
    ParentAuthorization(AuthorizationError),
    /// Child depth was not strictly lower than parent depth.
    #[error("child delegation depth must be strictly lower")]
    DelegationDepthWidened,
    /// Child direct fanout exceeded the parent ceiling.
    #[error("child delegation fanout exceeds parent ceiling")]
    FanoutWidened,
    /// Child resource vector exceeded the carved parent envelope.
    #[error("child delegation resource envelope exceeds parent ceiling")]
    ResourceEnvelopeWidened,
    /// Child validity begins too early, already elapsed, or ends too late.
    #[error("child validity interval widens or is outside parent validity")]
    ValidityWidened,
    /// Child removed or changed a parent node-assignment fence.
    #[error("child assignment scope widens parent authority")]
    AssignmentWidened,
    /// Child sandbox and incarnation bindings were not paired.
    #[error("child sandbox and incarnation bindings must appear together")]
    PartialRuntimeScope,
    /// No delegable parent grant covers one child grant.
    #[error("child grant {grant} is not covered by a delegable parent grant")]
    GrantWidened {
        /// Uncovered child grant identity.
        grant: GrantId,
    },
    /// Child claims remained malformed after attenuation checks.
    #[error("attenuated child capability is invalid: {0}")]
    InvalidChild(CapabilityValidationError),
}

fn validate_draft(draft: &CapabilityDraft) -> Result<(), CapabilityValidationError> {
    if draft.expires_at <= draft.not_before {
        return Err(CapabilityValidationError::InvalidValidity);
    }
    if draft.sandbox.is_some() != draft.incarnation.is_some() {
        return Err(CapabilityValidationError::PartialRuntimeScope);
    }
    if draft.grants.is_empty() || draft.grants.len() > MAX_GRANTS {
        return Err(CapabilityValidationError::InvalidGrantCount);
    }

    let mut ids = BTreeSet::new();
    for grant in &draft.grants {
        if !ids.insert(grant.id) {
            return Err(CapabilityValidationError::DuplicateGrant { grant: grant.id });
        }
        if grant.delegable && draft.delegation.remaining_depth == 0 {
            return Err(CapabilityValidationError::DelegableAtDepthZero);
        }
    }
    Ok(())
}

fn validate_context(
    claims: &CapabilityDraft,
    context: &AuthorizationContext,
) -> Result<(), AuthorizationError> {
    if context.now < claims.not_before {
        return Err(AuthorizationError::NotYetValid);
    }
    if context.now >= claims.expires_at {
        return Err(AuthorizationError::Expired);
    }
    if context.audience != claims.audience {
        return Err(AuthorizationError::AudienceMismatch);
    }
    if context.holder != claims.holder {
        return Err(AuthorizationError::HolderMismatch);
    }
    if context.channel_binding != claims.channel_binding {
        return Err(AuthorizationError::ChannelMismatch);
    }
    if context.project != claims.project {
        return Err(AuthorizationError::ProjectMismatch);
    }
    if context.sandbox != claims.sandbox || context.incarnation != claims.incarnation {
        return Err(AuthorizationError::RuntimeScopeMismatch);
    }
    if context.assignment_epoch != claims.assignment_epoch {
        return Err(AuthorizationError::AssignmentMismatch);
    }
    if context.revocation_generation != claims.revocation_generation {
        return Err(AuthorizationError::Revoked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AttenuationError, AttenuationRequest, AuthorizationContext, AuthorizationError,
        CapabilityDraft, CapabilityRecord, ChannelBinding, DelegationLimits, Grant,
    };
    use crate::selector::{Operation, OperationSet, RelativePath, ResourceKind, Selector};
    use crate::{
        AssignmentEpoch, AuditId, CapabilityId, ExportId, GrantId, IncarnationId, ObjectDigest,
        PrincipalId, ProjectId, ResourceDimension, ResourceVector, Revision, RevocationScopeId,
        SandboxId,
    };

    struct Fixture {
        capability: CapabilityRecord,
        context: AuthorizationContext,
        export: ExportId,
    }

    fn grant(operations: OperationSet, selector: Selector, delegable: bool) -> Grant {
        match Grant::new(
            GrantId::new(),
            ResourceKind::ChildDelegation,
            operations,
            selector,
            delegable,
        ) {
            Ok(grant) => grant,
            Err(error) => panic!("test grant must be valid: {error}"),
        }
    }

    fn fixture() -> Fixture {
        let audience = PrincipalId::new();
        let holder = PrincipalId::new();
        let project = ProjectId::new();
        let sandbox = SandboxId::new();
        let incarnation = IncarnationId::new();
        let export = ExportId::new();
        let channel_binding = ChannelBinding::new([0x11; 32]);
        let selector = Selector::Path {
            export,
            prefix: RelativePath::default(),
        };
        let draft = CapabilityDraft {
            id: CapabilityId::new(),
            issuer: PrincipalId::new(),
            audience,
            holder,
            channel_binding,
            root_subject: PrincipalId::new(),
            project,
            sandbox: Some(sandbox),
            incarnation: Some(incarnation),
            grants: vec![grant(
                OperationSet::one(Operation::Delegate)
                    .union(OperationSet::one(Operation::ContentRead)),
                selector,
                true,
            )],
            policy_digest: ObjectDigest::from_bytes([0x22; 32]),
            assignment_epoch: Some(AssignmentEpoch::new(7)),
            not_before: 100,
            expires_at: 200,
            revocation_scope: RevocationScopeId::new(),
            revocation_generation: Revision::new(3),
            delegation: DelegationLimits::new(
                3,
                4,
                ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 1024),
            ),
            parent_decision: AuditId::new(),
        };
        let context = AuthorizationContext {
            now: 150,
            audience,
            holder,
            channel_binding,
            project,
            sandbox: Some(sandbox),
            incarnation: Some(incarnation),
            assignment_epoch: Some(AssignmentEpoch::new(7)),
            revocation_generation: Revision::new(3),
        };
        let capability = match CapabilityRecord::issue(draft) {
            Ok(capability) => capability,
            Err(error) => panic!("test capability must be valid: {error}"),
        };
        Fixture {
            capability,
            context,
            export,
        }
    }

    fn child_request(fixture: &Fixture) -> AttenuationRequest {
        let selector = Selector::Path {
            export: fixture.export,
            prefix: RelativePath::default(),
        };
        AttenuationRequest {
            id: CapabilityId::new(),
            audience: PrincipalId::new(),
            holder: PrincipalId::new(),
            channel_binding: ChannelBinding::new([0x33; 32]),
            sandbox: Some(SandboxId::new()),
            incarnation: Some(IncarnationId::new()),
            grants: vec![grant(
                OperationSet::one(Operation::ContentRead),
                selector.clone(),
                false,
            )],
            assignment_epoch: Some(AssignmentEpoch::new(7)),
            not_before: 150,
            expires_at: 190,
            delegation: DelegationLimits::new(
                2,
                2,
                ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 512),
            ),
            delegation_selector: selector,
            parent_decision: AuditId::new(),
        }
    }

    #[test]
    fn authorization_is_default_deny_and_channel_bound() {
        let fixture = fixture();
        let selector = Selector::Path {
            export: fixture.export,
            prefix: RelativePath::default(),
        };

        assert!(
            fixture
                .capability
                .authorize(
                    &fixture.context,
                    ResourceKind::ChildDelegation,
                    Operation::ContentRead,
                    &selector,
                )
                .is_ok()
        );
        assert_eq!(
            fixture.capability.authorize(
                &fixture.context,
                ResourceKind::ChildDelegation,
                Operation::Publish,
                &selector,
            ),
            Err(AuthorizationError::Denied)
        );

        let mut wrong_channel = fixture.context.clone();
        wrong_channel.channel_binding = ChannelBinding::new([0x44; 32]);
        assert_eq!(
            fixture.capability.authorize(
                &wrong_channel,
                ResourceKind::ChildDelegation,
                Operation::ContentRead,
                &selector,
            ),
            Err(AuthorizationError::ChannelMismatch)
        );
    }

    #[test]
    fn expiry_and_revocation_fail_closed() {
        let fixture = fixture();
        let selector = Selector::Path {
            export: fixture.export,
            prefix: RelativePath::default(),
        };
        let mut expired = fixture.context.clone();
        expired.now = 200;
        assert_eq!(
            fixture.capability.authorize(
                &expired,
                ResourceKind::ChildDelegation,
                Operation::ContentRead,
                &selector,
            ),
            Err(AuthorizationError::Expired)
        );

        let mut revoked = fixture.context.clone();
        revoked.revocation_generation = Revision::new(4);
        assert_eq!(
            fixture.capability.authorize(
                &revoked,
                ResourceKind::ChildDelegation,
                Operation::ContentRead,
                &selector,
            ),
            Err(AuthorizationError::Revoked)
        );
    }

    #[test]
    fn valid_attenuation_narrows_every_envelope() {
        let fixture = fixture();
        let child = fixture
            .capability
            .attenuate(&fixture.context, child_request(&fixture));

        assert!(child.is_ok());
        assert!(child.is_ok_and(|record| {
            record.claims().delegation.remaining_depth() == 2
                && record.claims().project == fixture.context.project
                && record.claims().root_subject == fixture.capability.claims().root_subject
        }));
    }

    #[test]
    fn attenuation_rejects_each_widening_axis() {
        let fixture = fixture();

        let mut depth = child_request(&fixture);
        depth.delegation = DelegationLimits::new(
            3,
            2,
            ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 512),
        );
        assert_eq!(
            fixture.capability.attenuate(&fixture.context, depth),
            Err(AttenuationError::DelegationDepthWidened)
        );

        let mut resources = child_request(&fixture);
        resources.delegation = DelegationLimits::new(
            2,
            2,
            ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 2048),
        );
        assert_eq!(
            fixture.capability.attenuate(&fixture.context, resources),
            Err(AttenuationError::ResourceEnvelopeWidened)
        );

        let mut expiry = child_request(&fixture);
        expiry.expires_at = 201;
        assert_eq!(
            fixture.capability.attenuate(&fixture.context, expiry),
            Err(AttenuationError::ValidityWidened)
        );

        let mut assignment = child_request(&fixture);
        assignment.assignment_epoch = None;
        assert_eq!(
            fixture.capability.attenuate(&fixture.context, assignment),
            Err(AttenuationError::AssignmentWidened)
        );

        let mut fanout = child_request(&fixture);
        fanout.delegation = DelegationLimits::new(
            2,
            5,
            ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 512),
        );
        assert_eq!(
            fixture.capability.attenuate(&fixture.context, fanout),
            Err(AttenuationError::FanoutWidened)
        );

        let mut operation = child_request(&fixture);
        operation.grants[0].operations = OperationSet::one(Operation::Publish);
        assert!(matches!(
            fixture.capability.attenuate(&fixture.context, operation),
            Err(AttenuationError::GrantWidened { .. })
        ));

        let mut selector = child_request(&fixture);
        selector.grants[0].selector = Selector::Path {
            export: ExportId::new(),
            prefix: RelativePath::default(),
        };
        assert!(matches!(
            fixture.capability.attenuate(&fixture.context, selector),
            Err(AttenuationError::GrantWidened { .. })
        ));

        let mut start = child_request(&fixture);
        start.not_before = 149;
        assert_eq!(
            fixture.capability.attenuate(&fixture.context, start),
            Err(AttenuationError::ValidityWidened)
        );

        let mut scope = child_request(&fixture);
        scope.incarnation = None;
        assert_eq!(
            fixture.capability.attenuate(&fixture.context, scope),
            Err(AttenuationError::PartialRuntimeScope)
        );
    }

    #[test]
    fn nondelegable_grant_cannot_cover_a_child() {
        let mut fixture = fixture();
        fixture.capability.draft.grants[0].delegable = false;
        let request = child_request(&fixture);

        assert!(matches!(
            fixture.capability.attenuate(&fixture.context, request),
            Err(AttenuationError::GrantWidened { .. })
        ));
    }

    #[test]
    fn deserialization_revalidates_duplicate_grants() {
        let fixture = fixture();
        let mut invalid = fixture.capability.claims().clone();
        invalid.grants.push(invalid.grants[0].clone());
        let encoded = serde_json::to_string(&invalid);
        let decoded = encoded
            .as_deref()
            .map(serde_json::from_str::<CapabilityRecord>);

        assert!(matches!(decoded, Ok(Err(_))));
    }

    #[test]
    fn valid_record_serialization_round_trips() {
        let fixture = fixture();
        let encoded = serde_json::to_string(&fixture.capability);
        let decoded = encoded
            .as_deref()
            .map(serde_json::from_str::<CapabilityRecord>);

        assert_eq!(decoded.ok().and_then(Result::ok), Some(fixture.capability));
    }
}
