//! Assignment intent and monotonic node-observation models.
//!
//! Assignment intent commits controller-selected semantics and the capability
//! observation used during placement. It contains no ownership lease, signing
//! key, guardian deadline, or broker grant. Node observations can advance
//! status only for that exact tuple and likewise carry no authority.

use std::cmp::Ordering;

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::state::{AssignmentPhase, DesiredSandboxState, SuspensionMode};
use aos_sandbox_core::{
    AssignmentEpoch, CanonicalAssignmentManifestV1, DesiredGeneration, IncarnationId, NodeId,
    ObjectDescriptor, ObjectDigest, ObservationSequence, OperationId, PortableMediaType, ProjectId,
    ProtocolVersion, ResourceVector, RestoreScopeId, SandboxId, SnapshotId,
};

use super::capability::{
    CarrierValidatedCapabilityObservationV1, NodeAdmissionStateV1, NodeBootId, NodeBootLineageV1,
    NodeCapabilityKindV1, NodeProtocolV1,
};
use super::carrier_authority::AuthenticatedFrameSealV1;
use super::evidence::AuthenticatedEvidenceContextV1;
use super::evidence_authority::VerifierEvidenceGrantV1;
use super::journal::{JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1};
use super::placement::PlacementSelectionV1;

/// Uses the core closed assignment transition vocabulary for node observations.
pub type AssignmentObservationPhaseV1 = AssignmentPhase;

/// Reports malformed assignment intent or contradictory node observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidAssignmentModel {
    /// An identity, digest, generation, or sequence uses its zero sentinel.
    #[error("assignment model contains an unspecified identity or generation")]
    Unspecified,
    /// A node observation names another assignment tuple.
    #[error("node observation does not match the reducer's exact assignment")]
    AssignmentMismatch,
    /// Placement evidence selected a node other than the assignment target.
    #[error("placement evidence does not select the assignment target node")]
    PlacementMismatch,
    /// The node claims a desired generation newer than controller intent.
    #[error("node observation is ahead of the controller's desired generation")]
    DesiredGenerationAhead,
    /// One sequence names two different observations for the same node boot.
    #[error("assignment observation sequence was reused for different content")]
    SequenceConflict,
    /// One boot identity is paired with different generations, or conversely.
    #[error("assignment observation boot identity and generation are inconsistent")]
    BootConflict,
    /// A newer boot does not directly extend the last authenticated lineage.
    #[error("assignment observation skipped or contradicted durable boot lineage")]
    BootLineageGap,
    /// The closed assignment state machine rejects a transition.
    #[error("assignment observation contains an invalid phase transition")]
    InvalidPhaseTransition,
    /// The reason class contradicts the observed assignment phase.
    #[error("assignment observation reason is incompatible with its phase")]
    ReasonPhaseMismatch,
    /// Ownership/Guardian evidence is absent, stale, or bound to another tuple.
    #[error("assignment observation authority evidence is incompatible with its phase")]
    AuthorityMismatch,
}

/// Selects the verifier-observed Guardian state for one assignment authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedGuardianStateV1 {
    /// Current lease is armed and fail-stop enforcement is active.
    Armed,
    /// Payload and external access are contained.
    Contained,
    /// Lease expiry was observed and containment completed.
    ExpiredAndContained,
}

/// Carries verifier-issued current ownership and Guardian observation evidence.
///
/// This type is evidence about separately issued authority; it is not a lease,
/// grant, signature, or capability and cannot authorize an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedAssignmentAuthorityV1 {
    node: NodeId,
    context: AuthenticatedEvidenceContextV1,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    guardian_state: VerifiedGuardianStateV1,
    guardian_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    carrier_frame_digest: ObjectDigest,
    verified_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

impl VerifiedAssignmentAuthorityV1 {
    /// Constructs evidence only inside the authenticated owner-verifier boundary.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_owner_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            SandboxId,
            IncarnationId,
            AssignmentEpoch,
            DesiredGeneration,
            ObjectDigest,
            u64,
            ObjectDigest,
            VerifiedGuardianStateV1,
            ObjectDigest,
            ObjectDigest,
            ObjectDigest,
            u64,
            u64,
        )>,
    ) -> Result<Self, InvalidAssignmentModel> {
        let (
            (
                context,
                sandbox,
                incarnation,
                epoch,
                desired_generation,
                assignment_digest,
                lease_generation,
                lease_digest,
                guardian_state,
                guardian_digest,
                audience_digest,
                carrier_frame_digest,
                verified_at_unix_seconds,
                valid_until_unix_seconds,
            ),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let node = context.node();
        if node.as_bytes() == &[0; 16]
            || verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != context
            || sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || desired_generation.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || lease_generation == 0
            || lease_digest.as_bytes() == &[0; 32]
            || guardian_digest.as_bytes() == &[0; 32]
            || audience_digest != context.audience_digest()
            || carrier_frame_digest != context.canonical_frame_digest()
            || valid_until_unix_seconds <= verified_at_unix_seconds
            || !context.is_current_at(verified_at_unix_seconds)
            || !context.is_current_at(valid_until_unix_seconds)
        {
            return Err(InvalidAssignmentModel::AuthorityMismatch);
        }
        Ok(Self {
            node,
            context,
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            assignment_digest,
            lease_generation,
            lease_digest,
            guardian_state,
            guardian_digest,
            audience_digest,
            carrier_frame_digest,
            verified_at_unix_seconds,
            valid_until_unix_seconds,
        })
    }

    /// Returns the verified lease generation.
    #[must_use]
    pub const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Returns the verified lease commitment without exposing lease authority.
    #[must_use]
    pub const fn lease_digest(self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the verifier-observed Guardian state.
    #[must_use]
    pub const fn guardian_state(self) -> VerifiedGuardianStateV1 {
        self.guardian_state
    }

    /// Returns the verified Guardian observation commitment.
    #[must_use]
    pub const fn guardian_digest(self) -> ObjectDigest {
        self.guardian_digest
    }

    /// Returns the authenticated audience commitment.
    #[must_use]
    pub const fn audience_digest(self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the exact authenticated carrier-frame commitment.
    #[must_use]
    pub const fn carrier_frame_digest(self) -> ObjectDigest {
        self.carrier_frame_digest
    }

    /// Reports whether the evidence is current for exact intent and node boot.
    #[must_use]
    pub fn is_current_for(
        self,
        intent: &AssignmentIntentV1,
        lineage: NodeBootLineageV1,
        coordinator_unix_seconds: u64,
    ) -> bool {
        let guardian_matches_lifecycle = match intent.desired_lifecycle() {
            DesiredSandboxState::Running | DesiredSandboxState::Suspended(_) => {
                self.guardian_state == VerifiedGuardianStateV1::Armed
            }
            DesiredSandboxState::Stopped | DesiredSandboxState::Deleted => matches!(
                self.guardian_state,
                VerifiedGuardianStateV1::Contained | VerifiedGuardianStateV1::ExpiredAndContained
            ),
        };
        self.node == intent.node()
            && self.context.lineage() == lineage
            && self.sandbox == intent.sandbox()
            && self.incarnation == intent.incarnation()
            && self.epoch == intent.epoch()
            && self.desired_generation == intent.desired_generation()
            && self.assignment_digest == intent.assignment_digest()
            && guardian_matches_lifecycle
            && self.context.is_current_at(coordinator_unix_seconds)
            && coordinator_unix_seconds >= self.verified_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    /// Reports whether this verifier observation remains current independent of lifecycle policy.
    #[must_use]
    pub fn is_current_at(self, coordinator_unix_seconds: u64) -> bool {
        self.context.is_current_at(coordinator_unix_seconds)
            && coordinator_unix_seconds >= self.verified_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    /// Returns the immutable lease/Guardian evidence deadline.
    #[must_use]
    pub(super) const fn valid_until_unix_seconds(self) -> u64 {
        self.valid_until_unix_seconds
    }

    /// Returns the exact verifier carrier/currentness context.
    #[must_use]
    pub(super) const fn context(self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Classifies a bounded node-side reason without accepting arbitrary text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentObservationReasonV1 {
    /// No exceptional condition is reported.
    None,
    /// Required immutable input is not yet resident.
    AwaitingContent,
    /// Hard node capacity is temporarily unavailable.
    AwaitingCapacity,
    /// A required node capability drifted after placement.
    CapabilityDrift,
    /// Ownership authority has not been acquired or renewed.
    AwaitingOwnershipAuthority,
    /// The assignment guardian is not yet armed.
    AwaitingGuardian,
    /// Ownership authority expired or was superseded.
    OwnershipFenced,
    /// Complete boot inventory is not yet reconciled.
    InventoryIncomplete,
    /// Unknown or ambiguous node-local state requires quarantine.
    ResidualState,
    /// A required external dependency is unavailable.
    MissingDependency,
    /// A closed node-side operation failed.
    NodeOperationFailed,
}

pub(super) fn assignment_reason_phase_consistent(
    phase: AssignmentObservationPhaseV1,
    reason: AssignmentObservationReasonV1,
) -> bool {
    match phase {
        AssignmentPhase::Active | AssignmentPhase::Released => {
            reason == AssignmentObservationReasonV1::None
        }
        AssignmentPhase::Fenced => reason == AssignmentObservationReasonV1::OwnershipFenced,
        AssignmentPhase::Failed => reason != AssignmentObservationReasonV1::None,
        AssignmentPhase::Proposed
        | AssignmentPhase::Accepted
        | AssignmentPhase::Arming
        | AssignmentPhase::Draining => true,
    }
}

/// Stores controller intent for one canonical assignment generation.
///
/// This value is a desired-state record, not proof that the target node owns
/// the sandbox. Effect admission must independently validate current ownership
/// authority and its guardian binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentIntentV1 {
    assignment: CanonicalAssignmentManifestV1,
    desired_lifecycle: DesiredSandboxState,
    selected_capability: SelectedCapabilityBindingV1,
}

/// Retains the exact non-authorizing capability selection carried by intent.
///
/// The binding commits the original carrier bytes and currentness interval but
/// cannot refresh that interval or substitute for the live observation that an
/// acceptance verifier must independently consume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedCapabilityBindingV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    sequence: ObservationSequence,
    evidence_binding_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    replay_fence: ObjectDigest,
}

impl SelectedCapabilityBindingV1 {
    /// Constructs a non-authorizing exact capability-selection binding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::PlacementMismatch`] for a sentinel,
    /// empty frame, or nonpositive immutable currentness interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: NodeId,
        lineage: NodeBootLineageV1,
        sequence: ObservationSequence,
        evidence_binding_digest: ObjectDigest,
        canonical_frame_digest: ObjectDigest,
        canonical_frame_bytes: u32,
        coordinator_epoch: u64,
        authenticated_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        carrier_binding_digest: ObjectDigest,
        replay_fence: ObjectDigest,
    ) -> Result<Self, InvalidAssignmentModel> {
        if node.as_bytes() == &[0; 16]
            || sequence.get() == 0
            || evidence_binding_digest.as_bytes() == &[0; 32]
            || canonical_frame_digest.as_bytes() == &[0; 32]
            || canonical_frame_bytes == 0
            || coordinator_epoch == 0
            || valid_until_unix_seconds <= authenticated_at_unix_seconds
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || carrier_binding_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
        {
            return Err(InvalidAssignmentModel::PlacementMismatch);
        }
        Ok(Self {
            node,
            lineage,
            sequence,
            evidence_binding_digest,
            canonical_frame_digest,
            canonical_frame_bytes,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            audience_digest,
            disclosure_domain_digest,
            carrier_binding_digest,
            replay_fence,
        })
    }

    fn from_observation(
        observation: &CarrierValidatedCapabilityObservationV1,
    ) -> Result<Self, InvalidAssignmentModel> {
        Self::new(
            observation.audience_node(),
            observation.snapshot().lineage(),
            observation.snapshot().sequence(),
            observation.evidence_binding_digest(),
            observation.canonical_observation_digest(),
            observation.canonical_frame_bytes(),
            observation.coordinator_epoch(),
            observation.authenticated_at_unix_seconds(),
            observation.valid_until_unix_seconds(),
            observation.audience_digest(),
            observation.disclosure_domain_digest(),
            observation.carrier_binding_digest(),
            observation.replay_fence(),
        )
    }

    /// Returns the selected node.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }
    /// Returns the selected durable boot lineage.
    #[must_use]
    pub const fn lineage(self) -> NodeBootLineageV1 {
        self.lineage
    }
    /// Returns the selected observation sequence.
    #[must_use]
    pub const fn sequence(self) -> ObservationSequence {
        self.sequence
    }
    /// Returns the complete capability evidence commitment.
    #[must_use]
    pub const fn evidence_binding_digest(self) -> ObjectDigest {
        self.evidence_binding_digest
    }
    /// Returns the exact carrier-frame commitment.
    #[must_use]
    pub const fn canonical_frame_digest(self) -> ObjectDigest {
        self.canonical_frame_digest
    }
    /// Returns the exact bounded carrier-frame length.
    #[must_use]
    pub const fn canonical_frame_bytes(self) -> u32 {
        self.canonical_frame_bytes
    }
    /// Returns the authenticating coordinator epoch.
    #[must_use]
    pub const fn coordinator_epoch(self) -> u64 {
        self.coordinator_epoch
    }
    /// Returns the original authentication time.
    #[must_use]
    pub const fn authenticated_at_unix_seconds(self) -> u64 {
        self.authenticated_at_unix_seconds
    }
    /// Returns the immutable currentness deadline.
    #[must_use]
    pub const fn valid_until_unix_seconds(self) -> u64 {
        self.valid_until_unix_seconds
    }
    /// Returns the authenticated audience commitment.
    #[must_use]
    pub const fn audience_digest(self) -> ObjectDigest {
        self.audience_digest
    }
    /// Returns the authenticated disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(self) -> ObjectDigest {
        self.disclosure_domain_digest
    }
    /// Returns the authenticated carrier-binding commitment.
    #[must_use]
    pub const fn carrier_binding_digest(self) -> ObjectDigest {
        self.carrier_binding_digest
    }
    /// Returns the verifier replay-fence commitment.
    #[must_use]
    pub const fn replay_fence(self) -> ObjectDigest {
        self.replay_fence
    }

    /// Reports whether the placement observation's immutable interval covers `time`.
    #[must_use]
    pub const fn is_current_at(self, time: u64) -> bool {
        time >= self.authenticated_at_unix_seconds && time <= self.valid_until_unix_seconds
    }

    /// Reports whether `observation` is the exact still-current source fact.
    #[must_use]
    pub fn matches_current(
        self,
        observation: &CarrierValidatedCapabilityObservationV1,
        coordinator_unix_seconds: u64,
    ) -> bool {
        Self::from_observation(observation).is_ok_and(|binding| binding == self)
            && observation.is_current_at(coordinator_unix_seconds)
    }
}

impl AssignmentIntentV1 {
    /// Constructs one assignment desired-state record.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::PlacementMismatch`] when the
    /// deterministic selection names another node. The canonical manifest has
    /// already validated every assignment identity and derives its own digest.
    pub fn new(
        assignment: CanonicalAssignmentManifestV1,
        desired_lifecycle: DesiredSandboxState,
        selection: &PlacementSelectionV1,
    ) -> Result<Self, InvalidAssignmentModel> {
        if assignment.manifest().node() != selection.node()
            || assignment.manifest().sandbox() != selection.sandbox()
            || assignment.manifest().reservations() != selection.requested_resources()
            || assignment.manifest().required_features() != selection.required_features()
        {
            return Err(InvalidAssignmentModel::PlacementMismatch);
        }
        Ok(Self {
            assignment,
            desired_lifecycle,
            selected_capability: SelectedCapabilityBindingV1::from_observation(
                selection.capability_observation(),
            )?,
        })
    }

    /// Reconstructs authenticated controller intent from its exact wire binding.
    ///
    /// The binding remains historical scheduling evidence. Acceptance still
    /// requires the evidence authority to consume the matching live capability
    /// observation, ownership lease, Guardian fact, and protected journal row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::PlacementMismatch`] when the manifest
    /// names a different node than the immutable capability binding.
    pub fn from_canonical_binding(
        assignment: CanonicalAssignmentManifestV1,
        desired_lifecycle: DesiredSandboxState,
        selected_capability: SelectedCapabilityBindingV1,
    ) -> Result<Self, InvalidAssignmentModel> {
        if assignment.manifest().node() != selected_capability.node() {
            return Err(InvalidAssignmentModel::PlacementMismatch);
        }
        Ok(Self {
            assignment,
            desired_lifecycle,
            selected_capability,
        })
    }

    /// Returns the canonical assignment manifest and internally derived digest.
    #[must_use]
    pub const fn assignment(&self) -> &CanonicalAssignmentManifestV1 {
        &self.assignment
    }

    /// Returns the logical sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.assignment.manifest().sandbox()
    }

    /// Returns the target runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.assignment.manifest().incarnation()
    }

    /// Returns the preferred node from the immutable assignment semantics.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.assignment.manifest().node()
    }

    /// Returns the assignment fencing epoch.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.assignment.manifest().epoch()
    }

    /// Returns the desired generation inside the assignment epoch.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.assignment.manifest().desired_generation()
    }

    /// Returns the internally derived canonical assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment.digest()
    }

    /// Returns resources expected to be reserved by controller state.
    #[must_use]
    pub const fn reservations(&self) -> ResourceVector {
        self.assignment.manifest().reservations()
    }

    /// Returns the desired sandbox lifecycle state.
    #[must_use]
    pub const fn desired_lifecycle(&self) -> DesiredSandboxState {
        self.desired_lifecycle
    }

    /// Returns the node boot used for placement capability evaluation.
    #[must_use]
    pub const fn selected_capability_boot(&self) -> NodeBootId {
        self.selected_capability.lineage().boot()
    }

    /// Returns the durable node boot generation used during placement.
    #[must_use]
    pub const fn selected_capability_boot_generation(&self) -> u64 {
        self.selected_capability.lineage().generation()
    }

    /// Returns the durable capability boot lineage used during placement.
    #[must_use]
    pub const fn selected_capability_lineage(&self) -> NodeBootLineageV1 {
        self.selected_capability.lineage()
    }

    /// Returns the exact capability observation sequence used for placement.
    #[must_use]
    pub const fn selected_capability_sequence(&self) -> ObservationSequence {
        self.selected_capability.sequence()
    }

    /// Returns the exact carrier/currentness evidence used by placement.
    #[must_use]
    pub const fn selected_capability_binding(&self) -> SelectedCapabilityBindingV1 {
        self.selected_capability
    }
}

/// Carries one exact assignment effect selected by its typed intent reducer.
///
/// The move-only plan retains the complete intent. Its effect commitment is
/// derived internally from that intent and the idempotent operation identity;
/// callers cannot provide an independent digest to be echoed into durability.
#[must_use]
pub(super) struct AssignmentEffectPlanV1 {
    operation: OperationId,
    intent: AssignmentIntentV1,
    effect_digest: ObjectDigest,
}

impl AssignmentEffectPlanV1 {
    fn from_reducer(operation: OperationId, intent: AssignmentIntentV1) -> Option<Self> {
        if operation.as_bytes() == &[0; 16] {
            return None;
        }
        let effect_digest = assignment_effect_plan_digest(operation, &intent);
        Some(Self {
            operation,
            intent,
            effect_digest,
        })
    }

    pub(super) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(super) const fn intent(&self) -> &AssignmentIntentV1 {
        &self.intent
    }

    pub(super) const fn effect_digest(&self) -> ObjectDigest {
        self.effect_digest
    }

    pub(super) fn matches(
        &self,
        operation: OperationId,
        intent: &AssignmentIntentV1,
        effect_digest: ObjectDigest,
    ) -> bool {
        self.operation == operation
            && &self.intent == intent
            && self.effect_digest == effect_digest
            && self.effect_digest == assignment_effect_plan_digest(self.operation, &self.intent)
    }
}

fn assignment_effect_plan_digest(
    operation: OperationId,
    intent: &AssignmentIntentV1,
) -> ObjectDigest {
    let selected = intent.selected_capability_binding();
    let lifecycle = match intent.desired_lifecycle() {
        DesiredSandboxState::Running => [0, 0],
        DesiredSandboxState::Suspended(SuspensionMode::MemoryResident) => [1, 0],
        DesiredSandboxState::Suspended(SuspensionMode::Hibernate) => [1, 1],
        DesiredSandboxState::Stopped => [2, 0],
        DesiredSandboxState::Deleted => [3, 0],
    };
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.multi-node.assignment-effect-plan.v1\0");
    digest.update(operation.as_bytes());
    digest.update(intent.sandbox().as_bytes());
    digest.update(intent.incarnation().as_bytes());
    digest.update(intent.node().as_bytes());
    digest.update(intent.epoch().get().to_be_bytes());
    digest.update(intent.desired_generation().get().to_be_bytes());
    digest.update(intent.assignment_digest().as_bytes());
    digest.update(lifecycle);
    digest.update(selected.lineage().boot().as_bytes());
    digest.update(selected.lineage().generation().to_be_bytes());
    digest.update(selected.sequence().get().to_be_bytes());
    digest.update(selected.evidence_binding_digest().as_bytes());
    digest.update(selected.canonical_frame_digest().as_bytes());
    digest.update(selected.canonical_frame_bytes().to_be_bytes());
    digest.update(selected.coordinator_epoch().to_be_bytes());
    digest.update(selected.authenticated_at_unix_seconds().to_be_bytes());
    digest.update(selected.valid_until_unix_seconds().to_be_bytes());
    digest.update(selected.audience_digest().as_bytes());
    digest.update(selected.disclosure_domain_digest().as_bytes());
    digest.update(selected.carrier_binding_digest().as_bytes());
    digest.update(selected.replay_fence().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Stores one complete assignment observation from a fixed node boot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAssignmentObservationV1 {
    context: AuthenticatedEvidenceContextV1,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    sequence: ObservationSequence,
    phase: AssignmentObservationPhaseV1,
    realized_lifecycle: Option<DesiredSandboxState>,
    reason: AssignmentObservationReasonV1,
    authority: Option<VerifiedAssignmentAuthorityV1>,
    observed_at_unix_seconds: u64,
}

impl NodeAssignmentObservationV1 {
    /// Constructs one bounded assignment observation.
    ///
    /// The timestamp selects verifier-current evidence; it never extends an
    /// ownership lease or substitutes for the independently checked lease.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::Unspecified`] for zero identities,
    /// generations, sequence, or digest.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authenticated_node(
        context: AuthenticatedEvidenceContextV1,
        sandbox: SandboxId,
        incarnation: IncarnationId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        sequence: ObservationSequence,
        phase: AssignmentObservationPhaseV1,
        realized_lifecycle: Option<DesiredSandboxState>,
        reason: AssignmentObservationReasonV1,
        observed_at_unix_seconds: u64,
    ) -> Result<Self, InvalidAssignmentModel> {
        let node = context.node();
        let lineage = context.lineage();
        if node.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || desired_generation.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || sequence.get() == 0
            || !context.is_current_at(observed_at_unix_seconds)
        {
            return Err(InvalidAssignmentModel::Unspecified);
        }
        if !assignment_reason_phase_consistent(phase, reason) {
            return Err(InvalidAssignmentModel::ReasonPhaseMismatch);
        }
        let lifecycle_matches_phase = match realized_lifecycle {
            Some(DesiredSandboxState::Running | DesiredSandboxState::Suspended(_)) => {
                phase == AssignmentPhase::Active
            }
            Some(DesiredSandboxState::Stopped) => {
                matches!(phase, AssignmentPhase::Fenced | AssignmentPhase::Released)
            }
            Some(DesiredSandboxState::Deleted) => phase == AssignmentPhase::Released,
            None => phase != AssignmentPhase::Active,
        };
        if !lifecycle_matches_phase {
            return Err(InvalidAssignmentModel::AuthorityMismatch);
        }
        Ok(Self {
            context,
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            assignment_digest,
            sequence,
            phase,
            realized_lifecycle,
            reason,
            authority: None,
            observed_at_unix_seconds,
        })
    }

    /// Attaches independently verified ownership/Guardian evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::AuthorityMismatch`] unless the
    /// singular verifier grant names this exact observation and currentness.
    pub(super) fn with_verified_authority(
        mut self,
        grant: VerifierEvidenceGrantV1<(VerifiedAssignmentAuthorityV1, u64)>,
    ) -> Result<Self, InvalidAssignmentModel> {
        let (
            (evidence, verified_at_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let authority_matches = {
            evidence.node == self.node()
                && evidence.context == self.context
                && evidence.sandbox == self.sandbox
                && evidence.incarnation == self.incarnation
                && evidence.epoch == self.epoch
                && evidence.desired_generation == self.desired_generation
                && evidence.assignment_digest == self.assignment_digest
                && verified_at_unix_seconds >= evidence.verified_at_unix_seconds
                && verified_at_unix_seconds <= evidence.valid_until_unix_seconds
        };
        let phase_authority_matches = match self.phase {
            AssignmentPhase::Active => evidence.guardian_state() == VerifiedGuardianStateV1::Armed,
            AssignmentPhase::Fenced => {
                matches!(
                    evidence.guardian_state(),
                    VerifiedGuardianStateV1::Contained
                        | VerifiedGuardianStateV1::ExpiredAndContained
                )
            }
            _ => true,
        };
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != self.context
            || !authority_matches
            || !phase_authority_matches
        {
            return Err(InvalidAssignmentModel::AuthorityMismatch);
        }
        self.authority = Some(evidence);
        Ok(self)
    }

    /// Returns the observing node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.context.node()
    }

    /// Returns the observing node boot.
    #[must_use]
    pub const fn boot(&self) -> NodeBootId {
        self.context.lineage().boot()
    }

    /// Returns the durable monotonic generation associated with the node boot.
    #[must_use]
    pub const fn boot_generation(&self) -> u64 {
        self.context.lineage().generation()
    }

    /// Returns the authenticated durable boot lineage.
    #[must_use]
    pub const fn lineage(&self) -> NodeBootLineageV1 {
        self.context.lineage()
    }

    /// Returns the exact authenticated carrier/audience/currentness context.
    #[must_use]
    pub const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }

    /// Returns the logical sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the observed runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the observed assignment epoch.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.epoch
    }

    /// Returns the observed desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the observed canonical assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the monotonic sequence within the node boot.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the closed assignment realization phase.
    #[must_use]
    pub const fn phase(&self) -> AssignmentObservationPhaseV1 {
        self.phase
    }

    /// Returns the exact realized lifecycle for terminal/active observations.
    #[must_use]
    pub const fn realized_lifecycle(&self) -> Option<DesiredSandboxState> {
        self.realized_lifecycle
    }

    /// Returns the closed reason class.
    #[must_use]
    pub const fn reason(&self) -> AssignmentObservationReasonV1 {
        self.reason
    }

    /// Returns verifier-issued authority/Guardian evidence when present.
    #[must_use]
    pub const fn authority(&self) -> Option<VerifiedAssignmentAuthorityV1> {
        self.authority
    }

    /// Returns diagnostic wall-clock observation time.
    #[must_use]
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }

    /// Reports whether this observation names the exact assignment intent.
    #[must_use]
    pub fn matches(&self, intent: &AssignmentIntentV1) -> bool {
        self.node() == intent.node()
            && self.sandbox == intent.sandbox()
            && self.incarnation == intent.incarnation()
            && self.epoch == intent.epoch()
            && self.desired_generation == intent.desired_generation()
            && self.assignment_digest == intent.assignment_digest()
    }
}

/// Proves exact node acceptance with current lease and armed Guardian evidence.
///
/// Construction is restricted to the verifier boundary and does not transfer
/// the separately issued ownership authority it observes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAssignmentAcceptanceV1 {
    intent: AssignmentIntentV1,
    observation: NodeAssignmentObservationV1,
    capability_observation: CarrierValidatedCapabilityObservationV1,
    capability_evidence_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    guardian_digest: ObjectDigest,
    journal_record: ProtectedJournalRecordV1,
}

impl VerifiedAssignmentAcceptanceV1 {
    /// Constructs exact acceptance from current authenticated node evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::AuthorityMismatch`] unless tuple,
    /// lifecycle, phase, boot, lease, Guardian, carrier, and currentness match.
    pub(super) fn from_owner_verifier(
        grant: VerifierEvidenceGrantV1<(
            AssignmentIntentV1,
            NodeAssignmentObservationV1,
            CarrierValidatedCapabilityObservationV1,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidAssignmentModel> {
        let (
            (intent, observation, capability_observation, journal_record, coordinator_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let authority = observation
            .authority()
            .ok_or(InvalidAssignmentModel::AuthorityMismatch)?;
        let capability_evidence_digest = capability_observation.evidence_binding_digest();
        let acceptance_effect_digest = assignment_acceptance_effect_digest(&intent, authority);
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != observation.context()
            || !observation.matches(&intent)
            || observation.phase() != AssignmentPhase::Active
            || observation.realized_lifecycle() != Some(intent.desired_lifecycle())
            || !observation
                .context()
                .is_current_at(coordinator_unix_seconds)
            || !intent
                .selected_capability_binding()
                .matches_current(&capability_observation, coordinator_unix_seconds)
            || capability_observation.audience_node() != intent.node()
            || capability_observation.snapshot().lineage() != observation.lineage()
            || capability_observation.coordinator_epoch()
                != observation.context().coordinator_epoch()
            || capability_observation.audience_digest() != observation.context().audience_digest()
            || capability_observation.disclosure_domain_digest()
                != observation.context().disclosure_domain_digest()
            || capability_observation.carrier_binding_digest()
                != observation.context().carrier_binding_digest()
            || capability_observation.replay_fence() != observation.context().replay_fence()
            || authority.context() != observation.context()
            || !authority.is_current_for(&intent, observation.lineage(), coordinator_unix_seconds)
            || journal_record.record().domain() != MultiNodeJournalDomainV1::Assignment
            || journal_record.record().payload_digest() != intent.assignment_digest()
            || journal_record.record().state_payload().assignment_digest()
                != Some(intent.assignment_digest())
            || journal_record
                .record()
                .state_payload()
                .assignment_capability_evidence_digest()
                != Some(capability_evidence_digest)
            || journal_record.record().effect_state() != JournalEffectStateV1::Committed
            || journal_record.record().effect_digest() != acceptance_effect_digest
            || !journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
            || journal_record.context() != observation.context()
        {
            return Err(InvalidAssignmentModel::AuthorityMismatch);
        }
        Ok(Self {
            intent,
            observation,
            capability_observation,
            capability_evidence_digest,
            lease_generation: authority.lease_generation(),
            lease_digest: authority.lease_digest(),
            guardian_digest: authority.guardian_digest(),
            journal_record,
        })
    }

    /// Returns the exact accepted assignment intent.
    #[must_use]
    pub const fn intent(&self) -> &AssignmentIntentV1 {
        &self.intent
    }

    /// Returns the authenticated active node observation.
    #[must_use]
    pub const fn observation(&self) -> &NodeAssignmentObservationV1 {
        &self.observation
    }

    /// Returns the live capability observation revalidated at acceptance.
    #[must_use]
    pub const fn capability_observation(&self) -> &CarrierValidatedCapabilityObservationV1 {
        &self.capability_observation
    }

    /// Returns the exact selected capability identity/currentness commitment.
    #[must_use]
    pub const fn capability_evidence_digest(&self) -> ObjectDigest {
        self.capability_evidence_digest
    }

    /// Returns the verified lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the lease commitment without carrying authority bytes.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the exact armed Guardian observation commitment.
    #[must_use]
    pub const fn guardian_digest(&self) -> ObjectDigest {
        self.guardian_digest
    }

    /// Returns the durable exact-acceptance journal record.
    #[must_use]
    pub const fn journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Reports whether the exact lease, Guardian, carrier, and durability evidence is current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.observation
            .context()
            .is_current_at(coordinator_unix_seconds)
            && self
                .capability_observation
                .is_current_at(coordinator_unix_seconds)
            && self.capability_evidence_digest
                == self.capability_observation.evidence_binding_digest()
            && self
                .intent
                .selected_capability_binding()
                .matches_current(&self.capability_observation, coordinator_unix_seconds)
            && self.observation.observed_at_unix_seconds() <= coordinator_unix_seconds
            && self.observation.authority().is_some_and(|authority| {
                authority.is_current_for(
                    &self.intent,
                    self.observation.lineage(),
                    coordinator_unix_seconds,
                )
            })
            && self
                .journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
    }
}

fn assignment_acceptance_effect_digest(
    intent: &AssignmentIntentV1,
    authority: VerifiedAssignmentAuthorityV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.assignment.acceptance-effect.v1\0");
    hasher.update(intent.sandbox().as_bytes());
    hasher.update(intent.incarnation().as_bytes());
    hasher.update(intent.node().as_bytes());
    hasher.update(intent.epoch().get().to_be_bytes());
    hasher.update(intent.desired_generation().get().to_be_bytes());
    hasher.update(intent.assignment_digest().as_bytes());
    hasher.update(
        intent
            .selected_capability_binding()
            .evidence_binding_digest()
            .as_bytes(),
    );
    hasher.update(authority.lease_generation().to_be_bytes());
    hasher.update(authority.lease_digest().as_bytes());
    hasher.update(authority.guardian_digest().as_bytes());
    hasher.update(authority.audience_digest().as_bytes());
    hasher.update(authority.carrier_frame_digest().as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Reports a durable assignment acceptance generation reduction result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentAcceptanceApplyOutcomeV1 {
    /// A newer exact epoch/generation was accepted.
    Applied,
    /// The exact current acceptance was replayed.
    Replay,
    /// An older fenced acceptance was ignored.
    Stale,
}

/// Reduces verified assignment acceptance across desired generations and epochs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentAcceptanceReducerV1 {
    sandbox: SandboxId,
    current: Option<VerifiedAssignmentAcceptanceV1>,
}

impl AssignmentAcceptanceReducerV1 {
    /// Constructs a reducer for one nonzero logical sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::Unspecified`] for the zero sandbox.
    pub fn new(sandbox: SandboxId) -> Result<Self, InvalidAssignmentModel> {
        if sandbox.as_bytes() == &[0; 16] {
            return Err(InvalidAssignmentModel::Unspecified);
        }
        Ok(Self {
            sandbox,
            current: None,
        })
    }

    /// Applies one verifier-issued acceptance with equivocation fencing.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel`] for expired evidence, another
    /// sandbox, a changed digest at the same fence, or a nonmonotonic
    /// generation within an epoch.
    pub fn apply(
        &mut self,
        acceptance: VerifiedAssignmentAcceptanceV1,
        coordinator_unix_seconds: u64,
    ) -> Result<AssignmentAcceptanceApplyOutcomeV1, InvalidAssignmentModel> {
        let next = acceptance.intent();
        if next.sandbox() != self.sandbox || !acceptance.is_current_at(coordinator_unix_seconds) {
            return Err(InvalidAssignmentModel::AssignmentMismatch);
        }
        let Some(current) = &self.current else {
            self.current = Some(acceptance);
            return Ok(AssignmentAcceptanceApplyOutcomeV1::Applied);
        };
        let prior = current.intent();
        let next_fence = (next.epoch(), next.desired_generation());
        let prior_fence = (prior.epoch(), prior.desired_generation());
        match next_fence.cmp(&prior_fence) {
            Ordering::Less => Ok(AssignmentAcceptanceApplyOutcomeV1::Stale),
            Ordering::Equal if acceptance == *current => {
                Ok(AssignmentAcceptanceApplyOutcomeV1::Replay)
            }
            Ordering::Equal => Err(InvalidAssignmentModel::SequenceConflict),
            Ordering::Greater if next.epoch() == prior.epoch() => {
                let expected = prior
                    .desired_generation()
                    .get()
                    .checked_add(1)
                    .ok_or(InvalidAssignmentModel::DesiredGenerationAhead)?;
                if next.desired_generation().get() != expected {
                    return Err(InvalidAssignmentModel::DesiredGenerationAhead);
                }
                validate_acceptance_journal_successor(current, &acceptance)?;
                self.current = Some(acceptance);
                Ok(AssignmentAcceptanceApplyOutcomeV1::Applied)
            }
            Ordering::Greater => {
                validate_acceptance_journal_successor(current, &acceptance)?;
                self.current = Some(acceptance);
                Ok(AssignmentAcceptanceApplyOutcomeV1::Applied)
            }
        }
    }

    /// Returns the latest exact acceptance while all evidence remains current.
    #[must_use]
    pub fn current_at(
        &self,
        coordinator_unix_seconds: u64,
    ) -> Option<&VerifiedAssignmentAcceptanceV1> {
        self.current
            .as_ref()
            .filter(|acceptance| acceptance.is_current_at(coordinator_unix_seconds))
    }
}

fn validate_acceptance_journal_successor(
    current: &VerifiedAssignmentAcceptanceV1,
    next: &VerifiedAssignmentAcceptanceV1,
) -> Result<(), InvalidAssignmentModel> {
    if next.journal_record().record().sequence()
        != current
            .journal_record()
            .record()
            .sequence()
            .saturating_add(1)
        || next.journal_record().record().predecessor_digest()
            != current.journal_record().record().digest()
    {
        return Err(InvalidAssignmentModel::SequenceConflict);
    }
    Ok(())
}

/// Reports the result of reducing one assignment observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentObservationApplyOutcomeV1 {
    /// Reducer state changed.
    Applied,
    /// The exact current observation was replayed.
    Replay,
    /// An older observation from the current boot was ignored.
    Stale,
    /// A valid observation from a prior node boot was ignored.
    PriorBoot,
}

/// Reduces observations for one fixed canonical assignment intent.
///
/// This reducer validates identity, order, and phase transitions only. Even an
/// `Active` result is an observation requiring independent ownership and
/// guardian validation before the controller may issue effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentObservationReducerV1 {
    intent: AssignmentIntentV1,
    current: Option<NodeAssignmentObservationV1>,
}

impl AssignmentObservationReducerV1 {
    /// Creates an empty observation reducer for exact controller intent.
    #[must_use]
    pub fn new(intent: AssignmentIntentV1) -> Self {
        Self {
            intent,
            current: None,
        }
    }

    /// Returns the immutable assignment intent.
    #[must_use]
    pub const fn intent(&self) -> &AssignmentIntentV1 {
        &self.intent
    }

    /// Issues a typed semantic plan for this reducer's exact immutable intent.
    ///
    /// The plan grants no carrier or effect authority by itself. Protected-store
    /// commit and effect-time carrier verification remain independently required.
    pub(super) fn issue_effect_plan(
        &self,
        operation: OperationId,
    ) -> Result<AssignmentEffectPlanV1, InvalidAssignmentModel> {
        AssignmentEffectPlanV1::from_reducer(operation, self.intent.clone())
            .ok_or(InvalidAssignmentModel::Unspecified)
    }

    /// Returns the latest observation while its carrier and authority evidence is current.
    #[must_use]
    pub fn current_at(
        &self,
        coordinator_unix_seconds: u64,
    ) -> Option<&NodeAssignmentObservationV1> {
        self.current.as_ref().filter(|observation| {
            observation
                .context()
                .is_current_at(coordinator_unix_seconds)
                && observation.observed_at_unix_seconds() <= coordinator_unix_seconds
                && observation
                    .authority()
                    .is_none_or(|authority| authority.is_current_at(coordinator_unix_seconds))
        })
    }

    /// Reduces one already authenticated node observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel`] for expired evidence, tuple mismatch,
    /// future desired generation, same-sequence equivocation, or an impossible
    /// phase transition.
    pub fn apply(
        &mut self,
        observation: NodeAssignmentObservationV1,
        coordinator_unix_seconds: u64,
    ) -> Result<AssignmentObservationApplyOutcomeV1, InvalidAssignmentModel> {
        if !observation
            .context()
            .is_current_at(coordinator_unix_seconds)
            || observation.observed_at_unix_seconds() > coordinator_unix_seconds
            || observation
                .authority()
                .is_some_and(|authority| !authority.is_current_at(coordinator_unix_seconds))
        {
            return Err(InvalidAssignmentModel::AuthorityMismatch);
        }
        if observation.desired_generation() > self.intent.desired_generation() {
            return Err(InvalidAssignmentModel::DesiredGenerationAhead);
        }
        if !observation.matches(&self.intent) {
            return Err(InvalidAssignmentModel::AssignmentMismatch);
        }

        let placement_lineage = self.intent.selected_capability_lineage();
        if observation.boot_generation() < self.intent.selected_capability_boot_generation() {
            return Ok(AssignmentObservationApplyOutcomeV1::PriorBoot);
        }
        match observation
            .boot_generation()
            .cmp(&placement_lineage.generation())
        {
            Ordering::Equal if observation.lineage() != placement_lineage => {
                return Err(InvalidAssignmentModel::BootConflict);
            }
            Ordering::Greater
                if !observation
                    .lineage()
                    .is_direct_successor_of(placement_lineage) =>
            {
                return Err(InvalidAssignmentModel::BootLineageGap);
            }
            _ => {}
        }

        let Some(current) = &self.current else {
            self.current = Some(observation);
            return Ok(AssignmentObservationApplyOutcomeV1::Applied);
        };

        if observation.boot_generation() < current.boot_generation() {
            return Ok(AssignmentObservationApplyOutcomeV1::PriorBoot);
        }
        if observation.boot_generation() > current.boot_generation() {
            if !observation
                .lineage()
                .is_direct_successor_of(current.lineage())
            {
                return Err(InvalidAssignmentModel::BootLineageGap);
            }
            self.current = Some(observation);
            return Ok(AssignmentObservationApplyOutcomeV1::Applied);
        }
        if observation.lineage() != current.lineage() {
            return Err(InvalidAssignmentModel::BootConflict);
        }

        match observation.sequence().cmp(&current.sequence()) {
            Ordering::Less => Ok(AssignmentObservationApplyOutcomeV1::Stale),
            Ordering::Equal if observation == *current => {
                Ok(AssignmentObservationApplyOutcomeV1::Replay)
            }
            Ordering::Equal => Err(InvalidAssignmentModel::SequenceConflict),
            Ordering::Greater => {
                if !current.phase().can_transition_to(observation.phase()) {
                    return Err(InvalidAssignmentModel::InvalidPhaseTransition);
                }
                self.current = Some(observation);
                Ok(AssignmentObservationApplyOutcomeV1::Applied)
            }
        }
    }
}

/// Maximum immutable snapshot chunks described by one transfer manifest.
pub const MAX_SNAPSHOT_TRANSFER_CHUNKS: usize = 65_536;
/// Maximum immutable dependencies admitted by one transfer manifest.
pub const MAX_SNAPSHOT_TRANSFER_DEPENDENCIES: usize = 4_096;
/// Maximum bytes in one independently verified snapshot chunk.
pub const MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum conservative canonical-wire charge for one complete manifest.
///
/// Each bounded row is charged at more than its closed V1 JSON schema can
/// encode, including maximum-length media types and feature names. This keeps
/// all 65,536 chunk commitments representable without permitting an
/// allocation proportional to attacker-controlled, unvalidated bytes.
pub const MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES: usize = 15 * 1024 * 1024;

const SNAPSHOT_MANIFEST_FIXED_WIRE_BYTES: usize = 16 * 1024;
const SNAPSHOT_CHUNK_MAX_WIRE_BYTES: usize = 192;
const SNAPSHOT_DEPENDENCY_MAX_WIRE_BYTES: usize = 768;
const SNAPSHOT_FEATURE_MAX_WIRE_BYTES: usize = 512;

/// Reports malformed immutable transfer or restore-admission evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidSnapshotTransfer {
    /// An identity, digest, generation, or size uses its zero sentinel.
    #[error("snapshot transfer contains an unspecified value")]
    Unspecified,
    /// The transfer semantic version is not exactly supported.
    #[error("snapshot transfer semantic version is unsupported")]
    IncompatibleVersion,
    /// The root object is not an immutable snapshot descriptor.
    #[error("snapshot transfer root descriptor is not a snapshot")]
    WrongRootMediaType,
    /// Chunks are oversized, unordered, overlapping, gapped, or incomplete.
    #[error("snapshot transfer chunks do not canonically cover the root object")]
    ChunksNotCanonical,
    /// Dependencies are oversized, duplicated, unordered, or malformed.
    #[error("snapshot transfer dependencies are not canonical")]
    DependenciesNotCanonical,
    /// A dependency could carry lease, signature, trust, or grant authority.
    #[error("snapshot transfer dependencies must be inert immutable data")]
    AuthorityBearingDependency,
    /// Required features are oversized, duplicated, or unordered.
    #[error("snapshot transfer required features are not canonical")]
    FeaturesNotCanonical,
    /// The bounded manifest rows exceed the canonical wire allocation ceiling.
    #[error("snapshot transfer manifest exceeds its canonical wire ceiling")]
    ManifestTooLarge,
    /// The supplied manifest commitment does not match its canonical fields.
    #[error("snapshot transfer manifest commitment does not match")]
    ManifestDigestMismatch,
    /// A supplied chunk does not match the committed length or digest.
    #[error("snapshot transfer chunk failed integrity validation")]
    ChunkIntegrityMismatch,
    /// A resume checkpoint does not name a valid committed chunk boundary.
    #[error("snapshot transfer resume checkpoint is invalid")]
    InvalidResumeCheckpoint,
    /// Restore admission evidence does not name the manifest destination.
    #[error("snapshot restore admission evidence does not match the manifest")]
    RestoreAdmissionMismatch,
}

/// Selects the immutable snapshot-transfer semantic protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotTransferVersionV1 {
    major: u16,
    minor: u16,
}

impl SnapshotTransferVersionV1 {
    /// Returns the only transfer semantics understood by this model.
    #[must_use]
    pub const fn v1_0() -> Self {
        Self { major: 1, minor: 0 }
    }

    /// Constructs an explicitly versioned transfer request.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::IncompatibleVersion`] unless the
    /// version is exactly 1.0. Transfer compatibility is independent from the
    /// coordinator-to-node protocol.
    pub const fn new(major: u16, minor: u16) -> Result<Self, InvalidSnapshotTransfer> {
        if major != 1 || minor != 0 {
            return Err(InvalidSnapshotTransfer::IncompatibleVersion);
        }
        Ok(Self { major, minor })
    }

    /// Returns the breaking semantic major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the additive semantic minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// Identifies one immutable transfer without granting source or destination authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotTransferIdentityV1 {
    operation: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    snapshot: SnapshotId,
    source_node: NodeId,
    destination_node: NodeId,
    storage_domain_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    manifest_digest: ObjectDigest,
}

impl SnapshotTransferIdentityV1 {
    /// Constructs an inert transfer identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::Unspecified`] for any zero value.
    pub fn new(
        operation: OperationId,
        project: ProjectId,
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        snapshot: SnapshotId,
        source_node: NodeId,
        destination_node: NodeId,
        storage_domain_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        manifest_digest: ObjectDigest,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if operation.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || desired_generation.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || snapshot.as_bytes() == &[0; 16]
            || source_node.as_bytes() == &[0; 16]
            || destination_node.as_bytes() == &[0; 16]
            || storage_domain_digest.as_bytes() == &[0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || manifest_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidSnapshotTransfer::Unspecified);
        }
        Ok(Self {
            operation,
            project,
            sandbox,
            incarnation,
            assignment_epoch,
            desired_generation,
            assignment_digest,
            snapshot,
            source_node,
            destination_node,
            storage_domain_digest,
            audience_digest,
            disclosure_domain_digest,
            manifest_digest,
        })
    }

    /// Returns the idempotent operation identity.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the logical snapshot identity.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the project authority domain bound to immutable data.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the logical sandbox bound to the snapshot.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact runtime incarnation captured by the snapshot.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the exact assignment fencing epoch captured by the snapshot.
    #[must_use]
    pub const fn assignment_epoch(self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the exact desired assignment generation captured by the snapshot.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the exact canonical assignment commitment captured by the snapshot.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the node that may serve immutable bytes.
    #[must_use]
    pub const fn source_node(self) -> NodeId {
        self.source_node
    }

    /// Returns the only admitted destination node.
    #[must_use]
    pub const fn destination_node(self) -> NodeId {
        self.destination_node
    }

    /// Returns the immutable storage-domain commitment.
    #[must_use]
    pub const fn storage_domain_digest(self) -> ObjectDigest {
        self.storage_domain_digest
    }

    /// Returns the exact authenticated transfer audience commitment.
    #[must_use]
    pub const fn audience_digest(self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the canonical manifest commitment.
    #[must_use]
    pub const fn manifest_digest(self) -> ObjectDigest {
        self.manifest_digest
    }
}

/// Commits one bounded, independently verifiable snapshot byte range.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotTransferChunkV1 {
    index: u32,
    offset: u64,
    length: u32,
    digest: ObjectDigest,
}

impl SnapshotTransferChunkV1 {
    /// Constructs one chunk commitment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunksNotCanonical`] for an empty or
    /// oversized chunk or a zero digest.
    pub fn new(
        index: u32,
        offset: u64,
        length: u32,
        digest: ObjectDigest,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if length == 0
            || length > MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES
            || digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
        }
        Ok(Self {
            index,
            offset,
            length,
            digest,
        })
    }

    /// Returns the zero-based chunk index.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Returns the byte offset in the immutable root object.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Returns the exact chunk length.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }

    /// Returns the SHA-256 commitment to the exact chunk bytes.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }

    /// Verifies exact immutable bytes against this chunk commitment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] for a
    /// length or SHA-256 mismatch.
    pub fn verify_bytes(self, bytes: &[u8]) -> Result<(), InvalidSnapshotTransfer> {
        if bytes.len() != self.length as usize
            || ObjectDigest::from_bytes(Sha256::digest(bytes).into()) != self.digest
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(())
    }
}

/// Describes all immutable data and semantic prerequisites for one transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotTransferManifestV1 {
    identity: SnapshotTransferIdentityV1,
    version: SnapshotTransferVersionV1,
    root: ObjectDescriptor,
    chunks: Vec<SnapshotTransferChunkV1>,
    dependencies: Vec<ObjectDescriptor>,
    required_features: Vec<aos_sandbox_core::FeatureRef>,
}

impl SnapshotTransferManifestV1 {
    /// Computes the canonical commitment used to construct a transfer identity.
    ///
    /// Inputs must still pass [`Self::new`] before use. This helper only
    /// exposes the deterministic source codec and grants no authority.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_commitment_for(
        operation: OperationId,
        project: ProjectId,
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        snapshot: SnapshotId,
        source_node: NodeId,
        destination_node: NodeId,
        storage_domain_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        version: SnapshotTransferVersionV1,
        root: &ObjectDescriptor,
        chunks: &[SnapshotTransferChunkV1],
        dependencies: &[ObjectDescriptor],
        required_features: &[aos_sandbox_core::FeatureRef],
    ) -> ObjectDigest {
        canonical_manifest_commitment(
            operation,
            project,
            sandbox,
            incarnation,
            assignment_epoch,
            desired_generation,
            assignment_digest,
            snapshot,
            source_node,
            destination_node,
            storage_domain_digest,
            audience_digest,
            disclosure_domain_digest,
            version,
            root,
            chunks,
            dependencies,
            required_features,
        )
    }

    /// Constructs and verifies one immutable transfer manifest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless the root is a snapshot,
    /// chunks exactly and contiguously cover it, dependencies and features are
    /// canonical bounded sets, and the identity commits the canonical fields.
    pub fn new(
        identity: SnapshotTransferIdentityV1,
        version: SnapshotTransferVersionV1,
        root: ObjectDescriptor,
        chunks: Vec<SnapshotTransferChunkV1>,
        dependencies: Vec<ObjectDescriptor>,
        required_features: Vec<aos_sandbox_core::FeatureRef>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if root.media_type().as_str() != PortableMediaType::Snapshot.as_str()
            || root.digest().as_bytes() == &[0; 32]
            || root.encoded_size() == 0
        {
            return Err(InvalidSnapshotTransfer::WrongRootMediaType);
        }
        validate_transfer_chunks(root.encoded_size(), &chunks)?;
        if dependencies.len() > MAX_SNAPSHOT_TRANSFER_DEPENDENCIES
            || dependencies.iter().any(|object| {
                object.digest().as_bytes() == &[0; 32]
                    || object.encoded_size() == 0
                    || PortableMediaType::parse(object.media_type().as_str()).is_err()
            })
            || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        if dependencies.iter().any(|object| {
            PortableMediaType::parse(object.media_type().as_str())
                .is_ok_and(|media_type| !is_inert_transfer_dependency(media_type))
        }) {
            return Err(InvalidSnapshotTransfer::AuthorityBearingDependency);
        }
        if required_features.len() > super::placement::MAX_PLACEMENT_REQUIRED_FEATURES
            || !required_features.windows(2).all(|pair| pair[0] < pair[1])
            || aos_sandbox_core::validate_required_features(&required_features).is_err()
        {
            return Err(InvalidSnapshotTransfer::FeaturesNotCanonical);
        }
        snapshot_manifest_aggregate_wire_bytes(
            chunks.len(),
            dependencies.len(),
            required_features.len(),
        )?;

        let manifest = Self {
            identity,
            version,
            root,
            chunks,
            dependencies,
            required_features,
        };
        if manifest.canonical_commitment() != identity.manifest_digest() {
            return Err(InvalidSnapshotTransfer::ManifestDigestMismatch);
        }
        Ok(manifest)
    }

    /// Returns the inert transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact independent transfer protocol version.
    #[must_use]
    pub const fn version(&self) -> SnapshotTransferVersionV1 {
        self.version
    }

    /// Returns the immutable snapshot root descriptor.
    #[must_use]
    pub const fn root(&self) -> &ObjectDescriptor {
        &self.root
    }

    /// Returns contiguous chunk commitments in transfer order.
    #[must_use]
    pub fn chunks(&self) -> &[SnapshotTransferChunkV1] {
        &self.chunks
    }

    /// Returns immutable prerequisite objects in canonical order.
    #[must_use]
    pub fn dependencies(&self) -> &[ObjectDescriptor] {
        &self.dependencies
    }

    /// Returns hard destination feature requirements in canonical order.
    #[must_use]
    pub fn required_features(&self) -> &[aos_sandbox_core::FeatureRef] {
        &self.required_features
    }

    /// Verifies one received chunk before it can advance a resume boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] when the
    /// index is absent or exact bytes differ in length or SHA-256 digest.
    pub fn verify_chunk(&self, index: u32, bytes: &[u8]) -> Result<(), InvalidSnapshotTransfer> {
        let chunk = self
            .chunks
            .get(
                usize::try_from(index)
                    .map_err(|_| InvalidSnapshotTransfer::ChunkIntegrityMismatch)?,
            )
            .filter(|chunk| chunk.index() == index)
            .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
        chunk.verify_bytes(bytes)
    }

    /// Computes the canonical commitment to a verified chunk prefix.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::InvalidResumeCheckpoint`] when the
    /// boundary exceeds the committed chunk count.
    pub fn prefix_commitment(
        &self,
        next_chunk: u32,
    ) -> Result<ObjectDigest, InvalidSnapshotTransfer> {
        let boundary = usize::try_from(next_chunk)
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let prefix = self
            .chunks
            .get(..boundary)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let mut hasher = Sha256::new();
        hasher.update(b"aos.snapshot-transfer-prefix.v1\0");
        hasher.update(self.identity.manifest_digest().as_bytes());
        hasher.update(next_chunk.to_be_bytes());
        for chunk in prefix {
            hasher.update(chunk.index().to_be_bytes());
            hasher.update(chunk.digest().as_bytes());
        }
        Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
    }

    fn canonical_commitment(&self) -> ObjectDigest {
        canonical_manifest_commitment(
            self.identity.operation(),
            self.identity.project(),
            self.identity.sandbox(),
            self.identity.incarnation(),
            self.identity.assignment_epoch(),
            self.identity.desired_generation(),
            self.identity.assignment_digest(),
            self.identity.snapshot(),
            self.identity.source_node(),
            self.identity.destination_node(),
            self.identity.storage_domain_digest(),
            self.identity.audience_digest(),
            self.identity.disclosure_domain_digest(),
            self.version,
            &self.root,
            &self.chunks,
            &self.dependencies,
            &self.required_features,
        )
    }
}

fn snapshot_manifest_aggregate_wire_bytes(
    chunks: usize,
    dependencies: usize,
    features: usize,
) -> Result<usize, InvalidSnapshotTransfer> {
    let charge = SNAPSHOT_MANIFEST_FIXED_WIRE_BYTES
        .checked_add(
            chunks
                .checked_mul(SNAPSHOT_CHUNK_MAX_WIRE_BYTES)
                .ok_or(InvalidSnapshotTransfer::ManifestTooLarge)?,
        )
        .and_then(|value| {
            dependencies
                .checked_mul(SNAPSHOT_DEPENDENCY_MAX_WIRE_BYTES)
                .and_then(|rows| value.checked_add(rows))
        })
        .and_then(|value| {
            features
                .checked_mul(SNAPSHOT_FEATURE_MAX_WIRE_BYTES)
                .and_then(|rows| value.checked_add(rows))
        })
        .ok_or(InvalidSnapshotTransfer::ManifestTooLarge)?;
    if charge > MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES {
        return Err(InvalidSnapshotTransfer::ManifestTooLarge);
    }
    Ok(charge)
}

/// Binds one requested chunk to the immutable manifest that commits it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotTransferChunkRequestV1 {
    identity: SnapshotTransferIdentityV1,
    chunk: SnapshotTransferChunkV1,
}

impl SnapshotTransferChunkRequestV1 {
    /// Reconstructs an inert request from an exact identity and chunk commitment.
    ///
    /// This does not prove that the chunk belongs to a manifest; the receiving
    /// transfer reducer must match both fields to its already validated manifest.
    #[must_use]
    pub const fn from_exact_commitment(
        identity: SnapshotTransferIdentityV1,
        chunk: SnapshotTransferChunkV1,
    ) -> Self {
        Self { identity, chunk }
    }

    /// Derives one exact chunk request from a validated manifest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] when the
    /// index is outside the manifest's committed chunk sequence.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        index: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let chunk = manifest
            .chunks()
            .get(
                usize::try_from(index)
                    .map_err(|_| InvalidSnapshotTransfer::ChunkIntegrityMismatch)?,
            )
            .copied()
            .filter(|chunk| chunk.index() == index)
            .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
        Ok(Self {
            identity: manifest.identity(),
            chunk,
        })
    }

    /// Returns the exact immutable transfer identity.
    #[must_use]
    pub const fn identity(self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact manifest-committed chunk.
    #[must_use]
    pub const fn chunk(self) -> SnapshotTransferChunkV1 {
        self.chunk
    }
}

/// Carries one exact chunk whose carrier, audience, and bytes were authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSnapshotChunkV1 {
    request: SnapshotTransferChunkRequestV1,
    bytes: Vec<u8>,
    context: AuthenticatedEvidenceContextV1,
}

impl AuthenticatedSnapshotChunkV1 {
    /// Constructs chunk evidence only inside the authenticated carrier boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] for source, disclosure, currentness,
    /// exact length, or chunk digest mismatch.
    pub(super) fn from_authenticated_carrier(
        request: SnapshotTransferChunkRequestV1,
        bytes: Vec<u8>,
        context: AuthenticatedEvidenceContextV1,
        frame_seal: &AuthenticatedFrameSealV1,
        canonical_body_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if context.node() != request.identity().source_node()
            || context.audience_digest() != request.identity().audience_digest()
            || context.disclosure_domain_digest() != request.identity().disclosure_domain_digest()
            || !context.is_current_at(verified_at_unix_seconds)
            || !frame_seal.matches(
                super::protocol::CanonicalNodeFrameKindV1::SnapshotChunkResponse,
                canonical_body_digest,
                context,
            )
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        request.chunk().verify_bytes(&bytes)?;
        Ok(Self {
            request,
            bytes,
            context,
        })
    }

    /// Returns the exact manifest-derived chunk request.
    #[must_use]
    pub const fn request(&self) -> SnapshotTransferChunkRequestV1 {
        self.request
    }

    /// Returns exact authenticated immutable chunk bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns exact carrier/audience/boot/currentness evidence.
    #[must_use]
    pub const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Binds one bounded dependency byte range to its manifest descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDependencyRangeV1 {
    identity: SnapshotTransferIdentityV1,
    dependency: ObjectDescriptor,
    offset: u64,
    length: u32,
}

impl SnapshotDependencyRangeV1 {
    /// Reconstructs one inert manifest-bound dependency range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] for an
    /// invalid descriptor or an empty, oversized, overflowing, or out-of-range span.
    pub fn from_exact_commitment(
        identity: SnapshotTransferIdentityV1,
        dependency: ObjectDescriptor,
        offset: u64,
        length: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let end = offset
            .checked_add(u64::from(length))
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if dependency.digest().as_bytes() == &[0; 32]
            || dependency.encoded_size() == 0
            || PortableMediaType::parse(dependency.media_type().as_str()).is_err()
            || length == 0
            || length > MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES
            || end > dependency.encoded_size()
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        Ok(Self {
            identity,
            dependency,
            offset,
            length,
        })
    }

    /// Derives one bounded range request from a validated manifest dependency.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] for an
    /// unknown dependency, zero/oversized range, overflow, or out-of-bounds end.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        dependency_index: u32,
        offset: u64,
        length: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let dependency = manifest
            .dependencies()
            .get(
                usize::try_from(dependency_index)
                    .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?,
            )
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let end = offset
            .checked_add(u64::from(length))
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if length == 0
            || length > MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES
            || end > dependency.encoded_size()
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        Ok(Self {
            identity: manifest.identity(),
            dependency: dependency.clone(),
            offset,
            length,
        })
    }

    /// Returns the exact scoped transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the manifest-bound immutable dependency descriptor.
    #[must_use]
    pub const fn dependency(&self) -> &ObjectDescriptor {
        &self.dependency
    }

    /// Returns the exact dependency byte offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the bounded byte count.
    #[must_use]
    pub const fn length(&self) -> u32 {
        self.length
    }
}

/// Carries one manifest-bound dependency range from an authenticated source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSnapshotDependencyRangeV1 {
    request: SnapshotDependencyRangeV1,
    bytes: Vec<u8>,
    context: AuthenticatedEvidenceContextV1,
}

impl AuthenticatedSnapshotDependencyRangeV1 {
    /// Constructs dependency bytes only inside the authenticated carrier boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless source, disclosure domain,
    /// currentness, descriptor, offset, and exact bounded byte count match.
    pub(super) fn from_authenticated_carrier(
        request: SnapshotDependencyRangeV1,
        bytes: Vec<u8>,
        context: AuthenticatedEvidenceContextV1,
        frame_seal: &AuthenticatedFrameSealV1,
        canonical_body_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if context.node() != request.identity().source_node()
            || context.audience_digest() != request.identity().audience_digest()
            || context.disclosure_domain_digest() != request.identity().disclosure_domain_digest()
            || !context.is_current_at(verified_at_unix_seconds)
            || !frame_seal.matches(
                super::protocol::CanonicalNodeFrameKindV1::SnapshotDependencyResponse,
                canonical_body_digest,
                context,
            )
            || bytes.len() != request.length() as usize
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(Self {
            request,
            bytes,
            context,
        })
    }

    /// Returns the exact manifest-derived dependency range request.
    #[must_use]
    pub const fn request(&self) -> &SnapshotDependencyRangeV1 {
        &self.request
    }

    /// Returns the exact authenticated range bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns exact carrier/audience/boot/currentness evidence.
    #[must_use]
    pub const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Hashes contiguous authenticated dependency ranges without trusting metadata.
#[derive(Clone, Debug)]
pub struct SnapshotDependencyReducerV1 {
    identity: SnapshotTransferIdentityV1,
    descriptor: ObjectDescriptor,
    next_offset: u64,
    hasher: Sha256,
}

impl SnapshotDependencyReducerV1 {
    /// Starts verification for one exact manifest dependency.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] for an
    /// unknown dependency index.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        dependency_index: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let descriptor = manifest
            .dependencies()
            .get(
                usize::try_from(dependency_index)
                    .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?,
            )
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?
            .clone();
        Ok(Self {
            identity: manifest.identity(),
            descriptor,
            next_offset: 0,
            hasher: Sha256::new(),
        })
    }

    /// Applies one exact contiguous authenticated range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] for another
    /// transfer or dependency, a gap, replay, overflow, or out-of-bounds bytes.
    pub fn apply_range(
        &mut self,
        range: AuthenticatedSnapshotDependencyRangeV1,
        coordinator_unix_seconds: u64,
    ) -> Result<(), InvalidSnapshotTransfer> {
        let request = range.request();
        let end = request
            .offset()
            .checked_add(u64::from(request.length()))
            .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
        if request.identity() != self.identity
            || request.dependency() != &self.descriptor
            || request.offset() != self.next_offset
            || end > self.descriptor.encoded_size()
            || !range.context().is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        self.hasher.update(range.bytes());
        self.next_offset = end;
        Ok(())
    }

    /// Finishes only after actual authenticated bytes match the descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless all bytes arrived and their
    /// streaming SHA-256 digest matches the immutable descriptor.
    pub fn finish(self) -> Result<VerifiedSnapshotDependencyV1, InvalidSnapshotTransfer> {
        let media_type = PortableMediaType::parse(self.descriptor.media_type().as_str())
            .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if !is_inert_transfer_dependency(media_type) {
            return Err(InvalidSnapshotTransfer::AuthorityBearingDependency);
        }
        if self.next_offset != self.descriptor.encoded_size()
            || ObjectDigest::from_bytes(self.hasher.finalize().into()) != self.descriptor.digest()
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(VerifiedSnapshotDependencyV1 {
            identity: self.identity,
            descriptor: self.descriptor,
        })
    }
}

/// Commits resumable progress only at an already verified chunk boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotTransferResumeV1 {
    identity: SnapshotTransferIdentityV1,
    next_chunk: u32,
    verified_prefix_digest: ObjectDigest,
}

impl SnapshotTransferResumeV1 {
    /// Constructs an integrity-bound resume checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::InvalidResumeCheckpoint`] when the
    /// identity differs or the boundary exceeds the manifest. The prefix
    /// commitment is derived from the manifest rather than accepted as input.
    pub(super) fn new(
        manifest: &SnapshotTransferManifestV1,
        identity: SnapshotTransferIdentityV1,
        next_chunk: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if identity != manifest.identity()
            || usize::try_from(next_chunk)
                .ok()
                .is_none_or(|index| index > manifest.chunks().len())
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        let verified_prefix_digest = manifest.prefix_commitment(next_chunk)?;
        Ok(Self {
            identity,
            next_chunk,
            verified_prefix_digest,
        })
    }

    /// Returns the exact transfer identity.
    #[must_use]
    pub const fn identity(self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the first not-yet-verified chunk index.
    #[must_use]
    pub const fn next_chunk(self) -> u32 {
        self.next_chunk
    }

    /// Returns the digest of the exact verified prefix bytes.
    #[must_use]
    pub const fn verified_prefix_digest(self) -> ObjectDigest {
        self.verified_prefix_digest
    }
}

/// Proves that a resume boundary and its exact staged bytes are durably committed.
///
/// This verifier-issued value is inert recovery evidence. It cannot publish,
/// restore, or grant access to the staged snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableSnapshotTransferCheckpointV1 {
    resume: SnapshotTransferResumeV1,
    staged_bytes: u64,
    staged_prefix_digest: ObjectDigest,
    journal_record: ProtectedJournalRecordV1,
    evidence_context: AuthenticatedEvidenceContextV1,
}

impl DurableSnapshotTransferCheckpointV1 {
    /// Constructs a checkpoint only inside the destination storage verifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless the exact chunk boundary,
    /// staged length, committed journal record, destination, disclosure domain,
    /// and verifier currentness all match the immutable manifest.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_storage_verifier(
        grant: VerifierEvidenceGrantV1<(
            SnapshotTransferManifestV1,
            SnapshotTransferResumeV1,
            Vec<u8>,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let (
            (manifest, resume, staged_prefix, journal_record, verified_at_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let evidence_context = journal_record.context();
        let boundary = usize::try_from(resume.next_chunk())
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let expected_bytes = manifest
            .chunks()
            .get(..boundary)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?
            .iter()
            .try_fold(0_u64, |total, chunk| {
                total
                    .checked_add(u64::from(chunk.length()))
                    .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)
            })?;
        let staged_bytes = u64::try_from(staged_prefix.len())
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let staged_prefix_digest =
            staged_prefix_commitment(manifest.identity(), resume, &staged_prefix);
        let durable_state = journal_record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != evidence_context
            || resume.identity() != manifest.identity()
            || manifest.prefix_commitment(resume.next_chunk())? != resume.verified_prefix_digest()
            || staged_bytes != expected_bytes
            || journal_record.record().domain() != MultiNodeJournalDomainV1::SnapshotTransfer
            || journal_record.record().operation() != manifest.identity().operation()
            || journal_record.record().payload_digest() != resume.verified_prefix_digest()
            || journal_record.record().effect_state() != JournalEffectStateV1::Committed
            || journal_record.record().effect_digest() != staged_prefix_digest
            || durable_state.manifest() != &manifest
            || durable_state.resume() != resume
            || durable_state.staged_chunks().len() != boundary
            || durable_state.publication().is_some()
            || journal_record.storage_domain_digest() != manifest.identity().storage_domain_digest()
            || !journal_record
                .context()
                .is_current_at(verified_at_unix_seconds)
            || evidence_context.node() != manifest.identity().destination_node()
            || evidence_context.audience_digest() != manifest.identity().audience_digest()
            || evidence_context.disclosure_domain_digest()
                != manifest.identity().disclosure_domain_digest()
            || !evidence_context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        Ok(Self {
            resume,
            staged_bytes,
            staged_prefix_digest,
            journal_record,
            evidence_context,
        })
    }

    /// Returns the exact integrity-verified chunk boundary.
    #[must_use]
    pub const fn resume(&self) -> SnapshotTransferResumeV1 {
        self.resume
    }

    /// Returns the exact scoped immutable transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.resume.identity()
    }

    /// Returns the first chunk not covered by the durable staged prefix.
    #[must_use]
    pub const fn next_chunk(&self) -> u32 {
        self.resume.next_chunk()
    }

    /// Returns the exact durably staged byte count.
    #[must_use]
    pub const fn staged_bytes(&self) -> u64 {
        self.staged_bytes
    }

    /// Returns the storage verifier's exact staged-byte commitment.
    #[must_use]
    pub const fn staged_prefix_digest(&self) -> ObjectDigest {
        self.staged_prefix_digest
    }

    /// Returns the committed journal record covering this boundary.
    #[must_use]
    pub const fn journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Returns the exact authenticated destination verifier context.
    #[must_use]
    pub const fn evidence_context(&self) -> AuthenticatedEvidenceContextV1 {
        self.evidence_context
    }
}

/// Reports a sequential immutable chunk reduction result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotTransferApplyOutcomeV1 {
    /// A newly verified chunk advanced the in-memory verified boundary.
    Applied(SnapshotTransferResumeV1),
    /// An already verified committed chunk was replayed exactly.
    Replay(SnapshotTransferResumeV1),
}

/// Reduces bounded immutable chunk bytes into a resumable verified prefix.
#[derive(Clone, Debug)]
pub struct SnapshotTransferReducerV1 {
    manifest: SnapshotTransferManifestV1,
    next_chunk: u32,
    verified_bytes: u64,
    root_hasher: Sha256,
}

impl SnapshotTransferReducerV1 {
    /// Starts one transfer at the beginning of its validated manifest.
    #[must_use]
    pub fn new(manifest: SnapshotTransferManifestV1) -> Self {
        Self {
            manifest,
            next_chunk: 0,
            verified_bytes: 0,
            root_hasher: Sha256::new(),
        }
    }

    /// Resumes only after re-verifying the exact durably staged byte prefix.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] when the checkpoint, staged length,
    /// any chunk digest, or the canonical prefix commitment differs.
    pub fn resume_from_staged_prefix(
        manifest: SnapshotTransferManifestV1,
        durable_checkpoint: DurableSnapshotTransferCheckpointV1,
        staged_prefix: &[u8],
        coordinator_unix_seconds: u64,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let checkpoint = durable_checkpoint.resume();
        if checkpoint.identity() != manifest.identity()
            || manifest.prefix_commitment(checkpoint.next_chunk())?
                != checkpoint.verified_prefix_digest()
            || staged_prefix.len() as u64 != durable_checkpoint.staged_bytes()
            || staged_prefix_commitment(manifest.identity(), checkpoint, staged_prefix)
                != durable_checkpoint.staged_prefix_digest()
            || !durable_checkpoint
                .evidence_context()
                .is_current_at(coordinator_unix_seconds)
            || !durable_checkpoint
                .journal_record()
                .context()
                .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        let boundary = usize::try_from(checkpoint.next_chunk())
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let chunks = manifest
            .chunks()
            .get(..boundary)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let expected_bytes = chunks.iter().try_fold(0_usize, |total, chunk| {
            total
                .checked_add(chunk.length() as usize)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)
        })?;
        if staged_prefix.len() != expected_bytes {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }

        let mut root_hasher = Sha256::new();
        let mut offset = 0_usize;
        for chunk in chunks {
            let end = offset
                .checked_add(chunk.length() as usize)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
            let bytes = staged_prefix
                .get(offset..end)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
            chunk.verify_bytes(bytes)?;
            root_hasher.update(bytes);
            offset = end;
        }
        Ok(Self {
            manifest,
            next_chunk: checkpoint.next_chunk(),
            verified_bytes: expected_bytes as u64,
            root_hasher,
        })
    }

    /// Returns the immutable manifest being reduced.
    #[must_use]
    pub const fn manifest(&self) -> &SnapshotTransferManifestV1 {
        &self.manifest
    }

    /// Returns the current integrity-bound in-memory resume position.
    ///
    /// Resumption still requires a [`DurableSnapshotTransferCheckpointV1`]
    /// issued after exact staged bytes and a committed journal record agree.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::InvalidResumeCheckpoint`] only if
    /// internal state is inconsistent with the immutable manifest.
    pub fn checkpoint(&self) -> Result<SnapshotTransferResumeV1, InvalidSnapshotTransfer> {
        SnapshotTransferResumeV1::new(&self.manifest, self.manifest.identity(), self.next_chunk)
    }

    /// Verifies one exact chunk and advances only the next contiguous boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] for integrity failure, an unknown
    /// index, or an attempt to skip an unverified chunk.
    pub fn apply_chunk(
        &mut self,
        authenticated_chunk: AuthenticatedSnapshotChunkV1,
        coordinator_unix_seconds: u64,
    ) -> Result<SnapshotTransferApplyOutcomeV1, InvalidSnapshotTransfer> {
        let index = authenticated_chunk.request().chunk().index();
        let bytes = authenticated_chunk.bytes();
        if authenticated_chunk.request().identity() != self.manifest.identity() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        if !authenticated_chunk
            .context()
            .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        self.manifest.verify_chunk(index, bytes)?;
        if index > self.next_chunk {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        if index < self.next_chunk {
            return Ok(SnapshotTransferApplyOutcomeV1::Replay(self.checkpoint()?));
        }
        self.next_chunk = self
            .next_chunk
            .checked_add(1)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        self.verified_bytes = self
            .verified_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        self.root_hasher.update(bytes);
        Ok(SnapshotTransferApplyOutcomeV1::Applied(self.checkpoint()?))
    }

    /// Finishes only after all actual staged bytes match chunks and the root digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] when chunks remain, byte totals
    /// differ, or the streaming SHA-256 root does not match the manifest.
    pub fn finish(self) -> Result<VerifiedStagedSnapshotV1, InvalidSnapshotTransfer> {
        if usize::try_from(self.next_chunk).ok() != Some(self.manifest.chunks().len())
            || self.verified_bytes != self.manifest.root().encoded_size()
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        let root_digest = ObjectDigest::from_bytes(self.root_hasher.finalize().into());
        if root_digest != self.manifest.root().digest() {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(VerifiedStagedSnapshotV1 {
            identity: self.manifest.identity(),
            root: self.manifest.root().clone(),
            verified_bytes: self.verified_bytes,
            final_prefix_digest: self.manifest.prefix_commitment(self.next_chunk)?,
        })
    }
}

/// Proves that actual staged bytes passed every chunk and whole-object digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStagedSnapshotV1 {
    identity: SnapshotTransferIdentityV1,
    root: ObjectDescriptor,
    verified_bytes: u64,
    final_prefix_digest: ObjectDigest,
}

impl VerifiedStagedSnapshotV1 {
    /// Returns the exact scoped transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the whole-object descriptor verified from actual bytes.
    #[must_use]
    pub const fn root(&self) -> &ObjectDescriptor {
        &self.root
    }

    /// Returns the exact number of staged bytes verified.
    #[must_use]
    pub const fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// Returns the final durable chunk-boundary commitment.
    #[must_use]
    pub const fn final_prefix_digest(&self) -> ObjectDigest {
        self.final_prefix_digest
    }
}

/// Proves one declared dependency's actual immutable bytes matched its descriptor.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VerifiedSnapshotDependencyV1 {
    identity: SnapshotTransferIdentityV1,
    descriptor: ObjectDescriptor,
}

impl VerifiedSnapshotDependencyV1 {
    /// Returns the exact project, sandbox, nodes, audience, and manifest binding.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact verified immutable descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}

/// Commits the exact canonical set of dependencies verified from actual bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSnapshotDependencySetV1 {
    identity: SnapshotTransferIdentityV1,
    dependencies: Vec<VerifiedSnapshotDependencyV1>,
    digest: ObjectDigest,
}

impl VerifiedSnapshotDependencySetV1 {
    /// Constructs the exact dependency set required by a manifest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] unless
    /// verified descriptors exactly equal the manifest dependency list.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        dependencies: Vec<VerifiedSnapshotDependencyV1>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if dependencies.len() != manifest.dependencies().len()
            || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
            || dependencies
                .iter()
                .zip(manifest.dependencies())
                .any(|(verified, expected)| {
                    verified.identity() != manifest.identity() || verified.descriptor() != expected
                })
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"aos.snapshot-transfer.dependencies.v1\0");
        hasher.update(manifest.identity().manifest_digest().as_bytes());
        for dependency in &dependencies {
            hash_descriptor(&mut hasher, dependency.descriptor());
        }
        Ok(Self {
            identity: manifest.identity(),
            dependencies,
            digest: ObjectDigest::from_bytes(hasher.finalize().into()),
        })
    }

    /// Returns the exact scoped transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns verified dependencies in canonical manifest order.
    #[must_use]
    pub fn dependencies(&self) -> &[VerifiedSnapshotDependencyV1] {
        &self.dependencies
    }

    /// Returns the canonical verified-dependency commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Couples a complete verified dependency set to protected current storage evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableSnapshotDependencySetV1 {
    verified: VerifiedSnapshotDependencySetV1,
    journal_record: ProtectedJournalRecordV1,
    live_until_unix_seconds: u64,
}

impl DurableSnapshotDependencySetV1 {
    /// Issues dependency durability evidence only inside the protected-store verifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] unless
    /// the protected record commits the exact complete dependency set under
    /// the destination, storage domain, audience, and current context.
    pub(super) fn from_storage_verifier(
        grant: VerifierEvidenceGrantV1<(
            VerifiedSnapshotDependencySetV1,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let (
            (verified, journal_record, coordinator_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let identity = verified.identity();
        let durable_state = journal_record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let live_until_unix_seconds = durable_state
            .dependencies()
            .iter()
            .filter_map(|dependency| dependency.live_until_unix_seconds)
            .min()
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != journal_record.context()
            || journal_record.record().domain() != MultiNodeJournalDomainV1::SnapshotTransfer
            || journal_record.record().operation() != identity.operation()
            || journal_record.record().payload_digest() != verified.digest()
            || journal_record.record().effect_state() != JournalEffectStateV1::Committed
            || journal_record.record().effect_digest() != verified.digest()
            || durable_state.manifest().identity() != identity
            || durable_state.dependencies().len() != verified.dependencies().len()
            || durable_state
                .dependencies()
                .iter()
                .zip(verified.dependencies())
                .any(|(durable, expected)| {
                    &durable.descriptor != expected.descriptor()
                        || durable.next_offset != durable.descriptor.encoded_size()
                        || durable.liveness_digest.is_none()
                        || durable
                            .live_until_unix_seconds
                            .is_none_or(|deadline| deadline < coordinator_unix_seconds)
                })
            || journal_record.storage_domain_digest() != identity.storage_domain_digest()
            || journal_record.context().node() != identity.destination_node()
            || journal_record.context().audience_digest() != identity.audience_digest()
            || journal_record.context().disclosure_domain_digest()
                != identity.disclosure_domain_digest()
            || !journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        Ok(Self {
            verified,
            journal_record,
            live_until_unix_seconds,
        })
    }

    /// Returns the exact scoped transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.verified.identity()
    }

    /// Returns the exact canonical verified-dependency commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.verified.digest()
    }

    /// Returns the opaque protected-store capability for dependency durability.
    #[must_use]
    pub const fn journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Reports whether the durable dependency inventory remains current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.journal_record
            .context()
            .is_current_at(coordinator_unix_seconds)
            && coordinator_unix_seconds <= self.live_until_unix_seconds
    }
}

/// Proves a storage verifier atomically published verified staged bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicSnapshotPublicationV1 {
    identity: SnapshotTransferIdentityV1,
    root: ObjectDescriptor,
    publication_generation: u64,
    publication_digest: ObjectDigest,
    journal_record: ProtectedJournalRecordV1,
    evidence_context: AuthenticatedEvidenceContextV1,
}

impl AtomicSnapshotPublicationV1 {
    /// Constructs publication evidence only inside the storage-verifier boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] for tuple, digest, generation,
    /// destination, disclosure-domain, or currentness mismatch.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_storage_verifier(
        grant: VerifierEvidenceGrantV1<(
            VerifiedStagedSnapshotV1,
            u64,
            ObjectDigest,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let (
            (
                staged,
                publication_generation,
                publication_digest,
                journal_record,
                verified_at_unix_seconds,
            ),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let evidence_context = journal_record.context();
        let durable_state = journal_record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        let durable_publication = durable_state
            .publication()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != evidence_context
            || publication_generation == 0
            || publication_digest.as_bytes() == &[0; 32]
            || journal_record.record().domain() != MultiNodeJournalDomainV1::SnapshotTransfer
            || journal_record.record().operation() != staged.identity().operation()
            || journal_record.record().payload_digest() != staged.final_prefix_digest()
            || journal_record.record().effect_state() != JournalEffectStateV1::Committed
            || journal_record.record().effect_digest() != publication_digest
            || durable_state.manifest().identity() != staged.identity()
            || durable_state.manifest().root() != staged.root()
            || usize::try_from(durable_state.resume().next_chunk()).ok()
                != Some(durable_state.manifest().chunks().len())
            || durable_state.staged_chunks().len() != durable_state.manifest().chunks().len()
            || durable_state.dependencies().iter().any(|dependency| {
                dependency.next_offset != dependency.descriptor.encoded_size()
                    || dependency
                        .live_until_unix_seconds
                        .is_none_or(|deadline| deadline < verified_at_unix_seconds)
            })
            || durable_publication.publication_generation != publication_generation
            || durable_publication.publication_digest != publication_digest
            || journal_record.storage_domain_digest() != staged.identity().storage_domain_digest()
            || !journal_record
                .context()
                .is_current_at(verified_at_unix_seconds)
            || evidence_context.node() != staged.identity().destination_node()
            || evidence_context.audience_digest() != staged.identity().audience_digest()
            || evidence_context.disclosure_domain_digest()
                != staged.identity().disclosure_domain_digest()
            || !evidence_context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        Ok(Self {
            identity: staged.identity(),
            root: staged.root().clone(),
            publication_generation,
            publication_digest,
            journal_record,
            evidence_context,
        })
    }

    /// Returns the exact scoped transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the atomically published root descriptor.
    #[must_use]
    pub const fn root(&self) -> &ObjectDescriptor {
        &self.root
    }

    /// Returns the monotonic storage publication generation.
    #[must_use]
    pub const fn publication_generation(&self) -> u64 {
        self.publication_generation
    }

    /// Returns the atomic publication commitment.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the opaque protected-store durability receipt commitment.
    #[must_use]
    pub fn protected_store_receipt_commitment(&self) -> ObjectDigest {
        self.journal_record.receipt_commitment()
    }

    /// Returns the exact opaque protected-store record proving durability.
    #[must_use]
    pub const fn protected_journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Returns the verifier-issued carrier/audience/currentness context.
    #[must_use]
    pub const fn evidence_context(&self) -> AuthenticatedEvidenceContextV1 {
        self.evidence_context
    }
}

/// Commits completion of every integrity-verified chunk in one transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotTransferCompletionV1 {
    identity: SnapshotTransferIdentityV1,
    verified_bytes: u64,
    root_digest: ObjectDigest,
    verified_prefix_digest: ObjectDigest,
    dependency_set_digest: ObjectDigest,
    dependencies_live_until_unix_seconds: u64,
    dependency_record: ProtectedJournalRecordV1,
    publication_generation: u64,
    publication_digest: ObjectDigest,
    journal_record: ProtectedJournalRecordV1,
    evidence_context: AuthenticatedEvidenceContextV1,
    completion_digest: ObjectDigest,
}

impl SnapshotTransferCompletionV1 {
    /// Constructs completion evidence at the manifest's final chunk boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::RestoreAdmissionMismatch`] unless the
    /// staged root, verified dependency set, and atomic publication name one
    /// exact immutable transfer.
    pub(super) fn from_atomic_publication(
        staged: VerifiedStagedSnapshotV1,
        dependencies: DurableSnapshotDependencySetV1,
        publication: AtomicSnapshotPublicationV1,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if dependencies.identity() != staged.identity()
            || publication.identity() != staged.identity()
            || publication.root() != staged.root()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        let identity = staged.identity();
        let verified_bytes = staged.verified_bytes();
        let root_digest = staged.root().digest();
        let verified_prefix_digest = staged.final_prefix_digest();
        let dependency_set_digest = dependencies.digest();
        let dependencies_live_until_unix_seconds = dependencies.live_until_unix_seconds;
        let dependency_record = dependencies.journal_record().clone();
        let publication_generation = publication.publication_generation();
        let publication_digest = publication.publication_digest();
        let protected_store_receipt_commitment = publication.protected_store_receipt_commitment();
        let journal_record = publication.protected_journal_record().clone();
        let evidence_context = publication.evidence_context();
        if dependency_record.storage_domain_digest()
            != publication
                .protected_journal_record()
                .storage_domain_digest()
            || dependency_record.replay_fence()
                != publication.protected_journal_record().replay_fence()
            || publication
                .protected_journal_record()
                .durability_generation()
                <= dependency_record.durability_generation()
            || publication.protected_journal_record().record().sequence()
                != dependency_record.record().sequence().saturating_add(1)
            || publication
                .protected_journal_record()
                .record()
                .predecessor_digest()
                != dependency_record.record().digest()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        let completion_digest = snapshot_transfer_completion_digest(
            identity,
            verified_bytes,
            root_digest,
            verified_prefix_digest,
            dependency_set_digest,
            dependencies_live_until_unix_seconds,
            publication_generation,
            publication_digest,
            dependency_record.receipt_commitment(),
            protected_store_receipt_commitment,
            evidence_context,
        );
        Ok(Self {
            identity,
            verified_bytes,
            root_digest,
            verified_prefix_digest,
            dependency_set_digest,
            dependencies_live_until_unix_seconds,
            dependency_record,
            publication_generation,
            publication_digest,
            journal_record,
            evidence_context,
            completion_digest,
        })
    }

    /// Returns the completed immutable transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact number of verified root-object bytes.
    #[must_use]
    pub const fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// Returns the verified root-object digest.
    #[must_use]
    pub const fn root_digest(&self) -> ObjectDigest {
        self.root_digest
    }

    /// Returns the final verified-prefix commitment.
    #[must_use]
    pub const fn verified_prefix_digest(&self) -> ObjectDigest {
        self.verified_prefix_digest
    }

    /// Returns the canonical commitment to this exact completed transfer.
    #[must_use]
    pub const fn completion_digest(&self) -> ObjectDigest {
        self.completion_digest
    }

    /// Returns the exact verified-dependency-set commitment.
    #[must_use]
    pub const fn dependency_set_digest(&self) -> ObjectDigest {
        self.dependency_set_digest
    }

    /// Returns the exact protected dependency durability capability.
    #[must_use]
    pub const fn protected_dependency_record(&self) -> &ProtectedJournalRecordV1 {
        &self.dependency_record
    }

    /// Reports whether the complete durable dependency inventory remains live.
    #[must_use]
    pub fn dependencies_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.dependency_record
            .context()
            .is_current_at(coordinator_unix_seconds)
            && coordinator_unix_seconds <= self.dependencies_live_until_unix_seconds
    }

    /// Returns the monotonic atomic publication generation.
    #[must_use]
    pub const fn publication_generation(&self) -> u64 {
        self.publication_generation
    }

    /// Returns the immutable atomic-publication effect commitment.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the opaque atomic-publication protected-store receipt.
    #[must_use]
    pub fn protected_store_receipt_commitment(&self) -> ObjectDigest {
        self.journal_record.receipt_commitment()
    }

    /// Returns the exact opaque protected-store record proving publication durability.
    #[must_use]
    pub const fn protected_journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Returns the exact verifier/currentness context for publication.
    #[must_use]
    pub const fn evidence_context(&self) -> AuthenticatedEvidenceContextV1 {
        self.evidence_context
    }
}

/// Carries current policy/owner approval observed for one exact restore scope.
///
/// The value is verifier evidence, not an ownership lease or effect capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRestoreAuthorizationV1 {
    context: AuthenticatedEvidenceContextV1,
    project: ProjectId,
    sandbox: SandboxId,
    destination: NodeId,
    storage_domain_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    restore_scope: RestoreScopeId,
    generation: u64,
    authorization_digest: ObjectDigest,
    verified_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

impl VerifiedRestoreAuthorizationV1 {
    /// Constructs evidence only inside the current policy/owner verifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::RestoreAdmissionMismatch`] for zero
    /// or noncurrent scope, identity, domain, or authorization values.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_owner_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            ProjectId,
            SandboxId,
            NodeId,
            ObjectDigest,
            ObjectDigest,
            ObjectDigest,
            RestoreScopeId,
            u64,
            ObjectDigest,
            u64,
            u64,
        )>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let (
            (
                context,
                project,
                sandbox,
                destination,
                storage_domain_digest,
                audience_digest,
                disclosure_domain_digest,
                restore_scope,
                generation,
                authorization_digest,
                verified_at_unix_seconds,
                valid_until_unix_seconds,
            ),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != context
            || project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || destination.as_bytes() == &[0; 16]
            || storage_domain_digest.as_bytes() == &[0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || restore_scope.as_bytes() == &[0; 16]
            || generation == 0
            || authorization_digest.as_bytes() == &[0; 32]
            || valid_until_unix_seconds <= verified_at_unix_seconds
            || context.node() != destination
            || context.audience_digest() != audience_digest
            || context.disclosure_domain_digest() != disclosure_domain_digest
            || !context.is_current_at(verified_at_unix_seconds)
            || !context.is_current_at(valid_until_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        Ok(Self {
            context,
            project,
            sandbox,
            destination,
            storage_domain_digest,
            audience_digest,
            disclosure_domain_digest,
            restore_scope,
            generation,
            authorization_digest,
            verified_at_unix_seconds,
            valid_until_unix_seconds,
        })
    }

    /// Reports whether authorization is current and bound to the transfer identity.
    #[must_use]
    pub fn is_current_for(
        self,
        identity: SnapshotTransferIdentityV1,
        coordinator_unix_seconds: u64,
    ) -> bool {
        self.project == identity.project()
            && self.sandbox == identity.sandbox()
            && self.destination == identity.destination_node()
            && self.storage_domain_digest == identity.storage_domain_digest()
            && self.audience_digest == identity.audience_digest()
            && self.disclosure_domain_digest == identity.disclosure_domain_digest()
            && self.context.node() == identity.destination_node()
            && self.context.is_current_at(coordinator_unix_seconds)
            && coordinator_unix_seconds >= self.verified_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    /// Returns the exact restore scope.
    #[must_use]
    pub const fn restore_scope(self) -> RestoreScopeId {
        self.restore_scope
    }

    /// Returns the monotonic policy authorization generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the authorization observation commitment.
    #[must_use]
    pub const fn authorization_digest(self) -> ObjectDigest {
        self.authorization_digest
    }

    /// Returns the exact authenticated owner-verifier carrier context.
    #[must_use]
    pub const fn evidence_context(self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Records current policy evidence required to consider restore, without authorizing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRestoreAdmissionV1 {
    identity: SnapshotTransferIdentityV1,
    destination: NodeId,
    destination_capability: CarrierValidatedCapabilityObservationV1,
    authorization: VerifiedRestoreAuthorizationV1,
    restore_scope: RestoreScopeId,
    reauthorization_generation: u64,
    reauthorization_digest: ObjectDigest,
    capability_observation_digest: ObjectDigest,
    capability_carrier_binding_digest: ObjectDigest,
    completion: SnapshotTransferCompletionV1,
    dependency_inventory_digest: ObjectDigest,
}

impl SnapshotRestoreAdmissionV1 {
    /// Evaluates destination capability, dependencies, and reauthorization evidence.
    ///
    /// This creates admission evidence only. It is not an ownership lease,
    /// assignment, restore command, or permission to mutate destination state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] for identity mismatches or malformed
    /// evidence. Policy or capability deficiencies produce a typed blocked result.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_verified_publication(
        manifest: &SnapshotTransferManifestV1,
        completion: SnapshotTransferCompletionV1,
        destination: &CarrierValidatedCapabilityObservationV1,
        authorization: VerifiedRestoreAuthorizationV1,
        coordinator_unix_seconds: u64,
    ) -> Result<SnapshotRestoreAdmissionDecisionV1, InvalidSnapshotTransfer> {
        if completion.identity() != manifest.identity()
            || completion.verified_bytes() != manifest.root().encoded_size()
            || completion.root_digest() != manifest.root().digest()
            || !completion
                .evidence_context()
                .is_current_at(coordinator_unix_seconds)
            || !completion
                .protected_journal_record()
                .context()
                .is_current_at(coordinator_unix_seconds)
            || !authorization.is_current_for(manifest.identity(), coordinator_unix_seconds)
            || authorization.evidence_context().audience_digest() != destination.audience_digest()
            || authorization.evidence_context().coordinator_epoch()
                != destination.coordinator_epoch()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }

        let snapshot = destination.snapshot();
        if snapshot.node() != manifest.identity().destination_node()
            || destination.disclosure_domain_digest()
                != manifest.identity().disclosure_domain_digest()
            || destination.audience_digest() != manifest.identity().audience_digest()
            || !destination.is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        let block = if !completion.dependencies_current_at(coordinator_unix_seconds) {
            Some(SnapshotRestoreBlockReasonV1::MissingDependency)
        } else if snapshot.admission() != NodeAdmissionStateV1::Accepting {
            Some(SnapshotRestoreBlockReasonV1::DestinationAdmissionClosed)
        } else if !snapshot
            .supports_protocol(NodeProtocolV1::SnapshotTransfer, ProtocolVersion::new(1, 0))
        {
            Some(SnapshotRestoreBlockReasonV1::SnapshotTransferProtocolIncompatible)
        } else if snapshot
            .fact(NodeCapabilityKindV1::SnapshotTransfer)
            .is_none()
        {
            Some(SnapshotRestoreBlockReasonV1::SnapshotTransferUnsupported)
        } else if manifest
            .required_features()
            .iter()
            .any(|feature| !snapshot.supports_feature(feature))
        {
            Some(SnapshotRestoreBlockReasonV1::MissingFeature)
        } else {
            None
        };
        if let Some(reason) = block {
            return Ok(SnapshotRestoreAdmissionDecisionV1::Blocked(reason));
        }

        let dependency_inventory_digest = completion.dependency_set_digest();
        Ok(SnapshotRestoreAdmissionDecisionV1::Eligible(Self {
            identity: manifest.identity(),
            destination: snapshot.node(),
            destination_capability: destination.clone(),
            authorization,
            restore_scope: authorization.restore_scope(),
            reauthorization_generation: authorization.generation(),
            reauthorization_digest: authorization.authorization_digest(),
            capability_observation_digest: destination.canonical_observation_digest(),
            capability_carrier_binding_digest: destination.carrier_binding_digest(),
            completion,
            dependency_inventory_digest,
        }))
    }

    /// Returns the exact immutable transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the evaluated destination node.
    #[must_use]
    pub const fn destination(&self) -> NodeId {
        self.destination
    }

    /// Returns the exact carrier-validated destination capability observation.
    #[must_use]
    pub const fn destination_capability(&self) -> &CarrierValidatedCapabilityObservationV1 {
        &self.destination_capability
    }

    /// Returns the exact verifier-issued restore authorization observation.
    #[must_use]
    pub const fn authorization(&self) -> VerifiedRestoreAuthorizationV1 {
        self.authorization
    }

    /// Reports whether every exact admission prerequisite remains current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.destination_capability
            .is_current_at(coordinator_unix_seconds)
            && self
                .authorization
                .is_current_for(self.identity, coordinator_unix_seconds)
            && self
                .completion
                .evidence_context()
                .is_current_at(coordinator_unix_seconds)
            && self
                .completion
                .protected_journal_record()
                .context()
                .is_current_at(coordinator_unix_seconds)
            && self
                .completion
                .dependencies_current_at(coordinator_unix_seconds)
    }

    /// Returns the policy restore scope.
    #[must_use]
    pub const fn restore_scope(&self) -> RestoreScopeId {
        self.restore_scope
    }

    /// Returns the current policy reauthorization generation.
    #[must_use]
    pub const fn reauthorization_generation(&self) -> u64 {
        self.reauthorization_generation
    }

    /// Returns the current policy reauthorization commitment.
    #[must_use]
    pub const fn reauthorization_digest(&self) -> ObjectDigest {
        self.reauthorization_digest
    }

    /// Returns the exact carrier-validated destination capability commitment.
    #[must_use]
    pub const fn capability_observation_digest(&self) -> ObjectDigest {
        self.capability_observation_digest
    }

    /// Returns the authenticated carrier binding for destination capabilities.
    #[must_use]
    pub const fn capability_carrier_binding_digest(&self) -> ObjectDigest {
        self.capability_carrier_binding_digest
    }

    /// Returns the exact integrity-verified transfer completion receipt.
    #[must_use]
    pub const fn transfer_completion_digest(&self) -> ObjectDigest {
        self.completion.completion_digest()
    }

    /// Returns the exact verified and durably published transfer completion.
    #[must_use]
    pub const fn completion(&self) -> &SnapshotTransferCompletionV1 {
        &self.completion
    }

    /// Returns the authenticated verified-dependency inventory commitment.
    #[must_use]
    pub const fn dependency_inventory_digest(&self) -> ObjectDigest {
        self.dependency_inventory_digest
    }
}

/// Explains a fail-closed restore-admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotRestoreBlockReasonV1 {
    /// Destination is cordoned or draining for new placement.
    DestinationAdmissionClosed,
    /// Destination does not implement exact snapshot-transfer v1 semantics.
    SnapshotTransferProtocolIncompatible,
    /// Destination lacks integrity-checked snapshot-transfer support.
    SnapshotTransferUnsupported,
    /// Destination lacks a hard semantic feature from the manifest.
    MissingFeature,
    /// Complete dependency durability/current-liveness proof is absent or stale.
    MissingDependency,
}

/// Reports whether inert restore admission evidence can be constructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotRestoreAdmissionDecisionV1 {
    /// All modeled immutable and current-policy prerequisites are present.
    Eligible(SnapshotRestoreAdmissionV1),
    /// Restore remains blocked without producing effect authority.
    Blocked(SnapshotRestoreBlockReasonV1),
}

fn validate_transfer_chunks(
    encoded_size: u64,
    chunks: &[SnapshotTransferChunkV1],
) -> Result<(), InvalidSnapshotTransfer> {
    if chunks.is_empty() || chunks.len() > MAX_SNAPSHOT_TRANSFER_CHUNKS {
        return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
    }
    let mut expected_offset = 0_u64;
    for (expected_index, chunk) in chunks.iter().enumerate() {
        let Ok(expected_index) = u32::try_from(expected_index) else {
            return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
        };
        if chunk.index() != expected_index || chunk.offset() != expected_offset {
            return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
        }
        expected_offset = expected_offset
            .checked_add(u64::from(chunk.length()))
            .ok_or(InvalidSnapshotTransfer::ChunksNotCanonical)?;
    }
    if expected_offset != encoded_size {
        return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
    }
    Ok(())
}

fn staged_prefix_commitment(
    identity: SnapshotTransferIdentityV1,
    checkpoint: SnapshotTransferResumeV1,
    staged_prefix: &[u8],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.snapshot-transfer.staged-prefix.v1\0");
    hasher.update(identity.operation().as_bytes());
    hasher.update(identity.manifest_digest().as_bytes());
    hasher.update(identity.destination_node().as_bytes());
    hasher.update(identity.storage_domain_digest().as_bytes());
    hasher.update(identity.audience_digest().as_bytes());
    hasher.update(identity.disclosure_domain_digest().as_bytes());
    hasher.update(checkpoint.next_chunk().to_be_bytes());
    hasher.update(checkpoint.verified_prefix_digest().as_bytes());
    hasher.update((staged_prefix.len() as u64).to_be_bytes());
    hasher.update(Sha256::digest(staged_prefix));
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn snapshot_transfer_completion_digest(
    identity: SnapshotTransferIdentityV1,
    verified_bytes: u64,
    root_digest: ObjectDigest,
    verified_prefix_digest: ObjectDigest,
    dependency_set_digest: ObjectDigest,
    dependencies_live_until_unix_seconds: u64,
    publication_generation: u64,
    publication_digest: ObjectDigest,
    dependency_store_receipt_commitment: ObjectDigest,
    protected_store_receipt_commitment: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.snapshot-transfer.completion.v1\0");
    hasher.update(identity.operation().as_bytes());
    hasher.update(identity.project().as_bytes());
    hasher.update(identity.sandbox().as_bytes());
    hasher.update(identity.incarnation().as_bytes());
    hasher.update(identity.assignment_epoch().get().to_be_bytes());
    hasher.update(identity.desired_generation().get().to_be_bytes());
    hasher.update(identity.assignment_digest().as_bytes());
    hasher.update(identity.snapshot().as_bytes());
    hasher.update(identity.source_node().as_bytes());
    hasher.update(identity.destination_node().as_bytes());
    hasher.update(identity.storage_domain_digest().as_bytes());
    hasher.update(identity.audience_digest().as_bytes());
    hasher.update(identity.disclosure_domain_digest().as_bytes());
    hasher.update(identity.manifest_digest().as_bytes());
    hasher.update(verified_bytes.to_be_bytes());
    hasher.update(root_digest.as_bytes());
    hasher.update(verified_prefix_digest.as_bytes());
    hasher.update(dependency_set_digest.as_bytes());
    hasher.update(dependencies_live_until_unix_seconds.to_be_bytes());
    hasher.update(publication_generation.to_be_bytes());
    hasher.update(publication_digest.as_bytes());
    hasher.update(dependency_store_receipt_commitment.as_bytes());
    hasher.update(protected_store_receipt_commitment.as_bytes());
    hasher.update(context.node().as_bytes());
    hasher.update(context.lineage().digest().as_bytes());
    hasher.update(context.audience_digest().as_bytes());
    hasher.update(context.disclosure_domain_digest().as_bytes());
    hasher.update(context.carrier_binding_digest().as_bytes());
    hasher.update(context.canonical_frame_digest().as_bytes());
    hasher.update(context.canonical_frame_bytes().to_be_bytes());
    hasher.update(context.coordinator_epoch().to_be_bytes());
    hasher.update(context.verified_at_unix_seconds().to_be_bytes());
    hasher.update(context.valid_until_unix_seconds().to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn hash_descriptor(hasher: &mut Sha256, descriptor: &ObjectDescriptor) {
    let media_type = descriptor.media_type().as_str();
    hasher.update((media_type.len() as u16).to_be_bytes());
    hasher.update(media_type.as_bytes());
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
}

fn is_inert_transfer_dependency(media_type: PortableMediaType) -> bool {
    matches!(
        media_type,
        PortableMediaType::Content
            | PortableMediaType::Directory
            | PortableMediaType::Tree
            | PortableMediaType::Delta
            | PortableMediaType::View
            | PortableMediaType::Environment
            | PortableMediaType::Optimization
            | PortableMediaType::SandboxSpec
            | PortableMediaType::Policy
            | PortableMediaType::Snapshot
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_manifest_commitment(
    operation: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    snapshot: SnapshotId,
    source_node: NodeId,
    destination_node: NodeId,
    storage_domain_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    version: SnapshotTransferVersionV1,
    root: &ObjectDescriptor,
    chunks: &[SnapshotTransferChunkV1],
    dependencies: &[ObjectDescriptor],
    required_features: &[aos_sandbox_core::FeatureRef],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.snapshot-transfer-manifest.v1\0");
    hasher.update(operation.as_bytes());
    hasher.update(project.as_bytes());
    hasher.update(sandbox.as_bytes());
    hasher.update(incarnation.as_bytes());
    hasher.update(assignment_epoch.get().to_be_bytes());
    hasher.update(desired_generation.get().to_be_bytes());
    hasher.update(assignment_digest.as_bytes());
    hasher.update(snapshot.as_bytes());
    hasher.update(source_node.as_bytes());
    hasher.update(destination_node.as_bytes());
    hasher.update(storage_domain_digest.as_bytes());
    hasher.update(audience_digest.as_bytes());
    hasher.update(disclosure_domain_digest.as_bytes());
    hasher.update(version.major().to_be_bytes());
    hasher.update(version.minor().to_be_bytes());
    hash_descriptor(&mut hasher, root);
    hasher.update((chunks.len() as u32).to_be_bytes());
    for chunk in chunks {
        hasher.update(chunk.index().to_be_bytes());
        hasher.update(chunk.offset().to_be_bytes());
        hasher.update(chunk.length().to_be_bytes());
        hasher.update(chunk.digest().as_bytes());
    }
    hasher.update((dependencies.len() as u32).to_be_bytes());
    for dependency in dependencies {
        hash_descriptor(&mut hasher, dependency);
    }
    hasher.update((required_features.len() as u32).to_be_bytes());
    for feature in required_features {
        hasher.update((feature.namespace().len() as u16).to_be_bytes());
        hasher.update(feature.namespace().as_bytes());
        hasher.update(feature.major().to_be_bytes());
        hasher.update(feature.minor().to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
