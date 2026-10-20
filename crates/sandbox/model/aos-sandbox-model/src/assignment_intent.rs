//! Defines non-authorizing assignment intent and its immutable capability binding.
//!
//! These records contain desired-state semantics and historical scheduling DATA.
//! Acceptance and effects still require the actual independent ownership,
//! Guardian, native-journal and current authenticated observation originals.

use crate::state::DesiredSandboxState;
use crate::{
    AssignmentEpoch, CanonicalAssignmentManifestV1, DesiredGeneration, IncarnationId, NodeBootId,
    NodeBootLineageV1, NodeId, ObjectDigest, ObservationSequence, ResourceVector, SandboxId,
};

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
}

impl AssignmentIntentV1 {
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
