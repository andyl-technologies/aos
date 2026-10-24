//! Canonical drain intent, bounded targets and closed progress DATA.
//!
//! A directive neither issues a lease nor authorizes a stop, snapshot, release
//! or replacement. Actual Guardian, containment, durable byte/publication and
//! current protected-store evidence remain with their native issuers.

use sha2::{Digest as _, Sha256};

use crate::{
    AssignmentEpoch, AssignmentIntentV1, DesiredGeneration, IncarnationId, NodeId, ObjectDigest,
    OperationId, SandboxId,
};

/// Maximum assignments carried by one node drain operation.
pub const MAX_DRAIN_ASSIGNMENTS: usize = 4_096;

/// Selects the scope of a node admission closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeDrainModeV1 {
    /// Closes new placement without changing existing assignments.
    CordonOnly,
    /// Moves or stops selected assignments while retaining the node.
    Evacuate,
    /// Evacuates selected assignments before permanent node removal.
    Decommission,
}

/// Selects the desired non-authorizing drain workflow for one assignment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DrainAssignmentStrategyV1 {
    /// Creates a durable snapshot, stops, and makes the sandbox eligible for replacement.
    SnapshotStopAndReplace,
    /// Stops a reconstructible sandbox and makes it eligible for replacement.
    StopAndReplace,
    /// Stops the sandbox while retaining its durable state on this node.
    StopInPlace,
    /// Leaves an already stopped durable sandbox in place.
    LeaveStopped,
}

/// Identifies one exact assignment selected by a drain operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DrainAssignmentPlanV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    strategy: DrainAssignmentStrategyV1,
}

impl DrainAssignmentPlanV1 {
    /// Constructs one inert exact assignment target for canonical decoding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::Unspecified`] for a zero identity,
    /// generation, or assignment commitment.
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        strategy: DrainAssignmentStrategyV1,
    ) -> Result<Self, InvalidDrainModel> {
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || desired_generation.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidDrainModel::Unspecified);
        }
        Ok(Self {
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            assignment_digest,
            strategy,
        })
    }

    /// Derives one drain target from current canonical assignment intent.
    #[must_use]
    pub const fn from_intent(
        intent: &AssignmentIntentV1,
        strategy: DrainAssignmentStrategyV1,
    ) -> Self {
        Self {
            sandbox: intent.sandbox(),
            incarnation: intent.incarnation(),
            epoch: intent.epoch(),
            desired_generation: intent.desired_generation(),
            assignment_digest: intent.assignment_digest(),
            strategy,
        }
    }

    /// Returns the logical sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact runtime incarnation to drain.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the assignment epoch to drain.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.epoch
    }

    /// Returns the exact desired generation selected for draining.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the canonical assignment digest to drain.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the desired drain workflow.
    #[must_use]
    pub const fn strategy(self) -> DrainAssignmentStrategyV1 {
        self.strategy
    }
}

/// Reports malformed or contradictory drain state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidDrainModel {
    /// An operation, node, generation, sequence, or assignment uses a zero sentinel.
    #[error("drain model contains an unspecified identity or generation")]
    Unspecified,
    /// Assignment targets are oversized, duplicated, or not in canonical order.
    #[error("drain assignments must be a canonical set of at most 4096 entries")]
    AssignmentsNotCanonical,
    /// A cordon-only operation unexpectedly carries assignment workflows.
    #[error("cordon-only drain directive cannot carry assignment workflows")]
    CordonHasAssignments,
    /// A decommission directive would leave durable state on the removed node.
    #[error("node decommission requires replacement for every selected assignment")]
    IncompatibleStrategy,
    /// Cordon-only carries a deadline, or evacuation lacks a future deadline.
    #[error("drain deadline is incompatible with the requested node drain mode")]
    InvalidDeadline,
    /// An observation names another drain operation or node.
    #[error("drain observation does not match its directive")]
    DirectiveMismatch,
    /// One boot generation names two different opaque boot identities.
    #[error("drain observation boot generation was reused")]
    BootConflict,
    /// A newer boot does not directly extend the last authenticated lineage.
    #[error("drain observation skipped or contradicted durable boot lineage")]
    BootLineageGap,
    /// One sequence names different drain observations within a node boot.
    #[error("drain observation sequence was reused for different content")]
    SequenceConflict,
    /// Per-assignment observations do not exactly cover the directive targets.
    #[error("drain observation must cover every directive assignment exactly once")]
    ObservationCoverageMismatch,
    /// Node-wide phase contradicts its per-assignment progress.
    #[error("drain phase is inconsistent with per-assignment progress")]
    ProgressMismatch,
    /// Progress lacks snapshot, containment, guardian, or release evidence.
    #[error("drain progress lacks required evidence or carries contradictory evidence")]
    EvidenceMismatch,
    /// A durable journal record does not commit the exact directive generation.
    #[error("drain directive journal evidence does not match")]
    JournalMismatch,
    /// A drain phase transition is not in the closed state graph.
    #[error("drain observation contains an invalid phase transition")]
    InvalidPhaseTransition,
}

/// Stores one accepted node cordon or drain desired-state generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainDirectiveV1 {
    operation: OperationId,
    node: NodeId,
    generation: u64,
    mode: NodeDrainModeV1,
    accepted_at_unix_seconds: u64,
    deadline_unix_seconds: Option<u64>,
    assignments: Vec<DrainAssignmentPlanV1>,
}

impl DrainDirectiveV1 {
    /// Constructs one bounded node drain directive.
    ///
    /// The deadline controls operation policy only. It is not an ownership
    /// lease deadline and cannot extend or replace guardian containment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel`] for sentinel identities, noncanonical
    /// targets, assignment work in a cordon-only directive, or an invalid
    /// evacuation deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: OperationId,
        node: NodeId,
        generation: u64,
        mode: NodeDrainModeV1,
        accepted_at_unix_seconds: u64,
        deadline_unix_seconds: Option<u64>,
        assignments: Vec<DrainAssignmentPlanV1>,
    ) -> Result<Self, InvalidDrainModel> {
        if operation.as_bytes() == &[0; 16] || node.as_bytes() == &[0; 16] || generation == 0 {
            return Err(InvalidDrainModel::Unspecified);
        }
        if assignments.len() > MAX_DRAIN_ASSIGNMENTS
            || !assignments
                .windows(2)
                .all(|pair| pair[0].sandbox() < pair[1].sandbox())
        {
            return Err(InvalidDrainModel::AssignmentsNotCanonical);
        }
        if mode == NodeDrainModeV1::CordonOnly && !assignments.is_empty() {
            return Err(InvalidDrainModel::CordonHasAssignments);
        }
        if mode == NodeDrainModeV1::Decommission
            && assignments.iter().any(|assignment| {
                matches!(
                    assignment.strategy(),
                    DrainAssignmentStrategyV1::StopInPlace
                        | DrainAssignmentStrategyV1::LeaveStopped
                )
            })
        {
            return Err(InvalidDrainModel::IncompatibleStrategy);
        }
        let invalid_deadline = match mode {
            NodeDrainModeV1::CordonOnly => deadline_unix_seconds.is_some(),
            NodeDrainModeV1::Evacuate | NodeDrainModeV1::Decommission => {
                deadline_unix_seconds.is_none_or(|deadline| deadline <= accepted_at_unix_seconds)
            }
        };
        if invalid_deadline {
            return Err(InvalidDrainModel::InvalidDeadline);
        }

        Ok(Self {
            operation,
            node,
            generation,
            mode,
            accepted_at_unix_seconds,
            deadline_unix_seconds,
            assignments,
        })
    }

    /// Returns the durable drain operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the target node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the monotonic drain desired-state generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the requested drain scope.
    #[must_use]
    pub const fn mode(&self) -> NodeDrainModeV1 {
        self.mode
    }

    /// Returns the diagnostic acceptance time.
    #[must_use]
    pub const fn accepted_at_unix_seconds(&self) -> u64 {
        self.accepted_at_unix_seconds
    }

    /// Returns the operation deadline when evacuation was requested.
    #[must_use]
    pub const fn deadline_unix_seconds(&self) -> Option<u64> {
        self.deadline_unix_seconds
    }

    /// Returns exact assignment workflows in canonical sandbox order.
    #[must_use]
    pub fn assignments(&self) -> &[DrainAssignmentPlanV1] {
        &self.assignments
    }
}

/// Computes the canonical commitment to non-authorizing drain desired state.
#[must_use]
pub fn drain_directive_digest(directive: &DrainDirectiveV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.drain-directive.v1\0");
    hasher.update(directive.operation().as_bytes());
    hasher.update(directive.node().as_bytes());
    hasher.update(directive.generation().to_be_bytes());
    hasher.update([match directive.mode() {
        NodeDrainModeV1::CordonOnly => 0,
        NodeDrainModeV1::Evacuate => 1,
        NodeDrainModeV1::Decommission => 2,
    }]);
    hasher.update(directive.accepted_at_unix_seconds().to_be_bytes());
    match directive.deadline_unix_seconds() {
        Some(deadline) => {
            hasher.update([1]);
            hasher.update(deadline.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update((directive.assignments().len() as u32).to_be_bytes());
    for assignment in directive.assignments() {
        hasher.update(assignment.sandbox().as_bytes());
        hasher.update(assignment.incarnation().as_bytes());
        hasher.update(assignment.epoch().get().to_be_bytes());
        hasher.update(assignment.desired_generation().get().to_be_bytes());
        hasher.update(assignment.assignment_digest().as_bytes());
        hasher.update([match assignment.strategy() {
            DrainAssignmentStrategyV1::SnapshotStopAndReplace => 0,
            DrainAssignmentStrategyV1::StopAndReplace => 1,
            DrainAssignmentStrategyV1::StopInPlace => 2,
            DrainAssignmentStrategyV1::LeaveStopped => 3,
        }]);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Describes node-wide drain progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainPhaseV1 {
    /// The node still accepts new placement.
    Requested,
    /// New placement is closed.
    Cordoned,
    /// Assignment-specific workflows are in progress.
    Draining,
    /// Every selected assignment is safely stopped or contained.
    Contained,
    /// Selected assignments are eligible for separate replacement planning.
    ReadyForReassignment,
    /// Drain policy completed.
    Complete,
    /// Progress needs capacity, a dependency, or operator action.
    Blocked,
}

impl DrainPhaseV1 {
    /// Reports whether `next` is a valid edge or idempotent observation.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Requested, Self::Cordoned | Self::Blocked)
                    | (
                        Self::Cordoned,
                        Self::Draining | Self::Complete | Self::Blocked
                    )
                    | (Self::Draining, Self::Contained | Self::Blocked)
                    | (
                        Self::Contained,
                        Self::ReadyForReassignment | Self::Complete | Self::Blocked
                    )
                    | (Self::ReadyForReassignment, Self::Complete | Self::Blocked)
                    | (
                        Self::Blocked,
                        Self::Cordoned | Self::Draining | Self::Contained
                    )
            )
    }
}

/// Classifies why one assignment drain cannot progress.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DrainBlockReasonV1 {
    /// A durable snapshot could not be committed.
    SnapshotUnavailable,
    /// A declared external dependency is missing.
    MissingDependency,
    /// Current ownership authority is unavailable.
    OwnershipAuthorityUnavailable,
    /// The guardian has not yet proven containment.
    ContainmentUnconfirmed,
    /// Residual node-local resources require operator inspection.
    ResidualState,
    /// Destination placement has no compatible node.
    DestinationUnavailable,
}

/// Describes progress for one exact assignment drain workflow.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DrainAssignmentProgressV1 {
    /// Work has not begun.
    Pending,
    /// Quiesce or snapshot work is in progress.
    Preparing,
    /// Payload stop and guardian containment are in progress.
    Stopping,
    /// Payload and assignment-scoped external access are contained.
    Contained,
    /// Node-local assignment resources are released.
    Released,
    /// Progress is blocked for a stable reason.
    Blocked(DrainBlockReasonV1),
}

impl DrainAssignmentProgressV1 {
    /// Reports whether `next` advances or repeats per-assignment drain progress.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::Pending,
                    Self::Preparing | Self::Stopping | Self::Contained | Self::Blocked(_)
                ) | (
                    Self::Preparing,
                    Self::Stopping | Self::Contained | Self::Blocked(_)
                ) | (Self::Stopping, Self::Contained | Self::Blocked(_))
                    | (Self::Contained, Self::Released | Self::Blocked(_))
                    | (
                        Self::Blocked(_),
                        Self::Preparing | Self::Stopping | Self::Contained | Self::Released
                    )
            )
    }
}

/// Selects the guardian fact committed by containment evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DrainGuardianStateV1 {
    /// The guardian is armed for the current assignment epoch.
    Armed,
    /// Ownership expiry was observed and fail-closed containment completed.
    ExpiredAndContained,
    /// Explicit stop containment completed while current authority remained valid.
    ExplicitlyContained,
}
