//! Cordon and drain desired-state and observation models.
//!
//! Draining is modeled as an ordered controller operation. A plan can request
//! snapshot, stop, containment, and release observations, but it never grants
//! a destination assignment or ownership authority. Reassignment remains a
//! separate fenced controller transaction followed by independent ownership
//! acquisition.

use std::cmp::Ordering;

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDigest, ObservationSequence,
    OperationId, SandboxId, SnapshotId,
};

use super::assignment::{AssignmentIntentV1, SnapshotTransferCompletionV1};
use super::capability::{NodeBootId, NodeBootLineageV1};
use super::evidence::AuthenticatedEvidenceContextV1;
use super::evidence_authority::VerifierEvidenceGrantV1;
use super::journal::{JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1};

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

/// Reports a durable drain-generation reduction result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainDirectiveApplyOutcomeV1 {
    /// The next contiguous drain generation was installed.
    Applied,
    /// The exact current directive was replayed.
    Replay,
    /// An older directive was ignored.
    Stale,
}

/// Reduces node drain desired state across generations with equivocation fencing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainDirectiveReducerV1 {
    node: NodeId,
    current: Option<DrainDirectiveV1>,
    current_record: Option<ProtectedJournalRecordV1>,
}

impl DrainDirectiveReducerV1 {
    /// Constructs a reducer for one nonzero node.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::Unspecified`] for the zero node.
    pub fn new(node: NodeId) -> Result<Self, InvalidDrainModel> {
        if node.as_bytes() == &[0; 16] {
            return Err(InvalidDrainModel::Unspecified);
        }
        Ok(Self {
            node,
            current: None,
            current_record: None,
        })
    }

    /// Applies one exact contiguous generation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel`] for expired durability evidence, another
    /// node, a generation gap, or same-generation equivocation.
    pub fn apply(
        &mut self,
        directive: DrainDirectiveV1,
        journal_record: ProtectedJournalRecordV1,
        coordinator_unix_seconds: u64,
    ) -> Result<DrainDirectiveApplyOutcomeV1, InvalidDrainModel> {
        let directive_digest = drain_directive_digest(&directive);
        if journal_record.record().domain() != MultiNodeJournalDomainV1::Drain
            || journal_record.record().operation() != directive.operation()
            || journal_record.record().payload_digest() != directive_digest
            || journal_record.record().effect_state() != JournalEffectStateV1::IntentCommitted
            || journal_record.record().effect_digest() != directive_digest
            || journal_record.context().node() != directive.node()
            || !journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
            || directive.accepted_at_unix_seconds() > coordinator_unix_seconds
        {
            return Err(InvalidDrainModel::JournalMismatch);
        }
        if directive.node() != self.node {
            return Err(InvalidDrainModel::DirectiveMismatch);
        }
        let Some(current) = &self.current else {
            self.current = Some(directive);
            self.current_record = Some(journal_record);
            return Ok(DrainDirectiveApplyOutcomeV1::Applied);
        };
        match directive.generation().cmp(&current.generation()) {
            Ordering::Less => Ok(DrainDirectiveApplyOutcomeV1::Stale),
            Ordering::Equal
                if directive == *current
                    && self.current_record.as_ref() == Some(&journal_record) =>
            {
                Ok(DrainDirectiveApplyOutcomeV1::Replay)
            }
            Ordering::Equal => Err(InvalidDrainModel::SequenceConflict),
            Ordering::Greater => {
                let expected = current
                    .generation()
                    .checked_add(1)
                    .ok_or(InvalidDrainModel::InvalidPhaseTransition)?;
                if directive.generation() != expected {
                    return Err(InvalidDrainModel::InvalidPhaseTransition);
                }
                let current_record = self
                    .current_record
                    .as_ref()
                    .ok_or(InvalidDrainModel::JournalMismatch)?;
                if journal_record.record().sequence()
                    != current_record.record().sequence().saturating_add(1)
                    || journal_record.record().predecessor_digest()
                        != current_record.record().digest()
                {
                    return Err(InvalidDrainModel::JournalMismatch);
                }
                self.current = Some(directive);
                self.current_record = Some(journal_record);
                Ok(DrainDirectiveApplyOutcomeV1::Applied)
            }
        }
    }

    /// Returns the latest accepted drain generation while its receipt is current.
    #[must_use]
    pub fn current_at(&self, coordinator_unix_seconds: u64) -> Option<&DrainDirectiveV1> {
        self.current.as_ref().filter(|_| {
            self.current_record
                .as_ref()
                .is_some_and(|record| record.context().is_current_at(coordinator_unix_seconds))
        })
    }

    /// Returns the exact journal record while its protected receipt remains current.
    #[must_use]
    pub fn current_record_at(
        &self,
        coordinator_unix_seconds: u64,
    ) -> Option<&ProtectedJournalRecordV1> {
        self.current_record
            .as_ref()
            .filter(|record| record.context().is_current_at(coordinator_unix_seconds))
    }
}

fn drain_directive_digest(directive: &DrainDirectiveV1) -> ObjectDigest {
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

/// Commits a guardian observation used by drain containment decisions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DrainGuardianEvidenceV1 {
    context: AuthenticatedEvidenceContextV1,
    assignment_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    state: DrainGuardianStateV1,
    evidence_digest: ObjectDigest,
}

impl DrainGuardianEvidenceV1 {
    /// Constructs current guardian evidence for one exact assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] for zero commitments or generation.
    pub(super) fn from_guardian_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            ObjectDigest,
            u64,
            ObjectDigest,
            DrainGuardianStateV1,
            ObjectDigest,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (context, assignment_digest, lease_generation, lease_digest, state, evidence_digest),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != context
            || assignment_digest.as_bytes() == &[0; 32]
            || lease_generation == 0
            || lease_digest.as_bytes() == &[0; 32]
            || evidence_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            context,
            assignment_digest,
            lease_generation,
            lease_digest,
            state,
            evidence_digest,
        })
    }

    /// Returns the exact assignment commitment.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the observed ownership lease generation.
    #[must_use]
    pub const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Returns the exact ownership-lease commitment without exposing authority.
    #[must_use]
    pub const fn lease_digest(self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the guardian's closed state.
    #[must_use]
    pub const fn state(self) -> DrainGuardianStateV1 {
        self.state
    }

    /// Returns the authenticated guardian fact commitment.
    #[must_use]
    pub const fn evidence_digest(self) -> ObjectDigest {
        self.evidence_digest
    }

    /// Returns the exact carrier/audience/currentness context.
    #[must_use]
    pub const fn context(self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Commits a durable snapshot completed before destructive drain progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainSnapshotEvidenceV1 {
    context: AuthenticatedEvidenceContextV1,
    guardian: DrainGuardianEvidenceV1,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    completion: SnapshotTransferCompletionV1,
}

impl DrainSnapshotEvidenceV1 {
    /// Constructs immutable snapshot and transfer-manifest evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] for a zero identity or digest.
    pub(super) fn from_snapshot_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            DrainGuardianEvidenceV1,
            DrainAssignmentPlanV1,
            SnapshotTransferCompletionV1,
            u64,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (context, guardian, plan, completion, verified_at_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != context
            || guardian.assignment_digest() != plan.assignment_digest()
            || guardian.state() != DrainGuardianStateV1::Armed
            || guardian.context().node() != context.node()
            || guardian.context().lineage() != context.lineage()
            || guardian.context().audience_digest() != context.audience_digest()
            || guardian.context().disclosure_domain_digest() != context.disclosure_domain_digest()
            || !guardian.context().is_current_at(verified_at_unix_seconds)
            || completion.identity().sandbox() != plan.sandbox()
            || completion.identity().incarnation() != plan.incarnation()
            || completion.identity().assignment_epoch() != plan.epoch()
            || completion.identity().desired_generation() != plan.desired_generation()
            || completion.identity().assignment_digest() != plan.assignment_digest()
            || completion.identity().source_node() != context.node()
            || completion.identity().audience_digest() != context.audience_digest()
            || completion.identity().disclosure_domain_digest()
                != context.disclosure_domain_digest()
            || completion.root_digest().as_bytes() == &[0; 32]
            || !completion
                .evidence_context()
                .is_current_at(verified_at_unix_seconds)
            || !completion
                .protected_journal_record()
                .context()
                .is_current_at(verified_at_unix_seconds)
            || !completion.dependencies_current_at(verified_at_unix_seconds)
            || !context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            context,
            guardian,
            sandbox: plan.sandbox(),
            incarnation: plan.incarnation(),
            epoch: plan.epoch(),
            desired_generation: plan.desired_generation(),
            assignment_digest: plan.assignment_digest(),
            completion,
        })
    }

    /// Returns the durable snapshot identity.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotId {
        self.completion.identity().snapshot()
    }

    /// Returns the immutable snapshot commitment.
    #[must_use]
    pub const fn snapshot_digest(&self) -> ObjectDigest {
        self.completion.root_digest()
    }

    /// Returns the snapshot-transfer manifest commitment.
    #[must_use]
    pub const fn transfer_manifest_digest(&self) -> ObjectDigest {
        self.completion.identity().manifest_digest()
    }

    /// Returns the exact sandbox bound to the snapshot.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact assignment incarnation captured by the snapshot.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the exact assignment epoch captured by the snapshot.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.epoch
    }

    /// Returns the exact desired generation captured by the snapshot.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the exact drained assignment commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the exact carrier/audience/currentness context.
    #[must_use]
    pub const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }

    /// Returns the exact armed lease/Guardian evidence used for snapshotting.
    #[must_use]
    pub const fn guardian(&self) -> DrainGuardianEvidenceV1 {
        self.guardian
    }

    /// Returns the exact verified and atomically published transfer completion.
    #[must_use]
    pub const fn completion(&self) -> &SnapshotTransferCompletionV1 {
        &self.completion
    }
}

/// Commits payload, external-access, and guardian containment facts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DrainContainmentEvidenceV1 {
    assignment_digest: ObjectDigest,
    payload_stopped: bool,
    network_default_drop: bool,
    guardian: DrainGuardianEvidenceV1,
    evidence_digest: ObjectDigest,
}

impl DrainContainmentEvidenceV1 {
    /// Constructs fail-closed containment evidence for one assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] unless payload stop,
    /// network default-drop, assignment binding, and a contained guardian fact
    /// are all present.
    pub(super) fn from_containment_verifier(
        grant: VerifierEvidenceGrantV1<(
            ObjectDigest,
            bool,
            bool,
            DrainGuardianEvidenceV1,
            ObjectDigest,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (assignment_digest, payload_stopped, network_default_drop, guardian, evidence_digest),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != guardian.context()
            || assignment_digest.as_bytes() == &[0; 32]
            || assignment_digest != guardian.assignment_digest()
            || !payload_stopped
            || !network_default_drop
            || guardian.state() == DrainGuardianStateV1::Armed
            || evidence_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            assignment_digest,
            payload_stopped,
            network_default_drop,
            guardian,
            evidence_digest,
        })
    }

    /// Returns the exact contained assignment commitment.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Reports the committed payload-stop fact.
    #[must_use]
    pub const fn payload_stopped(self) -> bool {
        self.payload_stopped
    }

    /// Reports the committed external-network default-drop fact.
    #[must_use]
    pub const fn network_default_drop(self) -> bool {
        self.network_default_drop
    }

    /// Returns the exact guardian evidence.
    #[must_use]
    pub const fn guardian(self) -> DrainGuardianEvidenceV1 {
        self.guardian
    }

    /// Returns the aggregate containment commitment.
    #[must_use]
    pub const fn evidence_digest(self) -> ObjectDigest {
        self.evidence_digest
    }
}

/// Commits node-local resource release after containment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DrainReleaseEvidenceV1 {
    context: AuthenticatedEvidenceContextV1,
    assignment_digest: ObjectDigest,
    containment_digest: ObjectDigest,
    released_inventory_digest: ObjectDigest,
}

impl DrainReleaseEvidenceV1 {
    /// Constructs release evidence for one exact assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] for a zero commitment.
    pub(super) fn from_release_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            DrainContainmentEvidenceV1,
            ObjectDigest,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (context, containment, released_inventory_digest),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let assignment_digest = containment.assignment_digest();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != context
            || assignment_digest.as_bytes() == &[0; 32]
            || containment.evidence_digest().as_bytes() == &[0; 32]
            || released_inventory_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            context,
            assignment_digest,
            containment_digest: containment.evidence_digest(),
            released_inventory_digest,
        })
    }

    /// Returns the exact released assignment commitment.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the exact containment commitment that preceded release.
    #[must_use]
    pub const fn containment_digest(self) -> ObjectDigest {
        self.containment_digest
    }

    /// Returns the post-release node inventory commitment.
    #[must_use]
    pub const fn released_inventory_digest(self) -> ObjectDigest {
        self.released_inventory_digest
    }

    /// Returns the exact carrier/audience/currentness context.
    #[must_use]
    pub const fn context(self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Correlates assignment drain progress with one planned sandbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainAssignmentObservationV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    progress: DrainAssignmentProgressV1,
    snapshot_evidence: Option<DrainSnapshotEvidenceV1>,
    containment_evidence: Option<DrainContainmentEvidenceV1>,
    release_evidence: Option<DrainReleaseEvidenceV1>,
}

impl DrainAssignmentObservationV1 {
    /// Decodes node-reported progress without manufacturing verifier evidence.
    ///
    /// The resulting row can describe progress for diagnostics, but reducers
    /// reject containment, release, and snapshot-dependent transitions until
    /// [`Self::from_authenticated_node`] consumes the required opaque evidence.
    pub(super) fn from_reported_progress(
        plan: DrainAssignmentPlanV1,
        progress: DrainAssignmentProgressV1,
    ) -> Self {
        Self {
            sandbox: plan.sandbox(),
            incarnation: plan.incarnation(),
            epoch: plan.epoch(),
            desired_generation: plan.desired_generation(),
            assignment_digest: plan.assignment_digest(),
            progress,
            snapshot_evidence: None,
            containment_evidence: None,
            release_evidence: None,
        }
    }

    /// Derives progress for one exact planned assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] when evidence does not
    /// match the exact assignment, strategy, or reported progress.
    pub(super) fn from_authenticated_node(
        plan: DrainAssignmentPlanV1,
        progress: DrainAssignmentProgressV1,
        snapshot_evidence: Option<DrainSnapshotEvidenceV1>,
        containment_evidence: Option<DrainContainmentEvidenceV1>,
        release_evidence: Option<DrainReleaseEvidenceV1>,
    ) -> Result<Self, InvalidDrainModel> {
        let needs_containment = matches!(
            progress,
            DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
        );
        let needs_release = progress == DrainAssignmentProgressV1::Released;
        let needs_snapshot = plan.strategy() == DrainAssignmentStrategyV1::SnapshotStopAndReplace
            && matches!(
                progress,
                DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
            );
        let snapshot_allowed = progress != DrainAssignmentProgressV1::Pending;
        let containment_allowed = matches!(
            progress,
            DrainAssignmentProgressV1::Contained
                | DrainAssignmentProgressV1::Released
                | DrainAssignmentProgressV1::Blocked(_)
        );
        let release_allowed = matches!(
            progress,
            DrainAssignmentProgressV1::Released | DrainAssignmentProgressV1::Blocked(_)
        );
        if (needs_snapshot && snapshot_evidence.is_none())
            || (plan.strategy() != DrainAssignmentStrategyV1::SnapshotStopAndReplace
                && snapshot_evidence.is_some())
            || (!snapshot_allowed && snapshot_evidence.is_some())
            || (needs_containment && containment_evidence.is_none())
            || (needs_release && release_evidence.is_none())
            || (!containment_allowed && containment_evidence.is_some())
            || (!release_allowed && release_evidence.is_some())
            || (release_evidence.is_some() && containment_evidence.is_none())
            || (release_evidence.is_some()
                && plan.strategy() == DrainAssignmentStrategyV1::SnapshotStopAndReplace
                && snapshot_evidence.is_none())
            || containment_evidence
                .is_some_and(|evidence| evidence.assignment_digest() != plan.assignment_digest())
            || release_evidence
                .is_some_and(|evidence| evidence.assignment_digest() != plan.assignment_digest())
            || release_evidence
                .zip(containment_evidence)
                .is_some_and(|(release, containment)| {
                    release.containment_digest() != containment.evidence_digest()
                })
            || snapshot_evidence.as_ref().is_some_and(|evidence| {
                evidence.sandbox() != plan.sandbox()
                    || evidence.incarnation() != plan.incarnation()
                    || evidence.epoch() != plan.epoch()
                    || evidence.desired_generation() != plan.desired_generation()
                    || evidence.assignment_digest() != plan.assignment_digest()
            })
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            sandbox: plan.sandbox(),
            incarnation: plan.incarnation(),
            epoch: plan.epoch(),
            desired_generation: plan.desired_generation(),
            assignment_digest: plan.assignment_digest(),
            progress,
            snapshot_evidence,
            containment_evidence,
            release_evidence,
        })
    }

    /// Returns the planned sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact drained runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the exact drained assignment epoch.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.epoch
    }

    /// Returns the exact desired generation selected for draining.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the exact drained assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns its observed drain progress.
    #[must_use]
    pub const fn progress(&self) -> DrainAssignmentProgressV1 {
        self.progress
    }

    /// Returns durable snapshot evidence when required by strategy and progress.
    #[must_use]
    pub const fn snapshot_evidence(&self) -> Option<&DrainSnapshotEvidenceV1> {
        self.snapshot_evidence.as_ref()
    }

    /// Returns payload, network, and guardian containment evidence.
    #[must_use]
    pub const fn containment_evidence(&self) -> Option<DrainContainmentEvidenceV1> {
        self.containment_evidence
    }

    /// Returns node-local resource release evidence.
    #[must_use]
    pub const fn release_evidence(&self) -> Option<DrainReleaseEvidenceV1> {
        self.release_evidence
    }

    /// Reports whether this observation names one exact plan row.
    #[must_use]
    pub fn matches(&self, plan: DrainAssignmentPlanV1) -> bool {
        self.sandbox == plan.sandbox()
            && self.incarnation == plan.incarnation()
            && self.epoch == plan.epoch()
            && self.desired_generation == plan.desired_generation()
            && self.assignment_digest == plan.assignment_digest()
    }
}

/// Stores one complete node drain observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainObservationV1 {
    operation: OperationId,
    node: NodeId,
    generation: u64,
    context: AuthenticatedEvidenceContextV1,
    sequence: ObservationSequence,
    phase: DrainPhaseV1,
    assignments: Vec<DrainAssignmentObservationV1>,
    reassignment_ready: Vec<SandboxId>,
    observed_at_unix_seconds: u64,
}

impl DrainObservationV1 {
    /// Reconstructs one raw carrier report for watch/history decoding.
    ///
    /// This path deliberately cannot attach drain evidence or derive
    /// reassignment readiness. A directive reducer must match the report to its
    /// exact current directive before it can advance trusted drain state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel`] for sentinels, stale carrier context, or
    /// noncanonical assignment rows.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authenticated_wire(
        operation: OperationId,
        generation: u64,
        context: AuthenticatedEvidenceContextV1,
        sequence: ObservationSequence,
        phase: DrainPhaseV1,
        assignments: Vec<DrainAssignmentObservationV1>,
        observed_at_unix_seconds: u64,
    ) -> Result<Self, InvalidDrainModel> {
        if operation.as_bytes() == &[0; 16]
            || generation == 0
            || sequence.get() == 0
            || !context.is_current_at(observed_at_unix_seconds)
            || assignments.len() > MAX_DRAIN_ASSIGNMENTS
            || !assignments
                .windows(2)
                .all(|pair| pair[0].sandbox() < pair[1].sandbox())
        {
            return Err(InvalidDrainModel::ObservationCoverageMismatch);
        }
        Ok(Self {
            operation,
            node: context.node(),
            generation,
            context,
            sequence,
            phase,
            assignments,
            reassignment_ready: Vec::new(),
            observed_at_unix_seconds,
        })
    }

    /// Constructs an authenticated carrier report without trusted drain evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel`] for another node, noncanonical coverage,
    /// impossible aggregate progress, or stale carrier currentness.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authenticated_report(
        directive: &DrainDirectiveV1,
        context: AuthenticatedEvidenceContextV1,
        sequence: ObservationSequence,
        phase: DrainPhaseV1,
        assignments: Vec<DrainAssignmentObservationV1>,
        observed_at_unix_seconds: u64,
    ) -> Result<Self, InvalidDrainModel> {
        let progress = assignments
            .iter()
            .map(DrainAssignmentObservationV1::progress)
            .collect::<Vec<_>>();
        if sequence.get() == 0
            || context.node() != directive.node()
            || !context.is_current_at(observed_at_unix_seconds)
            || assignments.len() != directive.assignments().len()
            || !assignments
                .windows(2)
                .all(|pair| pair[0].sandbox() < pair[1].sandbox())
            || assignments
                .iter()
                .zip(directive.assignments())
                .any(|(observed, planned)| !observed.matches(*planned))
            || !observation_phase_consistent(directive, phase, &progress)
        {
            return Err(InvalidDrainModel::ObservationCoverageMismatch);
        }
        Ok(Self {
            operation: directive.operation(),
            node: directive.node(),
            generation: directive.generation(),
            context,
            sequence,
            phase,
            assignments,
            reassignment_ready: Vec::new(),
            observed_at_unix_seconds,
        })
    }

    /// Constructs a complete observation against one exact directive.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel`] for sentinel observation generations or
    /// when assignment coverage differs from the directive.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authenticated_node(
        directive: &DrainDirectiveV1,
        context: AuthenticatedEvidenceContextV1,
        sequence: ObservationSequence,
        phase: DrainPhaseV1,
        assignments: Vec<DrainAssignmentObservationV1>,
        observed_at_unix_seconds: u64,
    ) -> Result<Self, InvalidDrainModel> {
        let progress = assignments
            .iter()
            .map(DrainAssignmentObservationV1::progress)
            .collect::<Vec<_>>();
        if sequence.get() == 0
            || context.node() != directive.node()
            || !context.is_current_at(observed_at_unix_seconds)
        {
            return Err(InvalidDrainModel::Unspecified);
        }
        if assignments.len() != directive.assignments().len()
            || !assignments
                .windows(2)
                .all(|pair| pair[0].sandbox() < pair[1].sandbox())
            || assignments
                .iter()
                .zip(directive.assignments())
                .any(|(observed, planned)| !observed.matches(*planned))
        {
            return Err(InvalidDrainModel::ObservationCoverageMismatch);
        }
        if !observation_phase_consistent(directive, phase, &progress) {
            return Err(InvalidDrainModel::ProgressMismatch);
        }
        if assignments.iter().any(|observation| {
            !drain_evidence_is_current(observation, context, observed_at_unix_seconds)
        }) {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        let reassignment_ready = directive
            .assignments()
            .iter()
            .zip(&assignments)
            .filter_map(|(plan, observation)| {
                let replacement = matches!(
                    plan.strategy(),
                    DrainAssignmentStrategyV1::SnapshotStopAndReplace
                        | DrainAssignmentStrategyV1::StopAndReplace
                );
                let contained = matches!(
                    observation.progress(),
                    DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
                );
                (replacement && contained).then_some(plan.sandbox())
            })
            .collect();

        Ok(Self {
            operation: directive.operation(),
            node: directive.node(),
            generation: directive.generation(),
            context,
            sequence,
            phase,
            assignments,
            reassignment_ready,
            observed_at_unix_seconds,
        })
    }

    /// Returns the drain operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the observing node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the observed drain generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the observing node boot.
    #[must_use]
    pub const fn boot(&self) -> NodeBootId {
        self.context.lineage().boot()
    }

    /// Returns the durable node boot generation.
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

    /// Returns the monotonic observation sequence within the node boot.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns node-wide drain progress.
    #[must_use]
    pub const fn phase(&self) -> DrainPhaseV1 {
        self.phase
    }

    /// Returns exact per-assignment progress in canonical sandbox order.
    #[must_use]
    pub fn assignments(&self) -> &[DrainAssignmentObservationV1] {
        &self.assignments
    }

    /// Returns the canonical subset eligible for separate replacement planning.
    ///
    /// Membership is derived only after required snapshot and containment
    /// evidence has been validated. It grants no replacement authority.
    #[must_use]
    pub fn reassignment_ready(&self) -> &[SandboxId] {
        &self.reassignment_ready
    }

    /// Returns diagnostic wall-clock observation time.
    #[must_use]
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }

    /// Verifies that this observation still names an exact directive.
    #[must_use]
    pub fn matches(&self, directive: &DrainDirectiveV1) -> bool {
        self.operation == directive.operation()
            && self.node == directive.node()
            && self.generation == directive.generation()
            && self.assignments.len() == directive.assignments().len()
            && self
                .assignments
                .iter()
                .zip(directive.assignments())
                .all(|(observed, planned)| observed.matches(*planned))
    }
}

pub(super) fn observation_phase_consistent(
    directive: &DrainDirectiveV1,
    phase: DrainPhaseV1,
    progress: &[DrainAssignmentProgressV1],
) -> bool {
    match phase {
        DrainPhaseV1::Requested | DrainPhaseV1::Cordoned => progress
            .iter()
            .all(|value| *value == DrainAssignmentProgressV1::Pending),
        DrainPhaseV1::Draining => true,
        DrainPhaseV1::Contained => progress.iter().all(|value| {
            matches!(
                value,
                DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
            )
        }),
        DrainPhaseV1::ReadyForReassignment => {
            directive
                .assignments()
                .iter()
                .zip(progress)
                .any(|(plan, value)| {
                    matches!(
                        plan.strategy(),
                        DrainAssignmentStrategyV1::SnapshotStopAndReplace
                            | DrainAssignmentStrategyV1::StopAndReplace
                    ) && matches!(
                        value,
                        DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
                    )
                })
        }
        DrainPhaseV1::Complete => {
            directive
                .assignments()
                .iter()
                .zip(progress)
                .all(|(plan, value)| match plan.strategy() {
                    DrainAssignmentStrategyV1::SnapshotStopAndReplace
                    | DrainAssignmentStrategyV1::StopAndReplace => {
                        *value == DrainAssignmentProgressV1::Released
                    }
                    DrainAssignmentStrategyV1::StopInPlace
                    | DrainAssignmentStrategyV1::LeaveStopped => matches!(
                        value,
                        DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
                    ),
                })
        }
        DrainPhaseV1::Blocked => progress
            .iter()
            .any(|value| matches!(value, DrainAssignmentProgressV1::Blocked(_))),
    }
}

fn drain_evidence_is_current(
    observation: &DrainAssignmentObservationV1,
    observation_context: AuthenticatedEvidenceContextV1,
    observed_at_unix_seconds: u64,
) -> bool {
    let context_matches = |context: AuthenticatedEvidenceContextV1| {
        context.node() == observation_context.node()
            && context.lineage() == observation_context.lineage()
            && context.audience_digest() == observation_context.audience_digest()
            && context.disclosure_domain_digest() == observation_context.disclosure_domain_digest()
            && context.is_current_at(observed_at_unix_seconds)
    };
    observation.snapshot_evidence().is_none_or(|evidence| {
        context_matches(evidence.context())
            && context_matches(evidence.guardian().context())
            && evidence
                .completion()
                .evidence_context()
                .is_current_at(observed_at_unix_seconds)
            && evidence
                .completion()
                .protected_journal_record()
                .context()
                .is_current_at(observed_at_unix_seconds)
            && evidence
                .completion()
                .dependencies_current_at(observed_at_unix_seconds)
    }) && observation
        .containment_evidence()
        .is_none_or(|evidence| context_matches(evidence.guardian().context()))
        && observation
            .release_evidence()
            .is_none_or(|evidence| context_matches(evidence.context()))
}

/// Reports the result of reducing one complete drain observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainObservationApplyOutcomeV1 {
    /// Reducer state changed.
    Applied,
    /// The exact current observation was replayed.
    Replay,
    /// An older observation within the current node boot was ignored.
    Stale,
    /// An observation from an older durable node boot was ignored.
    PriorBoot,
}

/// Reduces complete drain observations for one immutable directive.
///
/// The reducer changes status only. It cannot issue snapshot, stop, cleanup,
/// reassignment, or ownership effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainObservationReducerV1 {
    directive: DrainDirectiveV1,
    current: Option<DrainObservationV1>,
}

impl DrainObservationReducerV1 {
    /// Creates an empty reducer for one accepted drain directive.
    #[must_use]
    pub fn new(directive: DrainDirectiveV1) -> Self {
        Self {
            directive,
            current: None,
        }
    }

    /// Returns the immutable drain directive.
    #[must_use]
    pub const fn directive(&self) -> &DrainDirectiveV1 {
        &self.directive
    }

    /// Returns the latest complete observation only while all evidence is current.
    #[must_use]
    pub fn current_at(&self, coordinator_unix_seconds: u64) -> Option<&DrainObservationV1> {
        self.current.as_ref().filter(|observation| {
            observation
                .context()
                .is_current_at(coordinator_unix_seconds)
                && observation.observed_at_unix_seconds() <= coordinator_unix_seconds
                && observation.assignments().iter().all(|assignment| {
                    drain_evidence_is_current(
                        assignment,
                        observation.context(),
                        coordinator_unix_seconds,
                    )
                })
        })
    }

    /// Reduces one already authenticated complete observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel`] for directive mismatch, boot or sequence
    /// equivocation, or an edge outside the closed drain phase graph.
    pub fn apply(
        &mut self,
        observation: DrainObservationV1,
        coordinator_unix_seconds: u64,
    ) -> Result<DrainObservationApplyOutcomeV1, InvalidDrainModel> {
        if !observation.matches(&self.directive) {
            return Err(InvalidDrainModel::DirectiveMismatch);
        }
        if !observation
            .context()
            .is_current_at(coordinator_unix_seconds)
            || observation.observed_at_unix_seconds() > coordinator_unix_seconds
            || observation.assignments().iter().any(|assignment| {
                !drain_evidence_is_current(
                    assignment,
                    observation.context(),
                    coordinator_unix_seconds,
                )
            })
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }

        let Some(current) = &self.current else {
            self.current = Some(observation);
            return Ok(DrainObservationApplyOutcomeV1::Applied);
        };

        if observation.boot_generation() < current.boot_generation() {
            return Ok(DrainObservationApplyOutcomeV1::PriorBoot);
        }
        if observation.boot_generation() > current.boot_generation() {
            if !observation
                .lineage()
                .is_direct_successor_of(current.lineage())
            {
                return Err(InvalidDrainModel::BootLineageGap);
            }
            self.current = Some(observation);
            return Ok(DrainObservationApplyOutcomeV1::Applied);
        }
        if observation.lineage() != current.lineage() {
            return Err(InvalidDrainModel::BootConflict);
        }

        match observation.sequence().cmp(&current.sequence()) {
            Ordering::Less => Ok(DrainObservationApplyOutcomeV1::Stale),
            Ordering::Equal if observation == *current => {
                Ok(DrainObservationApplyOutcomeV1::Replay)
            }
            Ordering::Equal => Err(InvalidDrainModel::SequenceConflict),
            Ordering::Greater => {
                if !current.phase().can_transition_to(observation.phase()) {
                    return Err(InvalidDrainModel::InvalidPhaseTransition);
                }
                if current
                    .assignments()
                    .iter()
                    .zip(observation.assignments())
                    .any(|(prior, next)| !prior.progress().can_transition_to(next.progress()))
                {
                    return Err(InvalidDrainModel::InvalidPhaseTransition);
                }
                self.current = Some(observation);
                Ok(DrainObservationApplyOutcomeV1::Applied)
            }
        }
    }
}
