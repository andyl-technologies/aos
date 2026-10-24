//! Cordon and drain desired-state and observation models.
//!
//! Draining is modeled as an ordered controller operation. A plan can request
//! snapshot, stop, containment, and release observations, but it never grants
//! a destination assignment or ownership authority. Reassignment remains a
//! separate fenced controller transaction followed by independent ownership
//! acquisition.

use aos_sandbox_model::{
    DrainAssignmentPlanV1, DrainAssignmentProgressV1, DrainAssignmentStrategyV1,
    DrainBlockReasonV1, DrainDirectiveV1, DrainGuardianStateV1, DrainPhaseV1, InvalidDrainModel,
    MAX_DRAIN_ASSIGNMENTS, NodeDrainModeV1, drain_directive_digest,
};
use sha2::{Digest as _, Sha256};

use aos_sandbox_model::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDigest, ObservationSequence,
    OperationId, SandboxId, SnapshotId,
};

use super::assignment::SnapshotTransferCompletionV1;
use super::evidence::AuthenticatedEvidenceContextV1;
use super::journal::{JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1};
use aos_sandbox_model::AssignmentIntentV1;
use aos_sandbox_model::{NodeBootId, NodeBootLineageV1};

#[cfg(feature = "multi-node")]
mod verified_observation;

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
    /// `Self::from_authenticated_node` consumes the required opaque evidence.
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
    /// reassignment readiness. The protected owner must match the report to its
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
