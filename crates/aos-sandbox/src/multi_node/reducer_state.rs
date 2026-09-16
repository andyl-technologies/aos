//! Typed durable projections for the multi-node reducers.
//!
//! These states retain complete semantic inputs plus exact evidence and
//! partial-effect commitments. Decoding never recreates carrier, owner, or
//! store authority: restored evidence is historical ordering/currentness data
//! and must be revalidated by the appropriate private authority before an
//! effect is admitted.

use serde::{Deserialize, Serialize};

use aos_sandbox_core::state::{AssignmentPhase, DesiredSandboxState};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDescriptor, ObjectDigest,
    ObservationSequence, SandboxId,
};

use super::assignment::{
    AssignmentIntentV1, AssignmentObservationReasonV1, MAX_SNAPSHOT_TRANSFER_CHUNKS,
    MAX_SNAPSHOT_TRANSFER_DEPENDENCIES, MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES,
    SnapshotTransferManifestV1, SnapshotTransferResumeV1, assignment_reason_phase_consistent,
};
use super::capability::{NodeBootId, NodeBootLineageV1, NodeCapabilitySnapshotV1};
use super::draining::{
    DrainAssignmentProgressV1, DrainBlockReasonV1, DrainDirectiveV1, DrainPhaseV1,
    observation_phase_consistent,
};
use super::journal::{InvalidMultiNodeJournal, MultiNodeJournalDomainV1};
use super::protocol::semantic_codec_v1::{
    CapabilityWire as CapabilitySemanticWire, DrainDirectiveWire as DrainDirectiveSemanticWire,
    IntentWire as IntentSemanticWire, ManifestWire as ManifestSemanticWire, capability_model,
    capability_wire, drain_directive_model, drain_directive_wire, intent_model, intent_wire,
    manifest_model, manifest_wire,
};
use super::protocol::{
    NodeWatchBindingV1, NodeWatchCursorV1, RollingVersionWindowV1, stable_watch_bootstrap_uid,
    stable_watch_event_uid,
};

/// Retains an authority-neutral exact carrier/currentness commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableEvidenceBindingV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    replay_fence: ObjectDigest,
}

impl DurableEvidenceBindingV1 {
    /// Constructs a historical evidence binding that grants no authority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for a zero
    /// commitment or an empty currentness interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: NodeId,
        lineage: NodeBootLineageV1,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        carrier_binding_digest: ObjectDigest,
        canonical_frame_digest: ObjectDigest,
        canonical_frame_bytes: u32,
        coordinator_epoch: u64,
        authenticated_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        replay_fence: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if node.as_bytes() == &[0; 16]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || carrier_binding_digest.as_bytes() == &[0; 32]
            || canonical_frame_digest.as_bytes() == &[0; 32]
            || canonical_frame_bytes == 0
            || coordinator_epoch == 0
            || valid_until_unix_seconds <= authenticated_at_unix_seconds
            || replay_fence.as_bytes() == &[0; 32]
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self {
            node,
            lineage,
            audience_digest,
            disclosure_domain_digest,
            carrier_binding_digest,
            canonical_frame_digest,
            canonical_frame_bytes,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            replay_fence,
        })
    }

    /// Reports whether the historical interval covered `time`.
    #[must_use]
    pub const fn covered(self, time: u64) -> bool {
        time >= self.authenticated_at_unix_seconds && time <= self.valid_until_unix_seconds
    }

    /// Returns the bound node.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the durable non-ABA boot lineage.
    #[must_use]
    pub const fn lineage(self) -> NodeBootLineageV1 {
        self.lineage
    }

    /// Returns the exact carrier-frame commitment.
    #[must_use]
    pub const fn canonical_frame_digest(self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Returns the immutable currentness deadline.
    #[must_use]
    pub const fn valid_until_unix_seconds(self) -> u64 {
        self.valid_until_unix_seconds
    }
}

/// Stores the complete capability reducer projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityJournalStateV1 {
    snapshot: NodeCapabilitySnapshotV1,
    evidence: DurableEvidenceBindingV1,
}

impl CapabilityJournalStateV1 {
    /// Constructs exact durable capability state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for mismatched
    /// node or boot lineage.
    pub fn new(
        snapshot: NodeCapabilitySnapshotV1,
        evidence: DurableEvidenceBindingV1,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if snapshot.node() != evidence.node || snapshot.lineage() != evidence.lineage {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self { snapshot, evidence })
    }

    /// Returns the complete validated snapshot semantics.
    #[must_use]
    pub const fn snapshot(&self) -> &NodeCapabilitySnapshotV1 {
        &self.snapshot
    }

    /// Returns historical carrier binding data requiring fresh revalidation.
    #[must_use]
    pub const fn evidence(&self) -> DurableEvidenceBindingV1 {
        self.evidence
    }

    /// Projects one carrier-authenticated observation into durable state.
    pub(super) fn from_authenticated_observation(
        observation: &super::capability::CarrierValidatedCapabilityObservationV1,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let snapshot = observation.snapshot().clone();
        let evidence = DurableEvidenceBindingV1::new(
            snapshot.node(),
            snapshot.lineage(),
            observation.audience_digest(),
            observation.disclosure_domain_digest(),
            observation.carrier_binding_digest(),
            observation.canonical_observation_digest(),
            observation.canonical_frame_bytes(),
            observation.coordinator_epoch(),
            observation.authenticated_at_unix_seconds(),
            observation.valid_until_unix_seconds(),
            observation.replay_fence(),
        )?;
        Self::new(snapshot, evidence)
    }

    /// Checks the closed capability reducer's advancing-successor rules.
    pub(super) fn admits_successor(&self, next: &Self) -> bool {
        let current = self.snapshot();
        let successor = next.snapshot();
        let current_evidence = self.evidence();
        let successor_evidence = next.evidence();
        if successor.node() != current.node()
            || successor_evidence.coordinator_epoch < current_evidence.coordinator_epoch
            || (successor_evidence.coordinator_epoch == current_evidence.coordinator_epoch
                && (successor_evidence.audience_digest != current_evidence.audience_digest
                    || successor_evidence.disclosure_domain_digest
                        != current_evidence.disclosure_domain_digest
                    || successor_evidence.carrier_binding_digest
                        != current_evidence.carrier_binding_digest))
            || successor.boot_generation() < current.boot_generation()
        {
            return false;
        }
        if successor_evidence.coordinator_epoch > current_evidence.coordinator_epoch
            && successor == current
        {
            return true;
        }
        if successor.boot_generation() > current.boot_generation() {
            return successor
                .lineage()
                .is_direct_successor_of(current.lineage());
        }
        successor.lineage() == current.lineage() && successor.sequence() > current.sequence()
    }
}

/// Stores one raw assignment observation without recreating owner authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAssignmentObservationV1 {
    pub(crate) sandbox: SandboxId,
    pub(crate) incarnation: IncarnationId,
    pub(crate) epoch: AssignmentEpoch,
    pub(crate) desired_generation: DesiredGeneration,
    pub(crate) assignment_digest: ObjectDigest,
    pub(crate) sequence: ObservationSequence,
    pub(crate) phase: AssignmentPhase,
    pub(crate) realized_lifecycle: Option<DesiredSandboxState>,
    pub(crate) reason: AssignmentObservationReasonV1,
    pub(crate) observed_at_unix_seconds: u64,
    pub(crate) authority_evidence_digest: Option<ObjectDigest>,
}

impl DurableAssignmentObservationV1 {
    /// Constructs one complete authority-neutral assignment observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for sentinel
    /// fields, an unknown reason, or a contradictory lifecycle/phase pair.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        sequence: ObservationSequence,
        phase: AssignmentPhase,
        realized_lifecycle: Option<DesiredSandboxState>,
        reason: AssignmentObservationReasonV1,
        observed_at_unix_seconds: u64,
        authority_evidence_digest: Option<ObjectDigest>,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let lifecycle_valid = match realized_lifecycle {
            Some(DesiredSandboxState::Running | DesiredSandboxState::Suspended(_)) => {
                phase == AssignmentPhase::Active
            }
            Some(DesiredSandboxState::Stopped) => {
                matches!(phase, AssignmentPhase::Fenced | AssignmentPhase::Released)
            }
            Some(DesiredSandboxState::Deleted) => phase == AssignmentPhase::Released,
            None => phase != AssignmentPhase::Active,
        };
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || desired_generation.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || sequence.get() == 0
            || !assignment_reason_phase_consistent(phase, reason)
            || !lifecycle_valid
            || authority_evidence_digest.is_some_and(|v| v.as_bytes() == &[0; 32])
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self {
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            assignment_digest,
            sequence,
            phase,
            realized_lifecycle,
            reason,
            observed_at_unix_seconds,
            authority_evidence_digest,
        })
    }

    /// Returns the exact assignment commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the observed exact desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the observed phase.
    #[must_use]
    pub const fn phase(&self) -> AssignmentPhase {
        self.phase
    }

    /// Returns the exact closed observation reason.
    #[must_use]
    pub const fn reason(&self) -> AssignmentObservationReasonV1 {
        self.reason
    }
}

/// Stores the complete assignment intent and latest raw observation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentJournalStateV1 {
    intent: AssignmentIntentV1,
    observation: Option<DurableAssignmentObservationV1>,
    capability_evidence_digest: ObjectDigest,
    affinities: Vec<DurableAffinityProjectionV1>,
}

/// Stores one exact protected local-live affinity dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableAffinityProjectionV1 {
    /// Exact live assignment commitment.
    pub assignment_digest: ObjectDigest,
    /// Exact desired assignment generation.
    pub desired_generation: DesiredGeneration,
    /// Exact ownership epoch.
    pub epoch: AssignmentEpoch,
    /// Exact live runtime incarnation.
    pub incarnation: IncarnationId,
    /// Protected liveness-record commitment.
    pub liveness_record_digest: ObjectDigest,
    /// Currentness deadline of the protected liveness fact.
    pub live_until_unix_seconds: u64,
    /// Node carrying the live assignment.
    pub node: NodeId,
    /// Dependent sandbox.
    pub sandbox: SandboxId,
    /// Independently authenticated worker identity commitment.
    pub worker_identity_digest: ObjectDigest,
}

impl AssignmentJournalStateV1 {
    /// Constructs exact durable assignment reducer state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for a zero or
    /// intent-mismatched commitment.
    pub fn new(
        intent: AssignmentIntentV1,
        observation: Option<DurableAssignmentObservationV1>,
        capability_evidence_digest: ObjectDigest,
        affinities: Vec<DurableAffinityProjectionV1>,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if capability_evidence_digest.as_bytes() == &[0; 32]
            || capability_evidence_digest
                != intent
                    .selected_capability_binding()
                    .evidence_binding_digest()
            || observation.as_ref().is_some_and(|row| {
                row.sandbox != intent.sandbox()
                    || row.incarnation != intent.incarnation()
                    || row.epoch != intent.epoch()
                    || row.desired_generation > intent.desired_generation()
                    || row.assignment_digest != intent.assignment_digest()
            })
            || affinities.len() > super::placement::MAX_AFFINITY_PLACEMENTS
            || !affinities
                .windows(2)
                .all(|pair| pair[0].sandbox < pair[1].sandbox)
            || affinities.iter().any(|affinity| {
                affinity.sandbox.as_bytes() == &[0; 16]
                    || affinity.node.as_bytes() == &[0; 16]
                    || affinity.incarnation.as_bytes() == &[0; 16]
                    || affinity.epoch.get() == 0
                    || affinity.desired_generation.get() == 0
                    || affinity.assignment_digest.as_bytes() == &[0; 32]
                    || affinity.worker_identity_digest.as_bytes() == &[0; 32]
                    || affinity.liveness_record_digest.as_bytes() == &[0; 32]
                    || affinity.live_until_unix_seconds == 0
            })
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self {
            intent,
            observation,
            capability_evidence_digest,
            affinities,
        })
    }

    /// Returns exact assignment intent.
    #[must_use]
    pub const fn intent(&self) -> &AssignmentIntentV1 {
        &self.intent
    }

    /// Returns the latest authority-neutral observation projection.
    #[must_use]
    pub const fn observation(&self) -> Option<&DurableAssignmentObservationV1> {
        self.observation.as_ref()
    }

    /// Returns the exact selected capability evidence commitment.
    #[must_use]
    pub const fn capability_evidence_digest(&self) -> ObjectDigest {
        self.capability_evidence_digest
    }

    /// Returns canonical local-live affinity projections.
    #[must_use]
    pub fn affinities(&self) -> &[DurableAffinityProjectionV1] {
        &self.affinities
    }
}

/// Stores one authority-neutral drain assignment progress row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableDrainAssignmentV1 {
    pub(crate) sandbox: SandboxId,
    pub(crate) incarnation: IncarnationId,
    pub(crate) epoch: AssignmentEpoch,
    pub(crate) desired_generation: DesiredGeneration,
    pub(crate) assignment_digest: ObjectDigest,
    pub(crate) progress: DrainAssignmentProgressV1,
    pub(crate) snapshot_completion_digest: Option<ObjectDigest>,
    pub(crate) containment_digest: Option<ObjectDigest>,
    pub(crate) release_digest: Option<ObjectDigest>,
}

impl DurableDrainAssignmentV1 {
    /// Constructs one exact authority-neutral drain progress row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for sentinel
    /// assignment fields or zero evidence commitments.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        progress: DrainAssignmentProgressV1,
        snapshot_completion_digest: Option<ObjectDigest>,
        containment_digest: Option<ObjectDigest>,
        release_digest: Option<ObjectDigest>,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || desired_generation.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || [
                snapshot_completion_digest,
                containment_digest,
                release_digest,
            ]
            .into_iter()
            .flatten()
            .any(|v| v.as_bytes() == &[0; 32])
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self {
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            assignment_digest,
            progress,
            snapshot_completion_digest,
            containment_digest,
            release_digest,
        })
    }
}

/// Stores one complete raw drain observation and evidence commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableDrainObservationV1 {
    pub(crate) sequence: ObservationSequence,
    pub(crate) phase: DrainPhaseV1,
    pub(crate) assignments: Vec<DurableDrainAssignmentV1>,
    pub(crate) observed_at_unix_seconds: u64,
    pub(crate) evidence: DurableEvidenceBindingV1,
}

impl DurableDrainObservationV1 {
    /// Constructs a bounded, canonically ordered raw drain observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for a zero
    /// sequence, stale historical evidence, or unordered rows.
    pub fn new(
        sequence: ObservationSequence,
        phase: DrainPhaseV1,
        assignments: Vec<DurableDrainAssignmentV1>,
        observed_at_unix_seconds: u64,
        evidence: DurableEvidenceBindingV1,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if sequence.get() == 0
            || !evidence.covered(observed_at_unix_seconds)
            || assignments.len() > super::draining::MAX_DRAIN_ASSIGNMENTS
            || !assignments.windows(2).all(|p| p[0].sandbox < p[1].sandbox)
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self {
            sequence,
            phase,
            assignments,
            observed_at_unix_seconds,
            evidence,
        })
    }

    /// Returns exact assignment rows in canonical order.
    #[must_use]
    pub fn assignments(&self) -> &[DurableDrainAssignmentV1] {
        &self.assignments
    }

    /// Returns the exact monotonic observation sequence.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the durable node-wide drain phase.
    #[must_use]
    pub const fn phase(&self) -> DrainPhaseV1 {
        self.phase
    }

    /// Returns the authenticated observation time retained for replay.
    #[must_use]
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }

    /// Returns historical carrier binding data requiring fresh revalidation.
    #[must_use]
    pub const fn evidence(&self) -> DurableEvidenceBindingV1 {
        self.evidence
    }
}

/// Stores the complete drain directive and latest observation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainJournalStateV1 {
    directive: DrainDirectiveV1,
    observation: Option<DurableDrainObservationV1>,
}

impl DrainJournalStateV1 {
    /// Constructs exact durable drain reducer state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for a
    /// cross-node observation or noncanonical row count.
    pub fn new(
        directive: DrainDirectiveV1,
        observation: Option<DurableDrainObservationV1>,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if let Some(value) = &observation {
            let progress = value
                .assignments
                .iter()
                .map(|row| row.progress)
                .collect::<Vec<_>>();
            if value.evidence.node != directive.node()
                || value.assignments.len() != directive.assignments().len()
                || !value
                    .assignments
                    .windows(2)
                    .all(|pair| pair[0].sandbox < pair[1].sandbox)
                || !observation_phase_consistent(&directive, value.phase, &progress)
            {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            }
            for (row, plan) in value.assignments.iter().zip(directive.assignments()) {
                let contained = matches!(
                    row.progress,
                    DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
                );
                let snapshot_allowed = row.progress != DrainAssignmentProgressV1::Pending;
                let containment_allowed = matches!(
                    row.progress,
                    DrainAssignmentProgressV1::Contained
                        | DrainAssignmentProgressV1::Released
                        | DrainAssignmentProgressV1::Blocked(_)
                );
                let release_allowed = matches!(
                    row.progress,
                    DrainAssignmentProgressV1::Released | DrainAssignmentProgressV1::Blocked(_)
                );
                let needs_snapshot = contained
                    && plan.strategy()
                        == super::draining::DrainAssignmentStrategyV1::SnapshotStopAndReplace;
                if row.sandbox != plan.sandbox()
                    || row.incarnation != plan.incarnation()
                    || row.epoch != plan.epoch()
                    || row.desired_generation != plan.desired_generation()
                    || row.assignment_digest != plan.assignment_digest()
                    || (contained && row.containment_digest.is_none())
                    || (row.progress == DrainAssignmentProgressV1::Released
                        && row.release_digest.is_none())
                    || (needs_snapshot && row.snapshot_completion_digest.is_none())
                    || (plan.strategy()
                        != super::draining::DrainAssignmentStrategyV1::SnapshotStopAndReplace
                        && row.snapshot_completion_digest.is_some())
                    || (!snapshot_allowed && row.snapshot_completion_digest.is_some())
                    || (!containment_allowed && row.containment_digest.is_some())
                    || (!release_allowed && row.release_digest.is_some())
                    || (row.release_digest.is_some() && row.containment_digest.is_none())
                    || (row.release_digest.is_some()
                        && plan.strategy()
                            == super::draining::DrainAssignmentStrategyV1::SnapshotStopAndReplace
                        && row.snapshot_completion_digest.is_none())
                {
                    return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
                }
            }
        }
        Ok(Self {
            directive,
            observation,
        })
    }

    /// Returns the exact current directive.
    #[must_use]
    pub const fn directive(&self) -> &DrainDirectiveV1 {
        &self.directive
    }

    /// Returns the latest authority-neutral observation.
    #[must_use]
    pub const fn observation(&self) -> Option<&DurableDrainObservationV1> {
        self.observation.as_ref()
    }
}

/// Stores one verified durable staged-object boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableStagedChunkV1 {
    /// Digest verified from the actual authenticated bytes.
    pub bytes_digest: ObjectDigest,
    /// Manifest chunk index.
    pub index: u32,
    /// Exact byte length verified at this boundary.
    pub length: u32,
    /// Opaque protected-object receipt commitment for the staged bytes.
    pub protected_object_receipt: ObjectDigest,
}

/// Stores durable dependency staging and protected-liveness commitments.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDependencyProjectionV1 {
    /// Immutable dependency descriptor.
    pub descriptor: ObjectDescriptor,
    /// Bytes verified so far, always a contiguous prefix.
    pub next_offset: u64,
    /// Streaming commitment derived from the actual staged prefix bytes.
    pub verified_prefix_digest: ObjectDigest,
    /// Opaque protected-object receipt for the staged prefix.
    pub protected_object_receipt: ObjectDigest,
    /// Protected current-liveness proof commitment, when complete.
    pub liveness_digest: Option<ObjectDigest>,
    /// Currentness deadline of the liveness proof.
    pub live_until_unix_seconds: Option<u64>,
}

/// Stores atomic-publication evidence without recreating its opaque capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurablePublicationProjectionV1 {
    /// Exact publication commitment.
    pub publication_digest: ObjectDigest,
    /// Monotonic publication generation.
    pub publication_generation: u64,
    /// Protected-store receipt commitment.
    pub protected_receipt_commitment: ObjectDigest,
}

/// Stores complete snapshot-transfer reducer and partial-effect state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotTransferJournalStateV1 {
    manifest: SnapshotTransferManifestV1,
    resume: SnapshotTransferResumeV1,
    staged_chunks: Vec<DurableStagedChunkV1>,
    dependencies: Vec<DurableDependencyProjectionV1>,
    publication: Option<DurablePublicationProjectionV1>,
}

impl SnapshotTransferJournalStateV1 {
    /// Constructs a complete durable snapshot-transfer projection.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] unless staged
    /// rows exactly cover the resume prefix and dependency rows match the manifest.
    pub fn new(
        manifest: SnapshotTransferManifestV1,
        resume: SnapshotTransferResumeV1,
        staged_chunks: Vec<DurableStagedChunkV1>,
        dependencies: Vec<DurableDependencyProjectionV1>,
        publication: Option<DurablePublicationProjectionV1>,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let boundary = usize::try_from(resume.next_chunk())
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        snapshot_state_aggregate_wire_bytes(staged_chunks.len(), dependencies.len())?;
        if resume.identity() != manifest.identity()
            || staged_chunks.len() > MAX_SNAPSHOT_TRANSFER_CHUNKS
            || staged_chunks.len() != boundary
            || staged_chunks.iter().zip(manifest.chunks()).enumerate().any(
                |(index, (stored, expected))| {
                    stored.index != index as u32
                        || stored.index != expected.index()
                        || stored.length != expected.length()
                        || stored.bytes_digest != expected.digest()
                        || stored.protected_object_receipt.as_bytes() == &[0; 32]
                },
            )
            || dependencies.len() > MAX_SNAPSHOT_TRANSFER_DEPENDENCIES
            || dependencies.len() != manifest.dependencies().len()
            || dependencies
                .iter()
                .zip(manifest.dependencies())
                .any(|(stored, expected)| {
                    &stored.descriptor != expected
                        || stored.next_offset > expected.encoded_size()
                        || stored.verified_prefix_digest.as_bytes() == &[0; 32]
                        || stored.protected_object_receipt.as_bytes() == &[0; 32]
                        || stored.liveness_digest.is_some()
                            != stored.live_until_unix_seconds.is_some()
                        || (stored.next_offset == expected.encoded_size())
                            != stored.liveness_digest.is_some()
                        || stored
                            .liveness_digest
                            .is_some_and(|digest| digest.as_bytes() == &[0; 32])
                        || stored.live_until_unix_seconds == Some(0)
                })
            || publication.is_some_and(|p| {
                p.publication_generation == 0
                    || p.publication_digest.as_bytes() == &[0; 32]
                    || p.protected_receipt_commitment.as_bytes() == &[0; 32]
            })
            || (publication.is_some()
                && (boundary != manifest.chunks().len()
                    || dependencies
                        .iter()
                        .any(|dependency| dependency.liveness_digest.is_none())))
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self {
            manifest,
            resume,
            staged_chunks,
            dependencies,
            publication,
        })
    }

    /// Returns the immutable transfer manifest.
    #[must_use]
    pub const fn manifest(&self) -> &SnapshotTransferManifestV1 {
        &self.manifest
    }

    /// Returns the exact durable verified boundary.
    #[must_use]
    pub const fn resume(&self) -> SnapshotTransferResumeV1 {
        self.resume
    }

    /// Returns exact verified staged-object boundaries.
    #[must_use]
    pub fn staged_chunks(&self) -> &[DurableStagedChunkV1] {
        &self.staged_chunks
    }

    /// Returns dependency staging and current-liveness commitments.
    #[must_use]
    pub fn dependencies(&self) -> &[DurableDependencyProjectionV1] {
        &self.dependencies
    }

    /// Returns historical atomic-publication commitments, when publication completed.
    #[must_use]
    pub const fn publication(&self) -> Option<DurablePublicationProjectionV1> {
        self.publication
    }
}

/// Charges every closed V1 row above its maximum canonical JSON representation.
///
/// The checked aggregate is intentionally independent of allocator behavior;
/// even a maximum manifest plus its second durable staged representation fits
/// the snapshot domain decoder ceiling.
fn snapshot_state_aggregate_wire_bytes(
    staged_chunks: usize,
    dependencies: usize,
) -> Result<usize, InvalidMultiNodeJournal> {
    const FIXED_BYTES: usize = 64 * 1024;
    const STAGED_CHUNK_BYTES: usize = 640;
    const DEPENDENCY_BYTES: usize = 2 * 1024;
    const PUBLICATION_BYTES: usize = 1024;

    let charge = FIXED_BYTES
        .checked_add(MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES)
        .and_then(|value| {
            staged_chunks
                .checked_mul(STAGED_CHUNK_BYTES)
                .and_then(|rows| value.checked_add(rows))
        })
        .and_then(|value| {
            dependencies
                .checked_mul(DEPENDENCY_BYTES)
                .and_then(|rows| value.checked_add(rows))
        })
        .and_then(|value| value.checked_add(PUBLICATION_BYTES))
        .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
    if charge > super::journal::MAX_SNAPSHOT_JOURNAL_STATE_BYTES {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    Ok(charge)
}

/// Stores one typed watch event projection without live carrier authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableWatchEventV1 {
    /// Exact canonical event-body byte length.
    pub canonical_event_bytes: u32,
    /// Digest derived from the exact canonical event body.
    pub canonical_event_digest: ObjectDigest,
    /// Stable event UID.
    pub event_uid: ObjectDigest,
    /// Exact predecessor UID.
    pub predecessor_event_uid: ObjectDigest,
    /// Monotonic event sequence.
    pub sequence: u64,
    /// Protected-object receipt for the retained canonical event bytes.
    pub protected_event_receipt: ObjectDigest,
    /// Authenticated response frame that carried the semantic payload.
    pub carrier_frame_digest: ObjectDigest,
}

/// Stores complete watch binding, cursor, floor, and retained history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchJournalStateV1 {
    binding: NodeWatchBindingV1,
    cursor: NodeWatchCursorV1,
    bootstrap_inventory_digest: ObjectDigest,
    bootstrap_inventory_receipt: ObjectDigest,
    events: Vec<DurableWatchEventV1>,
}

impl WatchJournalStateV1 {
    /// Constructs a complete stable watch/history projection.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] unless the
    /// cursor uses the exact binding and retained event UIDs form one chain.
    pub fn new(
        binding: NodeWatchBindingV1,
        cursor: NodeWatchCursorV1,
        bootstrap_inventory_digest: ObjectDigest,
        bootstrap_inventory_receipt: ObjectDigest,
        events: Vec<DurableWatchEventV1>,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if cursor.binding() != binding
            || bootstrap_inventory_digest.as_bytes() == &[0; 32]
            || bootstrap_inventory_receipt.as_bytes() == &[0; 32]
            || events.len() > super::protocol::MAX_WATCH_EVENTS
            || (events.is_empty()
                && (cursor.event_sequence() != binding.bootstrap_watermark()
                    || cursor.last_event_uid()
                        != stable_watch_bootstrap_uid(
                            binding,
                            cursor.lineage(),
                            bootstrap_inventory_digest,
                        )))
            || events.windows(2).any(|pair| {
                pair[1].sequence != pair[0].sequence.saturating_add(1)
                    || pair[1].predecessor_event_uid != pair[0].event_uid
            })
            || events.first().is_some_and(|first| {
                first.sequence != binding.bootstrap_watermark().saturating_add(1)
                    || first.predecessor_event_uid
                        != stable_watch_bootstrap_uid(
                            binding,
                            cursor.lineage(),
                            bootstrap_inventory_digest,
                        )
            })
            || events.last().is_some_and(|last| {
                last.sequence != cursor.event_sequence()
                    || last.event_uid != cursor.last_event_uid()
            })
            || events.iter().any(|event| {
                event.sequence <= binding.history_floor_sequence()
                    || event.event_uid.as_bytes() == &[0; 32]
                    || event.predecessor_event_uid.as_bytes() == &[0; 32]
                    || event.canonical_event_bytes == 0
                    || event.canonical_event_bytes > super::protocol::MAX_NODE_RESPONSE_BYTES
                    || event.canonical_event_digest.as_bytes() == &[0; 32]
                    || event.protected_event_receipt.as_bytes() == &[0; 32]
                    || event.carrier_frame_digest.as_bytes() == &[0; 32]
                    || event.event_uid
                        != stable_watch_event_uid(
                            binding,
                            cursor.lineage(),
                            event.sequence,
                            event.predecessor_event_uid,
                            event.canonical_event_digest,
                        )
            })
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self {
            binding,
            cursor,
            bootstrap_inventory_digest,
            bootstrap_inventory_receipt,
            events,
        })
    }

    /// Returns the exact query/auth/schema/audience binding.
    #[must_use]
    pub const fn binding(&self) -> NodeWatchBindingV1 {
        self.binding
    }

    /// Returns the last durably consumed cursor.
    #[must_use]
    pub const fn cursor(&self) -> NodeWatchCursorV1 {
        self.cursor
    }

    /// Returns retained stable history after the compaction floor.
    #[must_use]
    pub fn events(&self) -> &[DurableWatchEventV1] {
        &self.events
    }

    /// Returns the complete-bootstrap inventory commitment.
    #[must_use]
    pub const fn bootstrap_inventory_digest(&self) -> ObjectDigest {
        self.bootstrap_inventory_digest
    }

    /// Returns the protected artifact receipt for the complete inventory body.
    #[must_use]
    pub const fn bootstrap_inventory_receipt(&self) -> ObjectDigest {
        self.bootstrap_inventory_receipt
    }
}

/// Selects one completely decoded typed durable reducer state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultiNodeReducerStateV1 {
    /// Capability reducer state.
    Capability(CapabilityJournalStateV1),
    /// Assignment reducer state.
    Assignment(AssignmentJournalStateV1),
    /// Drain reducer state.
    Drain(DrainJournalStateV1),
    /// Snapshot transfer reducer state.
    SnapshotTransfer(SnapshotTransferJournalStateV1),
    /// Watch/history reducer state.
    Watch(WatchJournalStateV1),
}

impl MultiNodeReducerStateV1 {
    pub(super) const fn domain(&self) -> MultiNodeJournalDomainV1 {
        match self {
            Self::Capability(_) => MultiNodeJournalDomainV1::Capability,
            Self::Assignment(_) => MultiNodeJournalDomainV1::Assignment,
            Self::Drain(_) => MultiNodeJournalDomainV1::Drain,
            Self::SnapshotTransfer(_) => MultiNodeJournalDomainV1::SnapshotTransfer,
            Self::Watch(_) => MultiNodeJournalDomainV1::Watch,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageWire {
    boot: [u8; 16],
    digest: ObjectDigest,
    generation: u64,
    predecessor_boot: Option<[u8; 16]>,
    predecessor_digest: Option<ObjectDigest>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWire {
    authenticated_at_unix_seconds: u64,
    audience_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    canonical_frame_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    coordinator_epoch: u64,
    disclosure_domain_digest: ObjectDigest,
    lineage: LineageWire,
    node: NodeId,
    replay_fence: ObjectDigest,
    valid_until_unix_seconds: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityWire {
    evidence: EvidenceWire,
    snapshot: CapabilitySemanticWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentWire {
    affinities: Vec<DurableAffinityProjectionV1>,
    capability_evidence_digest: ObjectDigest,
    intent: IntentSemanticWire,
    observation: Option<AssignmentObservationWire>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentObservationWire {
    assignment_digest: ObjectDigest,
    authority_evidence_digest: Option<ObjectDigest>,
    desired_generation: DesiredGeneration,
    epoch: AssignmentEpoch,
    incarnation: IncarnationId,
    observed_at_unix_seconds: u64,
    phase: AssignmentPhase,
    realized_lifecycle: Option<DesiredSandboxState>,
    reason: u8,
    sandbox: SandboxId,
    sequence: ObservationSequence,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainWire {
    directive: DrainDirectiveSemanticWire,
    observation: Option<DrainObservationWire>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainObservationWire {
    assignments: Vec<DrainAssignmentWire>,
    evidence: EvidenceWire,
    observed_at_unix_seconds: u64,
    phase: u8,
    sequence: ObservationSequence,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainAssignmentWire {
    assignment_digest: ObjectDigest,
    containment_digest: Option<ObjectDigest>,
    desired_generation: DesiredGeneration,
    epoch: AssignmentEpoch,
    incarnation: IncarnationId,
    progress: u8,
    release_digest: Option<ObjectDigest>,
    sandbox: SandboxId,
    snapshot_completion_digest: Option<ObjectDigest>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    dependencies: Vec<DurableDependencyProjectionV1>,
    manifest: ManifestSemanticWire,
    publication: Option<DurablePublicationProjectionV1>,
    resume_identity_digest: ObjectDigest,
    resume_next_chunk: u32,
    resume_prefix_digest: ObjectDigest,
    staged_chunks: Vec<DurableStagedChunkV1>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchWire {
    authorization_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    bootstrap_inventory_digest: ObjectDigest,
    bootstrap_inventory_receipt: ObjectDigest,
    bootstrap_watermark: u64,
    coordinator_epoch: u64,
    cursor_event_sequence: u64,
    cursor_last_event_uid: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    events: Vec<DurableWatchEventV1>,
    history_floor_event_uid: ObjectDigest,
    history_floor_sequence: u64,
    lineage: LineageWire,
    node: NodeId,
    query_digest: ObjectDigest,
    schema_maximum_major: u16,
    schema_maximum_minor: u16,
    schema_minimum_major: u16,
    schema_minimum_minor: u16,
}

fn lineage_wire(v: NodeBootLineageV1) -> LineageWire {
    LineageWire {
        boot: *v.boot().as_bytes(),
        digest: v.digest(),
        generation: v.generation(),
        predecessor_boot: v.predecessor_boot().map(|b| *b.as_bytes()),
        predecessor_digest: v.predecessor_digest(),
    }
}
fn lineage_model(v: LineageWire) -> Result<NodeBootLineageV1, InvalidMultiNodeJournal> {
    NodeBootLineageV1::new(
        NodeBootId::new(v.boot).map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?,
        v.generation,
        v.predecessor_boot
            .map(NodeBootId::new)
            .transpose()
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?,
        v.predecessor_digest,
        v.digest,
    )
    .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)
}
fn evidence_wire(v: DurableEvidenceBindingV1) -> EvidenceWire {
    EvidenceWire {
        authenticated_at_unix_seconds: v.authenticated_at_unix_seconds,
        audience_digest: v.audience_digest,
        canonical_frame_bytes: v.canonical_frame_bytes,
        canonical_frame_digest: v.canonical_frame_digest,
        carrier_binding_digest: v.carrier_binding_digest,
        coordinator_epoch: v.coordinator_epoch,
        disclosure_domain_digest: v.disclosure_domain_digest,
        lineage: lineage_wire(v.lineage),
        node: v.node,
        replay_fence: v.replay_fence,
        valid_until_unix_seconds: v.valid_until_unix_seconds,
    }
}
fn evidence_model(v: EvidenceWire) -> Result<DurableEvidenceBindingV1, InvalidMultiNodeJournal> {
    DurableEvidenceBindingV1::new(
        v.node,
        lineage_model(v.lineage)?,
        v.audience_digest,
        v.disclosure_domain_digest,
        v.carrier_binding_digest,
        v.canonical_frame_digest,
        v.canonical_frame_bytes,
        v.coordinator_epoch,
        v.authenticated_at_unix_seconds,
        v.valid_until_unix_seconds,
        v.replay_fence,
    )
}

fn progress_byte(v: DrainAssignmentProgressV1) -> u8 {
    match v {
        DrainAssignmentProgressV1::Pending => 0,
        DrainAssignmentProgressV1::Preparing => 1,
        DrainAssignmentProgressV1::Stopping => 2,
        DrainAssignmentProgressV1::Contained => 3,
        DrainAssignmentProgressV1::Released => 4,
        DrainAssignmentProgressV1::Blocked(r) => {
            10 + match r {
                DrainBlockReasonV1::SnapshotUnavailable => 0,
                DrainBlockReasonV1::MissingDependency => 1,
                DrainBlockReasonV1::OwnershipAuthorityUnavailable => 2,
                DrainBlockReasonV1::ContainmentUnconfirmed => 3,
                DrainBlockReasonV1::ResidualState => 4,
                DrainBlockReasonV1::DestinationUnavailable => 5,
            }
        }
    }
}

fn assignment_reason_byte(v: AssignmentObservationReasonV1) -> u8 {
    match v {
        AssignmentObservationReasonV1::None => 0,
        AssignmentObservationReasonV1::AwaitingContent => 1,
        AssignmentObservationReasonV1::AwaitingCapacity => 2,
        AssignmentObservationReasonV1::CapabilityDrift => 3,
        AssignmentObservationReasonV1::AwaitingOwnershipAuthority => 4,
        AssignmentObservationReasonV1::AwaitingGuardian => 5,
        AssignmentObservationReasonV1::OwnershipFenced => 6,
        AssignmentObservationReasonV1::InventoryIncomplete => 7,
        AssignmentObservationReasonV1::ResidualState => 8,
        AssignmentObservationReasonV1::MissingDependency => 9,
        AssignmentObservationReasonV1::NodeOperationFailed => 10,
    }
}

fn assignment_reason_model(
    v: u8,
) -> Result<AssignmentObservationReasonV1, InvalidMultiNodeJournal> {
    Ok(match v {
        0 => AssignmentObservationReasonV1::None,
        1 => AssignmentObservationReasonV1::AwaitingContent,
        2 => AssignmentObservationReasonV1::AwaitingCapacity,
        3 => AssignmentObservationReasonV1::CapabilityDrift,
        4 => AssignmentObservationReasonV1::AwaitingOwnershipAuthority,
        5 => AssignmentObservationReasonV1::AwaitingGuardian,
        6 => AssignmentObservationReasonV1::OwnershipFenced,
        7 => AssignmentObservationReasonV1::InventoryIncomplete,
        8 => AssignmentObservationReasonV1::ResidualState,
        9 => AssignmentObservationReasonV1::MissingDependency,
        10 => AssignmentObservationReasonV1::NodeOperationFailed,
        _ => return Err(InvalidMultiNodeJournal::NonCanonicalPayload),
    })
}
fn progress_model(v: u8) -> Result<DrainAssignmentProgressV1, InvalidMultiNodeJournal> {
    Ok(match v {
        0 => DrainAssignmentProgressV1::Pending,
        1 => DrainAssignmentProgressV1::Preparing,
        2 => DrainAssignmentProgressV1::Stopping,
        3 => DrainAssignmentProgressV1::Contained,
        4 => DrainAssignmentProgressV1::Released,
        10 => DrainAssignmentProgressV1::Blocked(DrainBlockReasonV1::SnapshotUnavailable),
        11 => DrainAssignmentProgressV1::Blocked(DrainBlockReasonV1::MissingDependency),
        12 => DrainAssignmentProgressV1::Blocked(DrainBlockReasonV1::OwnershipAuthorityUnavailable),
        13 => DrainAssignmentProgressV1::Blocked(DrainBlockReasonV1::ContainmentUnconfirmed),
        14 => DrainAssignmentProgressV1::Blocked(DrainBlockReasonV1::ResidualState),
        15 => DrainAssignmentProgressV1::Blocked(DrainBlockReasonV1::DestinationUnavailable),
        _ => return Err(InvalidMultiNodeJournal::NonCanonicalPayload),
    })
}
fn phase_byte(v: DrainPhaseV1) -> u8 {
    match v {
        DrainPhaseV1::Requested => 0,
        DrainPhaseV1::Cordoned => 1,
        DrainPhaseV1::Draining => 2,
        DrainPhaseV1::Contained => 3,
        DrainPhaseV1::ReadyForReassignment => 4,
        DrainPhaseV1::Complete => 5,
        DrainPhaseV1::Blocked => 6,
    }
}
fn phase_model(v: u8) -> Result<DrainPhaseV1, InvalidMultiNodeJournal> {
    Ok(match v {
        0 => DrainPhaseV1::Requested,
        1 => DrainPhaseV1::Cordoned,
        2 => DrainPhaseV1::Draining,
        3 => DrainPhaseV1::Contained,
        4 => DrainPhaseV1::ReadyForReassignment,
        5 => DrainPhaseV1::Complete,
        6 => DrainPhaseV1::Blocked,
        _ => return Err(InvalidMultiNodeJournal::NonCanonicalPayload),
    })
}

pub(super) fn encode_state(
    state: &MultiNodeReducerStateV1,
) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
    let bytes = match state {
        MultiNodeReducerStateV1::Capability(s) => canonical_json(&CapabilityWire {
            evidence: evidence_wire(s.evidence),
            snapshot: capability_wire(&s.snapshot),
        }),
        MultiNodeReducerStateV1::Assignment(s) => canonical_json(&AssignmentWire {
            affinities: s.affinities.clone(),
            capability_evidence_digest: s.capability_evidence_digest,
            intent: intent_wire(&s.intent),
            observation: s.observation.as_ref().map(|r| AssignmentObservationWire {
                assignment_digest: r.assignment_digest,
                authority_evidence_digest: r.authority_evidence_digest,
                desired_generation: r.desired_generation,
                epoch: r.epoch,
                incarnation: r.incarnation,
                observed_at_unix_seconds: r.observed_at_unix_seconds,
                phase: r.phase,
                realized_lifecycle: r.realized_lifecycle,
                reason: assignment_reason_byte(r.reason),
                sandbox: r.sandbox,
                sequence: r.sequence,
            }),
        }),
        MultiNodeReducerStateV1::Drain(s) => canonical_json(&DrainWire {
            directive: drain_directive_wire(&s.directive),
            observation: s.observation.as_ref().map(|o| DrainObservationWire {
                assignments: o
                    .assignments
                    .iter()
                    .map(|r| DrainAssignmentWire {
                        assignment_digest: r.assignment_digest,
                        containment_digest: r.containment_digest,
                        desired_generation: r.desired_generation,
                        epoch: r.epoch,
                        incarnation: r.incarnation,
                        progress: progress_byte(r.progress),
                        release_digest: r.release_digest,
                        sandbox: r.sandbox,
                        snapshot_completion_digest: r.snapshot_completion_digest,
                    })
                    .collect(),
                evidence: evidence_wire(o.evidence),
                observed_at_unix_seconds: o.observed_at_unix_seconds,
                phase: phase_byte(o.phase),
                sequence: o.sequence,
            }),
        }),
        MultiNodeReducerStateV1::SnapshotTransfer(s) => canonical_json(&SnapshotWire {
            dependencies: s.dependencies.clone(),
            manifest: manifest_wire(&s.manifest),
            publication: s.publication,
            resume_identity_digest: s.resume.identity().manifest_digest(),
            resume_next_chunk: s.resume.next_chunk(),
            resume_prefix_digest: s.resume.verified_prefix_digest(),
            staged_chunks: s.staged_chunks.clone(),
        }),
        MultiNodeReducerStateV1::Watch(s) => {
            let b = s.binding;
            let c = s.cursor;
            canonical_json(&WatchWire {
                authorization_digest: b.authorization_digest(),
                audience_digest: b.audience_digest(),
                bootstrap_inventory_digest: s.bootstrap_inventory_digest,
                bootstrap_inventory_receipt: s.bootstrap_inventory_receipt,
                bootstrap_watermark: b.bootstrap_watermark(),
                coordinator_epoch: b.coordinator_epoch(),
                cursor_event_sequence: c.event_sequence(),
                cursor_last_event_uid: c.last_event_uid(),
                disclosure_domain_digest: b.disclosure_domain_digest(),
                events: s.events.clone(),
                history_floor_event_uid: b.history_floor_event_uid(),
                history_floor_sequence: b.history_floor_sequence(),
                lineage: lineage_wire(c.lineage()),
                node: c.node(),
                query_digest: b.query_digest(),
                schema_maximum_major: b.schema().writer().major(),
                schema_maximum_minor: b.schema().writer().minor(),
                schema_minimum_major: b.schema().minimum_reader().major(),
                schema_minimum_minor: b.schema().minimum_reader().minor(),
            })
        }
    }
    .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    Ok(bytes)
}

/// Encodes one immutable manifest for the fixed protected transfer inbox.
pub(super) fn encode_snapshot_manifest_seed(
    manifest: &SnapshotTransferManifestV1,
) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
    let body = canonical_json(&manifest_wire(manifest))
        .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    if body.is_empty() || body.len() > MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    let mut bytes = Vec::with_capacity(body.len().saturating_add(44));
    bytes.extend_from_slice(b"AOSMSS01");
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    let digest: [u8; 32] = Sha256::digest(&body).into();
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

/// Decodes and byte-roundtrips one fixed protected transfer-inbox manifest.
pub(super) fn decode_snapshot_manifest_seed(
    bytes: &[u8],
) -> Result<SnapshotTransferManifestV1, InvalidMultiNodeJournal> {
    if bytes.len() < 44
        || bytes.len() > MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES.saturating_add(44)
        || bytes.get(..8) != Some(b"AOSMSS01")
    {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    let length = u32::from_be_bytes(
        bytes
            .get(8..12)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?,
    ) as usize;
    let body_end = 12_usize
        .checked_add(length)
        .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let body = bytes
        .get(12..body_end)
        .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let digest = bytes
        .get(body_end..)
        .filter(|digest| digest.len() == 32)
        .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let expected_digest: [u8; 32] = Sha256::digest(body).into();
    if expected_digest.as_slice() != digest {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    let wire: SnapshotManifestWire =
        serde_json::from_slice(body).map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    let manifest =
        manifest_model(wire).map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
    if encode_snapshot_manifest_seed(&manifest)?.as_slice() != bytes {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    Ok(manifest)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::to_value(value)?)
}

pub(super) fn decode_state(
    domain: MultiNodeJournalDomainV1,
    bytes: &[u8],
) -> Result<MultiNodeReducerStateV1, InvalidMultiNodeJournal> {
    let state = match domain {
        MultiNodeJournalDomainV1::Capability => {
            let w: CapabilityWire = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            MultiNodeReducerStateV1::Capability(CapabilityJournalStateV1::new(
                capability_model(w.snapshot)
                    .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?,
                evidence_model(w.evidence)?,
            )?)
        }
        MultiNodeJournalDomainV1::Assignment => {
            let w: AssignmentWire = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            let observation = w
                .observation
                .map(|r| {
                    DurableAssignmentObservationV1::new(
                        r.sandbox,
                        r.incarnation,
                        r.epoch,
                        r.desired_generation,
                        r.assignment_digest,
                        r.sequence,
                        r.phase,
                        r.realized_lifecycle,
                        assignment_reason_model(r.reason)?,
                        r.observed_at_unix_seconds,
                        r.authority_evidence_digest,
                    )
                })
                .transpose()?;
            MultiNodeReducerStateV1::Assignment(AssignmentJournalStateV1::new(
                intent_model(w.intent).map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?,
                observation,
                w.capability_evidence_digest,
                w.affinities,
            )?)
        }
        MultiNodeJournalDomainV1::Drain => {
            let w: DrainWire = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            let observation = w
                .observation
                .map(|o| -> Result<_, InvalidMultiNodeJournal> {
                    DurableDrainObservationV1::new(
                        o.sequence,
                        phase_model(o.phase)?,
                        o.assignments
                            .into_iter()
                            .map(|r| {
                                DurableDrainAssignmentV1::new(
                                    r.sandbox,
                                    r.incarnation,
                                    r.epoch,
                                    r.desired_generation,
                                    r.assignment_digest,
                                    progress_model(r.progress)?,
                                    r.snapshot_completion_digest,
                                    r.containment_digest,
                                    r.release_digest,
                                )
                            })
                            .collect::<Result<Vec<_>, InvalidMultiNodeJournal>>()?,
                        o.observed_at_unix_seconds,
                        evidence_model(o.evidence)?,
                    )
                })
                .transpose()?;
            MultiNodeReducerStateV1::Drain(DrainJournalStateV1::new(
                drain_directive_model(w.directive)
                    .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?,
                observation,
            )?)
        }
        MultiNodeJournalDomainV1::SnapshotTransfer => {
            let w: SnapshotWire = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            let manifest = manifest_model(w.manifest)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            let resume =
                SnapshotTransferResumeV1::new(&manifest, manifest.identity(), w.resume_next_chunk)
                    .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            if resume.identity().manifest_digest() != w.resume_identity_digest
                || resume.verified_prefix_digest() != w.resume_prefix_digest
            {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            }
            MultiNodeReducerStateV1::SnapshotTransfer(SnapshotTransferJournalStateV1::new(
                manifest,
                resume,
                w.staged_chunks,
                w.dependencies,
                w.publication,
            )?)
        }
        MultiNodeJournalDomainV1::Watch => {
            let w: WatchWire = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            let schema = RollingVersionWindowV1::new(
                aos_sandbox_core::ProtocolVersion::new(
                    w.schema_minimum_major,
                    w.schema_minimum_minor,
                ),
                aos_sandbox_core::ProtocolVersion::new(
                    w.schema_maximum_major,
                    w.schema_maximum_minor,
                ),
            )
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            let binding = NodeWatchBindingV1::new(
                w.coordinator_epoch,
                w.history_floor_sequence,
                w.history_floor_event_uid,
                w.bootstrap_watermark,
                w.query_digest,
                w.authorization_digest,
                w.audience_digest,
                w.disclosure_domain_digest,
                schema,
            )
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            let cursor = NodeWatchCursorV1::new(
                w.node,
                lineage_model(w.lineage)?,
                binding,
                w.cursor_event_sequence,
                w.cursor_last_event_uid,
            )
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            MultiNodeReducerStateV1::Watch(WatchJournalStateV1::new(
                binding,
                cursor,
                w.bootstrap_inventory_digest,
                w.bootstrap_inventory_receipt,
                w.events,
            )?)
        }
    };
    if encode_state(&state)?.as_slice() != bytes {
        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
    }
    Ok(state)
}
