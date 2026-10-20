//! Assignment intent and monotonic node-observation models.
//!
//! Assignment intent commits controller-selected semantics and the capability
//! observation used during placement. It contains no ownership lease, signing
//! key, guardian deadline, or broker grant. Node observations can advance
//! status only for that exact tuple and likewise carry no authority.

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::snapshot_transfer::{hash_descriptor, is_inert_transfer_dependency};
use aos_sandbox_core::{
    InvalidSnapshotTransfer, MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES, MAX_SNAPSHOT_TRANSFER_CHUNKS,
    MAX_SNAPSHOT_TRANSFER_DEPENDENCIES, MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES,
    MAX_SNAPSHOT_TRANSFER_REQUIRED_FEATURES, SnapshotDependencyRangeV1,
    SnapshotTransferChunkRequestV1, SnapshotTransferChunkV1, SnapshotTransferIdentityV1,
    SnapshotTransferManifestV1, SnapshotTransferResumeV1, SnapshotTransferVersionV1,
};

use aos_sandbox_core::state::{AssignmentPhase, DesiredSandboxState};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDescriptor, ObjectDigest,
    ObservationSequence, OperationId, PortableMediaType, ProjectId, SandboxId, SnapshotId,
};

use super::capability::CarrierValidatedCapabilityObservationV1;
use super::evidence::AuthenticatedEvidenceContextV1;
use super::evidence_authority::VerifierEvidenceGrantV1;
use super::journal::{JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1};
#[cfg(feature = "multi-node")]
use super::protocol;
use aos_sandbox_core::{
    AssignmentIntentV1, InvalidAssignmentModel, NodeBootId, NodeBootLineageV1,
    SelectedCapabilityBindingV1,
};

#[cfg(feature = "multi-node")]
mod acceptance_evidence;

#[cfg(feature = "multi-node")]
mod effect_plan;

#[cfg(feature = "multi-node")]
mod remote_verification;

#[cfg(feature = "multi-node")]
mod restore_admission;

#[cfg(feature = "multi-node")]
pub use acceptance_evidence::VerifiedAssignmentAcceptanceV1;

#[cfg(feature = "multi-node")]
pub(super) use effect_plan::AssignmentEffectPlanV1;

#[cfg(feature = "multi-node")]
pub use remote_verification::{
    AuthenticatedSnapshotChunkV1, AuthenticatedSnapshotDependencyRangeV1,
    DurableSnapshotTransferCheckpointV1, SnapshotDependencyReducerV1,
    SnapshotTransferApplyOutcomeV1, SnapshotTransferReducerV1,
};

#[cfg(feature = "multi-node")]
pub use restore_admission::{
    SnapshotRestoreAdmissionDecisionV1, SnapshotRestoreAdmissionV1, SnapshotRestoreBlockReasonV1,
    VerifiedRestoreAuthorizationV1,
};

/// Uses the core closed assignment transition vocabulary for node observations.
pub type AssignmentObservationPhaseV1 = AssignmentPhase;

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

    pub(super) fn matches_drain_plan(
        self,
        plan: aos_sandbox_core::DrainAssignmentPlanV1,
        context: AuthenticatedEvidenceContextV1,
        coordinator_unix_seconds: u64,
    ) -> bool {
        self.node == context.node()
            && self.context == context
            && self.sandbox == plan.sandbox()
            && self.incarnation == plan.incarnation()
            && self.epoch == plan.epoch()
            && self.desired_generation == plan.desired_generation()
            && self.assignment_digest == plan.assignment_digest()
            && self.is_current_at(coordinator_unix_seconds)
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

/// Copies the exact non-authorizing binding from a validated observation.
///
/// # Errors
///
/// Returns [`InvalidAssignmentModel::PlacementMismatch`] for an unspecified
/// identity or commitment, empty frame, or invalid currentness interval.
pub fn selected_capability_binding_from_observation_v1(
    observation: &CarrierValidatedCapabilityObservationV1,
) -> Result<SelectedCapabilityBindingV1, InvalidAssignmentModel> {
    SelectedCapabilityBindingV1::new(
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

/// Reports whether `observation` is the exact still-current source fact.
#[must_use]
pub(super) fn selected_capability_matches_current_v1(
    binding: SelectedCapabilityBindingV1,
    observation: &CarrierValidatedCapabilityObservationV1,
    coordinator_unix_seconds: u64,
) -> bool {
    selected_capability_binding_from_observation_v1(observation)
        .is_ok_and(|observed| observed == binding)
        && observation.is_current_at(coordinator_unix_seconds)
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
