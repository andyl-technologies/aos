//! Selected protected-store remote orchestration and sealed result values.
//!
//! These children are compiled only with `multi-node`. Local currentness,
//! complete inventory discovery, and full retained-history replay remain in
//! the parent owner; every selected mutation uses that same custody.

mod assignment;
mod drain;
mod exchange;
mod snapshot;
mod watch;

use snapshot::{
    protected_cross_owner_admission_digest, protected_empty_dependency_digest,
    protected_snapshot_dependency_liveness, protected_snapshot_dependency_receipt,
    protected_snapshot_dependency_subject, protected_snapshot_destination_storage_binding,
    protected_snapshot_inbox_journal_limits, protected_snapshot_inbox_receipt,
    protected_snapshot_publication_digest, protected_snapshot_publication_receipt,
    protected_snapshot_restore_authorization_digest, protected_snapshot_restore_scope,
    read_protected_snapshot_manifest,
};

use drain::durable_drain_observation;

use watch::{protected_watch_binding_digest, watch_binding_advances};

use exchange::protected_outbound_operation;

use std::path::Path;

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{NodeId, ObjectDigest, OperationId, RestoreScopeId};

use crate::journal::{Journal, JournalLimits, RecordNamespace, RecoveryReport};

use crate::local_inventory::assignment::{
    AssignmentEffectPlanV1, AssignmentIntentV1, AssignmentObservationReducerV1,
    AtomicSnapshotPublicationV1, AuthenticatedSnapshotChunkV1,
    AuthenticatedSnapshotDependencyRangeV1, DurableSnapshotDependencySetV1,
    DurableSnapshotTransferCheckpointV1, InvalidAssignmentModel, InvalidSnapshotTransfer,
    SnapshotDependencyRangeV1, SnapshotRestoreAdmissionDecisionV1, SnapshotRestoreAdmissionV1,
    SnapshotTransferChunkRequestV1, SnapshotTransferCompletionV1, SnapshotTransferManifestV1,
    SnapshotTransferResumeV1, VerifiedAssignmentAuthorityV1, VerifiedRestoreAuthorizationV1,
    VerifiedSnapshotDependencySetV1, VerifiedStagedSnapshotV1, staged_prefix_commitment,
};
use crate::local_inventory::carrier_authority::{
    AuthenticatedAssignmentCarrierContractV1, issue_response_from_protected_channel,
    issue_session_from_protected_channel, verify_assignment_contract_from_protected_channel,
};
#[cfg(feature = "multi-node")]
use crate::local_inventory::carrier_authority::{
    DormantAuthenticatedCoordinatorNodeTransportV1, DormantOutboundExchangeV1,
    DormantOutboundResponseV1, DormantTransportHandshakeV1,
};
use crate::local_inventory::draining::{
    DrainAssignmentPlanV1, DrainAssignmentStrategyV1, DrainDirectiveV1, DrainObservationV1,
    InvalidDrainModel, NodeDrainModeV1, drain_directive_digest,
};
use crate::local_inventory::evidence::AuthenticatedEvidenceContextV1;
use crate::local_inventory::evidence_authority::ProtectedEvidenceIntegrationV1;
use crate::local_inventory::journal::{
    AssignmentEffectSemanticGrantV1, InvalidMultiNodeJournal, JournalEffectStateV1,
    MultiNodeJournalDomainV1, MultiNodeJournalRecordV1, MultiNodeJournalReducerV1,
    ProtectedJournalRecordV1,
};
use crate::local_inventory::protected_artifact_store::ProtectedArtifactKindV1;
use crate::local_inventory::protected_artifact_store::remote::{
    ProtectedArtifactRecoveryV1, ProtectedArtifactStoreOutcomeV1, snapshot_chunk_effect,
    snapshot_dependency_effect,
};
use crate::local_inventory::protocol::{
    AuthenticatedNodeSessionV1, CanonicalNodeFrameV1, CanonicalNodeSemanticCodecV1,
    InvalidMultiNodeProtocol, MAX_WATCH_EVENTS, NodeRequestBodyV1, NodeRequestEnvelopeV1,
    NodeResponseBodyV1, NodeResponseEnvelopeV1, NodeWatchBindingV1, NodeWatchBootstrapV1,
    NodeWatchCursorV1, NodeWatchEventBodyV1, NodeWatchEventV1, ResyncInventoryV1,
    RollingVersionWindowV1,
};
use crate::local_inventory::reducer_state::{
    CapabilityJournalStateV1, DrainJournalStateV1, DurableAssignmentObservationV1,
    DurableDependencyProjectionV1, DurableDrainObservationV1, DurableEvidenceBindingV1,
    DurablePublicationProjectionV1, DurableStagedChunkV1, DurableWatchEventV1,
    MultiNodeReducerStateV1, SnapshotTransferJournalStateV1, WatchJournalStateV1,
    decode_snapshot_manifest_seed,
};
#[cfg(feature = "multi-node")]
use crate::local_inventory::remote::placement::PlacementCandidateV1;

use super::{
    ProtectedMultiNodeAuthorityOpenErrorV1, ProtectedMultiNodeAuthorityOwnerV1,
    ProtectedMultiNodeCurrentRecordV1, ProtectedMultiNodeOwnerRoleV1,
    ProtectedRecordCommitOutcomeV1, ProtectedStoreAuthoritySessionV1, ProtectedStoreObjectKindV1,
    ProtectedStorePersistOutcomeV1, ProtectedStoreRecoveryOutcomeV1,
    ProtectedStoreRecoveryRequiredV1, durable_drain_matches_report, protected_context_digest,
    protected_receipt_commitment, replay_protected_store_semantics,
};

const PROTECTED_MULTI_NODE_DESTINATION_ROOT: &str = "/var/lib/aos/sandbox/multi-node-destination";

const PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_JOURNAL_NAME: &str =
    "multi-node-snapshot-inbox-v1.journal";

const PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_KEY: &[u8] =
    b"\0aos-multi-node-snapshot-inbox-v1\0manifest";

/// Reports authenticated multi-node observation persistence failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedMultiNodeUpdateErrorV1 {
    /// The authenticated carrier or semantic response was invalid or stale.
    #[error("multi-node carrier update is invalid: {0}")]
    Protocol(#[from] InvalidMultiNodeProtocol),
    /// Drain desired-state or authenticated observation semantics were invalid.
    #[error("multi-node drain update is invalid: {0}")]
    Drain(#[from] InvalidDrainModel),
    /// Snapshot manifest, integrity, resume, or evidence semantics were invalid.
    #[error("multi-node snapshot update is invalid: {0}")]
    Snapshot(#[from] InvalidSnapshotTransfer),
    /// Protected replay, transition validation, or persistence failed.
    #[error("multi-node protected update failed: {0}")]
    Journal(#[from] InvalidMultiNodeJournal),
}

/// Couples an assignment journal record to its authenticated carrier contract.
///
/// The wrapper is singular. It is the only value in this module that allows a
/// future publisher to retain peer, node, epoch, assignment, lease, detached
/// signature, and replay binding alongside the durable record.
#[must_use]
pub struct ProtectedAssignmentStoreCommitV1 {
    record: ProtectedJournalRecordV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Retains exact assignment authority across an outcome-unknown store write.
#[must_use]
pub struct ProtectedAssignmentRecoveryRequiredV1 {
    recovery: ProtectedStoreRecoveryRequiredV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Reports a protected assignment write without discarding ambiguity state.
#[must_use]
pub enum ProtectedAssignmentWriteOutcomeV1 {
    /// The exact protected assignment row was read back after commit.
    Committed(ProtectedAssignmentStoreCommitV1),
    /// The exact transaction and carrier authority must be recovered.
    RecoveryRequired(ProtectedAssignmentRecoveryRequiredV1),
}

/// Reports recovery of one protected assignment write.
#[must_use]
pub enum ProtectedAssignmentWriteResolutionV1 {
    /// The exact protected assignment row was authenticated as committed.
    Committed(ProtectedAssignmentStoreCommitV1),
    /// Recovery remains indeterminate or found a conflicting current value.
    RecoveryRequired {
        /// Retains the exact transaction and carrier authority for another observation.
        recovery: ProtectedAssignmentRecoveryRequiredV1,
        /// Describes the fail-closed recovery classification.
        reason: InvalidMultiNodeJournal,
    },
}

/// Reports protected assignment verification or persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedAssignmentWriteErrorV1 {
    /// Carrier, signature, trust-policy, or protected identity verification failed.
    #[error("protected assignment carrier verification failed: {0}")]
    Protocol(#[from] InvalidMultiNodeProtocol),
    /// Assignment intent or reducer plan construction failed.
    #[error("protected assignment reducer planning failed: {0}")]
    Assignment(#[from] InvalidAssignmentModel),
    /// Protected storage or canonical replay validation failed.
    #[error("protected assignment journal write failed: {0}")]
    Journal(#[from] InvalidMultiNodeJournal),
}

/// Allows publication only after the exact assignment store commit completed.
#[must_use]
pub(in crate::local_inventory::store_authority) struct ProtectedAssignmentPublicationV1 {
    record: ProtectedJournalRecordV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Carries an exact prepared multi-node effect after durable publication.
#[must_use]
pub(in crate::local_inventory::store_authority) struct ProtectedAssignmentEffectHandoffV1 {
    publication: ProtectedAssignmentPublicationV1,
    semantic_grant: AssignmentEffectSemanticGrantV1,
    effect_time_carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Retains a current, reducer-authorized assignment effect without dispatching it.
#[must_use]
pub struct ProtectedAssignmentEffectReadyV1 {
    handoff: ProtectedAssignmentEffectHandoffV1,
}

pub(in crate::local_inventory::store_authority) enum ProtectedAssignmentCommitOutcomeV1 {
    Committed(ProtectedAssignmentStoreCommitV1),
    RecoveryRequired {
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
    },
}

pub(in crate::local_inventory::store_authority) enum ProtectedAssignmentResolutionV1 {
    Committed(ProtectedAssignmentStoreCommitV1),
    RecoveryRequired {
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
        reason: InvalidMultiNodeJournal,
    },
}

/// Owns destination-only protected storage and restore admission.
///
/// The destination bootstrap, journal, artifact root, clock floor, and node
/// identity are independent of the source owner. The inner owner is not
/// exposed, so source-authenticated context cannot be retyped as destination
/// durability or restore authority.
pub struct ProtectedSnapshotDestinationAuthorityOwnerV1 {
    inner: ProtectedMultiNodeAuthorityOwnerV1,
}

/// Proves the source owner currently admits one immutable transfer identity.
///
/// This value is issued only from authenticated source replay. It contains no
/// destination mutation authority.
#[must_use]
pub struct ProtectedSnapshotSourceAdmissionV1 {
    manifest: SnapshotTransferManifestV1,
    source_record: ProtectedJournalRecordV1,
    source_store_root: ObjectDigest,
    source_epoch: u64,
}

/// Joins destination-only restore admission to its current assignment intent.
///
/// The token remains inert: it proves that a destination assignment may
/// consume the published snapshot, but dispatches no restore effect.
#[must_use]
pub struct ProtectedDestinationAssignmentRestoreV1 {
    admission: SnapshotRestoreAdmissionV1,
    assignment: AssignmentIntentV1,
    destination_record: ProtectedJournalRecordV1,
}

/// Retains a protected row and its monotonic evidence verifier session.
///
/// Public callers can retain the authenticated context, but the generic grant
/// mint remains crate-controlled for typed verifier adapters.
pub struct ProtectedMultiNodeEvidenceSessionV1 {
    integration: ProtectedEvidenceIntegrationV1,
}

/// Retains an authenticated outbound request and its exact canonical frame.
#[must_use]
pub struct ProtectedOutboundNodeRequestV1 {
    envelope: NodeRequestEnvelopeV1,
    canonical_frame: Vec<u8>,
}

/// Retains a carrier-authenticated cursor-gap binding for exact resynchronization.
#[must_use]
pub struct ProtectedWatchResyncRequiredV1 {
    binding: NodeWatchBindingV1,
}

/// Reports durable watch progress or an authenticated resynchronization edge.
#[must_use]
pub enum ProtectedWatchCommitOutcomeV1 {
    /// The exact ordered batch was durably committed or retained for recovery.
    Store(ProtectedRecordCommitOutcomeV1),
    /// The authenticated peer proved that the current cursor fell below its floor.
    ResyncRequired(ProtectedWatchResyncRequiredV1),
    /// One exact semantic event artifact still needs protected readback.
    ArtifactRecoveryRequired(ProtectedWatchArtifactRecoveryV1),
    /// A semantic domain reducer write must be recovered before cursor commit.
    ReducerRecoveryRequired(ProtectedStoreRecoveryRequiredV1),
}

/// Retains one exact watch semantic artifact across an unknown write outcome.
#[must_use]
pub struct ProtectedWatchArtifactRecoveryV1 {
    recovery: ProtectedArtifactRecoveryV1,
}

/// Reports complete-inventory persistence before its cursor marker is committed.
#[must_use]
pub enum ProtectedWatchBootstrapCommitOutcomeV1 {
    /// The inventory artifact and exact cursor marker were durably committed.
    Store(ProtectedRecordCommitOutcomeV1),
    /// The complete inventory artifact still needs protected readback.
    ArtifactRecoveryRequired(ProtectedWatchArtifactRecoveryV1),
    /// A capability reducer write must be resolved before the cursor can advance.
    ReducerRecoveryRequired(ProtectedStoreRecoveryRequiredV1),
}

/// Reports protected readback of a watch semantic artifact.
#[must_use]
pub enum ProtectedWatchArtifactRecoveryOutcomeV1 {
    /// The exact semantic artifact is durably present; the caller may retry the reducer commit.
    Stored,
    /// Protected readback remains indeterminate.
    RecoveryRequired(ProtectedWatchArtifactRecoveryV1),
}

/// Retains one exact authenticated snapshot-byte write across ambiguous storage.
#[must_use]
pub struct ProtectedSnapshotArtifactRecoveryV1 {
    recovery: ProtectedArtifactRecoveryV1,
    response_frame_digest: ObjectDigest,
}

/// Reports protected snapshot staging followed by durable reducer publication.
#[must_use]
pub enum ProtectedSnapshotChunkCommitOutcomeV1 {
    /// The exact verified boundary entered the protected multi-node journal.
    Store(ProtectedRecordCommitOutcomeV1),
    /// Fixed artifact storage still needs exact readback classification.
    ArtifactRecoveryRequired(ProtectedSnapshotArtifactRecoveryV1),
}

/// Retains an exact dependency-range write across ambiguous fixed storage.
#[must_use]
pub struct ProtectedSnapshotDependencyRecoveryV1 {
    recovery: ProtectedArtifactRecoveryV1,
    response_frame_digest: ObjectDigest,
}

/// Reports one durable dependency-range transition.
#[must_use]
pub enum ProtectedSnapshotDependencyCommitOutcomeV1 {
    /// The protected dependency prefix and reducer state advanced together.
    Store(ProtectedRecordCommitOutcomeV1),
    /// Fixed artifact storage still needs exact readback classification.
    ArtifactRecoveryRequired(ProtectedSnapshotDependencyRecoveryV1),
}

/// Confirms that the authenticated source accepted the exact durable resume boundary.
#[must_use]
pub struct ProtectedSnapshotResumeReadyV1 {
    identity: crate::local_inventory::assignment::SnapshotTransferIdentityV1,
    resume: SnapshotTransferResumeV1,
}

/// Identifies the distinct protected endpoints of one fixed-root transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedSnapshotTransferRolesV1 {
    source_node: NodeId,
    destination_node: NodeId,
    source_current_until_unix_seconds: u64,
    destination_validated_at_unix_seconds: u64,
    destination_storage_binding: ObjectDigest,
}

impl ProtectedSnapshotTransferRolesV1 {
    /// Returns the authenticated carrier endpoint that serves immutable bytes.
    #[must_use]
    pub const fn source_node(self) -> NodeId {
        self.source_node
    }

    /// Returns the distinct fixed protected-storage endpoint receiving bytes.
    #[must_use]
    pub const fn destination_node(self) -> NodeId {
        self.destination_node
    }

    /// Returns the protected source currentness deadline.
    #[must_use]
    pub const fn source_current_until_unix_seconds(self) -> u64 {
        self.source_current_until_unix_seconds
    }

    /// Returns the monotonic protected time at which destination storage was checked.
    #[must_use]
    pub const fn destination_validated_at_unix_seconds(self) -> u64 {
        self.destination_validated_at_unix_seconds
    }

    /// Returns the destination role's fixed storage binding.
    #[must_use]
    pub const fn destination_storage_binding(self) -> ObjectDigest {
        self.destination_storage_binding
    }
}

impl ProtectedSnapshotResumeReadyV1 {
    /// Returns the immutable transfer identity.
    #[must_use]
    pub const fn identity(&self) -> crate::local_inventory::assignment::SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact durable boundary accepted by the source.
    #[must_use]
    pub const fn resume(&self) -> SnapshotTransferResumeV1 {
        self.resume
    }
}

impl ProtectedOutboundNodeRequestV1 {
    /// Returns the authenticated semantic request envelope.
    #[must_use]
    pub const fn envelope(&self) -> &NodeRequestEnvelopeV1 {
        &self.envelope
    }

    /// Returns the exact canonical bytes ready for an external transport.
    #[must_use]
    pub fn canonical_frame(&self) -> &[u8] {
        &self.canonical_frame
    }
}

impl ProtectedSnapshotSourceAdmissionV1 {
    /// Returns the exact immutable transfer admitted by the source owner.
    #[must_use]
    pub const fn manifest(&self) -> &SnapshotTransferManifestV1 {
        &self.manifest
    }

    /// Returns the source owner's authenticated coordinator epoch.
    #[must_use]
    pub const fn source_epoch(&self) -> u64 {
        self.source_epoch
    }

    /// Returns the source protected-store root that admitted the manifest.
    #[must_use]
    pub const fn source_store_root(&self) -> ObjectDigest {
        self.source_store_root
    }
}

impl ProtectedDestinationAssignmentRestoreV1 {
    /// Returns destination-only restore admission evidence.
    #[must_use]
    pub const fn admission(&self) -> &SnapshotRestoreAdmissionV1 {
        &self.admission
    }

    /// Returns the exact destination assignment joined to the admission.
    #[must_use]
    pub const fn assignment(&self) -> &AssignmentIntentV1 {
        &self.assignment
    }

    /// Returns the destination protected row that fixed the assignment join.
    #[must_use]
    pub const fn destination_record(&self) -> &ProtectedJournalRecordV1 {
        &self.destination_record
    }
}

impl ProtectedMultiNodeEvidenceSessionV1 {
    /// Returns the exact protected verifier context retained by this session.
    #[must_use]
    pub fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.integration.context()
    }
}

impl ProtectedAssignmentStoreCommitV1 {
    /// Returns the exact protected assignment journal record.
    #[must_use]
    pub fn record(&self) -> &ProtectedJournalRecordV1 {
        &self.record
    }

    /// Consumes the readback-confirmed commit into a publication typestate.
    pub(in crate::local_inventory::store_authority) fn into_publication(
        self,
    ) -> ProtectedAssignmentPublicationV1 {
        ProtectedAssignmentPublicationV1 {
            record: self.record,
            carrier: self.carrier,
        }
    }
}

impl ProtectedAssignmentPublicationV1 {
    /// Releases only the reducer-authorized effect under current assignment authority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::InvalidRecoveryTransition`] unless the
    /// semantic grant names this exact protected row and a current effect-time
    /// carrier preserves its peer, assignment, and lease authority.
    pub(in crate::local_inventory::store_authority) fn into_effect_handoff(
        self,
        semantic_grant: AssignmentEffectSemanticGrantV1,
        effect_time_carrier: AuthenticatedAssignmentCarrierContractV1,
        effect_time_unix_seconds: u64,
    ) -> Result<ProtectedAssignmentEffectHandoffV1, InvalidMultiNodeJournal> {
        let record = self.record.record();
        let intent = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?
            .intent();
        if record.domain() != crate::local_inventory::journal::MultiNodeJournalDomainV1::Assignment
            || record.effect_state()
                != crate::local_inventory::journal::JournalEffectStateV1::EffectPrepared
            || record.payload_digest() != semantic_grant.payload_digest()
            || semantic_grant.intent() != intent
            || !semantic_grant.matches(record.operation(), intent, record.effect_digest())
            || record.digest() != semantic_grant.record_digest()
            || self.record.receipt_commitment() != semantic_grant.receipt_commitment()
            || self.record.authority_binding_digest()
                != Some(semantic_grant.authority_binding_digest())
            || self.record.authority_binding_digest() != Some(self.carrier.digest())
            || !effect_time_carrier.matches_assignment_and_lease_of(&self.carrier)
            || effect_time_carrier.replay_fence() != self.carrier.replay_fence()
            || effect_time_carrier.verified_at_unix_seconds() != effect_time_unix_seconds
            || !effect_time_carrier.is_current_for(intent, effect_time_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::InvalidRecoveryTransition);
        }
        Ok(ProtectedAssignmentEffectHandoffV1 {
            publication: self,
            semantic_grant,
            effect_time_carrier,
        })
    }
}

impl ProtectedAssignmentEffectHandoffV1 {
    /// Returns the exact typed assignment intent selected by the reducer plan.
    pub(in crate::local_inventory::store_authority) fn intent(
        &self,
    ) -> &crate::local_inventory::assignment::AssignmentIntentV1 {
        self.semantic_grant.intent()
    }

    /// Returns the exact durable operation identity.
    pub(in crate::local_inventory::store_authority) fn operation(&self) -> OperationId {
        self.semantic_grant.operation()
    }

    /// Returns the exact durable effect commitment.
    pub(in crate::local_inventory::store_authority) fn effect_digest(&self) -> ObjectDigest {
        self.semantic_grant.effect_digest()
    }

    /// Returns the carrier contract that authenticated the durable row.
    pub(in crate::local_inventory::store_authority) fn carrier_contract_digest(
        &self,
    ) -> ObjectDigest {
        self.publication.carrier.digest()
    }

    /// Returns the current carrier contract checked at effect handoff time.
    pub(in crate::local_inventory::store_authority) fn effect_time_carrier_contract_digest(
        &self,
    ) -> ObjectDigest {
        self.effect_time_carrier.digest()
    }

    /// Returns the reducer-issued semantic authority retained by the handoff.
    pub(in crate::local_inventory::store_authority) fn semantic_authority_binding_digest(
        &self,
    ) -> ObjectDigest {
        self.semantic_grant.authority_binding_digest()
    }
}

impl ProtectedAssignmentEffectReadyV1 {
    /// Returns the exact reducer-selected assignment intent.
    #[must_use]
    pub fn intent(&self) -> &crate::local_inventory::assignment::AssignmentIntentV1 {
        self.handoff.intent()
    }

    /// Returns the exact durable operation identity.
    #[must_use]
    pub fn operation(&self) -> OperationId {
        self.handoff.operation()
    }

    /// Returns the exact durable effect commitment.
    #[must_use]
    pub fn effect_digest(&self) -> ObjectDigest {
        self.handoff.effect_digest()
    }

    /// Returns the carrier commitment persisted with the assignment row.
    #[must_use]
    pub fn carrier_contract_digest(&self) -> ObjectDigest {
        self.handoff.carrier_contract_digest()
    }

    /// Returns the freshly reauthenticated effect-time carrier commitment.
    #[must_use]
    pub fn effect_time_carrier_contract_digest(&self) -> ObjectDigest {
        self.handoff.effect_time_carrier_contract_digest()
    }

    /// Returns the reducer-issued semantic authority commitment.
    #[must_use]
    pub fn semantic_authority_binding_digest(&self) -> ObjectDigest {
        self.handoff.semantic_authority_binding_digest()
    }
}

impl ProtectedMultiNodeAuthorityOwnerV1 {
    pub(in crate::local_inventory::store_authority) fn commit_domain_projection(
        &mut self,
        state: MultiNodeReducerStateV1,
        operation: OperationId,
        effect_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        let domain = state.domain();
        let (sequence, predecessor_digest) = self.store.backend.next_domain_boundary(domain)?;
        let payload = crate::local_inventory::journal::CanonicalJournalPayloadV1::new(state)?;
        let payload_digest = payload.digest();
        let record = MultiNodeJournalRecordV1::new(
            domain,
            operation,
            sequence,
            predecessor_digest,
            payload_digest,
            payload,
            JournalEffectStateV1::Committed,
            effect_digest,
        )?;
        self.store
            .commit_record_once(record, verified_at_unix_seconds)
    }
}
