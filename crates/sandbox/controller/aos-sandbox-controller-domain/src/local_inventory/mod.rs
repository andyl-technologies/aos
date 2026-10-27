//! Protected local recovery inventory and retained authority history.
//!
//! The local Controller consumes protected snapshot inventory during recovery.
//! Capability reports and node observations remain untrusted until an
//! authenticated carrier and the relevant durable state validate them. An
//! assignment or reconciliation value never confers, renews, releases, or
//! transfers ownership authority. Private sealed adapters bind authenticated
//! peer, epoch, lease, signature and replay facts to exact protected journal
//! transactions. This module owns no transport listener or service activation.
//!
//! Local recovery validates the complete historical assignment, drain, watch
//! and snapshot projections, including an owner-proven empty transfer set.
//! Their canonical domains and fixed protected names remain unchanged. The
//! fixed local lease issuer belongs to the separate `aos-sandbox-ownership` crate.
//!
//! The optional Coordinator owns placement, remote observation reconciliation,
//! canonical transport exchanges, and watch/drain/transfer request workflows.
//! Its `multi-node` inputs borrow genuine native channel and store contracts in
//! [`remote`]. Private local issuers retain authenticated sessions, source and
//! destination admission, artifact custody, protected writes, publication and
//! outcome-unknown recovery. They cannot be created from portable DATA.
//!
//! Local opening, inventory discovery, currentness and complete retained-history
//! replay remain available by default. Shared identities and non-authorizing
//! models belong to `aos-sandbox-core`; generated remote wire mapping belongs to
//! the explicitly selected coordinator protocol crate. Authenticated snapshot
//! handoffs and the native streaming proof issuers require `multi-node`.

pub mod assignment;
pub mod capability;
mod carrier_authority;
pub mod draining;
pub mod evidence;
mod evidence_authority;
pub mod journal;
mod protected_artifact_store;
pub mod protocol;
mod reducer_state;
#[cfg(feature = "multi-node")]
pub mod remote;
mod store_authority;

pub use assignment::{
    AssignmentObservationPhaseV1, AssignmentObservationReasonV1, AtomicSnapshotPublicationV1,
    DurableSnapshotDependencySetV1, NodeAssignmentObservationV1, SnapshotTransferCompletionV1,
    VerifiedAssignmentAuthorityV1, VerifiedGuardianStateV1, VerifiedSnapshotDependencySetV1,
    VerifiedSnapshotDependencyV1, VerifiedStagedSnapshotV1,
};

#[cfg(feature = "multi-node")]
pub use assignment::{
    AuthenticatedSnapshotChunkV1, AuthenticatedSnapshotDependencyRangeV1,
    DurableSnapshotTransferCheckpointV1, SnapshotDependencyReducerV1,
    SnapshotRestoreAdmissionDecisionV1, SnapshotRestoreAdmissionV1, SnapshotRestoreBlockReasonV1,
    SnapshotTransferApplyOutcomeV1, SnapshotTransferReducerV1, VerifiedAssignmentAcceptanceV1,
    VerifiedRestoreAuthorizationV1,
};

pub use capability::CarrierValidatedCapabilityObservationV1;
pub use draining::{
    DrainAssignmentObservationV1, DrainContainmentEvidenceV1, DrainGuardianEvidenceV1,
    DrainObservationV1, DrainReleaseEvidenceV1, DrainSnapshotEvidenceV1,
};
#[cfg(feature = "multi-node")]
pub use evidence_authority::AffinityPlacementV1;

pub use evidence::{AuthenticatedEvidenceContextV1, InvalidEvidenceContext};
pub use journal::{
    CanonicalJournalPayloadV1, DurableJournalEffectV1, InvalidMultiNodeJournal,
    JournalApplyOutcomeV1, JournalEffectStateV1, MAX_ASSIGNMENT_JOURNAL_STATE_BYTES,
    MAX_CAPABILITY_JOURNAL_STATE_BYTES, MAX_DRAIN_JOURNAL_STATE_BYTES,
    MAX_MULTI_NODE_DOMAIN_STATE_BYTES, MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES,
    MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS, MAX_SNAPSHOT_JOURNAL_STATE_BYTES,
    MAX_WATCH_JOURNAL_STATE_BYTES, MultiNodeJournalCheckpointV1, MultiNodeJournalDomainV1,
    MultiNodeJournalRecordV1, MultiNodeJournalReducerV1, PartialEffectRecoveryV1,
    ProtectedJournalCheckpointV1, ProtectedJournalRecordV1,
};
pub use protocol::{
    AuthenticatedNodeSessionV1, BoundedFrameDecodeError, BoundedFrameDecoderV1,
    CanonicalNodeFrameV1, CanonicalNodeSemanticCodecV1, NodeResponseBodyV1, NodeWatchEventBodyV1,
    NodeWatchEventV1, ResyncInventoryV1,
};
#[cfg(feature = "multi-node")]
pub use protocol::{
    CarrierValidatedResyncInventoryV1, NodeRequestEnvelopeV1, NodeResponseEnvelopeV1,
    NodeWatchBootstrapV1,
};

pub use reducer_state::{
    AssignmentJournalStateV1, CapabilityJournalStateV1, DrainJournalStateV1,
    DurableAffinityProjectionV1, DurableAssignmentObservationV1, DurableDrainAssignmentV1,
    DurableDrainObservationV1, DurableEvidenceBindingV1, DurablePublicationProjectionV1,
    DurableStagedChunkV1, DurableWatchEventV1, MultiNodeReducerStateV1,
    SnapshotTransferJournalStateV1, WatchJournalStateV1,
};
pub use store_authority::{
    ProtectedCheckpointCommitOutcomeV1, ProtectedMultiNodeAuthorityOpenErrorV1,
    ProtectedMultiNodeAuthorityOwnerV1, ProtectedMultiNodeCurrentRecordV1,
    ProtectedRecordCommitOutcomeV1, ProtectedStoreRecoveryOutcomeV1,
    ProtectedStoreRecoveryRequiredV1,
};
