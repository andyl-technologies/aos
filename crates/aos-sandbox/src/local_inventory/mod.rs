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
//! fixed local lease issuer belongs to [`crate::local_ownership`].
//!
//! The optional Coordinator owns placement, ordered-watch adapters and committed
//! lease projection. Its selected `multi-node` inputs retain their sealed Native
//! producers here. `local_inventory::remote` exposes protected transport and store
//! orchestration. The verifier retains its private child and custody. Protected-store
//! remote exchange, assignment, drain, watch writes, and destination transfer
//! orchestration are feature-gated private children of that same owner. Local
//! opener, inventory discovery, readback, and all retained-history checks remain
//! available by default. Coordinator persistence DATA, shared session verifiers,
//! and model helpers are retained. Authenticated snapshot byte handoffs,
//! protected streaming checkpoints and streaming verification require `multi-node`.
//! Immutable manifests, resume DATA, historical Journal checkpoints and completed
//! drain evidence remain available by default.
//! This is not a fully isolated ownership crate
//! or a coordinator-free implementation graph.

pub mod assignment;
pub mod capability;
mod carrier_authority;
pub mod draining;
pub mod evidence;
mod evidence_authority;
pub mod journal;
#[cfg(feature = "multi-node")]
mod placement_input;
mod protected_artifact_store;
pub mod protocol;
mod reducer_state;
#[cfg(feature = "multi-node")]
pub mod remote;
mod store_authority;

pub use assignment::{
    AssignmentIntentV1, AssignmentObservationPhaseV1, AssignmentObservationReasonV1,
    AtomicSnapshotPublicationV1, DurableSnapshotDependencySetV1, InvalidAssignmentModel,
    InvalidSnapshotTransfer, MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES, MAX_SNAPSHOT_TRANSFER_CHUNKS,
    MAX_SNAPSHOT_TRANSFER_DEPENDENCIES, MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES,
    NodeAssignmentObservationV1, SelectedCapabilityBindingV1, SnapshotDependencyRangeV1,
    SnapshotTransferChunkRequestV1, SnapshotTransferChunkV1, SnapshotTransferCompletionV1,
    SnapshotTransferIdentityV1,
    SnapshotTransferManifestV1, SnapshotTransferResumeV1,
    SnapshotTransferVersionV1, VerifiedAssignmentAuthorityV1, VerifiedGuardianStateV1,
    VerifiedSnapshotDependencySetV1, VerifiedSnapshotDependencyV1, VerifiedStagedSnapshotV1,
};

#[cfg(feature = "multi-node")]
pub use assignment::{
    AssignmentObservationApplyOutcomeV1, AssignmentObservationReducerV1,
    AuthenticatedSnapshotChunkV1, AuthenticatedSnapshotDependencyRangeV1,
    DurableSnapshotTransferCheckpointV1, SnapshotDependencyReducerV1,
    SnapshotRestoreAdmissionDecisionV1, SnapshotRestoreAdmissionV1,
    SnapshotRestoreBlockReasonV1, SnapshotTransferApplyOutcomeV1, SnapshotTransferReducerV1,
    VerifiedAssignmentAcceptanceV1, VerifiedRestoreAuthorizationV1,
};

pub use capability::{
    CarrierValidatedCapabilityObservationV1, HardFeatureFactRequirementV1, InvalidNodeCapability,
    MAX_NODE_CAPABILITY_FACTS, MAX_NODE_FEATURES, MAX_NODE_PROTOCOL_OFFERS, NodeAdmissionStateV1,
    NodeBootId, NodeBootLineageV1, NodeCapabilityFactV1, NodeCapabilityKindV1,
    NodeCapabilitySnapshotV1, NodeProbeEvidenceV1, NodeProtocolOfferV1, NodeProtocolV1,
    hard_feature_fact_requirements_v1_0,
};
pub use draining::{
    DrainAssignmentObservationV1, DrainAssignmentPlanV1, DrainAssignmentProgressV1,
    DrainAssignmentStrategyV1, DrainBlockReasonV1, DrainContainmentEvidenceV1, DrainDirectiveV1,
    DrainGuardianEvidenceV1, DrainGuardianStateV1, DrainObservationV1, DrainPhaseV1,
    DrainReleaseEvidenceV1, DrainSnapshotEvidenceV1, InvalidDrainModel, MAX_DRAIN_ASSIGNMENTS,
    NodeDrainModeV1,
};
#[cfg(feature = "multi-node")]
pub use evidence_authority::AffinityPlacementV1;
#[cfg(feature = "multi-node")]
pub use placement_input::InvalidPlacementInput;
#[cfg(feature = "multi-node")]
pub use reducer_state::MAX_ASSIGNMENT_AFFINITIES;

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
    CanonicalNodeFrameKindV1, CanonicalNodeFrameV1, CanonicalNodeSemanticCodecV1,
    InvalidMultiNodeProtocol, MAX_NODE_REQUEST_BYTES, MAX_NODE_RESPONSE_BYTES,
    MAX_RESYNC_ASSIGNMENTS, MAX_WATCH_EVENTS, NodeResponseBodyV1, NodeWatchBindingV1,
    NodeWatchCursorV1, NodeWatchEventBodyV1, NodeWatchEventV1, ResyncInventoryV1,
    RollingVersionWindowV1, stable_watch_bootstrap_uid, stable_watch_event_uid,
};
#[cfg(feature = "multi-node")]
pub use protocol::{
    CarrierValidatedResyncInventoryV1, NodeRequestBodyV1, NodeRequestEnvelopeV1,
    NodeResponseEnvelopeV1, NodeWatchBootstrapV1,
};

pub use reducer_state::{
    AssignmentJournalStateV1, CapabilityJournalStateV1, DrainJournalStateV1,
    DurableAffinityProjectionV1, DurableAssignmentObservationV1, DurableDependencyProjectionV1,
    DurableDrainAssignmentV1, DurableDrainObservationV1, DurableEvidenceBindingV1,
    DurablePublicationProjectionV1, DurableStagedChunkV1, DurableWatchEventV1,
    MultiNodeReducerStateV1, SnapshotTransferJournalStateV1, WatchJournalStateV1,
};
pub use store_authority::{
    ProtectedCheckpointCommitOutcomeV1, ProtectedMultiNodeAuthorityOpenErrorV1,
    ProtectedMultiNodeAuthorityOwnerV1, ProtectedMultiNodeCurrentRecordV1,
    ProtectedRecordCommitOutcomeV1, ProtectedStoreRecoveryOutcomeV1,
    ProtectedStoreRecoveryRequiredV1,
};
