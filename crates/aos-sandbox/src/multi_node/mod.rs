//! Pure coordinator-to-node scheduling and reconciliation models.
//!
//! This module contains no transport, clock, lease-signing, or privileged
//! effect implementation. Capability reports and node observations remain
//! untrusted until an authenticated carrier and the relevant durable controller
//! state validate them. In particular, an assignment or reconciliation value
//! from this module never confers, renews, releases, or transfers ownership
//! authority.

pub mod assignment;
pub mod capability;
mod carrier_authority;
pub mod draining;
pub mod evidence;
mod evidence_authority;
pub mod journal;
pub mod placement;
pub mod protocol;
mod reducer_state;
mod store_authority;

pub use assignment::{
    AssignmentAcceptanceApplyOutcomeV1, AssignmentAcceptanceReducerV1, AssignmentIntentV1,
    AssignmentObservationApplyOutcomeV1, AssignmentObservationPhaseV1,
    AssignmentObservationReasonV1, AssignmentObservationReducerV1, AtomicSnapshotPublicationV1,
    AuthenticatedSnapshotChunkV1, AuthenticatedSnapshotDependencyRangeV1,
    DurableSnapshotDependencySetV1, DurableSnapshotTransferCheckpointV1, InvalidAssignmentModel,
    InvalidSnapshotTransfer, MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES, MAX_SNAPSHOT_TRANSFER_CHUNKS,
    MAX_SNAPSHOT_TRANSFER_DEPENDENCIES, MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES,
    NodeAssignmentObservationV1, SelectedCapabilityBindingV1, SnapshotDependencyRangeV1,
    SnapshotDependencyReducerV1, SnapshotRestoreAdmissionDecisionV1, SnapshotRestoreAdmissionV1,
    SnapshotRestoreBlockReasonV1, SnapshotTransferApplyOutcomeV1, SnapshotTransferChunkRequestV1,
    SnapshotTransferChunkV1, SnapshotTransferCompletionV1, SnapshotTransferIdentityV1,
    SnapshotTransferManifestV1, SnapshotTransferReducerV1, SnapshotTransferResumeV1,
    SnapshotTransferVersionV1, VerifiedAssignmentAcceptanceV1, VerifiedAssignmentAuthorityV1,
    VerifiedGuardianStateV1, VerifiedRestoreAuthorizationV1, VerifiedSnapshotDependencySetV1,
    VerifiedSnapshotDependencyV1, VerifiedStagedSnapshotV1,
};
pub use capability::{
    CapabilityApplyOutcomeV1, CapabilityChangeV1, CarrierValidatedCapabilityObservationV1,
    HardFeatureFactRequirementV1, InvalidNodeCapability, MAX_NODE_CAPABILITY_FACTS,
    MAX_NODE_FEATURES, MAX_NODE_PROTOCOL_OFFERS, NodeAdmissionStateV1, NodeBootId,
    NodeBootLineageV1, NodeCapabilityFactV1, NodeCapabilityKindV1, NodeCapabilityReducerV1,
    NodeCapabilitySnapshotV1, NodeProbeEvidenceV1, NodeProtocolOfferV1, NodeProtocolV1,
    hard_feature_fact_requirements_v1_0,
};
pub use draining::{
    DrainAssignmentObservationV1, DrainAssignmentPlanV1, DrainAssignmentProgressV1,
    DrainAssignmentStrategyV1, DrainBlockReasonV1, DrainContainmentEvidenceV1,
    DrainDirectiveApplyOutcomeV1, DrainDirectiveReducerV1, DrainDirectiveV1,
    DrainGuardianEvidenceV1, DrainGuardianStateV1, DrainObservationApplyOutcomeV1,
    DrainObservationReducerV1, DrainObservationV1, DrainPhaseV1, DrainReleaseEvidenceV1,
    DrainSnapshotEvidenceV1, InvalidDrainModel, MAX_DRAIN_ASSIGNMENTS, NodeDrainModeV1,
};
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
pub use placement::{
    AffinityPlacementV1, CandidateRejectionReasonV1, CandidateRejectionV1, InvalidPlacementInput,
    MAX_AFFINITY_PLACEMENTS, MAX_PLACEMENT_CANDIDATES, MAX_PLACEMENT_REQUIRED_FEATURES,
    PlacementBlockReasonV1, PlacementCandidateV1, PlacementDecisionV1, PlacementSelectionV1,
    place_deterministically,
};
pub use protocol::{
    AssignmentResyncActionV1, AssignmentResyncPlanV1, AuthenticatedNodeSessionV1,
    BoundedFrameDecodeError, BoundedFrameDecoderV1, CanonicalNodeFrameKindV1, CanonicalNodeFrameV1,
    CanonicalNodeSemanticCodecV1, CarrierValidatedResyncInventoryV1, InvalidMultiNodeProtocol,
    MAX_NODE_REQUEST_BYTES, MAX_NODE_RESPONSE_BYTES, MAX_RESYNC_ASSIGNMENTS, MAX_WATCH_EVENTS,
    NodeRequestBodyV1, NodeRequestEnvelopeV1, NodeResponseBodyV1, NodeResponseEnvelopeV1,
    NodeWatchBindingV1, NodeWatchBootstrapV1, NodeWatchCursorV1, NodeWatchEventBodyV1,
    NodeWatchEventV1, ResyncInventoryV1, RollingVersionWindowV1, build_assignment_resync_plan,
    stable_watch_bootstrap_uid, stable_watch_event_uid,
};
pub use reducer_state::{
    AssignmentJournalStateV1, CapabilityJournalStateV1, DrainJournalStateV1,
    DurableAffinityProjectionV1, DurableAssignmentObservationV1, DurableDependencyProjectionV1,
    DurableDrainAssignmentV1, DurableDrainObservationV1, DurableEvidenceBindingV1,
    DurablePublicationProjectionV1, DurableStagedChunkV1, DurableWatchEventV1,
    MultiNodeReducerStateV1, SnapshotTransferJournalStateV1, WatchJournalStateV1,
};
