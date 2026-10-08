//! Explicitly selected remote placement, transport, and protected orchestration.
//!
//! This module is absent without `multi-node`. Its adapters consume the local
//! protected owner's validated views; they do not replace lease or complete
//! inventory ownership. Transport custody remains in the verifier's private
//! child. No listener, worker, service registration or advertisement is added.

#[cfg(target_os = "linux")]
mod lease_protobuf;
pub mod placement;
pub mod watch_service;

pub use super::carrier_authority::{
    DormantAuthenticatedCoordinatorNodeTransportV1, DormantCoordinatorNodeEncodingV1,
    DormantOutboundExchangeV1, DormantOutboundResponseV1, DormantTransportHandshakeV1,
};
pub use placement::{
    AffinityPlacementV1, CandidateRejectionReasonV1, CandidateRejectionV1, InvalidPlacementInput,
    MAX_AFFINITY_PLACEMENTS, MAX_PLACEMENT_CANDIDATES, MAX_PLACEMENT_REQUIRED_FEATURES,
    PlacementBlockReasonV1, PlacementCandidateV1, PlacementDecisionV1, PlacementSelectionV1,
    place_deterministically,
};
pub use watch_service::{
    DormantOrderedWatchClientV1, DormantOrderedWatchServiceV1, DormantWatchClientOutcomeV1,
    DormantWatchReadOutcomeV1, MAX_DORMANT_WATCH_HISTORY,
};

pub use super::store_authority::remote::{
    ProtectedAssignmentEffectReadyV1, ProtectedAssignmentRecoveryRequiredV1,
    ProtectedAssignmentStoreCommitV1, ProtectedAssignmentWriteErrorV1,
    ProtectedAssignmentWriteOutcomeV1, ProtectedAssignmentWriteResolutionV1,
    ProtectedDestinationAssignmentRestoreV1, ProtectedMultiNodeEvidenceSessionV1,
    ProtectedMultiNodeUpdateErrorV1, ProtectedOutboundNodeRequestV1,
    ProtectedSnapshotArtifactRecoveryV1, ProtectedSnapshotChunkCommitOutcomeV1,
    ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedSnapshotDependencyRecoveryV1,
    ProtectedSnapshotDestinationAuthorityOwnerV1, ProtectedSnapshotResumeReadyV1,
    ProtectedSnapshotSourceAdmissionV1, ProtectedSnapshotTransferRolesV1,
    ProtectedWatchArtifactRecoveryOutcomeV1, ProtectedWatchArtifactRecoveryV1,
    ProtectedWatchBootstrapCommitOutcomeV1, ProtectedWatchCommitOutcomeV1,
    ProtectedWatchResyncRequiredV1,
};
