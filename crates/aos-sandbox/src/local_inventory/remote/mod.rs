//! Explicitly selected protected transport and store orchestration.
//!
//! This module is absent without `multi-node`. Its adapters consume the local
//! protected owner's validated views; they do not replace lease or complete
//! inventory ownership. Transport custody remains in the verifier's private
//! child. No listener, worker, service registration or advertisement is added.

pub use super::carrier_authority::{
    ProtectedCoordinatorChannelOriginalV1, ProtectedCoordinatorRequestOriginalV1,
};

pub use super::store_authority::remote::{
    ProtectedAssignmentEffectReadyV1, ProtectedAssignmentRecoveryRequiredV1,
    ProtectedAssignmentStoreCommitV1, ProtectedAssignmentWriteErrorV1,
    ProtectedAssignmentWriteOutcomeV1, ProtectedAssignmentWriteResolutionV1,
    ProtectedCoordinatorChannelScopeV1, ProtectedCoordinatorResponseScopeV1,
    ProtectedDestinationAssignmentRestoreV1, ProtectedDrainRequestScopeV1,
    ProtectedMultiNodeEvidenceSessionV1, ProtectedMultiNodeUpdateErrorV1,
    ProtectedOutboundNodeRequestV1, ProtectedSnapshotArtifactRecoveryV1,
    ProtectedSnapshotChunkCommitOutcomeV1, ProtectedSnapshotDependencyCommitOutcomeV1,
    ProtectedSnapshotDependencyRecoveryV1, ProtectedSnapshotDestinationAuthorityOwnerV1,
    ProtectedSnapshotRequestScopeV1, ProtectedSnapshotResumeReadyV1,
    ProtectedSnapshotSourceAdmissionV1, ProtectedSnapshotTransferRolesV1,
    ProtectedWatchArtifactRecoveryOutcomeV1, ProtectedWatchArtifactRecoveryV1,
    ProtectedWatchBootstrapCommitOutcomeV1, ProtectedWatchCommitOutcomeV1,
    ProtectedWatchRequestScopeV1, ProtectedWatchResyncRequiredV1,
};
