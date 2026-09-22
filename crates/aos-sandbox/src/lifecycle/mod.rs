//! Dormant lifecycle transaction records and recovery classification.
//!
//! This module models controller intent without granting broker authority or
//! dispatching effects. Its protected-journal adapter owns exact CAS, replay,
//! recovery, and postcommit capabilities, but remains disconnected from the
//! controller, public protocol, and readiness advertisement.

mod attempt;
mod auxiliary_checkpoint;
mod auxiliary_payload;
mod boot_reconcile;
mod cancel;
mod coordination;
mod deletion;
mod digest;
mod durable;
mod evidence;
mod format;
mod history;
mod idempotency;
mod incarnation_rebuild;
mod intent;
mod journal;
mod model;
mod operation;
mod phase6;
mod projection;
pub mod protected_journal;
pub(crate) mod protected_journal_adapter;
pub mod protected_journal_join;
mod protected_owner;
mod public_admission;
mod public_operation;
mod recovery;
mod replay_validation;
mod runtime_admission;
mod semantic;
mod semantic_digest;
mod semantic_format;
mod snapshot;
mod snapshot_availability;
mod snapshot_barrier;
mod suspension;
mod verification;

pub use attempt::{
    LifecycleAmbiguousResumeV1, LifecycleAttemptHistoryV1, LifecycleAttemptStateV1,
    LifecycleEffectAttemptV1, LifecycleEffectDirectionV1, MAXIMUM_LIFECYCLE_ATTEMPTS,
    MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP, resume_ambiguous_attempt_v1,
};
pub use auxiliary_checkpoint::{
    decode_lifecycle_auxiliary_checkpoint_v1, encode_lifecycle_auxiliary_checkpoint_v1,
};
pub use auxiliary_payload::{
    LifecycleAuxiliaryPayloadV1, MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES,
    decode_lifecycle_auxiliary_payload_v1, encode_lifecycle_auxiliary_payload_v1,
};
pub use boot_reconcile::{
    CurrentLifecycleBootDomainInventoriesV1, LifecycleAuthenticatedAtomicStorageSuccessorV1,
    LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
    LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
    LifecycleAuthenticatedBrokerDomainInventoryV1,
    LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
    LifecycleAuthenticatedRuntimeInventorySuccessorV1, LifecycleAuthenticatedRuntimeInventoryV1,
    LifecycleAuthenticatedStorageInventoryBootstrapV1,
    LifecycleAuthenticatedStorageInventorySuccessorV1, LifecycleAuthenticatedStorageInventoryV1,
    LifecycleAuthenticatedStorageReadbackV1, LifecycleAuthenticatedTransferInventoryV1,
    LifecycleBootBootstrapEndpointV1, LifecycleBootDomainEntryV1, LifecycleBootDomainInventoryV1,
    LifecycleBootDomainV1, LifecycleBootInventoryBootstrapChallengeV1, LifecycleBootReconcilerV1,
    LifecycleBootRecoveryActionV1, LifecycleBootRecoveryStepV1, LifecycleBootResourceObservationV1,
    LifecycleBootResourceStateV1, LifecycleStorageInventoryEntryV1,
    LifecycleStorageInventoryKindV1, LifecycleStorageTransitionEntryV1,
    LifecycleStorageTransitionKindV1,
};
pub(crate) use boot_reconcile::{
    LifecycleAuthenticatedBootDesiredV1, LifecycleBootInventoryBootstrapSourceV1,
    LifecycleBootInventoryRefreshSourceV1, LifecycleFreshPhysicalInventoryV1,
    fresh_physical_inventory,
};
pub use cancel::{
    LifecycleCancelIdempotencyDigestV1, LifecycleCancelIdempotencyIndexV1,
    LifecycleCancelOutcomeV1, LifecycleCancelRequestV1, LifecycleCancellationRecordV1,
    MAXIMUM_LIFECYCLE_CANCEL_BINDINGS,
};
pub use coordination::{
    LifecycleBootInventoryDigestV1, LifecycleBootInventoryDomainsV1, LifecycleBootInventoryV1,
    LifecycleControllerDependencySnapshotV1, LifecycleCoordinationPhaseV1,
    LifecycleCoordinationTransactionV1, LifecycleDatasetTransactionDigestV1,
    LifecycleProtectedRetentionAcknowledgementV1, LifecycleQuiesceDigestV1,
    LifecycleRetentionLedgerEntryV1, LifecycleRetentionLedgerReceiptV1, LifecycleRetentionLedgerV1,
    LifecycleRetentionPurposeV1, LifecycleSuspendObservationDigestV1,
    LifecycleSuspendObservationV1, LifecycleThawCompensationDigestV1, LifecycleWriterFenceDigestV1,
};
pub use deletion::{
    LifecycleDeletionActionV1, LifecycleDeletionObservationV1, LifecycleDeletionPlanV1,
    LifecycleDeletionReceiptV1,
};
pub(crate) use durable::decode_lifecycle_auxiliary_record_from_protected_envelope_v1;
pub use durable::{
    LifecycleAtomicJoinDigestV1, LifecycleAuxiliaryCheckpointV1, LifecycleAuxiliaryHistoryV1,
    LifecycleAuxiliaryKindV1, LifecycleAuxiliaryRecordV1, LifecycleCancellationAdmissionV1,
    MAXIMUM_LIFECYCLE_AUXILIARY_BYTES, MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS,
    bind_lifecycle_atomic_join_v1, decode_lifecycle_auxiliary_record_v1,
    encode_lifecycle_auxiliary_record_v1, lifecycle_atomic_join_digest_v1,
};
pub use evidence::{
    LifecycleBootCommitFactV1, LifecycleBootRecordDigestV1, LifecycleCoordinationCommitFactV1,
    LifecycleCoordinationRecordDigestV1, LifecycleIncarnationCommitFactV1,
    LifecycleIncarnationOriginV1, LifecycleProtectedCoordinationV1,
    LifecycleProtectedRetentionLedgerV1, LifecycleRetentionCommitFactV1,
    LifecycleRetentionLedgerDigestV1, LifecycleSemanticEvidenceV1,
};
pub use format::{
    decode_operation_record_v1, encode_operation_record_v1, normalized_request_digest_v1,
};
pub use history::{LifecycleHistoryV1, LifecycleReplayError};
pub use idempotency::{
    LifecycleIdempotencyBindingV1, LifecycleIdempotencyIndexV1, LifecycleIdempotencyResolutionV1,
    LifecycleIdempotencyScopeV1, MAXIMUM_LIFECYCLE_IDEMPOTENCY_BINDINGS,
};
pub use incarnation_rebuild::{
    LifecycleAttachmentReconstructionV1, LifecycleIncarnationRebuildV1,
    LifecyclePolicyIntersectionV1, LifecycleRebuildActionV1, LifecycleRebuildModeV1,
};
pub use intent::{
    DesiredStateCasV1, DesiredStateFenceV1, LifecycleFailureClassV1, LifecycleFailureV1,
    LifecycleIntentV1, LifecycleMethodV1, LifecycleResourceV1, LifecycleResumeSourceV1,
    LifecycleRetryV1, LifecycleStepClassV1, LifecycleStepDomainV1, LifecycleStepStateV1,
    LifecycleTargetFenceV1, LifecycleTimeV1, LiveRuntimeFenceV1, ResourceExpectationV1,
    ResourceExpectedStateV1,
};
pub use journal::{
    LIFECYCLE_JOURNAL_NAMESPACE_V1, LifecycleJournalHistoryV1, LifecycleJournalOwnershipRecordV1,
    LifecycleJournalRecordKindV1, LifecycleJournalVerifierV1, decode_lifecycle_journal_record_v1,
    encode_lifecycle_journal_record_v1,
};
pub use model::{
    DesiredStateCasDigestV1, DesiredStateDocumentDigestV1, LifecycleFailureDigestV1,
    LifecycleIdempotencyDigestV1, LifecycleInventoryDigestV1, LifecycleJournalCommitDigestV1,
    LifecycleNormalizedRequestDigestV1, LifecycleOperationV1, LifecyclePhaseV1,
    LifecycleRecordDigestV1, LifecycleResourceStateDigestV1, LifecycleSemanticCommitDigestV1,
    LifecycleSemanticCommitV1, LifecycleStepAdmissionDigestV1, LifecycleStepBodyDigestV1,
    LifecycleStepPlanDigestV1, LifecycleStepRequestDigestV1, LifecycleStepResultDigestV1,
    LifecycleStepV1, LifecycleTerminalResultV1, MAXIMUM_LIFECYCLE_EXPECTATIONS,
    MAXIMUM_LIFECYCLE_STEPS,
};
pub(crate) use phase6::LifecycleEffectRequestV1;
pub use phase6::{
    CurrentLifecycleBootInventoryV1, CurrentLifecycleCoordinationV1, CurrentLifecycleEffectV1,
    CurrentLifecycleOperationV1, CurrentLifecycleRetentionLedgerV1,
    CurrentLifecycleRuntimeLivenessV1, CurrentLifecycleSuspendObservationV1,
    CurrentLifecycleTargetAssignmentV1, LifecycleAuthenticatedBrokerEffectV1,
    LifecycleDeferredEffectCursorV1, LifecycleEffectDomainV1, LifecycleEffectObservationV1,
    LifecycleMethodCompletionV1, LifecycleMethodPlanV1, LifecyclePersistedEffectCursorV1,
    LifecyclePhase6EffectPlanV1, LifecyclePhase6ErrorV1,
    lifecycle_phase6_effect_body_commitment_v2, lifecycle_phase6_plan_commitment_v1,
    lifecycle_phase6_planned_step_v1,
};
pub use projection::{
    LifecycleModelError, LifecycleOperationClaimV1, LifecycleTerminalProjectionV1,
};
pub(crate) use protected_journal::lifecycle_protected_key_v1;
pub use protected_journal::{
    AppliedLifecycleJournalTransactionV1, LifecycleProtectedJournalErrorV1,
    LifecycleProtectedJournalKeyV1,
};
pub use protected_owner::{
    LifecycleCurrentAuxiliaryPublicationV1, LifecycleOperationAdmissionV1,
    LifecycleProgressCommitOutcomeV1, LifecycleProgressOutcomeUnknownV1,
    LifecycleProgressRecoveryV1, LifecycleProtectedCancellationAdmissionV1,
    LifecycleProtectedCancellationResolutionV1, LifecycleProtectedJournalOwnerV1,
    PreparedLifecycleProgressV1,
};
pub use public_admission::{
    LifecyclePublicMutationAdmissionErrorV1, LifecyclePublicMutationAdmissionV1,
    lifecycle_public_mutation_admission_v1,
};
pub use public_operation::{
    LifecyclePublicOperationErrorV1, lifecycle_operation_from_public_mutation_v1,
};
pub use recovery::{LifecycleRecoveryActionV1, classify_operation_recovery_v1};
pub use runtime_admission::{
    LifecycleRuntimeAdmissionErrorV1, LifecycleRuntimeAdmissionFenceV1,
    lifecycle_runtime_admission_fence_from_journal_v1,
};
pub use semantic::{
    LifecycleAssignmentCommitFactV1, LifecycleAuthoritativeSemanticCommitV1,
    LifecycleCascadePlanDigestV1, LifecycleCascadeTombstonePlanV1, LifecycleCommittedResourceV1,
    LifecycleDependencyEdgeV1, LifecycleMethodSemanticCommitDigestV1,
    LifecycleMethodSemanticCommitV1, LifecycleReadCommitFactV1, LifecycleReservationCommitFactV1,
    LifecycleRetentionAcknowledgementV1, LifecycleRetentionClaimDigestV1,
    LifecycleSemanticCommitFactV1, LifecycleSnapshotManifestDigestV1,
    LifecycleSnapshotRetentionReleaseV1, LifecycleTransactionIdV1,
};
pub use snapshot::{LifecycleSnapshotTombstoneDigestV1, LifecycleValidatedSnapshotV1};
pub use snapshot_availability::{
    LifecycleExternalAvailabilityEvidenceV1, LifecycleExternalAvailabilityProviderV1,
    LifecycleSecretIssuerAvailabilityV1, LifecycleSecretIssuerTrustOwnerV1,
    LifecycleServiceCheckpointAvailabilityV1, LifecycleServiceCheckpointTrustOwnerV1,
    LifecycleSnapshotAvailabilityContractV1, LifecycleSnapshotAvailabilityModeV1,
    LifecycleSnapshotDependencyClassV1, LifecycleSnapshotDependencyV1,
    LifecycleSnapshotTransferJoinV1,
};
pub use snapshot_barrier::{
    LifecycleAtomicDatasetSnapshotMemberV1, LifecycleAtomicDatasetSnapshotPlanV1,
    LifecycleSnapshotBarrierActionV1, LifecycleSnapshotBarrierV1,
};
pub use suspension::{
    LifecycleSuspensionActionV1, LifecycleSuspensionModeV1, LifecycleSuspensionPlanV1,
};
pub use verification::LifecycleReplayVerificationV1;
