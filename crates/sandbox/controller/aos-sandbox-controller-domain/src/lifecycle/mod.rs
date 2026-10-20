//! Dormant lifecycle transaction records and recovery classification.
//!
//! This module models controller intent without granting broker authority or
//! dispatching effects. Protected transactions use the shared native domain owner;
//! Protocol owns resource/edge DATA, model errors, postorder rules and the whole
//! Delete grammar. Lifecycle admission and recovery policy stay here. This
//! organization does not activate the controller, public protocol or readiness
//! advertisement.

mod atomic_snapshot_source;
mod attempt;
mod auxiliary_checkpoint;
mod auxiliary_payload;
mod boot_reconcile;
pub(crate) use boot_reconcile::{SelectedDeleteStoragePreparationDataV2,
    SelectedDeleteResourceDataV4, select_first_local_delete_network_data_v4,
    DeleteStorageSelectionErrorV2, select_first_local_delete_storage_preparation_data_v2};
mod cancel;
mod codec;
mod coordination;
mod create_placement_join;
mod deletion;
#[cfg(target_os = "linux")]
pub(crate) mod delete_batch_comparison;
#[cfg(target_os = "linux")]
pub(crate) mod delete_pending;
#[cfg(test)]
mod delete_batch_tests;
mod digest;
mod durable;
mod evidence;
mod format;
pub use format::LifecycleOperationDecodeOriginalV1;
pub use durable::LifecycleAuxiliaryDecodeOriginalV1;
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
mod protected_owner;
pub(crate) use protected_owner::completed_stop;
pub(crate) use protected_owner::{LifecycleHistoricalReadOriginalV1,
    stop_source_receiving_demand_v4, stop_inventory_challenge_receiving_bytes_v5,
    stop_cleanup_completion_receiving_demand_v1};
pub(crate) use protected_owner::{PreparedSourceLifecycleAdmissionV1, SourceLifecycleAdmissionCommitV1,
    create_provisioning_admission_receiving_demand_v1,
    create_provisioning_uncommitted_source_receiving_demand_v1};
mod public_admission;
mod public_operation;
#[cfg(target_os = "linux")]
pub(crate) use public_admission::{
    DeleteCandidateOperationErrorV2, authorized_delete_operation_data_v2,
    delete_candidate_projection_generation_data_v2,
};
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

pub use crate::controller_lifecycle_stop::StopCleanupSourceAppendOriginalV1;

pub use atomic_snapshot_source::{
    LifecycleAtomicSnapshotSourceAdmissionV1, LifecycleAtomicSnapshotSourceCompletionV1,
    LifecycleAtomicSnapshotSourceErrorV1, LifecycleAtomicSnapshotSourceRecoveryV1,
    LifecycleAtomicSnapshotSourceStoreV1,
};
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
    DeletePlanningBrokerInventoryDataV2, DeletePlanningMountInventoryDataV2, delete_planning_broker_inventory_receiving_demand_v2,
    delete_planning_broker_inventory_role_receiving_demand_v2,
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
pub use create_placement_join::{CreatePlacementJoinErrorV1, CreatePlacementObservationJoinV1};
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
    LifecycleIntentV1, LifecycleMethodV1, LifecycleResumeSourceV1, LifecycleRetryV1,
    LifecycleStepClassV1, LifecycleStepDomainV1, LifecycleStepStateV1, LifecycleTargetFenceV1,
    LifecycleTimeV1, LiveRuntimeFenceV1, ResourceExpectationV1, ResourceExpectedStateV1,
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
pub use projection::{LifecycleOperationClaimV1, LifecycleTerminalProjectionV1};
pub use protected_journal::{
    AppliedLifecycleJournalTransactionV1, LifecycleProtectedJournalErrorV1,
    LifecycleProtectedJournalKeyV1, LifecycleProtectedRecordKindV1, lifecycle_protected_key_v1,
};
pub(crate) use protected_owner::{
    retained_lifecycle_replay_receiving_demand_v1, LifecycleVerifierRecoveryOriginalV1,
    LifecycleCurrentOperationSelectionOriginalV1,
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
    lifecycle_desired_state_semantic_commit_v1, lifecycle_public_mutation_admission_v1,
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
    LifecycleMethodSemanticCommitDigestV1, LifecycleMethodSemanticCommitV1,
    LifecycleReadCommitFactV1, LifecycleReservationCommitFactV1,
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

mod progress_identity;
#[doc(hidden)]
pub use progress_identity::{
    lifecycle_plan_resource_id_v5,
    lifecycle_initial_reservation_transaction_id_v1,
    lifecycle_plan_binding_transaction_id_v1,
    lifecycle_progress_transaction_id_v1,
};


pub(crate) use protected_owner::{
    operation_record_kind as provisioning_operation_record_kind_v1,
    require_same_lifecycle_admission_v1,
};

pub(crate) use public_admission::{lifecycle_desired_state_semantic_commit_with_facts_v1, start_semantic_commit_receiving_demand_v2};

pub(crate) use protected_owner::create_provisioning_committed_source_receiving_demand_v1;

pub(crate) use phase6::lifecycle_phase6_bind_controller_anchor_v1;

pub(crate) use model::create_operation_resident_bytes_v1;

pub(crate) use protected_owner::{start_provisioning_admission_receiving_demand_v1, start_provisioning_source_receiving_demand_v2};
