//! Implements the unprivileged AOS sandbox controller.
//!
//! The [`journal`] module owns the append-only desired-state and operation
//! journal. It validates and replays durable transactions before a future
//! reconciler is allowed to issue effects. Protected publisher stores retain
//! current policy and capabilities. [`publisher_admin::audit`] owns
//! inert execution/challenge audit records; Linux publisher control and sessions
//! bind their registration to the original live process without granting effects.
//! [`cli_model`] owns CLI grammar and the Controller's adopted request envelope;
//! protocol owns untrusted public request DATA and client proposals.
//! [`controller_query`] retains protected observation and operator projection;
//! checked public models, reducers, and holder-key signature profiles live in
//! `aos_sandbox_protocol::public_api`. [`environment`],
//! [`git`], [`hierarchy`],
//! [`lifecycle`], [`local_inventory`], and [`policy_compiler`] own RFC-0021
//! domain models and protected-journal seams. [`source_domain`] owns the live
//! fixed Source journal custody and original Q04 loans.
//! [`execution_output_reservation`] owns accepted-Create-derived, protected
//! pre-Host output-byte claims while execution authorization remains closed.
//! [`execution_guest_identity`] reads back private-namespace credential
//! mapping bounds without granting execution authority.
//! [`controller_execution_observe_reservation`] shares the non-authorizing
//! Create-to-Observe reservation codec with the Controller execution owner.
//! The private broker-authority engine shares signed admission and authenticated
//! journal records through the privileged-broker facade. Raw Linux syscalls and
//! audience-specific privileged broker effects deliberately live outside this crate.

#[cfg(all(feature = "test-fixtures", not(debug_assertions)))]
compile_error!("the protected-journal test fixture is unavailable in release builds");

#[cfg(all(feature = "cache-physical-join-vm-fixture", not(debug_assertions)))]
compile_error!("the Cache physical-join VM fixture is unavailable in release builds");

mod attach_decision;
pub mod attach_route_issuer;
#[cfg(target_os = "linux")]
pub mod attachment_effect_owner;
#[cfg(target_os = "linux")]
pub mod attachment_mount;
#[cfg(target_os = "linux")]
pub mod attachment_reconciliation;
#[cfg(target_os = "linux")]
pub mod attachment_slot_state;
#[cfg(target_os = "linux")]
pub mod attachment_source;
#[cfg(target_os = "linux")]
pub mod attachment_state;
#[cfg(target_os = "linux")]
pub mod attachment_verification;
pub mod cache_residency;
pub mod cli_model;
pub mod controller;
mod controller_inventory_absence;
#[cfg(target_os = "linux")]
pub mod controller_execution_argument_attempt;
pub mod controller_execution_argument_receipt;
pub mod controller_execution_observe_reservation;
pub mod controller_execution_output_settlement;
#[cfg(target_os = "linux")]
pub mod controller_execution_operation;
#[cfg(target_os = "linux")]
mod closed_controller_append;
#[cfg(target_os = "linux")]
pub mod controller_lifecycle_stop;
#[cfg(target_os = "linux")]
pub mod controller_execution_preissue;
#[cfg(target_os = "linux")]
pub mod controller_execution_spec_attempt;
/// Retains original Capture60 admission on the actual Controller writer.
#[cfg(target_os = "linux")]
pub mod controller_storage_capture_admission;
#[cfg(target_os = "linux")]
pub mod controller_fuse_admission;
pub mod controller_no_apply_settlement_cursor;
pub mod controller_query;
#[cfg(target_os = "linux")]
mod controller_resource_reservation;
#[cfg(target_os = "linux")]
pub mod controller_service;
pub mod controller_storage_output_reserve_attempt;
#[cfg(target_os = "linux")]
pub mod destination_slot_effect;
#[cfg(target_os = "linux")]
pub mod destination_slot_inventory;
pub mod dispatch;
pub mod environment;
pub mod execution_guest_identity;
#[cfg(target_os = "linux")]
pub mod execution_output_reservation;
#[cfg(target_os = "linux")]
pub mod execution_parent_resource;
pub mod filesystem_view_state;
pub mod git;
#[cfg(target_os = "linux")]
pub mod guest_root_publication;
pub mod hierarchy;
#[cfg(target_os = "linux")]
pub mod host_catalog_publication;
#[cfg(target_os = "linux")]
pub mod host_catalog_reconciliation;
#[cfg(target_os = "linux")]
pub mod immutable_image;
pub mod journal;
pub mod lifecycle;
mod lifecycle_authority;
#[cfg(target_os = "linux")]
pub mod mount_attempt;
#[cfg(target_os = "linux")]
mod mount_inventory_snapshot;
#[cfg(target_os = "linux")]
pub mod mount_observation_state;
#[cfg(target_os = "linux")]
pub mod mount_preparation;
#[cfg(target_os = "linux")]
pub mod mount_source_acquisition_inventory;
pub mod local_inventory;
#[cfg(target_os = "linux")]
pub mod normal_root;
#[cfg(target_os = "linux")]
pub use normal_root::{
    StoragePhysicalWorkerLoanV1, StorageBoundPhysicalWorkerLoanV1, StoragePhysicalWorkerDisposalV1,
    StorageResidentCaptureWorkerV2, StorageCaptureWorkerBorrowV2, StorageCaptureWorkerDisposalV2,
    StorageCaptureStopQuiescenceV4,
    StorageRootLaunchExportReceivingLoanV2, StorageRootLaunchExportDisposalV2,
    StorageInitialSessionHelloDisposalV1, StorageSessionHelloDisposalErrorV1,
    StorageOutputOwedAfterOriginalV1,
    StorageFloorPhysicalProgramReceivingV2,
    StorageLifecycleSessionLoanV1, StorageLifecyclePositiveDisposalV1, StorageLifecycleDisposalErrorV1,
    StorageStateRecoveryEncodingLoanV1, StorageInitialPinQuiescenceLoanV1,
    StorageGuestRootTemplateReceivingLoanV1, StoragePrepareReceivingLoanV1, StoragePrepareSessionReplayLoanV1, StoragePrepareStartupJournalLoanV1, StorageReceivingClosedV1,
};
mod operator_abandon_ack;
pub mod ownership_resume;
pub mod policy_compiler;
pub(crate) mod protected_domain_journal;
#[cfg(target_os = "linux")]
pub mod production_operation_compiler;
#[cfg(target_os = "linux")]
pub mod source_provider_startup;
pub mod source_domain;

#[cfg(target_os = "linux")]
pub use production_operation_compiler::{ControllerNixStartRecipeSelectorV2, NixStartAdmissionErrorV2};
#[cfg(target_os = "linux")]
pub mod public_api_session;
pub mod public_attach_pending;
#[cfg(target_os = "linux")]
pub mod public_capability_issuance;
#[cfg(target_os = "linux")]
pub mod public_mutation_compiler;
#[cfg(target_os = "linux")]
pub mod public_policy_planner;
#[cfg(target_os = "linux")]
pub mod cold_launch_publication;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use cold_launch_publication::{OriginalPublicationActionV1, OriginalPublicationActionClosedV1};
pub mod publication;
pub mod publisher_admin;
pub mod reconciler;
#[cfg(target_os = "linux")]
pub mod resource_inventory;
pub mod runtime_authority;
#[cfg(target_os = "linux")]
mod runtime_deployment;
pub mod runtime_execution;
#[cfg(target_os = "linux")]
pub mod runtime_scope;
pub mod sandbox_spec_state;
#[cfg(target_os = "linux")]
mod signer_mount;
#[cfg(target_os = "linux")]
mod systemd_property_data;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod tpm_nv_custody;

#[cfg(target_os = "linux")]
pub use controller_resource_reservation::{
    ControllerAttachmentStartupV1, ControllerFirstGlobalPrefixAttemptV1, ControllerResourceBankOpeningV1,
    ControllerPublisherBusEnvironmentV1, ControllerPublisherBusEnvironmentErrorV1,
    ControllerPublisherReceivingV1, ControllerPublisherStartupDataV1,
    ControllerSourceGenesisReceivingV1, ControllerPublicTlsReceivingV1,
    ControllerInitialBrokerSessionRoleV1, ControllerInitialBrokerSessionCaptureShapeV1,
    ControllerInitialBrokerSessionShapeV1, ControllerInitialBrokerSessionClosedV1,
    ControllerInitialBrokerSessionReceivingV1, ControllerInitialBrokerSessionReceivingLoanV1,
    ControllerInitialSessionCompletedNativeBorrowV1,
    ControllerRuntimeStartupShapeV1, ControllerRuntimeCredentialShapeV1,
    ControllerRuntimeRequestedCountsV1, ControllerRuntimeTaskEnvelopeV1,
    CONTROLLER_RUNTIME_TASKS_V1, CONTROLLER_RUNTIME_ROLE_TASKS_V1,
    CONTROLLER_RUNTIME_BLOCKING_THREADS_V1, CONTROLLER_RUNTIME_STACK_BYTES_V1,
    CreateContinuationIntakeAttemptV1,
    CreateProvisioningOriginalsV1, OriginalCreateProvisioningRootLoanV1,
    CreateProvisioningStorageIoOriginalV1, CreateProvisioningStorageIoLoanV1,
    CreateProvisioningStorageIoErrorV1,
    StorageProvisioningIoDisposalV1, StorageProvisioningWorkspaceOriginalV1, StorageProvisioningSessionIoShapeDataV1, DeleteStoragePreparationIoOriginalV3, DeleteStorageApplyIoOriginalV3, DeleteNetworkApplyIoOriginalV4, DeleteMountReapIoOriginalV4,
    CreateProvisioningClientSessionAssociationErrorV1, StorageProvisioningSessionPostShapeDataV1,
    OriginalCreateStorageReadyV1, CreateStorageReadyClosedV1,
    OriginalCreateStorageRootExchangeV1, CreateStorageRootExchangeClosedV1, CreateStorageControllerDriverShapeDataV1,
    OriginalCreateStorageUseSigningV1,
    OriginalCreateStorageClientSessionV1, CreateStorageClientSessionClosedV1,
    CreateStorageClientSessionShapeDataV1, CreateStorageEndpointRevalidationShapeDataV1,
    CreateStorageClientPositiveDisposalV1,
    OriginalCreateStorageInventoryV1, CreateStorageInventoryClosedV1,
    CreateStorageInventoryShapeDataV1, CreateStorageInventoryPendingDisposalV1,
    NixOriginalStartIntakeAttemptV1,
    NixOriginalStartIntakeLoanV1, ProjectPreparationReservationAttemptV1,
    StorageComponentEnvelopeOriginalV1,
    CreateStorageOwnershipProgressV1,
};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use controller_resource_reservation::{
    ResourceReservationErrorV1, require_original_host_component_pair_v2,
};

#[cfg(target_os = "linux")]
pub use runtime_deployment::{
    HeldRuntimeDeploymentAppendComparisonV1, HeldRuntimeDeploymentMainComparisonV1,
    HeldRuntimeDeploymentPairComparisonV1, HostPhysicalInvocationErrorV1,
    HostPhysicalInvocationLeaseV1, ProductionRuntimeDeploymentStartupCaptureV1,
    ProductionRuntimeDeploymentStartupPartsV1, ProductionRuntimeDeploymentStartupV1,
    RuntimeBootPreparationStartupClosedV1, RuntimeBootPreparationStartupFailureViewV1,
    RuntimeBootPreparationStartupOriginalV1,
    RuntimeBootPreparationOriginsClosedV1, RuntimeBootPreparationOriginsOriginalV1,
    RuntimeBootPreparationNativeFailureViewV1, RuntimeBootPreparationNativeOriginalV1,
    RuntimeDeploymentCanaryFailureV2, RuntimeDeploymentComparisonErrorV1,
    RuntimeDeploymentComparisonOriginsV1, RuntimeDeploymentNativeTransactionDataV1,
    RuntimeDeploymentOriginalClockCauseV3, RuntimeDeploymentOriginalClockRangeV3,
    RuntimeDeploymentOriginalWindowV3, RuntimeDeploymentStartupErrorV1,
    observe_original_runtime_deployment_clock_v3,
};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use runtime_deployment::{
    RuntimeDeploymentStorageDeliveryReadbackV2, observe_canary_storage_delivery_v2,
};

#[cfg(target_os = "linux")]
pub use attachment_mount::{
    AttachmentMountError, AttachmentMountPreparationInputV1,
    CompletedCurrentAttachmentMountAttemptV1, DurableCurrentAttachmentMountAttemptV1,
    PreparedCurrentAttachmentMountDispatchV1, PreparedCurrentAttachmentMountRecoveryV1,
    PreparedCurrentAttachmentMountReplayCatalogQueryV1,
    PreparedCurrentAttachmentMountResumeDispatchV1, PreparedCurrentAttachmentMountResumeV1,
    PreparedCurrentAttachmentMountV1,
};
#[cfg(target_os = "linux")]
pub use attachment_reconciliation::{
    AttachmentReconciliationActionV1, AttachmentReconciliationConflictV1,
    AttachmentReconciliationError, CurrentAttachmentReconciliationV1,
};
#[cfg(target_os = "linux")]
pub use attachment_slot_state::{
    AttachmentSlotCommitOutcomeV1, AttachmentSlotMutationV1, AttachmentSlotPresenceV1,
    AttachmentSlotStateError, CommittedCurrentAssignmentAttachmentSlotV1,
    CommittedCurrentAttachmentSlotV1, DurableAttachmentSlotV1,
};
#[cfg(target_os = "linux")]
pub use attachment_source::{
    AttachmentSourceActionV1, AttachmentSourceAttemptKindV1, AttachmentSourceAttemptOutcomeV1,
    AttachmentSourceBoundsV1, AttachmentSourceCompletionOutcomeV1, AttachmentSourceError,
    CurrentAttachmentSourcePlanV1, DurableAttachmentSourceAttemptV1,
    DurableAttachmentSourceCompletionV1,
};
#[cfg(target_os = "linux")]
pub use attachment_state::{
    AttachmentDesiredCommitOutcomeV1, AttachmentDesiredMutationV1, AttachmentDesiredPresenceV1,
    AttachmentDesiredStateError, CommittedCurrentAttachmentDesiredStateV1,
    DurableAttachmentDesiredStateV1,
};
#[cfg(target_os = "linux")]
pub use attachment_verification::{
    AttachmentVerificationError, AttachmentVerificationOutcomeV1, DurableAttachmentVerificationV1,
};
pub use controller::{
    ActivatedOperationCompiler, ControllerQuantumReport, ControllerReconciliationStep,
    ControllerRequestScopeV1, ControllerServiceError, NodeController, NodeControllerLimits,
    OperationCompilationError,
};
#[cfg(target_os = "linux")]
pub use controller::{CurrentOriginalAttachConsumeCutV3, CurrentOriginalAttachHostConsumeDraftV3};
#[cfg(target_os = "linux")]
pub use destination_slot_effect::{
    CompletedCurrentDestinationSlotAttemptV1, DestinationSlotAttemptAdmissionOutcomeV1,
    DestinationSlotCompletionOutcomeV1, DestinationSlotDispatchClient, DestinationSlotEffectError,
    DurableCurrentDestinationSlotAttemptV1, PreparedCurrentDestinationSlotDispatchV1,
    PreparedCurrentDestinationSlotResumeDispatchV1, PreparedCurrentDestinationSlotResumeV1,
    PreparedCurrentDestinationSlotV1,
};
#[cfg(target_os = "linux")]
pub use destination_slot_inventory::{
    CurrentDestinationSlotReconciliationV1, DestinationSlotInventoryClient,
    DestinationSlotInventorySnapshotOutcomeV1, DestinationSlotReconciliationActionV1,
    DurableDestinationSlotInventorySnapshotV1,
};
pub use dispatch::{
    BrokerDispatchAttemptError, BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1,
    BrokerDispatchTemplateError, BrokerDispatchTemplateV1, GuardianPlanRequestV1,
};
pub use filesystem_view_state::{
    DurableFilesystemViewRevisionV1, FilesystemViewRevisionCommitOutcomeV1,
    FilesystemViewRevisionMutationV1, FilesystemViewRevisionPresenceV1,
    FilesystemViewRevisionStateError, current_filesystem_view_revision_v1,
};
#[cfg(target_os = "linux")]
pub use host_catalog_reconciliation::{
    DurableCurrentHostCatalogV1, DurablePendingHostCatalogV1, HostCatalogReconciliationError,
    HostCatalogReconciliationV1,
};
pub use journal::{
    CommitResult, ControllerPolicyHoldV1,
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, GlobalCapacityReservationV1, IdempotencyKey,
    IdempotencyOutcome, Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction,
    ProtectedJournalCurrentnessOriginalsV1,
    PreparedGlobalCapacityReservationV1,
    ProtectedJournalAuthority,
    ProtectedJournalLockCustodyV1, ProtectedJournalPreflight, ProtectedJournalSnapshot,
    RecordNamespace, RecoveryReport,
};
#[cfg(target_os = "linux")]
pub use journal::{
    StorageNativeIssuanceEdgeDataV1, StorageNativeIssuanceHistoryCursorV1,
    StorageNativeIssuanceHistoryDataV1, StorageNativeIssuanceHistoryErrorV1,
};
pub use lifecycle_authority::{
    AtomicStorageLifecyclePublicationErrorV1, SnapshotDerivedStoragePreparationV3,
    compile_atomic_storage_lifecycle_template_v1, compile_storage_create_preparation_template_v1,
    prepare_atomic_storage_lifecycle_authority_effect_v1,
    prepare_atomic_storage_lifecycle_publication_v1, prepare_runtime_lifecycle_authority_effect_v1,
    prepare_snapshot_derived_storage_v3,
};
#[cfg(target_os = "linux")]
pub use mount_attempt::{
    CompletedCurrentMountAttemptV1, CurrentMountInventoryReconciliationV1,
    DurableCurrentMountAttemptV1, DurableMountInventorySnapshotV1, MountAttemptAdmissionOutcomeV1,
    MountAttemptError, MountAttemptInventoryObservationV1, MountAttemptInventoryStatusV1,
    MountCompletionOutcomeV1, MountDispatchClient, MountInventoryClient,
    MountInventorySnapshotOutcomeV1,
};
#[cfg(target_os = "linux")]
pub use mount_observation_state::{
    CurrentMountFilesystemInventoryV1, MountFilesystemInventoryError,
    MountJournalObservationIdentityV1,
};
#[cfg(target_os = "linux")]
pub use mount_source_acquisition_inventory::{
    DurableMountSourceAcquisitionInventorySnapshotV1, MountSourceAcquisitionInventoryClient,
    MountSourceAcquisitionInventoryError, MountSourceAcquisitionInventorySnapshotOutcomeV1,
};
pub use ownership_resume::{
    OwnershipResumeError, OwnershipResumeOutcomeV1,
};
pub use publication::{
    prepare_authority_publication, bind_authority_publication_lease, AuthorityPublicationDraftV1,
    AuthorityPublicationError, AuthorityPublicationOutcome, AuthorityPublicationProposalV1,
    AuthorityPublicationStore, CurrentAuthorityPublicationV1, PreparedAuthorityPublicationV1,
    RecoveredBrokerDispatchTemplateV1, RecoveredOwnershipLeaseV1,
};
#[cfg(target_os = "linux")]
pub use reconciler::OperatorCleanupRecoveryCompletionV2;

pub use reconciler::{
    AcceptOutcome, AuthorityEffectAttemptTimingV1, AuthorityEffectObservationV1, EffectFailure,
    EffectObservation, OperationPlan, OperatorStorageRepairReconcileV1,
    OwnershipGateActivationOutcome, PreparedAuthorityBrokerRequestV1, PreparedAuthorityEffectV1,
    PublicMutationEffectV1, PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
    ReconcileOutcome, Reconciler, ReconcilerError, SingleNodeEffectExecutor,
    UnfinishedOperationStateV1, ValidatedAuthorityEffectReceiptV1, ValidatedHostEffectReceiptV1,
    ValidatedUnfinishedOperationV1, activated_ownership_gate_digest_from_journal_v1,
    public_operation_resource_from_journal_v1,
};
#[cfg(target_os = "linux")]
pub use resource_inventory::{
    DurableNetworkResourceInventorySnapshotV1, DurableStorageResourceInventorySnapshotV1,
    NetworkResourceInventoryClient, ResourceInventoryError, ResourceInventoryServiceIdentity,
    ResourceInventorySnapshotOutcomeV1, StorageResourceInventoryClient,
    begin_authenticated_storage_inventory_v1, complete_authenticated_storage_inventory_v1,
};
pub use sandbox_spec_state::{
    DurableSandboxSpecV1, SandboxSpecCommitOutcomeV1, SandboxSpecPublicationV1,
    SandboxSpecStateError,
};

#[cfg(target_os = "linux")]

#[cfg(test)]
mod ownership_composition_tests;

#[doc(hidden)]
pub use controller_resource_reservation::{CreateStorageReadyNativeInputsV1,
    CreateStorageBundleShapeDataV1, CreateStorageBundleClosedV1, OriginalCreateStorageBundleV1};

pub use controller_resource_reservation::ControllerStorageFloorPhysicalReceivingV1;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use journal::{DeleteInventorySessionAppendOriginalV1, DeleteInventorySessionAppendDisposalV1, DeleteInventoryIoDisposalV1, DeleteInventorySecurityShapeDataV1};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use public_mutation_compiler::delete_admission::{
    ControllerDeleteAuthorizationOriginalV1, ControllerDeleteAuthorizedScopeV1,
    ControllerDeleteCandidateOriginalV2, ControllerDeleteSourceAuthorizedScopeV1,
    ControllerDeletePendingOriginalV2, OriginalDeleteStoragePreparationLoanV3, OriginalDeleteStorageApplyLoanV3, OriginalDeleteNetworkApplyLoanV4, OriginalDeleteMountReapLoanV4,
};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use controller_resource_reservation::{ControllerDeletePlanningRootOriginalV1, ControllerDeletePlanningRootLoanV1};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use controller_resource_reservation::{ControllerDeleteFinalDisposalOriginalV4, ControllerDeletePendingRootClientOriginalV2,
    ControllerDeletePendingRootChallengeLoanV2, ControllerDeletePendingRootFailureViewV2, OriginalDeleteResourceSigningV2};

#[doc(hidden)]
pub use controller_resource_reservation::{CreateProvisioningSourceWorkspaceContextV1,
    CreateStoppedCompletionAttemptV1, CreateStoppedPreAckContextV1,
    CreateStoppedCompletionAssociationV1, CreateStoppedPreAckOriginalV1,
    CreateStoppedPostAckContextV1, CreateStoppedTerminalOriginalV1, CreateStoppedTerminalCustodyV1};

#[doc(hidden)]
pub use controller_resource_reservation::AcceptedStartEntryOriginalV1;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use controller_resource_reservation::operator_create_recovery::{OperatorRecoverInventoryLoanV1,
    OperatorRecoverInventoryDisposalV1};
#[cfg(target_os = "linux")]
pub use controller_resource_reservation::{OperatorCreateRecoveryOriginalV1,
    OperatorCreateRecoveryLoanV1, OperatorCreateRecoveryClosedV1, OperatorStopCleanupObservationLoanV1};
pub use controller_resource_reservation::OperatorExecutionNoApplyRecoveryCompletedHandoffV2;
pub use controller_resource_reservation::OperatorStopCleanupRecoveryCompletedHandoffV1;
#[doc(hidden)]
pub use controller_resource_reservation::OperatorRecoveredStoppedCreateSeedV1;

#[doc(hidden)]
pub use controller_resource_reservation::OriginalStartHostRootLoanV1;
#[doc(hidden)]
pub use controller_resource_reservation::{OriginalStartAssignmentInputsLoanV2,
    StartAssignmentInputsCompletedTurnV2};


#[doc(hidden)]
pub use controller_resource_reservation::{PreparedStartResourceRequestOriginalV2,
    PreparedStartResourceRequestClosedV2, StartHostCatalogPublicationLoanV2, StartHostCatalogIoLoanV2, StartHostCatalogNativeCompletionV2, StartHostCatalogCompletionRefusalV2, StartHostSessionRejoinOriginalV2, StartHostCatalogProjectionOriginalV2, StartHostCatalogProjectionClosedV2, StartResourceUpperDisposalV2, StartResourceSessionOpeningOriginalV2,
    StartResourceSessionOpeningLoanV2, StartResourceSessionOpeningOwnerLinkV2,
    StartResourceColdCompletionOriginalV4,
    StartResourceSessionAssociationV4, StartResourceHelloDisposalV4, StartResourceHelloDisposalErrorV4, StartResourceSessionCurrentnessErrorV4,
    StartResourceProvisioningIoLoanV2, StartResourcePreparedRequestBorrowV2, StartResourceSessionPostShapeDataV2,
    StartResourceSessionResidentShapeDataV4};

#[doc(hidden)]
pub use controller_resource_reservation::{OperatorReconciliationObservationCustodyV2,
    OperatorFirstLocalOrdinaryEnrollmentOriginalV2,
    OperatorFirstLocalReconciliationCompleteV2, OperatorReconciliationInventoryProofV2,
    OperatorReconciliationInventoryLoanV2, ControllerRecoveryInventoryLoanV2,
    OperatorReconciliationObservationEntryRefusalV2, OperatorReconciliationObservationOriginalV2,
    OperatorReconciliationObservationLoanV2, ControllerReconciliationInventoryRoleV2};

#[cfg(target_os = "linux")]
pub use controller_resource_reservation::{CatalogMaintenanceClosedV2, CatalogMaintenanceOriginalV2, ControllerCatalogMaintenanceLoanV2};
#[doc(hidden)]
pub use controller_resource_reservation::ControllerCatalogMaintenanceSigningBorrowV3;
#[doc(hidden)]
pub use controller_resource_reservation::ControllerMaintenanceStorageRequestOriginalV3;
#[doc(hidden)]
pub use controller_resource_reservation::ControllerMaintenanceStorageIoLoanV3;
#[doc(hidden)]
pub use controller_resource_reservation::ControllerMaintenanceStorageSdkDisposalV3;

#[doc(hidden)]
pub use controller_resource_reservation::{ControllerCatalogMaintenanceIoLoanV2, ControllerCatalogMaintenanceSessionCurrentnessErrorV2};

#[doc(hidden)]
pub use controller_resource_reservation::{ControllerCatalogMaintenanceCompletionRefusalV2, ControllerCatalogMaintenanceCatalogDisposalV2};

#[doc(hidden)]
pub use controller_resource_reservation::CatalogMaintenanceColdCompletedNativeBorrowV2;
pub use controller_resource_reservation::CatalogMaintenanceRefreshCompletedNativeBorrowV2;

#[doc(hidden)]
pub use controller_resource_reservation::CatalogMaintenanceSdkShapeDataV2;

#[doc(hidden)]
pub use controller_resource_reservation::CatalogMaintenanceSourceBorrowV2;
