//! Implements the unprivileged AOS sandbox controller.
//!
//! The [`journal`] module owns the append-only desired-state and operation
//! journal. It validates and replays durable transactions before a future
//! reconciler is allowed to issue effects. Protected publisher stores retain
//! current policy and capabilities; Linux local provisioning commits issuance
//! before activating process-local holder channels. [`publisher_ingress`] owns
//! inert execution/challenge audit records; Linux publisher control and sessions
//! bind their registration to the original live process without granting effects.
//! [`client_state`], [`cli_model`], and [`controller_query`] provide dormant pure
//! client and observation projections. [`attach_holder_proof`] and
//! [`create_holder_proof`] define the holder-key signature profiles. [`environment`],
//! [`git`], [`hierarchy`],
//! [`lifecycle`], [`multi_node`], [`policy_compiler`], and
//! [`publisher_admission`] own inert RFC-0021 domain models and
//! protected-journal seams. [`publisher_roots`] owns
//! the portable root registry and retains live root custody only on Linux,
//! without activating it.
//! [`execution_output_reservation`] owns accepted-Create-derived, protected
//! pre-Host output-byte claims while execution authorization remains closed.
//! [`execution_guest_identity`] reads back private-namespace credential
//! mapping bounds without granting execution authority.
//! [`controller_execution_observe_reservation`] shares the non-authorizing
//! Create-to-Observe reservation codec with the Controller execution owner.
//! Raw Linux syscalls and
//! privileged broker implementations deliberately live outside this crate.

#[cfg(all(feature = "test-fixtures", not(debug_assertions)))]
compile_error!("the protected-journal test fixture is unavailable in release builds");

#[cfg(all(feature = "cache-physical-join-vm-fixture", not(debug_assertions)))]
compile_error!("the Cache physical-join VM fixture is unavailable in release builds");

pub mod attach_holder_proof;
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
pub mod authority;
pub mod cache_residency;
pub mod cli_model;
pub mod client_state;
pub mod controller;
#[cfg(target_os = "linux")]
pub mod controller_execution_argument_attempt;
pub mod controller_execution_argument_receipt;
pub mod controller_execution_observe_reservation;
pub mod controller_execution_output_settlement;
#[cfg(target_os = "linux")]
pub mod controller_execution_preissue;
#[cfg(target_os = "linux")]
pub mod controller_execution_spec_attempt;
pub mod controller_no_apply_settlement_cursor;
pub mod controller_query;
#[cfg(target_os = "linux")]
pub mod controller_service;
pub mod controller_storage_output_reserve_attempt;
pub mod create_holder_proof;
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
pub mod journal;
pub mod lifecycle;
mod lifecycle_authority;
#[cfg(target_os = "linux")]
mod local_channel;
#[cfg(target_os = "linux")]
pub mod local_provisioning;
#[cfg(target_os = "linux")]
pub mod local_sessions;
#[cfg(target_os = "linux")]
pub mod mount_attempt;
#[cfg(target_os = "linux")]
pub mod mount_manager_source_inventory;
#[cfg(target_os = "linux")]
pub mod mount_manager_startup;
#[cfg(target_os = "linux")]
pub mod mount_observation_state;
#[cfg(target_os = "linux")]
pub mod mount_preparation;
#[cfg(target_os = "linux")]
pub mod mount_source_acquisition_inventory;
pub mod multi_node;
mod operator_abandon_ack;
pub mod ownership_authority;
pub mod ownership_resume;
pub mod ownership_service;
pub mod policy_compiler;
#[cfg(target_os = "linux")]
pub mod production_operation_compiler;
#[cfg(target_os = "linux")]
pub mod public_api_session;
pub mod public_attach_pending;
#[cfg(target_os = "linux")]
pub mod public_capability_issuance;
#[cfg(target_os = "linux")]
pub mod public_mutation_compiler;
#[cfg(target_os = "linux")]
pub mod public_policy_planner;
pub mod publication;
pub mod publisher_admission;
pub mod publisher_authority;
#[cfg(target_os = "linux")]
pub mod publisher_control;
pub mod publisher_ingress;
pub mod publisher_policy;
pub mod publisher_roots;
#[cfg(target_os = "linux")]
pub mod publisher_sessions;
pub mod reconciler;
#[cfg(target_os = "linux")]
pub mod resource_inventory;
pub mod runtime_authority;
pub mod runtime_execution;
#[cfg(target_os = "linux")]
pub mod runtime_scope;
pub mod sandbox_spec_state;

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
pub use authority::{
    AuthorizationArtifactQuartet, AuthorizationArtifacts, AuthorizationPreparation,
    AuthorizationPreparationError, BrokerPlanPreparation, PreparedSigningRequest,
    PublisherPlanPreparation, ReturnedSignature, SignedBrokerPlan, SignedPublisherPlan,
    SigningAuthority,
};
pub use controller::{
    ActivatedOperationCompiler, ControllerQuantumReport, ControllerReconciliationStep,
    ControllerRequestScopeV1, ControllerServiceError, NodeController, NodeControllerLimits,
    OperationCompilationError,
};
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
    CommitResult, ControllerPolicyEffectAckV1, ControllerPolicyHoldV1,
    FixedSourceProviderJournalHandoffV1, GlobalCapacityReservationPurposeV1,
    GlobalCapacityReservationRecoveryBindingV1, GlobalCapacityReservationRequestV1,
    GlobalCapacityReservationV1, IdempotencyKey, IdempotencyOutcome, Journal, JournalError,
    JournalLimits, JournalRecord, JournalTransaction, MountManagerStartupPolicyReceiptV1,
    MountSourceAcquisitionJournalAuthorityV2, MountSourceConsumptionCommitReceipt,
    MountSourceConsumptionCompanionProjectionV2, MountSourceConsumptionJournalAuthorityV1,
    MountSourceConsumptionPreflight, MountSourceMigrationJournalAuthorityV2,
    PreparedGlobalCapacityReservationV1, ProtectedJournalAuthority, ProtectedJournalPreflight,
    ProtectedJournalSnapshot, RecordNamespace, RecoveryReport,
};
pub use lifecycle_authority::{
    AtomicStorageLifecyclePublicationErrorV1, compile_atomic_storage_lifecycle_template_v1,
    compile_storage_create_preparation_template_v1,
    prepare_atomic_storage_lifecycle_authority_effect_v1,
    prepare_atomic_storage_lifecycle_publication_v1, prepare_runtime_lifecycle_authority_effect_v1,
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
pub use mount_manager_source_inventory::{
    CapturedMountManagerStartupV1, MountManagerActivationDescriptorKindV1,
    MountManagerActivationDescriptorV1, MountManagerActivationDescriptorsV1,
    MountManagerExecutionDeathKindV1, MountManagerSourceAbsenceProjectionV1,
    MountManagerSourceAbsenceV1, MountManagerSourceControlSessionV1,
    MountManagerSourceInventoryError, MountManagerStartupCaptureOutcomeV1,
    MountManagerStartupJournalBorrowV1, MountManagerStartupProtectedOpenReportV1,
    MountManagerStartupProtectedOwnerV1,
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
pub use ownership_authority::{
    DurableOwnershipAuthority, DurableOwnershipAuthorityError, DurableOwnershipBeginOutcome,
    DurableOwnershipQueryOutcome, ExpectedOwnershipLease, OwnershipAuthority,
    OwnershipAuthorityError, OwnershipAuthorityVerifier, OwnershipClaimAction, OwnershipClaimError,
    OwnershipClaimV1, OwnershipLeaseAcquisitionError, OwnershipTransactionReceiptV1,
    ProtectedOwnershipClockError, RecoveredOwnershipLease, SignedOwnershipLease,
    UnverifiedOwnershipLeaseResponse,
};
pub use ownership_resume::{
    OwnershipAuthoritySessionClient, OwnershipClockObservationError, OwnershipResumeError,
    OwnershipResumeOutcomeV1, OwnershipSessionTransportError, UntrustedOwnershipResponsePartsV1,
};
pub use ownership_service::{
    DurableOwnershipProtocolService, InProcessOwnershipSessionClient, OwnershipProtocolServiceError,
};
pub use publication::{
    AuthorityPublicationDraftV1, AuthorityPublicationError, AuthorityPublicationOutcome,
    AuthorityPublicationProposalV1, AuthorityPublicationStore, CurrentAuthorityPublicationV1,
    PreparedAuthorityPublicationV1, RecoveredBrokerDispatchTemplateV1, RecoveredOwnershipLeaseV1,
};
pub use reconciler::{
    AcceptOutcome, AuthorityBoundEffectPlanV1, AuthorityEffectAttemptTimingV1,
    AuthorityEffectObservationV1, EffectDomain, EffectFailure, EffectObservation, EffectPlan,
    EffectReceipt, OperationPlan, OwnershipGateActivationOutcome, OwnershipGatePlanV1,
    OwnershipGateStatusV1, PreparedAuthorityBrokerRequestV1, PreparedAuthorityEffectV1,
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
