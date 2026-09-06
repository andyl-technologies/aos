//! Implements the unprivileged AOS sandbox controller.
//!
//! The [`journal`] module owns the append-only desired-state and operation
//! journal. It validates and replays durable transactions before a future
//! reconciler is allowed to issue effects. Protected publisher stores retain
//! current policy and capabilities; Linux local provisioning commits issuance
//! before activating process-local holder channels. [`publisher_ingress`] owns
//! inert execution/challenge audit records; Linux publisher control and sessions
//! bind their registration to the original live process without granting effects.
//! Raw Linux syscalls and
//! privileged broker implementations deliberately live outside this crate.

#[cfg(target_os = "linux")]
pub mod attachment_mount;
#[cfg(target_os = "linux")]
pub mod attachment_reconciliation;
#[cfg(target_os = "linux")]
pub mod attachment_slot_state;
#[cfg(target_os = "linux")]
pub mod attachment_state;
#[cfg(target_os = "linux")]
pub mod attachment_verification;
pub mod authority;
pub mod controller;
#[cfg(target_os = "linux")]
pub mod destination_slot_effect;
#[cfg(target_os = "linux")]
pub mod destination_slot_inventory;
pub mod dispatch;
pub mod filesystem_view_state;
pub mod journal;
#[cfg(target_os = "linux")]
mod local_channel;
#[cfg(target_os = "linux")]
pub mod local_provisioning;
#[cfg(target_os = "linux")]
pub mod local_sessions;
#[cfg(target_os = "linux")]
pub mod mount_attempt;
#[cfg(target_os = "linux")]
pub mod mount_preparation;
pub mod ownership_authority;
pub mod ownership_resume;
pub mod ownership_service;
pub mod publication;
pub mod publisher_authority;
#[cfg(target_os = "linux")]
pub mod publisher_control;
pub mod publisher_ingress;
pub mod publisher_policy;
#[cfg(target_os = "linux")]
pub mod publisher_sessions;
pub mod reconciler;
pub mod runtime_authority;
#[cfg(target_os = "linux")]
pub mod runtime_scope;
pub mod sandbox_spec_state;

#[cfg(target_os = "linux")]
pub use attachment_mount::{
    AttachmentMountError, AttachmentMountPreparationInputV1,
    CompletedCurrentAttachmentMountAttemptV1, DurableCurrentAttachmentMountAttemptV1,
    PreparedCurrentAttachmentMountDispatchV1, PreparedCurrentAttachmentMountResumeDispatchV1,
    PreparedCurrentAttachmentMountResumeV1, PreparedCurrentAttachmentMountV1,
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
    BrokerDispatchTemplateError, BrokerDispatchTemplateV1,
};
pub use filesystem_view_state::{
    DurableFilesystemViewRevisionV1, FilesystemViewRevisionCommitOutcomeV1,
    FilesystemViewRevisionMutationV1, FilesystemViewRevisionPresenceV1,
    FilesystemViewRevisionStateError,
};
pub use journal::{
    CommitResult, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalLimits,
    JournalRecord, JournalTransaction, RecordNamespace, RecoveryReport,
};
#[cfg(target_os = "linux")]
pub use mount_attempt::{
    CompletedCurrentMountAttemptV1, CurrentMountInventoryReconciliationV1,
    DurableCurrentMountAttemptV1, DurableMountInventorySnapshotV1, MountAttemptAdmissionOutcomeV1,
    MountAttemptError, MountAttemptInventoryObservationV1, MountAttemptInventoryStatusV1,
    MountCompletionOutcomeV1, MountDispatchClient, MountInventoryClient,
    MountInventorySnapshotOutcomeV1,
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
    AcceptOutcome, AuthorityBoundEffectPlanV2, AuthorityEffectAttemptTimingV1,
    AuthorityEffectObservationV2, EffectDomain, EffectFailure, EffectObservation, EffectPlan,
    EffectReceipt, OperationPlan, OwnershipGateActivationOutcome, OwnershipGatePlanV1,
    OwnershipGateStatusV1, PreparedAuthorityEffectV2, ReconcileOutcome, Reconciler,
    ReconcilerError, SingleNodeEffectExecutor, ValidatedHostEffectReceiptV1,
};
pub use sandbox_spec_state::{
    DurableSandboxSpecV1, SandboxSpecCommitOutcomeV1, SandboxSpecPublicationV1,
    SandboxSpecStateError,
};
