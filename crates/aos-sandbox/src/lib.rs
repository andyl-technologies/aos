//! Implements the unprivileged AOS sandbox controller.
//!
//! The [`journal`] module owns the append-only desired-state and operation
//! journal. It validates and replays durable transactions before a future
//! reconciler is allowed to issue effects. Linux syscalls and privileged
//! broker implementations deliberately live outside this crate.

pub mod authority;
pub mod controller;
pub mod dispatch;
pub mod journal;
pub mod ownership_authority;
pub mod ownership_resume;
pub mod ownership_service;
pub mod publication;
pub mod publisher_authority;
pub mod publisher_policy;
pub mod reconciler;

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
pub use dispatch::{
    BrokerDispatchAttemptError, BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1,
    BrokerDispatchTemplateError, BrokerDispatchTemplateV1,
};
pub use journal::{
    CommitResult, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalLimits,
    JournalRecord, JournalTransaction, RecordNamespace, RecoveryReport,
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
