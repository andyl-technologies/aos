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
pub mod publication;
pub mod reconciler;

pub use authority::{
    AuthorizationArtifactQuartet, AuthorizationArtifacts, AuthorizationPreparation,
    AuthorizationPreparationError, BrokerPlanPreparation, PreparedSigningRequest,
    ReturnedSignature, SignedBrokerPlan, SigningAuthority,
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
    ExpectedOwnershipLease, OwnershipAuthority, OwnershipAuthorityError,
    OwnershipAuthorityVerifier, OwnershipClaimAction, OwnershipClaimError, OwnershipClaimV1,
    OwnershipLeaseAcquisitionError, SignedOwnershipLease, UnverifiedOwnershipLeaseResponse,
};
pub use publication::{
    AuthorityPublicationError, AuthorityPublicationOutcome, AuthorityPublicationProposalV1,
    AuthorityPublicationStore, CurrentAuthorityPublicationV1, PreparedAuthorityPublicationV1,
    RecoveredBrokerDispatchTemplateV1, RecoveredOwnershipLeaseV1,
};
pub use reconciler::{
    AcceptOutcome, EffectDomain, EffectFailure, EffectObservation, EffectPlan, EffectReceipt,
    OperationPlan, ReconcileOutcome, Reconciler, ReconcilerError, SingleNodeEffectExecutor,
};
