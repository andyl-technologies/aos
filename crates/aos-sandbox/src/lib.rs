//! Implements the unprivileged AOS sandbox controller.
//!
//! The [`journal`] module owns the append-only desired-state and operation
//! journal. It validates and replays durable transactions before a future
//! reconciler is allowed to issue effects. Linux syscalls and privileged
//! broker implementations deliberately live outside this crate.

pub mod authority;
pub mod journal;
pub mod reconciler;

pub use authority::{
    AuthorizationArtifactQuartet, AuthorizationArtifacts, AuthorizationPreparation,
    AuthorizationPreparationError, PreparedSigningRequest, ReturnedSignature, SigningAuthority,
};
pub use journal::{
    CommitResult, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalLimits,
    JournalRecord, JournalTransaction, RecordNamespace, RecoveryReport,
};
pub use reconciler::{
    AcceptOutcome, EffectDomain, EffectFailure, EffectObservation, EffectPlan, EffectReceipt,
    OperationPlan, ReconcileOutcome, Reconciler, ReconcilerError, SingleNodeEffectExecutor,
};
