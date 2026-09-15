//! Durable finite operation execution, scheduling, and recovery state.

mod admission;
mod controller;
mod event;
mod inputs;
mod lifecycle;
mod machine;
mod scheduler;
mod state;
mod summary;
mod transaction;

#[cfg(test)]
mod tests;

pub use admission::{
    AdmissionError, AdmissionFailure, AdmissionResult, AdmittedOperation, AuthorityCheckBoundary,
    AuthorityRejection, RuntimeAuthorityRole, TrustedAdmissionPolicy, TrustedAuthoritySnapshot,
};
pub use event::{
    CancellationResult, CompensationInterventionReason, DispatchAbortReason,
    EXECUTION_EVENT_SCHEMA, ExecutionEvent, ExecutionEventKind, OperationInterventionReason,
    ReconciliationResult,
};
pub use inputs::InputResolutionError;
pub use lifecycle::{ResourceReleaseError, ResourceReleaseFailure};
pub use machine::{
    Boundary, ExecutionBoundaryControl, ExecutionBoundaryObservation, ExecutionBoundaryObserver,
    ExecutionError, ExecutionStep,
};
pub use scheduler::ReadyOperation;
pub use state::{CompensationState, OperationHistory, OperationState, RecoveryAction, StateError};
pub use summary::{OperationStatus, OperationSummary, TerminalResult, TransactionSummary};
pub use transaction::{CheckedExecutionJournalSnapshot, ExecutionTransaction, TransactionError};
