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

pub use admission::{AdmissionError, AdmissionFailure, AdmittedOperation, TrustedAdmissionPolicy};
pub use event::{
    CancellationResult, DispatchAbortReason, EXECUTION_EVENT_SCHEMA, ExecutionEvent,
    ExecutionEventKind, ReconciliationResult,
};
pub use inputs::InputResolutionError;
pub use lifecycle::{ResourceReleaseError, ResourceReleaseFailure};
pub use machine::{Boundary, ExecutionError, ExecutionStep};
pub use scheduler::ReadyOperation;
pub use state::{OperationHistory, OperationState, RecoveryAction, StateError};
pub use summary::{OperationStatus, OperationSummary, TerminalResult, TransactionSummary};
pub use transaction::{ExecutionTransaction, TransactionError};
