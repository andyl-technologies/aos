//! `crucible-daemon` owns the long-lived host process.
//!
//! Spec index: RFC-0010 files 20, 21; RFC-0015 file 04a.
//!
//! This L4 crate will host sessions and serve the API over a transport as
//! specified by its indexed RFC-0010 files. It may later contain host-facing
//! diagnostics, but any run-affecting choice must enter through the engine's
//! deterministic decision stream.
//!
//! Module map: [`assignment_ledger`] owns crash-safe executor idempotency and
//! runtime-state records; [`control_responsiveness`] forwards daemon-routed
//! acknowledgement evidence to the API's quantum-counted control-responsive
//! contract; [`executor_supervisor`] owns bounded single-host admission,
//! idempotent scheduling, completion, and cancellation. Future modules split
//! session hosting, API transport, and diagnostics.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod assignment_ledger;
pub mod control_responsiveness;
pub mod executor_supervisor;

pub use assignment_ledger::{
    AssignmentLedger, AssignmentLedgerError, AssignmentPublish, AssignmentRecord,
    AttemptExecutionKey, AttemptRuntimeState, AttemptStateCas, DirectoryAssignmentLedger,
    MemoryAssignmentLedger,
};
pub use control_responsiveness::{
    DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, DaemonControlResponsiveRoute,
    validate_daemon_control_responsiveness,
};
pub use executor_supervisor::{
    AllowAllAttemptAdmission, AttemptAdmissionValidator, CancellationOutcome, CompletionOutcome,
    CompletionValidationFailure, ExecutorCapacity, ExecutorCapacityError, LocalExecutorError,
    LocalExecutorSupervisor, QueuedAttempt,
};
