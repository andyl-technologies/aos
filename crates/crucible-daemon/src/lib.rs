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
//! contract; [`executor_loopback`] provides the strict Unix-stream component
//! transport; [`executor_supervisor`] owns bounded single-host admission,
//! idempotent scheduling, completion, and cancellation;
//! [`repository_admission`] is its read-only production semantic boundary.
//! [`executor_worker`] resolves accepted assignments, delegates execution, and
//! publishes immutable observation candidates; [`crucible_artifact`] strictly
//! translates opaque campaign payloads into Crucible execution-model values;
//! [`crucible_execution`] supplies the typed runner boundary used by the local
//! QEMU/session adapter.
//! Future modules split session hosting, API transport, and diagnostics.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod assignment_ledger;
pub mod control_responsiveness;
pub mod crucible_artifact;
pub mod crucible_execution;
pub mod executor_loopback;
pub mod executor_supervisor;
pub mod executor_worker;
pub mod repository_admission;

pub use assignment_ledger::{
    AssignmentLedger, AssignmentLedgerError, AssignmentPublish, AssignmentRecord,
    AttemptExecutionKey, AttemptRuntimeState, AttemptStateCas, DirectoryAssignmentLedger,
    MemoryAssignmentLedger,
};
pub use control_responsiveness::{
    DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, DaemonControlResponsiveRoute,
    validate_daemon_control_responsiveness,
};
pub use crucible_artifact::{
    CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2, CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
    CrucibleArtifactError, decode_crucible_configuration_artifact,
    decode_crucible_configuration_artifact_with_selections, decode_crucible_scenario_artifact,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
};
pub use crucible_execution::{
    CrucibleAttemptExecution, CrucibleExecutionModel, CrucibleExecutionModelError,
    CrucibleExecutionRunner, CrucibleResolvedAttemptStart,
};
pub use executor_loopback::{
    LoopbackExecutorProtocolError, LoopbackExecutorServerError, LoopbackExecutorService,
    LoopbackExecutorTimeouts, serve_loopback_executor_once,
    serve_loopback_executor_once_with_timeouts,
};
pub use executor_supervisor::{
    AllowAllAttemptAdmission, AttemptAdmissionValidator, CancellationOutcome, CompletionOutcome,
    CompletionValidationFailure, ExecutionCancellation, ExecutorCapacity, ExecutorCapacityError,
    LocalExecutorError, LocalExecutorSupervisor, ObservationPublicationOutcome, QueuedAttempt,
};
pub use executor_worker::{
    AttemptExecutionContext, AttemptExecutionInput, AttemptExecutionModel, AttemptResultAbortError,
    AttemptResultPreparationError, AttemptResultPublicationError, AttemptResultStageOutcome,
    AttemptResultStagingError, AttemptWorkResult, AttemptWorkerFailure,
    AttemptWorkerReconcileError, AttemptWorkerReconcileOutcome, LocalAttemptWorker,
    PendingAttemptResult, PreparedAttemptResult, PublishedAttemptResult, RepositoryAttemptWorker,
    RepositoryAttemptWorkerError, ResolvedAttemptStart, StagedAttemptResult,
    abort_prepared_attempt_result, abort_staged_attempt_result, prepare_attempt_result,
    publish_prepared_attempt_result, reconcile_attempt_failure, reconcile_published_attempt_result,
    retry_pending_attempt_result, stage_prepared_attempt_result,
};
pub use repository_admission::RepositoryAttemptAdmission;
