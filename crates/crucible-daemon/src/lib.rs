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
//! runtime-state records; [`campaign_loopback`] provides the strict local
//! user-facing service transport; [`control_responsiveness`] forwards
//! daemon-routed acknowledgement evidence to the API's quantum-counted
//! control-responsive contract; [`executor_loopback`] provides the strict
//! Unix-stream component transport; [`executor_supervisor`] owns bounded
//! single-host admission,
//! idempotent scheduling, completion, and cancellation;
//! [`repository_admission`] is its read-only production semantic boundary.
//! [`executor_worker`] resolves accepted assignments, delegates execution, and
//! publishes immutable observation candidates; [`crucible_artifact`] strictly
//! translates opaque campaign payloads into Crucible execution-model values;
//! [`crucible_execution`] supplies the typed runner boundary used by the local
//! QEMU/session adapter; [`crucible_qemu_runner`] connects that boundary to the
//! exact-restore/thin-replay QEMU realization path; [`crucible_qemu_session`]
//! composes its attempt-scoped live backend, resource guard, and modeled driver;
//! [`planner_loopback`] owns
//! the strict local pure-planner component transport.
//! Future modules split session hosting, API transport, and diagnostics.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod assignment_ledger;
pub mod campaign_loopback;
pub mod control_responsiveness;
pub mod crucible_artifact;
pub mod crucible_execution;
pub mod crucible_qemu_runner;
pub mod crucible_qemu_session;
pub mod executor_capability;
pub mod executor_loopback;
pub mod executor_supervisor;
pub mod executor_worker;
pub mod planner_loopback;
pub mod repository_admission;

pub use assignment_ledger::{
    AssignmentLedger, AssignmentLedgerError, AssignmentPublish, AssignmentRecord,
    AttemptExecutionKey, AttemptRuntimeState, AttemptStateCas, DirectoryAssignmentLedger,
    MemoryAssignmentLedger,
};
pub use campaign_loopback::{
    LoopbackCampaignProtocolError, LoopbackCampaignServerError, LoopbackCampaignService,
    LoopbackCampaignServiceError, LoopbackCampaignTimeouts, serve_loopback_campaign_once,
    serve_loopback_campaign_once_with_timeouts,
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
    CrucibleExecutionOutcome, CrucibleExecutionRunner, CrucibleMaterializationTier,
    CrucibleResolvedAttemptStart,
};
pub use crucible_qemu_runner::{
    QemuCrucibleAttemptSession, QemuCrucibleRealizationStore, QemuCrucibleSessionFactory,
    QemuExactThinExecutionRunner, QemuExactThinRunnerError,
};
pub use crucible_qemu_session::{
    QemuAttemptOperationalBoundary, QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory,
    QemuGuardedLiveRealizationExecutor, QemuLiveAttemptDriver, QemuLiveAttemptResult,
    QemuLiveAttemptSession, QemuLiveAttemptSessionError, QemuLiveAttemptSessionFactory,
};
pub use executor_capability::LocalExecutorCapabilityService;
pub use executor_loopback::{
    LoopbackExecutorProtocolError, LoopbackExecutorServerError, LoopbackExecutorService,
    LoopbackExecutorTimeouts, serve_loopback_executor_component_once, serve_loopback_executor_once,
    serve_loopback_executor_once_with_timeouts,
};
pub use executor_supervisor::{
    AllowAllAttemptAdmission, AttemptAdmissionValidator, CancellationOutcome, CompletionOutcome,
    CompletionValidationFailure, ExecutionCancellation, ExecutorAvailability, ExecutorCapacity,
    ExecutorCapacityError, LocalExecutorError, LocalExecutorSupervisor,
    ObservationPublicationOutcome, QueuedAttempt,
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
pub use planner_loopback::{
    LoopbackPlannerProtocolError, LoopbackPlannerServerError, LoopbackPlannerService,
    LoopbackPlannerTimeouts, serve_loopback_planner_once,
    serve_loopback_planner_once_with_timeouts,
};
pub use repository_admission::RepositoryAttemptAdmission;
