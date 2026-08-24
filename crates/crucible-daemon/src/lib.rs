//! `crucible-daemon` owns the long-lived host process.
//!
//! Spec index: RFC-0010 files 20, 21; RFC-0016 file 04a.
//!
//! This L4 crate will host sessions and serve the API over a transport as
//! specified by its indexed RFC-0010 files. It may later contain host-facing
//! diagnostics, but any run-affecting choice must enter through the engine's
//! deterministic decision stream.
//!
//! Module map: [`assignment_ledger`] owns crash-safe executor idempotency and
//! runtime-state records; [`campaign_bootstrap`] composes durable directory
//! storage, strict policy, managed endpoint, and listener ownership;
//! [`campaign_endpoint`] owns exact local campaign and executor Unix socket
//! namespaces;
//! [`campaign_attachment`] composes one packaged planner and checked local
//! executor with a named durable campaign;
//! [`campaign_runtime`] owns one sticky, bounded, long-lived supervisor thread;
//! [`campaign_loopback`] provides the strict local
//! user-facing service transport; [`campaign_server`] owns its bounded
//! authenticated listener and fixed connection workers;
//! [`campaign_policy`] owns its immutable Unix identity and operation grants;
//! [`campaign_retention`] composes snapshot-bound semantic pins with durable
//! executor publication roots for local garbage-collection inventory;
//! [`control_responsiveness`] forwards
//! daemon-routed acknowledgement evidence to the API's quantum-counted
//! control-responsive contract; [`executor_loopback`] provides the strict
//! Unix-stream component transport; [`executor_supervisor`] owns bounded
//! single-host admission,
//! idempotent scheduling, completion, and cancellation;
//! [`repository_admission`] is its read-only production semantic boundary.
//! [`executor_worker`] resolves accepted assignments, delegates execution, and
//! publishes immutable observation candidates; [`executor_pool`] owns the
//! fixed worker threads and their short supervisor reconciliation phases;
//! [`executor_server`] owns the bounded authenticated Unix listener that lends
//! cloneable executor-service handles to fixed connection workers;
//! [`executor_service`] couples both owners into one fail-closed daemon
//! lifecycle;
//! [`exact_checkpoint_store`] owns durable streamed exact-checkpoint roots;
//! [`exact_checkpoint_restore`] authenticates exact-pin selections or durable
//! attempt-resume roots and streams their VMState into fail-closed guarded
//! launch authorities;
//! [`exact_pin_retention`] binds current exact semantic pins to authenticated
//! durable checkpoint materializations for generation-fenced GC;
//! [`crucible_artifact`] strictly
//! translates opaque campaign payloads into Crucible execution-model values;
//! [`crucible_execution`] supplies the typed runner boundary used by the local
//! QEMU/session adapter; [`crucible_qemu_runner`] connects that boundary to the
//! exact-restore/thin-replay QEMU realization path; [`crucible_qemu_session`]
//! composes its attempt-scoped live backend, resource guard, and modeled driver;
//! [`qemu_exact_resume_executor`] owns concrete guarded real-node resume from a
//! durable operational checkpoint root;
//! [`qemu_lifecycle_launcher`] streams lifecycle checkpoint artifacts into one
//! exact guarded process generation;
//! [`qemu_campaign_lifecycle`] installs that launcher beneath the exact admitted
//! campaign-attempt resource and cancellation contract;
//! [`qemu_resource_guard`] binds one indivisible host process/filesystem owner
//! to signal-driven cancellation and exact quantum accounting;
//! [`planner_loopback`] owns
//! the strict local pure-planner component transport; [`planner_process`]
//! owns the killable packaged canonical-planner worker.
//! Future modules split session hosting, API transport, and diagnostics.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod assignment_ledger;
pub mod campaign_attachment;
pub mod campaign_bootstrap;
pub mod campaign_endpoint;
pub mod campaign_gc;
pub mod campaign_loopback;
pub mod campaign_policy;
pub mod campaign_retention;
pub mod campaign_runtime;
pub mod campaign_server;
pub mod control_responsiveness;
pub mod crucible_artifact;
pub mod crucible_execution;
pub mod crucible_qemu_runner;
pub mod crucible_qemu_session;
#[cfg(target_os = "linux")]
pub mod exact_checkpoint_restore;
pub mod exact_checkpoint_store;
pub mod exact_pin_retention;
pub mod executor_capability;
pub mod executor_loopback;
pub mod executor_pool;
pub mod executor_server;
pub mod executor_service;
pub mod executor_supervisor;
pub mod executor_worker;
#[cfg(target_os = "linux")]
pub mod paused_checkpoint_promotion;
pub mod planner_loopback;
pub mod planner_process;
pub mod qemu_campaign_driver;
pub mod qemu_campaign_lifecycle;
#[cfg(target_os = "linux")]
pub mod qemu_exact_resume_executor;
pub mod qemu_lifecycle_launcher;
pub mod qemu_resource_guard;
pub mod repository_admission;

pub use assignment_ledger::{
    AssignmentLedger, AssignmentLedgerError, AssignmentPublish, AssignmentRecord,
    AssignmentRetentionAdmin, AssignmentRetentionFence, AssignmentRetentionGeneration,
    AssignmentRetentionInventoryError, AssignmentRetentionRoot, AssignmentRetentionSummary,
    AssignmentRetentionVisitorError, AttemptExecutionKey, AttemptExecutionOrigin,
    AttemptRuntimeState, AttemptStateCas, DirectoryAssignmentLedger, MemoryAssignmentLedger,
};
pub use campaign_attachment::{
    AttachedCanonicalCampaignRuntime, CanonicalCampaignRuntimeConfig,
    CanonicalCampaignRuntimeConfigError, CanonicalCampaignRuntimeError,
    DEFAULT_CANONICAL_EXECUTOR_SCAN_LIMIT, DEFAULT_CANONICAL_PLANNER_INPUT_BYTES,
    DEFAULT_CANONICAL_PLANNER_SCAN_LIMIT, PreparedCanonicalCampaignRuntime,
    prepare_canonical_campaign_runtime,
};
pub use campaign_bootstrap::{
    CampaignLocalService, CampaignLocalServiceConfig, CampaignLocalServiceError,
    CampaignLocalServiceMode, PreparedCampaignLocalService,
};
pub use campaign_endpoint::{
    CampaignLoopbackEndpointConfig, CampaignLoopbackEndpointError, ExecutorLoopbackEndpointConfig,
    ExecutorLoopbackEndpointError, ManagedCampaignLoopbackListener,
    ManagedExecutorLoopbackListener,
};
pub use campaign_gc::{
    CampaignGcApplyError, CampaignGcApplyReport, CampaignGcApplyStatus,
    CampaignGcBlobInventoryBasis, CampaignGcCandidate, CampaignGcCandidateManifest,
    CampaignGcCandidateSetId, CampaignGcCandidateSetSummary, CampaignGcJournalCreateDisposition,
    CampaignGcJournalError, CampaignGcJournalPhase, CampaignGcJournalTransition,
    CampaignGcManifestError, CampaignGcPhysicalStore, CampaignGcPlan, CampaignGcPlanError,
    CampaignGcPlanId, CampaignGcPlanningError, CampaignGcPreparedPlan, CampaignGcRootManifest,
    CampaignGcRootSetId, DirectoryCampaignGcJournal, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES,
    MAX_CAMPAIGN_GC_MANIFEST_ENTRIES, MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES,
    MAX_CAMPAIGN_GC_PLAN_BYTES, apply_single_host_campaign_gc, plan_single_host_campaign_gc,
};
pub use campaign_loopback::{
    LoopbackCampaignProtocolError, LoopbackCampaignServerError, LoopbackCampaignService,
    LoopbackCampaignServiceError, LoopbackCampaignTimeouts, MAX_CAMPAIGN_REQUESTS_PER_CONNECTION,
    UnixPeerCampaignCredentials, UnixPeerCampaignPrincipalResolver,
    serve_authenticated_repository_campaign_connection,
    serve_authenticated_repository_campaign_connection_with_limits,
    serve_authenticated_repository_campaign_connection_with_timeouts,
    serve_authenticated_repository_campaign_once,
    serve_authenticated_repository_campaign_once_with_timeouts, serve_loopback_campaign_once,
    serve_loopback_campaign_once_with_timeouts,
};
pub use campaign_policy::{
    CAMPAIGN_POLICY_SCHEMA, CAMPAIGN_POLICY_SCHEMA_VERSION, CampaignAccessGrant,
    CampaignAccessScope, MAX_CAMPAIGN_ACCESS_GRANTS, MAX_CAMPAIGN_PEER_BINDINGS,
    MAX_CAMPAIGN_POLICY_BYTES, UnixPeerCampaignBinding, UnixPeerCampaignIdentity,
    UnixPeerCampaignPolicy, UnixPeerCampaignPolicyError, UnixPeerCampaignPolicyLoadError,
};
pub use campaign_retention::{
    LocalCampaignRetentionError, LocalCampaignRetentionRoot, LocalCampaignRetentionSummary,
    visit_local_campaign_retention_roots,
};
pub use campaign_runtime::{
    CampaignRuntime, CampaignRuntimeCompletion, CampaignRuntimeConfig, CampaignRuntimeConfigError,
    CampaignRuntimeDriver, CampaignRuntimeJoinError, CampaignRuntimeReport,
    CampaignRuntimeStartError, CampaignRuntimeStepDisposition, CampaignRuntimeWake,
    DEFAULT_CAMPAIGN_RUNTIME_POLL_INTERVAL, MAX_CAMPAIGN_RUNTIME_IMMEDIATE_BURST,
    MAX_CAMPAIGN_RUNTIME_POLL_INTERVAL, MIN_CAMPAIGN_RUNTIME_POLL_INTERVAL,
};
pub use campaign_server::{
    CampaignLoopbackListenerError, CampaignLoopbackServer, CampaignLoopbackServerConfig,
    CampaignLoopbackServerConfigError, CampaignLoopbackServerReport,
    CampaignLoopbackServerShutdown, MAX_CAMPAIGN_LISTENER_WORKERS,
    MAX_CAMPAIGN_PENDING_CONNECTIONS,
};
pub use control_responsiveness::{
    DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, DaemonControlResponsiveRoute,
    validate_daemon_control_responsiveness,
};
pub use crucible_artifact::{
    CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2, CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V1,
    CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1, CrucibleArtifactError, CrucibleCampaignArtifactStore,
    MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES, decode_crucible_configuration_artifact,
    decode_crucible_configuration_artifact_with_selections, decode_crucible_scenario_artifact,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
};
pub use crucible_execution::{
    CrucibleAttemptExecution, CrucibleExecutionModel, CrucibleExecutionModelError,
    CrucibleExecutionOutcome, CrucibleExecutionRunner, CrucibleMaterializationTier,
    CrucibleResolvedAttemptStart,
};
pub use crucible_qemu_runner::{
    QemuAttemptExecutionRouter, QemuAttemptExecutionRouterError, QemuCrucibleAttemptSession,
    QemuCrucibleRealizationStore, QemuCrucibleSessionFactory, QemuExactThinExecutionRunner,
    QemuExactThinRunnerError,
};
pub use crucible_qemu_session::{
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory, QemuExactCheckpointRealization, QemuExecutionQuantumCounter,
    QemuGuardedLiveRealizationExecutor, QemuLiveAttemptDriver, QemuLiveAttemptResult,
    QemuLiveAttemptSession, QemuLiveAttemptSessionError, QemuLiveAttemptSessionFactory,
};
#[cfg(target_os = "linux")]
pub use exact_checkpoint_restore::{
    ExactCheckpointRestoreError, ExactCheckpointResumeError, MaterializedAttemptCheckpoint,
    MaterializedExactCheckpoint, QemuGuardedReplayOracleSession, captured_qemu_vmstate_blob,
    materialize_attempt_exact_checkpoint, materialize_selected_exact_checkpoint,
    realize_materialized_attempt_checkpoint_guarded, realize_materialized_exact_checkpoint_guarded,
};
pub use exact_checkpoint_store::{
    CapturedExactCheckpoint, EXACT_CHECKPOINT_ROOT_SCHEMA, EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    ExactCheckpointId, ExactCheckpointPublication, ExactCheckpointStore, ExactCheckpointStoreError,
    LoadedExactCheckpoint, PrepareReplayOraclePromotionError, PreparedExactCheckpoint,
    PreparedReplayOraclePromotion, QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION,
    QEMU_VMSTATE_SCHEMA_VERSION,
};
pub use exact_pin_retention::{
    DirectoryExactPinMaterializationStore, EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA,
    EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA_VERSION, ExactPinMaterializationSelection,
    ExactPinReplayPromotion, ExactPinReplayTarget, ExactPinReplayValidator, ExactPinRetentionAdmin,
    ExactPinRetentionError, ExactPinRetentionFence, ExactPinSelectionClearDisposition,
    ExactPinSelectionDisposition, MAX_EXACT_PIN_MATERIALIZATION_SELECTIONS,
};
pub use executor_capability::LocalExecutorCapabilityService;
pub use executor_loopback::{
    DEFAULT_EXECUTOR_REQUESTS_PER_CONNECTION, LoopbackExecutorProtocolError,
    LoopbackExecutorServerError, LoopbackExecutorService, LoopbackExecutorTimeouts,
    MAX_EXECUTOR_REQUESTS_PER_CONNECTION, serve_loopback_executor_component_connection_with_limits,
    serve_loopback_executor_component_once, serve_loopback_executor_once,
    serve_loopback_executor_once_with_timeouts,
};
pub use executor_pool::{
    LocalExecutorPoolCompletion, LocalExecutorPoolConfigError, LocalExecutorPoolReport,
    LocalExecutorPoolService, LocalExecutorPoolServiceError, LocalExecutorPoolShutdown,
    LocalExecutorPoolShutdownError, LocalExecutorWorkerPool, MAX_LOCAL_EXECUTOR_WORKERS,
};
pub use executor_server::{
    ExecutorLoopbackListenerError, ExecutorLoopbackServer, ExecutorLoopbackServerConfig,
    ExecutorLoopbackServerConfigError, ExecutorLoopbackServerReport,
    ExecutorLoopbackServerShutdown, MAX_EXECUTOR_LISTENER_WORKERS,
    MAX_EXECUTOR_PENDING_CONNECTIONS, UnixPeerExecutorIdentity,
};
pub use executor_service::{
    ExecutorLocalService, ExecutorLocalServiceError, ExecutorLocalServiceReport,
    ExecutorLocalServiceShutdown,
};
pub use executor_supervisor::{
    AllowAllAttemptAdmission, AttemptAdmissionValidator, CancellationOutcome,
    CheckpointCompletionOutcome, CheckpointPromotionCompletionOutcome, CheckpointPromotionRecovery,
    CheckpointPromotionStageOutcome, CheckpointPublicationOutcome, CheckpointRequestOutcome,
    CompletionOutcome, CompletionValidationFailure, ExecutionCancellation,
    ExecutionCheckpointRequest, ExecutorAvailability, ExecutorCapacity, ExecutorCapacityError,
    LocalExecutorError, LocalExecutorSupervisor, ObservationPublicationOutcome, QueuedAttempt,
};
pub use executor_worker::{
    AttemptExecutionContext, AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct,
    AttemptResultAbortError, AttemptResultPreparationError, AttemptResultPublicationError,
    AttemptResultStageOutcome, AttemptResultStagingError, AttemptWorkResult, AttemptWorkerFailure,
    AttemptWorkerReconcileError, AttemptWorkerReconcileOutcome, CheckpointResultAbortError,
    CheckpointResultAbortToken, CheckpointResultPublicationError, CheckpointResultReconcileError,
    CheckpointResultStageOutcome, CheckpointResultStagingError, LocalAttemptWorker,
    PendingAttemptResult, PendingCheckpointResult, PreparedAttemptResult,
    PreparedAttemptWorkResult, PreparedCheckpointResult, PublishedAttemptResult,
    PublishedAttemptResultAbortError, PublishedCheckpointResult, RepositoryAttemptWorker,
    RepositoryAttemptWorkerError, ResolvedAttemptStart, StagedAttemptResult,
    StagedCheckpointResult, abort_checkpoint_result, abort_prepared_attempt_result,
    abort_published_attempt_result, abort_staged_attempt_result, prepare_attempt_result,
    publish_prepared_attempt_result, publish_staged_checkpoint_result, reconcile_attempt_failure,
    reconcile_published_attempt_result, reconcile_published_checkpoint_result,
    retry_pending_attempt_result, retry_pending_checkpoint_result, stage_prepared_attempt_result,
    stage_prepared_checkpoint_result,
};
#[cfg(target_os = "linux")]
pub use paused_checkpoint_promotion::{
    PausedCheckpointPromotionPreparationError, PausedCheckpointPromotionPublicationError,
    PausedCheckpointPromotionReconcileError, PausedCheckpointPromotionStageOutcome,
    PausedCheckpointPromotionStagingError, PausedCheckpointPromotionTarget,
    PreparedPausedCheckpointPromotion, PublishedPausedCheckpointPromotion,
    StagedPausedCheckpointPromotion, publish_staged_paused_checkpoint_promotion,
    reconcile_published_paused_checkpoint_promotion, recover_published_paused_checkpoint_promotion,
    revert_recovered_paused_checkpoint_promotion, revert_staged_paused_checkpoint_promotion,
    stage_prepared_paused_checkpoint_promotion,
    validate_and_prepare_paused_checkpoint_promotion_guarded,
};
pub use planner_loopback::{
    LoopbackPlannerProtocolError, LoopbackPlannerServerError, LoopbackPlannerService,
    LoopbackPlannerTimeouts, serve_loopback_planner_once,
    serve_loopback_planner_once_with_timeouts,
};
pub use planner_process::{
    CANONICAL_PLANNER_WORKER_ARGUMENT, CanonicalPlannerProcessCancellation,
    CanonicalPlannerProcessConfig, CanonicalPlannerProcessError, CanonicalPlannerProcessSupervisor,
    serve_canonical_planner_process_once,
};
pub use qemu_campaign_driver::{
    MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES, QemuFreshModeledDriver, QemuFreshModeledDriverError,
};
pub use qemu_campaign_lifecycle::{
    QemuAttemptProductionVmLifecycleError, QemuAttemptProductionVmLifecycleFactory,
    QemuFreshAttemptDriver, QemuFreshAttemptLifecycle, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner, QemuFreshExecutionRunner, QemuFreshExecutionRunnerError,
    QemuFreshStartMaterialization, QemuFreshStartReplayError,
};
#[cfg(target_os = "linux")]
pub use qemu_exact_resume_executor::QemuExactResumeLiveRealizationExecutor;
pub use qemu_lifecycle_launcher::QemuAttemptProductionVmNodeLauncher;
pub use qemu_resource_guard::{
    ComposedQemuAttemptResourceGuard, ComposedQemuAttemptResourceGuardFactory,
    LinuxQemuAttemptHostResourceFactory, LinuxQemuAttemptHostResourceOwner,
    MAX_QEMU_ATTEMPT_GENERATION_NODES, QemuAttemptCancellationSignal, QemuAttemptGenerationLease,
    QemuAttemptGenerationResourceOwner, QemuAttemptHostResourceFactory,
    QemuAttemptHostResourceOwner,
};
pub use repository_admission::RepositoryAttemptAdmission;
