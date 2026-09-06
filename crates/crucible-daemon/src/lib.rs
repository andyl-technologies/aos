//! `crucible-daemon` owns the long-lived host process.
//!
//! Spec index: RFC-0010 files 20, 21; RFC-0020 file 04a.
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
//! [`campaign_attachment`] composes each packaged planner and checked local
//! executor with one named durable campaign, while [`campaign_bootstrap`]
//! owns a bounded startup-fixed set of those attachments;
//! [`campaign_runtime_control`] owns their bounded operational attachment
//! messages without admitting deployment paths into semantic identities;
//! [`campaign_runtime`] owns one sticky, bounded, long-lived supervisor thread;
//! [`campaign_loopback`] provides the strict local
//! user-facing service transport; [`campaign_server`] owns its bounded
//! authenticated listener and fixed connection workers;
//! [`campaign_policy`] owns its immutable Unix identity and operation grants;
//! [`campaign_retention`] composes snapshot-bound semantic pins with durable
//! executor publication roots for local garbage-collection inventory;
//! [`campaign_store_quota`] adapts pinned Linux project quotas to the CAS
//! store graph without introducing a storage dependency into the kernel layer;
//! [`campaign_store_composition`] exposes the bounded concrete store
//! capabilities accepted by local operator tooling;
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
//! campaign-attempt resource and cancellation contract, while its private
//! guest-selectable boundary resolves paused ABI requests into scenario-bound
//! campaign opportunities and replies;
//! [`qemu_hot_fork_reconciliation`] retains one forked child's source-parent,
//! target cgroup/pidfd, private-channel, accounting, and publication authority;
//! [`qemu_hot_fork_world`] withholds those children until every running node is
//! exact-bound to one complete process-neutral world continuation;
//! [`qemu_hot_fork_runner`] orders modeled child driving, process teardown,
//! semantic publication, and source-template recovery without overlapping
//! execution incarnations;
//! [`qemu_hot_fork_factory`] exact-binds one prepared source per fixed worker,
//! installs target guards, and owns terminal quarantine handoff;
//! [`hot_checkpoint_manager`] bounds and ranks those retained sources while
//! producing generation-fenced exact/thin demotion plans;
//! [`hot_checkpoint_fallback`] authenticates the exact immutable fallback and
//! enforces a second check at the irreversible source-release boundary;
//! [`hot_checkpoint_retention`] durably fences those exact/thin roots against
//! single-host garbage collection across restart;
//! [`managed_hot_checkpoint_pool`] composes those plans with exact source-pool
//! authority and process-wide fork-rate admission;
//! [`durable_managed_hot_checkpoint_pool`] orders durable fallback retention,
//! live-source admission/demotion, cold-root release, and restart recovery;
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
pub mod campaign_runtime_control;
pub mod campaign_server;
pub mod campaign_store_composition;
pub mod campaign_store_quota;
pub mod control_responsiveness;
pub mod crucible_artifact;
pub mod crucible_execution;
pub mod crucible_measurement;
pub mod crucible_qemu_runner;
pub mod crucible_qemu_session;
#[cfg(target_os = "linux")]
pub mod durable_managed_hot_checkpoint_pool;
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
mod guest_selectable;
#[cfg(target_os = "linux")]
pub mod hot_checkpoint_fallback;
#[cfg(target_os = "linux")]
pub mod hot_checkpoint_manager;
#[cfg(target_os = "linux")]
pub mod hot_checkpoint_retention;
#[cfg(target_os = "linux")]
pub mod managed_hot_checkpoint_pool;
pub mod packaged_qemu_executor;
#[cfg(target_os = "linux")]
pub mod paused_checkpoint_promotion;
pub mod planner_loopback;
pub mod planner_process;
pub mod qemu_baked_genesis;
pub mod qemu_campaign_driver;
pub mod qemu_campaign_lifecycle;
pub mod qemu_campaign_resume;
#[cfg(target_os = "linux")]
pub mod qemu_exact_resume_executor;
#[cfg(target_os = "linux")]
pub mod qemu_hot_fork_factory;
#[cfg(target_os = "linux")]
pub mod qemu_hot_fork_pool;
#[cfg(target_os = "linux")]
pub mod qemu_hot_fork_reconciliation;
#[cfg(target_os = "linux")]
pub mod qemu_hot_fork_runner;
#[cfg(target_os = "linux")]
pub mod qemu_hot_fork_world;
#[cfg(target_os = "linux")]
pub mod qemu_hot_fork_world_resource;
pub mod qemu_lifecycle_launcher;
pub mod qemu_resource_guard;
pub mod repository_admission;
mod supervision;

pub use assignment_ledger::{
    AssignmentLedger, AssignmentLedgerError, AssignmentPublish, AssignmentRecord,
    AssignmentRetentionAdmin, AssignmentRetentionFence, AssignmentRetentionGeneration,
    AssignmentRetentionInventoryError, AssignmentRetentionRoot, AssignmentRetentionSummary,
    AssignmentRetentionVisitorError, AttemptExecutionKey, AttemptExecutionOrigin,
    AttemptRuntimeState, AttemptStateCas, CheckpointPromotionExecutionBasis,
    DirectoryAssignmentLedger, MemoryAssignmentLedger, visit_directory_attempt_states_bounded,
};
pub use campaign_attachment::{
    AttachedCanonicalCampaignRuntime, CanonicalCampaignRuntimeConfig,
    CanonicalCampaignRuntimeConfigError, CanonicalCampaignRuntimeError,
    DEFAULT_CANONICAL_EXECUTOR_SCAN_LIMIT, DEFAULT_CANONICAL_PLANNER_INPUT_BYTES,
    DEFAULT_CANONICAL_PLANNER_SCAN_LIMIT, MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES,
    PreparedCanonicalCampaignRuntime, prepare_canonical_campaign_runtime,
};
pub use campaign_bootstrap::{
    CampaignLocalRepositoryStore, CampaignLocalService, CampaignLocalServiceConfig,
    CampaignLocalServiceError, CampaignLocalServiceMode, CampaignLocalStoreGcAuthority,
    CampaignRuntimeAttachmentHandle, CampaignStoreMaintenanceConfig,
    CampaignStoreMaintenanceConfigError, PreparedCampaignLocalService,
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
#[cfg(target_os = "linux")]
pub use campaign_gc::{
    CampaignGcHotCheckpointRoots, apply_single_host_campaign_gc_with_hot_checkpoints,
    plan_single_host_campaign_gc_with_hot_checkpoints,
};
pub use campaign_loopback::{
    LoopbackCampaignProtocolError, LoopbackCampaignServerError, LoopbackCampaignService,
    LoopbackCampaignServiceError, LoopbackCampaignTimeouts, MAX_CAMPAIGN_REQUESTS_PER_CONNECTION,
    UnixPeerCampaignCredentials, UnixPeerCampaignPrincipalResolver,
    serve_authenticated_repository_campaign_connection,
    serve_authenticated_repository_campaign_connection_with_limits,
    serve_authenticated_repository_campaign_connection_with_runtime_control_limits,
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
pub use campaign_runtime_control::{
    AttachCampaignRuntimeRequest, AttachCampaignRuntimeResponse,
    CampaignRuntimeAttachmentDisposition, CampaignRuntimeControlCodecError,
    CampaignRuntimeControlService, MAX_CAMPAIGN_RUNTIME_CONTROL_MESSAGE_BYTES,
};
pub use campaign_server::{
    CampaignLoopbackListenerError, CampaignLoopbackServer, CampaignLoopbackServerConfig,
    CampaignLoopbackServerConfigError, CampaignLoopbackServerReport,
    CampaignLoopbackServerShutdown, MAX_CAMPAIGN_LISTENER_WORKERS,
    MAX_CAMPAIGN_PENDING_CONNECTIONS,
};
pub use campaign_store_quota::LinuxProjectQuotaBinder;
pub use control_responsiveness::{
    DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, DaemonControlResponsiveRoute,
    validate_daemon_control_responsiveness,
};
pub use crucible_artifact::{
    CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2, CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V1,
    CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V2, CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
    CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1, CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V2,
    CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3, CrucibleArtifactError, CrucibleCampaignArtifactStore,
    MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES, decode_crucible_configuration_artifact,
    decode_crucible_configuration_artifact_with_selections,
    decode_crucible_configuration_artifact_with_signal_fault_replay,
    decode_crucible_scenario_artifact, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};
pub use crucible_execution::{
    CrucibleAttemptExecution, CrucibleExecutionModel, CrucibleExecutionModelError,
    CrucibleExecutionOutcome, CrucibleExecutionRunner, CrucibleMaterializationTier,
    CrucibleResolvedAttemptStart, decode_crucible_attempt_execution,
};
pub use crucible_measurement::{
    CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1, CrucibleMeasurementError,
    encode_crucible_measurement_set, evaluate_crucible_measurement_set,
    evaluate_crucible_objectives, project_crucible_objective_values,
    verify_crucible_measurement_set,
};
pub use crucible_qemu::LinuxQemuAttemptHostConfig;
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
pub use durable_managed_hot_checkpoint_pool::{
    DurableHotCheckpointCatalogError, DurableManagedHotCheckpointAdmissionError,
    DurableManagedHotCheckpointAdmissionFailure, DurableManagedHotCheckpointConstructionError,
    DurableManagedHotCheckpointDemotionError, DurableManagedHotCheckpointDemotionFailure,
    DurableManagedHotCheckpointReleaseError, DurableManagedQemuHotForkTemplatePool,
};
#[cfg(target_os = "linux")]
pub use exact_checkpoint_restore::{
    ExactCheckpointRestoreError, ExactCheckpointResumeError, InstalledProductionAttemptCheckpoint,
    MaterializedAttemptCheckpoint, MaterializedExactCheckpoint,
    PreparedProductionAttemptReplayOraclePromotion, ProductionAttemptCheckpointRestoreError,
    QemuGuardedReplayOracleSession,
    authenticate_production_exact_checkpoint_replay_oracle_promotion, captured_qemu_vmstate_blob,
    install_attempt_production_exact_checkpoint, install_attempt_production_resume_checkpoint,
    materialize_attempt_exact_checkpoint, materialize_selected_exact_checkpoint,
    prepare_attempt_production_replay_oracle_promotion,
    realize_materialized_attempt_checkpoint_guarded, realize_materialized_exact_checkpoint_guarded,
};
pub use exact_checkpoint_store::{
    AttemptCheckpointPublication, AttemptCheckpointResult, CapturedAttemptCheckpoint,
    CapturedExactCheckpoint, EXACT_CHECKPOINT_ROOT_SCHEMA, EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    ExactCheckpointId, ExactCheckpointPublication, ExactCheckpointStore, ExactCheckpointStoreError,
    LoadedAttemptCheckpoint, LoadedExactCheckpoint, LoadedProductionExactCheckpoint,
    PrepareReplayOraclePromotionError, PreparedAttemptCheckpoint, PreparedExactCheckpoint,
    PreparedProductionExactCheckpoint, PreparedReplayOraclePromotion,
    ProductionExactCheckpointPublication, QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION,
    QEMU_VMSTATE_SCHEMA_VERSION,
};
pub use exact_pin_retention::{
    DirectoryExactPinMaterializationStore, EXACT_PIN_MATERIALIZATION_DIRECTORY,
    EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA, EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA_VERSION,
    ExactPinMaterializationSelection, ExactPinReplayPromotion, ExactPinReplayTarget,
    ExactPinReplayValidator, ExactPinRetentionAdmin, ExactPinRetentionError,
    ExactPinRetentionFence, ExactPinSelectionClearDisposition, ExactPinSelectionDisposition,
    FindingExactPinBoundaries, MAX_EXACT_PIN_MATERIALIZATION_SELECTIONS,
    MAX_FINDING_EXACT_PIN_CANDIDATES, select_finding_exact_pins,
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
    LocalCheckpointPromotionWorker, LocalExecutorPoolCompletion, LocalExecutorPoolConfigError,
    LocalExecutorPoolReport, LocalExecutorPoolService, LocalExecutorPoolServiceError,
    LocalExecutorPoolShutdown, LocalExecutorPoolShutdownError, LocalExecutorWorkerPool,
    MAX_LOCAL_CHECKPOINT_PROMOTION_QUEUE, MAX_LOCAL_CHECKPOINT_PROMOTION_WORKERS,
    MAX_LOCAL_EXECUTOR_WORKERS, ProductionCheckpointPromotionWorker,
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
    CheckpointCompletionOutcome, CheckpointHandoffFailure, CheckpointPromotionCompletionOutcome,
    CheckpointPromotionRecovery, CheckpointPromotionRestartWork, CheckpointPromotionStageOutcome,
    CheckpointPublicationOutcome, CheckpointRequestOutcome, CompletionOutcome,
    CompletionValidationFailure, ExecutionCancellation, ExecutionCheckpointRequest,
    ExecutorAvailability, ExecutorCapacity, ExecutorCapacityError, LocalExecutorError,
    LocalExecutorSupervisor, ObservationPublicationOutcome, PausedCheckpointPromotionRecovery,
    QueuedAttempt,
};
pub use executor_worker::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionInput,
    AttemptExecutionModel, AttemptExecutionProduct, AttemptExecutionReconciliationStep,
    AttemptExecutionRuntimeBasis, AttemptResultAbortError, AttemptResultPreparationError,
    AttemptResultPublicationError, AttemptResultStageOutcome, AttemptResultStagingError,
    AttemptWorkResult, AttemptWorkerFailure, AttemptWorkerReconcileError,
    AttemptWorkerReconcileOutcome, CheckpointResultAbortError, CheckpointResultAbortToken,
    CheckpointResultPublicationError, CheckpointResultReconcileError, CheckpointResultStageOutcome,
    CheckpointResultStagingError, LocalAttemptWorker, PendingAttemptResult,
    PendingCheckpointResult, PreparedAttemptResult, PreparedAttemptWorkResult,
    PreparedCheckpointResult, PublishedAttemptResult, PublishedAttemptResultAbortError,
    PublishedCheckpointResult, RepositoryAttemptWorker, RepositoryAttemptWorkerError,
    ResolvedAttemptStart, StagedAttemptResult, StagedCheckpointResult, abort_checkpoint_result,
    abort_prepared_attempt_result, abort_published_attempt_result, abort_staged_attempt_result,
    prepare_attempt_result, publish_prepared_attempt_result, publish_staged_checkpoint_result,
    reconcile_attempt_failure, reconcile_published_attempt_result,
    reconcile_published_checkpoint_result, resolve_attempt_execution_input,
    retry_pending_attempt_result, retry_pending_checkpoint_result, stage_prepared_attempt_result,
    stage_prepared_checkpoint_result,
};
pub use guest_selectable::GuestSelectableError;
#[cfg(target_os = "linux")]
pub use hot_checkpoint_fallback::{
    AuthenticatedHotCheckpointDemotionError, AuthenticatedHotCheckpointDemotionSink,
    HotCheckpointFallbackAuthenticator, HotCheckpointSourceDemoter,
    QemuFixedHotCheckpointSourceDemoter, QemuFixedHotCheckpointSourceDemotionError,
    QemuHotCheckpointFallbackAuthenticationError, QemuHotCheckpointFallbackAuthenticator,
    QemuHotCheckpointThinFallbackCatalog,
};
#[cfg(target_os = "linux")]
pub use hot_checkpoint_manager::{
    HotCheckpointAdmissionCommit, HotCheckpointAdmissionCommitError, HotCheckpointAdmissionPlan,
    HotCheckpointAdmissionRejection, HotCheckpointCandidate, HotCheckpointDemotion,
    HotCheckpointDemotionReason, HotCheckpointFallback, HotCheckpointFallbackTier,
    HotCheckpointForkPermit, HotCheckpointForkRateError, HotCheckpointHotnessComponent,
    HotCheckpointHotnessError, HotCheckpointHotnessSignals, HotCheckpointInventoryError,
    HotCheckpointLimits, HotCheckpointLimitsError, HotCheckpointManager,
    HotCheckpointOrderlyDemotionPlan, HotCheckpointPlannedDemotion, HotCheckpointPressure,
    HotCheckpointResourceProfile, HotCheckpointResourceProfileError, HotCheckpointRetentionReason,
    HotCheckpointScore, HotCheckpointStatus, HotCheckpointUsage,
    MAX_HOT_CHECKPOINT_SCORE_COMPONENT,
};
#[cfg(target_os = "linux")]
pub use hot_checkpoint_retention::{
    DirectoryHotCheckpointFallbackRetentionStore, HotCheckpointFallbackRecord,
    HotCheckpointFallbackRetentionAdmin, HotCheckpointFallbackRetentionCas,
    HotCheckpointFallbackRetentionError, HotCheckpointFallbackRetentionFence,
    HotCheckpointFallbackRetentionStore, HotCheckpointFallbackRetentionSummary,
    HotCheckpointFallbackSlot, MAX_HOT_CHECKPOINT_FALLBACK_ROOTS,
    MemoryHotCheckpointFallbackRetentionStore,
};
#[cfg(target_os = "linux")]
pub use managed_hot_checkpoint_pool::{
    HotCheckpointTemplateDemotionFailure, HotCheckpointTemplateDemotionSink,
    ManagedHotCheckpointAdmissionError, ManagedHotCheckpointAdmissionFailure,
    ManagedHotCheckpointDemotionError, ManagedHotCheckpointDemotionFailure,
    ManagedHotCheckpointStartError, ManagedQemuHotForkTemplatePool,
    ManagedQemuHotForkTemplatePoolConstructionError,
};
pub use packaged_qemu_executor::{
    AttachedPackagedQemuExecutor, MAX_PACKAGED_SCENARIO_CATALOG_BYTES,
    PackagedExactPinMaterializerError, PackagedQemuExecutor, PackagedQemuExecutorCompletion,
    PackagedQemuExecutorConfig, PackagedQemuExecutorConfigError, PackagedQemuExecutorError,
    PackagedQemuExecutorJoinError, PackagedQemuExecutorStartError,
};
#[cfg(target_os = "linux")]
pub use paused_checkpoint_promotion::{
    PausedCheckpointPromotionPreparationError, PausedCheckpointPromotionPublicationError,
    PausedCheckpointPromotionReconcileError, PausedCheckpointPromotionRecoveryResolutionError,
    PausedCheckpointPromotionRestartPreparationError, PausedCheckpointPromotionStageOutcome,
    PausedCheckpointPromotionStagingError, PausedCheckpointPromotionTarget,
    PreparedPausedCheckpointPromotion, PreparedPausedCheckpointPromotionRestart,
    ProductionPausedCheckpointPromotionTarget, ProductionPausedCheckpointReplayFactory,
    ProductionPausedCheckpointReplaySession, PublishedPausedCheckpointPromotion,
    ResolvedProductionPausedCheckpointPromotionRecovery, StagedPausedCheckpointPromotion,
    prepare_production_paused_checkpoint_promotion_restart,
    publish_staged_paused_checkpoint_promotion, reconcile_published_paused_checkpoint_promotion,
    recover_published_paused_checkpoint_promotion,
    recover_published_production_paused_checkpoint_promotion,
    resolve_production_paused_checkpoint_promotion_recovery,
    revert_recovered_paused_checkpoint_promotion, revert_staged_paused_checkpoint_promotion,
    stage_prepared_paused_checkpoint_promotion,
    validate_and_prepare_paused_checkpoint_promotion_guarded,
    validate_and_prepare_production_paused_checkpoint_promotion,
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
pub use qemu_baked_genesis::{
    ProductionBakedGenesisCaptureError, ProductionBakedGenesisCheckpoint,
    ProductionBakedGenesisCheckpointError, ProductionBakedGenesisReplayCatalogError,
    ProductionBakedGenesisReplayCatalogFactory, ProductionBakedGenesisReplayFactory,
    ProductionBakedGenesisReplayLauncher, ProductionBakedGenesisReplayStore,
    capture_production_baked_genesis,
};
pub use qemu_campaign_driver::{
    MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES, QemuFreshModeledDriver, QemuFreshModeledDriverError,
    QemuModeledAttemptLifecycle,
};
#[cfg(target_os = "linux")]
pub use qemu_campaign_driver::{QemuHotForkModeledDriver, QemuHotForkModeledDriverError};
pub use qemu_campaign_lifecycle::{
    QemuAttemptProductionVmLifecycleError, QemuAttemptProductionVmLifecycleFactory,
    QemuFreshAttemptDriver, QemuFreshAttemptLifecycle, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner, QemuFreshDriveOutcome, QemuFreshExecutionRunner,
    QemuFreshExecutionRunnerError, QemuFreshGenesisCheckpointCandidate,
    QemuFreshGenesisCheckpointCaptureFailure, QemuFreshGenesisCheckpointError,
    QemuFreshStartMaterialization, QemuFreshStartReplayError,
    capture_fresh_genesis_checkpoint_candidate,
};
pub use qemu_campaign_resume::{
    QemuProductionExactResumeExecutionRunner, QemuProductionExactResumeExecutionRunnerError,
    QemuProductionExactResumeLifecycleFactory, QemuProductionExactResumeLifecycleOwner,
};
#[cfg(target_os = "linux")]
pub use qemu_exact_resume_executor::QemuExactResumeLiveRealizationExecutor;
#[cfg(target_os = "linux")]
pub use qemu_hot_fork_factory::{
    FixedQemuHotForkTemplateFactory, FixedQemuHotForkTemplateFactoryConstructionError,
    FixedQemuHotForkTemplateFactoryError, LinuxQemuHotForkTemplateLauncher,
    LinuxQemuHotForkTemplateLauncherError, ProcessLifetimeQemuHotForkQuarantine,
    QemuHotForkBoundTemplate, QemuHotForkFactoryQuarantine, QemuHotForkLifecycleQuarantine,
    QemuHotForkPooledLifecycle, QemuHotForkTemplateKey, QemuHotForkTemplateLaunchFailure,
    QemuHotForkTemplateLauncher, QemuHotForkTemplateSource,
    QemuHotForkTemplateSourceRecoveryFailure,
};
#[cfg(target_os = "linux")]
pub use qemu_hot_fork_pool::{
    MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS, QemuHotForkKeyedLifecycleFactory,
    QemuHotForkTemplatePool, QemuHotForkTemplatePoolCapacityError,
    QemuHotForkTemplatePoolConstructionError, QemuHotForkTemplatePoolError,
    QemuHotForkTemplatePoolInsertionError, QemuHotForkTemplatePoolLifecycle,
    QemuHotForkTemplatePoolRetirementError, QemuHotForkTemplatePoolSlot,
};
#[cfg(target_os = "linux")]
pub use qemu_hot_fork_reconciliation::{
    LinuxQemuHotForkAttemptLaunchError, LinuxQemuHotForkLiveChild,
    LinuxQemuHotForkReconciliationBackend, LinuxQemuHotForkReconciliationError,
    LinuxQemuHotForkSourceWorldAttemptLaunchError, LinuxQemuHotForkSourceWorldFailureOwner,
    LinuxQemuHotForkWorldAttemptLaunchError, LinuxQemuHotForkWorldAttemptLaunchFailure,
    QemuHotForkAttemptBasis, QemuHotForkAttemptReconciliation,
    QemuHotForkAttemptReconciliationError, QemuHotForkChildDisposition,
    QemuHotForkChildObservation, QemuHotForkChildObservationError,
    QemuHotForkPublicationDisposition, QemuHotForkReconciliationBackend,
    QemuHotForkReconciliationChildBasis, QemuHotForkReconciliationPhase,
    QemuHotForkReconciliationStep, QemuHotForkWorldChildSourceBasis,
};
#[cfg(target_os = "linux")]
pub use qemu_hot_fork_runner::{
    LinuxQemuHotForkAttemptLifecycleError, QemuHotForkAttemptDriver, QemuHotForkAttemptLifecycle,
    QemuHotForkAttemptLifecycleFactory, QemuHotForkAttemptLifecycleRecoveryError,
    QemuHotForkChildExitPolicy, QemuHotForkChildExitPolicyError, QemuHotForkExecutionRunner,
    QemuHotForkExecutionRunnerError, QemuHotForkLiveExecution,
};
#[cfg(target_os = "linux")]
pub use qemu_hot_fork_world::{
    QemuHotForkCompleteWorldAssembly, QemuHotForkWorldAssembly, QemuHotForkWorldAssemblyToken,
    QemuHotForkWorldChild, QemuHotForkWorldChildAdmissionError,
    QemuHotForkWorldChildAdmissionFailure, QemuHotForkWorldIncomplete,
};
#[cfg(target_os = "linux")]
pub use qemu_hot_fork_world_resource::{QemuHotForkWorldNodeTarget, QemuHotForkWorldResourceOwner};
pub use qemu_lifecycle_launcher::QemuAttemptProductionVmNodeLauncher;
pub use qemu_resource_guard::{
    ComposedQemuAttemptResourceGuard, ComposedQemuAttemptResourceGuardFactory,
    LinuxQemuAttemptHostResourceFactory, LinuxQemuAttemptHostResourceOwner,
    MAX_QEMU_ATTEMPT_GENERATION_NODES, QemuAttemptCancellationSignal, QemuAttemptGenerationLease,
    QemuAttemptGenerationResourceOwner, QemuAttemptHostResourceFactory,
    QemuAttemptHostResourceOwner, SharedQemuAttemptHostResourceFactory,
};
pub use repository_admission::RepositoryAttemptAdmission;
