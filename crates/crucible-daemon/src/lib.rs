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
//! [`campaign_endpoint`] owns the exact local Unix socket namespace;
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
//! [`exact_checkpoint_store`] owns durable streamed exact-checkpoint roots;
//! [`exact_checkpoint_restore`] authenticates current exact-pin selections and
//! streams their VMState into fail-closed guarded launch authorities;
//! [`exact_pin_retention`] binds current exact semantic pins to authenticated
//! durable checkpoint materializations for generation-fenced GC;
//! [`crucible_artifact`] strictly
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
pub mod campaign_bootstrap;
pub mod campaign_endpoint;
pub mod campaign_gc;
pub mod campaign_loopback;
pub mod campaign_policy;
pub mod campaign_retention;
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
pub mod executor_supervisor;
pub mod executor_worker;
pub mod planner_loopback;
pub mod repository_admission;

pub use assignment_ledger::{
    AssignmentLedger, AssignmentLedgerError, AssignmentPublish, AssignmentRecord,
    AssignmentRetentionAdmin, AssignmentRetentionFence, AssignmentRetentionGeneration,
    AssignmentRetentionInventoryError, AssignmentRetentionRoot, AssignmentRetentionSummary,
    AssignmentRetentionVisitorError, AttemptExecutionKey, AttemptRuntimeState, AttemptStateCas,
    DirectoryAssignmentLedger, MemoryAssignmentLedger,
};
pub use campaign_bootstrap::{
    CampaignLocalService, CampaignLocalServiceConfig, CampaignLocalServiceError,
    CampaignLocalServiceMode,
};
pub use campaign_endpoint::{
    CampaignLoopbackEndpointConfig, CampaignLoopbackEndpointError, ManagedCampaignLoopbackListener,
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
    decode_crucible_configuration_artifact, decode_crucible_configuration_artifact_with_selections,
    decode_crucible_scenario_artifact, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
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
#[cfg(target_os = "linux")]
pub use exact_checkpoint_restore::{
    ExactCheckpointRestoreError, MaterializedExactCheckpoint, materialize_selected_exact_checkpoint,
};
pub use exact_checkpoint_store::{
    CapturedExactCheckpoint, EXACT_CHECKPOINT_ROOT_SCHEMA, EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    ExactCheckpointId, ExactCheckpointPublication, ExactCheckpointStore, ExactCheckpointStoreError,
    LoadedExactCheckpoint, PreparedExactCheckpoint, QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION,
    QEMU_VMSTATE_SCHEMA_VERSION,
};
pub use exact_pin_retention::{
    DirectoryExactPinMaterializationStore, EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA,
    EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA_VERSION, ExactPinMaterializationSelection,
    ExactPinRetentionAdmin, ExactPinRetentionError, ExactPinRetentionFence,
    ExactPinSelectionClearDisposition, ExactPinSelectionDisposition,
    MAX_EXACT_PIN_MATERIALIZATION_SELECTIONS,
};
pub use executor_capability::LocalExecutorCapabilityService;
pub use executor_loopback::{
    LoopbackExecutorProtocolError, LoopbackExecutorServerError, LoopbackExecutorService,
    LoopbackExecutorTimeouts, serve_loopback_executor_component_once, serve_loopback_executor_once,
    serve_loopback_executor_once_with_timeouts,
};
pub use executor_pool::{
    LocalExecutorPoolConfigError, LocalExecutorPoolReport, LocalExecutorPoolService,
    LocalExecutorPoolServiceError, LocalExecutorPoolShutdownError, LocalExecutorWorkerPool,
    MAX_LOCAL_EXECUTOR_WORKERS,
};
pub use executor_supervisor::{
    AllowAllAttemptAdmission, AttemptAdmissionValidator, CancellationOutcome,
    CheckpointCompletionOutcome, CheckpointPublicationOutcome, CheckpointRequestOutcome,
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
pub use planner_loopback::{
    LoopbackPlannerProtocolError, LoopbackPlannerServerError, LoopbackPlannerService,
    LoopbackPlannerTimeouts, serve_loopback_planner_once,
    serve_loopback_planner_once_with_timeouts,
};
pub use repository_admission::RepositoryAttemptAdmission;
