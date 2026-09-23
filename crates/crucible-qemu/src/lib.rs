//! `crucible-qemu` owns host-side QEMU integration.
//!
//! Spec index: RFC-0010 files 10, 11.
//!
//! This L2 crate will build launch arguments, supervise QEMU children, map the
//! shared-memory region, speak QMP, and implement the engine backend trait
//! described by its indexed RFC-0010 files. It is an unsafe-boundary crate
//! because future implementations may cross FFI and raw descriptor boundaries.
//!
//! Module map: `launch` owns the deterministic Contract-A launch profile and
//! canonical QEMU argument construction; the mapped quantum path owns current
//! production fingerprint samples;
//! `shutdown` owns the graceful QEMU child shutdown escalation ladder; `coverage`
//! owns host-side plugin coverage observation bridging; `host_setup` owns the
//! real Linux descriptor handoff and setup lifecycle driver; `inertness`
//! owns the sim-off/sim-on QEMU control-plane inertness assertion;
//! `gdbstub_proxy` owns the mediated debug gdbstub bridge
//! between QEMU and the operator-facing `--gdb-listen` endpoint; `async_driver`
//! owns the bounded host-I/O bridge between
//! synchronous scheduler node steps and real-time child I/O; `crash_detection`
//! owns typed crashed-node status classification; `node` owns the
//! scheduler-facing one-child/three-channel QEMU wrapper; `node_factory` owns
//! the Linux post-setup node composition boundary; `linux_attempt_host`
//! exposes the sealed combined cgroup/project-quota attempt owner;
//! `quantum` owns the
//! per-quantum shared-memory hot path; `qmp` owns the minimal typed QMP client;
//! `unix_socket_path` keeps QEMU run-directory socket operations within the
//! kernel pathname limit;
//! `realization` owns the start/resume/fork instantiate branch coordinator,
//! including replay-probe admission and version-nine descriptor restoration.
//!
//! Unsafe boundary discipline: descriptor, shared-memory, monitor, and FFI
//! details stay private; public callers use a safe host-driver API that
//! validates process and mapping invariants before touching raw state.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod artifact_identity;
mod async_driver;
#[cfg(target_os = "linux")]
mod block_realization_gate;
mod checkpoint;
mod console_observation;
mod coverage;
mod crash_detection;
#[cfg(target_os = "linux")]
mod exact_checkpoint_input;
mod fault_action_sink;
mod fault_capability;
mod fault_implementation;
mod gdbstub_proxy;
#[cfg(target_os = "linux")]
mod host_setup;
mod inertness;
mod launch;
#[cfg(target_os = "linux")]
mod linux_attempt_host;
#[cfg(target_os = "linux")]
mod linux_attempt_process;
#[cfg(target_os = "linux")]
// The lifecycle-bound quota/run-directory owner remains behind the combined
// public host-resource facade.
mod linux_attempt_storage;
#[cfg(target_os = "linux")]
// Raw cgroup mutation stays internal; `linux_attempt_process` exposes only the
// sealed process owner needed by the still-separate quota/session composition.
mod linux_cgroup;
#[cfg(target_os = "linux")]
mod live_plugin_gate;
#[cfg(not(target_os = "linux"))]
#[path = "live_plugin_gate/unsupported.rs"]
mod live_plugin_gate;
#[cfg(unix)]
mod mapped_quantum;
mod node;
#[cfg(target_os = "linux")]
mod node_factory;
mod node_set;
mod plugin_control;
mod production_fault_runtime;
mod production_fault_sink;
mod qmp;
mod quantum;
mod quantum_boundary;
mod realization;
mod shutdown;
#[cfg(target_os = "linux")]
mod spawn;
mod storage_array;
mod storage_fault_resolver;
#[cfg(target_os = "linux")]
mod supervision;
mod unix_socket_path;

pub use artifact_identity::{
    QemuLaunchArtifactIdentity, QemuLaunchArtifactIdentityError, normalize_qemu_build_id,
};
pub use async_driver::{
    QemuAdvanceCompletionFence, QemuAsyncCrashEscalationTarget, QemuAsyncDriverError,
    QemuAsyncDriverOperation, QemuAsyncDriverPolicy, QemuAsyncDriverRuntimeError,
    QemuAsyncDriverTargetError, QemuAsyncLifecycleAwaitOutcome, QemuAsyncLifecycleAwaitReport,
    QemuAsyncNodeStepOutcome, QemuAsyncNodeStepReport, QemuAsyncNodeStepTarget,
    QemuAsyncQuantumCompletion, QemuAsyncWait, QemuAsyncWaitOutcome, QemuHostIoRuntime,
    assert_async_driver_quantum_hot_path_is_shmem_only, await_bounded_lifecycle_event,
    run_bounded_qemu_node_step,
};
#[cfg(target_os = "linux")]
pub use block_realization_gate::{
    BlockRealizationGateConfig, BlockRealizationGateError, BlockRealizationReport,
    run_block_realization_gate,
};
pub use checkpoint::{
    QemuHostIoCheckpoint, QemuHostIoCheckpointCodecError, QemuLive9pIoServicerCheckpoint,
    QemuLiveBlockIoServicerCheckpoint, QemuNetworkTransportCheckpoint,
    QemuNodeCheckpointCodecError, QemuNodeContinuationCheckpoint,
};
pub use coverage::{QemuBasicBlockCoverageBridge, QemuCoverageError};
pub use crash_detection::{
    QemuBoundedAwaitTimeout, QemuChannelFailure, QemuChildExitProbe, QemuChildStatusProbeError,
    QemuCrashCause, QemuCrashDetector, QemuCrashHandling, QemuCrashedNodeStatus,
    QemuIntendedCrashFaultStatus, QemuNodeRunStatus, QemuProcessExit,
};
pub use crucible_shmem::AdvanceStopCondition as QemuQuantumStopCondition;
pub(crate) use exact_checkpoint_input::QemuExactCheckpointInputMaterialization;
pub use fault_action_sink::QemuFaultActionSink;
pub use fault_capability::{QemuFaultCapabilityRequirement, QemuTargetManifestRequirement};
pub use fault_implementation::node_effect_implementation_registry;
pub use gdbstub_proxy::{
    QemuGdbstubBreakpointPolicy, QemuGdbstubProxy, QemuGdbstubProxyError, QemuGdbstubProxyListener,
    QemuGdbstubProxyServer, QemuGdbstubProxySessionReport,
};
#[cfg(target_os = "linux")]
pub use host_setup::{
    QemuHostPluginSetup, QemuHostPluginSetupError, complete_qemu_host_plugin_setup,
    complete_qemu_host_plugin_setup_with_plugin_setup_plan,
};
pub use inertness::{
    QemuControlFrameClass, QemuControlPlaneInertnessError, QemuControlPlaneInertnessReport,
    QemuControlPlaneObservation, QemuSimulationMode, SIM_ON_CONTROL_FRAME_CLASSES,
    assert_qemu_control_plane_inert,
};
pub use launch::{
    CrucibleAcceleratorDevice, CrucibleShmem9pDevice, CrucibleShmemBlockDevice,
    CrucibleShmemNetworkDevice, DEFAULT_CRUCIBLE_ACCELERATOR_DEVICE_ID,
    DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID, DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID,
    DEFAULT_CRUCIBLE_SHMEM_9P_MOUNT_TAG, DEFAULT_CRUCIBLE_SHMEM_BLOCK_NODE_NAME,
    DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID, DEFAULT_CRUCIBLE_SHMEM_NETDEV_ID,
    DEFAULT_CRUCIBLE_SHMEM_NETWORK_DEVICE_ID, DEFAULT_CRUCIBLE_SHMEM_NETWORK_MAC,
    DEFAULT_ROOT_OVERLAY_FILE_NAME, DEFAULT_VMSTATE_FILE_NAME, DEFAULT_VMSTATE_NODE_NAME,
    DeterministicLaunchProfile, DiskImageMode, GuestBackingStateMode, GuestCoreContentMode,
    GuestEntropySeed, GuestEntropySeedFile, IcountShiftSetting, InputPolicy,
    LaunchProfileCandidate, LaunchProfileError, LivePluginGuestArchitecture, MachineResetMode,
    NodeIcountShift, QEMU_CONSOLE_CHARDEV_ID, QEMU_CONSOLE_SOCKET_FILE_NAME,
    QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID, QEMU_DEBUG_GUEST_ACTIVATION_PORT_NAME,
    QEMU_DEBUG_GUEST_ACTIVATION_SOCKET_FILE_NAME, QEMU_DEBUG_GUEST_VIRTIO_SERIAL_ID,
    QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD,
    QEMU_RR_CONTROL_BOUNDARY_TRACE_FILE_NAME, QEMU_RUNTIME_DETERMINISM_TRACE_FILE_NAME,
    QemuGdbstubChannelConfig, QemuLaunchAppRandomConfig, QemuLaunchArtifact, QemuLaunchCommand,
    QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchInheritedFds,
    QemuLaunchPluginConfig, QemuLaunchPluginSwitch, QemuLaunchResourceError,
    QemuLaunchResourceRequirements, QemuPreSpawnLaunchValidation,
    QemuPreSpawnLaunchValidationError, QemuQmpChannelConfig, QemuRootImageFormat,
    QemuVmLaunchConfig, QemuWhiteboxSetupError, QemuWhiteboxSetupValidation, ROOT_DRIVE_ID,
    qemu_fault_target_hash, validate_aarch64_whitebox_setup, validate_pre_spawn_qemu_launch_args,
    validate_x86_whitebox_hmp_mtree,
};
#[cfg(target_os = "linux")]
pub use linux_attempt_host::{
    LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory, LinuxQemuAttemptHostOwner,
};
#[cfg(target_os = "linux")]
pub use linux_attempt_process::{
    LinuxQemuAttemptCancellationSignal, LinuxQemuAttemptProcessConfig,
    LinuxQemuAttemptProcessFactory, LinuxQemuAttemptProcessOwner,
    LinuxQemuHotForkChildProcessAuthority, MAX_LINUX_QEMU_PROCESS_FINISH_TIMEOUT,
    MIN_LINUX_QEMU_PROCESS_FINISH_TIMEOUT,
};
#[cfg(target_os = "linux")]
pub use live_plugin_gate::{
    LivePluginInstallAdmission, LivePluginInstallGateConfig, LivePluginInstallGateError,
    LivePluginInstallReport, run_live_plugin_install_gate,
};
#[cfg(not(target_os = "linux"))]
pub use live_plugin_gate::{
    LivePluginInstallGateConfig, LivePluginInstallGateError, LivePluginInstallReport,
    run_live_plugin_install_gate,
};
#[cfg(unix)]
pub use mapped_quantum::{QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError};
pub(crate) use node::QemuQmpMachineControlChannel;
#[cfg(target_os = "linux")]
pub use node::{
    MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES, QemuExactCheckpointCaptureAdmission,
    QemuExactCheckpointCaptureBoundary, QemuExactCheckpointCaptureOutputs,
    QemuExactCheckpointCaptureResult, QemuHotForkChildConsoleObservation,
    QemuHotForkChildConsoleStageError, QemuHotForkChildConsoleStageProof,
    QemuHotForkChildConsoleStageState, QemuHotForkChildDiagnosticCapture,
    QemuHotForkChildDiagnosticConsumer, QemuHotForkChildDiagnosticDrain,
    QemuHotForkChildDiagnosticStageError, QemuHotForkChildDiagnosticStageProof,
    QemuHotForkChildDiagnosticStageState, QemuHotForkChildFileDestination,
    QemuHotForkChildFilesStageProof, QemuHotForkChildLaunch, QemuHotForkChildProcessBasis,
    QemuHotForkChildProcessContractStageProof, QemuHotForkChildProcessOwner,
    QemuHotForkChildQmpHandshakeError, QemuHotForkChildQmpHostEndpoint,
    QemuHotForkChildQmpStageError, QemuHotForkChildQmpStageProof, QemuHotForkChildQmpStageState,
    QemuHotForkChildResourcePreparationError, QemuHotForkCommandError,
    QemuHotForkDetachedChildResources, QemuHotForkHostContinuation, QemuHotForkLaunchError,
    QemuHotForkNodeStateContinuation, QemuHotForkPluginEndpointStageError,
    QemuHotForkPluginEndpointStageProof, QemuHotForkPluginEndpointStageState,
    QemuHotForkPluginHostEndpoint, QemuHotForkPreparedChildResources,
    QemuHotForkPrivateRingMapping, QemuHotForkPrivateRingStageError,
    QemuHotForkPrivateRingStageProof, QemuHotForkPrivateRingStageState,
    QemuHotForkSchedulerNodeAssemblyError, QemuHotForkSchedulerNodeContinuation,
    QemuHotForkSchedulerNodeInstallError, QemuHotForkSourceRearmError,
};
pub use node::{
    QemuBoundedSchedulerPreemptionTargetError, QemuLogicalTimeCalibration, QemuNode,
    QemuNodeChannelError, QemuNodeChannelPlane, QemuNodeChannels, QemuNodeChild,
    QemuNodeEmittedFrame, QemuNodeError, QemuNodeExternalProcessControl, QemuNodeIdleState,
    QemuNodeLifecycleState, QemuNodePendingQuantum, QemuPluginIpcControlChannel,
    QemuShmemHotPathChannel,
};
#[cfg(target_os = "linux")]
#[cfg(unix)]
pub use node::{QemuHotForkPluginRingImage, QemuVirtualTimerFireWitness};
#[cfg(target_os = "linux")]
pub use node::{QemuProcessIdentity, linux_process_identity, quarantine_orphaned_qemu_process};
#[cfg(all(target_os = "linux", feature = "test-support"))]
pub use node::{
    QemuTestHotForkIsolationFault, QemuTestHotForkOutcome, QemuTestHotForkSourceError,
    QemuTestQuantumBoundary, scripted_hot_fork_source_for_test,
    scripted_hot_fork_source_with_observations_for_test,
    scripted_hot_fork_source_with_script_for_test, scripted_hot_fork_source_with_state_for_test,
};
#[cfg(target_os = "linux")]
pub use node_factory::QemuNodeFactoryError;
#[cfg(target_os = "linux")]
pub(crate) use node_factory::{
    QemuExactCheckpointRestoreDescriptors, QemuGuardedBakedRestoreAdmission,
    QemuGuardedProbeRestoreAdmission,
};
#[cfg(target_os = "linux")]
pub(crate) use node_factory::{QemuNodeFactoryRuntime, QemuQmpExactSnapshotControlChannel};
#[cfg(target_os = "linux")]
pub use node_set::QemuNodeSetPreparedHotForkSource;
pub use node_set::{
    QemuHostParallelismEvidence, QemuNodeSelectablePendingRequest, QemuNodeSet,
    QemuNodeTerminalReplacementPlan,
};
#[cfg(target_os = "linux")]
pub use node_set::{QemuNodeSetBlockBoundaryCheckpoint, QemuNodeSetPreparedHotForkTemplate};
pub use production_fault_runtime::{
    ProductionFaultRuntime, ProductionFaultRuntimeCheckpoint,
    ProductionFaultRuntimeCheckpointCodecError, ProductionFaultRuntimeError,
    ProductionNetworkStateCheckpoint, QemuNodeLifecycleDecision, QemuNodeLifecycleIntent,
    QemuNodeLifecycleRelease, QemuNodeLifecycleWork,
};
pub use production_fault_sink::ProductionFaultActionSink;
pub use qmp::{
    QMP_CAPABILITIES_COMMAND, QMP_CLOSEFD_COMMAND, QMP_COMMAND_TIMEOUT, QMP_CONT_COMMAND,
    QMP_DEBUG_GUEST_ACTIVATION_TOKEN, QMP_DESCRIPTOR_NAME_MAX_BYTES, QMP_GETFD_COMMAND,
    QMP_GREETING_TIMEOUT, QMP_HOT_FORK_ASYNC_WORKER_BARRIER_COMMAND,
    QMP_HOT_FORK_ASYNC_WORKER_BARRIER_SCHEMA_VERSION, QMP_HOT_FORK_BLOCK_BARRIER_COMMAND,
    QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION, QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES,
    QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION, QMP_HOT_FORK_CHILD_CONSOLE_COMMAND,
    QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION, QMP_HOT_FORK_CHILD_DIAGNOSTICS_COMMAND,
    QMP_HOT_FORK_CHILD_DIAGNOSTICS_SCHEMA_VERSION, QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD,
    QMP_HOT_FORK_CHILD_FILES_COMMAND, QMP_HOT_FORK_CHILD_FILES_MAX,
    QMP_HOT_FORK_CHILD_FILES_SCHEMA_VERSION, QMP_HOT_FORK_CHILD_PROCESS_COMMAND,
    QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_COMMAND,
    QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION, QMP_HOT_FORK_CHILD_PROCESS_SCHEMA_VERSION,
    QMP_HOT_FORK_CHILD_QMP_COMMAND, QMP_HOT_FORK_CHILD_QMP_SCHEMA_VERSION,
    QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION, QMP_HOT_FORK_COMMAND,
    QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND, QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION,
    QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND, QMP_HOT_FORK_PLUGIN_ENDPOINTS_SCHEMA_VERSION,
    QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION, QMP_HOT_FORK_PRIVATE_RINGS_COMMAND,
    QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION, QMP_HOT_FORK_RCU_BARRIER_COMMAND,
    QMP_HOT_FORK_RCU_BARRIER_SCHEMA_VERSION, QMP_HOT_FORK_SCHEMA_VERSION,
    QMP_HOT_FORK_TEMPLATE_COMMAND, QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS,
    QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION, QMP_JOB_DISMISS_COMMAND, QMP_JOB_QUERY_INTERVAL,
    QMP_JOB_QUERY_LIMIT, QMP_QUERY_HOT_FORK_CHILD_RUNTIME_COMMAND,
    QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND, QMP_QUERY_JOBS_COMMAND,
    QMP_QUERY_STATUS_COMMAND, QMP_QUIT_COMMAND_NAME, QMP_SNAPSHOT_DELETE_COMMAND,
    QMP_SNAPSHOT_SAVE_COMMAND, QMP_SNAPSHOT_VMSTATE_DEVICE, QMP_STOP_COMMAND,
    QemuQmpVmStateControlChannel, QmpCheckpointEpochState, QmpCheckpointIdentity,
    QmpCheckpointRamKind, QmpClient, QmpCommandComplete, QmpCommandKind, QmpDescriptorName,
    QmpError, QmpGreeting, QmpHotForkBlockBarrierState, QmpHotForkBlockSnapshotBinding,
    QmpHotForkBlockSnapshotBindingError, QmpHotForkBlockSnapshotRoot, QmpHotForkBlockSourceProof,
    QmpHotForkChildConsoleState, QmpHotForkChildDiagnosticState, QmpHotForkChildFile,
    QmpHotForkChildFileRoot, QmpHotForkChildFilesState, QmpHotForkChildProcessContractIdentity,
    QmpHotForkChildProcessContractNames, QmpHotForkChildProcessContractState,
    QmpHotForkChildProcessPhase, QmpHotForkChildProcessState, QmpHotForkChildQmpState,
    QmpHotForkChildRuntimePhase, QmpHotForkChildRuntimeState, QmpHotForkOutcome,
    QmpHotForkPluginBarrierState, QmpHotForkPluginEndpointDescriptorPlan,
    QmpHotForkPluginEndpointIdentity, QmpHotForkPluginEndpointState,
    QmpHotForkPluginResourceInventory, QmpHotForkPrivateRingState, QmpHotForkProof,
    QmpHotForkRcuBarrierState, QmpHotForkRequest, QmpHotForkRequestError, QmpHotForkState,
    QmpHotForkTemplateOutcome, QmpHotForkTemplateResourceStageState, QmpHotForkTemplateState,
    QmpIoTimeoutPolicy, QmpJobPollPolicy, QmpRunState, QmpRunStateKind, QmpTimeoutStream,
};
pub(crate) use qmp::{QmpCheckpointCapture, QmpCheckpointCaptureRequest};
pub(crate) use qmp::{QmpCheckpointRestoreLayer, QmpCheckpointRestoreRequest};
pub use quantum::{
    QemuDeviceIoFreezeObservation, QemuDeviceIoFreezeReport, QemuInboundFrame, QemuOutboundFrame,
    QemuPendingQuantum, QemuQuantumError, QemuQuantumOperation, QemuQuantumOperationPlane,
    QemuQuantumReport, QemuQuantumShmemConfig, QemuQuantumShmemHotPath, QemuQuantumShmemView,
    assert_qemu_quantum_hot_path_is_shmem_only,
};
pub use realization::{
    QemuBakedGenesisSnapshot, QemuReplayOracleEvidence, QemuReplayOracleMatch,
    QemuVmRealizationError, QemuVmReplayRequest, QemuVmSnapshot, QemuVmSnapshotCodecError,
};
#[cfg(target_os = "linux")]
pub(crate) use realization::{QemuHotForkTemplateIdentity, QemuHotForkTemplatePreparer};
#[cfg(target_os = "linux")]
pub use realization::{
    QemuReplayValidationExactAdmission, QemuReplayValidationExecutor,
    QemuReplayValidationThinAdmission,
};
pub use shutdown::{
    QEMU_SHUTDOWN_ESCALATION_ORDER, QMP_QUIT_COMMAND, QemuChildWait, QemuReap, QemuShutdownAttempt,
    QemuShutdownError, QemuShutdownFailure, QemuShutdownPolicy, QemuShutdownReport,
    QemuShutdownRung, QemuShutdownTarget, QemuShutdownTargetError, UnixQemuChildShutdownTarget,
    send_control_quit_frame, send_qmp_quit_command, shutdown_qemu_child,
};
#[cfg(target_os = "linux")]
pub(crate) use spawn::spawn_prepared_qemu_child_with_fds_in_directory_guarded;
#[cfg(target_os = "linux")]
pub use spawn::{
    QemuChildProcessContract, QemuPreparedRunDirectory, QemuSpawnError, QemuSpawnHostResources,
    QemuSpawnSetupResources, QemuSpawnedChild,
};
pub use storage_array::{
    StorageArrayError, StorageArrayMemberWrite, StorageArrayWritePlan, plan_storage_array_write,
    read_storage_array,
};
pub use storage_fault_resolver::{
    ResolvedStorageArrayMember, ResolvedStorageArrayPolicy, ResolvedStorageRebuildService,
    ResolvedVolatileCacheLoss, StorageFaultResolutionContext, StorageFaultResolutionError,
    VolatileCacheLossReplay, block_delivery_fault_opportunity, block_durability_config,
    block_persistence_fault_opportunity, block_request_fault_opportunity,
    block_request_persistence_fault_opportunity, merge_block_fault_phase_directive,
    resolve_block_controller_transition, resolve_block_fault_directive,
    resolve_block_persistence_media_directive, resolve_storage_array_baseline,
    resolve_storage_array_policy, resolve_storage_array_rebuild_failure,
    resolve_storage_array_rebuild_service, resolve_volatile_cache_loss,
    storage_array_rebuild_fault_opportunity, storage_recovery_event_key,
};
#[cfg(target_os = "linux")]
pub use supervision::bounded_scheduler_preemption::BoundedSchedulerPreemptionError;
pub use supervision::bounded_scheduler_preemption::{
    BoundedSchedulerPreemptionEvidence, BoundedSchedulerPreemptionEvidenceClaim,
    BoundedSchedulerPreemptionEvidenceError, BoundedSchedulerPreemptionEvidenceSnapshot,
};
#[cfg(target_os = "linux")]
pub use supervision::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, NinepIoDiagnostics, NinepIoDiagnosticsSnapshot,
    QemuBlockFaultCoordinator, QemuDeviceHostWorkDelay, QemuLive9pIoRequestPin,
    QemuLive9pIoServiceStep, QemuLive9pIoServicer, QemuLive9pIoServicerError,
    QemuLive9pIoTransactionCheckpoint, QemuLive9pResponseEvidence, QemuLiveAcceleratorCheckpoint,
    QemuLiveAcceleratorServiceStep, QemuLiveAcceleratorServicer, QemuLiveAcceleratorServicerError,
    QemuLiveBlockHostWorkPool, QemuLiveBlockHostWorkPoolError, QemuLiveBlockIoDeliveryStep,
    QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoIntakeStep, QemuLiveBlockIoObservedRequest,
    QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer, QemuLiveBlockIoServicerError,
    QemuLiveHostIoRuntime, QemuLiveHostIoRuntimeError, QemuLiveHotForkChildReport,
    QemuLiveHotForkChildStressReport, QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig,
    QemuLiveNodeStepGateError, QemuNinepFaultCoordinator, QemuProductionExactRestoreLaunch,
    QemuProductionExactRestoreProfile, QemuProductionExactRestoreRequest,
    QemuProductionFreshLaunchAdmission, QemuRrControlBoundaryTraceError,
    QemuRrControlBoundaryTracePhase, QemuRrControlBoundaryTraceRecord,
    QemuRuntimeDeterminismIdlePhase, QemuRuntimeDeterminismIdleRecord,
    QemuRuntimeDeterminismTimerOwner, QemuRuntimeDeterminismTimerRecord,
    QemuRuntimeDeterminismTimerScope, QemuRuntimeDeterminismTraceError,
    QemuRuntimeDeterminismTraceRecord, QemuSharedBlockDevice, launch_qemu_production_fresh_node,
    parse_qemu_rr_control_boundary_trace, parse_qemu_runtime_determinism_trace,
    run_qemu_live_hot_fork_child_gate, run_qemu_live_hot_fork_child_stress_gate,
};
