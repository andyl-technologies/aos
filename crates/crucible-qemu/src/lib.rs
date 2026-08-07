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
//! canonical QEMU argument construction; `single_vm_fingerprint` owns the
//! safe run-twice-and-diff hook and real trace-plugin importer consumed by
//! `gate:single-vm-fingerprint`;
//! `shutdown` owns the graceful QEMU child shutdown escalation ladder;
//! `setup_failure` owns setup-abort classification and teardown; `coverage`
//! owns host-side plugin coverage observation bridging; `live_coverage_gate`
//! owns the Linux loaded-plugin coverage equivalence proof; `host_setup` owns
//! the real Linux descriptor handoff and setup lifecycle driver; `inertness`
//! owns the sim-off/sim-on QEMU control-plane inertness assertion;
//! `determinism_boundary` owns the QEMU hermeticity/fingerprint/microtest
//! boundary assertion; `gdbstub_proxy` owns the mediated debug gdbstub bridge
//! between QEMU and the operator-facing `--gdb-listen` endpoint; `async_driver`
//! owns the bounded host-I/O bridge between
//! synchronous scheduler node steps and real-time child I/O; `crash_detection`
//! owns typed crashed-node status classification; `node` owns the
//! scheduler-facing one-child/three-channel QEMU wrapper; `node_factory` owns
//! the Linux post-setup node composition boundary; `quantum` owns the
//! per-quantum shared-memory hot path; `qmp` owns the minimal typed QMP client;
//! `realization` owns the start/resume/fork instantiate branch coordinator; and
//! `exact_snapshot_policy` owns exact paired QEMU `savevm`/`loadvm` restore admission.
//!
//! Unsafe boundary discipline: descriptor, shared-memory, monitor, and FFI
//! details stay private; public callers use a safe host-driver API that
//! validates process and mapping invariants before touching raw state.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod async_driver;
#[cfg(target_os = "linux")]
mod block_realization_gate;
mod checkpoint;
mod coverage;
mod crash_detection;
mod determinism_boundary;
mod exact_snapshot_policy;
mod fault_action_sink;
mod fault_capability;
mod gdbstub_proxy;
#[cfg(target_os = "linux")]
mod host_setup;
mod host_worker_pool;
mod inertness;
mod launch;
#[cfg(target_os = "linux")]
mod live_coverage_gate;
#[cfg(target_os = "linux")]
mod live_plugin_gate;
#[cfg(all(target_os = "linux", feature = "test-support"))]
mod live_plugin_quantum_gate;
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
mod setup_failure;
mod shutdown;
mod single_vm_fingerprint;
#[cfg(target_os = "linux")]
mod spawn;
mod storage_fault_resolver;
#[cfg(target_os = "linux")]
mod supervision;

pub use async_driver::{
    QemuAsyncCrashEscalationTarget, QemuAsyncDriverError, QemuAsyncDriverOperation,
    QemuAsyncDriverPolicy, QemuAsyncDriverRuntimeError, QemuAsyncDriverTargetError,
    QemuAsyncLifecycleAwaitOutcome, QemuAsyncLifecycleAwaitReport, QemuAsyncNodeStepOutcome,
    QemuAsyncNodeStepReport, QemuAsyncNodeStepTarget, QemuAsyncQuantumCompletion, QemuAsyncWait,
    QemuAsyncWaitOutcome, QemuHostIoRuntime, assert_async_driver_quantum_hot_path_is_shmem_only,
    await_bounded_lifecycle_event, run_bounded_qemu_node_step,
};
#[cfg(target_os = "linux")]
pub use block_realization_gate::{
    BlockRealizationGateConfig, BlockRealizationGateError, BlockRealizationReport,
    run_block_realization_gate,
};
pub use checkpoint::{
    QemuHostIoCheckpoint, QemuLive9pIoServicerCheckpoint, QemuLiveBlockIoServicerCheckpoint,
    QemuNodeContinuationCheckpoint,
};
pub use coverage::{
    QemuBasicBlockCoverageBridge, QemuCoverageError, QemuCoverageFingerprintReport,
    QemuCoverageFingerprintRun, compare_coverage_opt_in_fingerprint_streams,
};
pub use crash_detection::{
    QemuBoundedAwaitTimeout, QemuChannelFailure, QemuChildExitProbe, QemuChildStatusProbeError,
    QemuCrashCause, QemuCrashDetector, QemuCrashHandling, QemuCrashedNodeStatus,
    QemuIntendedCrashFaultStatus, QemuNodeRunStatus, QemuProcessExit,
};
pub use determinism_boundary::{
    QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT, QemuDeterminismBoundaryError,
    QemuDeterminismBoundaryReport, QemuEntropyElimination, QemuEntropyEliminationMicrotest,
    QemuEntropyEliminationNegativeCase, QemuExecutionFingerprintDefinition,
    QemuFingerprintStateComponent, REQUIRED_QEMU_ENTROPY_ELIMINATIONS,
    REQUIRED_QEMU_FINGERPRINT_COMPONENTS, REQUIRED_QEMU_FINGERPRINT_EVENT_BOUNDARIES,
    qemu_entropy_elimination_microtests, validate_qemu_determinism_boundary,
};
pub use exact_snapshot_policy::{
    QEMU_EXACT_SNAPSHOT_RESTORE_CHECK, QemuExactSnapshotPolicy, QemuExactSnapshotPolicyError,
    QemuLoadvmCommandAuthorization, QemuLoadvmCommandPurpose, QemuLoadvmRealizationAdmission,
    QemuReplayOracleValidation,
};
pub use fault_action_sink::QemuFaultActionSink;
pub use fault_capability::QemuFaultCapabilityRequirement;
pub use gdbstub_proxy::{
    QemuGdbstubBreakpointPolicy, QemuGdbstubProxy, QemuGdbstubProxyError, QemuGdbstubProxyListener,
    QemuGdbstubProxyServer, QemuGdbstubProxySessionReport,
};
#[cfg(target_os = "linux")]
pub use host_setup::{
    QemuHostPluginSetup, QemuHostPluginSetupError, complete_qemu_host_plugin_setup,
};
pub use host_worker_pool::{
    QemuHostCompletionOrderKey, QemuHostWorkerOutcome, QemuHostWorkerPool, QemuHostWorkerPoolError,
    QemuHostWorkerPoolReport, QemuHostWorkerRun,
};
pub use inertness::{
    QemuControlFrameClass, QemuControlPlaneInertnessError, QemuControlPlaneInertnessReport,
    QemuControlPlaneObservation, QemuSimulationMode, SIM_ON_CONTROL_FRAME_CLASSES,
    assert_qemu_control_plane_inert,
};
pub use launch::{
    CrucibleShmem9pDevice, CrucibleShmem9pFsdevBackend, CrucibleShmemBlockDevice,
    CrucibleShmemNetworkDevice, DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID,
    DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID, DEFAULT_CRUCIBLE_SHMEM_9P_MOUNT_TAG,
    DEFAULT_CRUCIBLE_SHMEM_BLOCK_NODE_NAME, DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID,
    DEFAULT_CRUCIBLE_SHMEM_NETDEV_ID, DEFAULT_CRUCIBLE_SHMEM_NETWORK_DEVICE_ID,
    DEFAULT_CRUCIBLE_SHMEM_NETWORK_MAC, DEFAULT_ROOT_OVERLAY_FILE_NAME, DEFAULT_VMSTATE_FILE_NAME,
    DeterministicLaunchProfile, DiskImageMode, GuestBackingStateMode, GuestCoreContentMode,
    GuestEntropySeed, GuestEntropySeedFile, IcountShiftSetting, InputPolicy,
    LaunchProfileCandidate, LaunchProfileError, LivePluginGuestArchitecture, MachineResetMode,
    NodeClockSkewDeclaration, NodeIcountShift, QEMU_CONSOLE_CHARDEV_ID,
    QEMU_CONSOLE_SOCKET_FILE_NAME, QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD,
    QEMU_PLUGIN_WAKE_FD, QemuGdbstubChannelConfig, QemuLaunchAppRandomConfig, QemuLaunchArtifact,
    QemuLaunchCommand, QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchInheritedFds,
    QemuLaunchPluginConfig, QemuLaunchPluginSwitch, QemuPreSpawnLaunchValidation,
    QemuPreSpawnLaunchValidationError, QemuQmpChannelConfig, QemuRootImageFormat,
    QemuVmLaunchConfig, QemuWhiteboxSetupError, QemuWhiteboxSetupValidation,
    probe_x86_whitebox_setup, qemu_fault_target_hash, validate_aarch64_whitebox_setup,
    validate_pre_spawn_qemu_launch_args, validate_x86_whitebox_hmp_mtree,
};
#[cfg(target_os = "linux")]
pub use live_coverage_gate::{
    LoadedQemuCoverageGateConfig, LoadedQemuCoverageGateError, LoadedQemuCoverageGateReport,
    run_loaded_qemu_coverage_gate,
};
#[cfg(target_os = "linux")]
pub use live_plugin_gate::{
    LivePluginInstallGateConfig, LivePluginInstallGateError, LivePluginInstallReport,
    run_live_plugin_install_gate,
};
#[cfg(all(target_os = "linux", feature = "test-support"))]
pub use live_plugin_quantum_gate::{
    LivePluginAdvancementRates, LivePluginIdleObservation, LivePluginPreemptionReport,
    LivePluginQuantumGateConfig, LivePluginQuantumGateError, LivePluginQuantumReport,
    LivePluginQuantumSchedule, run_live_plugin_preemption_gate, run_live_plugin_quantum_gate,
};
#[cfg(unix)]
pub use mapped_quantum::{QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError};
pub use node::{
    QemuLogicalTimeCalibration, QemuNode, QemuNodeChannelError, QemuNodeChannelPlane,
    QemuNodeChannels, QemuNodeChild, QemuNodeEmittedFrame, QemuNodeError, QemuNodeIdleState,
    QemuNodeLifecycleState, QemuNodePendingQuantum, QemuPluginIpcControlChannel,
    QemuQmpMachineControlChannel, QemuShmemHotPathChannel,
};
#[cfg(target_os = "linux")]
pub use node_factory::{
    QemuNodeFactoryError, QemuNodeFactoryRuntime, QemuNodeRestoreAdmission, QemuNodeRestorePlan,
    QemuQmpExactSnapshotControlChannel, QemuWarmRestoreLaunchError,
    build_qemu_node_from_completed_setup, build_qemu_node_from_restored_checkpoint,
    spawn_setup_and_restore_qemu_node,
};
pub use node_set::QemuNodeSet;
#[cfg(target_os = "linux")]
pub use node_set::QemuNodeSetBlockBoundaryCheckpoint;
pub use production_fault_runtime::{
    ProductionFaultRuntime, ProductionFaultRuntimeCheckpoint, ProductionFaultRuntimeError,
    ProductionNetworkStateCheckpoint,
};
pub use production_fault_sink::ProductionFaultActionSink;
pub use qmp::{
    QMP_CAPABILITIES_COMMAND, QMP_COMMAND_TIMEOUT, QMP_CONT_COMMAND, QMP_GREETING_TIMEOUT,
    QMP_JOB_DISMISS_COMMAND, QMP_JOB_QUERY_INTERVAL, QMP_JOB_QUERY_LIMIT,
    QMP_QUERY_CPUS_FAST_COMMAND, QMP_QUERY_JOBS_COMMAND, QMP_QUERY_STATUS_COMMAND,
    QMP_QUIT_COMMAND_NAME, QMP_SNAPSHOT_DELETE_COMMAND, QMP_SNAPSHOT_LOAD_COMMAND,
    QMP_SNAPSHOT_SAVE_COMMAND, QMP_SNAPSHOT_VMSTATE_DEVICE, QMP_STOP_COMMAND,
    QemuQmpVmStateControlChannel, QmpClient, QmpCommandComplete, QmpCommandKind, QmpCpuTopology,
    QmpError, QmpGreeting, QmpIoTimeoutPolicy, QmpJobPollPolicy, QmpRunState, QmpRunStateKind,
    QmpSnapshotTag, QmpTimeoutStream,
};
pub use quantum::{
    QemuDeviceIoFreezeObservation, QemuDeviceIoFreezeReport, QemuDueInboundFrame, QemuInboundFrame,
    QemuOutboundFrame, QemuPendingQuantum, QemuQuantumError, QemuQuantumOperation,
    QemuQuantumOperationPlane, QemuQuantumReport, QemuQuantumShmemConfig, QemuQuantumShmemHotPath,
    QemuQuantumShmemView, assert_qemu_quantum_hot_path_is_shmem_only,
};
pub use realization::{
    QemuBackendRealizationExecutor, QemuBakedGenesisRestoreAdmission, QemuBakedGenesisSnapshot,
    QemuCachedAncestor, QemuVmBakeExecutor, QemuVmRealization, QemuVmRealizationError,
    QemuVmRealizationExecutor, QemuVmRealizationKind, QemuVmRealizationOperation,
    QemuVmRealizationStore, QemuVmReplayRequest, QemuVmSnapshot, bake_qemu_genesis_vm,
    check_qemu_replay_oracle, fork_qemu_vm, instantiate_qemu_vm, resume_qemu_vm, start_qemu_vm,
};
#[cfg(target_os = "linux")]
pub use realization::{
    QemuNodeRealizationExecutor, QemuNodeRealizationLauncher, QemuRealizedNodeBackend,
    QemuWarmRestoreNodeLauncher,
};
pub use setup_failure::{
    FailedQemuNodeSetup, QemuNodeSetup, QemuSchedulableNodeSetup, QemuSetupAbortError,
    QemuSetupDriver, QemuSetupFailureKind, QemuSetupFailureSource, abort_qemu_setup_failure,
    complete_qemu_node_setup, validate_qemu_setup_region_header,
};
pub use shutdown::{
    QEMU_SHUTDOWN_ESCALATION_ORDER, QMP_QUIT_COMMAND, QemuChildWait, QemuReap, QemuShutdownAttempt,
    QemuShutdownError, QemuShutdownFailure, QemuShutdownPolicy, QemuShutdownReport,
    QemuShutdownRung, QemuShutdownTarget, QemuShutdownTargetError, UnixQemuChildShutdownTarget,
    send_control_quit_frame, send_qmp_quit_command, shutdown_qemu_child,
};
#[cfg(target_os = "linux")]
pub use single_vm_fingerprint::{
    LiveDefinitionPreflightError, LiveDefinitionPreflightEvidence, LiveGenesisProbeExecutor,
    LiveGenesisProbeExecutorError, LiveGenesisProbeReport, LiveIdentityError,
    LiveInvocationIdentity, LiveInvocationPaths, LiveObservationAttempt, LiveObservationControl,
    LiveObservationControlFields, LiveObservationMode, LiveObservationModeFlags,
    LiveObservationProcess, LiveObservationProcessError, LiveObservationShutdown,
    LiveObservationShutdownPolicy, LivePreparationError, LivePreparationRequest,
    LivePreparedLaunch, LiveRunnerArtifactRoot, LiveRunnerArtifacts, LiveRunnerArtifactsError,
    LiveRunnerConfig, LiveRunnerConfigError, LiveRunnerImmutableInputs, LiveRunnerLaunchFields,
    LiveRunnerLaunchKind, LiveRunnerLaunchSpec, LiveRunnerQmpConnector, LiveRunnerQmpObservation,
    LiveRunnerQmpPollError, LiveRunnerQmpPollPolicy, LiveRunnerQmpPoller, LiveRunnerQmpSession,
    LiveRunnerSleeper, LiveTerminalHorizonExecutor, LiveTerminalHorizonExecutorError,
    LiveTerminalHorizonReport, LiveTerminalTargetExecutor, LiveTerminalTargetExecutorError,
    LiveTerminalTargetObservation, LiveTerminalTargetReport, PLUGIN_FINGERPRINT_CADENCE_ICOUNT,
    PLUGIN_FINGERPRINT_TARGET_ICOUNTS, PluginFingerprintRunner, PluginFingerprintRunnerConfig,
    PluginFingerprintRunnerError, RUST_PLUGIN_FINGERPRINT_DOMAIN, RawUnixArgvIdentity,
    RustPluginFingerprintDefinition, ThreadLiveRunnerSleeper, TypedLiveRunnerQmpConnector,
    VerifiedGuestImageDigests, VerifiedLiveRunInputs, VerifiedLiveRunInputsError,
    spawn_live_observation_process,
};
pub use single_vm_fingerprint::{
    PluginFingerprintBoundary, QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTerminalHorizonTraceImport,
    QemuTraceDefinitionPreflight, QemuTraceFingerprintDefinition, QemuTraceFingerprintImport,
    QemuTraceFingerprintImportError, QemuTraceGenesisFingerprintImport, QemuTraceIdentityContract,
    QemuTraceObservationContract, QemuTraceProcessArgvContract, QemuTraceVcpuContract,
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SINGLE_VM_FINGERPRINT_STATE_DUMP_EVENT_LIMIT,
    SingleVmFingerprintBisectionError, SingleVmFingerprintBisectionReport,
    SingleVmFingerprintBisectionRequest, SingleVmFingerprintCanonicalEvent,
    SingleVmFingerprintDivergenceStateDump, SingleVmFingerprintEventBoundary,
    SingleVmFingerprintGateError, SingleVmFingerprintGateReport,
    SingleVmFingerprintMemoryRegionState, SingleVmFingerprintMismatch,
    SingleVmFingerprintMismatchKind, SingleVmFingerprintProbe, SingleVmFingerprintProbeRequest,
    SingleVmFingerprintProbeRunner, SingleVmFingerprintRunError, SingleVmFingerprintRunInputs,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunStateDump,
    SingleVmFingerprintRunner, SingleVmFingerprintSample, SingleVmFingerprintSampleDifference,
    SingleVmFingerprintSampleMaterial, SingleVmFingerprintScenario,
    SingleVmFingerprintStateDumpProbe, SingleVmFingerprintStream, SingleVmFingerprintTrigger,
    SingleVmFingerprintVcpuState, SingleVmHostProfile, SingleVmNvcpuFingerprintContract,
    SingleVmNvcpuFingerprintMaterial, SingleVmQmpVcpuTopology, SingleVmRoundRobinCursor,
    SingleVmVcpuRegisterDigest, bisect_single_vm_fingerprint_with_probes,
    build_plugin_fingerprint_stream, compare_single_vm_fingerprint_streams,
    compute_single_vm_sample_rolling_fingerprint, initial_single_vm_rolling_fingerprint,
    nvcpu_material_from_shmem_sample, run_single_vm_fingerprint_gate,
};
#[cfg(target_os = "linux")]
pub use spawn::{
    QemuSpawnError, QemuSpawnHostResources, QemuSpawnSetupResources, QemuSpawnedChild,
    spawn_qemu_child_with_fds, spawn_qemu_child_with_fds_in_directory,
};
pub use storage_fault_resolver::{
    ResolvedVolatileCacheLoss, StorageFaultResolutionContext, StorageFaultResolutionError,
    VolatileCacheLossReplay, block_delivery_fault_opportunity, block_durability_config,
    block_persistence_fault_opportunity, block_request_fault_opportunity,
    block_request_persistence_fault_opportunity, merge_block_fault_phase_directive,
    resolve_block_fault_directive, resolve_block_persistence_media_directive,
    resolve_volatile_cache_loss, storage_recovery_event_key,
};
#[cfg(target_os = "linux")]
pub use supervision::{
    BlockIoAdvanceOutcome, BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, BlockNodeOutcome,
    LIVE_NETWORK_ACK_PAYLOAD, LIVE_NETWORK_ETHERTYPE, LIVE_NETWORK_PROBE_PAYLOAD,
    LIVE_NETWORK_REPLY_LATENCY_ICOUNT, LIVE_NETWORK_REPLY_PAYLOAD, LiveNetworkIoServiceStep,
    LiveNetworkIoSnapshot, LiveNetworkTxObservation, NinepIoAdvanceOutcome, NinepIoDiagnostics,
    NinepIoDiagnosticsSnapshot, QemuBlockFaultCoordinator, QemuDeviceHostWorkDelay,
    QemuLive9pIoGateConfig, QemuLive9pIoGateError, QemuLive9pIoReport, QemuLive9pIoRequestPin,
    QemuLive9pIoServiceStep, QemuLive9pIoServicer, QemuLive9pIoServicerError,
    QemuLiveBlockHostWorkPool, QemuLiveBlockHostWorkPoolError, QemuLiveBlockIoDeliveryStep,
    QemuLiveBlockIoGateConfig, QemuLiveBlockIoGateError, QemuLiveBlockIoHostWorkPin,
    QemuLiveBlockIoIntakeStep, QemuLiveBlockIoObservedRequest, QemuLiveBlockIoReport,
    QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer, QemuLiveBlockIoServicerError,
    QemuLiveBlockNodeGateConfig, QemuLiveBlockNodeGateError, QemuLiveBlockNodeReport,
    QemuLiveBlockStorageEvents, QemuLiveExactSnapshotReport, QemuLiveHostIoRuntime,
    QemuLiveHostIoRuntimeError, QemuLiveHostParallelGateError, QemuLiveHostParallelReport,
    QemuLiveNetworkIoGateConfig, QemuLiveNetworkIoGateError, QemuLiveNetworkIoReport,
    QemuLiveNetworkIoServicer, QemuLiveNetworkIoServicerError, QemuLiveNodeStepGateConfig,
    QemuLiveNodeStepGateError, QemuLiveNodeStepQuantum, QemuLiveNodeStepReport,
    QemuLiveNodeStepSchedule, QemuNinepFaultCoordinator, QemuSharedBlockDevice,
    launch_qemu_live_node, launch_qemu_live_node_exact_snapshot, launch_qemu_live_node_restored,
    run_qemu_live_9p_io_gate, run_qemu_live_block_io_gate, run_qemu_live_block_node_gate,
    run_qemu_live_exact_snapshot_gate, run_qemu_live_host_parallel_gate,
    run_qemu_live_network_io_gate, run_qemu_live_node_step_gate,
};
