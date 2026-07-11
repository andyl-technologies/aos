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
//! `savevm_policy` owns the conservative thin-replay fallback for incomplete
//! QEMU `savevm`/`loadvm` coverage.
//!
//! Unsafe boundary discipline: descriptor, shared-memory, monitor, and FFI
//! details stay private; public callers use a safe host-driver API that
//! validates process and mapping invariants before touching raw state.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod async_driver;
mod coverage;
mod crash_detection;
mod determinism_boundary;
mod gdbstub_proxy;
#[cfg(target_os = "linux")]
mod host_setup;
mod inertness;
mod launch;
#[cfg(target_os = "linux")]
mod live_coverage_gate;
#[cfg(unix)]
mod mapped_quantum;
mod node;
#[cfg(target_os = "linux")]
mod node_factory;
mod plugin_control;
mod qmp;
mod quantum;
mod realization;
mod savevm_policy;
mod setup_failure;
mod shutdown;
mod single_vm_fingerprint;
#[cfg(target_os = "linux")]
mod spawn;

pub use async_driver::{
    QemuAsyncCrashEscalationTarget, QemuAsyncDriverError, QemuAsyncDriverOperation,
    QemuAsyncDriverPolicy, QemuAsyncDriverRuntimeError, QemuAsyncDriverTargetError,
    QemuAsyncLifecycleAwaitOutcome, QemuAsyncLifecycleAwaitReport, QemuAsyncNodeStepOutcome,
    QemuAsyncNodeStepReport, QemuAsyncNodeStepTarget, QemuAsyncQuantumCompletion, QemuAsyncWait,
    QemuAsyncWaitOutcome, QemuHostIoRuntime, assert_async_driver_quantum_hot_path_is_shmem_only,
    await_bounded_lifecycle_event, run_bounded_qemu_node_step,
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
pub use gdbstub_proxy::{
    QemuGdbstubBreakpointPolicy, QemuGdbstubProxy, QemuGdbstubProxyError, QemuGdbstubProxyListener,
    QemuGdbstubProxyServer, QemuGdbstubProxySessionReport,
};
#[cfg(target_os = "linux")]
pub use host_setup::{
    QemuHostPluginSetup, QemuHostPluginSetupError, complete_qemu_host_plugin_setup,
};
pub use inertness::{
    QemuControlFrameClass, QemuControlPlaneInertnessError, QemuControlPlaneInertnessReport,
    QemuControlPlaneObservation, QemuSimulationMode, SIM_ON_CONTROL_FRAME_CLASSES,
    assert_qemu_control_plane_inert,
};
pub use launch::{
    DeterministicLaunchProfile, DiskImageMode, GuestBackingStateMode, GuestCoreContentMode,
    GuestEntropySeed, GuestEntropySeedFile, IcountShiftSetting, InputPolicy,
    LaunchProfileCandidate, LaunchProfileError, MachineResetMode, NodeClockSkewDeclaration,
    NodeIcountShift, QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD,
    QemuGdbstubChannelConfig, QemuLaunchArtifact, QemuLaunchCommand, QemuLaunchCommandBuilder,
    QemuLaunchCommandError, QemuLaunchInheritedFds, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuPreSpawnLaunchValidation, QemuPreSpawnLaunchValidationError, QemuQmpChannelConfig,
    QemuVmLaunchConfig, validate_pre_spawn_qemu_launch_args,
};
#[cfg(target_os = "linux")]
pub use live_coverage_gate::{
    LoadedQemuCoverageGateConfig, LoadedQemuCoverageGateError, LoadedQemuCoverageGateReport,
    run_loaded_qemu_coverage_gate,
};
#[cfg(unix)]
pub use mapped_quantum::{QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError};
pub use node::{
    QemuNode, QemuNodeChannelError, QemuNodeChannelPlane, QemuNodeChannels, QemuNodeChild,
    QemuNodeEmittedFrame, QemuNodeError, QemuNodeIdleState, QemuNodeLifecycleState,
    QemuNodePendingQuantum, QemuPluginIpcControlChannel, QemuQmpMachineControlChannel,
    QemuShmemHotPathChannel,
};
#[cfg(target_os = "linux")]
pub use node_factory::{
    QemuNodeFactoryError, QemuNodeFactoryRuntime, QemuNodeRestoreAdmission, QemuNodeRestorePlan,
    QemuQmpShutdownOnlyControlChannel, QemuWarmRestoreLaunchError,
    build_qemu_node_from_completed_setup, build_qemu_node_from_restored_checkpoint,
    spawn_setup_and_restore_qemu_node,
};
pub use qmp::{
    QMP_CAPABILITIES_COMMAND, QMP_COMMAND_TIMEOUT, QMP_GREETING_TIMEOUT, QMP_JOB_QUERY_INTERVAL,
    QMP_JOB_QUERY_LIMIT, QMP_QUERY_CPUS_FAST_COMMAND, QMP_QUERY_JOBS_COMMAND,
    QMP_QUERY_STATUS_COMMAND, QMP_QUIT_COMMAND_NAME, QMP_SNAPSHOT_LOAD_COMMAND,
    QMP_SNAPSHOT_SAVE_COMMAND, QMP_SNAPSHOT_VMSTATE_DEVICE, QemuQmpVmStateControlChannel,
    QmpClient, QmpCommandComplete, QmpCommandKind, QmpCpuTopology, QmpError, QmpGreeting,
    QmpIoTimeoutPolicy, QmpJobPollPolicy, QmpRunState, QmpRunStateKind, QmpSnapshotTag,
    QmpTimeoutStream,
};
pub use quantum::{
    QemuDeviceIoFreezeObservation, QemuDeviceIoFreezeReport, QemuDueInboundFrame, QemuInboundFrame,
    QemuOutboundFrame, QemuPendingQuantum, QemuQuantumError, QemuQuantumOperation,
    QemuQuantumOperationPlane, QemuQuantumReport, QemuQuantumShmemConfig, QemuQuantumShmemHotPath,
    QemuQuantumShmemView, assert_qemu_quantum_hot_path_is_shmem_only,
};
pub use realization::{
    QemuBackendRealizationExecutor, QemuBakedGenesisRestoreAdmission, QemuBakedGenesisSnapshot,
    QemuCachedAncestor, QemuVmBakeExecutor, QemuVmLoadvmAdmissionPolicy, QemuVmRealization,
    QemuVmRealizationError, QemuVmRealizationExecutor, QemuVmRealizationKind,
    QemuVmRealizationOperation, QemuVmRealizationStore, QemuVmReplayRequest, QemuVmSnapshot,
    bake_qemu_genesis_vm, check_qemu_replay_oracle, fork_qemu_vm, instantiate_qemu_vm,
    resume_qemu_vm, start_qemu_vm,
};
#[cfg(target_os = "linux")]
pub use realization::{
    QemuNodeRealizationExecutor, QemuNodeRealizationLauncher, QemuRealizedNodeBackend,
    QemuWarmRestoreNodeLauncher,
};
pub use savevm_policy::{
    QEMU_SAVEVM_FALLBACK_MARKER, QEMU_SAVEVM_PHASE0_S3_CHECK, QemuLoadvmCommandAuthorization,
    QemuLoadvmCommandPurpose, QemuLoadvmRealizationAdmission, QemuReplayOracleValidation,
    QemuSavevmCompletenessPolicy, QemuSavevmCompletenessStatus, QemuSavevmFallback,
    QemuSavevmPolicyError, QemuVmRealizationBranch,
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
    LiveObservationAttempt, LiveObservationProcess, LiveObservationProcessError,
    LiveObservationShutdown, LiveObservationShutdownPolicy, LiveRunnerArtifactRoot,
    LiveRunnerArtifacts, LiveRunnerArtifactsError, LiveRunnerConfig, LiveRunnerConfigError,
    LiveRunnerImmutableInputs, LiveRunnerLaunchFields, LiveRunnerLaunchKind, LiveRunnerLaunchSpec,
    LiveRunnerQmpConnector, LiveRunnerQmpObservation, LiveRunnerQmpPollError,
    LiveRunnerQmpPollPolicy, LiveRunnerQmpPoller, LiveRunnerQmpSession, LiveRunnerSleeper,
    ThreadLiveRunnerSleeper, TypedLiveRunnerQmpConnector, VerifiedGuestImageDigests,
    VerifiedLiveRunInputs, VerifiedLiveRunInputsError, spawn_live_observation_process,
};
pub use single_vm_fingerprint::{
    QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTraceDefinitionPreflight, QemuTraceFingerprintDefinition,
    QemuTraceFingerprintImport, QemuTraceFingerprintImportError, QemuTraceIdentityContract,
    QemuTraceObservationContract, QemuTraceVcpuContract, SINGLE_VM_FINGERPRINT_DIGEST_BYTES,
    SINGLE_VM_FINGERPRINT_STATE_DUMP_EVENT_LIMIT, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintCanonicalEvent, SingleVmFingerprintDivergenceStateDump,
    SingleVmFingerprintEventBoundary, SingleVmFingerprintGateError, SingleVmFingerprintGateReport,
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
    compare_single_vm_fingerprint_streams, compute_single_vm_sample_rolling_fingerprint,
    initial_single_vm_rolling_fingerprint, run_single_vm_fingerprint_gate,
};
#[cfg(target_os = "linux")]
pub use spawn::{
    QemuSpawnError, QemuSpawnHostResources, QemuSpawnSetupResources, QemuSpawnedChild,
    spawn_qemu_child_with_fds, spawn_qemu_child_with_fds_in_directory,
};
