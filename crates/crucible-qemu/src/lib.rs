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
//! safe run-twice-and-diff hook consumed by `gate:single-vm-fingerprint`;
//! `shutdown` owns the graceful QEMU child shutdown escalation ladder;
//! `setup_failure` owns setup-abort classification and teardown; `inertness`
//! owns the sim-off/sim-on QEMU control-plane inertness assertion;
//! `crash_detection` owns typed crashed-node status classification; and `qmp`
//! owns the minimal typed QMP client.
//!
//! Unsafe boundary discipline: descriptor, shared-memory, monitor, and FFI
//! details stay private; public callers use a safe host-driver API that
//! validates process and mapping invariants before touching raw state.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod crash_detection;
mod inertness;
mod launch;
mod qmp;
mod setup_failure;
mod shutdown;
mod single_vm_fingerprint;

pub use crash_detection::{
    QemuChannelFailure, QemuChildExitProbe, QemuChildStatusProbeError, QemuCrashCause,
    QemuCrashDetector, QemuCrashHandling, QemuCrashedNodeStatus, QemuIntendedCrashFaultStatus,
    QemuNodeRunStatus, QemuProcessExit,
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
    NodeIcountShift,
};
pub use qmp::{
    QMP_CAPABILITIES_COMMAND, QMP_JOB_QUERY_INTERVAL, QMP_JOB_QUERY_LIMIT, QMP_QUERY_JOBS_COMMAND,
    QMP_QUIT_COMMAND_NAME, QMP_SNAPSHOT_LOAD_COMMAND, QMP_SNAPSHOT_SAVE_COMMAND,
    QMP_SNAPSHOT_VMSTATE_DEVICE, QmpClient, QmpCommandComplete, QmpCommandKind, QmpError,
    QmpGreeting, QmpJobPollPolicy, QmpSnapshotTag,
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
pub use single_vm_fingerprint::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintEventBoundary, SingleVmFingerprintGateError, SingleVmFingerprintGateReport,
    SingleVmFingerprintMismatch, SingleVmFingerprintMismatchKind, SingleVmFingerprintRunError,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunner,
    SingleVmFingerprintSample, SingleVmFingerprintScenario, SingleVmFingerprintStream,
    SingleVmFingerprintTrigger, SingleVmHostProfile, compare_single_vm_fingerprint_streams,
    run_single_vm_fingerprint_gate,
};
