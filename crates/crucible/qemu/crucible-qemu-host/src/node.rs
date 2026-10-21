//! Scheduler-facing QEMU node wrapper.
//!
//! The wrapper owns exactly one child handle and the three QEMU
//! channels for that child: plugin IPC control, shared-memory hot path, and
//! QMP machine control. It exposes the synchronous backend boundary while
//! keeping per-quantum timing and frame traffic on the shared-memory channel.

mod backend;
use backend::virtual_time_from_advance_outcome;

use std::any::Any;
use std::process::Child;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::path::Path;

use crate::async_driver::run_bounded_qemu_node_step_with_start_hook;
use crate::console_observation::QemuConsoleObservationSpool;
use crate::shutdown::{
    QemuChildWait, QemuReap, QemuShutdownPolicy, QemuShutdownReport, QemuShutdownRung,
    QemuShutdownTarget, QemuShutdownTargetError, signal_child, wait_child,
};
use crate::supervision::HostSupervisionDeadline;
use crate::{
    QemuAdvanceCompletionFence, QemuAsyncCrashEscalationTarget, QemuAsyncDriverPolicy,
    QemuAsyncDriverTargetError, QemuAsyncNodeStepOutcome, QemuAsyncNodeStepTarget,
    QemuAsyncQuantumCompletion, QemuCrashDetector, QemuGdbstubChannelConfig, QemuHostIoRuntime,
    run_bounded_qemu_node_step,
};
use crucible_engine::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput, BackendNetworkOutput,
    BackendPhysicalStop, BackendRngEvidence, BackendSnapshot, Checkpoint, EventLog,
    ExecutionFingerprint, ExecutionHorizon, FingerprintSample, Icount, NodeId, ObservableEvent,
    SchedulerEventLogAppend, SimulationBackend, StepObservation, VirtualTime,
};
use crucible_qemu_protocol::guest_introspection::GuestIntrospectionRecord;
use crucible_qemu_shmem::{
    DequeuedFaultEvent, DequeuedFaultResult, FAULT_COMMAND_FLAG_PREPARE_ONLY, FaultCapabilityRowV1,
    FaultCommandHeaderV1, FaultResultStatus, FingerprintSample as QemuFingerprintSample,
    SchedulerPreemptionCommand, SchedulerPreemptionKind as ShmemSchedulerPreemptionKind,
};

/// Preserves the actual natural-wait cause before diagnostic formatting.
#[derive(Debug)]
pub(crate) enum ChildNaturalWaitFailure {
    AlreadyReaped,
    Io(std::io::Error),
}

impl ChildNaturalWaitFailure {
    fn into_shutdown_error(self) -> QemuShutdownTargetError {
        match self {
            Self::AlreadyReaped => {
                QemuShutdownTargetError::new("poll natural QEMU exit", "child was already reaped")
            }
            Self::Io(source) => {
                QemuShutdownTargetError::new("poll natural QEMU exit", source.to_string())
            }
        }
    }
}

mod channels;
mod child;
#[cfg(any(test, feature = "test-support", feature = "private-measurement-domain"))]
mod guarded_reset;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
mod readonly_backing;
mod source_child;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub use readonly_backing::QemuReadOnlyBackingError;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
mod parent_park_drain;
mod paused_observation;
#[cfg(target_os = "linux")]
mod receiving_transfer;
pub(crate) use channels::QemuQmpMachineControlChannel;
pub use channels::{QemuNodePendingQuantum, QemuPluginIpcControlChannel, QemuShmemHotPathChannel};
#[cfg(target_os = "linux")]
pub use receiving_transfer::QemuStoppedTransferError;
mod error;
mod exact_snapshot;
#[path = "node/host_policy.rs"]
mod host_policy;
mod network_output;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use exact_snapshot::capture_original::loan_fixture as checkpoint_original_loan_fixture;
#[cfg(target_os = "linux")]
pub use exact_snapshot::{
    CheckpointArmLoan, CheckpointOriginalCause, CheckpointOriginalError, CheckpointOriginalLoan,
    CheckpointTransportCause, QemuCheckpointDeviceReader,
};

pub use exact_snapshot::{
    CaptureReadError, QemuCapturedRamPage, QemuExactCheckpointCaptureAdmission,
    QemuExactCheckpointCaptureBoundary, QemuExactCheckpointCaptureOutputs,
    QemuExactCheckpointCaptureResult,
};
mod fault_events;
mod fault_fingerprint;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_child_console.rs"]
mod hot_fork_child_console;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_child_files.rs"]
mod hot_fork_child_files;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_child_qmp.rs"]
mod hot_fork_child_qmp;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_diagnostics.rs"]
mod hot_fork_diagnostics;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_disk.rs"]
mod hot_fork_disk;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_operation.rs"]
mod hot_fork_operation;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_plugin_endpoints.rs"]
mod hot_fork_plugin_endpoints;
#[cfg(target_os = "linux")]
mod storage_faults;
#[cfg(target_os = "linux")]
#[cfg(test)]
pub(crate) use hot_fork_plugin_endpoints::create_nonblocking_eventfd;
pub(crate) use hot_fork_plugin_endpoints::eventfd_id;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_preparation.rs"]
mod hot_fork_preparation;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_process_contract.rs"]
mod hot_fork_process_contract;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_ram_stage.rs"]
mod hot_fork_ram_stage;
#[cfg(target_os = "linux")]
use hot_fork_ram_stage::{QemuHotForkRamContinuation, QemuHotForkRamStage};
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_rearm.rs"]
mod hot_fork_rearm;
#[cfg(unix)]
#[path = "node/hot_fork_ring_image.rs"]
mod hot_fork_ring_image;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_scheduler_continuation.rs"]
mod hot_fork_scheduler_continuation;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_source_original.rs"]
mod hot_fork_source_original;
#[cfg(target_os = "linux")]
pub use hot_fork_source_original::QemuHotForkSourceOriginal;
#[path = "node/process_control.rs"]
mod process_control;
#[cfg(target_os = "linux")]
mod process_identity;
pub use error::{
    QemuBoundedSchedulerPreemptionTargetError, QemuFingerprintSampleError, QemuNodeChannelError,
    QemuNodeChannelPlane, QemuNodeError, QemuPendingQuantumReport,
};
#[cfg(target_os = "linux")]
use hot_fork_child_console::QemuHotForkChildConsoleStage;
#[cfg(target_os = "linux")]
pub use hot_fork_child_console::{
    QemuHotForkChildConsoleObservation, QemuHotForkChildConsoleStageError,
    QemuHotForkChildConsoleStageProof, QemuHotForkChildConsoleStageState,
};
#[cfg(target_os = "linux")]
use hot_fork_child_files::QemuHotForkChildFilesStage;
#[cfg(target_os = "linux")]
pub use hot_fork_child_files::{QemuHotForkChildFileDestination, QemuHotForkChildFilesStageProof};
#[cfg(target_os = "linux")]
use hot_fork_child_qmp::QemuHotForkChildQmpStage;
#[cfg(target_os = "linux")]
pub use hot_fork_child_qmp::{
    QemuHotForkChildQmpHandshakeError, QemuHotForkChildQmpHostEndpoint,
    QemuHotForkChildQmpStageError, QemuHotForkChildQmpStageProof, QemuHotForkChildQmpStageState,
};
#[cfg(target_os = "linux")]
use hot_fork_diagnostics::QemuHotForkChildDiagnosticStage;
#[cfg(target_os = "linux")]
pub use hot_fork_diagnostics::{
    MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES, QemuHotForkChildDiagnosticCapture,
    QemuHotForkChildDiagnosticConsumer, QemuHotForkChildDiagnosticDrain,
    QemuHotForkChildDiagnosticStageError, QemuHotForkChildDiagnosticStageProof,
    QemuHotForkChildDiagnosticStageState,
};
#[cfg(target_os = "linux")]
pub use hot_fork_operation::{
    QemuHotForkChildLaunch, QemuHotForkChildProcessBasis, QemuHotForkChildProcessOwner,
    QemuHotForkCommandError, QemuHotForkHostContinuation, QemuHotForkLaunchError,
};
#[cfg(target_os = "linux")]
use hot_fork_plugin_endpoints::QemuHotForkPluginEndpointStage;
#[cfg(target_os = "linux")]
pub use hot_fork_plugin_endpoints::{
    QemuHotForkPluginEndpointStageError, QemuHotForkPluginEndpointStageProof,
    QemuHotForkPluginEndpointStageState, QemuHotForkPluginHostEndpoint,
};
#[cfg(target_os = "linux")]
pub use hot_fork_preparation::{
    QemuHotForkChildResourcePreparationError, QemuHotForkPreparedChildResources,
};
#[cfg(target_os = "linux")]
use hot_fork_process_contract::QemuHotForkChildProcessContractStage;
#[cfg(target_os = "linux")]
pub use hot_fork_process_contract::QemuHotForkChildProcessContractStageProof;
#[cfg(target_os = "linux")]
pub use hot_fork_rearm::{QemuHotForkDetachedChildResources, QemuHotForkSourceRearmError};
#[cfg(unix)]
pub use hot_fork_ring_image::QemuHotForkPluginRingImage;
#[cfg(target_os = "linux")]
use hot_fork_ring_image::QemuHotForkPrivateRingStage;
#[cfg(target_os = "linux")]
pub use hot_fork_ring_image::{
    QemuHotForkPrivateRingMapping, QemuHotForkPrivateRingStageError,
    QemuHotForkPrivateRingStageProof, QemuHotForkPrivateRingStageState,
};
#[cfg(target_os = "linux")]
use hot_fork_scheduler_continuation::QemuHotForkInstalledNodeAuthority;
#[cfg(target_os = "linux")]
pub use hot_fork_scheduler_continuation::{
    QemuHotForkNodeStateContinuation, QemuHotForkSchedulerNodeAssemblyError,
    QemuHotForkSchedulerNodeContinuation, QemuHotForkSchedulerNodeInstallError,
};
pub use process_control::QemuNodeExternalProcessControl;
use process_control::QemuNodeProcessControl;
#[cfg(target_os = "linux")]
use process_identity::linux_process_identity_components;
#[cfg(target_os = "linux")]
pub use process_identity::{QemuProcessIdentity, linux_process_identity};

/// Force-kills a surviving QEMU only when its complete recorded identity matches.
///
/// A missing process or a reused PID is already contained and succeeds. An
/// exact match receives `SIGKILL`, after which this function waits until the
/// identity disappears or changes.
///
/// # Errors
///
/// Returns [`QemuNodeError`] when `/proc` cannot be validated, signaling fails,
/// or the matching process remains present through `timeout`.
#[cfg(target_os = "linux")]
pub fn quarantine_orphaned_qemu_process(
    expected: &QemuProcessIdentity,
    timeout: Duration,
) -> Result<(), QemuNodeError> {
    if linux_process_identity(expected.process_id)?.as_ref() != Some(expected) {
        return Ok(());
    }
    signal_child(
        expected.process_id,
        libc::SIGKILL,
        "kill orphaned QEMU generation",
    )
    .map_err(|error| QemuNodeError::fault_command(error.to_string()))?;
    let deadline = HostSupervisionDeadline::start(timeout);
    loop {
        if linux_process_identity(expected.process_id)?.as_ref() != Some(expected) {
            return Ok(());
        }
        if !deadline.has_time_remaining() {
            return Err(QemuNodeError::fault_command(format!(
                "orphaned QEMU PID {} remained present through {:?}",
                expected.process_id, timeout
            )));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Lifecycle state tracked by the host wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QemuNodeLifecycleState {
    /// The child is expected to be available for scheduler operations.
    Running,
    /// The node has completed the shutdown escalation and reaped the child.
    ShutdownRequested,
    /// The child cannot participate after an ambiguous supervision outcome.
    Quarantined,
}

/// A frame emitted by the QEMU node over the shared-memory hot path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QemuNodeEmittedFrame {
    /// The source node that emitted the frame.
    pub source: NodeId,
    /// The destination node for the frame.
    pub destination: NodeId,
    /// The source node icount at which the guest emitted the frame.
    pub emit_icount: Icount,
    /// The per-source deterministic frame sequence number.
    pub sequence: u64,
    /// The emitted payload bytes.
    pub payload: Vec<u8>,
}

/// The node's current idle observation from shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QemuNodeIdleState {
    /// Current logical picosecond coordinate observed for the node.
    pub current_icount: Icount,
    /// The next logical picosecond deadline that can wake the idle node.
    pub next_deadline: Option<Icount>,
}

/// Plugin logical-time calibration observed at one coherent shared-memory boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QemuLogicalTimeCalibration {
    /// Scheduler-visible logical picoseconds.
    pub logical_icount: u64,
    /// QEMU VMState-owned raw retired-instruction count.
    pub raw_icount: u64,
}

/// Plugin-validated native evidence for an actual virtual-timer callback.
pub type QemuVirtualTimerFireWitness = crucible_qemu_shmem::VirtualTimerFireWitness;

impl QemuLogicalTimeCalibration {
    /// Returns the picosecond bias over QEMU's scaled raw instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the scaled raw count overflows or
    /// exceeds logical time.
    pub fn offset(self) -> Result<u64, QemuNodeChannelError> {
        let raw_picoseconds = self
            .raw_icount
            .checked_mul(crucible_engine::SIM_TICKS_PER_INSTRUCTION)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "read logical-time calibration",
                    format!("raw icount {} overflows picoseconds", self.raw_icount),
                )
            })?;
        self.logical_icount
            .checked_sub(raw_picoseconds)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "read logical-time calibration",
                    format!(
                        "scaled raw icount {raw_picoseconds} is ahead of logical picoseconds {}",
                        self.logical_icount
                    ),
                )
            })
    }
}

/// The one QEMU child process owned by a [`QemuNode`].
#[derive(Debug)]
pub struct QemuNodeChild {
    child: source_child::OwnedNodeChild,
    reaped: bool,
    #[cfg(target_os = "linux")]
    ram_source: Option<crate::ram_source::QemuRamSourceService>,
    #[cfg(target_os = "linux")]
    ram_source_start: Option<crate::ram_source::SourceInput>,
    #[cfg(target_os = "linux")]
    launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    #[cfg(target_os = "linux")]
    original_plugin_startup: Option<crate::spawn::OriginalPluginStartup>,
    #[cfg(target_os = "linux")]
    preexec_setup: Option<crate::spawn::preexec_setup::PreparedPreexecSetup>,
    #[cfg(target_os = "linux")]
    checkpoint_original: Option<exact_snapshot::capture_original::CheckpointOriginal>,
}

/// Bounded deadline for reaping a force-killed child in [`QemuNodeChild::drop`].
///
/// A wedged QEMU (for example blocked in uninterruptible kernel sleep on a stuck
/// host ioctl) can outlive a `SIGKILL` until the kernel operation completes, so
/// the destructor bounds its reap to this deadline and abandons the process
/// rather than blocking the dropping thread forever.
const DROP_REAP_DEADLINE: Duration = Duration::from_secs(5);

/// The three logical channel roles owned by one QEMU node.
///
/// The shared-memory role includes its futex and eventfd wake objects; this
/// bundle describes protocol planes rather than a count of kernel objects.
pub struct QemuNodeChannels {
    plugin_control: Box<dyn QemuPluginIpcControlChannel>,
    shmem_hot_path: Box<dyn QemuShmemHotPathChannel>,
    qmp_machine_control: Box<dyn QemuQmpMachineControlChannel>,
    #[cfg(target_os = "linux")]
    original_native_binding: Option<crate::linux_attempt_host::OriginalNativeNodeBinding>,
}

impl QemuNodeChannels {
    /// Builds the three-plane role bundle for one QEMU child.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub(crate) fn new(
        plugin_control: impl QemuPluginIpcControlChannel + 'static,
        shmem_hot_path: impl QemuShmemHotPathChannel + 'static,
        qmp_machine_control: impl QemuQmpMachineControlChannel + 'static,
    ) -> Self {
        Self::new_with_original_binding(
            plugin_control,
            shmem_hot_path,
            qmp_machine_control,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    // The completed factory consumes the move-only witness before exposing
    // the Node. There is no attachment operation for an existing channel.
    pub(crate) fn new_with_original_binding(
        plugin_control: impl QemuPluginIpcControlChannel + 'static,
        shmem_hot_path: impl QemuShmemHotPathChannel + 'static,
        qmp_machine_control: impl QemuQmpMachineControlChannel + 'static,
        #[cfg(target_os = "linux")] original_native_binding: Option<
            crate::linux_attempt_host::OriginalNativeNodeBinding,
        >,
    ) -> Self {
        Self {
            plugin_control: Box::new(plugin_control),
            shmem_hot_path: Box::new(shmem_hot_path),
            qmp_machine_control: Box::new(qmp_machine_control),
            #[cfg(target_os = "linux")]
            original_native_binding,
        }
    }

    /// Returns the fixed roles carried by this channel bundle.
    #[must_use]
    pub const fn roles(&self) -> [QemuNodeChannelPlane; 3] {
        [
            QemuNodeChannelPlane::PluginIpcControl,
            QemuNodeChannelPlane::ShmemHotPath,
            QemuNodeChannelPlane::QmpMachineControl,
        ]
    }
}

/// Reader for QEMU's output-only per-node console stream.
struct QemuConsoleObservation {
    node: NodeId,
    spool: QemuConsoleObservationSpool,
}

/// Host-side wrapper exposing one QEMU child as a synchronous scheduler node.
pub struct QemuNode {
    child: QemuNodeProcessControl,
    channels: QemuNodeChannels,
    #[cfg(target_os = "linux")]
    checkpoint_cancellation: Option<std::os::fd::OwnedFd>,
    #[cfg(target_os = "linux")]
    hot_fork_private_ring_stage: Option<QemuHotForkPrivateRingStage>,
    #[cfg(target_os = "linux")]
    hot_fork_child_diagnostic_stage: Option<QemuHotForkChildDiagnosticStage>,
    #[cfg(target_os = "linux")]
    hot_fork_child_qmp_stage: Option<QemuHotForkChildQmpStage>,
    #[cfg(target_os = "linux")]
    hot_fork_child_console_stage: Option<QemuHotForkChildConsoleStage>,
    #[cfg(target_os = "linux")]
    hot_fork_child_process_contract_stage: Option<QemuHotForkChildProcessContractStage>,
    #[cfg(target_os = "linux")]
    hot_fork_child_files_stage: Option<QemuHotForkChildFilesStage>,
    #[cfg(target_os = "linux")]
    hot_fork_plugin_endpoint_stage: Option<QemuHotForkPluginEndpointStage>,
    #[cfg(target_os = "linux")]
    hot_fork_ram_stage: Option<hot_fork_ram_stage::RamAllocation<QemuHotForkRamStage>>,
    #[cfg(target_os = "linux")]
    hot_fork_ram_continuation:
        Option<hot_fork_ram_stage::RamAllocation<QemuHotForkRamContinuation>>,
    #[cfg(any(test, feature = "test-support"))]
    block_completion_observer: Option<std::sync::Arc<dyn crate::QemuTestBlockCompletionObserver>>,
    #[cfg(target_os = "linux")]
    _hot_fork_scheduler_authority: Option<QemuHotForkInstalledNodeAuthority>,
    lifecycle_state: QemuNodeLifecycleState,
    shutdown_policy: QemuShutdownPolicy,
    child_shutdown: shutdown_continuation::ChildShutdown,
    async_policy: QemuAsyncDriverPolicy,
    crash_detector: QemuCrashDetector,
    host_io_runtime: Box<dyn QemuHostIoRuntime>,
    last_observed_time: VirtualTime,
    last_step_ceiling: Option<Icount>,
    last_step_final_state: Option<QemuNodeIdleState>,
    last_step_inbound_frames_consumed: usize,
    // Console polling proves availability only at the scheduler-requested boundary.
    console_observation_boundary: VirtualTime,
    gdbstub: Option<QemuGdbstubChannelConfig>,
    pending_preemption: Option<crucible_engine::PreemptionDecision>,
    bounded_scheduler_preemption: Option<crate::BoundedSchedulerPreemptionEvidenceClaim>,
    selectable_resume_pending: bool,
    network_output_resume_pending: bool,
    // A fork child inherits the stopped template until its first ceiling is published.
    hot_fork_resume_pending: bool,
    pending_network_outputs: Vec<QemuNodeEmittedFrame>,
    pending_priming_observations: Vec<ObservableEvent>,
    next_network_output_sequence: u64,
    console_observation: Option<QemuConsoleObservation>,
    fault_capabilities: Vec<FaultCapabilityRowV1>,
    ready_markers: std::collections::BTreeSet<crucible_engine::model::FaultObjectId>,
    exact_fault_manifests: Option<crate::fault_capability::QemuExactFaultManifests>,
    next_fault_command_sequence: u64,
    setup_fault_command_sequence_floor: u64,
    next_fault_event_sequence: u64,
    fault_event_terminal_failure: Option<String>,
    // A command can change controller or RAM state without advancing icount.
    fault_fingerprint_invalidated: bool,
    #[cfg(target_os = "linux")]
    _launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    // Retain the reset original through the other node-owned resources.
    #[cfg(any(test, feature = "test-support", feature = "private-measurement-domain"))]
    reset_resume_pending: Option<guarded_reset::ResetResumeTransition>,
    // Release the slot witness only after every channel, runtime, staged owner
    // and reset keeper has finished destruction. Channel closure alone cannot
    // permit the external host to retire or reuse this native generation.
    #[cfg(target_os = "linux")]
    original_native_binding: Option<crate::linux_attempt_host::OriginalNativeNodeBinding>,
}

impl QemuNode {
    /// Activates the dormant guest-introspection bootstrap after a non-canonical fork.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the bounded QMP activation command fails.
    pub fn activate_debug_guest(&mut self) -> Result<(), QemuNodeError> {
        self.channels
            .qmp_machine_control
            .activate_debug_guest()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    /// Sends one request to this VM's debug guest agent.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory request path is
    /// unavailable, malformed, or full.
    pub fn send_guest_introspection(
        &mut self,
        record: GuestIntrospectionRecord,
    ) -> Result<(), QemuNodeError> {
        self.channels
            .shmem_hot_path
            .send_guest_introspection(record)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Receives one currently available response from this VM's debug guest agent.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory response path is
    /// unavailable or malformed.
    pub fn receive_guest_introspection(
        &mut self,
    ) -> Result<Option<GuestIntrospectionRecord>, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .receive_guest_introspection()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Binds an explicit scripted host-I/O fixture to its configured World.
    ///
    /// This method is available only to test support. It creates no native
    /// Source, owner or dispatch authority and refuses ordinary QEMU runtimes.
    ///
    /// # Errors
    ///
    /// Refuses unsupported runtimes, foreign nodes or unrepresented queues.
    #[cfg(any(test, feature = "test-support"))]
    pub fn bind_scripted_io_inventory_for_test(
        &mut self,
        world: &crucible_engine::model::World,
        node: &NodeId,
    ) -> Result<(), BackendError> {
        self.host_io_runtime
            .bind_scripted_io_inventory_for_test(world, node)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn observe_scripted_io_inventory_for_test(
        &self,
        node: &NodeId,
    ) -> Result<crucible_engine::BackendIoInventory, BackendError> {
        self.host_io_runtime.observe_scripted_io_inventory_for_test(
            node,
            crucible_engine::NodeCounter {
                ticks: self.last_observed_time.ticks,
            },
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn validate_scripted_run_admission_for_test(
        &self,
        admission: &crucible_engine::PreparedRunAdmission,
    ) -> Result<(), BackendError> {
        self.host_io_runtime
            .validate_scripted_run_admission_for_test(admission)
    }

    /// Builds a QEMU scheduler node from one owned child handle and its channels.
    #[must_use]
    pub fn new(
        child: QemuNodeChild,
        channels: QemuNodeChannels,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
        host_io_runtime: impl QemuHostIoRuntime + 'static,
        initial_fault_command_sequence: u64,
    ) -> Self {
        Self::new_with_boxed_runtime(
            child,
            channels,
            shutdown_policy,
            async_policy,
            crash_detector,
            Box::new(host_io_runtime),
            initial_fault_command_sequence,
        )
    }

    pub(crate) fn new_with_boxed_runtime(
        child: QemuNodeChild,
        channels: QemuNodeChannels,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
        host_io_runtime: Box<dyn QemuHostIoRuntime>,
        initial_fault_command_sequence: u64,
    ) -> Self {
        #[cfg(target_os = "linux")]
        let launch_cleanup = child.launch_cleanup.clone();
        #[cfg(target_os = "linux")]
        let (channels, original_native_binding) = {
            let mut channels = channels;
            let binding = channels.original_native_binding.take();
            (channels, binding)
        };
        Self {
            child: QemuNodeProcessControl::Direct(child),
            channels,
            #[cfg(target_os = "linux")]
            checkpoint_cancellation: None,
            #[cfg(target_os = "linux")]
            hot_fork_private_ring_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_child_diagnostic_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_child_qmp_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_child_console_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_child_process_contract_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_child_files_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_plugin_endpoint_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_ram_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_ram_continuation: None,
            #[cfg(any(test, feature = "test-support"))]
            block_completion_observer: None,
            #[cfg(target_os = "linux")]
            _hot_fork_scheduler_authority: None,
            lifecycle_state: QemuNodeLifecycleState::Running,
            shutdown_policy,
            child_shutdown: shutdown_continuation::ChildShutdown::new(),
            async_policy,
            crash_detector,
            host_io_runtime,
            last_observed_time: VirtualTime::default(),
            last_step_ceiling: None,
            last_step_final_state: None,
            last_step_inbound_frames_consumed: 0,
            console_observation_boundary: VirtualTime::default(),
            gdbstub: None,
            pending_preemption: None,
            bounded_scheduler_preemption: None,
            selectable_resume_pending: false,
            #[cfg(any(test, feature = "test-support", feature = "private-measurement-domain"))]
            reset_resume_pending: None,
            network_output_resume_pending: false,
            hot_fork_resume_pending: false,
            pending_network_outputs: Vec::new(),
            pending_priming_observations: Vec::new(),
            next_network_output_sequence: 0,
            console_observation: None,
            fault_capabilities: Vec::new(),
            ready_markers: std::collections::BTreeSet::new(),
            exact_fault_manifests: None,
            next_fault_command_sequence: initial_fault_command_sequence,
            setup_fault_command_sequence_floor: initial_fault_command_sequence,
            next_fault_event_sequence: 1,
            fault_event_terminal_failure: None,
            fault_fingerprint_invalidated: false,
            #[cfg(target_os = "linux")]
            _launch_cleanup: launch_cleanup,
            #[cfg(target_os = "linux")]
            original_native_binding,
        }
    }

    /// Enables one host-only bounded preemption sequence for this node.
    ///
    /// The sequence is consumed by the node's next published scheduler quantum.
    /// Its pidfd-authenticated report is written to `evidence` and never enters
    /// the deterministic guest event stream.
    pub fn enable_bounded_scheduler_preemption(
        &mut self,
        evidence: crate::BoundedSchedulerPreemptionEvidenceClaim,
    ) {
        self.bounded_scheduler_preemption = Some(evidence);
    }

    /// Installs the capability rows negotiated during plugin setup.
    #[must_use]
    pub fn with_fault_capabilities(
        mut self,
        fault_capabilities: Vec<FaultCapabilityRowV1>,
    ) -> Self {
        self.fault_capabilities = fault_capabilities;
        self
    }

    /// Returns the exact QEMU fault capabilities admitted for this node.
    #[must_use]
    pub fn fault_capabilities(&self) -> &[FaultCapabilityRowV1] {
        &self.fault_capabilities
    }

    /// Installs the launch-bound guest ready-marker manifest.
    #[must_use]
    pub fn with_ready_markers(
        mut self,
        ready_markers: std::collections::BTreeSet<crucible_engine::model::FaultObjectId>,
    ) -> Self {
        self.ready_markers = ready_markers;
        self
    }

    /// Returns the exact launch-bound guest ready-marker manifest.
    #[must_use]
    pub const fn ready_markers(
        &self,
    ) -> &std::collections::BTreeSet<crucible_engine::model::FaultObjectId> {
        &self.ready_markers
    }

    /// Installs the exact public target manifests accepted during setup.
    #[must_use]
    pub(crate) fn with_exact_fault_manifests(
        mut self,
        manifests: Option<crate::fault_capability::QemuExactFaultManifests>,
    ) -> Self {
        self.exact_fault_manifests = manifests;
        self
    }

    /// Borrows the exact register schema authenticated during native setup.
    pub(crate) fn register_capability_manifest(
        &self,
    ) -> Option<&crucible_qemu_shmem::FaultRegisterCapabilityManifestV1> {
        self.exact_fault_manifests
            .as_ref()
            .map(|manifests| &manifests.register)
    }

    /// Reserves retained manifest copies within this node's admitted service owner.
    #[cfg(target_os = "linux")]
    pub(crate) fn reserve_fault_manifest_metadata(
        &self,
        bytes: u64,
    ) -> Result<crate::QemuFaultManifestMetadataLease, crate::QemuAsyncDriverRuntimeError> {
        self.host_io_runtime.reserve_fault_manifest_metadata(bytes)
    }

    /// Reserves the next strictly increasing host command sequence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the per-process sequence space is
    /// exhausted. A reserved value is never reused, including after rejection.
    pub fn reserve_fault_command_sequence(&mut self) -> Result<u64, QemuNodeError> {
        let sequence = self.next_fault_command_sequence;
        self.next_fault_command_sequence = sequence.checked_add(1).ok_or_else(|| {
            QemuNodeError::fault_command("fault command sequence space is exhausted")
        })?;
        Ok(sequence)
    }

    /// Returns the next fault-command sequence without reserving it.
    #[must_use]
    pub const fn next_fault_command_sequence(&self) -> u64 {
        self.next_fault_command_sequence
    }

    /// Returns the next required per-node fault-event sequence.
    #[must_use]
    pub const fn next_fault_event_sequence(&self) -> u64 {
        self.next_fault_event_sequence
    }

    /// Restores the next fault-command sequence paired with a VM checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when `sequence` would reuse setup-time or
    /// already-reserved command identities.
    pub fn restore_fault_command_sequence(&mut self, sequence: u64) -> Result<(), QemuNodeError> {
        self.validate_fault_command_sequence_restore(sequence)?;
        self.next_fault_command_sequence = sequence;
        Ok(())
    }

    /// Validates a restored command cursor without mutating the live node.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the cursor would reuse setup identities.
    pub(crate) fn validate_fault_command_sequence_restore(
        &self,
        sequence: u64,
    ) -> Result<(), QemuNodeError> {
        if sequence < self.setup_fault_command_sequence_floor {
            return Err(QemuNodeError::fault_command(
                "restored fault command sequence reuses setup admission identity",
            ));
        }
        Ok(())
    }

    /// Restores the next event sequence paired with an exact QEMU checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when `sequence` is zero.
    pub fn restore_fault_event_sequence(&mut self, sequence: u64) -> Result<(), QemuNodeError> {
        self.validate_fault_event_sequence_restore(sequence)?;
        self.next_fault_event_sequence = sequence;
        self.fault_event_terminal_failure = None;
        Ok(())
    }

    /// Validates a restored event cursor without mutating the live node.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the cursor is zero.
    pub(crate) fn validate_fault_event_sequence_restore(
        &self,
        sequence: u64,
    ) -> Result<(), QemuNodeError> {
        if sequence == 0 {
            return Err(QemuNodeError::fault_command(
                "restored fault event sequence is zero",
            ));
        }
        Ok(())
    }

    /// Publishes one fault command through this node's mapped data plane.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the command transport rejects the
    /// envelope or payload.
    pub fn enqueue_fault_command(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        // This is identity-only old custody settlement. It precedes every
        // command publication, including batched and retrying callers.
        self.host_io_runtime
            .settle_pending_control_action()
            .map_err(|source| {
                QemuNodeChannelError::new("settle previous control action", source.to_string())
            })?;
        self.channels
            .shmem_hot_path
            .enqueue_fault_command(header, payload)?;
        // Publication precedes result delivery. An uncertain result must not
        // make the previously published same-icount sample usable again.
        self.fault_fingerprint_invalidated = true;
        Ok(())
    }

    /// Removes one completed fault result from this node's mapped data plane.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the result transport is corrupt.
    pub fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError> {
        self.channels.shmem_hot_path.dequeue_fault_result()
    }

    /// Applies one admitted command using caller-reserved result storage and
    /// an authored occurrence-event staging limit.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] under the same conditions as
    /// Returns [`QemuNodeError`] for an absent capability, stale result,
    /// coordinate mismatch, invalid result, bounded host-liveness timeout,
    /// guest progress, or insufficient caller-owned result or event storage.
    pub(crate) fn apply_fault_command_at_current_boundary_with_limits(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        result_buffer: Vec<u8>,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuNodeError> {
        self.apply_fault_command_at_current_boundary_with_storage(
            header,
            payload,
            Some(result_buffer),
            0,
            maximum_event_records,
        )
    }

    pub(crate) fn set_fault_event_staging_limit(
        &mut self,
        maximum_local_records: usize,
        canonical_current_offset: usize,
        configured_event_records: usize,
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .set_fault_event_staging_limit(
                maximum_local_records,
                canonical_current_offset,
                configured_event_records,
            )
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    pub(crate) fn staged_fault_event_count(&self) -> usize {
        self.host_io_runtime.staged_fault_event_count()
    }

    pub(crate) fn apply_fault_preparation_at_current_boundary(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        maximum_payload_bytes: usize,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuNodeError> {
        if header.command_flags & FAULT_COMMAND_FLAG_PREPARE_ONLY == 0 {
            return Err(QemuNodeError::fault_command(
                "dynamic result sizing is restricted to non-mutating PREPARE commands",
            ));
        }
        self.apply_fault_command_at_current_boundary_with_storage(
            header,
            payload,
            None,
            maximum_payload_bytes,
            maximum_event_records,
        )
    }

    fn apply_fault_command_at_current_boundary_with_storage(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        result_buffer: Option<Vec<u8>>,
        maximum_preparation_payload_bytes: usize,
        maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuNodeError> {
        let before = self.current_icount()?;
        if header.target_icount != before.retired {
            return Err(QemuNodeError::fault_command(format!(
                "command sequence {} targets icount {} at current boundary {}",
                header.command_sequence, header.target_icount, before.retired
            )));
        }
        let payload_len = u32::try_from(payload.len()).map_err(|_source| {
            QemuNodeError::fault_command(format!(
                "command sequence {} payload length {} exceeds the ABI integer range",
                header.command_sequence,
                payload.len()
            ))
        })?;
        let admitted = self.fault_capabilities.iter().any(|row| {
            row.command_kind == header.command_kind
                && row.semantic_version == header.semantic_version
                && row.supports_phase(header.phase)
                && payload_len <= row.maximum_payload_bytes
        });
        if !admitted {
            return Err(QemuNodeError::fault_command(format!(
                "command sequence {} kind {:?} version {} phase {:?} payload {} was not admitted during setup",
                header.command_sequence,
                header.command_kind,
                header.semantic_version,
                header.phase,
                payload.len()
            )));
        }
        if let Some(stale) = self.dequeue_fault_result().map_err(|source| {
            QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
        })? {
            return Err(QemuNodeError::fault_command(format!(
                "result transport contained stale result before sequence {}: {stale:?}",
                header.command_sequence
            )));
        }
        self.enqueue_fault_command(header.clone(), payload)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        let result = match result_buffer {
            Some(result_buffer) => self.host_io_runtime.await_fault_result(
                self.async_policy.advance_completion_timeout,
                result_buffer,
                maximum_event_records,
            ),
            None => self.host_io_runtime.await_fault_preparation_result(
                self.async_policy.advance_completion_timeout,
                maximum_preparation_payload_bytes,
                maximum_event_records,
            ),
        }
        .map_err(|source| {
            if let Some((requested, configured)) = source.fault_result_storage_coordinates() {
                QemuNodeError::FaultResultStorage {
                    requested: u64::from(requested),
                    configured: u64::from(configured),
                }
            } else if let Some((current, requested, configured)) =
                source.fault_event_storage_coordinates()
            {
                QemuNodeError::FaultEventStorage {
                    current,
                    requested,
                    configured,
                }
            } else {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            }
        })?;
        let after = self.current_icount()?;
        if after != before {
            return Err(QemuNodeError::fault_command(format!(
                "command sequence {} advanced guest icount from {} to {}",
                header.command_sequence, before.retired, after.retired
            )));
        }
        let DequeuedFaultResult::Valid {
            header: result_header,
            ..
        } = &result
        else {
            return Err(QemuNodeError::fault_command(format!(
                "command sequence {} produced an ABI-invalid result: {result:?}",
                header.command_sequence
            )));
        };
        if result_header.command_sequence != header.command_sequence
            || result_header.command_kind != header.command_kind as u16
            || result_header.semantic_version != header.semantic_version
            || result_header.phase != header.phase
            || result_header.observed_icount != before.retired
            || (result_header.status == FaultResultStatus::Applied
                && result_header.applied_icount != before.retired)
        {
            return Err(QemuNodeError::fault_command(format!(
                "command sequence {} received mismatched result {result_header:?}",
                header.command_sequence
            )));
        }
        Ok(result)
    }

    /// Returns this node with staged console bytes exposed as observations.
    pub(crate) fn with_console_observation(
        mut self,
        node: NodeId,
        spool: QemuConsoleObservationSpool,
    ) -> Self {
        self.set_console_observation(node, spool);
        self
    }

    pub(crate) fn set_console_observation(
        &mut self,
        node: NodeId,
        spool: QemuConsoleObservationSpool,
    ) {
        self.console_observation = Some(QemuConsoleObservation { node, spool });
    }

    /// Retains setup-time observations for the first authoritative scheduler drain.
    #[must_use]
    pub(crate) fn with_priming_observable_events(
        mut self,
        events: Vec<ObservableEvent>,
        ready_boundary: VirtualTime,
    ) -> Self {
        self.set_priming_observable_events(events, ready_boundary);
        self
    }

    pub(crate) fn set_priming_observable_events(
        &mut self,
        mut events: Vec<ObservableEvent>,
        ready_boundary: VirtualTime,
    ) {
        for event in &mut events {
            event.set_observation_time(ready_boundary);
        }
        self.pending_priming_observations = events;
    }

    fn drain_scheduler_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeError> {
        let mut boundary_events = self
            .channels
            .shmem_hot_path
            .drain_observable_events()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        let mut events = std::mem::take(&mut self.pending_priming_observations);
        events.append(&mut boundary_events);
        Ok(events)
    }

    /// Attaches a configured mediated gdbstub channel to this node wrapper.
    #[must_use]
    pub fn with_gdbstub(mut self, gdbstub: QemuGdbstubChannelConfig) -> Self {
        self.set_gdbstub(gdbstub);
        self
    }

    pub(crate) fn set_gdbstub(&mut self, gdbstub: QemuGdbstubChannelConfig) {
        self.gdbstub = Some(gdbstub);
    }

    /// Returns the configured gdbstub channel, when this node supports one.
    #[must_use]
    pub const fn gdbstub_channel(&self) -> Option<&QemuGdbstubChannelConfig> {
        self.gdbstub.as_ref()
    }

    /// Returns the wrapper's current lifecycle state.
    #[must_use]
    pub const fn lifecycle_state(&self) -> QemuNodeLifecycleState {
        self.lifecycle_state
    }

    /// Returns whether the owned child has been reaped by this wrapper.
    #[must_use]
    pub fn child_reaped(&self) -> bool {
        self.child.reaped()
    }

    /// Returns the operating-system process identifier of this QEMU generation.
    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.child.process_id()
    }

    /// Returns the complete Linux identity of this QEMU process generation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when `/proc` cannot be read or no longer names
    /// this child.
    #[cfg(target_os = "linux")]
    pub fn process_identity(&self) -> Result<QemuProcessIdentity, QemuNodeError> {
        linux_process_identity(self.process_id())?.ok_or_else(|| {
            QemuNodeError::fault_command(format!(
                "QEMU child PID {} has no live process identity",
                self.process_id()
            ))
        })
    }

    /// Queries QEMU's registered fork-child runtime without mutating it.
    ///
    /// The response binds callback registration to the complete plugin
    /// resource manifest and current process generation. It does not
    /// initialize a child or acknowledge hot-fork proof bit 8.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    pub fn query_hot_fork_child_runtime(
        &mut self,
    ) -> Result<crate::QmpHotForkChildRuntimeState, QemuNodeChannelError> {
        self.channels
            .qmp_machine_control
            .query_hot_fork_child_runtime()
    }

    /// Starts or advances QEMU's retained hot-fork template transaction.
    ///
    /// This does not fork a process. A blocked result proves that QEMU acquired
    /// and then rolled back every currently implemented subsystem barrier after
    /// the complete readiness bitmap remained unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot acquire, observe, or
    /// roll back the transaction or violates the closed response contract.
    pub fn prepare_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        if self.reset_resume_is_pending() {
            return Err(QemuNodeChannelError::new(
                "prepare hot-fork template",
                "reset continuation has not resumed",
            ));
        }
        self.channels
            .qmp_machine_control
            .prepare_hot_fork_template(block_snapshot_bindings)
    }

    /// Acquires all retained template barriers before child-resource staging.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when bounded acquisition fails or
    /// QEMU changes the retained transaction generation.
    pub fn prepare_hot_fork_template_barriers(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        if self.reset_resume_is_pending() {
            return Err(QemuNodeChannelError::new(
                "prepare hot-fork template",
                "reset continuation has not resumed",
            ));
        }
        self.channels
            .qmp_machine_control
            .prepare_hot_fork_template_barriers(block_snapshot_bindings)
    }

    /// Queries QEMU's retained hot-fork template transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    pub fn query_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.channels.qmp_machine_control.query_hot_fork_template()
    }

    /// Re-adopts this reconstructed child as a fresh template source.
    ///
    /// The operation consumes the inherited reconstruction records. It does
    /// not prepare a descendant template or stage any resources.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the child is incomplete, the VM is
    /// outside the exact paused boundary, or QEMU rejects its parent rebinding.
    pub fn adopt_hot_fork_child_as_template_source(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.channels
            .qmp_machine_control
            .adopt_hot_fork_child_as_template_source()
    }

    /// Aborts QEMU's retained hot-fork template transaction.
    ///
    /// A draining response leaves restoration pending. The owner must keep the
    /// source stopped and retry until `rollback_complete()` is true.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot roll back every
    /// acquired subsystem barrier or violates the closed abort response.
    pub fn abort_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.channels.qmp_machine_control.abort_hot_fork_template()
    }

    /// Returns numeric identity components after authenticating a preowned executable path.
    ///
    /// The successful path uses fixed stack storage, allowing lifecycle code to
    /// populate preallocated durable ownership after launch without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when `/proc` cannot be read, its bounded stat
    /// representation is malformed, or the executable inode does not match.
    #[cfg(target_os = "linux")]
    pub fn process_identity_components(
        &self,
        expected_executable: &Path,
    ) -> Result<(u32, u64), QemuNodeError> {
        linux_process_identity_components(self.process_id(), expected_executable)
    }

    /// Waits for the exact child to complete a terminal lifecycle fault.
    ///
    /// The authenticated fault event is only a declaration that QEMU has
    /// requested termination. This method independently reaps the owned child
    /// and requires its process status to agree with the transition-specific
    /// status before the host may classify the exit as intentional.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the child does not exit before the
    /// bounded supervision deadline, waitpid fails, the process is terminated
    /// by a signal, or its exit code differs from `expected_exit_code`.
    pub fn await_intended_lifecycle_exit(
        &mut self,
        expected_exit_code: i32,
        action: crucible_engine::ContentHash,
    ) -> Result<i32, QemuNodeError> {
        let operational_error = |source| {
            QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(
                crate::QemuAsyncDriverRuntimeError::operational_supervision(
                    "wait for intended lifecycle exit",
                    source,
                ),
            ))
        };
        let guard = self
            .host_io_runtime
            .host_operation_supervisor()
            .map(|supervisor| {
                supervisor
                    .begin(crucible_host_resources::host_supervision::HostOperationClass::Cleanup)
            })
            .transpose()
            .map_err(operational_error)?;
        let fixture_deadline = guard
            .is_none()
            .then(|| HostSupervisionDeadline::start(self.async_policy.advance_completion_timeout));
        loop {
            if let Some(guard) = &guard
                && let Err(source) = guard.wait_slice()
            {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                return Err(operational_error(source));
            }
            let status = match self.child.try_wait_natural_exit() {
                Ok(status) => status,
                Err(source) => {
                    self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                    return Err(QemuNodeError::fault_command(format!(
                        "wait for intended lifecycle exit {}: {source}",
                        action.to_hex()
                    )));
                }
            };
            match status {
                Some(status) => {
                    let Some(actual) = status.code() else {
                        self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                        return Err(QemuNodeError::fault_command(format!(
                            "intended lifecycle exit {} terminated without an exit code: {status}",
                            action.to_hex()
                        )));
                    };
                    if actual != expected_exit_code {
                        self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                        return Err(QemuNodeError::fault_command(format!(
                            "intended lifecycle exit {} returned {actual}, expected {expected_exit_code}",
                            action.to_hex()
                        )));
                    }
                    if let Some(guard) = &guard {
                        guard.complete().map_err(operational_error)?;
                    }
                    self.lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
                    return Ok(actual);
                }
                None if guard.is_some()
                    || fixture_deadline
                        .as_ref()
                        .is_some_and(|deadline| deadline.has_time_remaining()) =>
                {
                    if let Some(guard) = &guard {
                        guard.wait_for_change().map_err(operational_error)?;
                    } else {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                None => {
                    self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                    return Err(QemuNodeError::fault_command(format!(
                        "intended lifecycle exit {} did not complete within {:?}",
                        action.to_hex(),
                        self.async_policy.advance_completion_timeout
                    )));
                }
            }
        }
    }

    /// Instructs patched QEMU to complete a previously authenticated terminal
    /// lifecycle decision.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the node is not running or QEMU cannot
    /// acknowledge the terminal completion command. A failed acknowledgement
    /// quarantines the node because the process outcome is then ambiguous.
    pub fn complete_terminal_lifecycle_exit(
        &mut self,
        action: crucible_engine::ContentHash,
        evidence: crucible_engine::ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeError> {
        if self.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(QemuNodeError::fault_command(
                "terminal lifecycle completion requires a running node",
            ));
        }
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .complete_terminal_lifecycle_exit(action, evidence, process_generation)
        {
            self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
            return Err(QemuNodeError::from_channel(
                QemuNodeChannelPlane::QmpMachineControl,
                source,
            ));
        }
        Ok(())
    }

    /// Returns the fixed channel roles owned by this node.
    #[must_use]
    pub const fn channel_roles(&self) -> [QemuNodeChannelPlane; 3] {
        self.channels.roles()
    }

    /// Reads the current retired-instruction count through shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory hot path cannot be read.
    pub fn current_icount(&mut self) -> Result<Icount, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .current_icount()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Synchronizes the scheduler-facing time mirror after launch-time priming.
    ///
    /// Node factories use this once after the boot barrier has been released
    /// and before the node is returned to an authoritative scheduler.
    pub(crate) fn synchronize_observed_time(&mut self) -> Result<VirtualTime, QemuNodeError> {
        let current = self.current_icount()?;
        self.last_observed_time = VirtualTime {
            ticks: current.retired,
        };
        Ok(self.last_observed_time)
    }

    /// Retains frames emitted while a fresh guest crossed the boot barrier.
    ///
    /// The launch-time hot path owns and drains the outbound ring before the
    /// scheduler node maps it. Fresh-boot factories transfer that drained batch
    /// here so the authoritative scheduler observes it at the first boundary.
    /// Restore factories intentionally omit the transfer because the restored
    /// checkpoint supersedes the primed machine state.
    pub(crate) fn retain_priming_network_outputs(
        &mut self,
        outputs: Vec<QemuNodeEmittedFrame>,
    ) -> Result<(), QemuNodeError> {
        self.observe_network_output_batch(&outputs)?;
        self.pending_network_outputs.extend(outputs);
        Ok(())
    }

    fn observe_network_output_batch(
        &mut self,
        outputs: &[QemuNodeEmittedFrame],
    ) -> Result<(), QemuNodeError> {
        let mut next_sequence = self.next_network_output_sequence;
        for output in outputs {
            if output.sequence != next_sequence {
                return Err(QemuNodeError::NetworkOutputSequence {
                    expected: next_sequence,
                    observed: output.sequence,
                });
            }
            next_sequence = next_sequence.checked_add(1).ok_or({
                QemuNodeError::NetworkOutputSequence {
                    expected: next_sequence,
                    observed: output.sequence,
                }
            })?;
        }
        self.next_network_output_sequence = next_sequence;
        Ok(())
    }

    fn observe_network_output_sequence(
        &mut self,
        output: &QemuNodeEmittedFrame,
    ) -> Result<(), QemuNodeError> {
        if output.sequence != self.next_network_output_sequence {
            return Err(QemuNodeError::NetworkOutputSequence {
                expected: self.next_network_output_sequence,
                observed: output.sequence,
            });
        }
        self.next_network_output_sequence = self
            .next_network_output_sequence
            .checked_add(1)
            .ok_or(QemuNodeError::NetworkOutputSequence {
                expected: self.next_network_output_sequence,
                observed: output.sequence,
            })?;
        Ok(())
    }

    /// Advances the child to an instruction-count ceiling through shared memory.
    ///
    /// This drives a single bounded quantum (one publish/await/finish). It is
    /// therefore not, on its own, an idle driver: when the guest parks idle
    /// before the ceiling it returns [`AdvanceOutcome::Paused`], and a caller that
    /// needs to advance an idle guest to a later boundary must re-issue the
    /// advance in a loop (raising the ceiling and re-waking the plugin) — the same
    /// caller-side re-issue loop the raw shared-memory hot path requires. The
    /// async driver's yields are no-ops for a standalone gate, so wrapping this
    /// call does not by itself advance an idle guest.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the bounded async driver, shared-memory hot
    /// path, or timeout shutdown escalation fails.
    pub fn advance_to_ceiling(&mut self, ceiling: Icount) -> Result<AdvanceOutcome, QemuNodeError> {
        if self.channels.shmem_hot_path.coverage_enabled() {
            return Err(QemuNodeError::CoverageEventLogRequired);
        }
        let report = self.advance_to_ceiling_report(ceiling)?;
        self.finish_advance_report(ceiling, report)
    }

    /// Advances until the next authenticated all-vCPU idle publication.
    ///
    /// `liveness_ceiling` bounds guest execution if no idle boundary appears.
    /// The advance still completes immediately at the first fresh idle
    /// publication, including when its timer deadline lies below the ceiling.
    /// [`AdvanceOutcome::ReachedHorizon`] therefore means that the liveness
    /// bound was reached before the requested idle boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when coverage requires an event log, the
    /// bounded async driver fails, or the shared-memory boundary cannot be
    /// authenticated.
    pub fn advance_to_next_idle(
        &mut self,
        liveness_ceiling: Icount,
    ) -> Result<AdvanceOutcome, QemuNodeError> {
        if self.channels.shmem_hot_path.coverage_enabled() {
            return Err(QemuNodeError::CoverageEventLogRequired);
        }
        let report = self.advance_to_ceiling_report_with_stop_condition(
            liveness_ceiling,
            crate::QemuQuantumStopCondition::NextAuthenticatedIdle,
        )?;
        self.finish_advance_report(liveness_ceiling, report)
    }

    /// Advances the child and appends every coverage observation to one event log.
    ///
    /// This is the required coverage-enabled execution path. The SPSC queue is
    /// drained only after QEMU publishes a completed quantum, then the complete
    /// FIFO batch is appended through [`EventLog::append_observable_events`]. No
    /// QEMU wrapper collection survives the call, so coverage cannot form a
    /// second persistent record parallel to the unified log.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the bounded quantum fails or the unified
    /// event log rejects the observational batch.
    pub fn advance_to_ceiling_with_event_log(
        &mut self,
        ceiling: Icount,
        event_log: &mut EventLog,
    ) -> Result<(AdvanceOutcome, SchedulerEventLogAppend), QemuNodeError> {
        let report = self.advance_to_ceiling_report(ceiling)?;
        let appended = self.drain_observable_events_into(event_log)?;
        let outcome = self.finish_advance_report(ceiling, report)?;
        Ok((outcome, appended))
    }

    /// Drains pending observable events into the run's unified event log.
    ///
    /// A campaign driver calls this at its modeled observation boundary before
    /// constructing canonical coverage evidence. The node remains paused and
    /// retains process ownership.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory drain or unified-log
    /// append fails.
    pub fn drain_observable_events_into(
        &mut self,
        event_log: &mut EventLog,
    ) -> Result<SchedulerEventLogAppend, QemuNodeError> {
        let events = self.drain_scheduler_observable_events()?;
        event_log
            .append_observable_events(events)
            .map_err(|source| QemuNodeError::CoverageEventLog {
                message: source.to_string(),
            })
    }

    /// Drains selectable requests retained at the current paused boundary.
    ///
    /// The result is still untrusted plugin output. A campaign driver must bind
    /// each request to its scenario declaration and make the semantic choice
    /// before any reply is delivered or another guest quantum begins.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory marker transport is
    /// malformed or carries a request after the completed boundary.
    pub fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<
        Vec<crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
        QemuNodeError,
    > {
        self.channels
            .shmem_hot_path
            .drain_pending_selectable_requests()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Enqueues one exact host-authorized selectable reply for the next quantum.
    ///
    /// QEMU remains stopped until the next bounded step publishes its scheduler
    /// ceiling. The step then resumes QEMU, so the reply and new ceiling are
    /// both visible before the resumed vCPU may execute.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QEMU cannot confirm the native paused
    /// state, the pending token is stale or malformed, the reply does not fit
    /// its guest reservation, shared-memory publication fails, or another
    /// selectable resume is already pending.
    pub fn enqueue_selectable_reply(
        &mut self,
        pending: &crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_qemu_protocol::SelectionReply,
    ) -> Result<(), QemuNodeError> {
        if self.selectable_resume_pending {
            return Err(QemuNodeError::from_channel(
                QemuNodeChannelPlane::ShmemHotPath,
                QemuNodeChannelError::new(
                    "enqueue selectable reply",
                    "one selectable resume is already pending",
                ),
            ));
        }
        self.channels
            .qmp_machine_control
            .stop_for_checkpoint()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })?;
        self.channels
            .shmem_hot_path
            .enqueue_selectable_reply(pending, reply)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        self.selectable_resume_pending = true;
        Ok(())
    }

    /// Returns a copy of the exact host-mirrored selectable catalog plan.
    #[must_use]
    pub fn selectable_catalog_plan(
        &self,
    ) -> Option<crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan> {
        self.channels
            .shmem_hot_path
            .selectable_catalog_plan()
            .cloned()
    }

    fn reset_resume_is_pending(&self) -> bool {
        #[cfg(any(test, feature = "test-support", feature = "private-measurement-domain"))]
        {
            self.reset_resume_pending.is_some()
        }
        #[cfg(not(any(test, feature = "test-support", feature = "private-measurement-domain")))]
        {
            false
        }
    }

    /// Reports whether no selectable reply awaits plugin consumption.
    #[must_use]
    pub fn selectable_reply_is_checkpoint_quiescent(&self) -> bool {
        !self.reset_resume_is_pending()
            && self
                .channels
                .shmem_hot_path
                .selectable_reply_is_checkpoint_quiescent()
    }

    /// Prepares the paused node's observable stream for authoritative execution.
    ///
    /// Restore setup and boot-barrier priming execute before checkpoint load
    /// establishes the canonical runtime. The ABI-versioned logical-time
    /// restore acknowledgement resets coverage producer and consumer novelty
    /// state while QEMU is paused; this final drain discards the remaining
    /// non-coverage setup observations before the node becomes authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory queue cannot be drained.
    pub fn prepare_authoritative_observation_stream(&mut self) -> Result<usize, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .drain_observable_events()
            .map(|events| events.len())
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    fn advance_to_ceiling_report(
        &mut self,
        ceiling: Icount,
    ) -> Result<crate::QemuAsyncNodeStepReport, QemuNodeError> {
        self.advance_to_ceiling_report_with_stop_condition(
            ceiling,
            crate::QemuQuantumStopCondition::Ceiling,
        )
    }

    fn advance_to_ceiling_report_with_stop_condition(
        &mut self,
        ceiling: Icount,
        stop_condition: crate::QemuQuantumStopCondition,
    ) -> Result<crate::QemuAsyncNodeStepReport, QemuNodeError> {
        self.shutdown_health()?;
        if self.reset_resume_is_pending() {
            return Err(QemuNodeError::checkpoint(
                "reset requires its original-bound idle and fresh capture",
            ));
        }
        let Some(evidence) = self.bounded_scheduler_preemption.take() else {
            return self.advance_to_ceiling_report_without_host_preemption(ceiling, stop_condition);
        };
        // `pidfd_open` starts from a numeric PID. Only a directly owned,
        // unreaped child proves that the PID cannot have been recycled before
        // the kernel turns it into a stable process handle.
        let process_id = match &self.child {
            QemuNodeProcessControl::Direct(child) if child.reaped() => {
                return Err(QemuNodeError::BoundedSchedulerPreemptionTarget {
                    target: QemuBoundedSchedulerPreemptionTargetError::AlreadyReaped,
                });
            }
            QemuNodeProcessControl::Direct(child) => child.process_id(),
            QemuNodeProcessControl::External(_control) => {
                return Err(QemuNodeError::BoundedSchedulerPreemptionTarget {
                    target: QemuBoundedSchedulerPreemptionTargetError::ExternallyOwned,
                });
            }
        };
        let mut adversary =
            crate::supervision::bounded_scheduler_preemption::BoundedSchedulerPreemption::start_if(
                true, process_id,
            )
            .map_err(QemuNodeError::from_bounded_scheduler_preemption)?;
        let mut pending_quantum_certified = false;
        let resume_stopped_boundary = self.selectable_resume_pending
            || self.network_output_resume_pending
            || self.hot_fork_resume_pending;
        let mut target = QemuNodeAsyncStepTarget {
            #[cfg(any(test, feature = "test-support"))]
            block_completion_observer: self.block_completion_observer.clone(),
            ram_registration: self.host_io_runtime.ram_control_registration().cloned(),
            #[cfg(target_os = "linux")]
            ram_continuation: self.hot_fork_ram_continuation.as_deref(),
            child: &mut self.child,
            channels: &mut self.channels,
            lifecycle_state: &mut self.lifecycle_state,
            shutdown_policy: self.shutdown_policy,
            child_shutdown: &mut self.child_shutdown,
            supervisor: self.host_io_runtime.host_operation_supervisor().cloned(),
            stop_condition,
        };
        let step = run_bounded_qemu_node_step_with_start_hook(
            &mut target,
            self.host_io_runtime.as_mut(),
            self.async_policy,
            &self.crash_detector,
            ExecutionHorizon { icount: ceiling },
            |target, pending| {
                if resume_stopped_boundary {
                    target
                        .channels
                        .qmp_machine_control
                        .resume_after_checkpoint()?;
                }
                pending_quantum_certified = crate::supervision::bounded_scheduler_preemption::BoundedSchedulerPreemption::certify_async_quantum_pending(
                    &mut adversary,
                    target,
                    pending,
                )
                .map_err(|source| {
                    QemuNodeChannelError::new(
                        "certify bounded scheduler preemption over pending quantum",
                        source.to_string(),
                    )
                })?;
                Ok(())
            },
        );
        let preemption = crate::supervision::bounded_scheduler_preemption::BoundedSchedulerPreemption::finish_if_present(
            &mut adversary,
        );
        let report = step.map_err(QemuNodeError::from_async_driver)?;
        let preemption = preemption.map_err(QemuNodeError::from_bounded_scheduler_preemption)?;
        let preemption = preemption.ok_or_else(|| {
            QemuNodeError::from_bounded_scheduler_preemption(
                crate::BoundedSchedulerPreemptionError::NotStarted,
            )
        })?;
        evidence
            .record(preemption, pending_quantum_certified)
            .map_err(|source| {
                QemuNodeError::bounded_scheduler_preemption_message(source.to_string())
            })?;
        if resume_stopped_boundary {
            self.selectable_resume_pending = false;
            self.network_output_resume_pending = false;
            self.hot_fork_resume_pending = false;
        }
        Ok(report)
    }

    fn advance_to_ceiling_report_without_host_preemption(
        &mut self,
        ceiling: Icount,
        stop_condition: crate::QemuQuantumStopCondition,
    ) -> Result<crate::QemuAsyncNodeStepReport, QemuNodeError> {
        let mut target = QemuNodeAsyncStepTarget {
            #[cfg(any(test, feature = "test-support"))]
            block_completion_observer: self.block_completion_observer.clone(),
            ram_registration: self.host_io_runtime.ram_control_registration().cloned(),
            #[cfg(target_os = "linux")]
            ram_continuation: self.hot_fork_ram_continuation.as_deref(),
            child: &mut self.child,
            channels: &mut self.channels,
            lifecycle_state: &mut self.lifecycle_state,
            shutdown_policy: self.shutdown_policy,
            child_shutdown: &mut self.child_shutdown,
            supervisor: self.host_io_runtime.host_operation_supervisor().cloned(),
            stop_condition,
        };
        let horizon = ExecutionHorizon { icount: ceiling };
        let resume_stopped_boundary = self.selectable_resume_pending
            || self.network_output_resume_pending
            || self.hot_fork_resume_pending;
        let report = if resume_stopped_boundary {
            run_bounded_qemu_node_step_with_start_hook(
                &mut target,
                self.host_io_runtime.as_mut(),
                self.async_policy,
                &self.crash_detector,
                horizon,
                |target, _pending| {
                    target
                        .channels
                        .qmp_machine_control
                        .resume_after_checkpoint()
                },
            )
        } else {
            run_bounded_qemu_node_step(
                &mut target,
                self.host_io_runtime.as_mut(),
                self.async_policy,
                &self.crash_detector,
                horizon,
            )
        }
        .map_err(QemuNodeError::from_async_driver)?;
        if resume_stopped_boundary {
            self.selectable_resume_pending = false;
            self.network_output_resume_pending = false;
            self.hot_fork_resume_pending = false;
        }
        Ok(report)
    }

    fn finish_advance_report(
        &mut self,
        ceiling: Icount,
        report: crate::QemuAsyncNodeStepReport,
    ) -> Result<AdvanceOutcome, QemuNodeError> {
        let output_boundary = network_output::exact_output_boundary(&report, ceiling)?;
        if output_boundary.is_some() {
            // The producer's native dispatch fence precedes this confirmation.
            // Every bounded advance path retains the stop until a later step
            // publishes its ceiling and explicitly resumes QEMU.
            self.channels
                .qmp_machine_control
                .stop_for_checkpoint()
                .map_err(|source| {
                    QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
                })?;
            self.network_output_resume_pending = true;
        }
        self.last_step_ceiling = report.ceiling;
        self.last_step_final_state = report.final_state;
        self.last_step_inbound_frames_consumed = report.inbound_frames_consumed;
        self.observe_network_output_batch(&report.emitted_frames)?;
        self.pending_network_outputs.extend(report.emitted_frames);
        let advance = match report.outcome {
            QemuAsyncNodeStepOutcome::Completed { advance } => Ok(advance),
            QemuAsyncNodeStepOutcome::Crashed { status, shutdown } => Err(QemuNodeError::Crashed {
                status: Box::new(status),
                shutdown: Box::new(shutdown),
            }),
        }?;
        let advance = output_boundary.map_or(advance, |at| AdvanceOutcome::Paused { at });
        self.last_observed_time = virtual_time_from_advance_outcome(ceiling, advance);
        // crucible-lint: allow host-nondeterminism-state -- this opt-in diagnostic reads an already published boundary and changes no scheduler state.
        if std::env::var_os("CRUCIBLE_PHASE4_CLOCK_TRACE").is_some()
            && let Ok(calibration) = self.logical_time_calibration()
            && (5_823_790_656..=5_825_708_109).contains(&calibration.raw_icount)
            && calibration.logical_icount <= 555_385_025_750
        {
            // crucible-lint: allow direct-diagnostic -- the opt-in trace is captured from packaged-VM stderr.
            eprintln!(
                "CRUCIBLE-PHASE4-CLOCK-TRACE pid={} ceiling={} outcome={advance:?} logical={} raw={} bias={:?} raw_mod4096={} next_deadline={:?} inbound={} outputs={}",
                self.process_id(),
                ceiling.retired,
                calibration.logical_icount,
                calibration.raw_icount,
                calibration.offset(),
                calibration.raw_icount % 4096,
                self.last_step_final_state
                    .and_then(|state| state.next_deadline),
                self.last_step_inbound_frames_consumed,
                self.pending_network_outputs.len(),
            );
        }
        Ok(advance)
    }

    /// Returns how many scheduler-staged inputs the last completed step consumed.
    #[must_use]
    pub(crate) const fn last_step_inbound_frames_consumed(&self) -> usize {
        self.last_step_inbound_frames_consumed
    }

    /// Returns the attested state from the last completed scheduler step.
    #[must_use]
    pub(crate) const fn last_step_final_state(&self) -> Option<QemuNodeIdleState> {
        self.last_step_final_state
    }

    /// Returns the effective shared-memory ceiling from the last scheduler step.
    #[must_use]
    pub(crate) const fn last_step_ceiling(&self) -> Option<Icount> {
        self.last_step_ceiling
    }

    /// Delivers deterministic input through shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory input ring rejects the frame.
    pub fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeError> {
        self.channels
            .shmem_hot_path
            .deliver_frame(input)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Delivers deterministic input at the scheduler-resolved virtual time.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory input ring rejects the
    /// timestamped frame.
    pub fn deliver_frame_at(
        &mut self,
        // crucible-lint: allow host-nondeterminism-state -- the node transports an already scheduler-resolved input without deriving engine state.
        input: BackendInput,
        at: VirtualTime,
    ) -> Result<(), QemuNodeError> {
        self.channels
            .shmem_hot_path
            .deliver_frame_at(input, Icount { retired: at.ticks })
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Captures the paused replay node's host network-ring continuation.
    ///
    /// # Errors
    ///
    /// Returns an error when a ring snapshot is invalid.
    pub(crate) fn replay_network_transport_checkpoint(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .checkpoint_network_transport()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Reads one emitted frame through shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory output ring cannot be read.
    pub fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeError> {
        self.channels.shmem_hot_path.emit_frame().map_err(|source| {
            QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
        })
    }

    /// Reads the current idle state through shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory idle state cannot be read.
    pub fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeError> {
        self.channels.shmem_hot_path.idle_state().map_err(|source| {
            QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
        })
    }

    /// Reads the coherent logical/raw time calibration published by the plugin.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory state cannot be read or
    /// its raw instruction count is ahead of logical time.
    pub fn logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .logical_time_calibration()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Reads the most recent actual virtual-timer callback witness.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory state cannot be read.
    pub fn virtual_timer_fire_witness(
        &mut self,
    ) -> Result<Option<QemuVirtualTimerFireWitness>, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .virtual_timer_fire_witness()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Reads the current execution fingerprint through the data path.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the plugin reports an invalid sample,
    /// exits, or does not publish the current boundary's complete sample within
    /// its live fingerprint operation budget. Scripted nodes use their fixture
    /// advance-completion timeout.
    pub fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeError> {
        use crate::supervision::host_io_runtime::operational_wait::OperationPollBudget;
        use crucible_host_resources::host_supervision::HostOperationClass;

        let timeout = self.async_policy.advance_completion_timeout;
        let map_supervision =
            |source| QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source));
        let deadline = OperationPollBudget::begin(
            self.host_operation_supervisor(),
            HostOperationClass::FingerprintUpdate,
            timeout,
            "execution_fingerprint",
        )
        .map_err(map_supervision)?;
        if self.fault_fingerprint_invalidated {
            return self.read_fresh_fault_fingerprint(&deadline);
        }
        let mut capture_requested = false;

        loop {
            match self.channels.shmem_hot_path.execution_fingerprint() {
                Ok(fingerprint) => {
                    deadline
                        .complete("execution_fingerprint")
                        .map_err(map_supervision)?;
                    return Ok(fingerprint);
                }
                Err(source) if source.is_retryable() => {
                    let remaining = deadline.remaining("execution_fingerprint")
                        .map_err(map_supervision)?
                        .ok_or_else(|| QemuNodeError::from_channel(
                            QemuNodeChannelPlane::ShmemHotPath,
                            QemuNodeChannelError::bounded_await_timeout(
                                "execution_fingerprint",
                                format!("plugin did not publish the current black-box fingerprint within {timeout:?}: {}", source.message),
                                timeout,
                            ),
                        ))?;
                    if !capture_requested {
                        self.host_io_runtime
                            .publish_current_execution_fingerprint(remaining)
                            .map_err(map_supervision)?;
                        capture_requested = true;
                        continue;
                    }
                    match self.child.try_wait_natural_exit() {
                        Ok(None) => deadline
                            .wait(Duration::from_millis(1), "execution_fingerprint")
                            .map_err(map_supervision)?,
                        Ok(Some(status)) => {
                            return Err(QemuNodeError::from_channel(
                                QemuNodeChannelPlane::ShmemHotPath,
                                QemuNodeChannelError::new(
                                    "execution_fingerprint",
                                    format!(
                                        "QEMU exited with {status} before publishing the current black-box fingerprint"
                                    ),
                                ),
                            ));
                        }
                        Err(source) => {
                            return Err(QemuNodeError::from_channel(
                                QemuNodeChannelPlane::ShmemHotPath,
                                QemuNodeChannelError::new(
                                    "execution_fingerprint",
                                    format!("poll QEMU while awaiting fingerprint: {source}"),
                                ),
                            ));
                        }
                    }
                }
                Err(source) => {
                    return Err(QemuNodeError::from_channel(
                        QemuNodeChannelPlane::ShmemHotPath,
                        source,
                    ));
                }
            }
        }
    }

    /// Reads the complete black-box fingerprint sample at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the plugin has not published the current
    /// sample or the shared-memory channel cannot read it.
    pub fn fingerprint_sample(&mut self) -> Result<QemuFingerprintSample, QemuNodeError> {
        if self.fault_fingerprint_invalidated {
            return self.read_fresh_fault_fingerprint_sample();
        }
        self.channels
            .shmem_hot_path
            .fingerprint_sample()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Reports whether no live device coroutine crosses the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the production host runtime cannot inspect
    /// its shared node slot.
    pub(crate) fn checkpoint_device_io_is_quiescent(&mut self) -> Result<bool, QemuNodeError> {
        self.host_io_runtime
            .checkpoint_device_io_is_quiescent()
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Captures the complete host-I/O state as a read-only world projection.
    ///
    /// The caller supplies the identity of the scheduler continuation that owns
    /// the projection. The runtime's live execution binding is unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when device I/O is active or an attached
    /// device or shared-memory ring cannot be snapshotted exactly.
    pub(crate) fn checkpoint_host_io_projection(
        &mut self,
        scheduler_binding: crucible_engine::ContentHash,
    ) -> Result<crate::QemuHostIoCheckpoint, QemuNodeError> {
        if self.reset_resume_is_pending() {
            return Err(QemuNodeError::checkpoint(
                "reset continuation cannot cross a host-I/O checkpoint",
            ));
        }
        if !self.checkpoint_device_io_is_quiescent()? {
            return Err(QemuNodeError::checkpoint(
                "host-I/O projection requested while QEMU device I/O is active",
            ));
        }

        self.host_io_runtime
            .checkpoint_host_io(scheduler_binding)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    pub(crate) fn restore_node_continuation(
        &mut self,
        checkpoint: &crate::QemuNodeContinuationCheckpoint,
    ) -> Result<(), QemuNodeError> {
        if self.reset_resume_is_pending() {
            return Err(QemuNodeError::checkpoint(
                "reset continuation cannot be replaced by restore",
            ));
        }
        if checkpoint.next_fault_command_sequence < 2 {
            return Err(QemuNodeError::checkpoint(
                "restored fault-command sequence precedes setup capability admission",
            ));
        }
        if checkpoint.next_fault_event_sequence == 0 {
            return Err(QemuNodeError::checkpoint(
                "restored fault-event sequence is zero",
            ));
        }
        self.last_observed_time = checkpoint.last_observed_time;
        self.last_step_ceiling = None;
        self.last_step_final_state = None;
        self.last_step_inbound_frames_consumed = 0;
        self.console_observation_boundary = checkpoint.console_observation_boundary;
        self.pending_preemption = checkpoint.pending_preemption.clone();
        self.channels
            .shmem_hot_path
            .restore_network_transport(&checkpoint.network_transport)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        self.pending_network_outputs = checkpoint.pending_network_outputs.clone();
        self.next_network_output_sequence =
            checkpoint.network_transport.next_host_outbound_sequence;
        self.next_fault_command_sequence = checkpoint.next_fault_command_sequence;
        self.next_fault_event_sequence = checkpoint.next_fault_event_sequence;
        self.fault_event_terminal_failure = None;
        Ok(())
    }

    pub(crate) fn restore_network_transport_for_gate(
        &mut self,
        checkpoint: &crate::QemuNetworkTransportCheckpoint,
    ) -> Result<(), QemuNodeError> {
        self.channels
            .shmem_hot_path
            .restore_network_transport(checkpoint)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Resumes a fully reconstructed node after the factory restores continuation state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QMP does not acknowledge the running-state
    /// transition. The next bounded step proves execution.
    pub(crate) fn resume_after_restore(&mut self) -> Result<(), QemuNodeError> {
        if self.reset_resume_is_pending() {
            return Err(QemuNodeError::checkpoint(
                "reset cannot use ordinary restore resume",
            ));
        }
        self.channels
            .qmp_machine_control
            .resume_after_checkpoint()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })?;

        // A source checkpoint can resume the same output-stopped process.
        // Its native fence is now released; the next step needs only its new
        // ceiling, just like a freshly reconstructed restored generation.
        self.network_output_resume_pending = false;
        self.hot_fork_resume_pending = false;
        Ok(())
    }

    /// Deletes the VMState artifact owned by a previously captured snapshot.
    ///
    /// Callers use this when committing the Apache-side checkpoint to durable
    /// storage fails after QMP save succeeds. The host-I/O value is immutable
    /// owned data and needs no separate rollback operation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the pair is identity-inconsistent or QMP
    /// cannot complete the bounded delete job.
    pub fn delete_exact_snapshot(
        &mut self,
        snapshot: &crate::QemuVmSnapshot,
    ) -> Result<(), QemuNodeError> {
        if snapshot.host_io().execution_binding() != snapshot.checkpoint().id {
            return Err(QemuNodeError::checkpoint(
                "refusing to delete an identity-inconsistent exact snapshot",
            ));
        }
        match self
            .channels
            .qmp_machine_control
            .delete_checkpoint_vmstate(snapshot.checkpoint())
        {
            Ok(()) => Ok(()),
            Err(source) => self.handle_qmp_channel_error(source),
        }
    }

    /// Force-kills and reaps the child for the live exact-restore gate.
    ///
    /// The gate deliberately avoids every graceful teardown channel so the
    /// subsequent restore proves that no state survived in the old process.
    #[cfg(target_os = "linux")]
    pub(crate) fn force_crash_and_reap_for_gate(&mut self) -> Result<(), QemuNodeError> {
        self.force_quarantine_and_reap()
    }

    /// Force-kills and reaps an indeterminate process generation.
    ///
    /// This containment path deliberately sends no graceful guest or plugin
    /// command: ambiguity must not execute additional modeled behavior.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the process cannot be killed or remains
    /// unreaped after the bounded wait.
    #[cfg(target_os = "linux")]
    pub fn force_quarantine_and_reap(&mut self) -> Result<(), QemuNodeError> {
        self.retain_target_shutdown_original()?;
        let process = self.child_shutdown.contain(
            &mut self.child,
            &mut self.channels,
            &mut self.lifecycle_state,
            self.shutdown_policy,
            self.host_io_runtime.host_operation_supervisor(),
        );
        self.finish_shutdown(process).map(|_| ())
    }

    /// Runs shutdown escalation for the owned child through the node's channels.
    ///
    /// The runner uses plugin IPC `Quit`, QMP `quit`, `SIGTERM`, `SIGKILL`, and
    /// reap in that order. Polite channel failures are recorded by the shutdown
    /// report and do not prevent signal escalation or reap. A later call may
    /// finish factual closure after an earlier delivered failure; it never
    /// renews the original operation. [`Self::shutdown_health`] preserves that
    /// failure independently of physical closure.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the child remains live after the shutdown
    /// policy's final reap deadline or when the child cannot be signaled,
    /// queried, or reaped.
    pub fn shutdown_child(&mut self) -> Result<QemuShutdownReport, QemuNodeError> {
        if self.channels.shmem_hot_path.coverage_enabled() {
            return Err(QemuNodeError::CoverageEventLogRequired);
        }
        self.shutdown_child_after_coverage_drain()
    }

    /// Reports permanent failure of this child's retained cleanup invocation.
    ///
    /// Physical shutdown may finish after reporting an earlier refusal. This
    /// query preserves its logical health independently of that factual close.
    ///
    /// # Errors
    /// Returns the saved rung, Original or completion/post failure.
    pub fn shutdown_health(&self) -> Result<(), QemuNodeError> {
        self.child_shutdown.health()
    }

    /// Drains final coverage into `event_log`, then runs shutdown escalation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the final shared-memory drain, unified-log
    /// append, or child shutdown ladder fails.
    pub fn shutdown_child_with_event_log(
        &mut self,
        event_log: &mut EventLog,
    ) -> Result<(QemuShutdownReport, SchedulerEventLogAppend), QemuNodeError> {
        let appended = self.drain_observable_events_into(event_log)?;
        let report = self.shutdown_child_after_coverage_drain()?;
        Ok((report, appended))
    }

    fn shutdown_child_after_coverage_drain(&mut self) -> Result<QemuShutdownReport, QemuNodeError> {
        self.retain_target_shutdown_original()?;
        let process = self.child_shutdown.close(
            &mut self.child,
            &mut self.channels,
            &mut self.lifecycle_state,
            self.shutdown_policy,
            self.host_io_runtime.host_operation_supervisor(),
        );
        self.finish_shutdown(process)
    }

    fn retain_target_shutdown_original(&mut self) -> Result<(), QemuNodeError> {
        if self.child_shutdown.entered() {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        if let Some(ram) = self.hot_fork_ram_continuation.as_ref() {
            let original = match ram.cleanup.retained_target_cleanup() {
                Ok(original) => original,
                Err(source) => {
                    let first = QemuNodeError::RamCleanupLender {
                        source: crucible_engine::BackendOperationalCause::new(source),
                    };
                    self.child_shutdown.retain_ram_refusal(first.clone());
                    return Err(first);
                }
            };
            self.child_shutdown.retain_target_original(original);
        }
        Ok(())
    }

    fn finish_shutdown(
        &mut self,
        process: Result<QemuShutdownReport, QemuNodeError>,
    ) -> Result<QemuShutdownReport, QemuNodeError> {
        if !self.child.reaped() {
            return process;
        }
        let ram = self.finish_host_ram_cleanup();
        match (process, ram) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(first), Ok(())) | (Ok(_), Err(first)) => Err(first),
            (Err(first), Err(ram)) => Err(QemuNodeError::ShutdownAndRam {
                first: Box::new(first),
                ram: Box::new(ram),
            }),
        }
    }

    fn handle_qmp_channel_error<T>(
        &mut self,
        source: QemuNodeChannelError,
    ) -> Result<T, QemuNodeError> {
        let Some(timeout) = source.bounded_timeout() else {
            return Err(QemuNodeError::from_channel(
                QemuNodeChannelPlane::QmpMachineControl,
                source,
            ));
        };
        let status = self
            .crash_detector
            .bounded_await_timeout(source.operation, timeout);
        match self.shutdown_child() {
            Ok(shutdown) => Err(QemuNodeError::Crashed {
                status: Box::new(status),
                shutdown: Box::new(shutdown),
            }),
            Err(shutdown) => Err(QemuNodeError::ShutdownAfterChannelFailure {
                first: source,
                status,
                shutdown: Box::new(shutdown),
            }),
        }
    }
}

#[path = "node/async_step.rs"]
mod async_step;
#[cfg(any(test, feature = "test-support"))]
mod block_completion_observation;

use async_step::*;

struct QemuNodeShutdownTarget<'a, 'plugin, 'qmp> {
    child: &'a mut QemuNodeProcessControl,
    plugin_control: Option<&'a mut (dyn QemuPluginIpcControlChannel + 'plugin)>,
    qmp_machine_control: Option<&'a mut (dyn QemuQmpMachineControlChannel + 'qmp)>,
    supervisor: Option<&'a crucible_host_resources::host_supervision::HostOperationSupervisor>,
    guard: Option<&'a crucible_host_resources::host_supervision::HostOperationGuard>,
    observations: &'a mut [(
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    ); 5],
    // Entry, ladder, completion, observation and ten rung refusals: <=14.
    history_pending: &'a mut bool,
}

pub(crate) mod operational_health;
mod ram_cleanup;
mod shutdown_budget;
mod shutdown_continuation;

/// Measures only the new inline shutdown control in its existing node body.
pub(crate) fn child_shutdown_control_extent() -> Option<u64> {
    let fixed = std::mem::size_of::<shutdown_continuation::ChildShutdown>();
    #[cfg(target_os = "linux")]
    let fixed = fixed
        .checked_add(
            std::mem::size_of::<hot_fork_ram_stage::RamAllocation<QemuHotForkRamStage>>()
                .checked_sub(std::mem::size_of::<Box<QemuHotForkRamStage>>())?,
        )?
        .checked_add(
            std::mem::size_of::<hot_fork_ram_stage::RamAllocation<QemuHotForkRamContinuation>>()
                .checked_sub(std::mem::size_of::<Box<QemuHotForkRamContinuation>>())?,
        )?;
    u64::try_from(fixed).ok()
}

impl QemuShutdownTarget for QemuNodeShutdownTarget<'_, '_, '_> {
    fn child_reaped(&self) -> bool {
        self.child.reaped()
    }

    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.under_original(QemuShutdownRung::ControlQuit, |target| {
            if let Some(guard) = target.guard {
                return target
                    .plugin_control
                    .as_deref_mut()
                    .ok_or_else(|| {
                        QemuShutdownTargetError::new("child cleanup", "plugin channel absent")
                    })?
                    .send_quit_supervised(guard)
                    .map_err(channel_error_to_shutdown_error);
            }
            target
                .plugin_control
                .as_deref_mut()
                .ok_or_else(|| {
                    QemuShutdownTargetError::new("child cleanup", "plugin channel absent")
                })?
                .send_quit()
                .map_err(channel_error_to_shutdown_error)
        })
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.under_original(QemuShutdownRung::QmpQuit, |target| {
            let channel = target.qmp_machine_control.as_deref_mut().ok_or_else(|| {
                QemuShutdownTargetError::new("child cleanup", "QMP channel absent")
            })?;
            match target.guard {
                Some(original) => channel.quit_under_original(original),
                None => channel.quit(),
            }
            .map_err(channel_error_to_shutdown_error)
        })
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.under_original(QemuShutdownRung::Sigterm, |target| {
            target.child.send_sigterm()
        })
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.under_original(QemuShutdownRung::Sigkill, |target| {
            target.child.send_sigkill()
        })
    }

    fn wait_for_exit_observed(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> (Option<QemuChildWait>, Result<(), QemuShutdownTargetError>) {
        self.under_original_observed(rung, |target| {
            if target.guard.is_some() {
                target.wait_for_live_exit()
            } else {
                target.child.wait_for_exit(rung, timeout)
            }
        })
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.under_original(QemuShutdownRung::Reap, |target| {
            if target.guard.is_none() {
                return target.child.reap(timeout);
            }
            target.wait_for_live_exit().map(|state| match state {
                QemuChildWait::Exited => QemuReap::Reaped,
                QemuChildWait::StillRunning => QemuReap::StillAlive,
            })
        })
    }
}

fn channel_error_to_shutdown_error(error: QemuNodeChannelError) -> QemuShutdownTargetError {
    match error.operational_supervision_source() {
        Some(source) => QemuShutdownTargetError::operational_supervision(error.operation, source),
        None => QemuShutdownTargetError::new(error.operation, error.message),
    }
}

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub(crate) mod test_support;
#[cfg(all(target_os = "linux", feature = "test-support"))]
pub use test_support::hot_fork::{
    QemuTestHotForkIsolationFault, QemuTestHotForkOutcome, QemuTestHotForkSourceError,
    QemuTestQuantumBoundary, scripted_hot_fork_source_for_test,
    scripted_hot_fork_source_with_observations_for_test,
    scripted_hot_fork_source_with_script_for_test, scripted_hot_fork_source_with_state_for_test,
};
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub use test_support::native_aliases::{
    QemuTestNativeAliasKind, QemuTestNativeAliasProbeError, QemuTestNativeAliasRejection,
};
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub use test_support::native_descriptors::{
    QemuTestNativeSourceDescriptor, QemuTestNativeSourceDescriptorError,
    QemuTestNativeSourceDescriptorRole,
};

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "node_tests.rs"]
pub(crate) mod tests;

#[cfg(all(test, feature = "private-measurement-domain"))]
#[path = "node/stopped_launch_tests.rs"]
mod stopped_launch_tests;

#[path = "node/failed_launch.rs"]
mod failed_launch;
pub use failed_launch::QemuFailedLaunchOwner;
#[cfg(target_os = "linux")]
pub(crate) use failed_launch::{IssuedLaunchOwner, SourceLaunchReservation};

pub(crate) use failed_launch::RetainedChild;
