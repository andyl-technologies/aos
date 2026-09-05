//! Scheduler-facing QEMU node wrapper.
//!
//! The wrapper owns exactly one child handle and the three RFC-0010 QEMU
//! channels for that child: plugin IPC control, shared-memory hot path, and
//! QMP machine control. It exposes the synchronous backend boundary while
//! keeping per-quantum timing and frame traffic on the shared-memory channel.

use std::any::Any;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
use std::process::Child;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use crucible::model::{FaultCoordinate, ResolvedBindingAction};
use crucible::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput, BackendNetworkOutput,
    BackendSnapshot, Checkpoint, EventLog, ExecutionFingerprint, ExecutionHorizon,
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, NodeId, ObservableEvent,
    SchedulerEventLogAppend, SimulationBackend, StepObservation, VirtualTime,
};
use crucible_protocol::guest_introspection::GuestIntrospectionRecord;
use crucible_shmem::{
    DequeuedFaultEvent, DequeuedFaultResult, FAULT_COMMAND_FLAG_PREPARE_ONLY, FaultCapabilityRowV1,
    FaultCommandHeaderV1, FaultResultStatus, FingerprintSample as QemuFingerprintSample,
    HARD_FAULT_EVENT_CAPACITY, HARD_FAULT_PAYLOAD_BYTES, SchedulerPreemptionCommand,
    SchedulerPreemptionKind as ShmemSchedulerPreemptionKind,
};
// crucible-lint: allow host-nondeterminism-state -- node transport exposes untrusted causal records for scheduler validation.
use crucible::Decision;

use crate::async_driver::run_bounded_qemu_node_step_with_start_hook;
use crate::console_observation::QemuConsoleObservationSpool;
use crate::shutdown::{
    QemuChildWait, QemuReap, QemuShutdownPolicy, QemuShutdownReport, QemuShutdownRung,
    QemuShutdownTarget, QemuShutdownTargetError, shutdown_qemu_child, signal_child, wait_child,
};
use crate::supervision::HostSupervisionDeadline;
use crate::{
    QemuAdvanceCompletionFence, QemuAsyncCrashEscalationTarget, QemuAsyncDriverPolicy,
    QemuAsyncDriverTargetError, QemuAsyncNodeStepOutcome, QemuAsyncNodeStepTarget,
    QemuAsyncQuantumCompletion, QemuCrashDetector, QemuGdbstubChannelConfig, QemuGdbstubProxy,
    QemuGdbstubProxyServer, QemuHostIoRuntime, run_bounded_qemu_node_step,
};

mod channels;
mod checkpoint_probe;
pub use channels::{
    QemuNodePendingQuantum, QemuPluginIpcControlChannel, QemuQmpMachineControlChannel,
    QemuShmemHotPathChannel,
};
mod error;
mod exact_snapshot;
mod fault_events;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_child_console.rs"]
mod hot_fork_child_console;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_child_qmp.rs"]
mod hot_fork_child_qmp;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_diagnostics.rs"]
mod hot_fork_diagnostics;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_operation.rs"]
mod hot_fork_operation;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_plugin_endpoints.rs"]
mod hot_fork_plugin_endpoints;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_preparation.rs"]
mod hot_fork_preparation;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_process_contract.rs"]
mod hot_fork_process_contract;
#[cfg(unix)]
#[path = "node/hot_fork_ring_image.rs"]
mod hot_fork_ring_image;
#[cfg(target_os = "linux")]
#[path = "node/hot_fork_scheduler_continuation.rs"]
mod hot_fork_scheduler_continuation;
#[path = "node/process_control.rs"]
mod process_control;
#[cfg(target_os = "linux")]
mod process_identity;
pub use error::{QemuNodeChannelError, QemuNodeChannelPlane, QemuNodeError};
#[cfg(target_os = "linux")]
use hot_fork_child_console::QemuHotForkChildConsoleStage;
#[cfg(target_os = "linux")]
pub use hot_fork_child_console::{
    QemuHotForkChildConsoleObservation, QemuHotForkChildConsoleStageError,
    QemuHotForkChildConsoleStageProof, QemuHotForkChildConsoleStageState,
};
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
    QemuHotForkPluginHostContinuation,
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
    /// Current retired-instruction count observed for the node.
    pub current_icount: Icount,
    /// The next instruction-count deadline that can wake the idle node.
    pub next_deadline: Option<Icount>,
}

/// Plugin logical-time calibration observed at one coherent shared-memory boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QemuLogicalTimeCalibration {
    /// Scheduler-visible logical instruction count.
    pub logical_icount: u64,
    /// QEMU VMState-owned raw retired-instruction count.
    pub raw_icount: u64,
}

impl QemuLogicalTimeCalibration {
    /// Returns the idle-jump offset applied over QEMU's raw icount.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when raw icount is ahead of logical time.
    pub fn offset(self) -> Result<u64, QemuNodeChannelError> {
        self.logical_icount
            .checked_sub(self.raw_icount)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "read logical-time calibration",
                    format!(
                        "raw icount {} is ahead of logical icount {}",
                        self.raw_icount, self.logical_icount
                    ),
                )
            })
    }
}

/// The one QEMU child process owned by a [`QemuNode`].
#[derive(Debug)]
pub struct QemuNodeChild {
    child: Child,
    reaped: bool,
}

impl QemuNodeChild {
    /// Takes ownership of a spawned QEMU child process.
    #[must_use]
    // crucible-lint: allow rust-allow -- non-Linux builds do not construct child wrappers in this target.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    /// Returns whether the owned child has been reaped by this wrapper.
    #[must_use]
    pub const fn reaped(&self) -> bool {
        self.reaped
    }

    /// Returns the operating-system process identifier of the owned child.
    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    /// Polls for a natural child exit without sending a signal.
    ///
    /// A returned status is the exact `waitpid` result and marks this wrapper
    /// reaped, so dropping it cannot hide the outcome with kill-and-wait
    /// cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the child was already reaped or
    /// the nonblocking wait fails.
    pub fn try_wait_natural_exit(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, QemuShutdownTargetError> {
        if self.reaped {
            return Err(QemuShutdownTargetError::new(
                "poll natural QEMU exit",
                "child was already reaped",
            ));
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.reaped = true;
                Ok(Some(status))
            }
            Ok(None) => Ok(None),
            Err(error) => Err(QemuShutdownTargetError::new(
                "poll natural QEMU exit",
                error.to_string(),
            )),
        }
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        signal_child(self.child.id(), libc::SIGTERM, "send SIGTERM")
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        signal_child(self.child.id(), libc::SIGKILL, "send SIGKILL")
    }

    fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        let state = wait_child(&mut self.child, timeout)?;
        if state == QemuChildWait::Exited {
            self.reaped = true;
        }
        Ok(state)
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        if self.reaped {
            return Ok(QemuReap::Reaped);
        }

        match wait_child(&mut self.child, timeout)? {
            QemuChildWait::Exited => {
                self.reaped = true;
                Ok(QemuReap::Reaped)
            }
            QemuChildWait::StillRunning => Ok(QemuReap::StillAlive),
        }
    }

    /// Force-kills and synchronously reaps a failed fresh realization.
    ///
    /// This failure-only path deliberately has no reap timeout: returning an
    /// assembly error while abandoning this process would leave a live child or
    /// zombie owned by the long-running host. Ordinary node shutdown remains
    /// bounded by [`QemuShutdownPolicy`].
    pub(crate) fn force_kill_and_reap_failed_realization(
        &mut self,
    ) -> Result<(), QemuShutdownTargetError> {
        if self.reaped {
            return Ok(());
        }
        // A kill error can mean the child exited between the factory failure
        // and this call. Waiting is still mandatory and decides whether the
        // child was actually reaped.
        let _kill_result = self.child.kill();
        self.child.wait().map_err(|error| {
            QemuShutdownTargetError::new("reap failed QEMU realization", error.to_string())
        })?;
        self.reaped = true;
        Ok(())
    }

    /// Force-kills and boundedly reaps one failed attempt helper process.
    ///
    /// A timeout deliberately leaves this wrapper unreaped so the caller can
    /// transfer its unique direct-child wait authority into the attempt owner.
    pub(crate) fn force_kill_and_reap_failed_helper(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuShutdownTargetError> {
        if self.reaped {
            return Ok(());
        }
        let _kill_result = self.child.kill();
        match wait_child(&mut self.child, timeout)? {
            QemuChildWait::Exited => {
                self.reaped = true;
                Ok(())
            }
            QemuChildWait::StillRunning => Err(QemuShutdownTargetError::new(
                "reap failed QEMU helper",
                "child remained alive after SIGKILL and the bounded wait",
            )),
        }
    }
}

/// Bounded deadline for reaping a force-killed child in [`QemuNodeChild::drop`].
///
/// A wedged QEMU (for example blocked in uninterruptible kernel sleep on a stuck
/// host ioctl) can outlive a `SIGKILL` until the kernel operation completes, so
/// the destructor bounds its reap to this deadline and abandons the process
/// rather than blocking the dropping thread forever.
const DROP_REAP_DEADLINE: Duration = Duration::from_secs(5);

impl Drop for QemuNodeChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Force-kill (SIGKILL) and reap within a hard deadline. A blocking
        // `wait()` here would hang teardown indefinitely on a wedged child;
        // `wait_child` polls non-blockingly up to `DROP_REAP_DEADLINE` and then
        // abandons. `reaped` stays false on abandonment so the wrapper never
        // claims a reap it did not observe; the process was already SIGKILL'd,
        // so the OS reaps the zombie once it leaves any uninterruptible section.
        // The destructor has no error channel and this crate's lint bans direct
        // stderr diagnostics, so an abandonment is intentionally silent.
        let _ = self.child.kill();
        if let Ok(QemuChildWait::Exited) = wait_child(&mut self.child, DROP_REAP_DEADLINE) {
            self.reaped = true;
        }
    }
}

/// The three logical channel roles owned by one QEMU node.
///
/// The shared-memory role includes its futex and eventfd wake objects; this
/// bundle describes protocol planes rather than a count of kernel objects.
pub struct QemuNodeChannels {
    plugin_control: Box<dyn QemuPluginIpcControlChannel>,
    shmem_hot_path: Box<dyn QemuShmemHotPathChannel>,
    qmp_machine_control: Box<dyn QemuQmpMachineControlChannel>,
}

impl QemuNodeChannels {
    /// Builds the three-plane role bundle for one QEMU child.
    #[must_use]
    pub fn new(
        plugin_control: impl QemuPluginIpcControlChannel + 'static,
        shmem_hot_path: impl QemuShmemHotPathChannel + 'static,
        qmp_machine_control: impl QemuQmpMachineControlChannel + 'static,
    ) -> Self {
        Self {
            plugin_control: Box::new(plugin_control),
            shmem_hot_path: Box::new(shmem_hot_path),
            qmp_machine_control: Box::new(qmp_machine_control),
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
    hot_fork_plugin_endpoint_stage: Option<QemuHotForkPluginEndpointStage>,
    #[cfg(target_os = "linux")]
    _hot_fork_scheduler_authority: Option<QemuHotForkInstalledNodeAuthority>,
    lifecycle_state: QemuNodeLifecycleState,
    shutdown_policy: QemuShutdownPolicy,
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
    active_gdbstub: Option<QemuGdbstubProxyServer>,
    pending_preemption: Option<crucible::PreemptionDecision>,
    pending_network_outputs: Vec<QemuNodeEmittedFrame>,
    pending_priming_observations: Vec<ObservableEvent>,
    next_network_output_sequence: u64,
    console_observation: Option<QemuConsoleObservation>,
    fault_capabilities: Vec<FaultCapabilityRowV1>,
    ready_markers: std::collections::BTreeSet<crucible::model::FaultObjectId>,
    exact_fault_manifests: Option<crate::fault_capability::QemuExactFaultManifests>,
    next_fault_command_sequence: u64,
    setup_fault_command_sequence_floor: u64,
    next_fault_event_sequence: u64,
    fault_event_terminal_failure: Option<String>,
}

impl QemuNode {
    /// Returns this node's authoritative live block-device handle, when present.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn shared_block_device(&self) -> Option<crate::QemuSharedBlockDevice> {
        self.host_io_runtime.shared_block_device()
    }

    /// Captures block state for rollback of an uncommitted scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime cannot capture the
    /// complete block-fault continuation.
    #[cfg(target_os = "linux")]
    pub fn checkpoint_block_boundary_state(
        &self,
    ) -> Result<Option<crucible_device::block::BlockFaultState>, QemuNodeError> {
        self.host_io_runtime
            .checkpoint_block_boundary_state()
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Restores block state captured before an uncommitted scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime cannot restore the
    /// captured topology and state exactly.
    #[cfg(target_os = "linux")]
    pub fn restore_block_boundary_state(
        &mut self,
        state: Option<crucible_device::block::BlockFaultState>,
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .restore_block_boundary_state(state)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Applies storage-targeted actions through this node's live block adapter.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the coordinator rejects the boundary.
    #[cfg(target_os = "linux")]
    pub fn apply_block_boundary_actions(
        &mut self,
        coordinate: FaultCoordinate,
        evaluation_sequence: u64,
        actions: &[ResolvedBindingAction],
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .apply_block_boundary_actions(coordinate, evaluation_sequence, actions)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Installs the production signal coordinator for this node's block device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime has no attached block
    /// servicer or already owns a coordinator.
    #[cfg(target_os = "linux")]
    pub fn install_block_fault_coordinator(
        &mut self,
        coordinator: Box<dyn crate::QemuBlockFaultCoordinator>,
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .install_block_fault_coordinator(coordinator)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

    /// Installs the production signal coordinator for this node's 9p device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the host-I/O runtime has no attached 9p
    /// servicer or already owns a coordinator.
    #[cfg(target_os = "linux")]
    pub fn install_ninep_fault_coordinator(
        &mut self,
        coordinator: Box<dyn crate::QemuNinepFaultCoordinator>,
    ) -> Result<(), QemuNodeError> {
        self.host_io_runtime
            .install_ninep_fault_coordinator(coordinator)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })
    }

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
        Self {
            child: QemuNodeProcessControl::Direct(child),
            channels,
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
            hot_fork_plugin_endpoint_stage: None,
            #[cfg(target_os = "linux")]
            _hot_fork_scheduler_authority: None,
            lifecycle_state: QemuNodeLifecycleState::Running,
            shutdown_policy,
            async_policy,
            crash_detector,
            host_io_runtime: Box::new(host_io_runtime),
            last_observed_time: VirtualTime::default(),
            last_step_ceiling: None,
            last_step_final_state: None,
            last_step_inbound_frames_consumed: 0,
            console_observation_boundary: VirtualTime::default(),
            gdbstub: None,
            active_gdbstub: None,
            pending_preemption: None,
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
        }
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
        ready_markers: std::collections::BTreeSet<crucible::model::FaultObjectId>,
    ) -> Self {
        self.ready_markers = ready_markers;
        self
    }

    /// Returns the exact launch-bound guest ready-marker manifest.
    #[must_use]
    pub const fn ready_markers(
        &self,
    ) -> &std::collections::BTreeSet<crucible::model::FaultObjectId> {
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

    /// Returns the exact public target manifests accepted during setup.
    #[must_use]
    pub(crate) const fn exact_fault_manifests(
        &self,
    ) -> Option<&crate::fault_capability::QemuExactFaultManifests> {
        self.exact_fault_manifests.as_ref()
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
        self.channels
            .shmem_hot_path
            .enqueue_fault_command(header, payload)
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

    /// Applies one admitted QEMU fault command at the exact current boundary.
    ///
    /// The method refuses to advance the guest. It authenticates the command
    /// against setup-time capabilities, publishes it through shared memory,
    /// wakes QEMU until the correlated lossless result arrives, and verifies
    /// that the retired-instruction coordinate remained unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] for an absent capability, stale result,
    /// coordinate mismatch, invalid result, bounded host-liveness timeout, or
    /// any guest progress while the command was being applied.
    pub fn apply_fault_command_at_current_boundary(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<DequeuedFaultResult, QemuNodeError> {
        if header.command_flags & FAULT_COMMAND_FLAG_PREPARE_ONLY != 0 {
            return self.apply_fault_command_at_current_boundary_with_storage(
                header,
                payload,
                None,
                HARD_FAULT_PAYLOAD_BYTES as usize,
                HARD_FAULT_EVENT_CAPACITY as usize,
            );
        }
        // Compatibility APPLY callers have not staged a result buffer. Admit
        // the ABI hard ceiling before publication; production adapters use the
        // precise buffered path and do not pay this conservative cost.
        let requested_u64 = u64::from(HARD_FAULT_PAYLOAD_BYTES);
        let requested =
            usize::try_from(requested_u64).map_err(|_| QemuNodeError::FaultResultStorage {
                requested: requested_u64,
                configured: requested_u64,
            })?;
        let mut result_buffer = Vec::new();
        result_buffer.try_reserve_exact(requested).map_err(|_| {
            QemuNodeError::FaultResultStorage {
                requested: requested_u64,
                configured: requested_u64,
            }
        })?;
        self.apply_fault_command_at_current_boundary_with_storage(
            header,
            payload,
            Some(result_buffer),
            0,
            HARD_FAULT_EVENT_CAPACITY as usize,
        )
    }

    /// Applies one admitted command using caller-reserved result storage and
    /// an authored occurrence-event staging limit.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] under the same conditions as
    /// [`Self::apply_fault_command_at_current_boundary`], and when either
    /// caller-owned result storage or event staging is insufficient.
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
        self.console_observation = Some(QemuConsoleObservation { node, spool });
        self
    }

    /// Retains setup-time observations for the first authoritative scheduler drain.
    #[must_use]
    pub(crate) fn with_priming_observable_events(
        mut self,
        mut events: Vec<ObservableEvent>,
        ready_boundary: VirtualTime,
    ) -> Self {
        for event in &mut events {
            event.set_observation_time(ready_boundary);
        }
        self.pending_priming_observations = events;
        self
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
        self.gdbstub = Some(gdbstub);
        self
    }

    /// Returns the configured gdbstub channel, when this node supports one.
    #[must_use]
    pub const fn gdbstub_channel(&self) -> Option<&QemuGdbstubChannelConfig> {
        self.gdbstub.as_ref()
    }

    /// Returns the active operator-facing gdbstub listener, when attached.
    #[must_use]
    pub fn active_gdbstub_listener(&self) -> Option<SocketAddr> {
        self.active_gdbstub
            .as_ref()
            .map(QemuGdbstubProxyServer::local_addr)
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

    /// Consumes this failed node and transfers its direct-child wait authority.
    ///
    /// This crate-internal handoff deliberately drops every modeled channel and
    /// live-backend capability. The returned child must be authenticated and
    /// transferred to the attempt's cgroup reaper before any resource guard is
    /// released.
    pub(crate) fn into_direct_child_for_quarantine(self) -> Option<QemuNodeChild> {
        self.child.into_direct_child()
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

    /// Captures a stable bounded process inventory at an exact QEMU boundary.
    ///
    /// The method brackets two complete Linux thread, descriptor, and mapping
    /// passes with QEMU's versioned readiness query and exact process identity.
    /// The resulting value is Phase 6 audit evidence only: missing QEMU proof
    /// classes remain missing and the report cannot authorize a process fork.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuHotForkAuditError`] when QEMU is not at its exact
    /// paused/device-flush boundary, readiness changes, process identity or
    /// procfs validation fails, an inventory bound is exceeded, or two passes
    /// do not identify one fixed point.
    #[cfg(target_os = "linux")]
    pub fn audit_hot_fork_process(
        &mut self,
    ) -> Result<crate::QemuHotForkAudit, crate::QemuHotForkAuditError> {
        let process = self
            .process_identity()
            .map_err(crate::QemuHotForkAuditError::ProcessIdentity)?;
        let before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_readiness()
            .map_err(crate::QemuHotForkAuditError::Readiness)?;
        if !before.acknowledges(crate::QmpHotForkProof::ExactPausedBoundary) {
            return Err(crate::QemuHotForkAuditError::NotExactPausedBoundary);
        }
        let threads_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_thread_inventory()
            .map_err(crate::QemuHotForkAuditError::ThreadInventory)?;
        let rcu_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_rcu_inventory()
            .map_err(crate::QemuHotForkAuditError::RcuInventory)?;
        let aio_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_aio_inventory()
            .map_err(crate::QemuHotForkAuditError::AioInventory)?;
        let aio_handlers_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_aio_handler_inventory()
            .map_err(crate::QemuHotForkAuditError::AioHandlerInventory)?;
        let block_backends_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_block_backend_inventory()
            .map_err(crate::QemuHotForkAuditError::BlockBackendInventory)?;
        let plugin_resources_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()
            .map_err(crate::QemuHotForkAuditError::PluginResourceInventory)?;
        let bottom_halves_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_bottom_half_inventory()
            .map_err(crate::QemuHotForkAuditError::BottomHalfInventory)?;
        let mutexes_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_mutex_inventory()
            .map_err(crate::QemuHotForkAuditError::MutexInventory)?;
        let timers_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_timer_inventory()
            .map_err(crate::QemuHotForkAuditError::TimerInventory)?;
        let monitors_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_monitor_inventory()
            .map_err(crate::QemuHotForkAuditError::MonitorInventory)?;

        let inventory =
            crate::hot_fork_audit::capture_linux_qemu_hot_fork_process_inventory(&process)?;
        let monitors_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_monitor_inventory()
            .map_err(crate::QemuHotForkAuditError::MonitorInventory)?;
        if monitors_before != monitors_after {
            return Err(crate::QemuHotForkAuditError::MonitorInventoryChanged);
        }
        let timers_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_timer_inventory()
            .map_err(crate::QemuHotForkAuditError::TimerInventory)?;
        if timers_before != timers_after {
            return Err(crate::QemuHotForkAuditError::TimerInventoryChanged);
        }
        let mutexes_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_mutex_inventory()
            .map_err(crate::QemuHotForkAuditError::MutexInventory)?;
        if mutexes_before != mutexes_after {
            return Err(crate::QemuHotForkAuditError::MutexInventoryChanged);
        }
        let bottom_halves_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_bottom_half_inventory()
            .map_err(crate::QemuHotForkAuditError::BottomHalfInventory)?;
        if bottom_halves_before != bottom_halves_after {
            return Err(crate::QemuHotForkAuditError::BottomHalfInventoryChanged);
        }
        let plugin_resources_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()
            .map_err(crate::QemuHotForkAuditError::PluginResourceInventory)?;
        if plugin_resources_before != plugin_resources_after {
            return Err(crate::QemuHotForkAuditError::PluginResourceInventoryChanged);
        }
        let block_backends_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_block_backend_inventory()
            .map_err(crate::QemuHotForkAuditError::BlockBackendInventory)?;
        if block_backends_before != block_backends_after {
            return Err(crate::QemuHotForkAuditError::BlockBackendInventoryChanged);
        }
        let aio_handlers_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_aio_handler_inventory()
            .map_err(crate::QemuHotForkAuditError::AioHandlerInventory)?;
        if aio_handlers_before != aio_handlers_after {
            return Err(crate::QemuHotForkAuditError::AioHandlerInventoryChanged);
        }
        let aio_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_aio_inventory()
            .map_err(crate::QemuHotForkAuditError::AioInventory)?;
        if aio_before != aio_after {
            return Err(crate::QemuHotForkAuditError::AioInventoryChanged);
        }
        let rcu_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_rcu_inventory()
            .map_err(crate::QemuHotForkAuditError::RcuInventory)?;
        if rcu_before != rcu_after {
            return Err(crate::QemuHotForkAuditError::RcuInventoryChanged);
        }
        let threads_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_thread_inventory()
            .map_err(crate::QemuHotForkAuditError::ThreadInventory)?;
        if threads_before != threads_after {
            return Err(crate::QemuHotForkAuditError::ThreadInventoryChanged);
        }
        let after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_readiness()
            .map_err(crate::QemuHotForkAuditError::Readiness)?;
        if before != after {
            return Err(crate::QemuHotForkAuditError::ReadinessChanged);
        }
        crate::QemuHotForkAudit::new(
            crate::hot_fork_audit::QemuHotForkQmpInventory::new(
                before,
                threads_before,
                rcu_before,
                aio_before,
                aio_handlers_before,
                block_backends_before,
                plugin_resources_before,
                bottom_halves_before,
                mutexes_before,
                timers_before,
                monitors_before,
            ),
            inventory,
        )
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
        action: crucible::ContentHash,
    ) -> Result<i32, QemuNodeError> {
        let deadline = HostSupervisionDeadline::start(self.async_policy.advance_completion_timeout);
        loop {
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
                    self.lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
                    return Ok(actual);
                }
                None if deadline.has_time_remaining() => {
                    std::thread::sleep(Duration::from_millis(1));
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
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
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

    /// Advances one gate quantum and runs a hook after its horizon is published.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the bounded async driver, shared-memory
    /// hot path, post-publication hook, or timeout shutdown escalation fails.
    pub(crate) fn advance_to_ceiling_after_publish(
        &mut self,
        ceiling: Icount,
        after_publish: impl FnOnce(
            &mut dyn QemuAsyncNodeStepTarget<PendingQuantum = QemuNodePendingQuantum>,
            &mut QemuNodePendingQuantum,
        ) -> Result<(), QemuNodeChannelError>,
    ) -> Result<AdvanceOutcome, QemuNodeError> {
        if self.channels.shmem_hot_path.coverage_enabled() {
            return Err(QemuNodeError::CoverageEventLogRequired);
        }
        let mut target = QemuNodeAsyncStepTarget {
            child: &mut self.child,
            channels: &mut self.channels,
            lifecycle_state: &mut self.lifecycle_state,
            shutdown_policy: self.shutdown_policy,
        };
        let report = run_bounded_qemu_node_step_with_start_hook(
            &mut target,
            self.host_io_runtime.as_mut(),
            self.async_policy,
            &self.crash_detector,
            ExecutionHorizon { icount: ceiling },
            |target, pending| after_publish(target, pending),
        )
        .map_err(QemuNodeError::from_async_driver)?;
        self.finish_advance_report(ceiling, report)
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
        Vec<crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
        QemuNodeError,
    > {
        self.channels
            .shmem_hot_path
            .drain_pending_selectable_requests()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Enqueues one exact host-authorized selectable reply and resumes QEMU.
    ///
    /// The shared-memory publication precedes the QMP running-state transition,
    /// so the plugin's first resumed-vCPU callback observes and applies the
    /// exact reply before guest execution continues.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the pending token is stale or malformed,
    /// the reply does not fit its guest reservation, shared-memory publication
    /// fails, or QMP cannot acknowledge the running-state transition.
    pub fn enqueue_selectable_reply(
        &mut self,
        pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), QemuNodeError> {
        self.channels
            .shmem_hot_path
            .enqueue_selectable_reply(pending, reply)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        if let Err(source) = self.channels.qmp_machine_control.resume_after_checkpoint() {
            return self.handle_qmp_channel_error(source);
        }
        Ok(())
    }

    /// Returns a copy of the exact host-mirrored selectable catalog plan.
    #[must_use]
    pub fn selectable_catalog_plan(
        &self,
    ) -> Option<crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan> {
        self.channels
            .shmem_hot_path
            .selectable_catalog_plan()
            .cloned()
    }

    /// Reports whether no selectable reply awaits plugin consumption.
    #[must_use]
    pub fn selectable_reply_is_checkpoint_quiescent(&self) -> bool {
        self.channels
            .shmem_hot_path
            .selectable_reply_is_checkpoint_quiescent()
    }

    /// Prepares the paused node's observable stream for authoritative execution.
    ///
    /// Warm-restore setup and boot-barrier priming execute before VMState load
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
        let mut target = QemuNodeAsyncStepTarget {
            child: &mut self.child,
            channels: &mut self.channels,
            lifecycle_state: &mut self.lifecycle_state,
            shutdown_policy: self.shutdown_policy,
        };
        let report = run_bounded_qemu_node_step(
            &mut target,
            self.host_io_runtime.as_mut(),
            self.async_policy,
            &self.crash_detector,
            ExecutionHorizon { icount: ceiling },
        )
        .map_err(QemuNodeError::from_async_driver)?;
        Ok(report)
    }

    fn finish_advance_report(
        &mut self,
        ceiling: Icount,
        report: crate::QemuAsyncNodeStepReport,
    ) -> Result<AdvanceOutcome, QemuNodeError> {
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
        self.last_observed_time = virtual_time_from_advance_outcome(ceiling, advance);
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

    /// Reads the current execution fingerprint through the data path.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the plugin reports an invalid sample,
    /// exits, or does not publish the current boundary's complete sample within
    /// the configured bounded advance-completion timeout.
    pub fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeError> {
        let timeout = self.async_policy.advance_completion_timeout;
        let deadline = HostSupervisionDeadline::start(timeout);
        match self.channels.shmem_hot_path.execution_fingerprint() {
            Ok(fingerprint) => return Ok(fingerprint),
            Err(source) if source.is_retryable() => {
                let remaining = deadline.remaining().ok_or_else(|| {
                    QemuNodeError::from_channel(
                        QemuNodeChannelPlane::ShmemHotPath,
                        QemuNodeChannelError::bounded_await_timeout(
                            "execution_fingerprint",
                            format!(
                                "plugin did not publish the current black-box fingerprint within {timeout:?}: {}",
                                source.message
                            ),
                            timeout,
                        ),
                    )
                })?;
                self.host_io_runtime
                    .publish_current_execution_fingerprint(remaining)
                    .map_err(|source| {
                        QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(
                            source,
                        ))
                    })?;
            }
            Err(source) => {
                return Err(QemuNodeError::from_channel(
                    QemuNodeChannelPlane::ShmemHotPath,
                    source,
                ));
            }
        }
        loop {
            match self.channels.shmem_hot_path.execution_fingerprint() {
                Ok(fingerprint) => return Ok(fingerprint),
                Err(source) if source.is_retryable() && deadline.has_time_remaining() => {
                    match self.child.try_wait_natural_exit() {
                        Ok(None) => std::thread::sleep(Duration::from_millis(1)),
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
                        Err(error) => {
                            return Err(QemuNodeError::from_channel(
                                QemuNodeChannelPlane::ShmemHotPath,
                                QemuNodeChannelError::new(
                                    "execution_fingerprint",
                                    format!("poll QEMU while awaiting fingerprint: {error}"),
                                ),
                            ));
                        }
                    }
                }
                Err(source) if source.is_retryable() => {
                    return Err(QemuNodeError::from_channel(
                        QemuNodeChannelPlane::ShmemHotPath,
                        QemuNodeChannelError::bounded_await_timeout(
                            "execution_fingerprint",
                            format!(
                                "plugin did not publish the current black-box fingerprint within {timeout:?}: {}",
                                source.message
                            ),
                            timeout,
                        ),
                    ));
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
        self.channels
            .shmem_hot_path
            .fingerprint_sample()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Reports whether the real block continuation has work crossing this boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the production host runtime cannot inspect
    /// the block transport or device continuation.
    #[cfg(target_os = "linux")]
    pub(crate) fn has_pending_device_io_for_gate(&mut self) -> Result<bool, QemuNodeError> {
        self.host_io_runtime
            .has_pending_device_io()
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
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

    pub(crate) fn restore_node_continuation(
        &mut self,
        checkpoint: &crate::QemuNodeContinuationCheckpoint,
    ) -> Result<(), QemuNodeError> {
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

    pub(crate) fn checkpoint_network_transport_for_gate(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .checkpoint_network_transport()
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
        self.channels
            .qmp_machine_control
            .resume_after_checkpoint()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    /// Boots a restored generation that was intentionally left powered off.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QMP cannot confirm the running state.
    pub fn boot_powered_off_generation(&mut self) -> Result<(), QemuNodeError> {
        self.resume_after_restore()
    }

    /// Prevents a partially assembled restored node from leaking its child.
    pub(crate) fn reap_failed_realization(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.child.force_kill_and_reap_failed_realization()
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
        if self.child_reaped() {
            return Ok(());
        }
        self.child.send_sigkill().map_err(|error| {
            QemuNodeError::checkpoint(format!("force quarantine kill: {error}"))
        })?;
        match self
            .child
            .reap(self.shutdown_policy.reap_wait)
            .map_err(|error| {
                QemuNodeError::checkpoint(format!("reap quarantined child: {error}"))
            })? {
            QemuReap::Reaped => {
                self.lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
                Ok(())
            }
            QemuReap::StillAlive => Err(QemuNodeError::checkpoint(
                "force-killed quarantined process remained alive past the reap deadline",
            )),
        }
    }

    /// Runs shutdown escalation for the owned child through the node's channels.
    ///
    /// The runner uses plugin IPC `Quit`, QMP `quit`, `SIGTERM`, `SIGKILL`, and
    /// reap in that order. Polite channel failures are recorded by the shutdown
    /// report and do not prevent signal escalation or reap.
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
        if let Some(active_gdbstub) = self.active_gdbstub.take() {
            active_gdbstub.request_shutdown();
        }
        shutdown_node_child(
            &mut self.child,
            &mut self.channels,
            &mut self.lifecycle_state,
            self.shutdown_policy,
        )
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
        let shutdown = self.shutdown_child()?;
        Err(QemuNodeError::Crashed {
            status: Box::new(status),
            shutdown: Box::new(shutdown),
        })
    }
}

#[path = "node/async_step.rs"]
mod async_step;

use async_step::*;

impl Backend for QemuNode {
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.advance_to_ceiling(horizon.icount)
            .map_err(BackendError::from)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        self.execution_fingerprint().map_err(BackendError::from)
    }

    // crucible-lint: allow host-nondeterminism-state -- this adapter forwards an untrusted input to the validated shared-memory channel.
    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError> {
        self.deliver_frame(input).map_err(BackendError::from)
    }

    fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
        Err(BackendError::Rejected {
            message: String::from(
                "QEMU snapshots require capture_exact_snapshot with scheduler checkpoint metadata",
            ),
        })
    }

    fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
        Err(BackendError::Rejected {
            message: String::from("QEMU restore requires paired VMState and host-I/O realization"),
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.shutdown_child()
            .map(|_| ())
            .map_err(BackendError::from)
    }
}

impl SimulationBackend for QemuNode {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        let icount_ceiling = Icount {
            retired: ceiling.ticks,
        };
        if let Some(decision) = self.pending_preemption.as_ref() {
            let command = scheduler_preemption_command(
                decision,
                self.last_observed_time.ticks,
                icount_ceiling.retired,
            )?;
            self.channels
                .shmem_hot_path
                .publish_preemption_command(command)
                .map_err(|source| {
                    QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
                })?;
            self.pending_preemption = None;
        }
        let report = self
            .advance_to_ceiling_report(icount_ceiling)
            .map_err(BackendError::from)?;
        let outcome = self
            .finish_advance_report(icount_ceiling, report)
            .map_err(BackendError::from)?;
        self.console_observation_boundary = ceiling;
        Ok(StepObservation::from_advance_outcome(ceiling, outcome))
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, BackendError> {
        let mut events = self
            .drain_scheduler_observable_events()
            .map_err(BackendError::from)?;
        if let Some(console) = self.console_observation.as_mut() {
            let bytes = console
                .spool
                .take()
                .map_err(|error| BackendError::Rejected {
                    message: format!("take staged QEMU console output: {error}"),
                })?;
            if !bytes.is_empty() {
                events.push(ObservableEvent::console_output(
                    self.console_observation_boundary,
                    console.node.clone(),
                    bytes,
                ));
            }
        }
        Ok(events)
    }

    // crucible-lint: allow host-nondeterminism-state -- the scheduler validates every returned conjecture before append.
    fn drain_causal_decisions(&mut self) -> Result<Vec<Decision>, BackendError> {
        self.channels
            .shmem_hot_path
            .drain_causal_decisions()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source).into()
            })
    }

    fn drain_network_outputs(&mut self) -> Result<Vec<BackendNetworkOutput>, BackendError> {
        let mut outputs = Vec::new();
        for frame in self.pending_network_outputs.drain(..) {
            outputs.push(BackendNetworkOutput {
                source: frame.source,
                destination: frame.destination,
                emit_icount: frame.emit_icount,
                sequence: frame.sequence,
                payload: frame.payload,
                route: None,
                fault_continuation: Default::default(),
            });
        }
        while let Some(frame) = self.emit_frame().map_err(BackendError::from)? {
            self.observe_network_output_sequence(&frame)
                .map_err(BackendError::from)?;
            outputs.push(BackendNetworkOutput {
                source: frame.source,
                destination: frame.destination,
                emit_icount: frame.emit_icount,
                sequence: frame.sequence,
                payload: frame.payload,
                route: None,
                fault_continuation: Default::default(),
            });
        }
        Ok(outputs)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        match effect {
            BackendEffect::DeliverInput(input) => {
                if at < self.last_observed_time {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "qemu backend input at {} is behind physical node time {}",
                            at.ticks, self.last_observed_time.ticks
                        ),
                    });
                }
                self.deliver_frame_at(input.clone(), at)
                    .map_err(BackendError::from)
            }
            BackendEffect::Noop | BackendEffect::Preemption(_) | BackendEffect::Shutdown
                if at != self.last_observed_time =>
            {
                Err(BackendError::Rejected {
                    message: format!(
                        "qemu backend effect at {} does not match physical node time {}",
                        at.ticks, self.last_observed_time.ticks
                    ),
                })
            }
            BackendEffect::Noop => Ok(()),
            BackendEffect::Preemption(decision) => {
                if self.pending_preemption.is_some() {
                    return Err(BackendError::Rejected {
                        message: String::from(
                            "qemu backend already has a pending scheduler preemption",
                        ),
                    });
                }
                self.pending_preemption = Some(decision.clone());
                Ok(())
            }
            BackendEffect::Shutdown => self
                .shutdown_child()
                .map(|_| ())
                .map_err(BackendError::from),
        }
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Err(BackendError::Rejected {
            message: String::from(
                "QEMU snapshots require capture_exact_snapshot with scheduler checkpoint metadata",
            ),
        })
    }

    fn restore(&mut self, _snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        Err(BackendError::Rejected {
            message: String::from("QEMU restore requires paired VMState and host-I/O realization"),
        })
    }

    fn now(&self) -> VirtualTime {
        self.last_observed_time
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        Ok(FingerprintSample {
            node,
            at: self.last_observed_time,
            fingerprint: self.execution_fingerprint().map_err(BackendError::from)?,
        })
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, BackendError> {
        if self.active_gdbstub.is_some() {
            return Err(BackendError::Rejected {
                message: String::from("qemu gdbstub proxy is already active"),
            });
        }
        let Some(gdbstub) = self.gdbstub.as_ref() else {
            return Err(BackendError::Unsupported {
                capability: "open_gdbstub",
            });
        };
        if listen.as_str() != gdbstub.operator_listen() {
            return Err(BackendError::Rejected {
                message: format!(
                    "qemu gdbstub listen {} does not match configured operator listen {}",
                    listen.as_str(),
                    gdbstub.operator_listen()
                ),
            });
        }
        let proxy = QemuGdbstubProxy::new(gdbstub).map_err(|error| BackendError::Rejected {
            message: error.to_string(),
        })?;
        let server = proxy.spawn_one().map_err(|error| BackendError::Rejected {
            message: error.to_string(),
        })?;
        let actual_listen = GdbListen::new(server.local_addr().to_string()).map_err(|error| {
            BackendError::Rejected {
                message: error.to_string(),
            }
        })?;
        let info = GdbAttachInfo::new(node, gdbstub.qemu_endpoint().to_owned(), actual_listen)?;
        self.active_gdbstub = Some(server);
        Ok(info)
    }

    fn send_guest_introspection(
        &mut self,
        _node: &NodeId,
        record: GuestIntrospectionRecord,
    ) -> Result<(), BackendError> {
        QemuNode::send_guest_introspection(self, record).map_err(BackendError::from)
    }

    fn receive_guest_introspection(
        &mut self,
        _node: &NodeId,
    ) -> Result<Option<GuestIntrospectionRecord>, BackendError> {
        QemuNode::receive_guest_introspection(self).map_err(BackendError::from)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        // `BackendQuantumLoop` owns the simulation-backend path and drains
        // every observation into the unified log before invoking this hook.
        // Bypass the public coverage guard here so coverage-enabled nodes can
        // complete teardown after that canonical handoff.
        self.shutdown_child_after_coverage_drain()
            .map(|_| ())
            .map_err(BackendError::from)
    }
}

fn scheduler_preemption_command(
    decision: &crucible::PreemptionDecision,
    deadline_icount: u64,
    ceiling_icount: u64,
) -> Result<SchedulerPreemptionCommand, BackendError> {
    if decision.at.retired < deadline_icount || decision.at.retired > ceiling_icount {
        return Err(BackendError::Rejected {
            message: format!(
                "scheduler preemption at {} is outside backend RUN window [{deadline_icount}, {ceiling_icount}]",
                decision.at.retired
            ),
        });
    }
    let kind = match decision.kind {
        crucible::PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
            ShmemSchedulerPreemptionKind::VcpuSwitch {
                from_vcpu: from_vcpu.index,
                to_vcpu: to_vcpu.index,
            }
        }
        crucible::PreemptionKind::InterruptAt { target_vcpu, irq } => {
            ShmemSchedulerPreemptionKind::InterruptAt {
                target_vcpu: target_vcpu.index,
                irq: irq.vector,
            }
        }
    };
    Ok(SchedulerPreemptionCommand {
        at_icount: decision.at.retired,
        deadline_icount,
        ceiling_icount,
        kind,
    })
}

const fn virtual_time_from_advance_outcome(
    ceiling: Icount,
    outcome: AdvanceOutcome,
) -> VirtualTime {
    match outcome {
        AdvanceOutcome::ReachedHorizon => VirtualTime {
            ticks: ceiling.retired,
        },
        AdvanceOutcome::Paused { at } => VirtualTime { ticks: at.retired },
    }
}

struct QemuNodeShutdownTarget<'a> {
    child: &'a mut QemuNodeProcessControl,
    plugin_control: &'a mut dyn QemuPluginIpcControlChannel,
    qmp_machine_control: &'a mut dyn QemuQmpMachineControlChannel,
}

impl QemuShutdownTarget for QemuNodeShutdownTarget<'_> {
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.plugin_control
            .send_quit()
            .map_err(channel_error_to_shutdown_error)
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.qmp_machine_control
            .quit()
            .map_err(channel_error_to_shutdown_error)
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.child.send_sigterm()
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.child.send_sigkill()
    }

    fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        self.child.wait_for_exit(rung, timeout)
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.child.reap(timeout)
    }
}

fn channel_error_to_shutdown_error(error: QemuNodeChannelError) -> QemuShutdownTargetError {
    QemuShutdownTargetError::new(error.operation, error.message)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "node_tests.rs"]
pub(crate) mod tests;
