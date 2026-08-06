//! Scheduler-facing QEMU node wrapper.
//!
//! The wrapper owns exactly one child handle and the three RFC-0010 QEMU
//! channels for that child: plugin IPC control, shared-memory hot path, and
//! QMP machine control. It exposes the synchronous backend boundary while
//! keeping per-quantum timing and frame traffic on the shared-memory channel.

use std::any::Any;
use std::io::Read as _;
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::process::Child;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput, BackendNetworkOutput,
    BackendSnapshot, Checkpoint, EventLog, ExecutionFingerprint, ExecutionHorizon,
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, NodeId, ObservableEvent,
    SchedulerEventLogAppend, SimulationBackend, StepObservation, VirtualTime,
};
use crucible_shmem::{
    DequeuedFaultResult, FaultCapabilityRowV1, FaultCommandHeaderV1, FaultResultStatus,
    SchedulerPreemptionCommand, SchedulerPreemptionKind as ShmemSchedulerPreemptionKind,
};
// crucible-lint: allow host-nondeterminism-state -- node transport exposes untrusted causal records for scheduler validation.
use crucible::Decision;

use crate::shutdown::{
    QemuChildWait, QemuReap, QemuShutdownPolicy, QemuShutdownReport, QemuShutdownRung,
    QemuShutdownTarget, QemuShutdownTargetError, shutdown_qemu_child, signal_child, wait_child,
};
use crate::{
    QemuAsyncCrashEscalationTarget, QemuAsyncDriverPolicy, QemuAsyncDriverTargetError,
    QemuAsyncNodeStepOutcome, QemuAsyncNodeStepTarget, QemuAsyncQuantumCompletion,
    QemuCrashDetector, QemuGdbstubChannelConfig, QemuGdbstubProxy, QemuGdbstubProxyServer,
    QemuHostIoRuntime, run_bounded_qemu_node_step,
};

mod error;
pub use error::{QemuNodeChannelError, QemuNodeChannelPlane, QemuNodeError};

/// Lifecycle state tracked by the host wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QemuNodeLifecycleState {
    /// The child is expected to be available for scheduler operations.
    Running,
    /// The node has completed the shutdown escalation and reaped the child.
    ShutdownRequested,
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

/// Plugin IPC control channel for setup and teardown only.
pub trait QemuPluginIpcControlChannel: Send {
    /// Sends the plugin IPC `Quit` control message.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the control channel cannot accept
    /// the teardown request.
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError>;
}

/// Shared-memory hot-path channel for per-quantum data.
pub trait QemuShmemHotPathChannel: Send {
    /// Returns whether this channel owns a plugin-to-host coverage queue.
    ///
    /// The registration-time value is immutable. Direct node APIs use it to
    /// reject an advance before guest execution when no unified-log owner was
    /// supplied.
    fn coverage_enabled(&self) -> bool {
        false
    }

    /// Reads the node's current retired-instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory state cannot be
    /// observed.
    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError>;

    /// Starts a split quantum by publishing `horizon` through shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory hot path cannot
    /// publish the scheduler ceiling or wake the plugin.
    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError>;

    /// Polls a split quantum without consuming its pending token.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory completion report
    /// cannot be read or is not yet visible.
    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError>;

    /// Finishes a split quantum after the bounded host-I/O runtime completes.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory completion report
    /// cannot be read.
    fn finish_quantum(
        &mut self,
        mut pending: QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        self.poll_quantum(&mut pending)
    }

    /// Publishes one scheduler-commanded preemption before its bounded RUN.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the command is invalid or a prior
    /// command remains unconsumed.
    fn publish_preemption_command(
        &mut self,
        command: SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError>;

    /// Publishes one authenticated fault command at a scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the fault transport is absent,
    /// full, corrupt, or rejects the command envelope.
    fn enqueue_fault_command(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuNodeChannelError>;

    /// Removes one completed fault result from the lossless result transport.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the result transport is absent or
    /// corrupt.
    fn dequeue_fault_result(&mut self)
    -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError>;

    /// Advances the node to `horizon` or until it pauses earlier.
    ///
    /// This helper is retained for direct channel tests and already-completed
    /// quanta. [`QemuNode`] uses the split methods through the bounded async
    /// driver.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory advance request
    /// cannot complete.
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, QemuNodeChannelError> {
        let pending = self.start_quantum(horizon)?;
        self.finish_quantum(pending)
            .map(|completion| completion.outcome)
    }

    /// Drains coverage observations at the current completed boundary.
    ///
    /// Implementations without an enabled coverage transport return an empty
    /// batch. The caller must append a non-empty batch to the unified event log
    /// before continuing or tearing down the node.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared coverage ring is corrupt
    /// or contains an observation after the published boundary.
    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        Ok(Vec::new())
    }

    /// Drains causal decisions completed by synchronous guest callbacks.
    ///
    /// Implementations without a white-box app-random transport return an empty
    /// batch. The authoritative scheduler must validate and append every
    /// returned decision before another quantum begins.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the causal transport is corrupt or
    /// contains an entry after the completed boundary.
    // crucible-lint: allow host-nondeterminism-state -- this boundary returns values without admitting them into engine state.
    fn drain_causal_decisions(&mut self) -> Result<Vec<Decision>, QemuNodeChannelError> {
        Ok(Vec::new())
    }

    /// Delivers a deterministic frame through the shared-memory input ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the frame cannot be delivered.
    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError>;

    /// Delivers a deterministic frame at its scheduler-resolved instruction count.
    ///
    /// Channels that do not expose timestamped injection may inherit the legacy
    /// boundary-relative delivery behavior. Production shared-memory channels
    /// override this method so the event-log timestamp reaches QEMU unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the frame cannot be delivered at
    /// `delivery_icount`.
    fn deliver_frame_at(
        &mut self,
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<(), QemuNodeChannelError> {
        let _ = delivery_icount;
        self.deliver_frame(input)
    }

    /// Reads one emitted frame from the shared-memory output ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the output ring cannot be read.
    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError>;

    /// Reads the current idle state from shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the idle state cannot be observed.
    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError>;

    /// Reads the current execution fingerprint from the shared-memory data path.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the fingerprint cannot be read.
    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError>;
}

/// Type-erased token returned after a shared-memory quantum is started.
pub struct QemuNodePendingQuantum {
    token: Box<dyn Any>,
}

impl QemuNodePendingQuantum {
    /// Wraps a concrete pending-quantum token.
    #[must_use]
    pub fn new<T>(token: T) -> Self
    where
        T: Any,
    {
        Self {
            token: Box::new(token),
        }
    }

    /// Recovers the concrete token expected by the finishing channel.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the token came from a different
    /// shared-memory channel implementation.
    pub fn downcast_mut<T>(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut T, QemuNodeChannelError>
    where
        T: Any,
    {
        self.token.downcast_mut().ok_or_else(|| {
            QemuNodeChannelError::new(operation, "pending quantum token type mismatch")
        })
    }
}

/// QMP machine-control channel for snapshot and quit commands.
pub trait QemuQmpMachineControlChannel: Send {
    /// Captures the VM-state half of a checkpoint through QMP.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot save the checkpoint.
    fn save_checkpoint(&mut self) -> Result<Checkpoint, QemuNodeChannelError>;

    /// Restores the VM-state half of `checkpoint` through QMP.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot restore the checkpoint.
    fn restore_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), QemuNodeChannelError>;

    /// Requests QEMU termination through QMP `quit`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot send the quit command.
    fn quit(&mut self) -> Result<(), QemuNodeChannelError>;
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
    output: UnixStream,
}

/// Host-side wrapper exposing one QEMU child as a synchronous scheduler node.
pub struct QemuNode {
    child: QemuNodeChild,
    channels: QemuNodeChannels,
    lifecycle_state: QemuNodeLifecycleState,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
    crash_detector: QemuCrashDetector,
    host_io_runtime: Box<dyn QemuHostIoRuntime>,
    last_observed_time: VirtualTime,
    // Console polling proves availability only at the scheduler-requested boundary.
    console_observation_boundary: VirtualTime,
    gdbstub: Option<QemuGdbstubChannelConfig>,
    active_gdbstub: Option<QemuGdbstubProxyServer>,
    pending_preemption: Option<crucible::PreemptionDecision>,
    pending_network_outputs: Vec<QemuNodeEmittedFrame>,
    console_observation: Option<QemuConsoleObservation>,
    fault_capabilities: Vec<FaultCapabilityRowV1>,
    next_fault_command_sequence: u64,
}

impl QemuNode {
    /// Builds a QEMU scheduler node from one owned child handle and its channels.
    #[must_use]
    pub fn new(
        child: QemuNodeChild,
        channels: QemuNodeChannels,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
        host_io_runtime: impl QemuHostIoRuntime + 'static,
    ) -> Self {
        Self {
            child,
            channels,
            lifecycle_state: QemuNodeLifecycleState::Running,
            shutdown_policy,
            async_policy,
            crash_detector,
            host_io_runtime: Box::new(host_io_runtime),
            last_observed_time: VirtualTime::default(),
            console_observation_boundary: VirtualTime::default(),
            gdbstub: None,
            active_gdbstub: None,
            pending_preemption: None,
            pending_network_outputs: Vec::new(),
            console_observation: None,
            fault_capabilities: Vec::new(),
            // Sequence 1 is consumed by the mandatory setup-time capability
            // query before a live node can be constructed.
            next_fault_command_sequence: 2,
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

    /// Restores the next fault-command sequence paired with a VM checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when `sequence` would reuse setup-time or
    /// already-reserved command identities.
    pub fn restore_fault_command_sequence(&mut self, sequence: u64) -> Result<(), QemuNodeError> {
        if sequence < 2 {
            return Err(QemuNodeError::fault_command(
                "restored fault command sequence precedes capability admission",
            ));
        }
        self.next_fault_command_sequence = sequence;
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
        let result = self
            .host_io_runtime
            .await_fault_result(self.async_policy.advance_completion_timeout)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
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

    /// Returns this node with output-only console bytes exposed as observations.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QEMU console stream cannot be
    /// configured for non-blocking boundary reads.
    pub fn with_console_observation(
        mut self,
        node: NodeId,
        output: UnixStream,
    ) -> Result<Self, QemuNodeChannelError> {
        output.set_nonblocking(true).map_err(|error| {
            QemuNodeChannelError::new("configure QEMU console stream", error.to_string())
        })?;
        self.console_observation = Some(QemuConsoleObservation { node, output });
        Ok(self)
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
    pub const fn child_reaped(&self) -> bool {
        self.child.reaped()
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
    pub(crate) fn retain_priming_network_outputs(&mut self, outputs: Vec<QemuNodeEmittedFrame>) {
        self.pending_network_outputs.extend(outputs);
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
        let events = self
            .channels
            .shmem_hot_path
            .drain_observable_events()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        let appended = event_log
            .append_observable_events(events)
            .map_err(|source| QemuNodeError::CoverageEventLog {
                message: source.to_string(),
            })?;
        let outcome = self.finish_advance_report(ceiling, report)?;
        Ok((outcome, appended))
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
    /// Returns [`QemuNodeError`] when the fingerprint cannot be read.
    pub fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .execution_fingerprint()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Captures a checkpoint through QMP machine control.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QMP cannot save the checkpoint.
    pub fn save_checkpoint(&mut self) -> Result<Checkpoint, QemuNodeError> {
        match self.channels.qmp_machine_control.save_checkpoint() {
            Ok(mut checkpoint) => {
                checkpoint.virtual_time = self.last_observed_time;
                Ok(checkpoint)
            }
            Err(source) => self.handle_qmp_channel_error(source),
        }
    }

    /// Restores a checkpoint through QMP machine control.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QMP cannot restore `checkpoint`.
    pub fn restore_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), QemuNodeError> {
        match self
            .channels
            .qmp_machine_control
            .restore_checkpoint(checkpoint)
        {
            Ok(()) => {
                self.last_observed_time = checkpoint.virtual_time;
                Ok(())
            }
            Err(source) => self.handle_qmp_channel_error(source),
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
        let events = self
            .channels
            .shmem_hot_path
            .drain_observable_events()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        let appended = event_log
            .append_observable_events(events)
            .map_err(|source| QemuNodeError::CoverageEventLog {
                message: source.to_string(),
            })?;
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

struct QemuNodeAsyncStepTarget<'a> {
    child: &'a mut QemuNodeChild,
    channels: &'a mut QemuNodeChannels,
    lifecycle_state: &'a mut QemuNodeLifecycleState,
    shutdown_policy: QemuShutdownPolicy,
}

impl QemuAsyncCrashEscalationTarget for QemuNodeAsyncStepTarget<'_> {
    fn shutdown_after_crash(&mut self) -> Result<QemuShutdownReport, QemuAsyncDriverTargetError> {
        shutdown_node_child(
            self.child,
            self.channels,
            self.lifecycle_state,
            self.shutdown_policy,
        )
        .map_err(|error| QemuAsyncDriverTargetError::new("shutdown after crash", error.to_string()))
    }
}

impl QemuAsyncNodeStepTarget for QemuNodeAsyncStepTarget<'_> {
    type PendingQuantum = QemuNodePendingQuantum;

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<Self::PendingQuantum, QemuNodeChannelError> {
        self.channels.shmem_hot_path.start_quantum(horizon)
    }

    fn finish_quantum(
        &mut self,
        pending: &mut Self::PendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        self.channels.shmem_hot_path.poll_quantum(pending)
    }
}

fn shutdown_node_child(
    child: &mut QemuNodeChild,
    channels: &mut QemuNodeChannels,
    lifecycle_state: &mut QemuNodeLifecycleState,
    shutdown_policy: QemuShutdownPolicy,
) -> Result<QemuShutdownReport, QemuNodeError> {
    if child.reaped() {
        *lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
        return Ok(QemuShutdownReport {
            attempts: Vec::new(),
            failures: Vec::new(),
            reaped: true,
            leaked: false,
        });
    }

    let mut target = QemuNodeShutdownTarget {
        child,
        plugin_control: channels.plugin_control.as_mut(),
        qmp_machine_control: channels.qmp_machine_control.as_mut(),
    };
    let report =
        shutdown_qemu_child(&mut target, shutdown_policy).map_err(QemuNodeError::from_shutdown)?;
    *lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
    Ok(report)
}

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
        self.save_checkpoint().map_err(BackendError::from)
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<(), BackendError> {
        self.restore_checkpoint(checkpoint)
            .map_err(BackendError::from)
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
            .channels
            .shmem_hot_path
            .drain_observable_events()
            .map_err(|source| {
                BackendError::from(QemuNodeError::from_channel(
                    QemuNodeChannelPlane::ShmemHotPath,
                    source,
                ))
            })?;
        if let Some(console) = self.console_observation.as_mut() {
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                match console.output.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        return Err(BackendError::Rejected {
                            message: format!("read QEMU console output: {error}"),
                        });
                    }
                }
            }
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
            });
        }
        while let Some(frame) = self.emit_frame().map_err(BackendError::from)? {
            outputs.push(BackendNetworkOutput {
                source: frame.source,
                destination: frame.destination,
                emit_icount: frame.emit_icount,
                sequence: frame.sequence,
                payload: frame.payload,
                route: None,
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
        self.save_checkpoint()
            .map(BackendSnapshot::new)
            .map_err(BackendError::from)
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        self.restore_checkpoint(&snapshot.checkpoint)
            .map_err(BackendError::from)
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
    child: &'a mut QemuNodeChild,
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
mod tests {
    use std::collections::VecDeque;
    use std::error::Error;
    use std::net::TcpListener;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crucible::{
        CheckpointKind, ContentHash, EventLogCoverageObservation, ExecutionHorizon, GdbListen,
        NodeId, event_log_coverage_projection,
    };
    use crucible_shmem::{
        FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_SEMANTIC_VERSION,
        FaultBoundaryPhase, FaultCapabilityScope, FaultCommandKind, FaultResultHeaderV1,
    };

    use crate::{
        QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuQuantumOperation,
    };

    use super::*;

    mod shutdown_and_preemption;

    type SharedLog = Arc<Mutex<Vec<ChannelCall>>>;
    type SharedFaultCommands = Arc<Mutex<Vec<(FaultCommandHeaderV1, Vec<u8>)>>>;

    #[test]
    fn child_poll_preserves_clean_exit_status_and_disarms_drop_cleanup()
    -> Result<(), Box<dyn Error>> {
        let child = Command::new("true").spawn()?;
        let mut child = QemuNodeChild::new(child);
        wait_for_test_child_exit_pending(&child)?;
        let status = child
            .try_wait_natural_exit()?
            .ok_or("child remained live after closing its output pipe")?;

        assert!(status.success());
        assert!(child.reaped());
        drop(child);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn child_poll_preserves_signal_termination_as_unclean() -> Result<(), Box<dyn Error>> {
        use std::os::unix::process::ExitStatusExt as _;

        let child = Command::new("sleep").arg("60").spawn()?;
        let mut child = QemuNodeChild::new(child);
        signal_child(
            child.child.id(),
            libc::SIGTERM,
            "terminate child test fixture",
        )?;
        wait_for_test_child_exit_pending(&child)?;
        let status = child
            .try_wait_natural_exit()?
            .ok_or("signaled child remained live after closing its output pipe")?;

        assert!(!status.success());
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(child.reaped());
        Ok(())
    }

    fn wait_for_test_child_exit_pending(child: &QemuNodeChild) -> Result<(), Box<dyn Error>> {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

        let pid = Pid::from_child(&child.child);
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )?
        .ok_or("waitid returned no status for a blocking child-exit wait")?;
        Ok(())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ChannelCall {
        ShmemCurrentIcount,
        HostYield,
        HostAwait {
            wait: QemuAsyncWait,
            timeout: Duration,
            outcome: QemuAsyncWaitOutcome,
        },
        ShmemStart(u64),
        ShmemFinish(u64),
        ShmemPreemption(SchedulerPreemptionCommand),
        ShmemDeliver {
            node: String,
            payload: Vec<u8>,
        },
        ShmemEmit,
        ShmemIdle,
        ShmemFingerprint,
        QmpSnapshot,
        QmpRestore(ContentHash),
        PluginQuit,
        QmpQuit,
    }

    #[derive(Clone)]
    struct ScriptedPluginControl {
        log: SharedLog,
        fail_quit: bool,
    }

    #[derive(Clone)]
    struct ScriptedShmemHotPath {
        log: SharedLog,
        fail_advance: bool,
        coverage_enabled: bool,
        quantum_coverage: Arc<Mutex<VecDeque<Vec<ObservableEvent>>>>,
        teardown_coverage: Arc<Mutex<Vec<ObservableEvent>>>,
        fault_commands: SharedFaultCommands,
        stale_fault_results: Arc<Mutex<VecDeque<DequeuedFaultResult>>>,
    }

    #[derive(Clone)]
    struct ScriptedHostIoRuntime {
        log: SharedLog,
        outcomes: VecDeque<QemuAsyncWaitOutcome>,
        fault_results: VecDeque<DequeuedFaultResult>,
    }

    #[derive(Clone)]
    struct ScriptedQmpMachineControl {
        log: SharedLog,
        fail_snapshot: bool,
        timeout_snapshot: bool,
    }

    impl QemuPluginIpcControlChannel for ScriptedPluginControl {
        fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
            self.log.lock().unwrap().push(ChannelCall::PluginQuit);
            if self.fail_quit {
                return Err(QemuNodeChannelError::new("send_quit", "control closed"));
            }
            Ok(())
        }
    }

    impl QemuShmemHotPathChannel for ScriptedShmemHotPath {
        fn coverage_enabled(&self) -> bool {
            self.coverage_enabled
        }

        fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
            self.log
                .lock()
                .unwrap()
                .push(ChannelCall::ShmemCurrentIcount);
            Ok(Icount { retired: 11 })
        }

        fn start_quantum(
            &mut self,
            horizon: ExecutionHorizon,
        ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
            self.log
                .lock()
                .unwrap()
                .push(ChannelCall::ShmemStart(horizon.icount.retired));
            if self.fail_advance {
                return Err(QemuNodeChannelError::new(
                    "advance_to_horizon",
                    "futex wake failed",
                ));
            }
            Ok(QemuNodePendingQuantum::new(horizon.icount.retired))
        }

        fn poll_quantum(
            &mut self,
            pending: &mut QemuNodePendingQuantum,
        ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
            let horizon = *pending.downcast_mut::<u64>("finish_quantum")?;
            self.log
                .lock()
                .unwrap()
                .push(ChannelCall::ShmemFinish(horizon));
            if let Some(events) = self.quantum_coverage.lock().unwrap().pop_front() {
                self.teardown_coverage.lock().unwrap().extend(events);
            }
            Ok(QemuAsyncQuantumCompletion {
                outcome: AdvanceOutcome::ReachedHorizon,
                emitted_frames: Vec::new(),
                operations: vec![
                    QemuQuantumOperation::StoreSchedulerCeiling,
                    QemuQuantumOperation::FutexWake,
                    QemuQuantumOperation::ObservePluginReport,
                ],
            })
        }

        fn publish_preemption_command(
            &mut self,
            command: SchedulerPreemptionCommand,
        ) -> Result<(), QemuNodeChannelError> {
            self.log
                .lock()
                .unwrap()
                .push(ChannelCall::ShmemPreemption(command));
            Ok(())
        }

        fn enqueue_fault_command(
            &mut self,
            header: FaultCommandHeaderV1,
            payload: &[u8],
        ) -> Result<(), QemuNodeChannelError> {
            self.fault_commands
                .lock()
                .unwrap()
                .push((header, payload.to_vec()));
            Ok(())
        }

        fn dequeue_fault_result(
            &mut self,
        ) -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError> {
            Ok(self.stale_fault_results.lock().unwrap().pop_front())
        }

        fn drain_observable_events(
            &mut self,
        ) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
            Ok(std::mem::take(&mut *self.teardown_coverage.lock().unwrap()))
        }

        fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
            self.log.lock().unwrap().push(ChannelCall::ShmemDeliver {
                node: input.node.name,
                payload: input.payload,
            });
            Ok(())
        }

        fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
            self.log.lock().unwrap().push(ChannelCall::ShmemEmit);
            Ok(Some(QemuNodeEmittedFrame {
                source: node_id("vm-a"),
                destination: node_id("vm-b"),
                emit_icount: Icount { retired: 17 },
                sequence: 7,
                payload: vec![8, 9],
            }))
        }

        fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
            self.log.lock().unwrap().push(ChannelCall::ShmemIdle);
            Ok(QemuNodeIdleState {
                current_icount: Icount { retired: 13 },
                next_deadline: Some(Icount { retired: 21 }),
            })
        }

        fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
            self.log.lock().unwrap().push(ChannelCall::ShmemFingerprint);
            Ok(ExecutionFingerprint {
                hash: content_hash("fingerprint", "vm-a"),
            })
        }
    }

    impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
        fn save_checkpoint(&mut self) -> Result<Checkpoint, QemuNodeChannelError> {
            self.log.lock().unwrap().push(ChannelCall::QmpSnapshot);
            if self.timeout_snapshot {
                return Err(QemuNodeChannelError::bounded_await_timeout(
                    "save_checkpoint",
                    "QMP command timed out",
                    Duration::from_millis(2),
                ));
            }
            if self.fail_snapshot {
                return Err(QemuNodeChannelError::new("save_checkpoint", "QMP error"));
            }
            Ok(checkpoint("snapshot"))
        }

        fn restore_checkpoint(
            &mut self,
            checkpoint: &Checkpoint,
        ) -> Result<(), QemuNodeChannelError> {
            self.log
                .lock()
                .unwrap()
                .push(ChannelCall::QmpRestore(checkpoint.id));
            Ok(())
        }

        fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
            self.log.lock().unwrap().push(ChannelCall::QmpQuit);
            Ok(())
        }
    }

    impl QemuHostIoRuntime for ScriptedHostIoRuntime {
        fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
            self.log.lock().unwrap().push(ChannelCall::HostYield);
            Ok(())
        }

        fn await_child(
            &mut self,
            wait: QemuAsyncWait,
            timeout: Duration,
        ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
            let outcome = self.outcomes.pop_front().ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new("await child", "no scripted outcome")
            })?;
            self.log.lock().unwrap().push(ChannelCall::HostAwait {
                wait,
                timeout,
                outcome,
            });
            Ok(outcome)
        }

        fn repoll_child(
            &mut self,
            wait: QemuAsyncWait,
            timeout: Duration,
        ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
            self.await_child(wait, timeout)
        }

        fn await_fault_result(
            &mut self,
            _timeout: Duration,
        ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
            self.fault_results.pop_front().ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new("await fault result", "no scripted fault result")
            })
        }
    }

    #[test]
    fn qemu_node_owns_one_child_and_exactly_three_channel_roles() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

        assert_eq!(
            node.channel_roles(),
            [
                QemuNodeChannelPlane::PluginIpcControl,
                QemuNodeChannelPlane::ShmemHotPath,
                QemuNodeChannelPlane::QmpMachineControl,
            ]
        );
        assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
        assert!(!node.child_reaped());
        assert!(recorded(&log).is_empty());

        let report = node.shutdown_child()?;
        assert!(report.reaped);
        assert!(node.child_reaped());
        assert_eq!(
            report
                .attempts
                .iter()
                .map(|attempt| attempt.rung)
                .collect::<Vec<_>>(),
            [
                QemuShutdownRung::ControlQuit,
                QemuShutdownRung::QmpQuit,
                QemuShutdownRung::Sigterm,
            ]
        );
        assert_eq!(
            node.lifecycle_state(),
            QemuNodeLifecycleState::ShutdownRequested
        );

        Ok(())
    }

    #[test]
    fn live_fault_sequences_continue_after_capability_admission() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

        assert_eq!(node.reserve_fault_command_sequence()?, 2);
        assert_eq!(node.reserve_fault_command_sequence()?, 3);

        Ok(())
    }

    #[test]
    fn fault_command_applies_at_exact_current_boundary_without_guest_progress()
    -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let fault_commands = Arc::new(Mutex::new(Vec::new()));
        let payload = vec![1_u8, 2, 3, 4];
        let command = FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::MemoryMutation,
            command_flags: 0,
            phase: FaultBoundaryPhase::NodeBoundary,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 7,
            target_node_hash: [1; 32],
            target_icount: 11,
            authorization_ceiling_icount: 11,
            binding_hash: [2; 32],
            opportunity_hash: [3; 32],
            expected_precondition_hash: [4; 32],
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload_offset: 0,
            payload_length: u32::try_from(payload.len())?,
        };
        let result = DequeuedFaultResult::Valid {
            header: FaultResultHeaderV1 {
                abi_major: FAULT_COMMAND_ABI_MAJOR,
                abi_minor: FAULT_COMMAND_ABI_MINOR,
                command_kind: FaultCommandKind::MemoryMutation as u16,
                status: FaultResultStatus::Applied,
                semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
                command_sequence: 7,
                observed_icount: 11,
                applied_icount: 11,
                capability_version: 1,
                phase: FaultBoundaryPhase::NodeBoundary,
                before_hash: [4; 32],
                after_hash: [5; 32],
                evidence_hash: [6; 32],
                result_payload_hash: *blake3::hash(&[]).as_bytes(),
                result_offset: 0,
                result_length: 0,
            },
            payload: Vec::new(),
        };
        let channels = QemuNodeChannels::new(
            ScriptedPluginControl {
                log: Arc::clone(&log),
                fail_quit: false,
            },
            ScriptedShmemHotPath {
                log: Arc::clone(&log),
                fail_advance: false,
                coverage_enabled: false,
                quantum_coverage: Arc::new(Mutex::new(VecDeque::new())),
                teardown_coverage: Arc::new(Mutex::new(Vec::new())),
                fault_commands: Arc::clone(&fault_commands),
                stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            },
            ScriptedQmpMachineControl {
                log: Arc::clone(&log),
                fail_snapshot: false,
                timeout_snapshot: false,
            },
        );
        let child = Command::new("sleep").arg("60").spawn()?;
        let mut node = QemuNode::new(
            QemuNodeChild::new(child),
            channels,
            node_shutdown_policy(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("vm-a"),
            ScriptedHostIoRuntime {
                log,
                outcomes: VecDeque::new(),
                fault_results: VecDeque::from([result.clone()]),
            },
        )
        .with_fault_capabilities(vec![FaultCapabilityRowV1 {
            command_kind: FaultCommandKind::MemoryMutation,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            scope: FaultCapabilityScope::All,
            phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
            maximum_payload_bytes: 64,
            maximum_pending_commands: 1,
            required_feature_bits: 0,
            capability_hash: [7; 32],
        }]);

        assert_eq!(
            node.apply_fault_command_at_current_boundary(command.clone(), &payload)?,
            result
        );
        assert_eq!(*fault_commands.lock().unwrap(), vec![(command, payload)]);
        Ok(())
    }

    #[test]
    fn qemu_node_routes_scheduler_operations_over_strict_channels() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

        assert_eq!(node.current_icount()?, Icount { retired: 11 });
        assert_eq!(
            Backend::advance_to_horizon(
                &mut node,
                ExecutionHorizon {
                    icount: Icount { retired: 19 },
                },
            )?,
            AdvanceOutcome::ReachedHorizon
        );
        Backend::deliver_input(
            &mut node,
            BackendInput {
                node: node_id("vm-a"),
                payload: vec![1, 2, 3],
            },
        )?;
        assert_eq!(
            node.emit_frame()?,
            Some(QemuNodeEmittedFrame {
                source: node_id("vm-a"),
                destination: node_id("vm-b"),
                emit_icount: Icount { retired: 17 },
                sequence: 7,
                payload: vec![8, 9],
            })
        );
        assert_eq!(
            node.idle_state()?,
            QemuNodeIdleState {
                current_icount: Icount { retired: 13 },
                next_deadline: Some(Icount { retired: 21 }),
            }
        );
        assert_eq!(
            Backend::fingerprint(&mut node)?,
            ExecutionFingerprint {
                hash: content_hash("fingerprint", "vm-a"),
            }
        );

        let saved = Backend::snapshot(&mut node)?;
        assert_eq!(saved.id, checkpoint("snapshot").id);
        assert_eq!(saved.virtual_time, VirtualTime { ticks: 19 });
        Backend::restore(&mut node, &saved)?;
        let report = node.shutdown_child()?;

        assert!(report.reaped);
        assert_eq!(
            node.lifecycle_state(),
            QemuNodeLifecycleState::ShutdownRequested
        );
        assert_eq!(
            recorded(&log),
            vec![
                ChannelCall::ShmemCurrentIcount,
                ChannelCall::HostYield,
                ChannelCall::ShmemStart(19),
                ChannelCall::HostAwait {
                    wait: QemuAsyncWait::AdvanceCompletion,
                    timeout: Duration::from_millis(4),
                    outcome: QemuAsyncWaitOutcome::Completed,
                },
                ChannelCall::ShmemFinish(19),
                ChannelCall::HostYield,
                ChannelCall::ShmemDeliver {
                    node: String::from("vm-a"),
                    payload: vec![1, 2, 3],
                },
                ChannelCall::ShmemEmit,
                ChannelCall::ShmemIdle,
                ChannelCall::ShmemFingerprint,
                ChannelCall::QmpSnapshot,
                ChannelCall::QmpRestore(content_hash("checkpoint", "snapshot")),
                ChannelCall::PluginQuit,
                ChannelCall::QmpQuit,
            ]
        );

        Ok(())
    }

    #[test]
    fn qemu_node_appends_quantum_coverage_to_the_unified_event_log() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let event =
            ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
        let mut node = scripted_node_with_coverage(
            Arc::clone(&log),
            ScriptedNodeOptions::default(),
            [QemuAsyncWaitOutcome::Completed],
            [vec![event]],
            std::iter::empty(),
        )?;
        let mut event_log = EventLog::new();

        let (outcome, append) =
            node.advance_to_ceiling_with_event_log(Icount { retired: 19 }, &mut event_log)?;

        assert_eq!(outcome, AdvanceOutcome::ReachedHorizon);
        assert_eq!(append.entries.len(), 1);
        let projection = event_log_coverage_projection(&append.entries);
        assert_eq!(projection.len(), 1);
        assert_eq!(projection.entries()[0].at.icount, Icount { retired: 17 });
        assert_eq!(
            projection.entries()[0].observation,
            EventLogCoverageObservation::BasicBlock {
                node: node_id("vm-a"),
                guest_pc: 0x4010,
                block_len: 4,
            }
        );
        let (shutdown, _final_append) = node.shutdown_child_with_event_log(&mut event_log)?;
        assert!(shutdown.reaped);
        Ok(())
    }

    #[test]
    fn qemu_node_rejects_a_coverage_quantum_without_an_event_log() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let event =
            ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
        let mut node = scripted_node_with_coverage(
            Arc::clone(&log),
            ScriptedNodeOptions::default(),
            [QemuAsyncWaitOutcome::Completed],
            [vec![event]],
            std::iter::empty(),
        )?;

        assert_eq!(
            node.advance_to_ceiling(Icount { retired: 19 }),
            Err(QemuNodeError::CoverageEventLogRequired)
        );
        let mut event_log = EventLog::new();
        let (shutdown, append) = node.shutdown_child_with_event_log(&mut event_log)?;
        assert!(shutdown.reaped);
        assert!(append.entries.is_empty());
        Ok(())
    }

    #[test]
    fn qemu_node_generic_backend_drains_coverage_without_a_local_side_record()
    -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let event =
            ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
        let mut node = scripted_node_with_coverage(
            Arc::clone(&log),
            ScriptedNodeOptions::default(),
            [QemuAsyncWaitOutcome::Completed],
            [vec![event]],
            std::iter::empty(),
        )?;

        let step = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 19 })?;
        assert_eq!(step.reached, VirtualTime { ticks: 19 });
        let observations = SimulationBackend::drain_observable_events(&mut node)?;
        assert_eq!(observations.len(), 1);
        assert!(SimulationBackend::drain_observable_events(&mut node)?.is_empty());

        let mut event_log = EventLog::new();
        let append = event_log.append_observable_events(observations)?;
        assert_eq!(event_log_coverage_projection(&append.entries).len(), 1);
        SimulationBackend::shutdown(&mut node)?;
        assert!(node.child_reaped());
        SimulationBackend::shutdown(&mut node)?;
        assert!(node.child_reaped());
        Ok(())
    }

    #[test]
    fn qemu_node_stamps_polled_console_at_the_scheduler_boundary() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let (mut console_writer, console_reader) = UnixStream::pair()?;
        std::io::Write::write_all(&mut console_writer, b"guest output")?;
        let mut node = scripted_node_with_options(
            log,
            ScriptedNodeOptions::default(),
            [QemuAsyncWaitOutcome::Completed],
        )?
        .with_console_observation(node_id("vm-a"), console_reader)?;

        let boundary = VirtualTime { ticks: 97 };
        SimulationBackend::step_to(&mut node, boundary)?;
        node.last_observed_time = VirtualTime { ticks: 3 };
        let observations = SimulationBackend::drain_observable_events(&mut node)?;

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].at(), boundary);
        SimulationBackend::shutdown(&mut node)?;
        Ok(())
    }

    #[test]
    fn qemu_node_drains_final_coverage_before_teardown() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let event =
            ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
        let mut node = scripted_node_with_coverage(
            Arc::clone(&log),
            ScriptedNodeOptions::default(),
            std::iter::empty(),
            std::iter::empty(),
            [event],
        )?;
        let mut event_log = EventLog::new();

        let (report, append) = node.shutdown_child_with_event_log(&mut event_log)?;

        assert!(report.reaped);
        assert!(node.child_reaped());
        let projection = event_log_coverage_projection(&append.entries);
        assert_eq!(projection.len(), 1);
        assert_eq!(projection.entries()[0].at.icount, Icount { retired: 17 });
        Ok(())
    }

    #[test]
    fn qemu_node_satisfies_simulation_backend_trait() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node_with_runtime(
            Arc::clone(&log),
            false,
            false,
            false,
            [
                QemuAsyncWaitOutcome::Completed,
                QemuAsyncWaitOutcome::Completed,
            ],
        )?;

        let observation = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 23 })?;
        assert_eq!(observation.reached, VirtualTime { ticks: 23 });
        assert_eq!(SimulationBackend::now(&node), VirtualTime { ticks: 23 });

        assert!(matches!(
            SimulationBackend::apply(
                &mut node,
                &BackendEffect::Noop,
                VirtualTime { ticks: 22 },
            ),
            Err(BackendError::Rejected { message })
                if message.contains("does not match physical node time")
        ));
        SimulationBackend::apply(
            &mut node,
            &BackendEffect::DeliverInput(BackendInput {
                node: node_id("vm-a"),
                payload: vec![3, 2, 1],
            }),
            VirtualTime { ticks: 23 },
        )?;
        let sample = SimulationBackend::fingerprint(&mut node, node_id("vm-a"))?;
        assert_eq!(sample.node, node_id("vm-a"));
        assert_eq!(sample.at, VirtualTime { ticks: 23 });
        assert_eq!(
            sample.fingerprint,
            ExecutionFingerprint {
                hash: content_hash("fingerprint", "vm-a"),
            }
        );

        let snapshot = SimulationBackend::snapshot(&mut node)?;
        assert_eq!(snapshot.checkpoint.id, checkpoint("snapshot").id);
        assert_eq!(snapshot.checkpoint.virtual_time, VirtualTime { ticks: 23 });
        let later = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 29 })?;
        assert_eq!(later.reached, VirtualTime { ticks: 29 });
        assert_eq!(SimulationBackend::now(&node), VirtualTime { ticks: 29 });
        SimulationBackend::restore(&mut node, &snapshot)?;
        assert_eq!(SimulationBackend::now(&node), VirtualTime { ticks: 23 });
        SimulationBackend::shutdown(&mut node)?;

        assert_eq!(
            recorded(&log),
            vec![
                ChannelCall::HostYield,
                ChannelCall::ShmemStart(23),
                ChannelCall::HostAwait {
                    wait: QemuAsyncWait::AdvanceCompletion,
                    timeout: Duration::from_millis(4),
                    outcome: QemuAsyncWaitOutcome::Completed,
                },
                ChannelCall::ShmemFinish(23),
                ChannelCall::HostYield,
                ChannelCall::ShmemDeliver {
                    node: String::from("vm-a"),
                    payload: vec![3, 2, 1],
                },
                ChannelCall::ShmemFingerprint,
                ChannelCall::QmpSnapshot,
                ChannelCall::HostYield,
                ChannelCall::ShmemStart(29),
                ChannelCall::HostAwait {
                    wait: QemuAsyncWait::AdvanceCompletion,
                    timeout: Duration::from_millis(4),
                    outcome: QemuAsyncWaitOutcome::Completed,
                },
                ChannelCall::ShmemFinish(29),
                ChannelCall::HostYield,
                ChannelCall::QmpRestore(content_hash("checkpoint", "snapshot")),
                ChannelCall::PluginQuit,
                ChannelCall::QmpQuit,
            ]
        );

        Ok(())
    }

    fn scripted_node(
        log: SharedLog,
        fail_plugin_quit: bool,
        fail_shmem_advance: bool,
        fail_qmp_snapshot: bool,
    ) -> Result<QemuNode, Box<dyn Error>> {
        scripted_node_with_runtime(
            log,
            fail_plugin_quit,
            fail_shmem_advance,
            fail_qmp_snapshot,
            [QemuAsyncWaitOutcome::Completed],
        )
    }

    fn scripted_node_with_runtime(
        log: SharedLog,
        fail_plugin_quit: bool,
        fail_shmem_advance: bool,
        fail_qmp_snapshot: bool,
        runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
    ) -> Result<QemuNode, Box<dyn Error>> {
        scripted_node_with_options(
            log,
            ScriptedNodeOptions {
                fail_plugin_quit,
                fail_shmem_advance,
                fail_qmp_snapshot,
                qmp_snapshot_timeout: false,
            },
            runtime_outcomes,
        )
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct ScriptedNodeOptions {
        fail_plugin_quit: bool,
        fail_shmem_advance: bool,
        fail_qmp_snapshot: bool,
        qmp_snapshot_timeout: bool,
    }

    fn scripted_node_with_options(
        log: SharedLog,
        options: ScriptedNodeOptions,
        runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
    ) -> Result<QemuNode, Box<dyn Error>> {
        scripted_node_with_coverage(
            log,
            options,
            runtime_outcomes,
            std::iter::empty(),
            std::iter::empty(),
        )
    }

    fn scripted_node_with_coverage(
        log: SharedLog,
        options: ScriptedNodeOptions,
        runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
        quantum_coverage: impl IntoIterator<Item = Vec<ObservableEvent>>,
        teardown_coverage: impl IntoIterator<Item = ObservableEvent>,
    ) -> Result<QemuNode, Box<dyn Error>> {
        let quantum_coverage = quantum_coverage.into_iter().collect::<VecDeque<_>>();
        let teardown_coverage = teardown_coverage.into_iter().collect::<Vec<_>>();
        let coverage_enabled = !quantum_coverage.is_empty() || !teardown_coverage.is_empty();
        let channels = QemuNodeChannels::new(
            ScriptedPluginControl {
                log: Arc::clone(&log),
                fail_quit: options.fail_plugin_quit,
            },
            ScriptedShmemHotPath {
                log: Arc::clone(&log),
                fail_advance: options.fail_shmem_advance,
                coverage_enabled,
                quantum_coverage: Arc::new(Mutex::new(quantum_coverage)),
                teardown_coverage: Arc::new(Mutex::new(teardown_coverage)),
                fault_commands: Arc::new(Mutex::new(Vec::new())),
                stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            },
            ScriptedQmpMachineControl {
                log: Arc::clone(&log),
                fail_snapshot: options.fail_qmp_snapshot,
                timeout_snapshot: options.qmp_snapshot_timeout,
            },
        );
        let child = Command::new("sleep").arg("60").spawn()?;
        Ok(QemuNode::new(
            QemuNodeChild::new(child),
            channels,
            node_shutdown_policy(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("vm-a"),
            ScriptedHostIoRuntime {
                log,
                outcomes: runtime_outcomes.into_iter().collect(),
                fault_results: VecDeque::new(),
            },
        ))
    }

    fn node_shutdown_policy() -> QemuShutdownPolicy {
        let mut policy = QemuShutdownPolicy::fast_test();
        policy.sigterm_wait = Duration::from_secs(2);
        policy.sigkill_wait = Duration::from_secs(1);
        policy.reap_wait = Duration::from_secs(1);
        policy
    }

    fn shared_log() -> SharedLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn recorded(log: &SharedLog) -> Vec<ChannelCall> {
        log.lock().unwrap().clone()
    }

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn checkpoint(name: &str) -> Checkpoint {
        Checkpoint::new(
            content_hash("checkpoint", name),
            content_hash("configuration", name),
            CheckpointKind::Fat,
        )
    }

    fn content_hash(domain: &str, material: &str) -> ContentHash {
        ContentHash::from_canonical_material(domain, material)
    }
}
