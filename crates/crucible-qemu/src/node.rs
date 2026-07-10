//! Scheduler-facing QEMU node wrapper.
//!
//! The wrapper owns exactly one child handle and the three RFC-0010 QEMU
//! channels for that child: plugin IPC control, shared-memory hot path, and
//! QMP machine control. It exposes the synchronous backend boundary while
//! keeping per-quantum timing and frame traffic on the shared-memory channel.

use std::any::Any;
use std::fmt;
use std::net::SocketAddr;
use std::process::Child;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput, BackendSnapshot,
    Checkpoint, EventLog, ExecutionFingerprint, ExecutionHorizon, FingerprintSample, GdbAttachInfo,
    GdbListen, Icount, NodeId, ObservableEvent, SchedulerEventLogAppend, SimulationBackend,
    StepObservation, VirtualTime,
};
use thiserror::Error;

use crate::shutdown::{
    QemuChildWait, QemuReap, QemuShutdownError, QemuShutdownPolicy, QemuShutdownReport,
    QemuShutdownRung, QemuShutdownTarget, QemuShutdownTargetError, shutdown_qemu_child,
    signal_child, wait_child,
};
use crate::{
    QemuAsyncCrashEscalationTarget, QemuAsyncDriverError, QemuAsyncDriverPolicy,
    QemuAsyncDriverTargetError, QemuAsyncNodeStepOutcome, QemuAsyncNodeStepTarget,
    QemuAsyncQuantumCompletion, QemuCrashDetector, QemuGdbstubChannelConfig, QemuGdbstubProxy,
    QemuGdbstubProxyServer, QemuHostIoRuntime, QemuNodeRunStatus, run_bounded_qemu_node_step,
};

/// The role assigned to one QEMU node channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QemuNodeChannelPlane {
    /// Plugin IPC control carries setup and teardown messages only.
    PluginIpcControl,
    /// Shared memory carries all per-quantum timing and frame data.
    ShmemHotPath,
    /// QMP carries out-of-band machine-control commands.
    QmpMachineControl,
}

impl fmt::Display for QemuNodeChannelPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PluginIpcControl => f.write_str("plugin IPC control"),
            Self::ShmemHotPath => f.write_str("shmem hot path"),
            Self::QmpMachineControl => f.write_str("QMP machine control"),
        }
    }
}

/// A channel-local operation error before node-plane context is attached.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct QemuNodeChannelError {
    /// Operation being attempted on the channel.
    pub operation: &'static str,
    /// Deterministic failure detail.
    pub message: String,
    /// Timeout budget when this channel error came from a bounded await timeout.
    pub timeout: Option<Duration>,
}

impl QemuNodeChannelError {
    /// Creates a channel operation error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            timeout: None,
        }
    }

    /// Creates a channel error classified as a bounded await timeout.
    #[must_use]
    pub fn bounded_await_timeout(
        operation: &'static str,
        message: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            operation,
            message: message.into(),
            timeout: Some(timeout),
        }
    }

    /// Returns the bounded await timeout that caused this channel failure.
    #[must_use]
    pub const fn bounded_timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Errors returned by the scheduler-facing QEMU node wrapper.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuNodeError {
    /// A role-specific child channel failed an operation.
    #[error("{plane} channel operation {operation} failed: {message}")]
    Channel {
        /// Channel role that was used for the failed operation.
        plane: QemuNodeChannelPlane,
        /// Channel-local operation name.
        operation: &'static str,
        /// Deterministic failure detail.
        message: String,
    },
    /// The owned-child shutdown ladder failed.
    #[error("owned QEMU child shutdown failed: {source}")]
    Shutdown {
        /// Underlying shutdown escalation error.
        source: QemuShutdownError,
    },
    /// The bounded async driver failed around a node step.
    #[error("bounded QEMU async driver failed: {source}")]
    AsyncDriver {
        /// Underlying async-driver failure.
        source: QemuAsyncDriverError,
    },
    /// The bounded async driver classified the child as crashed and shut it down.
    #[error("QEMU node crashed during bounded await: {status:?}; shutdown={shutdown:?}")]
    Crashed {
        /// Scheduler-facing crashed-node status.
        status: Box<QemuNodeRunStatus>,
        /// Shutdown escalation report.
        shutdown: Box<QemuShutdownReport>,
    },
    /// The mediated gdbstub proxy failed.
    #[error("gdbstub proxy operation {operation} failed: {message}")]
    GdbstubProxy {
        /// Proxy operation being attempted.
        operation: &'static str,
        /// Deterministic failure detail.
        message: String,
    },
    /// Coverage observations were produced through an API without an event-log owner.
    #[error("coverage-enabled QEMU execution requires a unified event-log sink")]
    CoverageEventLogRequired,
    /// The unified event log rejected a coverage observation batch.
    #[error("append QEMU coverage observations to unified event log failed: {message}")]
    CoverageEventLog {
        /// Deterministic event-log failure diagnostic.
        message: String,
    },
}

impl QemuNodeError {
    /// Attaches a node channel role to a channel-local error.
    #[must_use]
    pub fn from_channel(plane: QemuNodeChannelPlane, source: QemuNodeChannelError) -> Self {
        Self::Channel {
            plane,
            operation: source.operation,
            message: source.message,
        }
    }

    /// Attaches scheduler-node context to a shutdown escalation error.
    #[must_use]
    pub const fn from_shutdown(source: QemuShutdownError) -> Self {
        Self::Shutdown { source }
    }

    /// Attaches scheduler-node context to an async-driver failure.
    #[must_use]
    pub const fn from_async_driver(source: QemuAsyncDriverError) -> Self {
        Self::AsyncDriver { source }
    }

    /// Attaches scheduler-node context to a gdbstub proxy failure.
    #[must_use]
    pub fn from_gdbstub_proxy(operation: &'static str, message: impl Into<String>) -> Self {
        Self::GdbstubProxy {
            operation,
            message: message.into(),
        }
    }
}

impl From<QemuNodeError> for BackendError {
    fn from(error: QemuNodeError) -> Self {
        Self::Rejected {
            message: error.to_string(),
        }
    }
}

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

impl Drop for QemuNodeChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        if self.child.wait().is_ok() {
            self.reaped = true;
        }
    }
}

/// Plugin IPC control channel for setup and teardown only.
pub trait QemuPluginIpcControlChannel {
    /// Sends the plugin IPC `Quit` control message.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the control channel cannot accept
    /// the teardown request.
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError>;
}

/// Shared-memory hot-path channel for per-quantum data.
pub trait QemuShmemHotPathChannel {
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

    /// Finishes a split quantum after the bounded host-I/O runtime completes.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory completion report
    /// cannot be read.
    fn finish_quantum(
        &mut self,
        pending: QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError>;

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

    /// Delivers a deterministic frame through the shared-memory input ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the frame cannot be delivered.
    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError>;

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
    pub fn downcast<T>(self, operation: &'static str) -> Result<T, QemuNodeChannelError>
    where
        T: Any,
    {
        self.token.downcast().map(|token| *token).map_err(|_| {
            QemuNodeChannelError::new(operation, "pending quantum token type mismatch")
        })
    }
}

/// QMP machine-control channel for snapshot and quit commands.
pub trait QemuQmpMachineControlChannel {
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

/// The exact three channels owned by one QEMU node.
pub struct QemuNodeChannels {
    plugin_control: Box<dyn QemuPluginIpcControlChannel>,
    shmem_hot_path: Box<dyn QemuShmemHotPathChannel>,
    qmp_machine_control: Box<dyn QemuQmpMachineControlChannel>,
}

impl QemuNodeChannels {
    /// Builds the three-channel bundle for one QEMU child.
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
    gdbstub: Option<QemuGdbstubChannelConfig>,
    active_gdbstub: Option<QemuGdbstubProxyServer>,
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
            gdbstub: None,
            active_gdbstub: None,
        }
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

    /// Advances the child to an instruction-count ceiling through shared memory.
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
        pending: Self::PendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        self.channels.shmem_hot_path.finish_quantum(pending)
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
        let report = self
            .advance_to_ceiling_report(icount_ceiling)
            .map_err(BackendError::from)?;
        let outcome = self
            .finish_advance_report(icount_ceiling, report)
            .map_err(BackendError::from)?;
        Ok(StepObservation::from_advance_outcome(ceiling, outcome))
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, BackendError> {
        self.channels
            .shmem_hot_path
            .drain_observable_events()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source).into()
            })
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        if at != self.last_observed_time {
            return Err(BackendError::Rejected {
                message: format!(
                    "qemu backend effect at {} does not match scheduler time {}",
                    at.ticks, self.last_observed_time.ticks
                ),
            });
        }
        match effect {
            BackendEffect::Noop => Ok(()),
            BackendEffect::DeliverInput(input) => self
                .deliver_frame(input.clone())
                .map_err(BackendError::from),
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
#[allow(clippy::expect_used)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::error::Error;
    use std::net::TcpListener;
    use std::process::Command;
    use std::rc::Rc;
    use std::time::Duration;

    use crucible::{
        CheckpointKind, ContentHash, EventLogCoverageObservation, ExecutionHorizon, GdbListen,
        NodeId, event_log_coverage_projection,
    };

    use crate::{
        QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuQuantumOperation,
    };

    use super::*;

    type SharedLog = Rc<RefCell<Vec<ChannelCall>>>;

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
        quantum_coverage: Rc<RefCell<VecDeque<Vec<ObservableEvent>>>>,
        teardown_coverage: Rc<RefCell<Vec<ObservableEvent>>>,
    }

    #[derive(Clone)]
    struct ScriptedHostIoRuntime {
        log: SharedLog,
        outcomes: VecDeque<QemuAsyncWaitOutcome>,
    }

    #[derive(Clone)]
    struct ScriptedQmpMachineControl {
        log: SharedLog,
        fail_snapshot: bool,
        timeout_snapshot: bool,
    }

    impl QemuPluginIpcControlChannel for ScriptedPluginControl {
        fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::PluginQuit);
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
            self.log.borrow_mut().push(ChannelCall::ShmemCurrentIcount);
            Ok(Icount { retired: 11 })
        }

        fn start_quantum(
            &mut self,
            horizon: ExecutionHorizon,
        ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
            self.log
                .borrow_mut()
                .push(ChannelCall::ShmemStart(horizon.icount.retired));
            if self.fail_advance {
                return Err(QemuNodeChannelError::new(
                    "advance_to_horizon",
                    "futex wake failed",
                ));
            }
            Ok(QemuNodePendingQuantum::new(horizon.icount.retired))
        }

        fn finish_quantum(
            &mut self,
            pending: QemuNodePendingQuantum,
        ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
            let horizon = pending.downcast::<u64>("finish_quantum")?;
            self.log
                .borrow_mut()
                .push(ChannelCall::ShmemFinish(horizon));
            if let Some(events) = self.quantum_coverage.borrow_mut().pop_front() {
                self.teardown_coverage.borrow_mut().extend(events);
            }
            Ok(QemuAsyncQuantumCompletion {
                outcome: AdvanceOutcome::ReachedHorizon,
                operations: vec![
                    QemuQuantumOperation::StoreSchedulerCeiling,
                    QemuQuantumOperation::FutexWake,
                    QemuQuantumOperation::ObservePluginReport,
                ],
            })
        }

        fn drain_observable_events(
            &mut self,
        ) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
            Ok(std::mem::take(&mut *self.teardown_coverage.borrow_mut()))
        }

        fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::ShmemDeliver {
                node: input.node.name,
                payload: input.payload,
            });
            Ok(())
        }

        fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::ShmemEmit);
            Ok(Some(QemuNodeEmittedFrame {
                source: node_id("vm-a"),
                destination: node_id("vm-b"),
                emit_icount: Icount { retired: 17 },
                sequence: 7,
                payload: vec![8, 9],
            }))
        }

        fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::ShmemIdle);
            Ok(QemuNodeIdleState {
                current_icount: Icount { retired: 13 },
                next_deadline: Some(Icount { retired: 21 }),
            })
        }

        fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::ShmemFingerprint);
            Ok(ExecutionFingerprint {
                hash: content_hash("fingerprint", "vm-a"),
            })
        }
    }

    impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
        fn save_checkpoint(&mut self) -> Result<Checkpoint, QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::QmpSnapshot);
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
                .borrow_mut()
                .push(ChannelCall::QmpRestore(checkpoint.id));
            Ok(())
        }

        fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::QmpQuit);
            Ok(())
        }
    }

    impl QemuHostIoRuntime for ScriptedHostIoRuntime {
        fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
            self.log.borrow_mut().push(ChannelCall::HostYield);
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
            self.log.borrow_mut().push(ChannelCall::HostAwait {
                wait,
                timeout,
                outcome,
            });
            Ok(outcome)
        }
    }

    #[test]
    fn qemu_node_owns_one_child_and_exactly_three_channel_roles() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Rc::clone(&log), false, false, false)?;

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
    fn qemu_node_routes_scheduler_operations_over_strict_channels() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Rc::clone(&log), false, false, false)?;

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
            Rc::clone(&log),
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
            Rc::clone(&log),
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
            Rc::clone(&log),
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
    fn qemu_node_drains_final_coverage_before_teardown() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let event =
            ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
        let mut node = scripted_node_with_coverage(
            Rc::clone(&log),
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
            Rc::clone(&log),
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
                if message.contains("does not match scheduler time")
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

    #[test]
    fn qemu_node_open_gdbstub_reports_configured_channel() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node_with_runtime(
            Rc::clone(&log),
            false,
            false,
            false,
            [QemuAsyncWaitOutcome::Completed],
        )?
        .with_gdbstub(QemuGdbstubChannelConfig::new(
            "tcp:127.0.0.1:9001",
            "127.0.0.1:0",
        )?);

        let info = SimulationBackend::open_gdbstub(
            &mut node,
            node_id("vm-a"),
            GdbListen::new("127.0.0.1:0")?,
        )?;

        assert_eq!(info.node, node_id("vm-a"));
        assert_eq!(info.qemu_endpoint, "tcp:127.0.0.1:9001");
        let active_listener = node
            .active_gdbstub_listener()
            .expect("open_gdbstub should bind an operator listener");
        assert_ne!(active_listener.port(), 0);
        assert_eq!(info.operator_listen.as_str(), active_listener.to_string());
        assert!(
            TcpListener::bind(active_listener).is_err(),
            "gdbstub attach should keep the operator listener bound"
        );
        assert!(info.is_out_of_band_debug_proxy());
        assert!(matches!(
            SimulationBackend::open_gdbstub(
                &mut node,
                node_id("vm-a"),
                GdbListen::new("127.0.0.1:0")?,
            ),
            Err(BackendError::Rejected { message }) if message.contains("already active")
        ));
        assert_eq!(recorded(&log), Vec::<ChannelCall>::new());
        assert!(node.shutdown_child()?.reaped);

        Ok(())
    }

    #[test]
    fn qemu_node_reports_shmem_failures_as_backend_rejections() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Rc::clone(&log), false, true, false)?;

        let result = Backend::advance_to_horizon(
            &mut node,
            ExecutionHorizon {
                icount: Icount { retired: 99 },
            },
        );

        assert_eq!(
            result,
            Err(BackendError::Rejected {
                message: String::from(
                    "bounded QEMU async driver failed: QEMU async shared-memory channel failed: advance_to_horizon failed: futex wake failed"
                ),
            })
        );
        assert_eq!(
            recorded(&log),
            vec![ChannelCall::HostYield, ChannelCall::ShmemStart(99)]
        );
        assert!(node.shutdown_child()?.reaped);

        Ok(())
    }

    #[test]
    fn qemu_node_timeout_reports_crash_and_runs_shutdown() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node_with_runtime(
            Rc::clone(&log),
            false,
            false,
            false,
            [QemuAsyncWaitOutcome::TimedOut],
        )?;

        let result = Backend::advance_to_horizon(
            &mut node,
            ExecutionHorizon {
                icount: Icount { retired: 31 },
            },
        );

        match result {
            Err(BackendError::Rejected { message }) => {
                assert!(message.contains("QEMU node crashed during bounded await"));
                assert!(message.contains("BoundedAwaitTimeout"));
            }
            other => panic!("expected bounded timeout crash, got {other:?}"),
        }
        assert!(node.child_reaped());
        assert_eq!(
            node.lifecycle_state(),
            QemuNodeLifecycleState::ShutdownRequested
        );
        assert_eq!(
            recorded(&log),
            vec![
                ChannelCall::HostYield,
                ChannelCall::ShmemStart(31),
                ChannelCall::HostAwait {
                    wait: QemuAsyncWait::AdvanceCompletion,
                    timeout: Duration::from_millis(4),
                    outcome: QemuAsyncWaitOutcome::TimedOut,
                },
                ChannelCall::PluginQuit,
                ChannelCall::QmpQuit,
            ]
        );

        Ok(())
    }

    #[test]
    fn qemu_node_reports_qmp_failures_without_touching_hot_path() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Rc::clone(&log), false, false, true)?;

        let result = Backend::snapshot(&mut node);

        assert_eq!(
            result,
            Err(BackendError::Rejected {
                message: String::from(
                    "QMP machine control channel operation save_checkpoint failed: QMP error"
                ),
            })
        );
        assert_eq!(recorded(&log), vec![ChannelCall::QmpSnapshot]);
        assert!(node.shutdown_child()?.reaped);

        Ok(())
    }

    #[test]
    fn qemu_node_qmp_timeout_reports_crash_and_runs_shutdown() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node_with_options(
            Rc::clone(&log),
            ScriptedNodeOptions {
                qmp_snapshot_timeout: true,
                ..ScriptedNodeOptions::default()
            },
            [QemuAsyncWaitOutcome::Completed],
        )?;

        let result = Backend::snapshot(&mut node);

        match result {
            Err(BackendError::Rejected { message }) => {
                assert!(message.contains("QEMU node crashed during bounded await"));
                assert!(message.contains("BoundedAwaitTimeout"));
                assert!(message.contains("save_checkpoint"));
            }
            other => panic!("expected QMP timeout crash, got {other:?}"),
        }
        assert!(node.child_reaped());
        assert_eq!(
            node.lifecycle_state(),
            QemuNodeLifecycleState::ShutdownRequested
        );
        assert_eq!(
            recorded(&log),
            vec![
                ChannelCall::QmpSnapshot,
                ChannelCall::PluginQuit,
                ChannelCall::QmpQuit,
            ]
        );

        Ok(())
    }

    #[test]
    fn qemu_node_shutdown_continues_to_reap_when_plugin_quit_fails() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Rc::clone(&log), true, false, false)?;

        let report = node.shutdown_child()?;

        assert!(report.reaped);
        assert!(node.child_reaped());
        assert_eq!(
            report
                .failures
                .iter()
                .map(|failure| failure.rung)
                .collect::<Vec<_>>(),
            [QemuShutdownRung::ControlQuit]
        );
        assert_eq!(
            recorded(&log),
            vec![ChannelCall::PluginQuit, ChannelCall::QmpQuit]
        );
        assert_eq!(
            node.lifecycle_state(),
            QemuNodeLifecycleState::ShutdownRequested
        );

        Ok(())
    }

    #[test]
    fn qemu_node_repeated_shutdown_is_idempotent_after_reap() -> Result<(), Box<dyn Error>> {
        let log = shared_log();
        let mut node = scripted_node(Rc::clone(&log), false, false, false)?;

        let first = node.shutdown_child()?;
        let first_log = recorded(&log);
        let second = node.shutdown_child()?;

        assert!(first.reaped);
        assert!(second.reaped);
        assert!(second.attempts.is_empty());
        assert!(second.failures.is_empty());
        assert_eq!(recorded(&log), first_log);
        assert_eq!(
            first_log,
            vec![ChannelCall::PluginQuit, ChannelCall::QmpQuit]
        );
        assert!(node.child_reaped());

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
                log: Rc::clone(&log),
                fail_quit: options.fail_plugin_quit,
            },
            ScriptedShmemHotPath {
                log: Rc::clone(&log),
                fail_advance: options.fail_shmem_advance,
                coverage_enabled,
                quantum_coverage: Rc::new(RefCell::new(quantum_coverage)),
                teardown_coverage: Rc::new(RefCell::new(teardown_coverage)),
            },
            ScriptedQmpMachineControl {
                log: Rc::clone(&log),
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
        Rc::new(RefCell::new(Vec::new()))
    }

    fn recorded(log: &SharedLog) -> Vec<ChannelCall> {
        log.borrow().clone()
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
