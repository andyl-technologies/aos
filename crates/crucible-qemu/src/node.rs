//! Scheduler-facing QEMU node wrapper.
//!
//! The wrapper owns exactly one child handle and the three RFC-0010 QEMU
//! channels for that child: plugin IPC control, shared-memory hot path, and
//! QMP machine control. It exposes the synchronous backend boundary while
//! keeping per-quantum timing and frame traffic on the shared-memory channel.

use std::fmt;
use std::process::Child;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, Backend, BackendError, BackendInput, Checkpoint, ExecutionFingerprint,
    ExecutionHorizon, Icount, NodeId,
};
use thiserror::Error;

use crate::shutdown::{
    QemuChildWait, QemuReap, QemuShutdownError, QemuShutdownPolicy, QemuShutdownReport,
    QemuShutdownRung, QemuShutdownTarget, QemuShutdownTargetError, shutdown_qemu_child,
    signal_child, wait_child,
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
}

impl QemuNodeChannelError {
    /// Creates a channel operation error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
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
    /// Reads the node's current retired-instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory state cannot be
    /// observed.
    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError>;

    /// Advances the node to `horizon` or until it pauses earlier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory advance request
    /// cannot complete.
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, QemuNodeChannelError>;

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
}

impl QemuNode {
    /// Builds a QEMU scheduler node from one owned child handle and its channels.
    #[must_use]
    pub const fn new(
        child: QemuNodeChild,
        channels: QemuNodeChannels,
        shutdown_policy: QemuShutdownPolicy,
    ) -> Self {
        Self {
            child,
            channels,
            lifecycle_state: QemuNodeLifecycleState::Running,
            shutdown_policy,
        }
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
    /// Returns [`QemuNodeError`] when the shared-memory hot path cannot advance.
    pub fn advance_to_ceiling(&mut self, ceiling: Icount) -> Result<AdvanceOutcome, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .advance_to_horizon(ExecutionHorizon { icount: ceiling })
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
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
        self.channels
            .qmp_machine_control
            .save_checkpoint()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    /// Restores a checkpoint through QMP machine control.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QMP cannot restore `checkpoint`.
    pub fn restore_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), QemuNodeError> {
        self.channels
            .qmp_machine_control
            .restore_checkpoint(checkpoint)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
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
        if self.child.reaped() {
            self.lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
            return Ok(QemuShutdownReport {
                attempts: Vec::new(),
                failures: Vec::new(),
                reaped: true,
                leaked: false,
            });
        }

        let mut target = QemuNodeShutdownTarget {
            child: &mut self.child,
            plugin_control: self.channels.plugin_control.as_mut(),
            qmp_machine_control: self.channels.qmp_machine_control.as_mut(),
        };
        let report = shutdown_qemu_child(&mut target, self.shutdown_policy)
            .map_err(QemuNodeError::from_shutdown)?;
        self.lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
        Ok(report)
    }
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
mod tests {
    use std::cell::RefCell;
    use std::error::Error;
    use std::process::Command;
    use std::rc::Rc;
    use std::time::Duration;

    use crucible::{CheckpointKind, ContentHash, ExecutionHorizon, NodeId};

    use super::*;

    type SharedLog = Rc<RefCell<Vec<ChannelCall>>>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ChannelCall {
        ShmemCurrentIcount,
        ShmemAdvance(u64),
        ShmemDeliver { node: String, payload: Vec<u8> },
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
    }

    #[derive(Clone)]
    struct ScriptedQmpMachineControl {
        log: SharedLog,
        fail_snapshot: bool,
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
        fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
            self.log.borrow_mut().push(ChannelCall::ShmemCurrentIcount);
            Ok(Icount { retired: 11 })
        }

        fn advance_to_horizon(
            &mut self,
            horizon: ExecutionHorizon,
        ) -> Result<AdvanceOutcome, QemuNodeChannelError> {
            self.log
                .borrow_mut()
                .push(ChannelCall::ShmemAdvance(horizon.icount.retired));
            if self.fail_advance {
                return Err(QemuNodeChannelError::new(
                    "advance_to_horizon",
                    "futex wake failed",
                ));
            }
            Ok(AdvanceOutcome::ReachedHorizon)
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
        assert_eq!(saved, checkpoint("snapshot"));
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
                ChannelCall::ShmemAdvance(19),
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
                    "shmem hot path channel operation advance_to_horizon failed: futex wake failed"
                ),
            })
        );
        assert_eq!(recorded(&log), vec![ChannelCall::ShmemAdvance(99)]);
        assert!(node.shutdown_child()?.reaped);

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
        let channels = QemuNodeChannels::new(
            ScriptedPluginControl {
                log: Rc::clone(&log),
                fail_quit: fail_plugin_quit,
            },
            ScriptedShmemHotPath {
                log: Rc::clone(&log),
                fail_advance: fail_shmem_advance,
            },
            ScriptedQmpMachineControl {
                log,
                fail_snapshot: fail_qmp_snapshot,
            },
        );
        let child = Command::new("sleep").arg("60").spawn()?;
        Ok(QemuNode::new(
            QemuNodeChild::new(child),
            channels,
            node_shutdown_policy(),
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
        Checkpoint {
            id: content_hash("checkpoint", name),
            configuration: content_hash("configuration", name),
            kind: CheckpointKind::Fat,
        }
    }

    fn content_hash(domain: &str, material: &str) -> ContentHash {
        ContentHash::from_canonical_material(domain, material)
    }
}
