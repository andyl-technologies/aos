//! Typed QEMU node crash detection.
//!
//! RFC-0010 QEMU-32 requires infrastructure failures around a QEMU child to be
//! surfaced as a crashed-node status, not retried or conflated with an intended
//! scenario fault. This module provides both the scheduler-facing status model
//! and the host-side hooks used to classify child-exit, plugin-IPC, and QMP I/O
//! failures.

use std::io::{self, ErrorKind};
use std::process::{Child, ExitStatus};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use crucible_protocol::FrameIoError;
use thiserror::Error;

/// Scheduler-facing status for one QEMU-backed node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuNodeRunStatus {
    /// The node remains runnable.
    Running,
    /// The node is idle at a scheduler-visible boundary.
    Idle,
    /// The node completed normally.
    Done,
    /// The node crashed because the QEMU infrastructure failed.
    Crashed(QemuCrashedNodeStatus),
    /// The scenario intentionally activated a crash fault.
    IntendedCrashFault(QemuIntendedCrashFaultStatus),
}

impl QemuNodeRunStatus {
    /// Returns whether this status is an infrastructure crash.
    #[must_use]
    pub const fn is_infrastructure_crash(&self) -> bool {
        matches!(self, Self::Crashed(_))
    }

    /// Returns whether this status is an intended scenario crash fault.
    #[must_use]
    pub const fn is_intended_crash_fault(&self) -> bool {
        matches!(self, Self::IntendedCrashFault(_))
    }
}

/// Host-side probe for observing whether a QEMU child has exited.
///
/// The production implementation is [`std::process::Child`]. Tests can provide
/// deterministic probes without spawning a process.
pub trait QemuChildExitProbe {
    /// Polls the child once for an exit status without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`QemuChildStatusProbeError`] when the child status cannot be
    /// queried.
    fn try_wait_for_exit(&mut self) -> Result<Option<ExitStatus>, QemuChildStatusProbeError>;
}

impl QemuChildExitProbe for Child {
    fn try_wait_for_exit(&mut self) -> Result<Option<ExitStatus>, QemuChildStatusProbeError> {
        self.try_wait()
            .map_err(|error| QemuChildStatusProbeError::from_io("poll QEMU child exit", error))
    }
}

/// Error returned when a child-exit probe cannot query process state.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed with {kind:?}")]
pub struct QemuChildStatusProbeError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Error kind returned by the process query.
    pub kind: ErrorKind,
}

impl QemuChildStatusProbeError {
    /// Creates a child-status probe error from a concrete I/O error.
    #[must_use]
    pub fn from_io(operation: &'static str, error: io::Error) -> Self {
        Self {
            operation,
            kind: error.kind(),
        }
    }
}

/// Infrastructure crash status reported to the scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuCrashedNodeStatus {
    /// Stable node identifier.
    pub node_id: String,
    /// Infrastructure cause that made the node unusable.
    pub cause: QemuCrashCause,
    /// Crash handling policy for determinism-gated paths.
    pub handling: QemuCrashHandling,
}

impl QemuCrashedNodeStatus {
    /// Builds a crashed-node status for an infrastructure cause.
    #[must_use]
    pub fn new(node_id: impl Into<String>, cause: QemuCrashCause) -> Self {
        Self {
            node_id: node_id.into(),
            cause,
            handling: QemuCrashHandling::ReportAndLocalize,
        }
    }
}

/// Intended scenario crash fault status, distinct from QEMU infrastructure failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuIntendedCrashFaultStatus {
    /// Stable node identifier.
    pub node_id: String,
    /// Scenario fault identifier that intentionally crashed the guest.
    pub fault_id: String,
}

impl QemuIntendedCrashFaultStatus {
    /// Builds an intended crash-fault status.
    #[must_use]
    pub fn new(node_id: impl Into<String>, fault_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            fault_id: fault_id.into(),
        }
    }
}

/// Infrastructure cause for a QEMU crashed-node status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuCrashCause {
    /// The child process exited before the scheduler expected it to.
    UnexpectedChildExit(QemuProcessExit),
    /// The plugin-IPC control channel closed or failed.
    PluginIpcClosed(QemuChannelFailure),
    /// The QMP channel closed or failed.
    QmpDisconnected(QemuChannelFailure),
    /// A bounded await on child infrastructure timed out.
    BoundedAwaitTimeout(QemuBoundedAwaitTimeout),
}

/// Timeout details for a bounded child-infrastructure await.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuBoundedAwaitTimeout {
    /// Operation whose bounded wait expired.
    pub operation: String,
    /// Timeout budget assigned to the operation.
    pub timeout: Duration,
}

impl QemuBoundedAwaitTimeout {
    /// Builds bounded-await timeout details.
    #[must_use]
    pub fn new(operation: impl Into<String>, timeout: Duration) -> Self {
        Self {
            operation: operation.into(),
            timeout,
        }
    }
}

/// Process-exit details captured for an unexpected child exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuProcessExit {
    /// Process exit code, when the platform provides one.
    pub code: Option<i32>,
    /// Terminating signal, on Unix targets.
    pub signal: Option<i32>,
    /// Whether the process reported successful termination.
    pub success: bool,
    /// Stable display string from the process status.
    pub display: String,
}

impl QemuProcessExit {
    /// Captures a process exit status.
    #[must_use]
    pub fn from_exit_status(status: ExitStatus) -> Self {
        Self {
            code: status.code(),
            signal: exit_signal(&status),
            success: status.success(),
            display: status.to_string(),
        }
    }
}

/// Channel failure details for plugin-IPC and QMP disconnects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuChannelFailure {
    /// Operation that observed the channel failure.
    pub operation: String,
    /// Human-readable channel error.
    pub detail: String,
}

impl QemuChannelFailure {
    /// Builds a channel failure descriptor.
    #[must_use]
    pub fn new(operation: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            detail: detail.into(),
        }
    }
}

/// Handling policy for QEMU infrastructure crashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuCrashHandling {
    /// Report the crash at the node boundary, localize it, and do not retry it.
    ReportAndLocalize,
}

impl QemuCrashHandling {
    /// Returns whether the crash may be retried on a determinism-gated path.
    #[must_use]
    pub const fn retry_on_determinism_gate(self) -> bool {
        match self {
            Self::ReportAndLocalize => false,
        }
    }
}

/// Crash detector for one QEMU-backed node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuCrashDetector {
    node_id: String,
}

impl QemuCrashDetector {
    /// Builds a crash detector for a stable node identifier.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
        }
    }

    /// Reports an unexpected child exit as an infrastructure crash.
    #[must_use]
    pub fn unexpected_child_exit(&self, status: ExitStatus) -> QemuNodeRunStatus {
        self.crashed(QemuCrashCause::UnexpectedChildExit(
            QemuProcessExit::from_exit_status(status),
        ))
    }

    /// Polls a QEMU child and reports an unexpected exit as an infrastructure crash.
    ///
    /// # Errors
    ///
    /// Returns [`QemuChildStatusProbeError`] when the child status cannot be
    /// queried.
    pub fn detect_unexpected_child_exit<P>(
        &self,
        child: &mut P,
    ) -> Result<Option<QemuNodeRunStatus>, QemuChildStatusProbeError>
    where
        P: QemuChildExitProbe,
    {
        child
            .try_wait_for_exit()
            .map(|status| status.map(|status| self.unexpected_child_exit(status)))
    }

    /// Reports a plugin-IPC close as an infrastructure crash.
    #[must_use]
    pub fn plugin_ipc_closed(
        &self,
        operation: impl Into<String>,
        detail: impl Into<String>,
    ) -> QemuNodeRunStatus {
        self.crashed(QemuCrashCause::PluginIpcClosed(QemuChannelFailure::new(
            operation, detail,
        )))
    }

    /// Converts a plugin-IPC frame operation failure into an infrastructure crash.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeRunStatus::Crashed`] when `result` is a frame I/O error.
    pub fn detect_plugin_ipc_result<T>(
        &self,
        operation: impl Into<String>,
        result: Result<T, FrameIoError>,
    ) -> Result<T, QemuNodeRunStatus> {
        let operation = operation.into();
        result.map_err(|error| self.plugin_ipc_closed(operation, error.to_string()))
    }

    /// Reports a QMP disconnect as an infrastructure crash.
    #[must_use]
    pub fn qmp_disconnected(
        &self,
        operation: impl Into<String>,
        detail: impl Into<String>,
    ) -> QemuNodeRunStatus {
        self.crashed(QemuCrashCause::QmpDisconnected(QemuChannelFailure::new(
            operation, detail,
        )))
    }

    /// Reports a bounded child-infrastructure await timeout as an infrastructure crash.
    #[must_use]
    pub fn bounded_await_timeout(
        &self,
        operation: impl Into<String>,
        timeout: Duration,
    ) -> QemuNodeRunStatus {
        self.crashed(QemuCrashCause::BoundedAwaitTimeout(
            QemuBoundedAwaitTimeout::new(operation, timeout),
        ))
    }

    /// Converts a QMP I/O operation failure into an infrastructure crash.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeRunStatus::Crashed`] when `result` is a QMP I/O error.
    pub fn detect_qmp_result<T>(
        &self,
        operation: impl Into<String>,
        result: io::Result<T>,
    ) -> Result<T, QemuNodeRunStatus> {
        let operation = operation.into();
        result.map_err(|error| self.qmp_disconnected(operation, error.to_string()))
    }

    /// Reports a scenario-requested crash fault distinctly from infrastructure crashes.
    #[must_use]
    pub fn intended_crash_fault(&self, fault_id: impl Into<String>) -> QemuNodeRunStatus {
        QemuNodeRunStatus::IntendedCrashFault(QemuIntendedCrashFaultStatus::new(
            self.node_id.clone(),
            fault_id,
        ))
    }

    fn crashed(&self, cause: QemuCrashCause) -> QemuNodeRunStatus {
        QemuNodeRunStatus::Crashed(QemuCrashedNodeStatus::new(self.node_id.clone(), cause))
    }
}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}
