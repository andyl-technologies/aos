//! Scheduler-facing QEMU node channel roles and errors.

use std::fmt;
use std::time::Duration;

use crucible::BackendError;
use thiserror::Error;

use crate::{QemuAsyncDriverError, QemuNodeRunStatus, QemuShutdownError, QemuShutdownReport};

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

/// Reports a channel-local operation error before node-plane context is attached.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct QemuNodeChannelError {
    /// Operation being attempted on the channel.
    pub operation: &'static str,
    /// Deterministic failure detail.
    pub message: String,
    /// Timeout budget when this channel error came from a bounded await timeout.
    pub timeout: Option<Duration>,
    /// Whether the operation may be retried without republishing its request.
    pub retryable: bool,
}

impl QemuNodeChannelError {
    /// Creates a channel operation error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            timeout: None,
            retryable: false,
        }
    }

    /// Creates a transient channel error for a request that remains in flight.
    #[must_use]
    pub fn retryable(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            timeout: None,
            retryable: true,
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
            retryable: false,
        }
    }

    /// Returns the bounded await timeout that caused this channel failure.
    #[must_use]
    pub const fn bounded_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Returns whether the same in-flight operation may be polled again.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }
}

/// Reports a failure returned by the scheduler-facing QEMU node wrapper.
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
