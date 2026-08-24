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
    /// A coordinated QEMU/host-I/O checkpoint transaction failed.
    #[error("QEMU exact checkpoint failed: {message}")]
    Checkpoint {
        /// Deterministic capture, binding, or cleanup failure detail.
        message: String,
    },
    /// A plugin-emitted network frame broke the per-node sequence contract.
    #[error("QEMU network output sequence mismatch: expected {expected}, observed {observed}")]
    NetworkOutputSequence {
        /// Next sequence required by the host continuation.
        expected: u64,
        /// Sequence carried by the emitted frame.
        observed: u64,
    },
    /// A live QEMU fault command violated its admitted boundary contract.
    #[error("QEMU fault command failed closed: {message}")]
    FaultCommand {
        /// Deterministic command, capability, coordinate, or result mismatch.
        message: String,
    },
    /// Precommit storage for the lossless QEMU result payload could not be reserved.
    #[error(
        "cannot admit or reserve {requested} bytes for the QEMU fault result against limit {configured}"
    )]
    FaultResultStorage {
        /// Exact result storage requested before visible mutation.
        requested: u64,
        /// Authored or hard byte ceiling governing the request.
        configured: u64,
    },
    /// Lossless occurrence-event staging exceeded its authored record ceiling.
    #[error(
        "cannot stage {requested} QEMU fault event records at current {current} against limit {configured}"
    )]
    FaultEventStorage {
        /// Events already retained by the in-flight command fence.
        current: u64,
        /// Additional records required before the plugin can acknowledge.
        requested: u64,
        /// Authored record ceiling governing the operation.
        configured: u64,
    },
    /// Non-consuming occurrence preview exceeded its authored event-log byte ceiling.
    #[error(
        "cannot stage {requested} QEMU fault-event log bytes at current {current} against limit {configured}"
    )]
    FaultEventPayloadStorage {
        /// Event-log bytes already retained by the production event continuation.
        current: u64,
        /// Additional canonical header and payload bytes required by the event.
        requested: u64,
        /// Authored aggregate event-log byte ceiling.
        configured: u64,
    },
    /// Non-consuming occurrence preview exceeded its authored inline payload ceiling.
    #[error(
        "cannot stage a QEMU fault-event payload of {requested} bytes against inline limit {configured}"
    )]
    FaultEventInlinePayloadStorage {
        /// Payload bytes required by the previewed event.
        requested: u64,
        /// Authored per-event inline payload ceiling.
        configured: u64,
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

    /// Creates a coordinated checkpoint error.
    #[must_use]
    pub fn checkpoint(message: impl Into<String>) -> Self {
        Self::Checkpoint {
            message: message.into(),
        }
    }

    /// Creates a fail-closed live fault-command error.
    #[must_use]
    pub fn fault_command(message: impl Into<String>) -> Self {
        Self::FaultCommand {
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
