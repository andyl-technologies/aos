//! Scheduler-facing QEMU node channel roles and errors.

use std::fmt;
use std::time::Duration;

use crucible_engine::{BackendError, BackendOperationalCause, BackendOperationalFailureKind};
use crucible_host_resources::host_supervision::{HostOperationState, HostSupervisionError};
use thiserror::Error;

use crate::{
    BoundedSchedulerPreemptionError, QemuAsyncDriverError, QemuNodeRunStatus, QemuShutdownError,
    QemuShutdownReport,
};

/// Process-control states that cannot safely admit a new pidfd adversary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum QemuBoundedSchedulerPreemptionTargetError {
    /// The QEMU process is parented and reaped by a retained outer lifecycle.
    #[error("the QEMU process is externally owned")]
    ExternallyOwned,
    /// The directly owned QEMU child has already been reaped.
    #[error("the directly owned QEMU process was already reaped")]
    AlreadyReaped,
}

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
    /// Capture failed before the separately observed process cleanup.
    #[error("{source}; checkpoint cleanup refusal: {cleanup:?}")]
    CheckpointCleanup {
        /// Initiating failure, retained as the actual typed carrier.
        #[source]
        source: Box<QemuNodeError>,
        /// Secondary cleanup failure; absence means that cleanup succeeded.
        cleanup: Option<Box<QemuNodeError>>,
    },
    /// Capture work failed before its independently checked original postcut.
    #[cfg(target_os = "linux")]
    #[error("{source}; checkpoint original postcut: {original_after}")]
    CheckpointPostcut {
        /// Initiating node failure, preserved without diagnostic replacement.
        #[source]
        source: Box<QemuNodeError>,
        /// Same retained original's separate post-operation refusal.
        original_after: HostSupervisionError,
    },
    /// The actual checkpoint original or its matched native receiver refused.
    #[cfg(target_os = "linux")]
    #[error("checkpoint original refused: {source}")]
    CheckpointOriginal {
        /// Typed first cause and independent original postcut.
        source: super::exact_snapshot::capture_original::CheckpointOriginalError,
    },
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
    /// RAM source cleanup failed while its service remains retained.
    #[error("{operation} failed: {source}")]
    RamSourceCleanup {
        /// Cleanup boundary that observed the original source failure.
        operation: &'static str,
        /// Same typed worker cause or direct cleanup refusal.
        #[source]
        source: crate::QemuAsyncDriverHealthError,
    },
    /// A timed-out channel failed before its independent physical shutdown.
    #[error("{first}; crash status={status:?}; shutdown refusal: {shutdown}")]
    ShutdownAfterChannelFailure {
        /// Actual initiating channel error, preserved before cleanup.
        first: QemuNodeChannelError,
        /// Original crash classification before cleanup was attempted.
        status: QemuNodeRunStatus,
        /// Independently retained physical cleanup failure.
        shutdown: Box<QemuNodeError>,
    },
    /// Child cleanup retains its actual live-check and completion observations.
    #[error(
        "child cleanup Original refused: begin={begin:?}; phases={observations:?}; completion={completion:?}; report={report:?}"
    )]
    ShutdownOriginal {
        /// One-time cleanup entry refusal, if entry did not succeed.
        begin: Option<HostSupervisionError>,
        /// First precheck and independent post for each ordered shutdown rung.
        observations: [(Option<HostSupervisionError>, Option<HostSupervisionError>); 5],
        /// Whether the actual completion effect occurred before its post.
        completion_effect: bool,
        /// Same operation's independent completion/post result.
        completion: Option<HostSupervisionError>,
        /// Actual rung outputs retained before their statuses were interpreted.
        report: QemuShutdownReport,
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
    /// The host-only bounded scheduling adversary failed closed.
    #[error("bounded QEMU scheduler preemption failed: {message}")]
    BoundedSchedulerPreemption {
        /// Deterministic failure detail from the pidfd controller.
        message: String,
    },
    /// The node cannot prove that its numeric PID still names its owned child.
    #[error("bounded QEMU scheduler preemption rejected its process target: {target}")]
    BoundedSchedulerPreemptionTarget {
        /// Ownership or lifecycle state that made pidfd admission unsafe.
        target: QemuBoundedSchedulerPreemptionTargetError,
    },
    /// The bounded async driver classified the child as crashed and shut it down.
    #[error("QEMU node crashed during bounded await: {status:?}; shutdown={shutdown:?}")]
    Crashed {
        /// Scheduler-facing crashed-node status.
        status: Box<QemuNodeRunStatus>,
        /// Shutdown escalation report.
        shutdown: Box<QemuShutdownReport>,
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
    /// A frame batch was not paired with its exact physical producer stop.
    #[error("QEMU network output boundary mismatch: {message}")]
    NetworkOutputBoundary {
        /// Missing or inconsistent producer boundary evidence.
        message: String,
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
    /// A host-I/O adapter exceeded an authored production resource ceiling.
    #[error(
        "cannot reserve {requested} units of `{field}` at current {current}; configured {configured}, hard {hard}"
    )]
    ResourceLimit {
        /// Closed resource field whose reservation failed.
        field: &'static str,
        /// Existing admitted usage in field units.
        current: u64,
        /// Additional requested usage in field units.
        requested: u64,
        /// Scenario-authored ceiling in field units.
        configured: u64,
        /// Compiled ceiling in field units.
        hard: u64,
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

    /// Retains a source cleanup cause without replacing its worker allocation.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_ram_source_cleanup(
        operation: &'static str,
        source: crate::ram_source::QemuRamSourceError,
    ) -> Self {
        Self::RamSourceCleanup {
            operation,
            source: crate::QemuAsyncDriverHealthError::ram_source(source),
        }
    }

    /// Attaches scheduler-node context to a shutdown escalation error.
    #[must_use]
    pub const fn from_shutdown(source: QemuShutdownError) -> Self {
        Self::Shutdown { source }
    }

    /// Attaches scheduler-node context to an async-driver failure.
    #[must_use]
    pub fn from_async_driver(source: QemuAsyncDriverError) -> Self {
        if let QemuAsyncDriverError::Runtime(runtime) = &source
            && let Some((field, current, requested, configured, hard)) =
                runtime.resource_limit_coordinates()
        {
            return Self::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            };
        }
        Self::AsyncDriver { source }
    }

    /// Converts a pidfd scheduling-adversary failure into node context.
    #[must_use]
    pub fn from_bounded_scheduler_preemption(source: BoundedSchedulerPreemptionError) -> Self {
        Self::bounded_scheduler_preemption_message(source.to_string())
    }

    /// Attaches node context to a host-adversary evidence failure.
    #[must_use]
    pub fn bounded_scheduler_preemption_message(message: impl Into<String>) -> Self {
        Self::BoundedSchedulerPreemption {
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
        let error = match error {
            error @ QemuNodeError::ShutdownOriginal { .. } => {
                let QemuNodeError::ShutdownOriginal {
                    begin,
                    observations,
                    completion,
                    ..
                } = &error
                else {
                    return Self::Rejected {
                        message: error.to_string(),
                    };
                };
                let source = begin
                    .or_else(|| {
                        observations
                            .iter()
                            .find_map(|(before, after)| before.or(*after))
                    })
                    .or(*completion);
                if let Some(source) = source {
                    return Self::RetainedOperationalFailure {
                        kind: operational_failure_kind(source),
                        source: BackendOperationalCause::new(error),
                    };
                }
                error
            }
            error @ (QemuNodeError::Shutdown { .. }
            | QemuNodeError::ShutdownAfterChannelFailure { .. }) => {
                return Self::RetainedOperationalFailure {
                    kind: BackendOperationalFailureKind::Unavailable,
                    source: BackendOperationalCause::new(error),
                };
            }
            QemuNodeError::AsyncDriver {
                source: QemuAsyncDriverError::OperationalHealth(source),
            }
            | QemuNodeError::RamSourceCleanup { source, .. } => {
                return Self::RetainedOperationalFailure {
                    kind: source.operational_kind(),
                    source: source.into_backend_cause(),
                };
            }
            QemuNodeError::AsyncDriver {
                source: QemuAsyncDriverError::Runtime(runtime),
            } => {
                if let Some(source) = runtime.operational_supervision_source() {
                    return Self::RetainedOperationalFailure {
                        kind: operational_failure_kind(source),
                        source: BackendOperationalCause::new(runtime),
                    };
                }
                QemuNodeError::AsyncDriver {
                    source: QemuAsyncDriverError::Runtime(runtime),
                }
            }
            error => error,
        };

        match error {
            QemuNodeError::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            } => Self::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            },
            error => Self::Rejected {
                message: error.to_string(),
            },
        }
    }
}

fn operational_failure_kind(source: HostSupervisionError) -> BackendOperationalFailureKind {
    match source {
        HostSupervisionError::DeadlineExpired { .. } => BackendOperationalFailureKind::Expired,
        HostSupervisionError::Terminal {
            state: HostOperationState::Canceled,
        } => BackendOperationalFailureKind::Canceled,
        HostSupervisionError::Terminal {
            state: HostOperationState::Expired,
        } => BackendOperationalFailureKind::Expired,
        HostSupervisionError::Terminal { .. } | HostSupervisionError::BorrowedOperation => {
            BackendOperationalFailureKind::Terminal
        }
        HostSupervisionError::InvalidBudget
        | HostSupervisionError::UnboundedInfrastructure { .. } => {
            BackendOperationalFailureKind::InvalidPolicy
        }
        HostSupervisionError::RevisionConflict { .. } => {
            BackendOperationalFailureKind::RevisionConflict
        }
        HostSupervisionError::CapacityExhausted => BackendOperationalFailureKind::CapacityExhausted,
        HostSupervisionError::IdentityExhausted => BackendOperationalFailureKind::IdentityExhausted,
        HostSupervisionError::ProgressRegressed => BackendOperationalFailureKind::ProgressRegressed,
        HostSupervisionError::Unavailable => BackendOperationalFailureKind::Unavailable,
    }
}

#[cfg(test)]
mod tests;
