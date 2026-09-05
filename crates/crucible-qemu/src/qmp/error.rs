//! Typed QMP failures and scheduler channel classification.

use super::*;

/// Typed errors returned by the minimal QMP client.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QmpError {
    /// A descriptor name is outside the typed Crucible QMP grammar.
    #[error("invalid QMP descriptor name of {length} bytes")]
    InvalidDescriptorName {
        /// Rejected byte length; invalid bytes are deliberately not retained.
        length: usize,
    },
    /// A hot-fork process contract contains a zero or unbounded identity field.
    #[error("invalid hot-fork child process contract identity")]
    InvalidHotForkChildProcessContract,
    /// Template acquisition crossed into a different retained transaction.
    #[error("hot-fork template generation changed from {expected} to {actual}")]
    HotForkTemplateGenerationChanged {
        /// First nonzero generation observed by this preparation operation.
        expected: u64,
        /// Different generation reported by QEMU.
        actual: u64,
    },
    /// Template preparation terminated without retaining its source barriers.
    #[error("hot-fork template {generation} is not retained: {outcome:?}")]
    HotForkTemplateNotRetained {
        /// Last generation reported by QEMU.
        generation: u64,
        /// Terminal coordinator outcome.
        outcome: QmpHotForkTemplateOutcome,
    },
    /// The bounded acquisition wait ended with non-plugin-ring proofs missing.
    #[error(
        "hot-fork template {generation} still lacks proofs {missing_proofs:#x} after {polls} polls"
    )]
    HotForkTemplateNotQuiescent {
        /// Exact retained transaction generation, still owned by the caller.
        generation: u64,
        /// Number of preparation exchanges attempted.
        polls: usize,
        /// Missing non-plugin-ring proof mask.
        missing_proofs: u64,
    },
    /// A descriptor-bearing send reported an impossible byte count.
    #[error("QMP descriptor transfer wrote {actual} bytes, expected 1..={expected_maximum}")]
    DescriptorTransferLength {
        /// Maximum request bytes supplied to the transport.
        expected_maximum: usize,
        /// Bytes reported by the transport.
        actual: usize,
    },
    /// A previous ambiguous descriptor transfer permanently poisoned the client.
    #[error("QMP connection is poisoned after an ambiguous descriptor transfer")]
    ConnectionPoisoned,
    /// A launch omitted the fixed inert guest-introspection endpoint.
    #[error("QEMU launch did not predeclare the fixed guest-introspection endpoint")]
    DebugGuestEndpointNotPredeclared,
    /// A public low-level load attempted production runtime realization.
    #[error("public QMP loadvm only admits replay-oracle probes, got {purpose:?}")]
    UnauthorizedLoadvmPurpose {
        /// Rejected authorization purpose.
        purpose: crate::QemuLoadvmCommandPurpose,
    },
    /// A QMP stream operation had no timeout budget.
    #[error("{operation} has zero QMP timeout")]
    UnboundedTimeout {
        /// Operation with an invalid timeout.
        operation: &'static str,
    },
    /// A QMP bound was invalid.
    #[error("{operation} has zero QMP bound")]
    InvalidBound {
        /// Operation with an invalid bound.
        operation: &'static str,
    },
    /// A bounded QMP stream operation timed out.
    #[error("{operation} timed out after {timeout:?}")]
    Timeout {
        /// Operation being attempted.
        operation: &'static str,
        /// Timeout budget assigned to the operation.
        timeout: Duration,
    },
    /// A QMP stream operation failed.
    #[error("{operation} failed with {kind:?}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Error kind returned by the stream.
        kind: ErrorKind,
    },
    /// A QMP JSON line could not be decoded or serialized.
    #[error("{operation} JSON failed: {message}")]
    Json {
        /// Operation being attempted.
        operation: &'static str,
        /// JSON error message.
        message: String,
    },
    /// The first QMP line was not a greeting.
    #[error("unexpected QMP greeting: {response}")]
    UnexpectedGreeting {
        /// JSON response that was not a valid greeting.
        response: String,
    },
    /// QMP returned an error object for a typed command.
    #[error("QMP command {command:?} failed: {class}: {description}")]
    Command {
        /// Command that failed.
        command: QmpCommandKind,
        /// QMP error class.
        class: String,
        /// QMP error description.
        description: String,
    },
    /// QMP returned a malformed `query-jobs` response.
    #[error("unexpected QMP job list for {command:?}: {response}")]
    UnexpectedJobList {
        /// Snapshot command awaiting a job result.
        command: QmpCommandKind,
        /// Unexpected `query-jobs` return value.
        response: String,
    },
    /// A typed query returned a structurally invalid payload.
    #[error("malformed typed QMP response for {command:?}: {response}")]
    MalformedTypedResponse {
        /// Query whose response failed validation.
        command: QmpCommandKind,
        /// Unexpected return payload.
        response: String,
    },
    /// QEMU acknowledged a run-state transition but reported another state.
    #[error("QMP command {command:?} produced run state {status:?} (running={running})")]
    UnexpectedRunState {
        /// Transition command that was acknowledged.
        command: QmpCommandKind,
        /// Typed state observed afterward.
        status: QmpRunStateKind,
        /// QEMU's paired running boolean.
        running: bool,
    },
    /// A QMP snapshot job reported an error.
    #[error("QMP job {job_id} for {command:?} failed: {detail}")]
    JobFailed {
        /// Snapshot command awaiting a job result.
        command: QmpCommandKind,
        /// QMP job id.
        job_id: String,
        /// QMP job error detail.
        detail: String,
    },
    /// A QMP snapshot job did not reach the concluded state.
    #[error("QMP job {job_id} for {command:?} did not conclude after {polls} polls")]
    JobNotConcluded {
        /// Snapshot command awaiting a job result.
        command: QmpCommandKind,
        /// QMP job id.
        job_id: String,
        /// Number of `query-jobs` polls attempted.
        polls: usize,
    },
    /// A QMP JSON line exceeded the configured byte bound before newline.
    #[error("QMP line for {operation} exceeded {max_bytes} bytes")]
    LineTooLong {
        /// Operation awaiting a line.
        operation: &'static str,
        /// Maximum configured line size.
        max_bytes: usize,
    },
    /// Too many asynchronous event objects arrived while awaiting one command response.
    #[error("QMP command {command:?} exceeded {limit} skipped async events")]
    AsyncEventLimitExceeded {
        /// Command awaiting a response.
        command: QmpCommandKind,
        /// Maximum events skipped for the command.
        limit: usize,
    },
    /// QMP returned neither an event, a return object, nor an error object.
    #[error("unexpected QMP response for {command:?}: {response}")]
    UnexpectedResponse {
        /// Command awaiting a response.
        command: QmpCommandKind,
        /// Unexpected JSON response.
        response: String,
    },
}

impl QmpError {
    pub(super) fn from_io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }

    pub(super) fn from_io_with_timeout(
        operation: &'static str,
        timeout: Duration,
        error: io::Error,
    ) -> Self {
        match error.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => Self::Timeout { operation, timeout },
            kind => Self::Io { operation, kind },
        }
    }
}

impl From<QmpError> for QemuNodeChannelError {
    fn from(error: QmpError) -> Self {
        match error {
            QmpError::Timeout { operation, timeout } => {
                QemuNodeChannelError::bounded_await_timeout(
                    operation,
                    format!("QMP operation timed out after {timeout:?}"),
                    timeout,
                )
            }
            other => QemuNodeChannelError::new("qmp", other.to_string()),
        }
    }
}
