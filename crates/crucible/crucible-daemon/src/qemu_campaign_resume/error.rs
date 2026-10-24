//! Keeps exact-resume phase, shutdown and retirement failures in one owned value.
//!
//! The runner records all completed boundary outcomes before classification.
//! Typed secondary causes, including an existing Main receipt, move inline;
//! combining failures creates no allocation, new operation or cleanup proof.

use crate::{AttemptWorkerFailure, CheckpointHandoffFailure};
use crucible_engine::SchedulerError;

/// Owns every failure produced by one exact-resume execution boundary.
#[derive(Debug)]
pub(crate) struct QemuProductionExactResumeExecutionRunnerError<F, D> {
    /// Keeps the first preparation, materialization or driver refusal.
    pub(crate) first: Option<ResumeFailure<F, D>>,
    /// Keeps the independently observed actual lifecycle shutdown refusal.
    pub(crate) shutdown: Option<SchedulerError>,
    /// Keeps actual factory retirement history and any original receipt.
    pub(crate) retirement: Option<F>,
}

impl<F, D> From<ResumeFailure<F, D>> for QemuProductionExactResumeExecutionRunnerError<F, D> {
    fn from(first: ResumeFailure<F, D>) -> Self {
        Self {
            first: Some(first),
            shutdown: None,
            retirement: None,
        }
    }
}

impl<F, D> std::fmt::Display for QemuProductionExactResumeExecutionRunnerError<F, D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(shutdown) = &self.shutdown {
            if self.first.is_some() {
                write!(
                    formatter,
                    "resumed production cleanup failed after a prior runner failure: {shutdown}"
                )?;
            } else {
                write!(
                    formatter,
                    "clean up resumed production campaign lifecycle: {shutdown}"
                )?;
            }
            if self.retirement.is_some() {
                formatter.write_str("; independent lifecycle retirement also failed")?;
            }
            return Ok(());
        }
        if self.retirement.is_some() {
            return formatter.write_str("retire resumed production campaign lifecycle");
        }
        match &self.first {
            Some(first) => std::fmt::Display::fmt(first, formatter),
            None => formatter.write_str("production exact-resume failure has no recorded cause"),
        }
    }
}

impl<F, D> std::error::Error for QemuProductionExactResumeExecutionRunnerError<F, D>
where
    F: std::error::Error + 'static,
    D: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(first) = &self.first {
            return Some(first);
        }
        if let Some(shutdown) = &self.shutdown {
            return Some(shutdown);
        }
        self.retirement.as_ref().map(|error| error as _)
    }
}

/// Failure from one exact production-resume phase.
#[derive(Debug)]
pub(crate) enum ResumeFailure<F, D> {
    /// The resume-only runner received an execution without a durable root.
    MissingCheckpoint,
    /// Exact closure installation or guarded lifecycle construction failed.
    Lifecycle(F),
    /// The checkpoint retained only an event-log suffix.
    IncompleteEventLog(u64),
    /// A selected continuation reached resume without an independent cold proof.
    MissingSelectedOriginProof,
    /// An ordinary attempt reached resume without an independent start-prefix proof.
    MissingAttemptStartProof,
    /// The restored physical source differs from the independently replayed boundary.
    SelectedOriginMismatch,
    /// The restored event log does not begin with the independently replayed start prefix.
    AttemptStartMismatch,
    /// Restored cumulative event evidence exceeded a campaign bound.
    EventLogLimit {
        /// Stable name of the exceeded bound.
        limit: &'static str,
    },
    /// Modeled driving or result construction failed.
    Driver(D),
    /// A checkpoint was returned without a sticky checkpoint request.
    UnsolicitedCheckpoint,
    /// Capturing a later exact checkpoint failed.
    CheckpointCapture(SchedulerError),
    /// Exact terminal execution fingerprint capture failed before teardown.
    TerminalFingerprintCapture(SchedulerError),
    /// Durable root-before-write handoff for a later checkpoint failed.
    CheckpointHandoff(CheckpointHandoffFailure),
}

impl<F, D> std::fmt::Display for ResumeFailure<F, D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCheckpoint => {
                formatter.write_str("production exact-resume runner received no checkpoint root")
            }
            Self::Lifecycle(_) => formatter.write_str("restore production campaign lifecycle"),
            Self::IncompleteEventLog(prior) => write!(
                formatter,
                "production checkpoint event log begins after {prior} prior events"
            ),
            Self::MissingSelectedOriginProof => formatter
                .write_str("selected continuation resume received no independent origin proof"),
            Self::MissingAttemptStartProof => formatter
                .write_str("ordinary attempt resume received no independent start-prefix proof"),
            Self::SelectedOriginMismatch => formatter
                .write_str("selected continuation physical source differs from cold replay"),
            Self::AttemptStartMismatch => formatter
                .write_str("ordinary attempt checkpoint differs from cold start-prefix replay"),
            Self::EventLogLimit { limit } => {
                write!(
                    formatter,
                    "production checkpoint event log exceeded `{limit}`"
                )
            }
            Self::Driver(_) => formatter.write_str("resumed production campaign driver failed"),
            Self::UnsolicitedCheckpoint => formatter
                .write_str("resumed production campaign driver returned an unsolicited checkpoint"),
            Self::CheckpointCapture(error) => {
                write!(formatter, "capture resumed production checkpoint: {error}")
            }
            Self::TerminalFingerprintCapture(error) => {
                write!(formatter, "capture resumed terminal fingerprints: {error}")
            }
            Self::CheckpointHandoff(error) => {
                write!(formatter, "handoff resumed production checkpoint: {error}")
            }
        }
    }
}

impl<F, D> std::error::Error for ResumeFailure<F, D>
where
    F: std::error::Error + 'static,
    D: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lifecycle(error) => Some(error),
            Self::Driver(error) => Some(error),
            Self::CheckpointCapture(error) | Self::TerminalFingerprintCapture(error) => Some(error),
            Self::CheckpointHandoff(error) => Some(error),
            Self::MissingCheckpoint
            | Self::IncompleteEventLog(_)
            | Self::MissingSelectedOriginProof
            | Self::MissingAttemptStartProof
            | Self::SelectedOriginMismatch
            | Self::AttemptStartMismatch
            | Self::EventLogLimit { .. }
            | Self::UnsolicitedCheckpoint => None,
        }
    }
}

/// Wraps a single phase failure without changing its worker classification.
pub(super) fn wrap_resume_failure<F, D>(
    failure: AttemptWorkerFailure<ResumeFailure<F, D>>,
) -> AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(first) => AttemptWorkerFailure::Retryable(first.into()),
        AttemptWorkerFailure::Canceled(first) => AttemptWorkerFailure::Canceled(first.into()),
        AttemptWorkerFailure::Terminal(first) => AttemptWorkerFailure::Terminal(first.into()),
    }
}

/// Combines actual outcomes after shutdown and retirement have both run once.
///
/// A phase failure alone retains its classification. Either independent
/// boundary refusal is terminal, and all owned causes survive in the result.
/// No field is a resource-return predicate or permission to repeat work.
///
/// # Errors
/// Returns the actual phase, shutdown and retirement causes whenever any
/// outcome refused; no cause is discarded to select another failure.
pub(super) fn finish_resume_outcomes<P, E, F, D>(
    driven: Result<P, AttemptWorkerFailure<ResumeFailure<F, D>>>,
    shutdown: Result<E, SchedulerError>,
    retirement: Result<(), F>,
) -> Result<(P, E), AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>>> {
    match (driven, shutdown, retirement) {
        (Ok(pending), Ok(events), Ok(())) => Ok((pending, events)),
        (driven, shutdown, retirement) => {
            let boundary_failed = shutdown.is_err() || retirement.is_err();
            let (first, class) = match driven {
                Ok(_) => (None, FailureClass::Terminal),
                Err(AttemptWorkerFailure::Retryable(first)) => {
                    (Some(first), FailureClass::Retryable)
                }
                Err(AttemptWorkerFailure::Canceled(first)) => (Some(first), FailureClass::Canceled),
                Err(AttemptWorkerFailure::Terminal(first)) => (Some(first), FailureClass::Terminal),
            };
            let error = QemuProductionExactResumeExecutionRunnerError {
                first,
                shutdown: shutdown.err(),
                retirement: retirement.err(),
            };
            if boundary_failed {
                return Err(AttemptWorkerFailure::Terminal(error));
            }
            Err(match class {
                FailureClass::Retryable => AttemptWorkerFailure::Retryable(error),
                FailureClass::Canceled => AttemptWorkerFailure::Canceled(error),
                FailureClass::Terminal => AttemptWorkerFailure::Terminal(error),
            })
        }
    }
}

#[derive(Clone, Copy)]
enum FailureClass {
    Retryable,
    Canceled,
    Terminal,
}
