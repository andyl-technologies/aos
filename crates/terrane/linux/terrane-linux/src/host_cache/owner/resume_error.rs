//! Distinguishes untouched queue refusals from failures after owner acceptance.

use super::CompletedRecovery;
use std::{fmt, io};

/// Reports whether a Resume request entered the physical owner queue.
///
/// Queue refusal returns the original private receipt for a later explicit
/// retry. Acceptance errors never return it: the physical owner retains the
/// outcome and durable custody, including any uncertain transport submission.
pub enum NativeResumeError {
    /// Returns a request on which the physical owner performed no effects.
    Unsubmitted {
        /// Describes the stopped or full queue.
        error: io::Error,
        /// Retains the original pre-submission allocation and its completion.
        ///
        /// A later explicit retry can pass `*completed` to `resume_recovered`.
        /// No completion or recovery authority is reconstructed on refusal.
        completed: Box<CompletedRecovery>,
    },
    /// Reports failure after queue acceptance, with custody retained by the owner.
    ///
    /// This category alone does not assert that an RPC was attempted. The
    /// executor retains the actual before-submission or uncertain outcome.
    Accepted(io::Error),
}

impl fmt::Debug for NativeResumeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsubmitted { error, .. } => {
                formatter.debug_tuple("Unsubmitted").field(error).finish()
            }
            Self::Accepted(error) => formatter.debug_tuple("Accepted").field(error).finish(),
        }
    }
}

impl fmt::Display for NativeResumeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsubmitted { error, .. } => {
                write!(formatter, "Resume was not submitted: {error}")
            }
            Self::Accepted(error) => write!(formatter, "accepted Resume failed: {error}"),
        }
    }
}

impl std::error::Error for NativeResumeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unsubmitted { error, .. } | Self::Accepted(error) => Some(error),
        }
    }
}
