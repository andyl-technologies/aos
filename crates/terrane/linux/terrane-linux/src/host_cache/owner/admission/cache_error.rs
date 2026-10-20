//! Preserves the actual admission receipt when cache handoff is not submitted.

use std::{error::Error, fmt, io};

/// Distinguishes queue refusal from failure after the owner accepts a handoff.
pub enum NativeAdmissionHandoffError<A> {
    /// Returns the original admission because no physical command was accepted.
    Unsubmitted {
        /// Explains the queue or stopped-owner refusal.
        error: io::Error,
        /// Retains the genuine completed admission for retry.
        admission: Box<A>,
    },
    /// Reports accepted work whose resources remain with the physical owner.
    Accepted(io::Error),
}

impl<A> fmt::Debug for NativeAdmissionHandoffError<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsubmitted { error, .. } => formatter
                .debug_struct("Unsubmitted")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::Accepted(error) => formatter.debug_tuple("Accepted").field(error).finish(),
        }
    }
}

impl<A> fmt::Display for NativeAdmissionHandoffError<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsubmitted { error, .. } | Self::Accepted(error) => error.fmt(formatter),
        }
    }
}

impl<A> Error for NativeAdmissionHandoffError<A> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unsubmitted { error, .. } | Self::Accepted(error) => Some(error),
        }
    }
}
