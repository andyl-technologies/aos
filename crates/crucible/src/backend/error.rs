//! Errors shared by the pure backend boundary and concrete drivers.

use std::error::Error;
use std::fmt;

/// Classifies an infrastructure failure independently of guest execution.
///
/// These categories carry no host clock coordinates and never describe a
/// modeled guest outcome. Concrete adapters retain their original typed cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendOperationalFailureKind {
    /// An applicable host deadline elapsed.
    Expired,
    /// Operational cancellation stopped continuation.
    Canceled,
    /// The requested infrastructure policy was invalid or unbounded.
    InvalidPolicy,
    /// The caller's policy revision was stale.
    RevisionConflict,
    /// The infrastructure operation roster was full.
    CapacityExhausted,
    /// An operation identity or revision could not advance.
    IdentityExhausted,
    /// Meaningful progress moved backward.
    ProgressRegressed,
    /// Infrastructure ownership could not be established.
    Unavailable,
    /// A completed operation was used again.
    Terminal,
}

/// Reports a backend-boundary failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// The backend does not support an optional capability.
    Unsupported {
        /// Optional capability rejected by this backend.
        capability: &'static str,
    },
    /// The backend rejected a request.
    Rejected {
        /// A deterministic diagnostic message.
        message: String,
    },
    /// Infrastructure supervision stopped a backend operation.
    OperationalFailure {
        /// Actionable failure category independent of the diagnostic text.
        kind: BackendOperationalFailureKind,
        /// Concrete adapter diagnostic for the retained original cause.
        message: String,
    },
    /// A backend-owned production resource reservation failed.
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

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { capability } => {
                write!(f, "backend capability {capability} is unsupported")
            }
            Self::Rejected { message } => f.write_str(message),
            Self::OperationalFailure { message, .. } => f.write_str(message),
            Self::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            } => write!(
                f,
                "backend resource `{field}` cannot reserve {requested} units at current {current}; configured {configured}, hard {hard}"
            ),
        }
    }
}

impl Error for BackendError {}
