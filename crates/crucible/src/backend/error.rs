//! Errors shared by the pure backend boundary and concrete drivers.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::shared_cause::{ClosedOperationalCause, SharedOperationalCause};

/// Shares an original operational cause through portable backend error boundaries.
///
/// Type erasure is limited to this implementation-independent error boundary;
/// the original cause remains available through [`Error::source`] and downcast.
/// Clones share custody, including any native buffers or resource loans owned
/// by that error, until the final clone closes. Equality identifies the same
/// cause allocation and is never a guest identity or serialized state input.
// crucible-lint: allow erased-error -- the pure backend boundary retains concrete driver causes and shared custody without implementation dependencies.
pub struct BackendOperationalCause(Option<Arc<dyn ClosedOperationalCause>>);

impl BackendOperationalCause {
    /// Retains an original typed cause without replacing it with diagnostics.
    ///
    /// The caller must fund the complete shared allocation and owned payloads
    /// before construction. The final observer deallocates the shared control
    /// before destroying the cause and releasing any original loans it retains.
    #[must_use]
    pub fn new<E: Error + Send + Sync + 'static>(source: E) -> Self {
        SharedOperationalCause::new(source).into_backend_cause()
    }

    pub(super) fn from_shared<E: Error + Send + Sync + 'static>(source: Arc<E>) -> Self {
        Self(Some(source))
    }

    fn shared(&self) -> &Arc<dyn ClosedOperationalCause> {
        match &self.0 {
            Some(shared) => shared,
            None => unreachable!("a live backend cause owns its original error"),
        }
    }
}

impl Clone for BackendOperationalCause {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for BackendOperationalCause {
    fn drop(&mut self) {
        if let Some(shared) = self.0.take() {
            shared.close();
        }
    }
}

impl fmt::Debug for BackendOperationalCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BackendOperationalCause")
            .field(self.shared().as_ref())
            .finish()
    }
}

impl fmt::Display for BackendOperationalCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.shared().as_ref(), formatter)
    }
}

impl Error for BackendOperationalCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.shared().as_ref())
    }
}

impl PartialEq for BackendOperationalCause {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.shared(), other.shared())
    }
}

impl Eq for BackendOperationalCause {}

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
    /// An infrastructure failure retains its original concrete cause and custody.
    RetainedOperationalFailure {
        /// Actionable failure category independent of the original error text.
        kind: BackendOperationalFailureKind,
        /// Shared original cause, including its native resource ownership.
        source: BackendOperationalCause,
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

impl BackendError {
    /// Returns an explicit infrastructure category without interpreting its text.
    #[must_use]
    pub const fn operational_kind(&self) -> Option<BackendOperationalFailureKind> {
        match self {
            Self::OperationalFailure { kind, .. }
            | Self::RetainedOperationalFailure { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { capability } => {
                write!(f, "backend capability {capability} is unsupported")
            }
            Self::Rejected { message } => f.write_str(message),
            Self::OperationalFailure { message, .. } => f.write_str(message),
            Self::RetainedOperationalFailure { source, .. } => source.fmt(f),
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

impl Error for BackendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RetainedOperationalFailure { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(all(test, unix))]
#[path = "error/tests.rs"]
mod tests;
