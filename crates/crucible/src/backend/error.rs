//! Errors shared by the pure backend boundary and concrete drivers.

use std::error::Error;
use std::fmt;

/// Reports a backend-boundary failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// The backend operation is not implemented by this backend.
    NotImplemented {
        /// The operation whose implementation is deferred.
        operation: &'static str,
    },
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
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "backend operation {operation} is not implemented yet")
            }
            Self::Unsupported { capability } => {
                write!(f, "backend capability {capability} is unsupported")
            }
            Self::Rejected { message } => f.write_str(message),
        }
    }
}

impl Error for BackendError {}
