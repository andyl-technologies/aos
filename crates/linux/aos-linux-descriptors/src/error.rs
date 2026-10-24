//! Concrete native descriptor errors shared by their actual callers.

/// Errors returned by the Linux descriptor mechanics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A kernel operation failed.
    #[error("{operation} failed: {source}")]
    Syscall {
        /// Stable operation label.
        operation: &'static str,
        /// Kernel error.
        #[source]
        source: std::io::Error,
    },

    /// A path, limit, flag combination, or descriptor violated an API contract.
    #[error("invalid {field}: {message}")]
    InvalidInput {
        /// Contract field being checked.
        field: &'static str,
        /// Human-readable reason.
        message: String,
    },

    /// A descriptor was valid but not of the kernel object type required by
    /// the wrapper.
    #[error("descriptor type mismatch: expected {expected}")]
    WrongDescriptorType {
        /// Required kernel descriptor type.
        expected: &'static str,
    },

    /// The running kernel returned a structure that violates its UAPI
    /// contract or omitted a requested field.
    #[error("malformed kernel {object} response: {message}")]
    MalformedKernelResponse {
        /// UAPI object being decoded.
        object: &'static str,
        /// Validation failure.
        message: String,
    },

    /// A kernel topology exceeded a caller-provided admission bound.
    #[error("{object} exceeds observation limit {limit}")]
    ObservationLimitExceeded {
        /// Topology object being observed.
        object: &'static str,
        /// Maximum number of admitted entries.
        limit: usize,
    },

    /// A bounded kernel exchange did not become ready before its deadline.
    #[error("{operation} exceeded its deadline")]
    DeadlineExceeded {
        /// Stable operation label.
        operation: &'static str,
    },
}

impl Error {
    /// Captures the current OS error using a stable operation label.
    #[must_use]
    pub fn syscall(operation: &'static str) -> Self {
        Self::Syscall {
            operation,
            source: std::io::Error::last_os_error(),
        }
    }

    /// Describes a violated descriptor or observation contract.
    #[must_use]
    pub fn invalid(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidInput {
            field,
            message: message.into(),
        }
    }
}

/// Convenience result type for Linux descriptor operations.
pub type Result<T> = std::result::Result<T, Error>;
