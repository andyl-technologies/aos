//! Audited Linux descriptor boundary for the AOS sandbox runtime.
//!
//! The crate wraps pidfds, namespace descriptors, race-resistant `openat2`
//! resolution, the descriptor-based mount API, and mount-topology queries.
//! All kernel resources are represented by owned descriptor types. Raw syscall
//! invocation and vendored Linux 6.18 UAPI live only in the private [`uapi`]
//! module; safe callers cannot manufacture a typed descriptor from an integer.
//!
//! The modules divide responsibility as follows:
//!
//! - [`pidfd`] pins a process and obtains typed namespace descriptors;
//! - [`path`] resolves descendants beneath a pre-opened directory;
//! - [`mount`] constructs, attributes, idmaps, and attaches detached mounts;
//! - [`inventory`] lists mounts and reads stable mount metadata.

#![cfg(target_os = "linux")]

pub mod inventory;
pub mod mount;
pub mod path;
pub mod pidfd;
mod uapi;

/// Errors returned by the Linux sandbox descriptor boundary.
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
}

impl Error {
    pub(crate) fn syscall(operation: &'static str) -> Self {
        Self::Syscall {
            operation,
            source: std::io::Error::last_os_error(),
        }
    }

    pub(crate) fn invalid(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidInput {
            field,
            message: message.into(),
        }
    }
}

/// Convenience result type for Linux sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;
