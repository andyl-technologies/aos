//! Package-operation failures interpreted by the command-line applications.
//!
//! The package manager reports domain failures without choosing a process exit
//! status. Applications retain their own exit-code and diagnostic conventions.

use thiserror::Error;

/// Describes a package operation that could not complete.
#[derive(Debug, Error)]
pub enum PackageError {
    /// Indicates an invalid operation argument.
    #[error("{message}")]
    InvalidArgument {
        /// Explains the invalid argument.
        message: String,
    },
    /// Indicates that no configured registry contains the requested package.
    #[error("package not found: {name}")]
    PackageNotFound {
        /// Names the requested package.
        name: String,
    },
    /// Indicates a registry read or synchronization failure.
    #[error("registry error: {message}")]
    RegistryError {
        /// Explains the registry failure.
        message: String,
    },
    /// Indicates an artifact download failure.
    #[error("download error: {message}")]
    DownloadError {
        /// Explains the download failure.
        message: String,
    },
    /// Indicates an artifact whose observed identity differs from its expected identity.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Contains the authenticated expected identity.
        expected: String,
        /// Contains the observed identity.
        actual: String,
    },
    /// Indicates a package profile that could not be read or updated.
    #[error("profile error: {message}")]
    ProfileError {
        /// Explains the profile failure.
        message: String,
    },
    /// Indicates a registry still referenced by installed packages.
    #[error("registry '{name}' still has {count} installed package(s) — remove them first")]
    RegistryHasPackages {
        /// Names the registry.
        name: String,
        /// Counts the installed packages referencing it.
        count: usize,
    },
    /// Indicates that the operator declined an interactive confirmation.
    #[error("operation cancelled by user")]
    UserCancelled,
    /// Indicates interruption while resumable state remains retained.
    #[error("{message}")]
    Interrupted {
        /// Explains the interruption and retained state.
        message: String,
    },
}
