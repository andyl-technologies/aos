//! Error types and exit-code conventions shared by all `aos` binaries.
//!
//! [`AosError`] enumerates the user-facing failure modes of the CLI
//! family (`aos`, `apm`, `apr`). Each variant carries enough context to
//! render a helpful message via its `Display` impl (derived with
//! `thiserror`), and maps to a process exit code through
//! [`AosError::exit_code`].
//!
//! Exit code conventions for the core `aos` commands:
//!
//! ```text
//! 0 -- success
//! 1 -- build / test failure
//! 2 -- user error (bad arguments, unknown variant, etc.)
//! 3 -- nix not found
//! ```
//!
//! The APM (package manager) variants follow the extended convention
//! documented in `cli.md`: `2` for missing packages, `3` for download
//! failures, `4` for hash mismatches, and `100` for user cancellation. An
//! operation interrupted by SIGINT exits with the shell-standard status 130.

use thiserror::Error;

/// The unified error type for `aos` CLI operations.
///
/// Variants cover Nix invocation failures, project-discovery problems,
/// argument validation, and the APM package-manager error surface. Use
/// [`exit_code`](Self::exit_code) to translate an error into the process
/// exit status mandated by the CLI conventions.
#[derive(Error, Debug)]
pub enum AosError {
    /// `nix-build` exited non-zero; carries the exit code and captured
    /// stderr (which may be empty if it was already streamed live).
    #[error("nix-build failed (exit code {exit_code}): {stderr}")]
    NixBuild { exit_code: i32, stderr: String },

    /// `nix-instantiate --eval` (or an equivalent evaluation) failed.
    #[error("nix evaluation failed: {message}")]
    NixEval { message: String },

    /// Building a disk/VM image failed after the Nix build succeeded.
    #[error("image build failed: {message}")]
    ImageBuild { message: String },

    /// No `nix-build` binary was found on `PATH`.
    #[error("nix is not installed or not in PATH — install it from https://nixos.org/download")]
    NixNotFound,

    /// The project root (a directory containing `default.nix`) could not
    /// be located from `AOS_ROOT`, the working directory, or the binary
    /// location.
    #[error(
        "cannot find project root (no default.nix found). Set AOS_ROOT or run from within the repository"
    )]
    RootNotFound,

    /// The user supplied an invalid argument or flag combination.
    #[error("{message}")]
    InvalidArgument { message: String },

    // APM (package manager) errors
    /// The named package does not exist in any configured registry.
    #[error("package not found: {name}")]
    PackageNotFound { name: String },

    /// A package registry could not be read, fetched, or updated.
    #[error("registry error: {message}")]
    RegistryError { message: String },

    /// Downloading a package artifact failed (network or I/O).
    #[error("download error: {message}")]
    DownloadError { message: String },

    /// A downloaded artifact's hash did not match the expected value.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// A user profile could not be created, read, or updated.
    #[error("profile error: {message}")]
    ProfileError { message: String },

    /// A registry removal was refused because packages installed from it
    /// are still present.
    #[error("registry '{name}' still has {count} installed package(s) — remove them first")]
    RegistryHasPackages { name: String, count: usize },

    /// The user aborted an interactive confirmation prompt.
    #[error("operation cancelled by user")]
    UserCancelled,

    /// A long-running operation was interrupted while retaining resumable state.
    #[error("{message}")]
    Interrupted { message: String },
}

impl AosError {
    /// Returns the process exit code appropriate for this error variant.
    ///
    /// Core variants follow the `aos` convention (1 = build failure,
    /// 2 = user error, 3 = nix missing); APM variants follow the package
    /// manager convention from `cli.md` (2 = not found, 3 = download
    /// error, 4 = hash mismatch, 100 = cancelled).
    pub fn exit_code(&self) -> i32 {
        match self {
            AosError::NixBuild { .. } | AosError::NixEval { .. } | AosError::ImageBuild { .. } => 1,
            AosError::InvalidArgument { .. } => 2,
            AosError::NixNotFound | AosError::RootNotFound => 3,
            // APM exit codes (per cli.md)
            AosError::PackageNotFound { .. } => 2,
            AosError::RegistryError { .. } | AosError::ProfileError { .. } => 1,
            AosError::DownloadError { .. } => 3,
            AosError::HashMismatch { .. } => 4,
            AosError::RegistryHasPackages { .. } => 1,
            AosError::UserCancelled => 100,
            AosError::Interrupted { .. } => 130,
        }
    }
}
