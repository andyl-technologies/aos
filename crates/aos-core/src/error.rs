use thiserror::Error;

/// Exit code conventions:
///   0 — success
///   1 — build / test failure
///   2 — user error (bad arguments, unknown variant, etc.)
///   3 — nix not found

#[derive(Error, Debug)]
pub enum AosError {
    #[error("nix-build failed (exit code {exit_code}): {stderr}")]
    NixBuild { exit_code: i32, stderr: String },

    #[error("nix evaluation failed: {message}")]
    NixEval { message: String },

    #[error("image build failed: {message}")]
    ImageBuild { message: String },

    #[error("nix is not installed or not in PATH — install it from https://nixos.org/download")]
    NixNotFound,

    #[error("cannot find project root (no default.nix found). Set AOS_ROOT or run from within the repository")]
    RootNotFound,

    #[error("{message}")]
    InvalidArgument { message: String },

    // APM (package manager) errors
    #[error("package not found: {name}")]
    PackageNotFound { name: String },

    #[error("registry error: {message}")]
    RegistryError { message: String },

    #[error("download error: {message}")]
    DownloadError { message: String },

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("profile error: {message}")]
    ProfileError { message: String },

    #[error("registry '{name}' still has {count} installed package(s) — remove them first")]
    RegistryHasPackages { name: String, count: usize },

    #[error("operation cancelled by user")]
    UserCancelled,
}

impl AosError {
    /// Return the process exit code appropriate for this error variant.
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
        }
    }
}
