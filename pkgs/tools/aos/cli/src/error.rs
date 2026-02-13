use thiserror::Error;

/// Exit code conventions:
///   0 — success
///   1 — build / test failure
///   2 — user error (bad arguments, unknown variant, etc.)
///   3 — nix not found

#[derive(Error, Debug)]
#[allow(dead_code)]
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
}

impl AosError {
    /// Return the process exit code appropriate for this error variant.
    pub fn exit_code(&self) -> i32 {
        match self {
            AosError::NixBuild { .. } | AosError::NixEval { .. } | AosError::ImageBuild { .. } => 1,
            AosError::InvalidArgument { .. } => 2,
            AosError::NixNotFound | AosError::RootNotFound => 3,
        }
    }
}
