//! Domain failures produced by Nix tool discovery and execution.
//!
//! These errors preserve process diagnostics without selecting the caller's
//! presentation or process exit status.

use thiserror::Error;

/// Describes a Nix invocation or project-discovery failure.
#[derive(Debug, Error)]
pub enum NixError {
    /// Indicates a failed Nix command and its captured diagnostics.
    #[error("nix-build failed (exit code {exit_code}): {stderr}")]
    NixBuild {
        /// Records the unsuccessful command's exit status.
        exit_code: i32,
        /// Retains stderr when diagnostics were not streamed live.
        stderr: String,
    },
    /// Indicates an unsuccessful Nix evaluation.
    #[error("nix evaluation failed: {message}")]
    NixEval {
        /// Explains the evaluation failure.
        message: String,
    },
    /// Indicates that the required Nix executable is unavailable.
    #[error("nix is not installed or not in PATH — install it from https://nixos.org/download")]
    NixNotFound,
    /// Indicates that the project root could not be located.
    #[error(
        "cannot find project root (no default.nix found). Set AOS_ROOT or run from within the repository"
    )]
    RootNotFound,
}
