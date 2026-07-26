//! Errors returned while building deterministic QEMU launch commands.

use thiserror::Error;

use super::QemuPreSpawnLaunchValidationError;

/// Reports an invalid QEMU launch command.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuLaunchCommandError {
    /// App-random was configured without enabling the white-box callback.
    #[error("app-random QEMU launch requires white-box mode")]
    AppRandomWhileWhiteboxDisabled,
    /// The node name cannot be represented in QEMU's comma-separated plugin args.
    #[error("app-random node name must not contain `,` or `=`")]
    InvalidAppRandomNodeName,
    /// White-box mode lacked a live QEMU port-map validation.
    #[error("white-box QEMU launch requires live setup collision validation")]
    MissingWhiteboxSetupValidation,
    /// A white-box validation was attached while the callback was disabled.
    #[error("white-box setup validation is forbidden when white-box mode is off")]
    WhiteboxSetupValidationWhileDisabled,
    /// A command-line field was empty or could not be represented stably.
    #[error("{field} must be fixed non-empty text without newlines or NUL bytes")]
    InvalidLaunchText {
        /// Invalid command-line field.
        field: &'static str,
    },
    /// An immutable launch input was not resolved to an AOS store path.
    #[error("{field} must be an AOS store path, got `{path}`")]
    InvalidStorePath {
        /// Invalid immutable input field.
        field: &'static str,
        /// Invalid path.
        path: String,
    },
    /// The CoW overlay file name was not a stable relative file name.
    #[error("root overlay file name must be stable relative text, got `{file_name}`")]
    InvalidOverlayFileName {
        /// Invalid overlay file name.
        file_name: String,
    },
    /// The QMP socket file name was not a stable relative file name.
    #[error("QMP socket file name must be stable relative text, got `{file_name}`")]
    InvalidQmpSocketFileName {
        /// Invalid socket file name.
        file_name: String,
    },
    /// A crucible-shmem device length was zero, not a sector multiple, or too large.
    #[error(
        "crucible-shmem block size must be a nonzero sector multiple within bounds, got {size}"
    )]
    InvalidCrucibleShmemBlockSize {
        /// Rejected device length in bytes.
        size: u64,
    },
    /// A plugin path contained a comma, which would be ambiguous in QEMU's plugin option.
    #[error("plugin path must not contain a comma")]
    PluginPathContainsComma,
    /// A plugin descriptor was negative.
    #[error("plugin argument `{field}` has invalid descriptor {fd}")]
    InvalidFileDescriptor {
        /// Invalid descriptor field.
        field: &'static str,
        /// Invalid descriptor value.
        fd: i32,
    },
    /// The resulting argv failed the pre-spawn QEMU launch validator.
    #[error("QEMU launch command failed pre-spawn validation: {source}")]
    PreSpawnValidation {
        /// Validator error.
        source: QemuPreSpawnLaunchValidationError,
    },
}
