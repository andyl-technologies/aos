//! Errors returned while building deterministic QEMU launch commands.

use thiserror::Error;

use super::QemuPreSpawnLaunchValidationError;

/// Reports an invalid QEMU launch command.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuLaunchCommandError {
    /// A process generation cannot use the reserved zero value.
    #[error("QEMU plugin process generation must be nonzero")]
    ZeroProcessGeneration,
    /// App-random was configured without enabling the white-box callback.
    #[error("app-random QEMU launch requires white-box mode")]
    AppRandomWhileWhiteboxDisabled,
    /// Only part of the app-random branch configuration was supplied.
    #[error("app-random branch seed and prefix draw count must be configured together")]
    InvalidAppRandomBranchConfiguration,
    /// App-random continuation cursors did not match their declared bounds.
    #[error("app-random continuation cursors do not match their declared draw bounds")]
    InvalidAppRandomContinuationConfiguration,
    /// The node name cannot be represented in QEMU's comma-separated plugin args.
    #[error("app-random node name must not contain `,` or `=`")]
    InvalidAppRandomNodeName,
    /// A terminal state dump lacked fingerprint mode, a target, or a safe path.
    #[error(
        "terminal state dump requires fingerprint mode, a nonzero target, and an absolute comma-free path"
    )]
    InvalidStateDumpConfiguration,
    /// A translation-prefetch experiment lacked a safe absolute report path.
    #[error("translation-prefetch report path must be absolute and comma-free")]
    InvalidTranslationPrefetchReportPath,
    /// The executable name did not identify an implemented fault architecture.
    #[error("QEMU executable does not identify an x86_64 or aarch64 fault backend: `{executable}`")]
    UnsupportedFaultCapabilityArchitecture {
        /// Executable path whose basename was unsupported.
        executable: String,
    },
    /// The supplied capability declaration was not a canonical exact manifest.
    #[error("QEMU launch requires an exact admitted World node fault-capability manifest")]
    InvalidFaultCapabilityRequirement,
    /// A production launch was not bound to an admitted World node manifest.
    #[error("production QEMU launch capability requirement is not World-bound")]
    UnboundFaultCapabilityRequirement,
    /// The VM and plugin target do not match the manifest's scenario node.
    #[error("QEMU VM, plugin, and fault-capability node identities do not match")]
    FaultCapabilityNodeMismatch,
    /// The QEMU system executable architecture differs from the World manifest.
    #[error("QEMU executable architecture does not match the fault-capability manifest")]
    FaultCapabilityArchitectureMismatch,
    /// The launch CPU model does not match the manifest's realized CPU type.
    #[error("QEMU launch CPU model does not match the fault-capability manifest")]
    FaultCapabilityCpuModelMismatch,
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
    /// An initrd was supplied for a firmware-only launch with no direct kernel.
    #[error("QEMU initrd launch requires a directly loaded kernel")]
    InitrdWithoutKernel,
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
