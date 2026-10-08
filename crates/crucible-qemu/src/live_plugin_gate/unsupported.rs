//! Unsupported-host production plugin-installation surface.
//!
//! Production launch requires Linux inherited-descriptor and shared-memory
//! setup primitives. The public configuration remains available on other
//! hosts, while execution fails before starting a child process.

use std::path::PathBuf;
use std::time::Duration;

use crucible::ExecutionFingerprint;
use thiserror::Error;

use crate::{
    LivePluginGuestArchitecture, QemuLaunchAppRandomConfig, QemuLaunchPluginSwitch,
    QemuRootImageFormat,
};

/// Configuration for a production plugin-installation probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePluginInstallGateConfig;

impl LivePluginInstallGateConfig {
    /// Builds an install-gate configuration with bounded defaults.
    #[must_use]
    pub fn new(
        _qemu_executable: impl Into<PathBuf>,
        _plugin: impl Into<PathBuf>,
        _kernel: impl Into<PathBuf>,
        _root_image: impl Into<PathBuf>,
        _run_directory: impl Into<PathBuf>,
        _architecture: LivePluginGuestArchitecture,
    ) -> Self {
        Self
    }

    /// Returns this configuration with a content-addressed initrd.
    #[must_use]
    pub fn with_initrd(self, _initrd: impl Into<PathBuf>) -> Self {
        self
    }

    /// Returns this configuration with an explicit guest kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(self, _kernel_cmdline: impl Into<String>) -> Self {
        self
    }

    /// Returns this configuration with the declared immutable root-image format.
    #[must_use]
    pub const fn with_root_image_format(self, _format: QemuRootImageFormat) -> Self {
        self
    }

    /// Returns this configuration with the optional white-box callback enabled.
    #[must_use]
    pub const fn with_whitebox(self, _whitebox: QemuLaunchPluginSwitch) -> Self {
        self
    }

    /// Returns this configuration with the retained guest's doorbell instruction ABI.
    #[must_use]
    pub const fn with_doorbell_instruction_abi_version(self, _version: u16) -> Self {
        self
    }

    /// Returns this configuration with the seeded app-random path enabled.
    #[must_use]
    pub fn with_app_random(self, _app_random: QemuLaunchAppRandomConfig) -> Self {
        self
    }

    /// Returns this configuration with live boundary fingerprint sampling set.
    #[must_use]
    pub const fn with_fingerprint(self, _fingerprint: QemuLaunchPluginSwitch) -> Self {
        self
    }

    /// Returns this configuration with a different exact icount boundary.
    #[must_use]
    pub const fn with_horizon_icount(self, _horizon_icount: u64) -> Self {
        self
    }

    /// Returns this configuration with a different host-side completion bound.
    #[must_use]
    pub const fn with_completion_timeout(self, _completion_timeout: Duration) -> Self {
        self
    }
}

/// Failure returned when production execution is requested on an unsupported host.
#[derive(Debug, Error)]
pub enum LivePluginInstallGateError {
    /// The inherited-descriptor production backend is unavailable on this host.
    #[error("production local-QEMU execution requires a Linux host")]
    UnsupportedHost,
}

/// Observed evidence returned by a successful production plugin-installation probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePluginInstallReport {
    /// Control protocol version negotiated during the handshake.
    pub negotiated_proto_version: u32,
    /// Shared-memory ABI version negotiated during the handshake.
    pub negotiated_abi_version: u32,
    /// VM slot accepted by the plugin.
    pub negotiated_slot: u32,
    /// Node count bound into the setup handshake.
    pub negotiated_node_count: u32,
    /// Whether the plugin acknowledged a schedulable setup.
    pub setup_ack_ready: bool,
    /// Validated shared-memory setup region length.
    pub shmem_region_len: u64,
    /// Exact completed instruction count.
    pub completed_icount: u64,
    /// Whether the boot barrier enforced the requested ceiling.
    pub boot_barrier_ceiling_enforced: bool,
    /// Execution fingerprint published at the boundary.
    pub execution_fingerprint: ExecutionFingerprint,
    /// Whether the run-phase control channel remained silent.
    pub run_control_silent: bool,
    /// Whether the plugin consumed the teardown request.
    pub plugin_quit_consumed: bool,
    /// Whether the child exited successfully.
    pub orderly_child_exit: bool,
    /// Whether the Rust plugin remained the sole time authority.
    pub time_authority_is_rust_plugin: bool,
    /// Setup-time x86 white-box region, when observed.
    pub whitebox_setup_region: Option<String>,
    /// Number of admitted white-box markers.
    pub whitebox_marker_count: usize,
    /// First admitted white-box marker instruction count.
    pub whitebox_marker_icount: Option<u64>,
    /// Last admitted white-box marker instruction count.
    pub whitebox_last_marker_icount: Option<u64>,
    /// Semantic point of the first admitted white-box marker.
    pub whitebox_marker_point: Option<String>,
    /// Number of validated live app-random decisions.
    pub app_random_decision_count: usize,
    /// First live app-random request identifier.
    pub app_random_request_id: Option<u64>,
    /// First validated live app-random value.
    pub app_random_value: Option<u64>,
    /// First live app-random request width.
    pub app_random_width_bits: Option<u8>,
}

/// Rejects a production plugin-installation probe on an unsupported host.
///
/// # Errors
///
/// Always returns [`LivePluginInstallGateError::UnsupportedHost`].
pub fn run_live_plugin_install_gate(
    _config: &LivePluginInstallGateConfig,
) -> Result<LivePluginInstallReport, LivePluginInstallGateError> {
    Err(LivePluginInstallGateError::UnsupportedHost)
}
