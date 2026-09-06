//! Non-Linux production-QEMU API compatibility surface.
//!
//! Production QEMU launch depends on Linux inherited-descriptor and
//! shared-memory setup primitives. These types preserve the
//! platform-neutral control-plane API while every operation that would
//! launch the local backend fails explicitly before starting a child
//! process.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    ProductionAppRandomConfig, ProductionGdbstubChannelConfig, ProductionGuestArchitecture,
    ProductionNodeBackend, ProductionNodeBackends, ProductionPluginSwitch,
    ProductionRootImageFormat,
};
use crucible::{ExecutionFingerprint, model::FaultResourceLimits};
use thiserror::Error;

/// Configuration for a production plugin-installation probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPluginInstallConfig;

impl ProductionPluginInstallConfig {
    /// Builds an install-gate configuration with bounded defaults.
    #[must_use]
    pub fn new(
        _backend_executable: impl Into<PathBuf>,
        _plugin: impl Into<PathBuf>,
        _kernel: impl Into<PathBuf>,
        _root_image: impl Into<PathBuf>,
        _run_directory: impl Into<PathBuf>,
        _architecture: ProductionGuestArchitecture,
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
    pub const fn with_root_image_format(self, _format: ProductionRootImageFormat) -> Self {
        self
    }

    /// Returns this configuration with the optional white-box callback enabled.
    #[must_use]
    pub const fn with_whitebox(self, _whitebox: ProductionPluginSwitch) -> Self {
        self
    }

    /// Returns this configuration with the retained guest's doorbell instruction ABI.
    #[must_use]
    pub const fn with_doorbell_instruction_abi_version(self, _version: u16) -> Self {
        self
    }

    /// Returns this configuration with the seeded app-random path enabled.
    #[must_use]
    pub fn with_app_random(self, _app_random: ProductionAppRandomConfig) -> Self {
        self
    }

    /// Returns this configuration with live boundary fingerprint sampling set.
    #[must_use]
    pub const fn with_fingerprint(self, _fingerprint: ProductionPluginSwitch) -> Self {
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

/// Failure returned when production local-QEMU execution is requested.
#[derive(Debug, Error)]
pub enum ProductionPluginInstallError {
    /// The inherited-descriptor production backend is unavailable on this host.
    #[error("production local-QEMU execution requires a Linux host")]
    UnsupportedHost,
}

/// Observed evidence returned by a successful production plugin-installation probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPluginInstallReport {
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
    /// Whether the QEMU child exited successfully.
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

/// Rejects a production plugin-installation probe on a non-Linux host.
///
/// # Errors
///
/// Always returns [`ProductionPluginInstallError::UnsupportedHost`].
pub fn run_production_plugin_install_gate(
    _config: &ProductionPluginInstallConfig,
) -> Result<ProductionPluginInstallReport, ProductionPluginInstallError> {
    Err(ProductionPluginInstallError::UnsupportedHost)
}

/// Non-Linux representation of a scheduler-facing live-node launch request.
#[derive(Clone, Debug)]
pub(crate) struct ProductionLiveNodeStepGateConfig;

impl ProductionLiveNodeStepGateConfig {
    pub(crate) fn new_with_root_image(
        _backend_executable: impl Into<PathBuf>,
        _plugin: impl Into<PathBuf>,
        _kernel: impl Into<PathBuf>,
        _root_image: impl Into<PathBuf>,
        _run_directory: impl Into<PathBuf>,
    ) -> Self {
        Self
    }

    pub(crate) const fn with_guest_architecture(
        self,
        _architecture: ProductionGuestArchitecture,
    ) -> Self {
        self
    }

    pub(crate) const fn with_root_image_format(self, _format: ProductionRootImageFormat) -> Self {
        self
    }

    pub(crate) fn with_kernel_cmdline(self, _kernel_cmdline: impl Into<String>) -> Self {
        self
    }

    pub(crate) const fn with_vm_shape(
        self,
        _memory_mib: u32,
        _smp_vcpus: u16,
        _icount_shift: u8,
    ) -> Self {
        self
    }

    pub(crate) const fn with_scenario_seed(self, _scenario_seed: u64) -> Self {
        self
    }

    pub(crate) const fn with_whitebox(self, _whitebox: ProductionPluginSwitch) -> Self {
        self
    }

    pub(crate) const fn with_coverage(self, _coverage: ProductionPluginSwitch) -> Self {
        self
    }

    pub(crate) const fn with_fingerprint(self, _fingerprint: ProductionPluginSwitch) -> Self {
        self
    }

    pub(crate) const fn with_queue_capacity(self, _capacity: u32) -> Self {
        self
    }

    pub(crate) const fn with_completion_timeout(self, _timeout: Duration) -> Self {
        self
    }

    pub(crate) const fn with_console_capture(self) -> Self {
        self
    }

    pub(crate) const fn with_second_run_scheduler_preemption(self, _enabled: bool) -> Self {
        self
    }

    pub(crate) const fn with_process_generation(self, _generation: u64) -> Self {
        self
    }

    pub(crate) const fn with_fault_resource_limits(self, _limits: FaultResourceLimits) -> Self {
        self
    }

    pub(crate) fn with_fault_capabilities(
        self,
        _capabilities: crucible::model::WorldNodeFaultCapabilities,
    ) -> Self {
        self
    }

    pub(crate) const fn with_accelerator(self) -> Self {
        self
    }

    pub(crate) fn with_app_random(self, _app_random: ProductionAppRandomConfig) -> Self {
        self
    }

    pub(crate) fn with_shmem_network_mac(self, _mac: impl Into<String>) -> Self {
        self
    }

    pub(crate) const fn with_network_tx_next_sequence(self, _next_sequence: u32) -> Self {
        self
    }

    pub(crate) fn with_shmem_block<T, U>(self, _base: T, _durability: U) -> Self {
        self
    }

    pub(crate) fn with_shmem_ninep<T, U>(self, _tree: T, _latency: U) -> Self {
        self
    }

    pub(crate) fn with_initrd(self, _initrd: impl Into<PathBuf>) -> Self {
        self
    }

    pub(crate) fn with_gdbstub(self, _gdbstub: ProductionGdbstubChannelConfig) -> Self {
        self
    }

    pub(crate) fn with_run_directory(self, _run_directory: impl Into<PathBuf>) -> Self {
        self
    }
}

/// Failure returned by a non-Linux scheduler-facing live-node launch.
#[derive(Debug, Error)]
#[error("production local-QEMU lifecycle requires a Linux host")]
pub(crate) struct ProductionLiveNodeLaunchError;

pub(crate) type ProductionLiveNode = ProductionNodeBackend;
pub(crate) type ProductionNodeSet = ProductionNodeBackends;

pub(crate) fn launch_production_live_node(
    _config: &ProductionLiveNodeStepGateConfig,
    _run_directory: impl AsRef<Path>,
    _node: &str,
    _router: &str,
    _crash_detector: &str,
) -> Result<ProductionLiveNode, ProductionLiveNodeLaunchError> {
    Err(ProductionLiveNodeLaunchError)
}

pub(crate) fn launch_production_live_node_exact_snapshot<T>(
    _config: &ProductionLiveNodeStepGateConfig,
    _run_directory: impl AsRef<Path>,
    _node: &str,
    _router: &str,
    _crash_detector: &str,
    _snapshot: &T,
) -> Result<ProductionLiveNode, ProductionLiveNodeLaunchError> {
    Err(ProductionLiveNodeLaunchError)
}

pub(crate) fn launch_production_live_node_exact_snapshot_paused<T>(
    _config: &ProductionLiveNodeStepGateConfig,
    _run_directory: impl AsRef<Path>,
    _node: &str,
    _router: &str,
    _crash_detector: &str,
    _snapshot: &T,
) -> Result<ProductionLiveNode, ProductionLiveNodeLaunchError> {
    Err(ProductionLiveNodeLaunchError)
}
