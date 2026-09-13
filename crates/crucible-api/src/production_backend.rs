//! Production QEMU types shared by the public API and local VM lifecycle.

#[cfg(not(target_os = "linux"))]
#[path = "production_backend/unsupported_live.rs"]
mod unsupported_live;

#[cfg(not(target_os = "linux"))]
pub(crate) use unsupported_live::{
    ProductionLiveNodeStepGateConfig, ProductionNodeSet, launch_production_live_node,
    launch_production_live_node_exact_snapshot, launch_production_live_node_exact_snapshot_paused,
};
#[cfg(not(target_os = "linux"))]
pub use unsupported_live::{
    ProductionPluginInstallConfig, ProductionPluginInstallError, ProductionPluginInstallReport,
    run_production_plugin_install_gate,
};

/// Guest architecture accepted by the production plugin-installation probe.
pub use crucible_qemu::LivePluginGuestArchitecture as ProductionGuestArchitecture;
/// Configuration for the production plugin-installation probe.
#[cfg(target_os = "linux")]
pub use crucible_qemu::LivePluginInstallGateConfig as ProductionPluginInstallConfig;
/// Failure returned by the production plugin-installation probe.
#[cfg(target_os = "linux")]
pub use crucible_qemu::LivePluginInstallGateError as ProductionPluginInstallError;
/// Observed evidence returned by the production plugin-installation probe.
#[cfg(target_os = "linux")]
pub use crucible_qemu::LivePluginInstallReport as ProductionPluginInstallReport;
/// Seeded live app-random launch configuration.
pub(crate) use crucible_qemu::QemuLaunchAppRandomConfig as ProductionAppRandomConfig;
/// Production plugin feature switch pinned into launch identity.
pub use crucible_qemu::QemuLaunchPluginSwitch as ProductionPluginSwitch;
/// Validated production live-node launch profile.
#[cfg(target_os = "linux")]
pub use crucible_qemu::QemuLiveNodeStepGateConfig as ProductionLiveNodeStepGateConfig;
/// Root-image format pinned into production launch identity.
pub use crucible_qemu::QemuRootImageFormat as ProductionRootImageFormat;
/// Runs the bounded production plugin-installation probe.
#[cfg(target_os = "linux")]
pub use crucible_qemu::run_live_plugin_install_gate as run_production_plugin_install_gate;
pub(crate) use crucible_qemu::{
    DEFAULT_ROOT_OVERLAY_FILE_NAME as PRODUCTION_ROOT_OVERLAY_FILE_NAME,
    DEFAULT_VMSTATE_FILE_NAME as PRODUCTION_VMSTATE_FILE_NAME,
    QemuGdbstubChannelConfig as ProductionGdbstubChannelConfig,
};
#[cfg(not(target_os = "linux"))]
pub(crate) use crucible_qemu::{
    QemuNode as ProductionNodeBackend, QemuNodeSet as ProductionNodeBackends,
};
#[cfg(target_os = "linux")]
pub(crate) use crucible_qemu::{
    QemuNodeSet as ProductionNodeSet, launch_qemu_live_node as launch_production_live_node,
    launch_qemu_live_node_exact_snapshot as launch_production_live_node_exact_snapshot,
    launch_qemu_live_node_exact_snapshot_paused as launch_production_live_node_exact_snapshot_paused,
};
