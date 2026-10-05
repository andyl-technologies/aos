//! QEMU-specific production lifecycle configuration at the daemon boundary.
//!
//! Control-plane callers choose process-neutral policy. This module translates
//! that policy into the QEMU launch types confined to the daemon boundary.

use crucible_api::ProductionVmLifecycleConfig;
use crucible_qemu::{QemuLaunchPluginSwitch, QemuRootImageFormat};

/// Selects a raw immutable root image for a production QEMU lifecycle.
#[must_use]
pub fn with_production_qemu_raw_root_image(
    config: ProductionVmLifecycleConfig,
) -> ProductionVmLifecycleConfig {
    config.with_root_image_format(QemuRootImageFormat::Raw)
}

/// Selects whether production QEMU publishes observation-only coverage.
#[must_use]
pub fn with_production_qemu_coverage(
    config: ProductionVmLifecycleConfig,
    enabled: bool,
) -> ProductionVmLifecycleConfig {
    let coverage = if enabled {
        QemuLaunchPluginSwitch::On
    } else {
        QemuLaunchPluginSwitch::Off
    };
    config.with_coverage(coverage)
}
