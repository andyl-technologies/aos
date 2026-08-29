//! Drift-checked host capture of a held Crucible plugin ring image.

use crucible_shmem::{HotForkRingImage, MappedRingIoBarrierSnapshot, SetupRegionBackingIdentity};

use super::{QemuNode, QemuNodeChannelError};
use crate::{QmpHotForkPluginBarrierState, QmpHotForkPluginResourceInventory};

/// One ring image paired with the exact retained QEMU/plugin barrier proof.
///
/// The capture remains an operational subsystem primitive. It does not carry
/// node slots, fingerprint samples, worker-local work, a host continuation, or
/// any child-side resource disposition, and therefore cannot authorize a
/// process fork by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkPluginRingImage {
    plugin_resources: QmpHotForkPluginResourceInventory,
    setup_region: SetupRegionBackingIdentity,
    plugin_barrier: QmpHotForkPluginBarrierState,
    host_barrier: MappedRingIoBarrierSnapshot,
    image: HotForkRingImage,
}

impl QemuHotForkPluginRingImage {
    /// Returns the unchanged sealed plugin-resource inventory.
    #[must_use]
    pub const fn plugin_resources(&self) -> &QmpHotForkPluginResourceInventory {
        &self.plugin_resources
    }

    /// Returns the exact backing identity authenticated against that inventory.
    #[must_use]
    pub const fn setup_region(&self) -> SetupRegionBackingIdentity {
        self.setup_region
    }

    /// Returns the unchanged QEMU/plugin barrier proof bracketing capture.
    #[must_use]
    pub const fn plugin_barrier(&self) -> QmpHotForkPluginBarrierState {
        self.plugin_barrier
    }

    /// Returns the exact host-observed ring barrier state.
    #[must_use]
    pub const fn host_barrier(&self) -> MappedRingIoBarrierSnapshot {
        self.host_barrier
    }

    /// Returns the bounded canonical ring image.
    #[must_use]
    pub const fn image(&self) -> &HotForkRingImage {
        &self.image
    }

    /// Consumes the proof wrapper and returns the canonical ring image.
    #[must_use]
    pub fn into_image(self) -> HotForkRingImage {
        self.image
    }
}

impl QemuNode {
    /// Captures held plugin rings under one unchanged QEMU barrier generation.
    ///
    /// The QMP plugin barrier and sealed resource inventory are sampled before
    /// and after host capture. Both samples must remain identical. The retained
    /// host mapping device, inode, and length must match the sealed inventory;
    /// the independently observed host ring count, held count, and
    /// producer/consumer admissions must match QEMU's barrier exactly before
    /// any image is accepted.
    ///
    /// The caller continues to own barrier release. This method neither forks
    /// QEMU nor changes readiness bit 6.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP or mapped-region access fails,
    /// the plugin barrier is not quiescent, the host and plugin observations
    /// disagree, the barrier changes across capture, or `maximum_bytes` is too
    /// small for the exact canonical image.
    pub fn capture_hot_fork_plugin_ring_image(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<QemuHotForkPluginRingImage, QemuNodeChannelError> {
        let resources_before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()?;
        let before = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_barrier()?;
        validate_plugin_barrier(before)?;

        let setup_region = self
            .channels
            .shmem_hot_path
            .hot_fork_setup_region_identity()?;
        validate_setup_region(&resources_before, setup_region)?;
        let host_before = self.channels.shmem_hot_path.hot_fork_ring_io_snapshot()?;
        validate_matching_barriers(before, host_before)?;
        let image = self
            .channels
            .shmem_hot_path
            .capture_hot_fork_ring_image(maximum_bytes)?;
        let host_after = self.channels.shmem_hot_path.hot_fork_ring_io_snapshot()?;
        if host_after != host_before {
            return Err(QemuNodeChannelError::new(
                "capture hot-fork plugin ring image",
                "host ring barrier changed across image capture",
            ));
        }

        let resources_after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()?;
        if resources_after != resources_before {
            return Err(QemuNodeChannelError::new(
                "capture hot-fork plugin ring image",
                "QEMU plugin resource inventory changed across image capture",
            ));
        }
        validate_setup_region(&resources_after, setup_region)?;
        let after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_barrier()?;
        if after != before {
            return Err(QemuNodeChannelError::new(
                "capture hot-fork plugin ring image",
                "QEMU plugin barrier changed across image capture",
            ));
        }
        validate_matching_barriers(after, host_after)?;

        Ok(QemuHotForkPluginRingImage {
            plugin_resources: resources_after,
            setup_region,
            plugin_barrier: after,
            host_barrier: host_after,
            image,
        })
    }
}

fn validate_setup_region(
    resources: &QmpHotForkPluginResourceInventory,
    setup_region: SetupRegionBackingIdentity,
) -> Result<(), QemuNodeChannelError> {
    let matches = resources.registered()
        && resources.complete()
        && resources.shmem_device() == setup_region.device()
        && resources.shmem_inode() == setup_region.inode()
        && resources.shmem_length() == setup_region.length();
    if !matches {
        return Err(QemuNodeChannelError::new(
            "capture hot-fork plugin ring image",
            "host mapping and sealed QEMU plugin resource identity disagree",
        ));
    }
    Ok(())
}

fn validate_plugin_barrier(
    barrier: QmpHotForkPluginBarrierState,
) -> Result<(), QemuNodeChannelError> {
    if barrier.generation() == 0
        || !barrier.registered()
        || !barrier.manifest_consistent()
        || !barrier.held()
        || barrier.teardown_closed()
        || !barrier.quiescent()
    {
        return Err(QemuNodeChannelError::new(
            "capture hot-fork plugin ring image",
            "QEMU plugin barrier is not one retained quiescent generation",
        ));
    }
    Ok(())
}

fn validate_matching_barriers(
    plugin: QmpHotForkPluginBarrierState,
    host: MappedRingIoBarrierSnapshot,
) -> Result<(), QemuNodeChannelError> {
    let matches = host.quiescent()
        && plugin.ring_count() == host.ring_count()
        && plugin.rings_held() == host.held_rings()
        && plugin.ring_producers_in_flight() == host.producers_in_flight()
        && plugin.ring_consumers_in_flight() == host.consumers_in_flight();
    if !matches {
        return Err(QemuNodeChannelError::new(
            "capture hot-fork plugin ring image",
            "host and QEMU plugin ring barriers disagree",
        ));
    }
    Ok(())
}
