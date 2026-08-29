//! Drift-checked host capture of a held Crucible plugin ring image.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;

use crucible_shmem::{HotForkRingImage, MappedRingIoBarrierSnapshot, SetupRegionBackingIdentity};
#[cfg(target_os = "linux")]
use crucible_shmem::{
    HotForkRingImageError, MappedSetupRegion, RegionAllocation, RegionLayoutError,
    RegionSerializationError, SetupRegionMapError, mmap_setup_region,
};
#[cfg(target_os = "linux")]
use thiserror::Error;

use super::{QemuNode, QemuNodeChannelError};
#[cfg(target_os = "linux")]
use crate::spawn::{QemuSpawnError, memfd_region};
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

/// One held branch-private setup mapping initialized from a captured ring image.
///
/// The mapping owns a fresh memfd whose device/inode identity differs from the
/// source mapping. Every destination producer and consumer remains held. This
/// type deliberately exposes no descriptor or barrier-release authority: a
/// later child-rebinding stage must consume it under the complete descriptor,
/// worker, continuation, and process-generation proof.
#[cfg(target_os = "linux")]
pub struct QemuHotForkPrivateRingMapping {
    // Retained for the complete mapping lifetime; no public descriptor escape
    // exists at this incomplete child-composition boundary.
    _descriptor: OwnedFd,
    region: MappedSetupRegion,
    plugin_resources: QmpHotForkPluginResourceInventory,
    source_setup_region: SetupRegionBackingIdentity,
    source_plugin_barrier: QmpHotForkPluginBarrierState,
    source_host_barrier: MappedRingIoBarrierSnapshot,
    image_digest: [u8; 32],
}

#[cfg(target_os = "linux")]
impl QemuHotForkPrivateRingMapping {
    fn plugin_resources(&self) -> &QmpHotForkPluginResourceInventory {
        &self.plugin_resources
    }

    /// Returns the fresh branch-private backing identity.
    #[must_use]
    pub fn backing_identity(&self) -> SetupRegionBackingIdentity {
        self.region.backing_identity()
    }

    /// Returns the source mapping identity authenticated during materialization.
    #[must_use]
    pub const fn source_setup_region(&self) -> SetupRegionBackingIdentity {
        self.source_setup_region
    }

    /// Returns the retained source-side QEMU/plugin barrier proof.
    #[must_use]
    pub const fn source_plugin_barrier(&self) -> QmpHotForkPluginBarrierState {
        self.source_plugin_barrier
    }

    /// Returns the exact held destination barrier state.
    #[must_use]
    pub const fn host_barrier(&self) -> MappedRingIoBarrierSnapshot {
        self.source_host_barrier
    }

    /// Returns the transfer-integrity digest restored into this mapping.
    #[must_use]
    pub const fn image_digest(&self) -> [u8; 32] {
        self.image_digest
    }

    /// Recaptures the held destination ring image for exact verification.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkRingImageError`] when the private mapping is no longer
    /// held and quiescent, its geometry is invalid, or `maximum_bytes` is too
    /// small for the canonical image.
    pub fn capture_ring_image(
        &self,
        maximum_bytes: usize,
    ) -> Result<HotForkRingImage, HotForkRingImageError> {
        self.region.capture_hot_fork_ring_image(maximum_bytes)
    }
}

/// Failure to create one held branch-private hot-fork ring mapping.
#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
enum QemuHotForkPrivateRingMappingError {
    /// The captured geometry could not allocate a fresh setup region.
    #[error("branch-private hot-fork setup-region allocation failed: {source}")]
    RegionLayout {
        /// Underlying shared-memory layout failure.
        source: RegionLayoutError,
    },
    /// The fresh non-ring setup state could not be serialized.
    #[error("branch-private hot-fork setup-region serialization failed: {source}")]
    RegionSerialization {
        /// Underlying shared-memory serialization failure.
        source: RegionSerializationError,
    },
    /// The private memfd could not be created, sized, or shrink-sealed.
    #[error("branch-private hot-fork memfd creation failed: {source}")]
    Memfd {
        /// Underlying descriptor preparation failure.
        source: QemuSpawnError,
    },
    /// Initial setup bytes could not be written to the private memfd.
    #[error("branch-private hot-fork setup-region write failed: {source}")]
    Write {
        /// Underlying positional-write failure.
        source: std::io::Error,
    },
    /// The private descriptor could not be mapped under the setup ABI.
    #[error("branch-private hot-fork setup-region mapping failed: {source}")]
    Map {
        /// Underlying descriptor/map validation failure.
        source: SetupRegionMapError,
    },
    /// The destination unexpectedly aliases the captured source mapping.
    #[error("branch-private hot-fork setup region aliases the captured source")]
    SourceAliased,
    /// The image geometry and captured source descriptor length disagree.
    #[error("branch-private hot-fork image length differs from captured source mapping")]
    SourceLengthMismatch,
    /// Holding, restoring, or recapturing the exact ring image failed.
    #[error("branch-private hot-fork ring image restore failed: {source}")]
    Image {
        /// Underlying image or mapped-region failure.
        source: HotForkRingImageError,
    },
    /// The destination barrier did not match the exact captured ring set.
    #[error("branch-private hot-fork ring barrier differs from captured source")]
    BarrierMismatch,
    /// Destination recapture did not reproduce the exact authenticated image.
    #[error("branch-private hot-fork ring image differs after restore")]
    ImageMismatch,
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
        if image.region_size() != setup_region.length() {
            return Err(QemuNodeChannelError::new(
                "capture hot-fork plugin ring image",
                "ring image length differs from the sealed setup-region descriptor",
            ));
        }
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

    /// Materializes a captured image into one distinct held private mapping.
    ///
    /// The node reauthenticates the exact source resource inventory, mapping
    /// identity, QEMU barrier generation, and host barrier immediately before
    /// and after destination creation. The destination begins from freshly
    /// initialized non-ring state, receives only the image's queue-backed
    /// ranges, reproduces the exact canonical image, and remains held.
    ///
    /// This operation does not fork QEMU, expose the destination descriptor,
    /// release either barrier, reconstruct workers, or change readiness bit 6.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the live source no longer matches
    /// the capture or when private mapping construction, restore, or exact
    /// recapture fails.
    #[cfg(target_os = "linux")]
    pub fn materialize_hot_fork_private_ring_mapping(
        &mut self,
        capture: QemuHotForkPluginRingImage,
    ) -> Result<QemuHotForkPrivateRingMapping, QemuNodeChannelError> {
        self.require_matching_hot_fork_capture(&capture)?;
        let private = materialize_private_ring_mapping(capture).map_err(|error| {
            QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                error.to_string(),
            )
        })?;

        let resources = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()?;
        if &resources != private.plugin_resources() {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "QEMU plugin resource inventory changed during private mapping creation",
            ));
        }
        let setup_region = self
            .channels
            .shmem_hot_path
            .hot_fork_setup_region_identity()?;
        if setup_region != private.source_setup_region() {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "source setup-region identity changed during private mapping creation",
            ));
        }
        let host = self.channels.shmem_hot_path.hot_fork_ring_io_snapshot()?;
        if host != private.host_barrier() {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "source host ring barrier changed during private mapping creation",
            ));
        }
        let plugin = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_barrier()?;
        if plugin != private.source_plugin_barrier() {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "QEMU plugin barrier changed during private mapping creation",
            ));
        }
        validate_plugin_barrier(plugin)?;
        validate_matching_barriers(plugin, host)?;
        Ok(private)
    }

    #[cfg(target_os = "linux")]
    fn require_matching_hot_fork_capture(
        &mut self,
        capture: &QemuHotForkPluginRingImage,
    ) -> Result<(), QemuNodeChannelError> {
        let resources = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()?;
        if resources != capture.plugin_resources {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "captured plugin resource inventory is no longer current",
            ));
        }
        let plugin = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_barrier()?;
        if plugin != capture.plugin_barrier {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "captured QEMU plugin barrier is no longer current",
            ));
        }
        validate_plugin_barrier(plugin)?;

        let setup_region = self
            .channels
            .shmem_hot_path
            .hot_fork_setup_region_identity()?;
        if setup_region != capture.setup_region {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "captured source setup-region identity is no longer current",
            ));
        }
        validate_setup_region(&resources, setup_region)?;
        let host = self.channels.shmem_hot_path.hot_fork_ring_io_snapshot()?;
        if host != capture.host_barrier {
            return Err(QemuNodeChannelError::new(
                "materialize hot-fork private ring mapping",
                "captured host ring barrier is no longer current",
            ));
        }
        validate_matching_barriers(plugin, host)
    }
}

#[cfg(target_os = "linux")]
fn materialize_private_ring_mapping(
    capture: QemuHotForkPluginRingImage,
) -> Result<QemuHotForkPrivateRingMapping, QemuHotForkPrivateRingMappingError> {
    let QemuHotForkPluginRingImage {
        plugin_resources,
        setup_region: source_setup_region,
        plugin_barrier: source_plugin_barrier,
        host_barrier: source_host_barrier,
        image,
    } = capture;
    if image.region_size() != source_setup_region.length() {
        return Err(QemuHotForkPrivateRingMappingError::SourceLengthMismatch);
    }
    let allocation = RegionAllocation::new(image.region_config())
        .map_err(|source| QemuHotForkPrivateRingMappingError::RegionLayout { source })?;
    if allocation.layout().region_size != image.region_size() {
        return Err(QemuHotForkPrivateRingMappingError::Image {
            source: HotForkRingImageError::LayoutMismatch,
        });
    }
    let setup_bytes = allocation
        .setup_region_bytes()
        .map_err(|source| QemuHotForkPrivateRingMappingError::RegionSerialization { source })?;
    let descriptor = memfd_region(image.region_size())
        .map_err(|source| QemuHotForkPrivateRingMappingError::Memfd { source })?;
    let writer = File::from(
        descriptor
            .try_clone()
            .map_err(|source| QemuHotForkPrivateRingMappingError::Write { source })?,
    );
    writer
        .write_all_at(&setup_bytes, 0)
        .map_err(|source| QemuHotForkPrivateRingMappingError::Write { source })?;
    drop(writer);
    drop(setup_bytes);
    drop(allocation);
    let mut region = mmap_setup_region(descriptor.as_fd(), image.region_size())
        .map_err(|source| QemuHotForkPrivateRingMappingError::Map { source })?;
    let destination = region.backing_identity();
    if destination.device() == source_setup_region.device()
        && destination.inode() == source_setup_region.inode()
    {
        return Err(QemuHotForkPrivateRingMappingError::SourceAliased);
    }

    let held = region.hold_hot_fork_ring_io().map_err(|source| {
        QemuHotForkPrivateRingMappingError::Image {
            source: HotForkRingImageError::RegionAccess { source },
        }
    })?;
    if held != source_host_barrier {
        return Err(QemuHotForkPrivateRingMappingError::BarrierMismatch);
    }
    region
        .restore_hot_fork_ring_image(&image)
        .map_err(|source| QemuHotForkPrivateRingMappingError::Image { source })?;
    let restored_barrier = region.hot_fork_ring_io_snapshot().map_err(|source| {
        QemuHotForkPrivateRingMappingError::Image {
            source: HotForkRingImageError::RegionAccess { source },
        }
    })?;
    if restored_barrier != source_host_barrier {
        return Err(QemuHotForkPrivateRingMappingError::BarrierMismatch);
    }

    let maximum_bytes = image
        .canonical_len()
        .map_err(|source| QemuHotForkPrivateRingMappingError::Image { source })?;
    let recaptured = region
        .capture_hot_fork_ring_image(maximum_bytes)
        .map_err(|source| QemuHotForkPrivateRingMappingError::Image { source })?;
    if recaptured != image {
        return Err(QemuHotForkPrivateRingMappingError::ImageMismatch);
    }

    Ok(QemuHotForkPrivateRingMapping {
        _descriptor: descriptor,
        region,
        plugin_resources,
        source_setup_region,
        source_plugin_barrier,
        source_host_barrier,
        image_digest: image.digest(),
    })
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
