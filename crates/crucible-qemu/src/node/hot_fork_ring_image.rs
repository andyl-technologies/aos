//! Drift-checked host capture of a held Crucible plugin ring image.

#[cfg(target_os = "linux")]
use std::fmt;
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
#[cfg(target_os = "linux")]
use crate::{QmpDescriptorName, QmpError};
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
    descriptor: OwnedFd,
    region: MappedSetupRegion,
    descriptor_name: QmpDescriptorName,
    plugin_resources: QmpHotForkPluginResourceInventory,
    source_setup_region: SetupRegionBackingIdentity,
    source_plugin_barrier: QmpHotForkPluginBarrierState,
    source_host_barrier: MappedRingIoBarrierSnapshot,
    image_digest: [u8; 32],
    image_canonical_len: usize,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for QemuHotForkPrivateRingMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHotForkPrivateRingMapping")
            .field("backing_identity", &self.backing_identity())
            .field("descriptor_name", &self.descriptor_name)
            .field("source_setup_region", &self.source_setup_region)
            .field("source_plugin_barrier", &self.source_plugin_barrier)
            .field("source_host_barrier", &self.source_host_barrier)
            .field("image_digest", &self.image_digest)
            .field("image_canonical_len", &self.image_canonical_len)
            .finish_non_exhaustive()
    }
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

    /// Returns the stable QMP name derived from this exact private backing.
    #[must_use]
    pub const fn descriptor_name(&self) -> &QmpDescriptorName {
        &self.descriptor_name
    }

    pub(super) fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    const fn image_canonical_len(&self) -> usize {
        self.image_canonical_len
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
    /// The exact destination identity could not form a bounded QMP name.
    #[error("branch-private hot-fork descriptor name failed: {source}")]
    DescriptorName {
        /// Underlying typed QMP name failure.
        source: QmpError,
    },
}

/// QMP ownership state for one node-retained private ring mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkPrivateRingStageState {
    /// QEMU duplicated and authenticated the exact standard-QMP descriptor.
    Installed,
    /// Transfer began but QMP ownership could not be determined safely.
    TransferUncertain,
}

/// Bounded evidence for one node-retained private ring descriptor stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkPrivateRingStageProof {
    state: QemuHotForkPrivateRingStageState,
    descriptor_name: QmpDescriptorName,
    backing_identity: SetupRegionBackingIdentity,
    source_setup_region: SetupRegionBackingIdentity,
    image_digest: [u8; 32],
}

impl QemuHotForkPrivateRingStageProof {
    /// Returns whether descriptor installation was acknowledged or uncertain.
    #[must_use]
    pub const fn state(&self) -> QemuHotForkPrivateRingStageState {
        self.state
    }

    /// Returns the exact stable name used by standard QMP `getfd`.
    #[must_use]
    pub const fn descriptor_name(&self) -> &QmpDescriptorName {
        &self.descriptor_name
    }

    /// Returns the fresh private backing identity retained by the node.
    #[must_use]
    pub const fn backing_identity(&self) -> SetupRegionBackingIdentity {
        self.backing_identity
    }

    /// Returns the source mapping identity authenticated before staging.
    #[must_use]
    pub const fn source_setup_region(&self) -> SetupRegionBackingIdentity {
        self.source_setup_region
    }

    /// Returns the exact canonical image digest retained by the mapping.
    #[must_use]
    pub const fn image_digest(&self) -> [u8; 32] {
        self.image_digest
    }
}

pub(super) enum QemuHotForkPrivateRingStage {
    Installed(QemuHotForkPrivateRingMapping),
    TransferUncertain(QemuHotForkPrivateRingMapping),
}

impl QemuHotForkPrivateRingStage {
    pub(super) fn proof(&self) -> QemuHotForkPrivateRingStageProof {
        match self {
            Self::Installed(mapping) => {
                mapping.stage_proof(QemuHotForkPrivateRingStageState::Installed)
            }
            Self::TransferUncertain(mapping) => {
                mapping.stage_proof(QemuHotForkPrivateRingStageState::TransferUncertain)
            }
        }
    }
}

impl QemuHotForkPrivateRingMapping {
    fn stage_proof(
        &self,
        state: QemuHotForkPrivateRingStageState,
    ) -> QemuHotForkPrivateRingStageProof {
        QemuHotForkPrivateRingStageProof {
            state,
            descriptor_name: self.descriptor_name.clone(),
            backing_identity: self.backing_identity(),
            source_setup_region: self.source_setup_region,
            image_digest: self.image_digest,
        }
    }
}

/// Failure to stage one private mapping in a retained QEMU template.
#[derive(Debug, Error)]
pub enum QemuHotForkPrivateRingStageError {
    /// Validation failed before any descriptor-bearing QMP command began.
    #[error("hot-fork private ring staging was rejected before transfer: {source}")]
    Rejected {
        /// Exact validation failure.
        source: QemuNodeChannelError,
        /// Untransferred mapping returned to its caller.
        mapping: Box<QemuHotForkPrivateRingMapping>,
    },
    /// Transfer began, so the node retained ownership and quarantined itself.
    #[error("hot-fork private ring descriptor transfer is ownership-ambiguous: {source}")]
    TransferUncertain {
        /// QMP transfer or acknowledgement failure.
        source: QemuNodeChannelError,
    },
}

impl QemuHotForkPrivateRingStageError {
    /// Returns an untransferred mapping when rejection preceded QMP transfer.
    #[must_use]
    pub fn into_untransferred_mapping(self) -> Option<QemuHotForkPrivateRingMapping> {
        match self {
            Self::Rejected { mapping, .. } => Some(*mapping),
            Self::TransferUncertain { .. } => None,
        }
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

    /// Stages one exact private ring descriptor in the retained QEMU template.
    ///
    /// The node reauthenticates the live source inventory/barriers and exact
    /// destination image before sending standard QMP `getfd`. On success the
    /// node, not the caller, retains the mapping and descriptor for subsequent
    /// child disposition. This operation neither forks nor releases any ring.
    ///
    /// If transfer begins but fails or lacks an acknowledgement, the node keeps
    /// the mapping, records an uncertain stage, poisons the QMP stream, and
    /// enters [`crate::QemuNodeLifecycleState::Quarantined`].
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkPrivateRingStageError::Rejected`] with the mapping
    /// when a pre-transfer invariant fails. Returns
    /// [`QemuHotForkPrivateRingStageError::TransferUncertain`] after any
    /// descriptor-bearing QMP failure; in that case the node retains ownership.
    pub fn stage_hot_fork_private_ring_mapping(
        &mut self,
        mapping: QemuHotForkPrivateRingMapping,
    ) -> Result<QemuHotForkPrivateRingStageProof, QemuHotForkPrivateRingStageError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(rejected_stage(
                mapping,
                "stage hot-fork private ring mapping",
                "descriptor staging requires a running node",
            ));
        }
        if self.hot_fork_private_ring_stage.is_some() {
            return Err(rejected_stage(
                mapping,
                "stage hot-fork private ring mapping",
                "node already retains a private ring descriptor stage",
            ));
        }
        if let Err(source) = self.require_matching_private_ring_mapping(&mapping) {
            return Err(QemuHotForkPrivateRingStageError::Rejected {
                source,
                mapping: Box::new(mapping),
            });
        }

        let transfer = self
            .channels
            .qmp_machine_control
            .install_hot_fork_private_ring_descriptor(
                mapping.descriptor_name(),
                mapping.descriptor(),
                mapping.backing_identity(),
            );
        if let Err(source) = transfer {
            self.hot_fork_private_ring_stage =
                Some(QemuHotForkPrivateRingStage::TransferUncertain(mapping));
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(QemuHotForkPrivateRingStageError::TransferUncertain { source });
        }

        let proof = mapping.stage_proof(QemuHotForkPrivateRingStageState::Installed);
        self.hot_fork_private_ring_stage = Some(QemuHotForkPrivateRingStage::Installed(mapping));
        Ok(proof)
    }

    /// Returns evidence for the private ring stage retained by this node.
    #[must_use]
    pub fn hot_fork_private_ring_stage(&self) -> Option<QemuHotForkPrivateRingStageProof> {
        self.hot_fork_private_ring_stage
            .as_ref()
            .map(QemuHotForkPrivateRingStage::proof)
    }

    /// Closes an acknowledged QMP descriptor stage and returns its held mapping.
    ///
    /// QEMU first releases its independently retained duplicate, then standard
    /// `closefd` releases the monitor-owned name. An error retains the mapping
    /// and quarantines the node because either ownership layer may then be
    /// unsafe to infer.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the node is not running, no stage is
    /// installed, transfer was already uncertain, or QMP cannot acknowledge the
    /// exact close. The mapping remains node-owned on every error.
    pub fn release_hot_fork_private_ring_mapping(
        &mut self,
    ) -> Result<QemuHotForkPrivateRingMapping, QemuNodeChannelError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "release hot-fork private ring mapping",
                "descriptor release requires a running node",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                "release hot-fork private ring mapping",
                "plugin endpoints still retain this private-ring generation",
            ));
        }
        let (name, identity) = match self.hot_fork_private_ring_stage.as_ref() {
            Some(QemuHotForkPrivateRingStage::Installed(mapping)) => (
                mapping.descriptor_name().clone(),
                mapping.backing_identity(),
            ),
            Some(QemuHotForkPrivateRingStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork private ring mapping",
                    "descriptor transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork private ring mapping",
                    "node retains no private ring descriptor stage",
                ));
            }
        };
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .close_hot_fork_private_ring_descriptor(&name, identity)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }

        match self.hot_fork_private_ring_stage.take() {
            Some(QemuHotForkPrivateRingStage::Installed(mapping)) => Ok(mapping),
            Some(QemuHotForkPrivateRingStage::TransferUncertain(_)) | None => {
                Err(QemuNodeChannelError::new(
                    "release hot-fork private ring mapping",
                    "private ring stage changed after acknowledged descriptor close",
                ))
            }
        }
    }

    fn require_matching_private_ring_mapping(
        &mut self,
        mapping: &QemuHotForkPrivateRingMapping,
    ) -> Result<(), QemuNodeChannelError> {
        let resources = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()?;
        if &resources != mapping.plugin_resources() {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork private ring mapping",
                "QEMU plugin resource inventory no longer matches the private mapping",
            ));
        }
        let setup_region = self
            .channels
            .shmem_hot_path
            .hot_fork_setup_region_identity()?;
        if setup_region != mapping.source_setup_region() {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork private ring mapping",
                "source setup-region identity no longer matches the private mapping",
            ));
        }
        let host = self.channels.shmem_hot_path.hot_fork_ring_io_snapshot()?;
        if host != mapping.host_barrier() {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork private ring mapping",
                "source host ring barrier no longer matches the private mapping",
            ));
        }
        let plugin = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_barrier()?;
        if plugin != mapping.source_plugin_barrier() {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork private ring mapping",
                "source QEMU plugin barrier no longer matches the private mapping",
            ));
        }
        validate_plugin_barrier(plugin)?;
        validate_matching_barriers(plugin, host)?;

        let recaptured = mapping
            .capture_ring_image(mapping.image_canonical_len())
            .map_err(|source| {
                QemuNodeChannelError::new(
                    "stage hot-fork private ring mapping",
                    format!("destination ring recapture failed: {source}"),
                )
            })?;
        if recaptured.digest() != mapping.image_digest() {
            return Err(QemuNodeChannelError::new(
                "stage hot-fork private ring mapping",
                "destination ring image changed before descriptor transfer",
            ));
        }
        Ok(())
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

    let image_digest = image.digest();
    let descriptor_name = private_ring_descriptor_name(destination, image_digest)
        .map_err(|source| QemuHotForkPrivateRingMappingError::DescriptorName { source })?;

    Ok(QemuHotForkPrivateRingMapping {
        descriptor,
        region,
        descriptor_name,
        plugin_resources,
        source_setup_region,
        source_plugin_barrier,
        source_host_barrier,
        image_digest,
        image_canonical_len: maximum_bytes,
    })
}

#[cfg(target_os = "linux")]
fn private_ring_descriptor_name(
    identity: SetupRegionBackingIdentity,
    image_digest: [u8; 32],
) -> Result<QmpDescriptorName, QmpError> {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = String::with_capacity(64);
    for byte in image_digest {
        digest.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        digest.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    QmpDescriptorName::new(format!(
        "crucible-hfork-rings-v1-{:016x}-{:016x}-{digest}",
        identity.device(),
        identity.inode()
    ))
}

#[cfg(target_os = "linux")]
fn rejected_stage(
    mapping: QemuHotForkPrivateRingMapping,
    operation: &'static str,
    message: &'static str,
) -> QemuHotForkPrivateRingStageError {
    QemuHotForkPrivateRingStageError::Rejected {
        source: QemuNodeChannelError::new(operation, message),
        mapping: Box::new(mapping),
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
        || !barrier.mapping_dontfork()
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
