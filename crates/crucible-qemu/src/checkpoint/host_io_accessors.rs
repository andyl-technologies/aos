//! Construction and inspection of host-I/O checkpoint aggregates.

use crucible::ContentHash;

use super::{
    QemuHostIoCheckpoint, QemuLive9pIoServicerCheckpoint, QemuLiveBlockIoServicerCheckpoint,
};

impl QemuHostIoCheckpoint {
    /// Builds a checkpoint for a runtime with no shared-memory host devices.
    #[must_use]
    pub const fn without_devices(execution_binding: ContentHash) -> Self {
        Self {
            execution_binding,
            block: None,
            ninep: None,
            #[cfg(target_os = "linux")]
            accelerator: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn with_devices(
        execution_binding: ContentHash,
        block: Option<QemuLiveBlockIoServicerCheckpoint>,
        ninep: Option<QemuLive9pIoServicerCheckpoint>,
        accelerator: Option<crate::QemuLiveAcceleratorCheckpoint>,
    ) -> Self {
        Self {
            execution_binding,
            block,
            ninep,
            accelerator,
        }
    }

    /// Returns the QEMU VMState identity paired with this host continuation.
    #[must_use]
    pub const fn execution_binding(&self) -> ContentHash {
        self.execution_binding
    }

    /// Returns the block continuation when the captured runtime owned one.
    #[must_use]
    pub const fn block(&self) -> Option<&QemuLiveBlockIoServicerCheckpoint> {
        self.block.as_ref()
    }

    /// Returns the 9p continuation when the captured runtime owned one.
    #[must_use]
    pub const fn ninep(&self) -> Option<&QemuLive9pIoServicerCheckpoint> {
        self.ninep.as_ref()
    }

    /// Returns the accelerator continuation when the captured runtime owned one.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn accelerator(&self) -> Option<&crate::QemuLiveAcceleratorCheckpoint> {
        self.accelerator.as_ref()
    }

    /// Returns the canonical content identity of this complete continuation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuHostIoCheckpointCodecError`] when nested device or
    /// ring state is malformed or exceeds the canonical checkpoint limit.
    pub fn canonical_identity(&self) -> Result<ContentHash, super::QemuHostIoCheckpointCodecError> {
        self.to_canonical_bytes()
            .map(|bytes| ContentHash::from_bytes(&bytes))
    }

    /// Compares the complete device continuation while ignoring its owner binding.
    ///
    /// Exact restore binds a snapshot to its QEMU VMState identity. A later
    /// read-only hot-fork projection binds the unchanged device cursors to the
    /// scheduler continuation captured for the whole World, so those binding
    /// hashes intentionally differ. Every block, 9p, accelerator, and ring
    /// field must otherwise remain identical.
    #[must_use]
    pub fn same_device_continuation(&self, other: &Self) -> bool {
        if !self.has_consistent_execution_binding() || !other.has_consistent_execution_binding() {
            return false;
        }

        let mut rebound = other.clone();
        rebound.execution_binding = self.execution_binding;
        if let Some(block) = &mut rebound.block {
            block.execution_binding = self.execution_binding;
        }
        if let Some(ninep) = &mut rebound.ninep {
            ninep.execution_binding = self.execution_binding;
        }

        self == &rebound
    }

    fn has_consistent_execution_binding(&self) -> bool {
        self.block
            .as_ref()
            .is_none_or(|block| block.execution_binding == self.execution_binding)
            && self
                .ninep
                .as_ref()
                .is_none_or(|ninep| ninep.execution_binding == self.execution_binding)
    }
}
