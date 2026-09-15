//! Descriptor-backed QEMU restore plans for restored node realization.

use crucible::{Checkpoint, ContentHash};
use rustix::fs::{SealFlags, fcntl_get_seals};
use std::io;
use std::os::fd::BorrowedFd;

use crate::realization::QemuBakedGenesisRestoreAdmission;
use crate::{QemuHostIoCheckpoint, QemuNodeContinuationCheckpoint, QemuVmSnapshot};

pub(crate) struct QemuNodeCheckpointAssertion<'a> {
    pub(super) checkpoint: &'a Checkpoint,
}

/// Opaque checkpoint assertion for one replay-oracle exact probe.
pub(crate) struct QemuGuardedProbeRestoreAdmission<'a>(QemuNodeCheckpointAssertion<'a>);

/// Opaque checkpoint assertion for one fresh baked-genesis replay launch.
pub(crate) struct QemuGuardedBakedRestoreAdmission<'a>(QemuNodeCheckpointAssertion<'a>);

/// Complete exact descriptor-backed plan accepted by the QEMU node factory.
pub(crate) struct QemuNodeRestorePlan<'a> {
    pub(super) checkpoint: &'a Checkpoint,
    pub(super) host_io_checkpoint: &'a QemuHostIoCheckpoint,
    pub(super) node_continuation: &'a QemuNodeContinuationCheckpoint,
    pub(super) exact_checkpoint: QemuExactCheckpointRestorePlan<'a>,
}

/// Borrowed descriptor set for an exact direct-plus-delta restore.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QemuExactCheckpointRestoreDescriptors<'a> {
    pub(super) ram: &'a [BorrowedFd<'a>],
    pub(super) device: BorrowedFd<'a>,
    pub(super) cancellation: BorrowedFd<'a>,
}

impl<'a> QemuExactCheckpointRestoreDescriptors<'a> {
    /// Binds ordered RAM, final device-state, and cancellation descriptors.
    #[must_use]
    pub(crate) const fn new(
        ram: &'a [BorrowedFd<'a>],
        device: BorrowedFd<'a>,
        cancellation: BorrowedFd<'a>,
    ) -> Self {
        Self {
            ram,
            device,
            cancellation,
        }
    }

    pub(crate) fn validate_immutable(self, expected_ram_layers: usize) -> Result<(), io::Error> {
        validate_immutable_restore_inputs(self.ram, self.device, expected_ram_layers)
    }
}

pub(crate) fn validate_immutable_restore_inputs(
    ram: &[BorrowedFd<'_>],
    device: BorrowedFd<'_>,
    expected_ram_layers: usize,
) -> Result<(), io::Error> {
    if expected_ram_layers != ram.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RAM layer descriptor count differs from the restore request",
        ));
    }
    let required = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    for descriptor in ram.iter().copied().chain(std::iter::once(device)) {
        if !fcntl_get_seals(descriptor)?.contains(required) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "exact checkpoint restore input is not an immutable sealed file",
            ));
        }
    }
    Ok(())
}

pub(super) struct QemuExactCheckpointRestorePlan<'a> {
    pub(super) request: &'a crate::QmpCheckpointRestoreRequest,
    pub(super) descriptors: QemuExactCheckpointRestoreDescriptors<'a>,
    pub(super) topology: ContentHash,
}

impl<'a> QemuNodeCheckpointAssertion<'a> {
    #[must_use]
    const fn snapshot_completeness_probe(checkpoint: &'a Checkpoint) -> Self {
        Self { checkpoint }
    }

    #[must_use]
    fn baked_genesis(admission: QemuBakedGenesisRestoreAdmission<'a>) -> Self {
        Self {
            checkpoint: admission.checkpoint(),
        }
    }

    pub(crate) const fn checkpoint(&self) -> &'a Checkpoint {
        self.checkpoint
    }
}

impl<'a> QemuGuardedProbeRestoreAdmission<'a> {
    pub(crate) const fn new(checkpoint: &'a Checkpoint) -> Self {
        Self(QemuNodeCheckpointAssertion::snapshot_completeness_probe(
            checkpoint,
        ))
    }

    pub(crate) const fn checkpoint(&self) -> &'a Checkpoint {
        self.0.checkpoint()
    }
}

impl<'a> QemuGuardedBakedRestoreAdmission<'a> {
    pub(crate) fn new(admission: QemuBakedGenesisRestoreAdmission<'a>) -> Self {
        Self(QemuNodeCheckpointAssertion::baked_genesis(admission))
    }

    pub(crate) const fn into_basis(self) -> QemuNodeCheckpointAssertion<'a> {
        self.0
    }
}

impl<'a> QemuNodeRestorePlan<'a> {
    pub(crate) fn exact_checkpoint(
        snapshot: &'a QemuVmSnapshot,
        request: &'a crate::QmpCheckpointRestoreRequest,
        descriptors: QemuExactCheckpointRestoreDescriptors<'a>,
        topology: ContentHash,
    ) -> Self {
        Self {
            checkpoint: snapshot.checkpoint(),
            host_io_checkpoint: snapshot.host_io(),
            node_continuation: snapshot.node_continuation(),
            exact_checkpoint: QemuExactCheckpointRestorePlan {
                request,
                descriptors,
                topology,
            },
        }
    }

    pub(crate) const fn exact_checkpoint_cancellation(&self) -> BorrowedFd<'a> {
        self.exact_checkpoint.descriptors.cancellation
    }

    pub(crate) fn validate_immutable_descriptors(&self) -> Result<(), io::Error> {
        self.exact_checkpoint
            .descriptors
            .validate_immutable(self.exact_checkpoint.request.layers().len())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn descriptor_validation_rejects_unsealed_device_state() -> Result<(), io::Error> {
        let mut input = crate::QemuExactCheckpointInputMaterialization::new(1)?;
        input.write_all(b"x")?;
        let sealed = input.finish()?;
        let unsealed = tempfile::tempfile()?;
        unsealed.set_len(1)?;
        let ram = [sealed.as_fd()];
        let descriptors =
            QemuExactCheckpointRestoreDescriptors::new(&ram, unsealed.as_fd(), sealed.as_fd());

        assert!(descriptors.validate_immutable(1).is_err());
        Ok(())
    }
}
