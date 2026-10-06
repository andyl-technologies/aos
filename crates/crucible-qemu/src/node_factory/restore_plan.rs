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

/// Borrowed immutable root metadata, device state, and cancellation inputs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QemuExactCheckpointRestoreDescriptors<'a> {
    pub(super) root: BorrowedFd<'a>,
    pub(super) device: BorrowedFd<'a>,
    pub(super) cancellation: BorrowedFd<'a>,
}

impl<'a> QemuExactCheckpointRestoreDescriptors<'a> {
    /// Binds immutable root metadata, device state, and cancellation descriptors.
    #[must_use]
    pub(crate) const fn new(
        root: BorrowedFd<'a>,
        device: BorrowedFd<'a>,
        cancellation: BorrowedFd<'a>,
    ) -> Self {
        Self {
            root,
            device,
            cancellation,
        }
    }

    pub(crate) fn validate_immutable(self) -> Result<(), io::Error> {
        validate_immutable_restore_inputs(self.root, self.device)
    }
}

pub(crate) fn validate_immutable_restore_inputs(
    root: BorrowedFd<'_>,
    device: BorrowedFd<'_>,
) -> Result<(), io::Error> {
    let required = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    for descriptor in [root, device] {
        if !fcntl_get_seals(descriptor)?.contains(required) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "exact checkpoint input is not an immutable sealed file",
            ));
        }
    }
    let bytes = rustix::fs::fstat(root)?.st_size;
    if bytes <= 0
        || u64::try_from(bytes)
            .is_ok_and(|bytes| bytes > crucible_ram::Limits::default().max_record_bytes as u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RAM root metadata exceeds its bound",
        ));
    }
    Ok(())
}

pub(super) struct QemuExactCheckpointRestorePlan<'a> {
    pub(super) request: &'a crate::QmpCheckpointRestoreRequest,
    pub(super) descriptors: QemuExactCheckpointRestoreDescriptors<'a>,
    pub(super) topology: ContentHash,
    pub(super) source: &'a crate::QemuPagedRamRestoreSource,
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
        source: &'a crate::QemuPagedRamRestoreSource,
    ) -> Self {
        Self {
            checkpoint: snapshot.checkpoint(),
            host_io_checkpoint: snapshot.host_io(),
            node_continuation: snapshot.node_continuation(),
            exact_checkpoint: QemuExactCheckpointRestorePlan {
                request,
                descriptors,
                topology,
                source,
            },
        }
    }

    pub(crate) fn ram_source(&self) -> &crate::QemuPagedRamRestoreSource {
        self.exact_checkpoint.source
    }

    pub(crate) const fn exact_checkpoint_cancellation(&self) -> BorrowedFd<'a> {
        self.exact_checkpoint.descriptors.cancellation
    }

    pub(crate) fn validate_immutable_descriptors(&self) -> Result<(), io::Error> {
        self.exact_checkpoint.descriptors.validate_immutable()
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
        let descriptors = QemuExactCheckpointRestoreDescriptors::new(
            sealed.as_fd(),
            unsealed.as_fd(),
            sealed.as_fd(),
        );

        assert!(descriptors.validate_immutable().is_err());
        Ok(())
    }
}
