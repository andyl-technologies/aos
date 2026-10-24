//! Original selected setup mapping ownership reserved before child execution.
//!
//! Initialization supplies public process geometry only. The same physical
//! mapping and prepared retention ticket survive source observation, actual
//! roster adoption, paired callbacks and an incomplete constructor outcome.

use std::os::fd::{AsRawFd, BorrowedFd};

use crucible_qemu_shmem::{OwnedSetupMapping, RegionAllocation, RegionConfig, mmap_setup_region};
use rustix::fs::{FileType, fstat};

use super::QemuSpawnError;

pub(super) struct PreparedWholeMapping {
    pub(super) owner: OwnedSetupMapping,
    pub(super) config: RegionConfig,
    pub(super) byte_length: u64,
    pub(super) identity: OriginalMappingIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OriginalMappingIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) byte_length: u64,
    pub(super) process: u32,
}

impl PreparedWholeMapping {
    /// Initializes and reserves the original mapping before native effects.
    ///
    /// No native epoch or role roster is invented. The native issuer separately
    /// authenticates actual original geometry and source readiness.
    pub(super) fn new(
        descriptor: BorrowedFd<'_>,
        config: RegionConfig,
    ) -> Result<Self, QemuSpawnError> {
        let allocation = RegionAllocation::new(config).map_err(error)?;
        let byte_length = allocation.layout().region_size;
        let before = fstat(descriptor).map_err(error)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || u64::try_from(before.st_size).ok() != Some(byte_length)
        {
            return Err(error(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "original whole region descriptor differs from its complete geometry",
            )));
        }
        let identity = OriginalMappingIdentity {
            device: before.st_dev,
            inode: before.st_ino,
            byte_length,
            process: std::process::id(),
        };
        let bytes = allocation.setup_region_bytes().map_err(error)?;
        crate::host_setup::write_shmem_setup_region(descriptor.as_raw_fd(), &bytes)
            .map_err(error)?;
        let mapping = mmap_setup_region(descriptor, byte_length).map_err(error)?;
        let after = fstat(descriptor).map_err(error)?;
        if (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        {
            return Err(error(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "original whole region identity changed during initialization",
            )));
        }
        let mut owner = OwnedSetupMapping::new(mapping);

        // This fallible reservation precedes child creation. The sticky local
        // fence grants neither a native epoch nor a callback loan; genuine source
        // HOLD and stopped-census issuance must still come from the original child.
        owner.prepare_whole_intent_retention().map_err(error)?;
        if let Err(failure) = owner.begin_whole_intent() {
            owner.refuse_whole_control();
            return Err(error(failure));
        }
        Ok(Self {
            owner,
            config,
            byte_length,
            identity,
        })
    }
}

fn error(source: impl std::error::Error + Send + Sync + 'static) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation: "prepare original whole mapping before child effects",
        source: std::io::Error::other(source),
    }
}
