//! Inspects genuine host-cache filesystems before enabling Linux adapters.
//!
//! Directory descriptors remain retained so pathname replacement cannot turn a
//! validated layout into a different filesystem. Actual seal enablement remains
//! the publisher's responsibility; filesystem names alone do not prove a seal.

use rustix::fs::{Mode, OFlags, fstat, fstatfs, open, openat};
#[cfg(feature = "tokio")]
mod content;
#[cfg(feature = "tokio")]
mod manifest_source;
#[cfg(feature = "tokio")]
mod metadata;
#[cfg(feature = "tokio")]
mod owner;
mod quota;
#[cfg(feature = "tokio")]
mod ready;
mod reassembly;
#[cfg(feature = "tokio")]
mod recovery_inspection;
mod residency;
mod seal;
#[cfg(feature = "tokio")]
mod shared_residences;
mod source;

#[cfg(feature = "tokio")]
pub use content::{
    NativeChunkedObject, NativeChunkedReader, NativeContentStore, NativeObjectPresentation,
    NativePreparedObject, NativeReadDriver, NativeReadPolicy, NativeSealedObject,
};
#[cfg(feature = "tokio")]
pub use manifest_source::NativeManifestSource;
#[cfg(feature = "tokio")]
pub use metadata::NativeHostMetadataReader;
#[cfg(feature = "native-test-fixtures")]
pub use owner::NativePolicyStall;
#[cfg(feature = "tokio")]
pub use owner::SurfaceIndexPolicy;
#[cfg(feature = "tokio")]
pub(crate) use owner::{
    AcceptedRecoveryManifestEffect, PublisherCacheRetirementTurn, PublisherCleanupTurn,
    PublisherCorruptionTurn, PublisherEncodedCacheTurn, PublisherEncodedReadTurn,
    PublisherRecoveryRestoreTurn, PublisherRecoveryRetirementTurn, PublisherResumeTurn,
    PublisherRunningTurn, RecoveryManifestBodyFailure, RecoveryManifestBodyRetention,
    RecoveryManifestEffect, RecoveryManifestEffectFailure, RecoveryRetainedManifest,
    RunningRecovery,
};
#[cfg(feature = "tokio")]
pub use owner::{
    CompletedRecovery, IndexRepairPolicy, NativeAdmissionHandoffError,
    NativeAdmissionHandoffReport, NativeCacheEvictionReport, NativeCacheHandoffError,
    NativeCacheHandoffReport, NativeCacheOwnerConfig, NativeCachePreparation, NativeChunkAdmission,
    NativeChunkAdmissionError, NativeChunkAdmissionTicket, NativeChunkFetchRequest,
    NativeConsumerLease, NativeFetchedChunk, NativeFileBacking, NativeIndexRepairReport,
    NativeInlinePublication, NativeLeaseAccounting, NativeManifestPublication,
    NativeMetadataAdmission, NativeMetadataAdmissionError, NativeMetadataOwner,
    NativeProducerReadClosure, NativeReadChunk, NativeResidentChunkSource, NativeResumeError,
    NativeSealedBacking, NativeSealedObjectLease, NativeSourceCleanupReport, RetainedManifest,
};
#[cfg(all(feature = "tokio", feature = "surface-fuse"))]
pub use owner::{
    NativeExposureLease, NativeExposureReconciliation, NativeExposureRootBacking, NativeRootIndex,
    NativeSurfaceIndex,
};
pub use quota::ProjectQuota;
#[cfg(feature = "tokio")]
pub use ready::NativeReady;
pub use reassembly::NativeReassemblyPlan;
#[cfg(feature = "tokio")]
pub use recovery_inspection::{
    DerivedIndexRepair, DetachedIndexStatus, NativeQuarantinedInode, NativeRecoveryCandidate,
    NativeRecoveryInspection, NativeRecoveryInspector, RecoveryIssue, VerifiedEncodedBody,
    VerifiedStandaloneChunk,
};
pub use residency::{NativeChunkSpan, NativeResidencePlan};
pub use seal::NativeSealCapability;
#[cfg(feature = "tokio")]
pub use shared_residences::NativeSharedResidences;
pub use source::NativeChunkSource;

use std::{
    collections::BTreeMap,
    fs::File,
    io,
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
};
use terrane_sdk::host::cache::{DomainHostLayout, HostReadLocation};

/// Holds inspected directory descriptors for one host layout.
pub struct NativeHostLayout<L: HostReadLocation = DomainHostLayout> {
    layout: L,
    root: OwnedFd,
    provisioning: crate::host_quota::DomainProvisioningGuard,
    directories: BTreeMap<&'static str, OwnedFd>,
    administrative_root: Option<(PathBuf, OwnedFd)>,
}

impl<L: HostReadLocation> NativeHostLayout<L> {
    /// Opens existing, non-stacked host directories on one local filesystem.
    ///
    /// This establishes mount/layout facts, not successful seal enablement.
    /// The publisher must still refuse operation if its genuine fs-verity probe
    /// fails. No directory or test inode is created by this inspection.
    ///
    /// # Errors
    /// Refuses symlink roots, unsupported filesystems, missing directories,
    /// cross-filesystem directories, or kernel inspection errors.
    pub fn inspect(layout: L) -> io::Result<Self> {
        Self::inspect_with_administrative_root(layout, None)
    }

    /// Inspects a domain layout and optional explicitly configured host scaffold.
    ///
    /// The administrative root is trusted host configuration, never inferred
    /// from path ancestry. It must use the same filesystem as this domain's
    /// single owner project. This inspection assigns no project identifiers and
    /// grants no admission authority without fresh authenticated quota queries.
    ///
    /// # Errors
    /// Refuses unsafe/missing roots, another filesystem, a redundant domain-root
    /// alias and failed native directory inspection.
    pub fn inspect_with_administrative_root(
        layout: L,
        administrative_root: Option<&Path>,
    ) -> io::Result<Self> {
        let root = open_directory_chain(layout.root())?;
        // Provisioning takes the exclusive lock on this exact inode. The guard
        // opens its own read-only description so O_PATH duplication cannot
        // accidentally convert or release another actor's flock.
        let provisioning =
            crate::host_quota::DomainProvisioningGuard::shared(&File::from(root.try_clone()?))?;
        let root_stat = fstat(&root)?;
        if provisioning.identity()? != (root_stat.st_dev, root_stat.st_ino) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "provisioning guard differs from inspected domain root",
            ));
        }
        let mut directories = BTreeMap::new();
        for name in [
            "chunks",
            "objects",
            "sealed",
            "staging",
            "quarantine",
            "pending-delete",
            "state",
        ] {
            let descriptor = openat(
                &root,
                name,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let metadata = fstat(&descriptor)?;
            let filesystem = fstatfs(&descriptor)?;
            // ext4, btrfs and f2fs implement fs-verity. Rejecting unknown local
            // filesystems is conservative; network and stacked mounts fail here.
            let kind = filesystem.f_type as u64;
            if metadata.st_dev != root_stat.st_dev
                || !matches!(kind, 0xef53 | 0x9123683e | 0xf2f52010)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "host cache requires one non-stacked fs-verity-capable local filesystem",
                ));
            }
            directories.insert(name, descriptor);
        }
        let administrative_root = administrative_root
            .map(|path| {
                let descriptor = open_directory_chain(path)?;
                let metadata = fstat(&descriptor)?;
                if metadata.st_dev != root_stat.st_dev || metadata.st_ino == root_stat.st_ino {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "administrative root must be distinct on the domain filesystem",
                    ));
                }
                Ok((path.to_path_buf(), descriptor))
            })
            .transpose()?;
        Ok(Self {
            layout,
            root,
            provisioning,
            directories,
            administrative_root,
        })
    }

    /// Returns the inspected domain layout.
    pub fn layout(&self) -> &L {
        &self.layout
    }

    /// Observes one configured allocation root through its retained descriptor.
    ///
    /// Labels name fixed host-layout roles, never caller-selected paths. This
    /// observation alone grants no quota, reservation or admission authority.
    /// The native owner must compare it with a fresh authenticated helper query
    /// while retaining its admission custody.
    ///
    /// # Errors
    /// Refuses unknown labels, replaced roots and failed native metadata reads.
    pub fn directory_binding(&self, label: &str) -> io::Result<(u64, u64)> {
        self.recheck()?;
        let descriptor = match label {
            "layout-root" => Some(&self.root),
            "administrative-root" => self.administrative_root.as_ref().map(|(_, file)| file),
            _ => self.directories.get(label),
        }
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "unknown host allocation root")
        })?;
        let metadata = fstat(descriptor)?;
        Ok((metadata.st_dev, metadata.st_ino))
    }

    /// Rechecks every retained directory against its current canonical name.
    ///
    /// # Errors
    /// Refuses renamed/replaced directories and failed kernel metadata reads.
    pub fn recheck(&self) -> io::Result<()> {
        let current_root = open_directory_chain(self.layout.root())?;
        let expected_root = fstat(&self.root)?;
        let actual_root = fstat(&current_root)?;
        if self.provisioning.identity()? != (expected_root.st_dev, expected_root.st_ino)
            || expected_root.st_dev != actual_root.st_dev
            || expected_root.st_ino != actual_root.st_ino
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host cache root was replaced",
            ));
        }
        if let Some((path, descriptor)) = &self.administrative_root {
            let current = open_directory_chain(path)?;
            let expected = fstat(descriptor)?;
            let actual = fstat(&current)?;
            if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "host administrative root was replaced",
                ));
            }
        }
        for (name, descriptor) in &self.directories {
            let current = openat(
                &self.root,
                *name,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let expected = fstat(descriptor)?;
            let actual = fstat(&current)?;
            if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "host cache directory was replaced",
                ));
            }
        }
        Ok(())
    }
}

// O_NOFOLLOW on a multi-component path protects only its final component.
// Walking from the retained filesystem root prevents following an ancestor
// symlink before the final directory's incarnation can be inspected.
fn open_directory_chain(path: &Path) -> io::Result<OwnedFd> {
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host directory must have an absolute canonical path",
        ));
    }
    let mut directory = open("/", flags, Mode::empty())?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host directory contains a noncanonical component",
            ));
        };
        directory = openat(&directory, name, flags, Mode::empty())?;
    }
    Ok(directory)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::open_directory_chain;
    use std::{fs, io::Read, os::unix::fs::symlink};

    #[test]
    fn native_host_cache_rejects_symlink_ancestors() {
        let mut random = [0_u8; 16];
        fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("terrane-native-host-chain-{suffix}"));
        fs::create_dir_all(root.join("real/leaf")).unwrap();
        symlink(root.join("real"), root.join("alias")).unwrap();

        let ordinary = open_directory_chain(&root.join("real/leaf"));
        let aliased = open_directory_chain(&root.join("alias/leaf"));

        assert!(ordinary.is_ok());
        assert!(aliased.is_err());
        drop(ordinary);
        fs::remove_dir_all(root).unwrap();
    }
}
