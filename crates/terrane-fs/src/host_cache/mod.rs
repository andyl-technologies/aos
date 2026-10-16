//! Inspects genuine host-cache filesystems before enabling Linux adapters.
//!
//! Directory descriptors remain retained so pathname replacement cannot turn a
//! validated layout into a different filesystem. Actual seal enablement remains
//! the publisher's responsibility; filesystem names alone do not prove a seal.

use rustix::fs::{Mode, OFlags, fstat, fstatfs, open, openat};
mod quota;
mod reassembly;
mod source;

pub use quota::ProjectQuota;
pub use reassembly::NativeReassemblyPlan;
pub use source::NativeChunkSource;

use std::{collections::BTreeMap, io, os::fd::OwnedFd};
use terrane::host::cache::DomainHostLayout;

/// Holds inspected directory descriptors for one host layout.
pub struct NativeHostLayout {
    layout: DomainHostLayout,
    root: OwnedFd,
    directories: BTreeMap<&'static str, OwnedFd>,
}

impl NativeHostLayout {
    /// Opens existing, non-stacked host directories on one local filesystem.
    ///
    /// This establishes mount/layout facts, not successful seal enablement.
    /// The publisher must still refuse operation if its genuine fs-verity probe
    /// fails. No directory or test inode is created by this inspection.
    ///
    /// # Errors
    /// Refuses symlink roots, unsupported filesystems, missing directories,
    /// cross-filesystem directories, or kernel inspection errors.
    pub fn inspect(layout: DomainHostLayout) -> io::Result<Self> {
        let root = open(
            layout.root(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let root_stat = fstat(&root)?;
        let mut directories = BTreeMap::new();
        for name in [
            "chunks",
            "sealed",
            "staging",
            "quarantine",
            "pending-delete",
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
        Ok(Self {
            layout,
            root,
            directories,
        })
    }

    /// Returns the inspected domain layout.
    pub fn layout(&self) -> &DomainHostLayout {
        &self.layout
    }

    /// Rechecks every retained directory against its current canonical name.
    ///
    /// # Errors
    /// Refuses renamed/replaced directories and failed kernel metadata reads.
    pub fn recheck(&self) -> io::Result<()> {
        let current_root = open(
            self.layout.root(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let expected_root = fstat(&self.root)?;
        let actual_root = fstat(&current_root)?;
        if expected_root.st_dev != actual_root.st_dev || expected_root.st_ino != actual_root.st_ino
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host cache root was replaced",
            ));
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
