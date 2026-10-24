//! Shares the existing physical Cache root and fixed-name native observations.
//!
//! These operations return only inode/owner DATA or a raw descriptor. They do
//! not hold the physical flock, parse a manifest, authenticate a caller, grant
//! F/role receiving or admit an effect. Fixed role owners retain their own
//! purpose, budget, actual originals and independently owed final observations.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

/// Supplies the existing native refusal vocabulary without a success callback.
pub trait PhysicalCacheObservationFailureV1: From<io::Error> + From<rustix::io::Errno> {
    /// Refuses a replaced or unsafe original root/lock.
    const ROOT_CHANGED: Self;
    /// Refuses an unsafe named manifest.
    const INVALID_MANIFEST: Self;
}

/// Copies observed root inode, mode and mapped owner DATA without ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheRootObservationDataV1 {
    /// Observed filesystem device.
    pub device: u64,
    /// Observed root inode.
    pub inode: u64,
    /// Observed mapped owner UID.
    pub uid: u32,
    /// Observed permission/special mode bits.
    pub mode: u32,
}

/// Copies the observed fixed lock identity without taking its flock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheLockObservationDataV1 {
    /// Observed filesystem device.
    pub device: u64,
    /// Observed lock inode.
    pub inode: u64,
}

/// Copies a validated named manifest identity without opening or authorizing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheManifestObservationDataV1 {
    /// Observed filesystem device.
    pub device: u64,
    /// Observed manifest inode.
    pub inode: u64,
}

/// Compares the existing complete disk-object inode predicates as passive DATA.
///
/// Actual Native callers retain their own fstat result and root/name post at
/// the original positions. A matching tuple supplies no file or read authority.
#[must_use]
pub fn disk_object_identity_matches_data_v2(stat: &rustix::fs::Stat,
    device: u64, inode: u64, uid: u32, bytes: u64,
) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_dev == device
        && stat.st_ino == inode
        && stat.st_nlink == 1
        && stat.st_uid == uid
        && stat.st_size >= 0
        && stat.st_size as u64 == bytes
}

/// Opens one supplied readonly root using the original fixed flags.
///
/// The caller must select its own fixed recipe and pay/retain the actual FD.
/// A successful open supplies neither authenticated location nor role custody.
///
/// # Errors
/// Returns the original native opening error.
pub fn open_readonly_root_v1(path: &str) -> rustix::io::Result<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Observes the same directory metadata and mapped-owner predicates.
///
/// # Errors
/// Returns the original fstat error or ROOT_CHANGED for wrong kind/owner/mode.
pub fn inspect_root_v1<E: PhysicalCacheObservationFailureV1>(
    root: &impl AsFd,
) -> Result<CacheRootObservationDataV1, E> {
    let stat = rustix::fs::fstat(root)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(E::ROOT_CHANGED);
    }
    Ok(CacheRootObservationDataV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode & 0o7777,
    })
}

/// Observes the original lock and fixed `.owner.lock` name in the same order.
///
/// # Errors
/// Returns original fstat/statat errors or ROOT_CHANGED for replaced/unsafe names.
pub fn inspect_lock_v1<E: PhysicalCacheObservationFailureV1>(
    root: &impl AsFd,
    lock: &impl AsFd,
) -> Result<CacheLockObservationDataV1, E> {
    let stat = rustix::fs::fstat(lock)?;
    let named = rustix::fs::statat(root, ".owner.lock", AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || named.st_dev != stat.st_dev
        || named.st_ino != stat.st_ino
        || named.st_mode != stat.st_mode
    {
        return Err(E::ROOT_CHANGED);
    }
    Ok(CacheLockObservationDataV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

/// Observes the exact `owner-state` name, preserving ordinary absence.
///
/// # Errors
/// Returns the original statat error or INVALID_MANIFEST for unsafe metadata.
pub fn inspect_manifest_identity_v1<E: PhysicalCacheObservationFailureV1>(
    root: &impl AsFd,
) -> Result<Option<CacheManifestObservationDataV1>, E> {
    let named = match rustix::fs::statat(root, "owner-state", AtFlags::SYMLINK_NOFOLLOW) {
        Ok(named) => named,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
        || named.st_uid != rustix::process::geteuid().as_raw()
        || named.st_mode & 0o7777 != 0o600
        || named.st_nlink != 1
    {
        return Err(E::INVALID_MANIFEST);
    }
    Ok(Some(CacheManifestObservationDataV1 {
        device: named.st_dev,
        inode: named.st_ino,
    }))
}

/// Rejects the same legacy object-root name without opening or repairing it.
///
/// # Errors
/// Returns ROOT_CHANGED for any present object or the original metadata error.
pub fn reject_legacy_object_root_at_v1<E: PhysicalCacheObservationFailureV1>(
    legacy: &Path,
) -> Result<(), E> {
    match std::fs::symlink_metadata(legacy) {
        Ok(_) => Err(E::ROOT_CHANGED),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Retains the shared fixed native object-view sampler without role authority.
pub mod current_view;

#[cfg(test)]
mod disk_identity_tests {
    use super::*;

    #[test]
    fn disk_identity_rejects_each_mutated_native_coordinate() {
        // The production object predicate requires one actual directory link.
        let file = tempfile::NamedTempFile::new().unwrap();
        let original = rustix::fs::fstat(file.as_file()).unwrap();
        assert_eq!(original.st_nlink, 1);
        let matches = |stat: &rustix::fs::Stat| disk_object_identity_matches_data_v2(
            stat, original.st_dev, original.st_ino, original.st_uid, original.st_size as u64,
        );
        assert!(matches(&original));

        let mut changed = original;
        changed.st_dev ^= 1;
        assert!(!matches(&changed));
        changed = original;
        changed.st_ino ^= 1;
        assert!(!matches(&changed));
        changed = original;
        changed.st_uid ^= 1;
        assert!(!matches(&changed));
        changed = original;
        changed.st_nlink = 2;
        assert!(!matches(&changed));
        changed = original;
        changed.st_size = -1;
        assert!(!matches(&changed));
        changed = original;
        changed.st_size += 1;
        assert!(!matches(&changed));

        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::File::open(directory.path()).unwrap();
        let directory = rustix::fs::fstat(&directory).unwrap();
        assert!(!disk_object_identity_matches_data_v2(&directory,
            directory.st_dev, directory.st_ino, directory.st_uid, directory.st_size as u64));
    }
}
