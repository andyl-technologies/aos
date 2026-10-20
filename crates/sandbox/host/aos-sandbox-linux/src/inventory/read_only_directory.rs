//! Original-descriptor facts for an attached or detached read-only directory.
//!
//! These observations contain no namespace, topology, backend, or admission
//! authority. A detached mount need not appear in a namespace's mount tree.

use std::os::fd::BorrowedFd;

use rustix::fs::{FileType, OFlags, StatVfsMountFlags};
use rustix::io::FdFlags;

use super::MountId;
use crate::boot::{KernelBootId, RootOriginalKernelBootIdAttemptV1};
use std::error::Error as StdError;
use crate::{Error, Result};

/// Records nonauthorizing facts sampled from one original directory descriptor.
///
/// Callers must retain the descriptor and repeat observation around their own
/// authenticated owner joins. Read-only status is not immutability or topology
/// proof, and these data do not establish namespace membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyDirectorySnapshot {
    /// Identifies the kernel sampled before and after descriptor inspection.
    pub boot_id: [u8; 16],
    /// Records the actual open-file-description status, including `O_PATH`.
    pub status_flags: OFlags,
    /// Records the actual descriptor flags, including `FD_CLOEXEC`.
    pub descriptor_flags: FdFlags,
    /// Records the directory's kernel device number.
    pub device: u64,
    /// Records the directory's kernel inode number.
    pub inode: u64,
    /// Records the directory's complete kernel mode.
    pub mode: u32,
    /// Records the kernel-lifetime unique mount ID from `statx` on this FD.
    pub mount_id: MountId,
    /// Records `fstatvfs` flags; these are not `MOUNT_ATTR_*` values.
    pub mount_flags: StatVfsMountFlags,
}

impl ReadOnlyDirectorySnapshot {
    /// Samples strict directory facts without a namespace lookup or path reopen.
    ///
    /// # Errors
    ///
    /// Rejects inspection failures, changed boot, non-`O_PATH` or non-`CLOEXEC`
    /// descriptors, nondirectories, zero device/inode, missing unique mount ID,
    /// and mounts not read-only according to the original FD's `fstatvfs`.
    pub fn capture(descriptor: BorrowedFd<'_>) -> Result<Self> {
        Self::capture_recipe(descriptor, None)
    }

    /// Samples the same descriptor into a prepaid original destination once.
    ///
    /// The retained boot arm additionally requires bounded canonical procfs
    /// input. Its original file/read/error prefix stays owned on refusal.
    /// This observation grants no directory or namespace authority.
    ///
    /// # Errors
    /// Retains failed native/boot/shape results and refuses repeated entry.
    pub fn capture_retaining_once_v1(
        descriptor: BorrowedFd<'_>,
        original: &mut ReadOnlyDirectorySnapshotOriginalV1,
    ) -> Result<Self> {
        if original.entered {
            original.reentry.get_or_insert_with(|| Error::invalid("directory snapshot", "original already entered"));
            return Err(snapshot_refusal());
        }
        original.entered = true;
        original.returned = Some(Self::capture_recipe(descriptor, Some(original)));
        match original.returned.as_ref() {
            Some(Ok(observed)) => Ok(observed.clone()),
            _ => Err(snapshot_refusal()),
        }
    }

    fn capture_recipe(
        descriptor: BorrowedFd<'_>,
        original: Option<&mut ReadOnlyDirectorySnapshotOriginalV1>,
    ) -> Result<Self> {
        // Split each actual destination once so native outputs can borrow
        // their original slots through the later probes without cloning DATA.
        let (boot_before, status_slot, descriptor_slot, stat_slot, mount_id_slot,
            mount_slot, shape_slot, boot_after, boot_binding_slot) = match original {
            Some(original) => (
                Some(&mut original.boot_before), Some(&mut original.status_flags),
                Some(&mut original.descriptor_flags), Some(&mut original.stat),
                Some(&mut original.mount_id), Some(&mut original.mount), Some(&mut original.shape),
                Some(&mut original.boot_after), Some(&mut original.boot_binding),
            ),
            None => (None, None, None, None, None, None, None, None, None),
        };
        let boot = capture_boot(boot_before)?;
        let status_flags = capture_native(rustix::fs::fcntl_getfl(descriptor),
            status_slot, "SourceRoot fcntl_getfl")?;
        let descriptor_flags = capture_native(rustix::io::fcntl_getfd(descriptor),
            descriptor_slot, "SourceRoot fcntl_getfd")?;
        let stat = capture_native(rustix::fs::fstat(descriptor),
            stat_slot, "SourceRoot fstat")?;
        let mount_id = capture_mount(MountId::from_fd(descriptor),
            mount_id_slot)?;
        let mount = capture_native(rustix::fs::fstatvfs(descriptor),
            mount_slot, "SourceRoot fstatvfs")?;
        let observed = Self {
            boot_id: boot.into_bytes(),
            status_flags: *status_flags,
            descriptor_flags: *descriptor_flags,
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            mount_id,
            mount_flags: mount.f_flag,
        };
        capture_comparison(observed.require_shape(),
            shape_slot)?;
        let after = capture_boot(boot_after)?;
        capture_comparison(if after != boot {
            Err(Error::invalid("directory snapshot", "kernel boot changed"))
        } else { Ok(()) }, boot_binding_slot)?;
        Ok(observed)
    }

    fn require_shape(&self) -> Result<()> {
        if !self.status_flags.contains(OFlags::PATH)
            || !self.descriptor_flags.contains(FdFlags::CLOEXEC)
            || FileType::from_raw_mode(self.mode) != FileType::Directory
            || self.device == 0
            || self.inode == 0
            || !self.mount_flags.contains(StatVfsMountFlags::RDONLY)
        {
            return Err(Error::invalid(
                "directory snapshot",
                "invalid read-only O_PATH directory",
            ));
        }
        Ok(())
    }
}

/// Retains one actual directory snapshot's native acquisition and comparisons.
///
/// The caller owns its same directory descriptor and pays this DATA before IO.
/// A failed boot prefix keeps its file; positive bounded boot files retire only
/// after complete UUID/EOF comparison, before the next native primitive.
#[must_use = "retain the whole failed directory snapshot with its purpose"]
pub struct ReadOnlyDirectorySnapshotOriginalV1 {
    boot_before: RootOriginalKernelBootIdAttemptV1,
    status_flags: Option<rustix::io::Result<OFlags>>,
    descriptor_flags: Option<rustix::io::Result<FdFlags>>,
    stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    mount_id: Option<Result<MountId>>,
    mount: Option<rustix::io::Result<rustix::fs::StatVfs>>,
    shape: Option<Result<()>>,
    boot_after: RootOriginalKernelBootIdAttemptV1,
    boot_binding: Option<Result<()>>,
    returned: Option<Result<ReadOnlyDirectorySnapshot>>,
    entered: bool,
    reentry: Option<Error>,
}

impl ReadOnlyDirectorySnapshotOriginalV1 {
    /// Creates inert native/result destinations without directory or boot IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            boot_before: RootOriginalKernelBootIdAttemptV1::new(), status_flags: None,
            descriptor_flags: None, stat: None, mount_id: None, mount: None, shape: None,
            boot_after: RootOriginalKernelBootIdAttemptV1::new(), boot_binding: None,
            returned: None, entered: false, reentry: None,
        }
    }

    /// Supplies conservative owner/diagnostic bytes and one temporary boot file.
    ///
    /// These compiled carriers create no resident namespace entry or payer.
    #[must_use]
    pub fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?.checked_mul(2)?)?
            .checked_add(4096)?;
        Some((bytes, RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1))
    }

    /// Borrows the first actual native or comparison cause without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.boot_before.failure().or_else(|| retained_error(&self.status_flags))
            .or_else(|| retained_error(&self.descriptor_flags)).or_else(|| retained_error(&self.stat))
            .or_else(|| retained_error(&self.mount_id)).or_else(|| retained_error(&self.mount))
            .or_else(|| retained_error(&self.shape)).or_else(|| self.boot_after.failure())
            .or_else(|| retained_error(&self.boot_binding)).or_else(|| retained_error(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Default for ReadOnlyDirectorySnapshotOriginalV1 {
    fn default() -> Self { Self::new() }
}

fn snapshot_refusal() -> Error {
    Error::invalid("directory snapshot", "retained original refused")
}

fn retained_error<T, E: StdError + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn StdError + 'static)>
{ slot.as_ref()?.as_ref().err().map(|cause| cause as _) }

fn capture_boot(original: Option<&mut RootOriginalKernelBootIdAttemptV1>) -> Result<KernelBootId> {
    let Some(original) = original else { return KernelBootId::current() };
    let boot = *original.observe_once().map_err(|_| snapshot_refusal())?;
    original.retire_positive_file_once().map_err(|_| snapshot_refusal())?;
    Ok(boot)
}

// The ordinary adapter preserves its owned native temporary lifetime; the
// retained adapter borrows the whole same result through subsequent probes.
enum SnapshotNativeOutputV1<'original, T> {
    Local(T),
    Original(&'original T),
}

impl<T> std::ops::Deref for SnapshotNativeOutputV1<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self {
            Self::Local(value) => value,
            Self::Original(value) => value,
        }
    }
}

fn capture_native<'original, T>(
    result: rustix::io::Result<T>,
    original: Option<&'original mut Option<rustix::io::Result<T>>>,
    operation: &'static str,
) -> Result<SnapshotNativeOutputV1<'original, T>> {
    let Some(original) = original else {
        return result.map(SnapshotNativeOutputV1::Local).map_err(|source| syscall(operation, source));
    };
    *original = Some(result);
    match original.as_ref() {
        Some(Ok(value)) => Ok(SnapshotNativeOutputV1::Original(value)),
        _ => Err(snapshot_refusal()),
    }
}

fn capture_mount(result: Result<MountId>, original: Option<&mut Option<Result<MountId>>>) -> Result<MountId> {
    let Some(original) = original else { return result };
    *original = Some(result);
    original.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or_else(snapshot_refusal)
}

fn capture_comparison(result: Result<()>, original: Option<&mut Option<Result<()>>>) -> Result<()> {
    let Some(original) = original else { return result };
    *original = Some(result);
    if matches!(original, Some(Ok(()))) { Ok(()) } else { Err(snapshot_refusal()) }
}

fn syscall(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn writable_directory_is_not_a_read_only_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            ReadOnlyDirectorySnapshot::capture(fd.as_fd()),
            Err(Error::InvalidInput { .. })
        ));
    }

    #[test]
    fn retained_directory_refusal_preserves_its_actual_prefix_across_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, rustix::fs::Mode::empty()).unwrap();
        let mut original = ReadOnlyDirectorySnapshotOriginalV1::new();

        assert!(ReadOnlyDirectorySnapshot::capture_retaining_once_v1(fd.as_fd(), &mut original).is_err());
        let first = std::ptr::from_ref(original.failure().unwrap());
        assert!(ReadOnlyDirectorySnapshot::capture_retaining_once_v1(fd.as_fd(), &mut original).is_err());

        assert!(original.entered);
        assert!(matches!(original.returned, Some(Err(_))));
        assert!(std::ptr::eq(std::ptr::from_ref(original.failure().unwrap()), first));
    }

    #[test]
    fn every_required_descriptor_fact_is_checked() {
        // DATA-only shape checks do not claim a kernel-observed positive root.
        let valid = ReadOnlyDirectorySnapshot {
            boot_id: [1; 16],
            status_flags: OFlags::PATH,
            descriptor_flags: FdFlags::CLOEXEC,
            device: 2,
            inode: 3,
            mode: FileType::Directory.as_raw_mode(),
            mount_id: MountId::new(4).unwrap(),
            mount_flags: StatVfsMountFlags::RDONLY,
        };
        assert!(valid.require_shape().is_ok());
        for field in 0..6 {
            let mut invalid = valid.clone();
            match field {
                0 => invalid.status_flags = OFlags::empty(),
                1 => invalid.descriptor_flags = FdFlags::empty(),
                2 => invalid.mode = FileType::RegularFile.as_raw_mode(),
                3 => invalid.device = 0,
                4 => invalid.inode = 0,
                _ => invalid.mount_flags = StatVfsMountFlags::empty(),
            }
            assert!(invalid.require_shape().is_err(), "field {field}");
        }
    }
}
