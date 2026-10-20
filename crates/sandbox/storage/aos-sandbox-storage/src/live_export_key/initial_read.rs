//! Retains the shared protected export directory and fixed-record read recipe.
//!
//! These private DATA destinations own reached native results. Their callers
//! establish the actual role, pathname, payment and enclosing currentness posts.
//! Ordinary adapters use the same native steps with their original local drops.

use super::*;
use std::error::Error;
use std::os::unix::fs::FileExt as _;

struct DirectoryStep {
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    metadata: Option<Result<Stat, rustix::io::Errno>>,
    validation: Option<Result<(), StorageLiveExportKeyErrorV1>>,
}

impl DirectoryStep {
    const fn new() -> Self {
        Self {
            opened: None,
            metadata: None,
            validation: None,
        }
    }

    fn capture(&mut self, path: &Path, final_directory: bool, owner: u32)
        -> Result<(), StorageLiveExportKeyErrorV1>
    {
        self.opened = Some(rustix::fs::open(path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty()));
        let descriptor = self.descriptor().ok_or(StorageLiveExportKeyErrorV1::Custody)?;
        self.metadata = Some(rustix::fs::fstat(descriptor));
        let identity = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageLiveExportKeyErrorV1::Custody)?;
        self.validation = Some(if FileType::from_raw_mode(identity.st_mode) != FileType::Directory
            || (identity.st_uid != 0 && identity.st_uid != owner)
            || identity.st_mode & 0o022 != 0
            || final_directory && (identity.st_uid != owner || identity.st_mode & 0o777 != 0o700)
        {
            Err(StorageLiveExportKeyErrorV1::Custody)
        } else {
            Ok(())
        });
        self.validation.as_ref().copied().ok_or(StorageLiveExportKeyErrorV1::Custody)?
    }

    fn descriptor(&self) -> Option<&OwnedFd> {
        self.opened.as_ref().and_then(|result| result.as_ref().ok())
    }

    fn take_descriptor(&mut self) -> Option<OwnedFd> {
        self.opened.take().and_then(Result::ok)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| self.metadata.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error))
            .or_else(|| self.validation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error))
    }
}

/// Holds every reached directory step until its real enclosing posts finish.
pub(crate) struct ProtectedExportDirectoryOriginalV1 {
    steps: Vec<DirectoryStep>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    result: Option<Result<(), StorageLiveExportKeyErrorV1>>,
    reentered: bool,
}

impl ProtectedExportDirectoryOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            steps: Vec::new(),
            allocation: None,
            result: None,
            reentered: false,
        }
    }

    /// Captures the same protected ancestry recipe once.
    ///
    /// # Errors
    /// Retains allocation, native and custody failure; repeat entry never retries.
    pub(crate) fn capture_once(&mut self, path: &Path, owner: u32)
        -> Result<(), StorageLiveExportKeyErrorV1>
    {
        if self.result.is_some() {
            self.reentered = true;
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        self.result = Some(walk_directory(path, owner, Some(self)).map(|_| ()));
        self.result.as_ref().copied().ok_or(StorageLiveExportKeyErrorV1::Custody)?
    }

    pub(crate) fn descriptor(&self) -> Option<&OwnedFd> {
        if self.reentered || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        self.steps.last().and_then(DirectoryStep::descriptor)
    }

    pub(crate) fn take_descriptor(&mut self) -> Option<OwnedFd> {
        self.descriptor()?;
        self.steps.last_mut().and_then(DirectoryStep::take_descriptor)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.allocation.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| self.steps.iter().find_map(DirectoryStep::failure))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error))
    }

    pub(crate) fn settle_positive(&mut self) {
        if !self.reentered && matches!(self.result, Some(Ok(()))) {
            self.steps = Vec::new();
        }
    }

    pub(crate) fn step_memory_bytes() -> usize {
        std::mem::size_of::<DirectoryStep>()
    }
}

fn walk_directory(path: &Path, owner: u32, mut retained: Option<&mut ProtectedExportDirectoryOriginalV1>)
    -> Result<Option<OwnedFd>, StorageLiveExportKeyErrorV1>
{
    if !path.is_absolute() || path == Path::new("/")
        || path.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(StorageLiveExportKeyErrorV1::Custody);
    }
    if let Some(original) = retained.as_deref_mut() {
        original.allocation = Some(original.steps.try_reserve_exact(path.ancestors().count()));
        if !matches!(original.allocation, Some(Ok(()))) {
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if let Some(original) = retained.as_deref_mut() {
            // Install the destination before the native open, including Err.
            original.steps.push(DirectoryStep::new());
            let step = original.steps.last_mut().ok_or(StorageLiveExportKeyErrorV1::Custody)?;
            step.capture(ancestor, ancestor == path, owner)?;
            if ancestor == path {
                return Ok(None);
            }
        } else {
            let mut step = DirectoryStep::new();
            step.capture(ancestor, ancestor == path, owner)?;
            if ancestor == path {
                return Ok(step.take_descriptor());
            }
            // Ordinary successful ancestors still close before the next open.
        }
    }
    Err(StorageLiveExportKeyErrorV1::Custody)
}

pub(super) fn open_directory(path: &Path, owner: u32)
    -> Result<OwnedFd, StorageLiveExportKeyErrorV1>
{
    walk_directory(path, owner, None)?.ok_or(StorageLiveExportKeyErrorV1::Custody)
}

/// Holds both actual fixed reads, metadata bookends and the open file.
pub(crate) struct ProtectedExportFileOriginalV1<const N: usize> {
    // Fields drop in declaration order. Preserve the ordinary local recipe's
    // repeated-buffer, record-buffer, then File destruction on every return.
    repeated: Zeroizing<[u8; N]>,
    bytes: Zeroizing<[u8; N]>,
    before: Option<Result<Stat, rustix::io::Errno>>,
    validation: Option<Result<(), StorageLiveExportKeyErrorV1>>,
    first_read: Option<Result<(), std::io::Error>>,
    second_read: Option<Result<(), std::io::Error>>,
    after: Option<Result<Stat, rustix::io::Errno>>,
    stable: Option<Result<(), StorageLiveExportKeyErrorV1>>,
    result: Option<Result<(), StorageLiveExportKeyErrorV1>>,
    reentered: bool,
    opened: Option<Result<File, rustix::io::Errno>>,
}

impl<const N: usize> ProtectedExportFileOriginalV1<N> {
    pub(crate) fn new() -> Self {
        Self {
            opened: None,
            before: None,
            validation: None,
            first_read: None,
            second_read: None,
            after: None,
            stable: None,
            bytes: Zeroizing::new([0; N]),
            repeated: Zeroizing::new([0; N]),
            result: None,
            reentered: false,
        }
    }

    /// Runs the shared exact root-owned 0600 fixed-record read once.
    ///
    /// # Errors
    /// Retains the file and actual first native/read error on every refusal.
    pub(crate) fn capture_once(&mut self, directory: BorrowedFd<'_>, name: &str, owner: u32)
        -> Result<(), StorageLiveExportKeyErrorV1>
    {
        if self.result.is_some() {
            self.reentered = true;
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        self.result = Some(self.capture(directory, name, owner));
        self.result.as_ref().copied().ok_or(StorageLiveExportKeyErrorV1::Custody)?
    }

    fn capture(&mut self, directory: BorrowedFd<'_>, name: &str, owner: u32)
        -> Result<(), StorageLiveExportKeyErrorV1>
    {
        self.opened = Some(rustix::fs::openat(directory, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty()).map(File::from));
        let file = self.opened.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageLiveExportKeyErrorV1::Custody)?;
        self.before = Some(rustix::fs::fstat(file));
        let before = self.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageLiveExportKeyErrorV1::Custody)?;
        self.validation = Some(if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != owner || before.st_mode & 0o777 != 0o600
            || before.st_nlink != 1 || before.st_size != N as i64
            || before.st_dev == 0 || before.st_ino == 0
        {
            Err(StorageLiveExportKeyErrorV1::Custody)
        } else {
            Ok(())
        });
        self.validation.as_ref().copied().ok_or(StorageLiveExportKeyErrorV1::Custody)??;
        self.first_read = Some(file.read_exact_at(&mut *self.bytes, 0));
        if !matches!(self.first_read, Some(Ok(()))) {
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        self.second_read = Some(file.read_exact_at(&mut *self.repeated, 0));
        if !matches!(self.second_read, Some(Ok(()))) {
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        self.after = Some(rustix::fs::fstat(file));
        let after = self.after.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageLiveExportKeyErrorV1::Custody)?;
        self.stable = Some(if !same_stable_file_metadata(before, after) || *self.bytes != *self.repeated {
            Err(StorageLiveExportKeyErrorV1::Custody)
        } else {
            Ok(())
        });
        self.stable.as_ref().copied().ok_or(StorageLiveExportKeyErrorV1::Custody)?
    }

    pub(crate) fn record(&self) -> Option<(&[u8; N], u64, u64)> {
        if self.reentered || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        let before = self.before.as_ref()?.as_ref().ok()?;
        Some((&self.bytes, before.st_dev, before.st_ino))
    }

    pub(super) fn take_record(&mut self) -> Option<(Zeroizing<[u8; N]>, u64, u64)> {
        let (_, device, inode) = self.record()?;
        let bytes = std::mem::replace(&mut self.bytes, Zeroizing::new([0; N]));
        Some((bytes, device, inode))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.validation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.first_read.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.second_read.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.stable.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
    }

    pub(crate) fn settle_positive(&mut self) {
        if !self.reentered && matches!(self.result, Some(Ok(()))) {
            self.opened = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[test]
    fn missing_ancestor_retains_actual_root_and_first_native_cause() {
        let path = PathBuf::from(format!("/rfc21-missing-export-{}", std::process::id()));
        let mut original = ProtectedExportDirectoryOriginalV1::new();
        // This private ancestry engine supports an explicit owner. Use the
        // real filesystem owner; the production fixed-root adapter stays0.
        let owner = std::fs::metadata("/").unwrap().uid();
        assert!(original.capture_once(&path, owner).is_err());
        assert!(original.steps.first().and_then(DirectoryStep::descriptor).is_some());
        let cause = original.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap()
            as *const rustix::io::Errno;
        let retained = original.steps.iter().filter(|step| step.descriptor().is_some()).count();

        assert!(original.capture_once(Path::new("/"), 0).is_err());
        original.settle_positive();

        assert_eq!(retained, original.steps.iter().filter(|step| step.descriptor().is_some()).count());
        assert_eq!(cause, original.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap()
            as *const rustix::io::Errno);
    }

    #[test]
    fn wrong_fixed_length_keeps_file_metadata_and_first_cause_after_repair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        std::fs::write(&path, [1_u8; 3]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner = path.metadata().unwrap().uid();
        let descriptor = File::open(directory.path()).unwrap();
        let mut original = ProtectedExportFileOriginalV1::<4>::new();

        assert!(original.capture_once(descriptor.as_fd(), "record", owner).is_err());
        let held = original.opened.as_ref().unwrap().as_ref().unwrap();
        let identity = rustix::fs::fstat(held).unwrap();
        let cause = original.failure().unwrap().downcast_ref::<StorageLiveExportKeyErrorV1>().unwrap()
            as *const StorageLiveExportKeyErrorV1;
        std::fs::write(&path, [2_u8; 4]).unwrap();
        assert!(original.capture_once(descriptor.as_fd(), "record", owner).is_err());
        original.settle_positive();

        let current = rustix::fs::fstat(original.opened.as_ref().unwrap().as_ref().unwrap()).unwrap();
        assert_eq!((identity.st_dev, identity.st_ino), (current.st_dev, current.st_ino));
        assert_eq!(cause, original.failure().unwrap().downcast_ref::<StorageLiveExportKeyErrorV1>().unwrap()
            as *const StorageLiveExportKeyErrorV1);
        assert!(original.first_read.is_none());
        assert!(original.record().is_none());
    }

    #[test]
    fn successful_fixed_reads_match_both_actual_metadata_bookends() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        std::fs::write(&path, [7_u8; 4]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner = path.metadata().unwrap().uid();
        let descriptor = File::open(directory.path()).unwrap();
        let mut original = ProtectedExportFileOriginalV1::<4>::new();

        original.capture_once(descriptor.as_fd(), "record", owner).unwrap();
        let (bytes, device, inode) = original.record().unwrap();
        assert_eq!(*bytes, [7; 4]);
        assert_eq!(*original.bytes, *original.repeated);
        assert!(same_stable_file_metadata(
            original.before.as_ref().unwrap().as_ref().unwrap(),
            original.after.as_ref().unwrap().as_ref().unwrap(),
        ));
        assert_ne!((device, inode), (0, 0));

        original.settle_positive();
        assert!(original.opened.is_none());
        assert!(matches!(original.first_read, Some(Ok(()))));
        assert!(matches!(original.second_read, Some(Ok(()))));
    }
}
