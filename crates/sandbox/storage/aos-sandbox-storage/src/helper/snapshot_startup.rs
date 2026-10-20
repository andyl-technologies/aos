//! Fixed Snapshot metadata opening retained through actual backend handoff.
//!
//! The legacy adapter and selected startup share the same open/stat/policy
//! engine. Selected startup additionally keeps an independent named bookend;
//! its genuine enclosing prefix pays before either native operation.

use super::*;
use std::path::Path;

#[derive(Default)]
struct DirectoryRead {
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    policy: Option<Result<(), ZfsHelperError>>,
}

impl DirectoryRead {
    fn capture(&mut self, path: &Path) {
        self.opened = Some(open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let Some(Ok(directory)) = self.opened.as_ref() else { return; };
        self.metadata = Some(fstat(directory));
        let Some(Ok(metadata)) = self.metadata.as_ref() else { return; };
        self.policy = Some(if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != 0
            || !matches!(metadata.st_mode & 0o7777, 0o500 | 0o700)
        {
            Err(ZfsHelperError::ProcessContract)
        } else {
            Ok(())
        });
    }

    fn positive(&self) -> bool {
        matches!(self.opened, Some(Ok(_)))
            && matches!(self.metadata, Some(Ok(_)))
            && matches!(self.policy, Some(Ok(())))
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.metadata.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.policy.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }

    fn take_validated(&mut self) -> Option<OwnedFd> {
        if !self.positive() { return None; }
        match self.opened.take() {
            Some(Ok(directory)) => Some(directory),
            _ => std::process::abort(),
        }
    }
}

// The ordinary wrapper retains its exact single open/fstat/policy order and
// ProcessContract projection. It gains no selected named post or service gate.
pub(super) fn open_ordinary_fixed() -> Result<ProtectedSnapshotMetadataDirectoryV1, ZfsHelperError> {
    let mut read = DirectoryRead::default();
    read.capture(Path::new(FIXED_SNAPSHOT_METADATA_DIRECTORY));
    let directory = read.take_validated().ok_or(ZfsHelperError::ProcessContract)?;
    Ok(ProtectedSnapshotMetadataDirectoryV1 { directory })
}

pub(crate) struct StorageSnapshotMetadataStartupV1 {
    original: DirectoryRead,
    named: DirectoryRead,
    identity: Option<Result<(), ZfsHelperError>>,
    completed: Option<SystemdZfsProcessBackend>,
    entered: bool,
    taken: bool,
    closed: Option<ZfsHelperError>,
}

impl StorageSnapshotMetadataStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            original: DirectoryRead::default(),
            named: DirectoryRead::default(),
            identity: None,
            completed: None,
            entered: false,
            taken: false,
            closed: None,
        }
    }

    pub(crate) const fn receiving_memory_bytes() -> usize {
        // Fixed native/path/error carriers and the actual result/owner slots.
        std::mem::size_of::<Self>() + 8 * 256 + 2 * FIXED_SNAPSHOT_METADATA_DIRECTORY.len()
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), ()> {
        self.capture_at(Path::new(FIXED_SNAPSHOT_METADATA_DIRECTORY))
    }

    fn capture_at(&mut self, path: &Path) -> Result<(), ()> {
        if self.entered || self.taken || self.closed.is_some() {
            self.closed.get_or_insert(ZfsHelperError::ProcessContract);
            return Err(());
        }
        self.entered = true;
        self.original.capture(path);
        // This independent actual named post does not erase the original
        // error, and its partially acquired descriptor remains on failure.
        self.named.capture(path);
        self.identity = Some(match (self.original.metadata.as_ref(), self.named.metadata.as_ref()) {
            (Some(Ok(before)), Some(Ok(after))) if self.original.positive() && self.named.positive()
                && before.st_dev == after.st_dev && before.st_ino == after.st_ino
                && before.st_mode == after.st_mode && before.st_uid == after.st_uid => Ok(()),
            _ => Err(ZfsHelperError::ProcessContract),
        });
        if self.positive() { Ok(()) } else { Err(()) }
    }

    fn positive(&self) -> bool {
        self.entered && !self.taken && self.closed.is_none()
            && self.original.positive() && self.named.positive()
            && matches!(self.identity, Some(Ok(())))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure().or_else(|| self.named.failure())
            .or_else(|| self.identity.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &dyn std::error::Error))
    }

    pub(crate) fn prepare_backend_once(&mut self) -> Result<SnapshotBackendHandoff<'_>, ()> {
        if !self.positive() { return Err(()); }
        Ok(SnapshotBackendHandoff { original: self })
    }
}

pub(crate) struct SnapshotBackendHandoff<'owner> {
    original: &'owner mut StorageSnapshotMetadataStartupV1,
}

impl SnapshotBackendHandoff<'_> {
    // Every fallible native and independent service post precedes this
    // handoff. Exclusive custody makes the following moves infallible.
    pub(crate) fn complete(self, executor: SystemdZfsExecutor) -> SystemdZfsProcessBackend {
        let directory = match self.original.original.take_validated() {
            Some(directory) => directory,
            None => std::process::abort(),
        };
        self.original.taken = true;
        self.original.completed = Some(SystemdZfsProcessBackend {
            executor,
            snapshot_reads: snapshot_read::SnapshotMetadataReadsV1::default(),
            snapshot_metadata: Some(ProtectedSnapshotMetadataDirectoryV1 { directory }),
        });
        // The actual normal backend is parked before its completed named
        // proof descriptor is positively disposed. No failed prefix can reuse.
        drop(self.original.named.opened.take());
        match self.original.completed.take() {
            Some(backend) => backend,
            None => std::process::abort(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aos-snapshot-prefix-{}-{sequence}", std::process::id(),
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_fixed_prefix_keeps_original_errno_after_name_appears() {
        let directory = TestDirectory::new();
        let path = directory.0.join("later");
        let mut attempt = StorageSnapshotMetadataStartupV1::new();

        assert!(attempt.capture_at(&path).is_err());
        let first = attempt.failure().unwrap()
            .downcast_ref::<rustix::io::Errno>().unwrap() as *const rustix::io::Errno;
        std::fs::create_dir(&path).unwrap();
        assert!(attempt.capture_at(&path).is_err());

        let retained = attempt.failure().unwrap()
            .downcast_ref::<rustix::io::Errno>().unwrap() as *const rustix::io::Errno;
        assert!(std::ptr::eq(first, retained));
        assert!(attempt.prepare_backend_once().is_err());
    }

    #[test]
    fn invalid_directory_keeps_both_native_opens_and_real_metadata_on_refusal() {
        let directory = TestDirectory::new();
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut attempt = StorageSnapshotMetadataStartupV1::new();

        assert!(attempt.capture_at(&directory.0).is_err());

        assert!(matches!(attempt.original.opened, Some(Ok(_))));
        assert!(matches!(attempt.original.metadata, Some(Ok(_))));
        assert!(matches!(attempt.named.opened, Some(Ok(_))));
        assert!(attempt.failure().unwrap().is::<ZfsHelperError>());
        assert!(attempt.prepare_backend_once().is_err());
    }
}
