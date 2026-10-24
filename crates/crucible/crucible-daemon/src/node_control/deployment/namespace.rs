//! Retains the funded preparation namespace from creation through real cleanup.
//!
//! This private owner holds original parent/root descriptors. Its path is a
//! diagnostic and fixed leaf name, never a replacement cleanup authority. There
//! are no children or remaining socket writers when cleanup is requested.

use crucible_host_resources::{LinuxDirectoryCleanup, LinuxDirectoryCleanupError};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, mkdirat, open, openat, statat, unlinkat};
use std::{fs, io, os::fd::OwnedFd, path::PathBuf, thread::ThreadId};

// One root plus three peer directories and three socket names. This is the
// actual fixed preparation roster, not permission to traverse operator data.
const CLEANUP_ENTRIES: u64 = 7;

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("funded namespace original changed")]
    Identity,
    #[error("funded namespace I/O refused")]
    Io(#[source] io::Error),
    #[error("funded namespace cleanup refused")]
    Cleanup(#[source] LinuxDirectoryCleanupError),
}

pub(super) struct FundedNamespace {
    path: PathBuf,
    process: u32,
    thread: ThreadId,
    parent: Option<OwnedFd>,
    root: Option<OwnedFd>,
    identity: Option<(u64, u64)>,
    created: bool,
    reclaimed: bool,
    failure: Option<Failure>,
}

impl FundedNamespace {
    pub(super) fn create_into(
        output: &mut Option<Self>,
        path: PathBuf,
    ) -> Result<(PathBuf, (u64, u64)), ()> {
        if output.is_some() {
            return Err(());
        }
        *output = Some(Self::pending(path));
        let owner = output.as_mut().ok_or(())?;
        match owner.create() {
            Ok(()) => Ok((owner.path.clone(), owner.identity.ok_or(())?)),
            Err(error) => {
                owner.record_failure(error);
                Err(())
            }
        }
    }

    fn pending(path: PathBuf) -> Self {
        Self {
            path,
            process: std::process::id(),
            thread: std::thread::current().id(),
            parent: None,
            root: None,
            identity: None,
            created: false,
            reclaimed: false,
            failure: None,
        }
    }

    fn create(&mut self) -> Result<(), Failure> {
        self.create_root_name()?;
        self.open_root()?;
        self.identify_root()
    }

    fn create_root_name(&mut self) -> Result<(), Failure> {
        if !self.path.is_absolute() {
            return Err(Failure::Identity);
        }
        let parent = self.path.parent().ok_or(Failure::Identity)?;
        let name = self.path.file_name().ok_or(Failure::Identity)?;
        // Pin the parent before mkdir. A prefix that has created nothing owns
        // no deletion right over a preexisting same-named directory.
        self.parent = Some(
            open(
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io_failure)?,
        );
        let parent_fd = self.parent.as_ref().ok_or(Failure::Identity)?;
        let metadata = fstat(parent_fd).map_err(io_failure)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_mode & 0o777 != 0o700
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || fs::canonicalize(parent).map_err(Failure::Io)? != parent
        {
            return Err(Failure::Identity);
        }
        mkdirat(parent_fd, name, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(io_failure)?;
        self.created = true;
        Ok(())
    }

    fn open_root(&mut self) -> Result<(), Failure> {
        let parent_fd = self.parent.as_ref().ok_or(Failure::Identity)?;
        let name = self.path.file_name().ok_or(Failure::Identity)?;
        // Retain the actual newly opened root before metadata or child work.
        // Any failure leaves this prefix in the original output owner.
        self.root = Some(
            openat(
                parent_fd,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io_failure)?,
        );
        Ok(())
    }

    fn identify_root(&mut self) -> Result<(), Failure> {
        let root = self.root.as_ref().ok_or(Failure::Identity)?;
        let metadata = fstat(root).map_err(io_failure)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_mode & 0o777 != 0o700
            || metadata.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(Failure::Identity);
        }
        self.identity = Some((metadata.st_dev, metadata.st_ino));
        self.authenticate_name()
    }

    fn authenticate_name(&self) -> Result<(), Failure> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(Failure::Identity);
        }
        let parent = self.parent.as_ref().ok_or(Failure::Identity)?;
        let root = self.root.as_ref().ok_or(Failure::Identity)?;
        let actual = fstat(root).map_err(io_failure)?;
        let named = statat(
            parent,
            self.path.file_name().ok_or(Failure::Identity)?,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io_failure)?;
        if FileType::from_raw_mode(actual.st_mode) != FileType::Directory
            || FileType::from_raw_mode(named.st_mode) != FileType::Directory
            || self.identity != Some((actual.st_dev, actual.st_ino))
            || (named.st_dev, named.st_ino) != (actual.st_dev, actual.st_ino)
        {
            return Err(Failure::Identity);
        }
        Ok(())
    }

    fn record_failure(&mut self, error: Failure) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }

    /// Runs only after the capsule drops its actual Prepared receiver owners.
    pub(super) fn cleanup(&mut self) -> Result<(), ()> {
        let result = self.cleanup_original();
        if let Err(error) = result {
            self.record_failure(error);
            return Err(());
        }
        Ok(())
    }

    fn cleanup_original(&mut self) -> Result<(), Failure> {
        if self.reclaimed {
            return Ok(());
        }
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(Failure::Identity);
        }
        if !self.created {
            self.root.take();
            self.parent.take();
            self.reclaimed = true;
            return Ok(());
        }
        self.authenticate_name()?;
        let root = self.root.as_ref().ok_or(Failure::Identity)?;
        let duplicate = rustix::io::dup(root).map_err(io_failure)?;
        LinuxDirectoryCleanup::new(duplicate, &self.path)
            .clear_contents(CLEANUP_ENTRIES)
            .map_err(Failure::Cleanup)?;
        // Final removal names only the original child under its pinned parent.
        // Excluding writers is the owning capsule's no-child phase invariant.
        self.authenticate_name()?;
        unlinkat(
            self.parent.as_ref().ok_or(Failure::Identity)?,
            self.path.file_name().ok_or(Failure::Identity)?,
            AtFlags::REMOVEDIR,
        )
        .map_err(io_failure)?;
        self.root.take();
        self.parent.take();
        self.reclaimed = true;
        Ok(())
    }

    pub(super) fn known_backing_data(&self) -> Option<usize> {
        let Self {
            path,
            process: _,
            thread: _,
            parent: _,
            root: _,
            identity: _,
            created: _,
            reclaimed: _,
            failure,
        } = self;
        let error_path = match failure {
            Some(Failure::Cleanup(error)) => match error {
                LinuxDirectoryCleanupError::DirectoryIdentity { path }
                | LinuxDirectoryCleanupError::Bound { path, reason: _ }
                | LinuxDirectoryCleanupError::Io {
                    path,
                    operation: _,
                    source: _,
                } => path.capacity(),
            },
            Some(Failure::Identity | Failure::Io(_)) | None => 0,
        };
        // No CString or Vec is retained here; the shared cleanup helper's work
        // bank is temporary. Opaque io/runtime backing stays separately reserved.
        path.capacity().checked_add(error_path)
    }
}

fn io_failure(error: rustix::io::Errno) -> Failure {
    Failure::Io(io::Error::from(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::PermissionsExt, net::UnixDatagram},
        path::Path,
    };

    fn parent() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn original_descriptors_remove_the_actual_fixed_namespace_after_receiver_drop() {
        let parent = parent();
        let path = parent.path().join("prepared");
        let mut output = None;
        let (actual, _) = FundedNamespace::create_into(&mut output, path.clone()).unwrap();
        let mut receivers = Vec::new();
        for index in 0..3 {
            fs::create_dir(actual.join(format!("peer-{index}"))).unwrap();
            receivers
                .push(UnixDatagram::bind(actual.join(format!("effect-{index}.sock"))).unwrap());
        }
        drop(receivers);
        output.as_mut().unwrap().cleanup().unwrap();
        assert!(output.as_ref().unwrap().reclaimed);
        assert!(output.as_ref().unwrap().root.is_none());
        assert!(output.as_ref().unwrap().parent.is_none());
        assert!(!path.exists());
        output.as_mut().unwrap().cleanup().unwrap();
    }

    #[test]
    fn replacement_refuses_without_removing_original_or_impostor_and_can_retry_original() {
        let parent = parent();
        let path = parent.path().join("prepared");
        let original = parent.path().join("retained-original");
        let mut output = None;
        FundedNamespace::create_into(&mut output, path.clone()).unwrap();
        fs::rename(&path, &original).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("operator-data"), b"retained").unwrap();
        let owner = output.as_mut().unwrap();
        assert!(owner.cleanup().is_err());
        assert!(!owner.reclaimed);
        assert!(original.exists());
        assert!(path.join("operator-data").exists());
        fs::remove_file(path.join("operator-data")).unwrap();
        fs::remove_dir(&path).unwrap();
        fs::rename(&original, &path).unwrap();
        owner.cleanup().unwrap();
        assert!(owner.reclaimed);
        assert!(owner.failure.is_some());
        assert!(!path.exists());
    }

    #[test]
    fn failed_create_does_not_delete_a_preexisting_namespace_or_renew_output() {
        let parent = parent();
        let path = parent.path().join("preexisting");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("data"), b"original").unwrap();
        let mut output = None;
        assert!(FundedNamespace::create_into(&mut output, path.clone()).is_err());
        assert!(
            FundedNamespace::create_into(&mut output, parent.path().join("replacement")).is_err()
        );
        let owner = output.as_mut().unwrap();
        assert!(!owner.created);
        owner.cleanup().unwrap();
        assert!(owner.reclaimed);
        assert!(Path::new(&path).join("data").exists());
        assert!(owner.parent.is_none());
        assert!(owner.root.is_none());
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn actual_mkdir_and_open_prefixes_cannot_claim_reclamation_before_identity() {
        let parent = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = parent.path().join("actual-created-prefix");
        let mut owner = FundedNamespace::pending(path.clone());
        // These are the same actual production stages. Stop before each later
        // fallible stage, never manufacture a completed reservation or capsule.
        owner.create_root_name().unwrap();
        assert!(owner.created);
        assert!(owner.parent.is_some());
        assert!(owner.root.is_none());
        assert!(owner.cleanup().is_err());
        assert!(!owner.reclaimed);
        assert!(path.exists());
        owner.open_root().unwrap();
        assert!(owner.root.is_some());
        assert!(owner.identity.is_none());
        assert!(owner.cleanup().is_err());
        assert!(!owner.reclaimed);
        assert!(path.exists());
        owner.identify_root().unwrap();
        owner.cleanup().unwrap();
        assert!(owner.reclaimed);
        assert!(owner.parent.is_none());
        assert!(owner.root.is_none());
        assert!(!path.exists());
    }

    #[test]
    fn actual_cleanup_error_and_original_descriptors_remain_observed_until_retry() {
        let parent = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut output = None;
        let (path, _) =
            FundedNamespace::create_into(&mut output, parent.path().join("original")).unwrap();
        for index in 0..8 {
            fs::create_dir(path.join(format!("unexpected-{index}"))).unwrap();
        }
        let owner = output.as_mut().unwrap();
        assert!(owner.cleanup().is_err());
        assert!(!owner.reclaimed);
        assert!(owner.parent.is_some());
        assert!(owner.root.is_some());
        let diagnostic_capacity = match owner.failure.as_ref().unwrap() {
            Failure::Cleanup(LinuxDirectoryCleanupError::Bound { path, .. }) => path.capacity(),
            other => panic!("unexpected actual cleanup cause: {other:?}"),
        };
        assert_eq!(
            owner.known_backing_data().unwrap(),
            owner.path.capacity() + diagnostic_capacity
        );
        // Directory entries are queued before traversal, so this root scan
        // reaches its bound before removing any child. Avoid depending on
        // filesystem order or on files that a partial scan may already unlink.
        fs::remove_dir(path.join("unexpected-0")).unwrap();
        fs::remove_dir(path.join("unexpected-1")).unwrap();
        owner.cleanup().unwrap();
        assert!(owner.reclaimed);
        assert!(owner.failure.is_some());
        assert!(!path.exists());
    }
}
