//! Retained private SQLite-file custody under an explicit existing directory.
//!
//! SQLite opens an absolute ordinary pathname after descriptor admission. The
//! same owner must retain custody of the private directory: identity checks do
//! not eliminate a same-owner pathname replacement/ABA between checks and VFS
//! access. There is no source-file, Hub-key or provider-namespace adoption here.

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{AtFlags, Mode, OFlags};

use crate::direct_upload::DirectClientError;

#[derive(Clone)]
pub(super) struct PrivateFile {
    parent: Arc<File>,
    file: Arc<File>,
    name: String,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PrivateFile {
    pub(super) fn admit(path: &Path, create: bool) -> Result<Self, DirectClientError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(DirectClientError::Checkpoint);
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && name.len() <= 128)
            .ok_or(DirectClientError::Checkpoint)?
            .to_owned();
        let parent_path = path.parent().ok_or(DirectClientError::Checkpoint)?;
        let parent = File::from(
            rustix::fs::open(
                parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DirectClientError::Checkpoint)?,
        );
        let metadata = parent
            .metadata()
            .map_err(|_| DirectClientError::Checkpoint)?;
        let uid = rustix::process::geteuid().as_raw();
        if uid == 65534
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o700
            || !metadata.is_dir()
        {
            return Err(DirectClientError::Checkpoint);
        }
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if create {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let file = File::from(
            rustix::fs::openat(&parent, &name, flags, Mode::RUSR | Mode::WUSR)
                .map_err(|_| DirectClientError::Checkpoint)?,
        );
        let metadata = file.metadata().map_err(|_| DirectClientError::Checkpoint)?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(DirectClientError::Checkpoint);
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| DirectClientError::Checkpoint)?;
        let result = Self {
            parent: Arc::new(parent),
            file: Arc::new(file),
            name,
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        result.verify()?;
        Ok(result)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn verify(&self) -> Result<(), DirectClientError> {
        let uid = rustix::process::geteuid().as_raw();
        let named_parent = rustix::fs::statat(
            rustix::fs::CWD,
            self.path.parent().ok_or(DirectClientError::Checkpoint)?,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| DirectClientError::Checkpoint)?;
        let parent = self
            .parent
            .metadata()
            .map_err(|_| DirectClientError::Checkpoint)?;
        let file = self
            .file
            .metadata()
            .map_err(|_| DirectClientError::Checkpoint)?;
        let named = rustix::fs::statat(&*self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DirectClientError::Checkpoint)?;
        if named_parent.st_dev != parent.dev()
            || named_parent.st_ino != parent.ino()
            || named_parent.st_mode & 0o170000 != 0o040000
            || uid == 65534
            || parent.uid() != uid
            || parent.mode() & 0o7777 != 0o700
            || file.uid() != uid
            || file.mode() & 0o7777 != 0o600
            || file.nlink() != 1
            || file.dev() != self.device
            || file.ino() != self.inode
            || named.st_dev != self.device
            || named.st_ino != self.inode
            || named.st_uid != uid
            || named.st_mode & 0o7777 != 0o600
            || named.st_nlink != 1
            || named.st_mode & 0o170000 != 0o100000
        {
            return Err(DirectClientError::Checkpoint);
        }
        for suffix in ["-journal", "-wal", "-shm"] {
            match rustix::fs::statat(
                &*self.parent,
                format!("{}{suffix}", self.name),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(rustix::io::Errno::NOENT) => {}
                Ok(sidecar)
                    if suffix == "-journal"
                        && sidecar.st_mode & 0o170000 == 0o100000
                        && sidecar.st_uid == uid
                        && sidecar.st_mode & 0o7777 == 0o600
                        && sidecar.st_nlink == 1
                        && sidecar.st_size >= 0
                        && sidecar.st_size <= 20 * 1024 * 1024 => {}
                _ => return Err(DirectClientError::Checkpoint),
            }
        }
        Ok(())
    }

    pub(super) fn sync_creation(&self) -> Result<(), DirectClientError> {
        self.file
            .sync_all()
            .map_err(|_| DirectClientError::Checkpoint)?;
        self.parent
            .sync_all()
            .map_err(|_| DirectClientError::Checkpoint)
    }
}

/// Creates a local private journal directory without following path links.
///
/// Existing ancestors must belong to the caller or root and not be writable by
/// others, except a root-owned sticky directory such as `/tmp`. The final
/// directory must belong to the caller with mode0700. Same-owner pathname
/// custody remains necessary after admission, as documented by the journal.
///
/// # Errors
/// Refuses relative/dotdot paths, symlinks, foreign/writable custody, nonprivate
/// existing final directories or directory creation/durability failure.
pub fn ensure_private_checkpoint_directory(path: &Path) -> Result<(), DirectClientError> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(DirectClientError::Checkpoint);
    }
    let uid = rustix::process::geteuid().as_raw();
    if uid == 65534 {
        return Err(DirectClientError::Checkpoint);
    }
    let mut current = File::from(
        rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DirectClientError::Checkpoint)?,
    );
    let mut components = path
        .components()
        .filter_map(|component| {
            if let Component::Normal(value) = component {
                Some(value)
            } else {
                None
            }
        })
        .peekable();
    while let Some(component) = components.next() {
        let metadata = current
            .metadata()
            .map_err(|_| DirectClientError::Checkpoint)?;
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if ![uid, 0].contains(&metadata.uid()) || (metadata.mode() & 0o022 != 0 && !sticky_root) {
            return Err(DirectClientError::Checkpoint);
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let descriptor = match rustix::fs::openat(&current, component, flags, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => {
                match rustix::fs::mkdirat(&current, component, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(DirectClientError::Checkpoint),
                }
                let descriptor = rustix::fs::openat(&current, component, flags, Mode::empty())
                    .map_err(|_| DirectClientError::Checkpoint)?;
                current
                    .sync_all()
                    .map_err(|_| DirectClientError::Checkpoint)?;
                descriptor
            }
            Err(_) => return Err(DirectClientError::Checkpoint),
        };
        current = File::from(descriptor);
        if components.peek().is_none() {
            let metadata = current
                .metadata()
                .map_err(|_| DirectClientError::Checkpoint)?;
            if metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
                return Err(DirectClientError::Checkpoint);
            }
            current
                .sync_all()
                .map_err(|_| DirectClientError::Checkpoint)?;
            return Ok(());
        }
    }
    Err(DirectClientError::Checkpoint)
}
