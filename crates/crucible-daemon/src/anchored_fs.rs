//! Directory-fd anchored filesystem authority.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, open, openat2, renameat_with,
    unlinkat,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum AnchoredFsError {
    #[error("anchored filesystem path is invalid: {path}")]
    InvalidPath { path: PathBuf },
    #[error("anchored filesystem directory was replaced: {path}")]
    DirectoryReplaced { path: PathBuf },
    #[error("anchored filesystem {operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl AnchoredFsError {
    pub(crate) fn into_io_parts(
        self,
        default_operation: &'static str,
    ) -> (&'static str, PathBuf, std::io::Error) {
        match self {
            Self::InvalidPath { path } => {
                let source = std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "anchored filesystem path is invalid",
                );
                (default_operation, path, source)
            }
            Self::DirectoryReplaced { path } => {
                let source = std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "anchored filesystem directory was replaced",
                );
                (default_operation, path, source)
            }
            Self::Io {
                operation,
                path,
                source,
            } => (operation, path, source),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AnchoredDirectory {
    path: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) struct AnchoredFile {
    path: PathBuf,
    file: File,
    parent: File,
    name: std::ffi::OsString,
    device: u64,
    inode: u64,
}

impl AnchoredFile {
    pub(crate) fn read_bounded(&self, maximum: u64) -> Result<Vec<u8>, AnchoredFsError> {
        let mut file = self
            .file
            .try_clone()
            .map_err(|source| anchored_io("clone-file", &self.path, source))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| anchored_io("seek-file", &self.path, source))?;
        let mut bytes = Vec::new();
        file.take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| anchored_io("read-file", &self.path, source))?;
        if bytes.len() as u64 > maximum {
            return Err(invalid_path(&self.path));
        }
        Ok(bytes)
    }

    pub(crate) fn verify_path_binding(&self) -> Result<(), AnchoredFsError> {
        let descriptor = openat2(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| {
            anchored_io(
                "reopen-anchored-file",
                &self.path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(|source| anchored_io("inspect-anchored-file", &self.path, source))?;
        if metadata.is_file() && metadata.dev() == self.device && metadata.ino() == self.inode {
            Ok(())
        } else {
            Err(AnchoredFsError::DirectoryReplaced {
                path: self.path.clone(),
            })
        }
    }

    pub(crate) fn write_byte(&self, offset: u64, value: u8) -> Result<(), AnchoredFsError> {
        let file = self.open_for_write()?;
        file.write_all_at(&[value], offset)
            .and_then(|()| file.sync_all())
            .map_err(|source| anchored_io("write-anchored-file", &self.path, source))?;
        self.verify_path_binding()
    }

    pub(crate) fn replace_contents(&self, bytes: &[u8]) -> Result<(), AnchoredFsError> {
        let file = self.open_for_write()?;
        file.set_len(0)
            .and_then(|()| file.write_all_at(bytes, 0))
            .and_then(|()| file.sync_all())
            .map_err(|source| anchored_io("replace-anchored-file", &self.path, source))?;
        self.verify_path_binding()
    }

    fn open_for_write(&self) -> Result<File, AnchoredFsError> {
        self.verify_path_binding()?;
        let descriptor = openat2(
            &self.parent,
            &self.name,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error("open-anchored-file-for-write", source))?;
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|source| anchored_io("inspect-anchored-file", &self.path, source))?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(AnchoredFsError::DirectoryReplaced {
                path: self.path.clone(),
            });
        }
        Ok(file)
    }

    fn io_error(&self, operation: &'static str, source: rustix::io::Errno) -> AnchoredFsError {
        anchored_io(
            operation,
            &self.path,
            std::io::Error::from_raw_os_error(source.raw_os_error()),
        )
    }
}

impl AnchoredDirectory {
    pub(crate) fn new(path: PathBuf) -> Result<Self, AnchoredFsError> {
        let descriptor = open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(|source| {
            anchored_io(
                "open-guarded-directory",
                &path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        let directory = File::from(descriptor);
        let metadata = directory
            .metadata()
            .map_err(|source| anchored_io("inspect-guarded-directory", &path, source))?;
        if !metadata.file_type().is_dir() {
            return Err(invalid_path(&path));
        }
        Ok(Self {
            path,
            directory,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn anchored_path(&self) -> PathBuf {
        use std::os::unix::io::AsRawFd;

        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    pub(crate) fn anchored_path_for(&self, path: &Path) -> Result<PathBuf, AnchoredFsError> {
        Ok(self.anchored_path().join(self.relative(path)?))
    }

    pub(crate) fn sync(&self) -> Result<(), AnchoredFsError> {
        self.directory
            .sync_all()
            .map_err(|source| anchored_io("sync-directory", &self.path, source))
    }

    pub(crate) fn open_child(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Self, AnchoredFsError> {
        let directory = self.open_directory(path, operation)?;
        let metadata = directory
            .metadata()
            .map_err(|source| anchored_io(operation, path, source))?;
        Ok(Self {
            path: path.to_owned(),
            directory,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn open_directory(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<File, AnchoredFsError> {
        let relative = self.relative(path)?;
        if relative.as_os_str().is_empty() || relative == Path::new(".") {
            return self
                .directory
                .try_clone()
                .map_err(|source| anchored_io(operation, path, source));
        }
        let descriptor = openat2(
            &self.directory,
            relative,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error(operation, path, source))?;
        Ok(File::from(descriptor))
    }

    pub(crate) fn open_regular_optional(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Option<AnchoredFile>, AnchoredFsError> {
        let (parent, name) = self.open_parent(path, operation)?;
        let descriptor = match openat2(
            &parent,
            &name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(descriptor) => descriptor,
            Err(source) if source == rustix::io::Errno::NOENT => return Ok(None),
            Err(source) => return Err(self.io_error(operation, path, source)),
        };
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|source| anchored_io(operation, path, source))?;
        if !metadata.is_file() {
            return Err(invalid_path(path));
        }
        Ok(Some(AnchoredFile {
            path: path.to_owned(),
            file,
            parent,
            name,
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }

    pub(crate) fn write_once(&self, path: &Path, bytes: &[u8]) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        let relative = self.relative(path)?;
        let parent = relative.parent().ok_or(invalid_path(path))?;
        let name = relative.file_name().ok_or(invalid_path(path))?;
        let directory = self.open_directory(parent, "open-write-parent")?;
        let temporary = format!(".{}.pending", name.to_string_lossy());
        let descriptor = openat2(
            &directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error("create-temporary", path, source))?;
        let mut file = File::from(descriptor);
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| anchored_io("write-temporary", path, source))?;
        renameat_with(
            &directory,
            temporary.as_str(),
            &directory,
            name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|source| self.io_error("publish", path, source))?;
        directory
            .sync_all()
            .map_err(|source| anchored_io("sync-directory", path, source))
    }

    pub(crate) fn create_file(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<File, AnchoredFsError> {
        self.verify_path_binding()?;
        let relative = self.relative(path)?;
        let descriptor = openat2(
            &self.directory,
            relative,
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error(operation, path, source))?;
        Ok(File::from(descriptor))
    }

    pub(crate) fn remove_file(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.unlink(path, operation, AtFlags::empty(), false)
            .map(|_| ())
    }

    pub(crate) fn remove_bound_file(
        &self,
        file: &AnchoredFile,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        file.verify_path_binding()?;
        self.remove_file(&file.path, operation)
    }

    pub(crate) fn remove_file_if_present(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.unlink(path, operation, AtFlags::empty(), true)
            .map(|_| ())
    }

    pub(crate) fn remove_directory_if_present(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<bool, AnchoredFsError> {
        self.unlink(path, operation, AtFlags::REMOVEDIR, true)
    }

    fn unlink(
        &self,
        path: &Path,
        operation: &'static str,
        flags: AtFlags,
        missing_ok: bool,
    ) -> Result<bool, AnchoredFsError> {
        self.verify_path_binding()?;
        let (directory, name) = self.open_parent(path, operation)?;
        match unlinkat(&directory, &name, flags) {
            Ok(()) => {
                directory
                    .sync_all()
                    .map_err(|source| anchored_io("sync-directory", path, source))?;
                Ok(true)
            }
            Err(source) if missing_ok && source == rustix::io::Errno::NOENT => Ok(false),
            Err(source) => Err(self.io_error(operation, path, source)),
        }
    }

    pub(crate) fn create_directory(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        let (directory, name) = self.open_parent(path, operation)?;
        mkdirat(&directory, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|source| self.io_error(operation, path, source))?;
        directory
            .sync_all()
            .map_err(|source| anchored_io("sync-directory", path, source))
    }

    pub(crate) fn rename_noreplace(
        &self,
        source: &Path,
        destination: &Path,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.rename(source, destination, RenameFlags::NOREPLACE, operation)
    }

    fn rename(
        &self,
        source: &Path,
        destination: &Path,
        flags: RenameFlags,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        let source_relative = self.relative(source)?;
        let destination_relative = self.relative(destination)?;
        let source_parent = source_relative.parent().ok_or(invalid_path(source))?;
        let destination_parent = destination_relative
            .parent()
            .ok_or(invalid_path(destination))?;
        let source_directory = self.open_directory(source_parent, operation)?;
        let destination_directory = if source_parent == destination_parent {
            source_directory
                .try_clone()
                .map_err(|source| anchored_io("clone-rename-directory", destination, source))?
        } else {
            self.open_directory(destination_parent, operation)?
        };
        renameat_with(
            &source_directory,
            source_relative.file_name().ok_or(invalid_path(source))?,
            &destination_directory,
            destination_relative
                .file_name()
                .ok_or(invalid_path(destination))?,
            flags,
        )
        .map_err(|source| self.io_error(operation, destination, source))?;
        source_directory
            .sync_all()
            .map_err(|error| anchored_io("sync-directory", source, error))?;
        if source_parent != destination_parent {
            destination_directory
                .sync_all()
                .map_err(|source| anchored_io("sync-directory", destination, source))?;
        }
        Ok(())
    }

    fn open_parent(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(File, std::ffi::OsString), AnchoredFsError> {
        let relative = self.relative(path)?;
        let parent = relative.parent().ok_or(invalid_path(path))?;
        let name = relative.file_name().ok_or(invalid_path(path))?.to_owned();
        Ok((self.open_directory(parent, operation)?, name))
    }

    fn relative<'a>(&self, path: &'a Path) -> Result<&'a Path, AnchoredFsError> {
        if path.is_relative() {
            return Ok(path);
        }
        path.strip_prefix(self.anchored_path())
            .or_else(|_| path.strip_prefix(&self.path))
            .map_err(|_| AnchoredFsError::DirectoryReplaced {
                path: self.path.clone(),
            })
    }

    fn io_error(
        &self,
        operation: &'static str,
        path: &Path,
        source: rustix::io::Errno,
    ) -> AnchoredFsError {
        anchored_io(
            operation,
            path,
            std::io::Error::from_raw_os_error(source.raw_os_error()),
        )
    }

    pub(crate) fn verify_path_binding(&self) -> Result<(), AnchoredFsError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(AnchoredFsError::DirectoryReplaced {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                return Err(anchored_io(
                    "revalidate-guarded-directory",
                    &self.path,
                    source,
                ));
            }
        };
        if metadata.file_type().is_dir()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            Ok(())
        } else {
            Err(AnchoredFsError::DirectoryReplaced {
                path: self.path.clone(),
            })
        }
    }
}

fn invalid_path(path: &Path) -> AnchoredFsError {
    AnchoredFsError::InvalidPath {
        path: path.to_owned(),
    }
}

fn anchored_io(operation: &'static str, path: &Path, source: std::io::Error) -> AnchoredFsError {
    AnchoredFsError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn pinned_child_rejects_replacement_before_mutation() {
        let parent = TempDir::new().expect("parent");
        let child = parent.path().join("child");
        let moved = parent.path().join("moved");
        fs::create_dir(&child).expect("child");
        let parent_guard = AnchoredDirectory::new(parent.path().to_owned()).expect("parent guard");
        let child_guard = parent_guard
            .open_child(&child, "open-child")
            .expect("child guard");

        fs::rename(&child, &moved).expect("move child");
        fs::create_dir(&child).expect("replacement child");

        assert!(matches!(
            child_guard.write_once(&child.join("state"), b"state"),
            Err(AnchoredFsError::DirectoryReplaced { .. })
        ));
        assert!(!child.join("state").exists());
        assert!(!moved.join("state").exists());
    }

    #[test]
    fn pinned_file_rejects_replacement_before_overwrite_or_removal() {
        let root = TempDir::new().expect("root");
        let path = root.path().join("state");
        let moved = root.path().join("moved");
        fs::write(&path, b"pinned").expect("pinned file");
        let guard = AnchoredDirectory::new(root.path().to_owned()).expect("root guard");
        let pinned = guard
            .open_regular_optional(&path, "pin-state")
            .expect("open state")
            .expect("state exists");
        fs::rename(&path, &moved).expect("move pinned state");
        fs::write(&path, b"replacement").expect("replacement state");

        assert!(pinned.replace_contents(b"current").is_err());
        assert!(guard.remove_bound_file(&pinned, "remove-state").is_err());
        assert_eq!(fs::read(&path).expect("replacement"), b"replacement");
        assert_eq!(fs::read(&moved).expect("pinned"), b"pinned");
    }
}
