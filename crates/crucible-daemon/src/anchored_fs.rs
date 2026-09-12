//! Directory-fd anchored filesystem authority.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, open, openat2, renameat_with};
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
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn try_clone(&self) -> Result<File, AnchoredFsError> {
        self.file
            .try_clone()
            .map_err(|source| anchored_io("clone-anchored-file", &self.path, source))
    }

    pub(crate) fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    pub(crate) fn logical_name(&self) -> std::ffi::OsString {
        self.removal_original_name()
            .unwrap_or_else(|| self.name.clone())
    }

    pub(crate) fn removal_original_name(&self) -> Option<std::ffi::OsString> {
        removal_identity(&self.name)
            .filter(|(_, device, inode)| *device == self.device && *inode == self.inode)
            .map(|(name, _, _)| name)
    }

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

    pub(crate) fn truncate(&self, length: u64) -> Result<(), AnchoredFsError> {
        let file = self.open_for_write()?;
        file.set_len(length)
            .and_then(|()| file.sync_all())
            .map_err(|source| anchored_io("truncate-anchored-file", &self.path, source))?;
        self.verify_path_binding()
    }

    pub(crate) fn append_at(&self, offset: u64, bytes: &[u8]) -> Result<(), AnchoredFsError> {
        let final_length = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid_path(&self.path))?;
        let file = self.open_for_write()?;
        file.write_all_at(bytes, offset)
            .and_then(|()| file.set_len(final_length))
            .and_then(|()| file.sync_all())
            .map_err(|source| anchored_io("append-anchored-file", &self.path, source))?;
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

    fn remove_after_validation(&self, operation: &'static str) -> Result<(), AnchoredFsError> {
        self.remove_after_validation_with(operation, || Ok(()), || Ok(()))
    }

    fn remove_after_validation_with(
        &self,
        operation: &'static str,
        after_rename: impl FnOnce() -> Result<(), AnchoredFsError>,
        before_destroy: impl FnOnce() -> Result<(), AnchoredFsError>,
    ) -> Result<(), AnchoredFsError> {
        if removal_identity(&self.name).is_some() {
            if self.removal_original_name().is_none() {
                return Err(AnchoredFsError::DirectoryReplaced {
                    path: self.path.clone(),
                });
            }
            before_destroy()?;
            self.destroy_contents(operation)?;
            return self.verify_path_binding();
        }
        let mut quarantine = std::ffi::OsString::from(".");
        quarantine.push(&self.name);
        quarantine.push(format!(".removing-v1-{:x}-{:x}", self.device, self.inode));
        renameat_with(
            &self.parent,
            &self.name,
            &self.parent,
            &quarantine,
            RenameFlags::NOREPLACE,
        )
        .map_err(|source| self.io_error(operation, source))?;
        self.parent
            .sync_all()
            .map_err(|source| anchored_io("sync-directory", &self.path, source))?;
        after_rename()?;

        let descriptor = openat2(
            &self.parent,
            &quarantine,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error(operation, source))?;
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(|source| anchored_io(operation, &self.path, source))?;
        if !metadata.is_file() || metadata.dev() != self.device || metadata.ino() != self.inode {
            renameat_with(
                &self.parent,
                &quarantine,
                &self.parent,
                &self.name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|source| self.io_error("restore-replaced-file", source))?;
            self.parent
                .sync_all()
                .map_err(|source| anchored_io("sync-directory", &self.path, source))?;
            return Err(AnchoredFsError::DirectoryReplaced {
                path: self.path.clone(),
            });
        }

        before_destroy()?;
        self.destroy_contents(operation)?;
        let descriptor = openat2(
            &self.parent,
            &quarantine,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error(operation, source))?;
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(|source| anchored_io(operation, &self.path, source))?;
        if metadata.is_file() && metadata.dev() == self.device && metadata.ino() == self.inode {
            Ok(())
        } else {
            Err(AnchoredFsError::DirectoryReplaced {
                path: self.path.clone(),
            })
        }
    }

    fn destroy_contents(&self, operation: &'static str) -> Result<(), AnchoredFsError> {
        use std::os::unix::io::AsRawFd;

        // Linux cannot unlink by file descriptor. Zeroing the retained inode
        // makes the destructive effect identity-bound; the authenticated,
        // deterministic quarantine name remains as a bounded tombstone.
        let descriptor = PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
        let file = OpenOptions::new()
            .write(true)
            .open(&descriptor)
            .map_err(|source| anchored_io(operation, &self.path, source))?;
        file.set_len(0)
            .and_then(|()| file.sync_all())
            .map_err(|source| anchored_io(operation, &self.path, source))
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
    pub(crate) fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

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

    pub(crate) fn open_inventory_child(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Self, AnchoredFsError> {
        let child = self.open_child(path, operation)?;
        if path.file_name().is_some_and(|name| {
            removal_identity(name).is_some()
                && !removal_identity(name).is_some_and(|(_, device, inode)| {
                    device == child.device && inode == child.inode
                })
        }) {
            return Err(AnchoredFsError::DirectoryReplaced {
                path: path.to_owned(),
            });
        }
        Ok(child)
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
        let file = File::from(descriptor);
        self.verify_path_binding()?;
        Ok(file)
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

    pub(crate) fn open_or_create_regular(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<AnchoredFile, AnchoredFsError> {
        let (parent, name) = self.open_parent(path, operation)?;
        #[cfg(test)]
        run_anchored_mutation_hook();
        let descriptor = openat2(
            &parent,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error(operation, path, source))?;
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|source| anchored_io(operation, path, source))?;
        if !metadata.is_file() {
            return Err(invalid_path(path));
        }
        self.verify_path_binding()?;
        Ok(AnchoredFile {
            path: path.to_owned(),
            file,
            parent,
            name,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub(crate) fn open_inventory_file(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Option<AnchoredFile>, AnchoredFsError> {
        let authority = self.open_regular_optional(path, operation)?;
        if authority.as_ref().is_some_and(|file| {
            removal_identity(&file.name).is_some() && file.removal_original_name().is_none()
        }) {
            return Err(AnchoredFsError::DirectoryReplaced {
                path: path.to_owned(),
            });
        }
        Ok(authority)
    }

    pub(crate) fn write_once(&self, path: &Path, bytes: &[u8]) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        #[cfg(test)]
        run_anchored_mutation_hook();
        let relative = self.relative(path)?;
        let parent = relative.parent().ok_or(invalid_path(path))?;
        let name = relative.file_name().ok_or(invalid_path(path))?;
        let directory = self.open_directory(parent, "open-write-parent")?;
        let temporary_path = self.write_once_pending_path(path)?;
        let temporary = temporary_path.file_name().ok_or(invalid_path(path))?;
        let descriptor = openat2(
            &directory,
            temporary,
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
            temporary,
            &directory,
            name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|source| self.io_error("publish", path, source))?;
        directory
            .sync_all()
            .map_err(|source| anchored_io("sync-directory", path, source))?;
        self.verify_path_binding()
    }

    pub(crate) fn write_once_pending_path(&self, path: &Path) -> Result<PathBuf, AnchoredFsError> {
        self.relative(path)?;
        let name = path.file_name().ok_or(invalid_path(path))?;
        let mut temporary = std::ffi::OsString::from(".");
        temporary.push(name);
        temporary.push(".pending");
        Ok(path.with_file_name(temporary))
    }

    pub(crate) fn create_file(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<File, AnchoredFsError> {
        self.verify_path_binding()?;
        #[cfg(test)]
        run_anchored_mutation_hook();
        let relative = self.relative(path)?;
        let descriptor = openat2(
            &self.directory,
            relative,
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| self.io_error(operation, path, source))?;
        let file = File::from(descriptor);
        self.verify_path_binding()?;
        Ok(file)
    }

    pub(crate) fn remove_bound_file(
        &self,
        file: &AnchoredFile,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        file.verify_path_binding()?;
        #[cfg(test)]
        run_anchored_mutation_hook();
        file.remove_after_validation(operation)?;
        self.verify_path_binding()
    }

    pub(crate) fn remove_bound_directory(
        &self,
        child: &AnchoredDirectory,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.remove_bound_directory_with(child, operation, || Ok(()))
    }

    fn remove_bound_directory_with(
        &self,
        child: &AnchoredDirectory,
        operation: &'static str,
        after_validation: impl FnOnce() -> Result<(), AnchoredFsError>,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        child.verify_path_binding()?;
        #[cfg(test)]
        run_anchored_mutation_hook();
        let name = child
            .path
            .file_name()
            .ok_or_else(|| invalid_path(&child.path))?
            .to_owned();
        if let Some((_, device, inode)) = removal_identity(&name) {
            if device != child.device || inode != child.inode {
                return Err(AnchoredFsError::DirectoryReplaced {
                    path: child.path.clone(),
                });
            }
            after_validation()?;
            child.verify_path_binding()?;
            return self.verify_path_binding();
        }

        let mut quarantine = std::ffi::OsString::from(".");
        quarantine.push(&name);
        quarantine.push(format!(".removing-v1-{:x}-{:x}", child.device, child.inode));
        let quarantine_path = child.path.with_file_name(&quarantine);
        let quarantined =
            self.rename_bound_directory_with(child, &quarantine_path, operation, || Ok(()))?;
        after_validation()?;
        quarantined.verify_path_binding()?;
        self.verify_path_binding()
    }

    pub(crate) fn rename_bound_directory_with(
        &self,
        child: &AnchoredDirectory,
        destination: &Path,
        operation: &'static str,
        after_validation: impl FnOnce() -> Result<(), AnchoredFsError>,
    ) -> Result<AnchoredDirectory, AnchoredFsError> {
        self.verify_path_binding()?;
        child.verify_path_binding()?;
        after_validation()?;
        self.rename_noreplace(&child.path, destination, operation)?;
        let moved = self.open_inventory_child(destination, operation);
        if moved
            .as_ref()
            .is_ok_and(|guard| guard.identity() == child.identity())
        {
            return moved;
        }

        self.rename_noreplace(destination, &child.path, "restore-substituted-directory")?;
        Err(AnchoredFsError::DirectoryReplaced {
            path: child.path.clone(),
        })
    }

    pub(crate) fn create_directory(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        #[cfg(test)]
        run_anchored_mutation_hook();
        let (directory, name) = self.open_parent(path, operation)?;
        mkdirat(&directory, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|source| self.io_error(operation, path, source))?;
        directory
            .sync_all()
            .map_err(|source| anchored_io("sync-directory", path, source))?;
        self.verify_path_binding()
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
        #[cfg(test)]
        run_anchored_mutation_hook();
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
        self.verify_path_binding()
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

pub(crate) fn removal_original_name(name: &std::ffi::OsStr) -> Option<std::ffi::OsString> {
    removal_identity(name).map(|(name, _, _)| name)
}

fn removal_identity(name: &std::ffi::OsStr) -> Option<(std::ffi::OsString, u64, u64)> {
    const MARKER: &[u8] = b".removing-v1-";
    let bytes = name.as_bytes();
    if bytes.first() != Some(&b'.') {
        return None;
    }
    let marker = bytes
        .windows(MARKER.len())
        .rposition(|part| part == MARKER)?;
    if marker <= 1 {
        return None;
    }
    let identity = &bytes[marker + MARKER.len()..];
    let separator = identity.iter().position(|byte| *byte == b'-')?;
    let device = std::str::from_utf8(&identity[..separator])
        .ok()
        .and_then(|value| u64::from_str_radix(value, 16).ok())?;
    let inode = std::str::from_utf8(&identity[separator + 1..])
        .ok()
        .and_then(|value| u64::from_str_radix(value, 16).ok())?;
    if identity != format!("{device:x}-{inode:x}").as_bytes() {
        return None;
    }
    Some((
        std::ffi::OsString::from_vec(bytes[1..marker].to_vec()),
        device,
        inode,
    ))
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
thread_local! {
    static ANCHORED_MUTATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn install_anchored_mutation_hook(hook: impl FnOnce() + 'static) {
    ANCHORED_MUTATION_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_anchored_mutation_hook() {
    ANCHORED_MUTATION_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn replace_root_after_precheck(root: &Path, moved: &Path) {
        let root = root.to_owned();
        let moved = moved.to_owned();
        install_anchored_mutation_hook(move || {
            fs::rename(&root, &moved).expect("move guarded root");
            fs::create_dir(&root).expect("replace guarded root");
        });
    }

    #[test]
    fn mutations_reject_parent_replacement_after_final_precheck() {
        for operation in ["write", "rename", "file-removal", "directory-removal"] {
            let parent = TempDir::new().expect("parent");
            let moved_parent = TempDir::new().expect("moved parent");
            let moved = moved_parent.path().join("guarded");
            let guard = AnchoredDirectory::new(parent.path().to_owned()).expect("parent guard");
            let source = parent.path().join("source");
            let destination = parent.path().join("destination");

            let result = match operation {
                "write" => {
                    replace_root_after_precheck(parent.path(), &moved);
                    guard.write_once(&destination, b"bytes")
                }
                "rename" => {
                    fs::write(&source, b"bytes").expect("source");
                    replace_root_after_precheck(parent.path(), &moved);
                    guard.rename_noreplace(&source, &destination, "rename")
                }
                "file-removal" => {
                    fs::write(&source, b"bytes").expect("source");
                    let file = guard
                        .open_inventory_file(&source, "pin-source")
                        .expect("open source")
                        .expect("source exists");
                    replace_root_after_precheck(parent.path(), &moved);
                    guard.remove_bound_file(&file, "remove-file")
                }
                "directory-removal" => {
                    fs::create_dir(&source).expect("source directory");
                    let child = guard.open_child(&source, "pin-source").expect("child");
                    replace_root_after_precheck(parent.path(), &moved);
                    guard.remove_bound_directory(&child, "remove-directory")
                }
                _ => unreachable!(),
            };

            assert!(matches!(
                result,
                Err(AnchoredFsError::DirectoryReplaced { .. })
            ));
            assert!(!destination.exists());
        }
    }

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

    #[test]
    fn bound_file_removal_restores_replacement_after_validation_race() {
        let root = TempDir::new().expect("root");
        let path = root.path().join("state");
        let moved = root.path().join("moved");
        fs::write(&path, b"pinned").expect("pinned file");
        let guard = AnchoredDirectory::new(root.path().to_owned()).expect("root guard");
        let pinned = guard
            .open_regular_optional(&path, "pin-state")
            .expect("open state")
            .expect("state exists");
        pinned.verify_path_binding().expect("initial validation");

        fs::rename(&path, &moved).expect("move pinned state after validation");
        fs::write(&path, b"replacement").expect("replacement state");

        assert!(matches!(
            pinned.remove_after_validation("remove-state"),
            Err(AnchoredFsError::DirectoryReplaced { .. })
        ));
        assert_eq!(fs::read(&path).expect("replacement"), b"replacement");
        assert_eq!(fs::read(&moved).expect("pinned"), b"pinned");
    }

    #[test]
    fn interrupted_bound_removal_resumes_and_rejects_forged_identity() {
        for validate_before_retry in [false, true] {
            let root = TempDir::new().expect("root");
            let path = root.path().join("state");
            fs::write(&path, b"pinned").expect("pinned file");
            let guard = AnchoredDirectory::new(root.path().to_owned()).expect("root guard");
            let pinned = guard
                .open_regular_optional(&path, "pin-state")
                .expect("open state")
                .expect("state exists");
            let quarantine = root.path().join(format!(
                ".state.removing-v1-{:x}-{:x}",
                pinned.device, pinned.inode
            ));
            fs::rename(&path, &quarantine).expect("interrupt after quarantine rename");
            let resumed = guard
                .open_inventory_file(&quarantine, "resume-removal")
                .expect("open quarantine")
                .expect("quarantine exists");
            if validate_before_retry {
                resumed.verify_path_binding().expect("validate quarantine");
            }
            guard
                .remove_bound_file(&resumed, "resume-removal")
                .expect("finish removal");
            assert!(!path.exists());
            assert_eq!(
                fs::metadata(&quarantine).expect("removal tombstone").len(),
                0
            );
        }

        let root = TempDir::new().expect("forged root");
        let forged = root.path().join(".state.removing-v1-0-0");
        fs::write(&forged, b"forged").expect("forged quarantine");
        let guard = AnchoredDirectory::new(root.path().to_owned()).expect("root guard");
        assert!(guard.open_inventory_file(&forged, "reject-forged").is_err());
        assert!(forged.exists());
    }

    #[test]
    fn removal_names_reject_noncanonical_hex_aliases() {
        let canonical = std::ffi::OsStr::new(".state.removing-v1-a-10");
        assert_eq!(
            removal_identity(canonical),
            Some((std::ffi::OsString::from("state"), 0xa, 0x10))
        );
        for alias in [
            ".state.removing-v1-A-10",
            ".state.removing-v1-a-010",
            ".state.removing-v1-0a-10",
            ".state.removing-v1-a-10A",
        ] {
            assert_eq!(removal_identity(std::ffi::OsStr::new(alias)), None);
        }
    }

    #[test]
    fn bound_removal_preserves_quarantine_when_restore_name_is_occupied() {
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

        assert!(
            pinned
                .remove_after_validation_with(
                    "remove-state",
                    || {
                        fs::write(&path, b"occupied")
                            .map_err(|source| anchored_io("occupy-restore-name", &path, source))
                    },
                    || Ok(())
                )
                .is_err()
        );
        assert_eq!(fs::read(&path).expect("occupied name"), b"occupied");
        assert_eq!(fs::read(&moved).expect("pinned"), b"pinned");
        assert!(
            fs::read_dir(root.path())
                .expect("root entries")
                .any(|entry| entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .contains(".removing-v1-"))
        );
    }

    #[test]
    fn bound_removal_never_destroys_a_post_validation_substitution() {
        let root = TempDir::new().expect("root");
        let path = root.path().join("state");
        fs::write(&path, b"same bytes").expect("pinned file");
        let guard = AnchoredDirectory::new(root.path().to_owned()).expect("root guard");
        let pinned = guard
            .open_regular_optional(&path, "pin-state")
            .expect("open state")
            .expect("state exists");
        let quarantine = root.path().join(format!(
            ".state.removing-v1-{:x}-{:x}",
            pinned.device, pinned.inode
        ));
        let moved = root.path().join("moved-quarantine");

        assert!(
            pinned
                .remove_after_validation_with(
                    "remove-state",
                    || Ok(()),
                    || {
                        fs::rename(&quarantine, &moved).map_err(|source| {
                            anchored_io("move-validated-quarantine", &quarantine, source)
                        })?;
                        fs::write(&quarantine, b"same bytes").map_err(|source| {
                            anchored_io("replace-validated-quarantine", &quarantine, source)
                        })?;
                        Ok(())
                    },
                )
                .is_err()
        );
        assert_eq!(fs::read(&quarantine).expect("replacement"), b"same bytes");
        assert_eq!(fs::metadata(&moved).expect("destroyed target").len(), 0);

        let child = root.path().join("child");
        fs::create_dir(&child).expect("child");
        let child_guard = guard.open_child(&child, "pin-child").expect("child guard");
        let child_quarantine = root.path().join(format!(
            ".child.removing-v1-{:x}-{:x}",
            child_guard.device, child_guard.inode
        ));
        let moved_child = root.path().join("moved-child-quarantine");
        assert!(
            guard
                .remove_bound_directory_with(&child_guard, "remove-child", || {
                    fs::rename(&child_quarantine, &moved_child).map_err(|source| {
                        anchored_io("move-validated-child-quarantine", &child_quarantine, source)
                    })?;
                    fs::create_dir(&child_quarantine).map_err(|source| {
                        anchored_io(
                            "replace-validated-child-quarantine",
                            &child_quarantine,
                            source,
                        )
                    })?;
                    Ok(())
                })
                .is_err()
        );
        assert!(child_quarantine.is_dir());
        assert!(moved_child.is_dir());
    }
}
