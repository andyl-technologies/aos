//! Descriptor-bound filesystem access for daemon-owned state directories.
//!
//! An authority keeps the opened directory inode alive and resolves every
//! descendant without following symbolic links. Mutating callers also verify
//! that the configured pathname still names the opened inode, so replacing a
//! state root or lock file fences the old daemon instead of creating a second
//! writer.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    AtFlags, Mode, OFlags, RawDir, RenameFlags, ResolveFlags, linkat, mkdirat, open, openat2,
    renameat_with, unlinkat,
};
use thiserror::Error;

/// Failure to resolve or revalidate descriptor-bound filesystem authority.
#[derive(Debug, Error)]
pub(crate) enum AnchoredFsError {
    /// A requested path was outside the authority or otherwise ambiguous.
    #[error("anchored filesystem path is invalid: {path}")]
    InvalidPath {
        /// Rejected path.
        path: PathBuf,
    },
    /// The configured name no longer identifies the opened object.
    #[error("anchored filesystem object was replaced: {path}")]
    Replaced {
        /// Configured path whose identity changed.
        path: PathBuf,
    },
    /// A filesystem operation failed.
    #[error("anchored filesystem {operation} failed for {path}: {source}")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Underlying operating-system failure.
        #[source]
        source: std::io::Error,
    },
}

impl AnchoredFsError {
    /// Converts the failure into stable I/O reporting fields.
    pub(crate) fn into_io_parts(
        self,
        caller_operation: &'static str,
    ) -> (&'static str, PathBuf, std::io::Error) {
        match self {
            Self::InvalidPath { path } => (
                caller_operation,
                path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path is outside descriptor-bound authority",
                ),
            ),
            Self::Replaced { path } => (
                caller_operation,
                path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "configured path no longer identifies the opened object",
                ),
            ),
            Self::Io {
                operation,
                path,
                source,
            } => (operation, path, source),
        }
    }
}

/// An opened regular file whose parent and name remain authenticated.
#[derive(Debug)]
pub(crate) struct AnchoredFile {
    path: PathBuf,
    file: File,
    parent: File,
    name: OsString,
    anchor: File,
    anchor_path: PathBuf,
    anchor_relative: PathBuf,
    anchor_device: u64,
    anchor_inode: u64,
    device: u64,
    inode: u64,
}

impl AnchoredFile {
    /// Returns the device and inode captured when the file was opened.
    pub(crate) const fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Returns the configured path used to open the file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Clones the retained file description.
    pub(crate) fn try_clone(&self) -> Result<File, AnchoredFsError> {
        self.file
            .try_clone()
            .map_err(|source| io_error("clone-file", &self.path, source))
    }

    /// Returns the length of the retained file inode.
    pub(crate) fn length(&self) -> Result<u64, AnchoredFsError> {
        self.file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| io_error("inspect-file", &self.path, source))
    }

    /// Reads at most `limit` bytes from the retained file inode.
    pub(crate) fn read_bounded(&self, limit: u64) -> Result<Vec<u8>, AnchoredFsError> {
        let mut bytes = Vec::new();
        self.try_clone()?
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read-file", &self.path, source))?;
        Ok(bytes)
    }

    /// Writes and syncs the retained file inode.
    pub(crate) fn write_all_sync(&self, bytes: &[u8]) -> Result<(), AnchoredFsError> {
        let mut file = self.try_clone()?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error("write-file", &self.path, source))
    }

    /// Verifies that the root-relative name still selects this inode.
    pub(crate) fn verify_path_binding(&self) -> Result<(), AnchoredFsError> {
        verify_root_binding(
            &self.anchor,
            &self.anchor_path,
            self.anchor_device,
            self.anchor_inode,
        )?;
        let descriptor = openat2(
            &self.anchor,
            &self.anchor_relative,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| errno_error("reopen-file", &self.path, source))?;
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(|source| io_error("inspect-file", &self.path, source))?;

        if metadata.is_file() && metadata.dev() == self.device && metadata.ino() == self.inode {
            Ok(())
        } else {
            Err(AnchoredFsError::Replaced {
                path: self.path.clone(),
            })
        }
    }

    fn remove(&self, operation: &'static str) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        unlinkat(&self.parent, &self.name, AtFlags::empty())
            .map_err(|source| errno_error(operation, &self.path, source))?;
        self.parent
            .sync_all()
            .map_err(|source| io_error("sync-parent", &self.path, source))
    }
}

/// An opened directory inode that bounds all descendant resolution.
#[derive(Debug)]
pub(crate) struct AnchoredDirectory {
    path: PathBuf,
    directory: File,
    anchor: File,
    anchor_path: PathBuf,
    anchor_relative: PathBuf,
    anchor_device: u64,
    anchor_inode: u64,
    device: u64,
    inode: u64,
}

impl AnchoredDirectory {
    /// Returns the device and inode captured when the directory was opened.
    pub(crate) const fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Opens an existing ordinary directory without following its final name.
    pub(crate) fn open(path: PathBuf) -> Result<Self, AnchoredFsError> {
        let descriptor = open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(|source| errno_error("open-directory", &path, source))?;
        let directory = File::from(descriptor);
        let metadata = directory
            .metadata()
            .map_err(|source| io_error("inspect-directory", &path, source))?;
        if !metadata.is_dir() {
            return Err(AnchoredFsError::InvalidPath { path });
        }

        let anchor = directory
            .try_clone()
            .map_err(|source| io_error("clone-directory", &path, source))?;
        Ok(Self {
            anchor,
            anchor_path: path.clone(),
            anchor_relative: PathBuf::new(),
            path,
            directory,
            anchor_device: metadata.dev(),
            anchor_inode: metadata.ino(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Returns the configured path represented by this authority.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Syncs the retained directory inode.
    pub(crate) fn sync(&self) -> Result<(), AnchoredFsError> {
        self.directory
            .sync_all()
            .map_err(|source| io_error("sync-directory", &self.path, source))
    }

    /// Verifies that the configured path still selects the retained inode.
    pub(crate) fn verify_path_binding(&self) -> Result<(), AnchoredFsError> {
        verify_root_binding(
            &self.anchor,
            &self.anchor_path,
            self.anchor_device,
            self.anchor_inode,
        )?;
        if self.anchor_relative.as_os_str().is_empty() {
            return Ok(());
        }
        let descriptor = openat2(
            &self.anchor,
            &self.anchor_relative,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| errno_error("revalidate-directory", &self.path, source))?;
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(|source| io_error("inspect-directory", &self.path, source))?;
        if metadata.dev() == self.device && metadata.ino() == self.inode {
            Ok(())
        } else {
            Err(AnchoredFsError::Replaced {
                path: self.path.clone(),
            })
        }
    }

    /// Opens one descendant directory beneath this authority.
    pub(crate) fn open_directory(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Self, AnchoredFsError> {
        let relative = self.relative(path)?;
        let anchor_relative = self.anchor_relative.join(relative);
        let directory = if relative.as_os_str().is_empty() || relative == Path::new(".") {
            self.directory
                .try_clone()
                .map_err(|source| io_error(operation, path, source))?
        } else {
            let descriptor = openat2(
                &self.directory,
                relative,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|source| errno_error(operation, path, source))?;
            File::from(descriptor)
        };
        let metadata = directory
            .metadata()
            .map_err(|source| io_error(operation, path, source))?;
        self.verify_path_binding()?;
        let anchor = self
            .anchor
            .try_clone()
            .map_err(|source| io_error("clone-directory-anchor", path, source))?;

        let opened = Self {
            anchor,
            anchor_path: self.anchor_path.clone(),
            anchor_relative,
            path: path.to_owned(),
            directory,
            anchor_device: self.anchor_device,
            anchor_inode: self.anchor_inode,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        opened.verify_path_binding()?;
        Ok(opened)
    }

    /// Opens one optional descendant directory without following symbolic links.
    pub(crate) fn open_directory_optional(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Option<Self>, AnchoredFsError> {
        match self.open_directory(path, operation) {
            Ok(directory) => Ok(Some(directory)),
            Err(AnchoredFsError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(source) => Err(source),
        }
    }

    /// Lists a bounded number of names from the retained directory inode.
    pub(crate) fn entry_names(
        &self,
        maximum: usize,
        operation: &'static str,
    ) -> Result<Vec<OsString>, AnchoredFsError> {
        self.verify_path_binding()?;
        let descriptor = openat2(
            &self.directory,
            Path::new("."),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| errno_error(operation, &self.path, source))?;
        let mut buffer = Vec::<u8>::with_capacity(64 * 1024);
        let mut entries = RawDir::new(descriptor, buffer.spare_capacity_mut());
        let mut names = Vec::new();
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|source| errno_error(operation, &self.path, source))?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if names.len() == maximum {
                return Err(AnchoredFsError::InvalidPath {
                    path: self.path.clone(),
                });
            }
            names.push(OsString::from_vec(bytes.to_vec()));
        }
        self.verify_path_binding()?;
        Ok(names)
    }

    /// Opens an existing regular descendant without following symbolic links.
    pub(crate) fn open_regular_optional(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Option<AnchoredFile>, AnchoredFsError> {
        self.verify_path_binding()?;
        let (parent, name) = match self.open_parent(path, operation) {
            Ok(parent) => parent,
            Err(AnchoredFsError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                self.verify_path_binding()?;
                return Ok(None);
            }
            Err(source) => return Err(source),
        };
        let descriptor = match openat2(
            &parent,
            &name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => {
                self.verify_path_binding()?;
                return Ok(None);
            }
            Err(source) => return Err(errno_error(operation, path, source)),
        };
        let file = self.finish_file_open(path, parent, name, File::from(descriptor))?;
        self.verify_path_binding()?;
        Ok(Some(file))
    }

    /// Opens or creates one regular descendant without following symlinks.
    pub(crate) fn open_or_create_regular(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<AnchoredFile, AnchoredFsError> {
        let (parent, name) = self.open_parent(path, operation)?;
        let descriptor = openat2(
            &parent,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| errno_error(operation, path, source))?;
        let file = self.finish_file_open(path, parent, name, File::from(descriptor))?;
        self.verify_path_binding()?;
        Ok(file)
    }

    /// Creates one new regular descendant without following symbolic links.
    pub(crate) fn create_new_regular(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<AnchoredFile, AnchoredFsError> {
        let (parent, name) = self.open_parent(path, operation)?;
        let descriptor = openat2(
            &parent,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|source| errno_error(operation, path, source))?;
        let file = self.finish_file_open(path, parent, name, File::from(descriptor))?;
        self.verify_path_binding()?;
        Ok(file)
    }

    /// Creates or opens one descendant directory beneath retained parents.
    pub(crate) fn ensure_directory(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Self, AnchoredFsError> {
        if let Some(directory) = self.open_directory_optional(path, operation)? {
            return Ok(directory);
        }

        let parent_path = path.parent().ok_or_else(|| AnchoredFsError::InvalidPath {
            path: path.to_owned(),
        })?;
        let parent = if self.relative(parent_path)?.as_os_str().is_empty() {
            self.open_directory(self.path(), operation)?
        } else {
            self.ensure_directory(parent_path, operation)?
        };
        let name = path
            .file_name()
            .ok_or_else(|| AnchoredFsError::InvalidPath {
                path: path.to_owned(),
            })?;
        match mkdirat(
            &parent.directory,
            name,
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        ) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(source) => return Err(errno_error(operation, path, source)),
        }
        parent.sync()?;
        let directory = self.open_directory(path, operation)?;
        self.verify_path_binding()?;
        Ok(directory)
    }

    /// Creates one new descendant directory beneath a retained parent.
    pub(crate) fn create_new_directory(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Self, AnchoredFsError> {
        self.verify_path_binding()?;
        let (parent, name) = self.open_parent(path, operation)?;
        mkdirat(&parent, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|source| errno_error(operation, path, source))?;
        parent
            .sync_all()
            .map_err(|source| io_error("sync-parent", path, source))?;
        let directory = self.open_directory(path, operation)?;
        self.verify_path_binding()?;
        Ok(directory)
    }

    /// Creates a hard link to an authenticated file without replacing a name.
    pub(crate) fn link_file_noreplace(
        &self,
        source: &AnchoredFile,
        destination: &Path,
        operation: &'static str,
    ) -> Result<bool, AnchoredFsError> {
        let source = self.reopen_file_identity(source, operation)?;
        let (destination_parent, destination_name) = self.open_parent(destination, operation)?;
        match linkat(
            &source.parent,
            &source.name,
            &destination_parent,
            &destination_name,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => return Ok(false),
            Err(source) => return Err(errno_error(operation, destination, source)),
        }
        let linked = self
            .open_regular_optional(destination, operation)?
            .ok_or_else(|| AnchoredFsError::Replaced {
                path: destination.to_owned(),
            })?;
        if linked.identity() != source.identity() {
            return Err(AnchoredFsError::Replaced {
                path: destination.to_owned(),
            });
        }
        destination_parent
            .sync_all()
            .map_err(|source| io_error("sync-parent", destination, source))?;
        self.verify_path_binding()?;
        Ok(true)
    }

    /// Atomically renames an authenticated file within this authority.
    pub(crate) fn rename_file(
        &self,
        source: &AnchoredFile,
        destination: &Path,
        no_replace: bool,
        operation: &'static str,
    ) -> Result<AnchoredFile, AnchoredFsError> {
        let source = self.reopen_file_identity(source, operation)?;
        let (destination_parent, destination_name) = self.open_parent(destination, operation)?;
        let flags = if no_replace {
            RenameFlags::NOREPLACE
        } else {
            RenameFlags::empty()
        };
        renameat_with(
            &source.parent,
            &source.name,
            &destination_parent,
            &destination_name,
            flags,
        )
        .map_err(|source| errno_error(operation, destination, source))?;
        let renamed = self
            .open_regular_optional(destination, operation)?
            .ok_or_else(|| AnchoredFsError::Replaced {
                path: destination.to_owned(),
            })?;
        if renamed.identity() != source.identity() {
            return Err(AnchoredFsError::Replaced {
                path: destination.to_owned(),
            });
        }
        destination_parent
            .sync_all()
            .map_err(|source| io_error("sync-parent", destination, source))?;
        self.verify_path_binding()?;
        Ok(renamed)
    }

    /// Atomically renames an authenticated directory within this authority.
    pub(crate) fn rename_directory(
        &self,
        source: &AnchoredDirectory,
        destination: &Path,
        no_replace: bool,
        operation: &'static str,
    ) -> Result<AnchoredDirectory, AnchoredFsError> {
        let source = self.reopen_directory_identity(source, operation)?;
        let (source_parent, source_name) = self.open_parent(source.path(), operation)?;
        let (destination_parent, destination_name) = self.open_parent(destination, operation)?;
        let flags = if no_replace {
            RenameFlags::NOREPLACE
        } else {
            RenameFlags::empty()
        };
        renameat_with(
            &source_parent,
            &source_name,
            &destination_parent,
            &destination_name,
            flags,
        )
        .map_err(|source| errno_error(operation, destination, source))?;
        let renamed = self.open_directory(destination, operation)?;
        if renamed.identity() != source.identity() {
            return Err(AnchoredFsError::Replaced {
                path: destination.to_owned(),
            });
        }
        destination_parent
            .sync_all()
            .map_err(|source| io_error("sync-parent", destination, source))?;
        self.verify_path_binding()?;
        Ok(renamed)
    }

    /// Removes an authenticated regular child from this directory.
    pub(crate) fn remove_file(
        &self,
        file: &AnchoredFile,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        let current = self.reopen_file_identity(file, operation)?;
        current.remove(operation)?;
        self.verify_path_binding()
    }

    /// Removes one optional regular descendant through its retained parent.
    pub(crate) fn remove_regular_optional(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<bool, AnchoredFsError> {
        let Some(file) = self.open_regular_optional(path, operation)? else {
            return Ok(false);
        };
        self.remove_file(&file, operation)?;
        Ok(true)
    }

    /// Removes an authenticated empty child directory.
    pub(crate) fn remove_directory(
        &self,
        child: &AnchoredDirectory,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        let current = self.reopen_directory_identity(child, operation)?;
        let (parent, name) = self.open_parent(current.path(), operation)?;
        unlinkat(&parent, &name, AtFlags::REMOVEDIR)
            .map_err(|source| errno_error(operation, &child.path, source))?;
        parent
            .sync_all()
            .map_err(|source| io_error("sync-parent", &child.path, source))?;
        self.verify_path_binding()
    }

    /// Syncs the authenticated parent of one descendant path.
    pub(crate) fn sync_parent(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(), AnchoredFsError> {
        self.verify_path_binding()?;
        let (parent, _) = self.open_parent(path, operation)?;
        parent
            .sync_all()
            .map_err(|source| io_error(operation, path, source))?;
        self.verify_path_binding()
    }

    fn reopen_file_identity(
        &self,
        file: &AnchoredFile,
        operation: &'static str,
    ) -> Result<AnchoredFile, AnchoredFsError> {
        let current = self
            .open_regular_optional(file.path(), operation)?
            .ok_or_else(|| AnchoredFsError::Replaced {
                path: file.path().to_owned(),
            })?;
        if current.identity() == file.identity() {
            Ok(current)
        } else {
            Err(AnchoredFsError::Replaced {
                path: file.path().to_owned(),
            })
        }
    }

    fn reopen_directory_identity(
        &self,
        directory: &AnchoredDirectory,
        operation: &'static str,
    ) -> Result<AnchoredDirectory, AnchoredFsError> {
        let current = self.open_directory(directory.path(), operation)?;
        if current.identity() == directory.identity() {
            Ok(current)
        } else {
            Err(AnchoredFsError::Replaced {
                path: directory.path().to_owned(),
            })
        }
    }

    fn finish_file_open(
        &self,
        path: &Path,
        parent: File,
        name: OsString,
        file: File,
    ) -> Result<AnchoredFile, AnchoredFsError> {
        let metadata = file
            .metadata()
            .map_err(|source| io_error("inspect-file", path, source))?;
        if !metadata.is_file() {
            return Err(AnchoredFsError::InvalidPath {
                path: path.to_owned(),
            });
        }

        Ok(AnchoredFile {
            path: path.to_owned(),
            file,
            parent,
            name,
            anchor: self
                .anchor
                .try_clone()
                .map_err(|source| io_error("clone-file-anchor", path, source))?,
            anchor_path: self.anchor_path.clone(),
            anchor_relative: self.anchor_relative.join(self.relative(path)?),
            anchor_device: self.anchor_device,
            anchor_inode: self.anchor_inode,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn open_parent(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(File, OsString), AnchoredFsError> {
        let relative = self.relative(path)?;
        let parent = relative
            .parent()
            .ok_or_else(|| AnchoredFsError::InvalidPath {
                path: path.to_owned(),
            })?;
        let name = relative
            .file_name()
            .ok_or_else(|| AnchoredFsError::InvalidPath {
                path: path.to_owned(),
            })?
            .to_owned();
        let directory = if parent.as_os_str().is_empty() || parent == Path::new(".") {
            self.directory
                .try_clone()
                .map_err(|source| io_error(operation, path, source))?
        } else {
            let descriptor = openat2(
                &self.directory,
                parent,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|source| errno_error(operation, path, source))?;
            File::from(descriptor)
        };
        Ok((directory, name))
    }

    fn relative<'a>(&self, path: &'a Path) -> Result<&'a Path, AnchoredFsError> {
        let relative = if let Ok(relative) = path.strip_prefix(&self.path) {
            relative
        } else if path.is_absolute() {
            return Err(AnchoredFsError::InvalidPath {
                path: path.to_owned(),
            });
        } else {
            path
        };
        if relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(AnchoredFsError::InvalidPath {
                path: path.to_owned(),
            });
        }
        Ok(relative)
    }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> AnchoredFsError {
    AnchoredFsError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

fn verify_root_binding(
    anchor: &File,
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), AnchoredFsError> {
    let descriptor_metadata = anchor
        .metadata()
        .map_err(|source| io_error("inspect-root-anchor", path, source))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("revalidate-root-anchor", path, source))?;
    if descriptor_metadata.is_dir()
        && path_metadata.file_type().is_dir()
        && descriptor_metadata.dev() == expected_device
        && descriptor_metadata.ino() == expected_inode
        && path_metadata.dev() == expected_device
        && path_metadata.ino() == expected_inode
    {
        Ok(())
    } else {
        Err(AnchoredFsError::Replaced {
            path: path.to_owned(),
        })
    }
}

fn errno_error(operation: &'static str, path: &Path, source: rustix::io::Errno) -> AnchoredFsError {
    io_error(
        operation,
        path,
        std::io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn replacement_fences_old_directory_authority() {
        let parent = TempDir::new().expect("parent");
        let configured = parent.path().join("state");
        fs::create_dir(&configured).expect("state root");
        let authority = AnchoredDirectory::open(configured.clone()).expect("authority");
        let detached = parent.path().join("detached");

        fs::rename(&configured, &detached).expect("detach root");
        fs::create_dir(&configured).expect("replacement root");

        assert!(matches!(
            authority.verify_path_binding(),
            Err(AnchoredFsError::Replaced { .. })
        ));
    }

    #[test]
    fn regular_open_rejects_a_symlink() {
        let root = TempDir::new().expect("root");
        let outside = root.path().join("outside");
        fs::write(&outside, b"outside").expect("outside file");
        let namespace = root.path().join("namespace");
        fs::create_dir(&namespace).expect("namespace");
        symlink(&outside, namespace.join("lock")).expect("lock symlink");
        let authority = AnchoredDirectory::open(namespace.clone()).expect("authority");

        assert!(
            authority
                .open_or_create_regular(&namespace.join("lock"), "open-lock")
                .is_err()
        );
    }
}
