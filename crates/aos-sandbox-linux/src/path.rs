//! Race-resistant descriptor-relative path resolution.
//!
//! Every descendant is resolved with `openat2` beneath an already-open root.
//! Symlinks, magic links, traversal, and optionally mount crossings are denied
//! by the kernel in one operation rather than by a check-then-open sequence.

use std::ffi::CString;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use crate::uapi::{
    self, OpenHow, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
};
use crate::{Error, Result};

const MAX_RELATIVE_PATH_BYTES: usize = 4096;

/// A pre-opened directory beneath which untrusted relative paths are resolved.
#[derive(Debug)]
pub struct BeneathRoot {
    fd: OwnedFd,
    identity: FileIdentity,
}

impl BeneathRoot {
    /// Validates and adopts an owned directory descriptor as a resolution root.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor cannot be inspected or does not name
    /// a directory.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        uapi::ensure_cloexec(fd.as_fd())?;
        let identity = inspect(fd.as_fd())?;
        if identity.file_type != FileType::Directory {
            return Err(Error::WrongDescriptorType {
                expected: "directory",
            });
        }
        Ok(Self { fd, identity })
    }

    /// Borrows the root descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Returns the root's device/inode identity captured at construction.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Resolves a non-empty relative descendant according to `options`.
    ///
    /// Resolution always sets `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and
    /// `RESOLVE_NO_SYMLINKS`. `options.no_mount_crossing` additionally sets
    /// `RESOLVE_NO_XDEV`.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, absolute, parent-containing, NUL-containing,
    /// or overlong paths; disallowed object types; traversal attempts; mount
    /// crossings; races that invalidate resolution; and kernel failures.
    pub fn resolve(&self, relative: &Path, options: ResolveOptions) -> Result<ResolvedPath> {
        let bytes = validate_relative_path(relative)?;
        let path =
            CString::new(bytes).map_err(|_| Error::invalid("relative path", "contains NUL"))?;
        let mut resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
        if options.no_mount_crossing {
            resolve |= RESOLVE_NO_XDEV;
        }
        let flags = u64::try_from(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .map_err(|_| Error::invalid("open flags", "platform flag conversion failed"))?
            | if options.require_directory {
                u64::try_from(libc::O_DIRECTORY)
                    .map_err(|_| Error::invalid("open flags", "O_DIRECTORY conversion failed"))?
            } else {
                0
            };
        let fd = uapi::openat2(
            self.fd.as_fd(),
            &path,
            &OpenHow {
                flags,
                mode: 0,
                resolve,
            },
        )?;
        let identity = inspect(fd.as_fd())?;
        if identity.file_type == FileType::Symlink {
            return Err(Error::WrongDescriptorType {
                expected: "non-symlink object",
            });
        }
        if options.require_directory && identity.file_type != FileType::Directory {
            return Err(Error::WrongDescriptorType {
                expected: "directory",
            });
        }
        Ok(ResolvedPath { fd, identity })
    }
}

/// Kernel-enforced constraints for descendant resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolveOptions {
    /// Reject any crossing to a different mount.
    pub no_mount_crossing: bool,
    /// Require the result to be a directory.
    pub require_directory: bool,
}

impl ResolveOptions {
    /// Returns strict defaults suitable for a mount source directory.
    #[must_use]
    pub const fn directory() -> Self {
        Self {
            no_mount_crossing: true,
            require_directory: true,
        }
    }

    /// Returns strict defaults for any non-symlink filesystem object.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            no_mount_crossing: true,
            require_directory: false,
        }
    }
}

/// An object pinned by an owned `O_PATH` descriptor.
#[derive(Debug)]
pub struct ResolvedPath {
    fd: OwnedFd,
    identity: FileIdentity,
}

impl ResolvedPath {
    /// Borrows the pinned object descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Returns the device/inode/type identity captured after resolution.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }
}

/// Stable metadata captured from one open filesystem object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    /// Device number containing the inode.
    pub device: u64,
    /// Inode number.
    pub inode: u64,
    /// Broad object type.
    pub file_type: FileType,
}

/// Broad object type derived from `st_mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    /// Directory.
    Directory,
    /// Regular file.
    Regular,
    /// Symbolic link. Resolution APIs reject this type before returning it.
    Symlink,
    /// Another non-symlink object type.
    Other,
}

fn inspect(fd: BorrowedFd<'_>) -> Result<FileIdentity> {
    let stat = uapi::fstat(fd)?;
    let kind = stat.st_mode & libc::S_IFMT;
    let file_type = if kind == libc::S_IFDIR {
        FileType::Directory
    } else if kind == libc::S_IFREG {
        FileType::Regular
    } else if kind == libc::S_IFLNK {
        FileType::Symlink
    } else {
        FileType::Other
    };
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        file_type,
    })
}

fn validate_relative_path(path: &Path) -> Result<&[u8]> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(Error::invalid("relative path", "must not be empty"));
    }
    if bytes.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(Error::invalid(
            "relative path",
            format!("exceeds {MAX_RELATIVE_PATH_BYTES} bytes"),
        ));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::invalid(
                    "relative path",
                    "must remain beneath the pre-opened root",
                ));
            }
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::fd::OwnedFd;

    use super::*;

    fn root(path: &Path) -> BeneathRoot {
        let fd: OwnedFd = File::open(path).unwrap().into();
        BeneathRoot::from_owned(fd).unwrap()
    }

    #[test]
    fn rejects_empty_absolute_parent_and_symlink_paths() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("child")).unwrap();
        std::os::unix::fs::symlink("child", temp.path().join("link")).unwrap();
        let root = root(temp.path());

        assert!(root.resolve(Path::new(""), ResolveOptions::any()).is_err());
        assert!(
            root.resolve(Path::new("/child"), ResolveOptions::any())
                .is_err()
        );
        assert!(
            root.resolve(Path::new("../child"), ResolveOptions::any())
                .is_err()
        );
        assert!(
            root.resolve(Path::new("link"), ResolveOptions::any())
                .is_err()
        );
    }

    #[test]
    fn resolves_and_pins_a_strict_descendant() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("child")).unwrap();
        let root = root(temp.path());
        let child = root
            .resolve(Path::new("child"), ResolveOptions::directory())
            .unwrap();
        assert_eq!(child.identity().file_type, FileType::Directory);
        assert_ne!(child.identity().inode, 0);
    }

    #[test]
    fn ordinary_file_cannot_become_beneath_root() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let fd: OwnedFd = File::open(temp.path()).unwrap().into();
        assert!(matches!(
            BeneathRoot::from_owned(fd),
            Err(Error::WrongDescriptorType { .. })
        ));
    }
}
