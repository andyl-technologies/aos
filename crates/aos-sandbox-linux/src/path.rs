//! Race-resistant descriptor-relative path resolution.
//!
//! Every descendant is resolved with `openat2` beneath an already-open root.
//! Symlinks, magic links, traversal, and optionally mount crossings are denied
//! by the kernel in one operation rather than by a check-then-open sequence.

use std::ffi::CString;
use std::io::Read as _;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use crate::pidfd::SingleThreadedProcess;
use crate::pidfd::{NamespaceFd, NamespaceKind};
use crate::uapi::{
    self, OpenHow, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
};
use crate::{Error, Result};

const MAX_RELATIVE_PATH_BYTES: usize = 4096;
const MAXIMUM_BOUNDED_READ_BYTES: usize = 16 * 1024 * 1024;

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

    /// Converts an already-validated directory path into a resolution root.
    ///
    /// # Errors
    ///
    /// Returns an error unless `path` names a directory.
    pub fn from_resolved(path: ResolvedPath) -> Result<Self> {
        if path.identity.file_type != FileType::Directory {
            return Err(Error::WrongDescriptorType {
                expected: "directory",
            });
        }
        Ok(Self {
            fd: path.fd,
            identity: path.identity,
        })
    }

    /// Borrows the root descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Makes this directory the short-lived helper's filesystem root.
    ///
    /// This is path hygiene after the helper has entered the payload mount
    /// namespace. It is not a security boundary; the exact inherited
    /// descriptor set and the helper's MAC/capability state are authoritative.
    ///
    /// # Errors
    ///
    /// Returns an error when changing directory or root fails.
    pub fn confine_helper_root(&self, _worker: &SingleThreadedProcess) -> Result<()> {
        uapi::fchdir(self.fd.as_fd())?;
        uapi::chroot_dot()?;
        uapi::chdir_root()
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

    /// Opens a regular descendant for a bounded read without a path race.
    ///
    /// Resolution rejects symlinks, magic links, traversal, and mount
    /// crossings exactly like [`BeneathRoot::resolve`], but returns a readable
    /// descriptor rather than `O_PATH`. Nonblocking and no-controlling-terminal
    /// flags prevent FIFO/terminal side effects before the regular-file check;
    /// they do not impose an I/O deadline on an underlying filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, resolution failures, non-regular
    /// results, or descriptor inspection failures.
    pub fn open_regular(&self, relative: &Path) -> Result<ResolvedFile> {
        let bytes = validate_relative_path(relative)?;
        let path =
            CString::new(bytes).map_err(|_| Error::invalid("relative path", "contains NUL"))?;
        // The type is checked after open: reject FIFO candidates without waiting
        // for a writer and never acquire a terminal while inspecting a candidate.
        let flags = u64::try_from(
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
        .map_err(|_| Error::invalid("open flags", "platform flag conversion failed"))?;
        let fd = uapi::openat2(
            self.fd.as_fd(),
            &path,
            &OpenHow {
                flags,
                mode: 0,
                resolve: RESOLVE_BENEATH
                    | RESOLVE_NO_MAGICLINKS
                    | RESOLVE_NO_SYMLINKS
                    | RESOLVE_NO_XDEV,
            },
        )?;
        let identity = inspect(fd.as_fd())?;
        if identity.file_type != FileType::Regular {
            return Err(Error::WrongDescriptorType {
                expected: "regular file",
            });
        }
        Ok(ResolvedFile { fd, identity })
    }

    /// Opens and type-checks a bind-pinned namespace beneath this root.
    ///
    /// Namespace pins are expected to cross from the catalog filesystem onto
    /// `nsfs`, so this operation intentionally omits `RESOLVE_NO_XDEV` while
    /// retaining beneath, no-magic-link, and no-symlink resolution.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid relative path, symlink traversal,
    /// missing pin, wrong namespace type, or kernel inspection failure.
    pub fn open_namespace(&self, relative: &Path, kind: NamespaceKind) -> Result<NamespaceFd> {
        let bytes = validate_relative_path(relative)?;
        let path =
            CString::new(bytes).map_err(|_| Error::invalid("relative path", "contains NUL"))?;
        let flags = u64::try_from(libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .map_err(|_| Error::invalid("open flags", "platform flag conversion failed"))?;
        let fd = uapi::openat2(
            self.fd.as_fd(),
            &path,
            &OpenHow {
                flags,
                mode: 0,
                resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
            },
        )?;
        NamespaceFd::from_owned(fd, kind)
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

/// A regular file pinned by an owned readable descriptor.
#[derive(Debug)]
pub struct ResolvedFile {
    fd: OwnedFd,
    identity: FileIdentity,
}

impl ResolvedFile {
    pub(crate) fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }

    /// Returns the device/inode/type identity captured after resolution.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Consumes the descriptor and reads at most `maximum` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when `maximum` exceeds sixteen MiB, I/O fails, or the
    /// file contains more than the admitted byte count.
    pub fn read_bounded(self, maximum: usize) -> Result<Vec<u8>> {
        if maximum > MAXIMUM_BOUNDED_READ_BYTES {
            return Err(Error::invalid(
                "bounded read",
                "maximum exceeds sixteen MiB",
            ));
        }
        let limit = maximum
            .checked_add(1)
            .ok_or_else(|| Error::invalid("bounded read", "maximum overflow"))?;
        let mut bytes = Vec::with_capacity(limit);
        std::fs::File::from(self.fd)
            .take(
                u64::try_from(limit).map_err(|_| {
                    Error::invalid("bounded read", "maximum does not fit read limit")
                })?,
            )
            .read_to_end(&mut bytes)
            .map_err(|source| Error::Syscall {
                operation: "read bounded regular file",
                source,
            })?;
        if bytes.len() > maximum {
            return Err(Error::invalid(
                "bounded read",
                "file exceeds admitted maximum",
            ));
        }
        Ok(bytes)
    }
}

impl ResolvedPath {
    /// Validates and adopts an inherited `O_PATH` descriptor.
    ///
    /// This constructor is intended for the exact descriptor table inherited
    /// by a fixed helper. Higher-level brokers must resolve caller-independent
    /// paths through [`BeneathRoot`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error when descriptor inspection fails or it is a symlink.
    pub fn from_inherited(fd: OwnedFd) -> Result<Self> {
        uapi::ensure_cloexec(fd.as_fd())?;
        let identity = inspect(fd.as_fd())?;
        if identity.file_type == FileType::Symlink {
            return Err(Error::WrongDescriptorType {
                expected: "non-symlink object",
            });
        }
        Ok(Self { fd, identity })
    }
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
    fn regular_open_rejects_fifo_without_waiting_for_a_writer() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = CString::new(temp.path().join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: the private temporary pathname is a live NUL-terminated string;
        // mkfifo consumes no pointers beyond this call and initializes no output.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let root = root(temp.path());
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result = root.open_regular(Path::new("fifo"));
            sender.send(result).unwrap();
            drop(temp);
        });

        // A regression to blocking open must fail the test, not hang the suite.
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(matches!(result, Err(Error::WrongDescriptorType { .. })));
        reader.join().unwrap();
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
    fn ordinary_catalog_file_is_not_a_namespace_pin() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("not-a-namespace"), b"x").unwrap();
        let root = root(temp.path());
        assert!(
            root.open_namespace(Path::new("not-a-namespace"), NamespaceKind::Mount)
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

    #[test]
    fn regular_file_reads_are_descriptor_pinned_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("catalog"), b"abc").unwrap();
        std::os::unix::fs::symlink("catalog", temp.path().join("link")).unwrap();
        let root = root(temp.path());
        assert_eq!(
            root.open_regular(Path::new("catalog"))
                .unwrap()
                .read_bounded(3)
                .unwrap(),
            b"abc"
        );
        assert!(
            root.open_regular(Path::new("catalog"))
                .unwrap()
                .read_bounded(2)
                .is_err()
        );
        assert!(root.open_regular(Path::new("link")).is_err());
    }
}
