//! Owned filesystem-context and detached-mount descriptors.
//!
//! Mounts are configured and attributed while detached, then attached to a
//! destination pinned by [`crate::path::ResolvedPath`]. No operation accepts a
//! process-global path or invokes the legacy stringly `mount(2)` API.

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::inventory::MountId;
use crate::path::ResolvedPath;
use crate::pidfd::SingleThreadedProcess;
use crate::pidfd::{NamespaceFd, NamespaceKind};
use crate::uapi::{
    self, FSCONFIG_CMD_CREATE, FSCONFIG_SET_FD, FSCONFIG_SET_FLAG, FSCONFIG_SET_STRING,
    MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID,
    MOUNT_ATTR_RDONLY, RawMountAttr,
};
use crate::{Error, Result};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

const MAX_FILESYSTEM_NAME_BYTES: usize = 64;
const MAX_PARAMETER_NAME_BYTES: usize = 128;
const MAX_PARAMETER_VALUE_BYTES: usize = 4096;

/// Attributes applied to a detached mount before publication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MountAttributes {
    read_only: Option<bool>,
    no_suid: bool,
    no_device: bool,
    no_exec: Option<bool>,
    no_atime: bool,
}

/// Lazily detaches one canonical relative mountpoint in a confined helper.
///
/// The caller must first resolve and verify the same path beneath its pinned
/// root, then call [`crate::path::BeneathRoot::confine_helper_root`]. Linux has
/// no descriptor-only unmount operation, so this is the sole narrow pathname
/// operation in the mount helper.
///
/// # Errors
///
/// Returns an error for an empty, absolute, parent-containing, NUL-containing,
/// or overlong path, or when `umount2` refuses the exact mountpoint.
pub fn detach_relative(path: &Path, _worker: &SingleThreadedProcess) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.len() > 4096
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Error::invalid(
            "unmount path",
            "must be a canonical relative path",
        ));
    }
    let path = CString::new(bytes).map_err(|_| Error::invalid("unmount path", "contains NUL"))?;
    uapi::umount_detach(&path)
}

impl MountAttributes {
    /// Returns a read-only, nosuid, nodev attribute set suitable for data.
    #[must_use]
    pub const fn secure_read_only() -> Self {
        Self {
            read_only: Some(true),
            no_suid: true,
            no_device: true,
            no_exec: None,
            no_atime: false,
        }
    }

    /// Adds or removes `noexec` from the attribute set.
    #[must_use]
    pub const fn with_no_exec(mut self, enabled: bool) -> Self {
        self.no_exec = Some(enabled);
        self
    }

    /// Enables or disables access-time suppression.
    #[must_use]
    pub const fn with_no_atime(mut self, enabled: bool) -> Self {
        self.no_atime = enabled;
        self
    }

    /// Returns a writable, nosuid, nodev attribute set for private workspaces.
    #[must_use]
    pub const fn secure_writable() -> Self {
        Self {
            read_only: Some(false),
            no_suid: true,
            no_device: true,
            no_exec: None,
            no_atime: false,
        }
    }

    fn raw(self, user_namespace: Option<&NamespaceFd>) -> Result<RawMountAttr> {
        if let Some(namespace) = user_namespace
            && namespace.kind() != NamespaceKind::User
        {
            return Err(Error::invalid(
                "mount idmap namespace",
                "must be a user namespace",
            ));
        }

        let mut set = 0;
        let mut clear = 0;
        match self.read_only {
            Some(true) => set |= MOUNT_ATTR_RDONLY,
            Some(false) => clear |= MOUNT_ATTR_RDONLY,
            None => {}
        }
        if self.no_suid {
            set |= MOUNT_ATTR_NOSUID;
        }
        if self.no_device {
            set |= MOUNT_ATTR_NODEV;
        }
        if self.no_atime {
            set |= MOUNT_ATTR_NOATIME;
        }
        match self.no_exec {
            Some(true) => set |= MOUNT_ATTR_NOEXEC,
            Some(false) => clear |= MOUNT_ATTR_NOEXEC,
            None => {}
        }
        let userns_fd = match user_namespace {
            Some(namespace) => {
                set |= MOUNT_ATTR_IDMAP;
                u64::try_from(namespace.as_fd().as_raw_fd()).map_err(|_| {
                    Error::invalid("mount idmap namespace", "descriptor is negative")
                })?
            }
            None => 0,
        };
        Ok(RawMountAttr {
            attr_set: set,
            attr_clr: clear,
            propagation: 0,
            userns_fd,
        })
    }
}

/// An invisible mount tree owned by a mount file descriptor.
#[derive(Debug)]
pub struct DetachedMount {
    fd: OwnedFd,
    mount_id: MountId,
}

impl DetachedMount {
    /// Validates and adopts a detached-mount descriptor inherited by a helper.
    ///
    /// The descriptor must originate in the broker's exact spawn table. The
    /// kernel performs the final mount-object check when `move_mount` consumes
    /// the child-side reference; arbitrary callers cannot reach this helper
    /// interface.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor cannot be inspected or secured
    /// with close-on-exec semantics.
    pub fn from_inherited(fd: OwnedFd) -> Result<Self> {
        uapi::ensure_cloexec(fd.as_fd())?;
        let _ = uapi::fstat(fd.as_fd())?;
        let mount_id = MountId::from_fd(fd.as_fd())?;
        Ok(Self { fd, mount_id })
    }
    /// Clones the mount containing `source` without publishing it.
    ///
    /// # Errors
    ///
    /// Returns an error if `source` is not a mountable object, cloning is
    /// denied, or the kernel lacks the new mount API.
    pub fn clone_from(source: &ResolvedPath, recursive: bool) -> Result<Self> {
        let fd = uapi::open_tree(source.as_fd(), recursive)?;
        let mount_id = MountId::from_fd(fd.as_fd())?;
        Ok(Self { fd, mount_id })
    }

    /// Clones and attributes a mount atomically with `open_tree_attr(2)`.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-user idmap namespace, unsupported attributes,
    /// an unsuitable source, insufficient privilege, or syscall failure.
    pub fn clone_with_attributes(
        source: &ResolvedPath,
        recursive: bool,
        attributes: MountAttributes,
        user_namespace: Option<&NamespaceFd>,
    ) -> Result<Self> {
        let raw = attributes.raw(user_namespace)?;
        let fd = uapi::open_tree_attr(source.as_fd(), recursive, &raw)?;
        let mount_id = MountId::from_fd(fd.as_fd())?;
        Ok(Self { fd, mount_id })
    }

    /// Borrows the detached mount descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Returns the kernel-lifetime unique identity of this mount object.
    #[must_use]
    pub const fn mount_id(&self) -> MountId {
        self.mount_id
    }

    /// Applies attributes and an optional idmap while the mount is detached.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong namespace kind, unsupported attributes,
    /// insufficient privilege, or a syscall failure.
    pub fn set_attributes(
        &self,
        recursive: bool,
        attributes: MountAttributes,
        user_namespace: Option<&NamespaceFd>,
    ) -> Result<()> {
        let raw = attributes.raw(user_namespace)?;
        uapi::mount_setattr(self.fd.as_fd(), recursive, &raw)
    }

    /// Atomically attaches this mount at an already-pinned destination.
    ///
    /// The mount descriptor is consumed so one prepared mount cannot be
    /// accidentally published into multiple destinations.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination is unsuitable, the mount has
    /// already been attached, privilege is insufficient, or `move_mount`
    /// fails.
    pub fn attach(self, destination: &ResolvedPath) -> Result<()> {
        uapi::move_mount(self.fd.as_fd(), destination.as_fd(), false)
    }

    /// Atomically inserts this mount beneath the current destination mount.
    ///
    /// This is the publication half of replacement on kernels supporting
    /// `MOVE_MOUNT_BENEATH`. The caller must subsequently detach the former
    /// top mount while holding the sandbox mutation lock.
    ///
    /// # Errors
    ///
    /// Returns an error if beneath insertion is unsupported, the destination
    /// is unsuitable, privilege is insufficient, or `move_mount` fails.
    pub fn attach_beneath(self, destination: &ResolvedPath) -> Result<()> {
        uapi::move_mount(self.fd.as_fd(), destination.as_fd(), true)
    }
}

/// A configurable kernel filesystem context returned by `fsopen(2)`.
#[derive(Debug)]
pub struct FileSystemContext {
    fd: OwnedFd,
}

impl FileSystemContext {
    /// Opens a filesystem context for a validated filesystem type name.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, unsupported filesystem, access
    /// denial, or syscall failure.
    pub fn open(filesystem: &str) -> Result<Self> {
        validate_token(filesystem, "filesystem name", MAX_FILESYSTEM_NAME_BYTES)?;
        let filesystem = cstring(filesystem, "filesystem name", MAX_FILESYSTEM_NAME_BYTES)?;
        Ok(Self {
            fd: uapi::fsopen(&filesystem)?,
        })
    }

    /// Sets a valueless filesystem parameter flag.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key, rejected parameter, access denial,
    /// or syscall failure.
    pub fn set_flag(&mut self, key: &str) -> Result<()> {
        let key = parameter_key(key)?;
        uapi::fsconfig(self.fd.as_fd(), FSCONFIG_SET_FLAG, Some(&key), None, 0)
    }

    /// Sets a string filesystem parameter.
    ///
    /// This low-level crate validates memory and descriptor safety only; a
    /// privileged broker must compile keys and values from a closed policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or overlong strings, a rejected parameter,
    /// access denial, or syscall failure.
    pub fn set_string(&mut self, key: &str, value: &str) -> Result<()> {
        let key = parameter_key(key)?;
        let value = cstring(
            value,
            "filesystem parameter value",
            MAX_PARAMETER_VALUE_BYTES,
        )?;
        uapi::fsconfig(
            self.fd.as_fd(),
            FSCONFIG_SET_STRING,
            Some(&key),
            Some(&value),
            0,
        )
    }

    /// Supplies an owned-by-caller descriptor as a filesystem parameter.
    ///
    /// The kernel borrows `value` only for this call; ownership stays with the
    /// caller.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key, unsuitable descriptor, access
    /// denial, or syscall failure.
    pub fn set_fd(&mut self, key: &str, value: BorrowedFd<'_>) -> Result<()> {
        let key = parameter_key(key)?;
        uapi::fsconfig(
            self.fd.as_fd(),
            FSCONFIG_SET_FD,
            Some(&key),
            None,
            value.as_raw_fd(),
        )
    }

    /// Finalizes superblock construction and consumes the configurable state.
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem rejects its completed configuration,
    /// access is denied, or the syscall fails.
    pub fn create(self) -> Result<CreatedFileSystem> {
        uapi::fsconfig(self.fd.as_fd(), FSCONFIG_CMD_CREATE, None, None, 0)?;
        Ok(CreatedFileSystem { fd: self.fd })
    }
}

/// A finalized filesystem context that can create a detached mount.
#[derive(Debug)]
pub struct CreatedFileSystem {
    fd: OwnedFd,
}

impl CreatedFileSystem {
    /// Creates an invisible mount from the finalized filesystem context.
    ///
    /// # Errors
    ///
    /// Returns an error for access denial, an invalid context, or syscall
    /// failure.
    pub fn mount(self) -> Result<DetachedMount> {
        let fd = uapi::fsmount(self.fd.as_fd())?;
        let mount_id = MountId::from_fd(fd.as_fd())?;
        Ok(DetachedMount { fd, mount_id })
    }
}

fn parameter_key(key: &str) -> Result<CString> {
    validate_token(key, "filesystem parameter key", MAX_PARAMETER_NAME_BYTES)?;
    cstring(key, "filesystem parameter key", MAX_PARAMETER_NAME_BYTES)
}

fn validate_token(value: &str, field: &'static str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(Error::invalid(
            field,
            format!("must contain 1..={maximum} bytes"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(Error::invalid(field, "contains a non-token byte"));
    }
    Ok(())
}

fn cstring(value: &str, field: &'static str, maximum: usize) -> Result<CString> {
    if value.len() > maximum {
        return Err(Error::invalid(field, format!("exceeds {maximum} bytes")));
    }
    CString::new(value).map_err(|_| Error::invalid(field, "contains NUL"))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::OwnedFd;

    use super::*;

    #[test]
    fn filesystem_tokens_are_bounded() {
        assert!(validate_token("tmpfs", "filesystem", 64).is_ok());
        assert!(validate_token("", "filesystem", 64).is_err());
        assert!(validate_token("tmp/fs", "filesystem", 64).is_err());
        assert!(validate_token(&"x".repeat(65), "filesystem", 64).is_err());
    }

    #[test]
    fn idmap_rejects_non_user_namespace_before_syscall() {
        let file: OwnedFd = File::open(".").unwrap().into();
        let namespace = NamespaceFd::from_owned(file, NamespaceKind::Mount);
        assert!(namespace.is_err(), "ordinary fd must fail nsfs validation");
    }

    #[test]
    fn attribute_profiles_are_fail_closed() {
        let read_only = MountAttributes::secure_read_only()
            .with_no_exec(true)
            .with_no_atime(true)
            .raw(None)
            .unwrap();
        assert_eq!(
            read_only.attr_set,
            MOUNT_ATTR_RDONLY
                | MOUNT_ATTR_NOSUID
                | MOUNT_ATTR_NODEV
                | MOUNT_ATTR_NOEXEC
                | MOUNT_ATTR_NOATIME
        );
        assert_eq!(read_only.userns_fd, 0);
        assert_eq!(read_only.attr_clr, 0);

        let writable = MountAttributes::secure_writable().raw(None).unwrap();
        assert_eq!(writable.attr_set, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);
        assert_eq!(writable.attr_clr, MOUNT_ATTR_RDONLY);
    }
}
