//! Fresh, owner-created FUSE connections and their detached mounts.
//!
//! The constructor opens the fixed kernel device itself. No operation adopts
//! an incoming FUSE descriptor or reconstructs connection provenance from its
//! device/inode numbers. The same original open file description remains owned
//! while constructing and retaining the detached mount. This is kernel-object
//! custody, not Controller, attachment, worker, or lease authority.

use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};

use rustix::fs::{FileType, Mode, OFlags};

use crate::inventory::MountId;
use crate::mount::{DetachedMount, FileSystemContext, MountAttributes};
use crate::pidfd::{NamespaceFd, NamespaceKind};
use crate::{Error, Result};

const FUSE_DEVICE: &str = "/dev/fuse";
const FUSE_DEVICE_MAJOR: u32 = 10;
const FUSE_DEVICE_MINOR: u32 = 229;
const MAXIMUM_READ_BYTES: &str = "131072";

/// Retains a freshly opened FUSE device and the mount created from that OFD.
///
/// There is no incoming-descriptor constructor, clone implementation, or
/// connection-identity factory. Device metadata alone cannot distinguish a
/// fresh connection from an initialized connection shared by another mount.
/// The broker must independently retain its authenticated request, namespace,
/// slot, worker, and protected journal custody before using this object.
pub struct FreshDetachedFuseMountV1 {
    device: OwnedFd,
    mount: DetachedMount,
}

impl FreshDetachedFuseMountV1 {
    /// Creates one read-only detached mount from an internally opened device.
    ///
    /// The fixed profile enables kernel permission checks and permits access
    /// by the separately confined consumer. `no_exec` and the optional idmap
    /// are kernel configuration inputs, not independently admitted policy.
    /// Callers must derive them from their own closed, authenticated policy.
    /// Neither this method nor successful FUSE initialization permits attaching
    /// the mount or publishing worker readiness.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-user idmap, an inaccessible or substituted
    /// fixed device, rejected filesystem parameters, mount creation, or mount
    /// attributes. No descriptor escapes if an intermediate operation fails.
    pub fn open_fixed_read_only(no_exec: bool, idmap: Option<&NamespaceFd>) -> Result<Self> {
        Self::open_fixed_read_only_inner(no_exec, idmap, false)
    }

    // The fixed worker producer retains its user namespace separately. FUSE
    // rejects idmapping until INIT negotiates FUSE_ALLOW_IDMAP, so this mount
    // cannot be published before genuine initialization and idmap completion.
    pub(crate) fn open_fixed_worker_read_only() -> Result<Self> {
        Self::open_fixed_read_only_inner(true, None, true)
    }

    fn open_fixed_read_only_inner(
        no_exec: bool,
        idmap: Option<&NamespaceFd>,
        verify_worker_label: bool,
    ) -> Result<Self> {
        if idmap.is_some_and(|namespace| namespace.kind() != NamespaceKind::User) {
            return Err(Error::invalid(
                "FUSE mount idmap",
                "must be a user namespace",
            ));
        }

        let device = rustix::fs::open(
            FUSE_DEVICE,
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| kernel_error("open fixed FUSE device", source))?;
        verify_device(device.as_fd())?;
        if verify_worker_label {
            // Inspect the original freshly opened OFD before any fscontext
            // consumes it. A later label check cannot establish fresh custody.
            crate::fuse_worker_objects::require_object_context(
                device.as_fd(),
                crate::fuse_worker_objects::FUSE_WORKER_DEVICE_CONTEXT_V1,
            )?;
        }

        let mut context = FileSystemContext::open("fuse")?;
        // Linux 7.2.3 accepts either an FD-valued parameter or numeric fget.
        // Keep this number private and derived solely from our fresh, retained
        // OFD: accepting an initialized inbound FUSE FD can reuse a connection.
        context.set_string("fd", &device.as_raw_fd().to_string())?;
        context.set_string("rootmode", "40755")?;
        context.set_string("user_id", &rustix::process::geteuid().as_raw().to_string())?;
        context.set_string("group_id", &rustix::process::getegid().as_raw().to_string())?;
        context.set_string("max_read", MAXIMUM_READ_BYTES)?;
        context.set_flag("default_permissions")?;
        context.set_flag("allow_other")?;

        let mount = context.create()?.mount()?;
        mount.set_attributes(
            false,
            MountAttributes::secure_read_only()
                .with_no_exec(no_exec)
                .with_no_atime(true),
            idmap,
        )?;

        Ok(Self { device, mount })
    }

    /// Borrows the same original OFD used during detached mount construction.
    ///
    /// Descriptor duplication is only a transport operation. It does not mint
    /// worker-consumer authority or prove which task will use the duplicate.
    #[must_use]
    pub fn device(&self) -> BorrowedFd<'_> {
        self.device.as_fd()
    }

    /// Borrows the retained detached mount without publishing it.
    #[must_use]
    pub fn mount(&self) -> &DetachedMount {
        &self.mount
    }

    /// Returns the kernel-lifetime unique identity of the retained mount.
    #[must_use]
    pub const fn mount_id(&self) -> MountId {
        self.mount.mount_id()
    }
}

fn verify_device(device: BorrowedFd<'_>) -> Result<()> {
    let stat = rustix::fs::fstat(device)
        .map_err(|source| kernel_error("inspect fixed FUSE device", source))?;
    verify_device_kind(
        FileType::from_raw_mode(stat.st_mode),
        rustix::fs::major(stat.st_rdev),
        rustix::fs::minor(stat.st_rdev),
    )
}

fn verify_device_kind(kind: FileType, major: u32, minor: u32) -> Result<()> {
    if kind != FileType::CharacterDevice || major != FUSE_DEVICE_MAJOR || minor != FUSE_DEVICE_MINOR
    {
        return Err(Error::WrongDescriptorType {
            expected: "fixed FUSE character device 10:229",
        });
    }

    Ok(())
}

fn kernel_error(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_device_shape_rejects_substitutions() {
        assert!(verify_device_kind(FileType::CharacterDevice, 10, 229).is_ok());
        assert!(verify_device_kind(FileType::RegularFile, 10, 229).is_err());
        assert!(verify_device_kind(FileType::CharacterDevice, 10, 228).is_err());
        assert!(verify_device_kind(FileType::CharacterDevice, 11, 229).is_err());
    }
}
