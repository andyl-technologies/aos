//! Fixed host-mount-namespace publication for retained Network namespaces.
//!
//! Namespace identity is transported by descriptor, while the runtime joins it
//! through one canonical bind pin. Only privileged one-shot workers call these
//! functions, and every path component is fixed or derived from an opaque
//! nonzero handle.

use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use aos_sandbox_linux::path::{BeneathRoot, FileType, ResolveOptions};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::mount::UnmountFlags;

const PIN_ROOT: &str = "/run/aos/sandbox-pins/netns";

/// Reports an unsafe, substituted, or failed namespace-pin mutation.
#[derive(Debug, thiserror::Error)]
pub enum NetworkNamespacePinMutationError {
    /// Descriptor-safe path validation or namespace typing failed.
    #[error("Network namespace pin authority is invalid: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A fixed filesystem or mount operation failed.
    #[error("Network namespace pin mutation failed: {0}")]
    Syscall(#[from] rustix::io::Errno),
    /// The root, candidate, or resulting namespace identity was inconsistent.
    #[error("Network namespace pin identity is inconsistent")]
    Identity,
}

/// Publishes one exact descriptor as its canonical handle-derived bind pin.
///
/// # Errors
///
/// Returns an error unless the protected pin root is exact, the destination is
/// initially absent, the bind mount succeeds, and reopening the final pin
/// reproduces the supplied namespace's physical identity.
pub(crate) fn publish_namespace_pin(
    network_handle: [u8; 32],
    namespace: &NamespaceFd,
) -> Result<(), NetworkNamespacePinMutationError> {
    let root = open_pin_root()?;
    let component = handle_component(network_handle)?;
    let destination = fixed_pin_path(&component);
    let placeholder = rustix::fs::openat(
        root.as_fd(),
        component.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?;
    let source = PathBuf::from(format!("/proc/self/fd/{}", namespace.as_fd().as_raw_fd()));

    if let Err(error) = rustix::mount::mount_bind(&source, &destination) {
        drop(placeholder);
        let _ = rustix::fs::unlinkat(root.as_fd(), component.as_str(), AtFlags::empty());
        return Err(error.into());
    }
    drop(placeholder);

    let observed = match root.open_namespace(Path::new(&component), NamespaceKind::Network) {
        Ok(observed) => observed,
        Err(error) => {
            let _ = rustix::mount::unmount(&destination, UnmountFlags::NOFOLLOW);
            let _ = rustix::fs::unlinkat(root.as_fd(), component.as_str(), AtFlags::empty());
            return Err(error.into());
        }
    };
    if observed.identity() != namespace.identity() {
        drop(observed);
        let _ = rustix::mount::unmount(&destination, UnmountFlags::NOFOLLOW);
        let _ = rustix::fs::unlinkat(root.as_fd(), component.as_str(), AtFlags::empty());
        return Err(NetworkNamespacePinMutationError::Identity);
    }
    Ok(())
}

/// Removes one canonical pin after revalidating its expected namespace.
///
/// # Errors
///
/// Returns an error when the protected root or pin changed, ordinary unmount
/// fails, the mountpoint cannot be removed, or absence cannot be proved.
pub(crate) fn remove_namespace_pin(
    network_handle: [u8; 32],
    expected: NamespaceIdentity,
    allow_absent: bool,
) -> Result<(), NetworkNamespacePinMutationError> {
    let root = open_pin_root()?;
    let component = handle_component(network_handle)?;
    let destination = fixed_pin_path(&component);
    match rustix::fs::statat(root.as_fd(), component.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) if allow_absent => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let observed = root.open_namespace(Path::new(&component), NamespaceKind::Network)?;
    if observed.identity() != expected {
        return Err(NetworkNamespacePinMutationError::Identity);
    }
    drop(observed);

    rustix::mount::unmount(&destination, UnmountFlags::NOFOLLOW)?;
    rustix::fs::unlinkat(root.as_fd(), component.as_str(), AtFlags::empty())?;
    match rustix::fs::statat(root.as_fd(), component.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) | Err(_) => Err(NetworkNamespacePinMutationError::Identity),
    }
}

fn open_pin_root() -> Result<BeneathRoot, NetworkNamespacePinMutationError> {
    let slash = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let filesystem = BeneathRoot::from_owned(slash)?;
    let resolved = filesystem.resolve(
        Path::new("run/aos/sandbox-pins/netns"),
        ResolveOptions {
            no_mount_crossing: false,
            require_directory: true,
        },
    )?;
    if resolved.identity().file_type != FileType::Directory {
        return Err(NetworkNamespacePinMutationError::Identity);
    }
    let metadata = rustix::fs::fstat(resolved.as_fd())?;
    if metadata.st_uid != 0 || metadata.st_mode & 0o077 != 0 {
        return Err(NetworkNamespacePinMutationError::Identity);
    }
    BeneathRoot::from_resolved(resolved).map_err(Into::into)
}

fn handle_component(network_handle: [u8; 32]) -> Result<String, NetworkNamespacePinMutationError> {
    if network_handle == [0; 32] {
        return Err(NetworkNamespacePinMutationError::Identity);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut component = String::with_capacity(64);
    for byte in network_handle {
        component.push(char::from(HEX[usize::from(byte >> 4)]));
        component.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(component)
}

fn fixed_pin_path(component: &str) -> PathBuf {
    Path::new(PIN_ROOT).join(component)
}
