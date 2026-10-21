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

mod publication_original;
pub(crate) use publication_original::NetworkNamespacePublicationOriginalV2;
mod removal_original;
pub(crate) use removal_original::NetworkNamespaceRemovalOriginalV2;

/// Reports an unsafe, substituted, or failed namespace-pin mutation.
#[derive(Debug, thiserror::Error)]
pub enum NetworkNamespacePinMutationError {
    /// Descriptor-safe path validation or namespace typing failed.
    #[error("Network namespace pin authority is invalid: {0}")]
    Linux(#[from] aos_linux_descriptors::Error),
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
    publication_original::publish_local_v2(network_handle, namespace)
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
    removal_original::remove_local_v2(network_handle, expected, allow_absent)
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
