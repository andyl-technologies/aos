//! Authenticated build identity for a packaged QEMU and plugin launch pair.

use std::collections::BTreeMap;
use std::path::Path;

use crucible_qemu::{QemuLaunchArtifactIdentity, QemuLaunchArtifactIdentityError};

/// Returns the normalized build identity of one matched packaged launch pair.
///
/// # Errors
///
/// Returns [`QemuLaunchArtifactIdentityError`] when either artifact or its
/// build marker is missing, malformed, or incompatible with its counterpart.
pub fn authenticated_qemu_build_id(
    qemu: &Path,
    plugin: &Path,
) -> Result<String, QemuLaunchArtifactIdentityError> {
    let identity = QemuLaunchArtifactIdentity::authenticate(qemu, plugin)?;
    Ok(identity.qemu_build_id().to_owned())
}

/// Returns the protocol versions required by a packaged QEMU campaign lineage.
pub fn packaged_qemu_protocol_versions() -> BTreeMap<String, u32> {
    BTreeMap::from([
        (
            String::from("control"),
            crucible_protocol::CONTROL_PROTOCOL_VERSION,
        ),
        (String::from("shared-memory"), crucible_shmem::ABI_VERSION),
    ])
}
