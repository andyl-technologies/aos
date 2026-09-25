//! Boot-scoped observations for the block-storage package's terminal handlers.
//!
//! A root probe attests to the selected executable in the current boot.
//! Device and journal readiness remain part of the admitted resource methods.

use std::fs;

use anyhow::{Context as _, Result, ensure};
use aos_provider_protocol::{
    RootObservationRequest, RootObservationResult, boot_scoped_handler_root,
};

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Identifies the package executable receiving a terminal root probe.
#[derive(Clone, Copy)]
pub enum BlockStorageRootRole {
    /// The systemd-repart provisioning executor.
    Provisioning,
    /// The GPT provisioning-marker observer.
    ProvisioningMarker,
    /// The ESP-backed boot transaction journal executor.
    BootTransactionStorage,
}

/// Observes the selected block-storage terminal in the current boot.
///
/// # Errors
///
/// Returns an error when the request selects another handler or interface,
/// cannot be decoded, or names a different boot.
pub fn observe_root(role: BlockStorageRootRole, input: &[u8]) -> Result<RootObservationResult> {
    let request: RootObservationRequest =
        aos_contract::canonical::from_slice(input, "block-storage root observation request")?;
    let native_boot_id = fs::read_to_string(BOOT_ID_PATH)
        .with_context(|| format!("reading block-storage handler boot identity {BOOT_ID_PATH}"))?;
    observe_root_for_boot(role, request, native_boot_id.trim())
}

fn observe_root_for_boot(
    role: BlockStorageRootRole,
    request: RootObservationRequest,
    native_boot_id: &str,
) -> Result<RootObservationResult> {
    let (handler, interface) = match role {
        BlockStorageRootRole::Provisioning => (
            "storage-provisioning-effects",
            "aos.systemd-repart.storage-provisioning-effects",
        ),
        BlockStorageRootRole::ProvisioningMarker => (
            "storage-provisioning-marker-observer",
            "aos.storage.provisioning-marker-observation",
        ),
        BlockStorageRootRole::BootTransactionStorage => (
            "boot-transaction-storage-view-effects",
            "aos.boot.transaction-storage-view-effects",
        ),
    };
    ensure!(
        request
            .implementation
            .handler
            .as_ref()
            .is_some_and(|selected| selected.as_str() == handler)
            && request.interface.name.as_str() == interface,
        "selected block-storage handler does not match this executable"
    );
    boot_scoped_handler_root(request, native_boot_id)
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::RootObservationRequest;

    use super::{BlockStorageRootRole, observe_root_for_boot};

    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    fn request(handler: &str, interface: &str) -> RootObservationRequest {
        serde_json::from_value(serde_json::json!({
            "schema": aos_provider_protocol::ROOT_OBSERVATION_REQUEST_SCHEMA,
            "provider": {
                "environment": {"authority":"system-image","key":"test","stage":"initrd"},
                "key": handler
            },
            "interface": {
                "name": interface,
                "abi": 1,
                "descriptor": Sha256Digest::of_bytes(b"interface")
            },
            "implementation": {
                "descriptor": Sha256Digest::of_bytes(b"implementation"),
                "artifact": {
                    "content": Sha256Digest::of_bytes(b"artifact"),
                    "store_path": "/nix/store/00000000000000000000000000000000-block-provider",
                    "nar_hash": Sha256Digest::of_bytes(b"nar"),
                    "closure": Sha256Digest::of_bytes(b"closure")
                },
                "handler": handler
            },
            "policy_revision": Sha256Digest::of_bytes(b"policy"),
            "boot_id": BOOT_ID,
            "challenge": Sha256Digest::of_bytes(b"challenge"),
            "maximum_age_millis": 1000,
            "control": {
                "attempt_remaining_millis": 1000,
                "recovery_remaining_millis": 1000,
                "cancelled": false
            }
        }))
        .expect("block-storage root request")
    }

    #[test]
    fn root_probe_accepts_only_its_selected_executable_role() {
        for (role, handler, interface) in [
            (
                BlockStorageRootRole::Provisioning,
                "storage-provisioning-effects",
                "aos.systemd-repart.storage-provisioning-effects",
            ),
            (
                BlockStorageRootRole::ProvisioningMarker,
                "storage-provisioning-marker-observer",
                "aos.storage.provisioning-marker-observation",
            ),
            (
                BlockStorageRootRole::BootTransactionStorage,
                "boot-transaction-storage-view-effects",
                "aos.boot.transaction-storage-view-effects",
            ),
        ] {
            let selected = request(handler, interface);
            let observed = observe_root_for_boot(role, selected.clone(), BOOT_ID)
                .expect("selected block-storage root");
            assert_eq!(observed.boot_id, BOOT_ID);
            assert_eq!(observed.challenge, selected.challenge);
            assert!(
                observe_root_for_boot(role, selected, "11234567-89ab-cdef-0123-456789abcdef")
                    .is_err()
            );
        }

        let wrong_role = request(
            "storage-provisioning-marker-observer",
            "aos.storage.provisioning-marker-observation",
        );
        assert!(
            observe_root_for_boot(BlockStorageRootRole::Provisioning, wrong_role, BOOT_ID).is_err()
        );
    }
}
