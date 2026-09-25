//! Boot-scoped root observation for the metadata package's terminal handlers.
//!
//! These handlers are stateless package programs. Their live assignment lasts
//! for the selected executable content within one kernel boot; resource-level
//! media, network, and trust checks remain with the admitted methods.

use std::fs;

use anyhow::{Context as _, Result, ensure};
use aos_provider_protocol::{
    RootObservationRequest, RootObservationResult, boot_scoped_handler_root,
};

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

#[derive(Clone, Copy)]
pub(crate) enum MetadataHandler {
    Acquisition,
    Policy,
}

pub(crate) fn observe_root(
    handler: MetadataHandler,
    request: RootObservationRequest,
) -> Result<RootObservationResult> {
    let native_boot_id = fs::read_to_string(BOOT_ID_PATH)
        .with_context(|| format!("reading metadata handler boot identity {BOOT_ID_PATH}"))?;
    observe_root_for_boot(handler, request, native_boot_id.trim())
}

fn observe_root_for_boot(
    handler: MetadataHandler,
    request: RootObservationRequest,
    native_boot_id: &str,
) -> Result<RootObservationResult> {
    let selected = request
        .implementation
        .handler
        .as_ref()
        .context("metadata root implementation has no handler")?;
    let valid_role = match handler {
        MetadataHandler::Acquisition => matches!(
            (selected.as_str(), request.interface.name.as_str()),
            (
                "storage-provisioning-platform-detector",
                "aos.metadata.storage-provisioning-platform-detection"
            ) | (
                "storage-provisioning-metadata-acquirer",
                "aos.metadata.storage-provisioning-acquisition"
            )
        ),
        MetadataHandler::Policy => {
            selected.as_str() == "storage-provisioning-input-authorizer"
                && request.interface.name.as_str()
                    == "aos.metadata.storage-provisioning-input-authorization"
        }
    };
    ensure!(
        valid_role,
        "selected metadata handler does not match this executable"
    );
    boot_scoped_handler_root(request, native_boot_id)
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::{InvocationControl, RootObservationRequest};

    use super::{MetadataHandler, observe_root_for_boot};

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
                    "store_path": "/nix/store/00000000000000000000000000000000-metadata",
                    "nar_hash": Sha256Digest::of_bytes(b"nar"),
                    "closure": Sha256Digest::of_bytes(b"closure")
                },
                "handler": handler
            },
            "policy_revision": Sha256Digest::of_bytes(b"policy"),
            "boot_id": BOOT_ID,
            "challenge": Sha256Digest::of_bytes(b"challenge"),
            "maximum_age_millis": 1000,
            "control": InvocationControl {
                attempt_remaining_millis: 1000,
                recovery_remaining_millis: 1000,
                cancelled: false,
            }
        }))
        .expect("metadata root request")
    }

    #[test]
    fn selected_handlers_observe_only_their_own_boot_and_executable_role() {
        for (handler, interface, executable) in [
            (
                "storage-provisioning-platform-detector",
                "aos.metadata.storage-provisioning-platform-detection",
                MetadataHandler::Acquisition,
            ),
            (
                "storage-provisioning-metadata-acquirer",
                "aos.metadata.storage-provisioning-acquisition",
                MetadataHandler::Acquisition,
            ),
            (
                "storage-provisioning-input-authorizer",
                "aos.metadata.storage-provisioning-input-authorization",
                MetadataHandler::Policy,
            ),
        ] {
            let selected = request(handler, interface);
            let observed = observe_root_for_boot(executable, selected.clone(), BOOT_ID)
                .expect("selected metadata root");
            assert_eq!(observed.boot_id, BOOT_ID);
            assert_eq!(observed.challenge, selected.challenge);
            assert!(observe_root_for_boot(executable, selected.clone(), "another-boot").is_err());
        }

        let policy = request(
            "storage-provisioning-input-authorizer",
            "aos.metadata.storage-provisioning-input-authorization",
        );
        assert!(observe_root_for_boot(MetadataHandler::Acquisition, policy, BOOT_ID).is_err());
    }
}
