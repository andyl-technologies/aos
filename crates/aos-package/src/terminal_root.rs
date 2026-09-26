//! Boot-scoped observations for terminal handlers shipped by the AOS package.
//!
//! Each caller supplies the handler and interface it actually implements.
//! Resource readiness remains in the admitted method, while this observation
//! identifies the selected executable in the current boot.

use std::fs;

use anyhow::{Context as _, Result, ensure};
use aos_provider_protocol::{
    RootObservationRequest, RootObservationResult, boot_scoped_handler_root,
};

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Observes one exact terminal role implemented by this package.
///
/// # Errors
///
/// Returns an error if the request is malformed, selects another handler or
/// interface, or names another boot.
pub(crate) fn observe_package_root(
    input: &[u8],
    handler: &str,
    interface: &str,
) -> Result<RootObservationResult> {
    let request: RootObservationRequest =
        aos_contract::canonical::from_slice(input, "AOS terminal root observation request")?;
    let native_boot_id = fs::read_to_string(BOOT_ID_PATH)
        .with_context(|| format!("reading AOS terminal boot identity {BOOT_ID_PATH}"))?;
    observe_root_for_boot(request, handler, interface, native_boot_id.trim())
}

fn observe_root_for_boot(
    request: RootObservationRequest,
    handler: &str,
    interface: &str,
    native_boot_id: &str,
) -> Result<RootObservationResult> {
    ensure!(
        request
            .implementation
            .handler
            .as_ref()
            .is_some_and(|selected| selected.as_str() == handler)
            && request.interface.name.as_str() == interface,
        "selected AOS terminal does not match this executable"
    );
    boot_scoped_handler_root(request, native_boot_id)
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::RootObservationRequest;

    use super::observe_root_for_boot;

    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    #[test]
    fn root_probe_rejects_changed_role_interface_and_boot() {
        let request: RootObservationRequest = serde_json::from_value(serde_json::json!({
            "schema": aos_provider_protocol::ROOT_OBSERVATION_REQUEST_SCHEMA,
            "provider": {
                "environment": {"authority":"system-image","key":"test","stage":"initrd"},
                "key": "configuration-evaluator"
            },
            "interface": {
                "name": "aos.configuration.storage-provisioning-evaluation",
                "abi": 1,
                "descriptor": Sha256Digest::of_bytes(b"interface")
            },
            "implementation": {
                "descriptor": Sha256Digest::of_bytes(b"implementation"),
                "artifact": {
                    "content": Sha256Digest::of_bytes(b"artifact"),
                    "store_path": "/nix/store/00000000000000000000000000000000-aos",
                    "nar_hash": Sha256Digest::of_bytes(b"nar"),
                    "closure": Sha256Digest::of_bytes(b"closure")
                },
                "handler": "storage-provisioning-configuration-evaluator"
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
        .expect("AOS terminal root request");
        let handler = "storage-provisioning-configuration-evaluator";
        let interface = "aos.configuration.storage-provisioning-evaluation";

        let observed = observe_root_for_boot(request.clone(), handler, interface, BOOT_ID)
            .expect("selected AOS terminal root");
        assert_eq!(observed.boot_id, BOOT_ID);
        assert_eq!(observed.challenge, request.challenge);
        assert!(
            observe_root_for_boot(request.clone(), "other-handler", interface, BOOT_ID).is_err()
        );
        assert!(
            observe_root_for_boot(request.clone(), handler, "other-interface", BOOT_ID).is_err()
        );
        assert!(
            observe_root_for_boot(
                request,
                handler,
                interface,
                "11234567-89ab-cdef-0123-456789abcdef"
            )
            .is_err()
        );
    }
}
