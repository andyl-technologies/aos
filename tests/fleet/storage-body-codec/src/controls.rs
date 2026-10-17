//! Exact small control bodies through the existing shared observation predicates.
//!
//! Structural/correlation validation authenticates no reply, observes no live
//! permission and says nothing about provider work or Native chunk consumption.

use crate::{files, Case};
use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::{
        DirectAuthorityLookup, DirectAuthorityLookupReply, DirectFinalGuardLookup,
        DirectFinalGuardReply, DirectStorageCapabilitiesReply, DirectStorageCapabilitiesRequest,
        DIRECT_AUTHORITY_LOOKUP_PATH, DIRECT_FINAL_GUARD_PATH, MAX_DIRECT_CAPABILITY_BYTES,
        MAX_DIRECT_CONTROL_BYTES,
    },
    storage_work::{
        binding_custody::{
            StorageBindingAdoptionReply, StorageBindingAdoptionRequest, MAX_BINDING_CUSTODY_BYTES,
            STORAGE_BINDING_ADOPTION_PATH,
        },
        StorageCapabilities, STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH,
    },
};

pub(super) fn supports(path: &str) -> bool {
    matches!(
        path,
        STORAGE_CAPABILITIES_PATH
            | STORAGE_BINDING_ADOPTION_PATH
            | DIRECT_AUTHORITY_LOOKUP_PATH
            | DIRECT_FINAL_GUARD_PATH
    )
}

pub(super) fn decode(
    case: &Case,
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(&'static str, &'static str, String)> {
    ensure!(
        case.method == "POST"
            && case.phase.is_none()
            && case.original_ingress.is_none()
            && case.received_ingress.is_none(),
        "small control transport differs"
    );
    let bound = match case.path_and_query.as_str() {
        STORAGE_BINDING_ADOPTION_PATH => MAX_BINDING_CUSTODY_BYTES,
        STORAGE_CAPABILITIES_PATH => MAX_DIRECT_CAPABILITY_BYTES,
        _ => MAX_DIRECT_CONTROL_BYTES,
    };
    ensure!(
        request.len() <= bound && reply.len() <= bound,
        "small control bound differs"
    );
    if case.status != 200 {
        ensure!(
            case.response_content_type.as_deref() == Some("text/plain; charset=utf-8"),
            "small control refusal type differs"
        );
        let id = match case.path_and_query.as_str() {
            DIRECT_AUTHORITY_LOOKUP_PATH | DIRECT_FINAL_GUARD_PATH => {
                ensure!(
                    case.status == 409 && reply == b"direct storage authority lookup refused",
                    "authority refusal body differs"
                );
                if case.path_and_query == DIRECT_AUTHORITY_LOOKUP_PATH {
                    let original: DirectAuthorityLookup = serde_json::from_slice(request)?;
                    original.validate_observation_shape(deployment)?;
                    original.request_nonce
                } else {
                    let original: DirectFinalGuardLookup = serde_json::from_slice(request)?;
                    original.validate_observation_shape(deployment)?;
                    original.request_nonce
                }
            }
            STORAGE_BINDING_ADOPTION_PATH => {
                ensure!(
                    case.status == 409 && reply == b"credential custody control refused",
                    "adoption refusal body differs"
                );
                let original: StorageBindingAdoptionRequest = serde_json::from_slice(request)?;
                original.validate_observation_shape(deployment)?;
                original.nonce
            }
            STORAGE_CAPABILITIES_PATH if request == STORAGE_CAPABILITIES_CHALLENGE => {
                ensure!(
                    case.status == 401
                        && matches!(
                            reply,
                            b"storage work signature is required"
                                | b"storage capability challenge is invalid"
                        ),
                    "capability refusal body differs"
                );
                files::digest(request)
            }
            _ => anyhow::bail!("unsupported small control refusal"),
        };
        return Ok(("storage_control_refused", "storage_control_metadata", id));
    }
    ensure!(
        case.response_content_type.as_deref() == Some("application/json"),
        "small control reply type differs"
    );
    let (operation, id) = match case.path_and_query.as_str() {
        DIRECT_AUTHORITY_LOOKUP_PATH => {
            let original: DirectAuthorityLookup = serde_json::from_slice(request)?;
            original.validate_observation_shape(deployment)?;
            let response: DirectAuthorityLookupReply = serde_json::from_slice(reply)?;
            response.validate_observation_for(&original)?;
            ("direct_authority_lookup", original.request_nonce)
        }
        DIRECT_FINAL_GUARD_PATH => {
            let original: DirectFinalGuardLookup = serde_json::from_slice(request)?;
            original.validate_observation_shape(deployment)?;
            let response: DirectFinalGuardReply = serde_json::from_slice(reply)?;
            response.validate_observation_for(&original)?;
            ("direct_final_guard", original.request_nonce)
        }
        STORAGE_BINDING_ADOPTION_PATH => {
            let original: StorageBindingAdoptionRequest = serde_json::from_slice(request)?;
            original.validate_observation_shape(deployment)?;
            let response: StorageBindingAdoptionReply = serde_json::from_slice(reply)?;
            response.validate_observation_for(&original)?;
            ("binding_adoption", original.nonce)
        }
        STORAGE_CAPABILITIES_PATH if request == STORAGE_CAPABILITIES_CHALLENGE => {
            ensure!(reply.len() <= 4096, "legacy capability bound differs");
            let response: StorageCapabilities = serde_json::from_slice(reply)?;
            aos_hub::storage_work::validate_capabilities_for_test(deployment, &response)?;
            ("legacy_storage_capabilities", files::digest(request))
        }
        STORAGE_CAPABILITIES_PATH => {
            let original: DirectStorageCapabilitiesRequest = serde_json::from_slice(request)?;
            ensure!(
                original.deployment_id == deployment,
                "capability audience differs"
            );
            let response: DirectStorageCapabilitiesReply = serde_json::from_slice(reply)?;
            response.validate_for(&original)?;
            ("direct_storage_capabilities", original.request_nonce)
        }
        _ => anyhow::bail!("unsupported small control"),
    };
    Ok((operation, "storage_control_metadata", id))
}
