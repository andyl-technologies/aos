//! Payload-free completion receipts for explicitly authenticated control handlers.
//!
//! Callers emit only after the existing handler accepts the request and constructs
//! the exact successful response. A receipt observes that handler completion;
//! it is neither a signature nor an execution permission. Independent capture
//! provenance must still join the original request and transported reply.
//!
//! ```text
//! storage_control_complete {version,route,compiledSource,requestBodySha256,
//! replyBodySha256,requestBytes,replyBytes,completedAtUnixMillis}
//! ```

use aos_hub_core::direct_upload::{
    valid_direct_digest, WireInteger, DIRECT_AUTHORITY_LOOKUP_PATH, DIRECT_FINAL_GUARD_PATH,
    MAX_DIRECT_CAPABILITY_BYTES, MAX_DIRECT_CONTROL_BYTES,
};
use aos_hub_core::mirror_guard::{
    batch::MIRROR_GUARD_BATCH_LOOKUP_PATH, MIRROR_GUARD_LOOKUP_PATH, MIRROR_GUARD_MAX_BYTES,
};
use aos_hub_core::storage_work::{
    binding_custody::{MAX_BINDING_CUSTODY_BYTES, STORAGE_BINDING_ADOPTION_PATH},
    MAX_BINDING_CONTROL_BYTES, STORAGE_BINDING_CONTROL_PATH, STORAGE_CAPABILITIES_PATH,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlCompletionReceipt<'a> {
    version: u8,
    route: &'a str,
    compiled_source: &'a str,
    request_body_sha256: &'a str,
    reply_body_sha256: &'a str,
    request_bytes: WireInteger,
    reply_bytes: WireInteger,
    completed_at_unix_millis: WireInteger,
}

fn maximum_bytes(route: &str) -> Option<usize> {
    match route {
        STORAGE_CAPABILITIES_PATH => Some(MAX_DIRECT_CAPABILITY_BYTES),
        STORAGE_BINDING_CONTROL_PATH => Some(MAX_BINDING_CONTROL_BYTES),
        STORAGE_BINDING_ADOPTION_PATH => Some(MAX_BINDING_CUSTODY_BYTES),
        DIRECT_AUTHORITY_LOOKUP_PATH | DIRECT_FINAL_GUARD_PATH => Some(MAX_DIRECT_CONTROL_BYTES),
        MIRROR_GUARD_LOOKUP_PATH | MIRROR_GUARD_BATCH_LOOKUP_PATH => Some(MIRROR_GUARD_MAX_BYTES),
        _ => None,
    }
}

fn completion<'a>(
    route: &'a str,
    source: &'a str,
    request_digest: &'a str,
    reply_digest: &'a str,
    request_bytes: usize,
    reply_bytes: usize,
    completed_at_unix_millis: u64,
) -> Option<ControlCompletionReceipt<'a>> {
    let maximum = maximum_bytes(route)?;
    if ![source, request_digest, reply_digest]
        .iter()
        .all(|value| valid_direct_digest(value))
        || request_bytes > maximum
        || reply_bytes > maximum
        || completed_at_unix_millis == 0
    {
        return None;
    }
    Some(ControlCompletionReceipt {
        version: 1,
        route,
        compiled_source: source,
        request_body_sha256: request_digest,
        reply_body_sha256: reply_digest,
        request_bytes: WireInteger::new(request_bytes as u64),
        reply_bytes: WireInteger::new(reply_bytes as u64),
        completed_at_unix_millis: WireInteger::new(completed_at_unix_millis),
    })
}

/// Emits exact byte commitments after an authenticated handler constructs its response.
///
/// No payload or authentication material is logged. Missing compiled identity,
/// invalid bounds or unavailable native hashing produce no completion receipt.
/// This telemetry never grants permission or replaces the existing handler checks.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn emit_completed(route: &str, request: &[u8], reply: &[u8]) {
    let Some(maximum) = maximum_bytes(route) else {
        return;
    };
    let Some(source) = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST") else {
        return;
    };
    if !valid_direct_digest(source) || request.len() > maximum || reply.len() > maximum {
        return;
    }

    let Ok(request_digest) = crate::digest::sha256_hex(request, maximum).await else {
        return;
    };
    let Ok(reply_digest) = crate::digest::sha256_hex(reply, maximum).await else {
        return;
    };
    let Some(receipt) = completion(
        route,
        source,
        &request_digest,
        &reply_digest,
        request.len(),
        reply.len(),
        worker::Date::now().as_millis(),
    ) else {
        return;
    };
    if let Ok(encoded) = serde_json::to_string(&receipt) {
        worker::console_log!("storage_control_complete {}", encoded);
    }
}

/// Observes the exact buffered response after an authenticated success branch.
///
/// Other statuses and streamed responses produce no receipt. The existing
/// response bytes, headers and authentication behavior remain unchanged.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn emit_buffered_response(
    route: &str,
    request: &[u8],
    response: &worker::Response,
) {
    if response.status_code() != 200 {
        return;
    }
    if let worker::ResponseBody::Body(reply) = response.body() {
        emit_completed(route, request, reply).await;
    }
}

/// Observes a bounded forwarded response after an authenticated success branch.
///
/// The clone is read only within the selected route's existing metadata bound.
/// Clone, read or hashing failures emit no receipt and never alter permission.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn emit_forwarded_response(
    route: &str,
    request: &[u8],
    response: &mut worker::Response,
) {
    if response.status_code() != 200 {
        return;
    }
    let Some(maximum) = maximum_bytes(route) else {
        return;
    };
    let Ok(cloned) = response.cloned() else {
        return;
    };
    let Ok(Some(reply)) = crate::hybrid::read_bounded_response(cloned, maximum).await else {
        return;
    };
    emit_completed(route, request, &reply).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn completion_contains_only_exact_hashes_counts_source_route_and_time() {
        let request = b"fixture-private-request-material";
        let reply = b"fixture-private-reply-token";
        let source = "ab".repeat(32);
        let request_digest = hex::encode(Sha256::digest(request));
        let reply_digest = hex::encode(Sha256::digest(reply));
        let receipt = completion(
            STORAGE_BINDING_CONTROL_PATH,
            &source,
            &request_digest,
            &reply_digest,
            request.len(),
            reply.len(),
            123_456,
        )
        .unwrap();
        let encoded = serde_json::to_string(&receipt).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();

        assert_eq!(value.as_object().unwrap().len(), 8);
        assert_eq!(value["compiledSource"], source);
        assert_eq!(value["requestBodySha256"], request_digest);
        assert_eq!(value["replyBodySha256"], reply_digest);
        assert_eq!(value["requestBytes"], request.len().to_string());
        assert_eq!(value["replyBytes"], reply.len().to_string());
        assert_eq!(value["completedAtUnixMillis"], "123456");
        assert!(!encoded.contains("fixture-private"));
        assert!(!encoded.contains("signature"));
    }

    #[test]
    fn completion_refuses_unselected_routes_invalid_identity_and_excessive_bytes() {
        let digest = "ab".repeat(32);
        assert!(completion(
            "/_internal/storage/unknown",
            &digest,
            &digest,
            &digest,
            1,
            1,
            1
        )
        .is_none());
        for route in [
            "/__hub/mirror-candidate-guard",
            "/__hub/mirror-candidate-guard-batch",
        ] {
            assert!(completion(route, &digest, &digest, &digest, 1, 1, 1).is_none());
        }
        assert!(completion(
            STORAGE_CAPABILITIES_PATH,
            "unknown",
            &digest,
            &digest,
            1,
            1,
            1
        )
        .is_none());
        assert!(completion(STORAGE_CAPABILITIES_PATH, &digest, "bad", &digest, 1, 1, 1).is_none());
        assert!(completion(
            STORAGE_CAPABILITIES_PATH,
            &digest,
            &digest,
            &digest,
            1,
            1,
            0
        )
        .is_none());
        for (request, reply) in [
            (MAX_DIRECT_CAPABILITY_BYTES + 1, 1),
            (1, MAX_DIRECT_CAPABILITY_BYTES + 1),
        ] {
            assert!(completion(
                STORAGE_CAPABILITIES_PATH,
                &digest,
                &digest,
                &digest,
                request,
                reply,
                1
            )
            .is_none());
        }
    }

    #[test]
    fn completion_retains_exact_route_specific_bounds() {
        let digest = "ab".repeat(32);
        for route in [
            STORAGE_CAPABILITIES_PATH,
            STORAGE_BINDING_CONTROL_PATH,
            STORAGE_BINDING_ADOPTION_PATH,
            DIRECT_AUTHORITY_LOOKUP_PATH,
            DIRECT_FINAL_GUARD_PATH,
            MIRROR_GUARD_LOOKUP_PATH,
            MIRROR_GUARD_BATCH_LOOKUP_PATH,
        ] {
            let maximum = maximum_bytes(route).unwrap();
            assert!(completion(route, &digest, &digest, &digest, maximum, maximum, 1).is_some());
            assert!(completion(route, &digest, &digest, &digest, maximum + 1, 0, 1).is_none());
        }
    }
}
