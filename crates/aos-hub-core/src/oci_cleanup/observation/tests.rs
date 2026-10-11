//! Retained body observations cannot replace current authentication or cleanup.

use super::*;
use crate::{
    mirror_guard::MirrorGuardIssuer,
    oci_cleanup::{ManagedOciCleanupOriginal, MAX_MANAGED_OCI_CLEANUP_BYTES},
    storage_authority::canonical_digest,
    storage_work::{StorageObjectIdentity, StorageWorkKey},
};

fn pair() -> (ManagedOciCleanupRequest, ManagedOciCleanupReply) {
    let upload = "a".repeat(32);
    let original = ManagedOciCleanupOriginal {
        upload_id: upload.clone(),
        upload_resource_version: 2,
        terminal_state: "cancelled".into(),
        finished_at: 99,
        registry_id: 1,
        repository_id: 2,
        writer_id: "fixture-writer".into(),
        token_id: "fixture-owner".into(),
        ordinal: 0,
        offset: 0,
        path: format!("oci/uploads/{upload}/chunks/0-retained"),
        sha256: "b".repeat(64),
        size: 17,
        placement_id: 3,
        placement_resource_version: 4,
        placement_prefix: "qualification/cleanup".into(),
        binding_id: 5,
        binding_resource_version: 6,
        binding_write_revision: 7,
        delete_capability_fingerprint: "fixture-delete-capability".into(),
        delete_capability_resource_version: 8,
    };
    let request = ManagedOciCleanupRequest {
        deployment_id: "fixture".into(),
        original,
        protected_profile_digest: "c".repeat(64),
        issuer: MirrorGuardIssuer {
            source_digest: "d".repeat(64),
            script_version: "fixture-source".into(),
        },
        clock_uncertainty_seconds: 2,
        nonce: "e".repeat(64),
        issued_at: 100,
        expires_at: 130,
    };
    let reply = ManagedOciCleanupReply {
        request_digest: canonical_digest(&request).unwrap(),
        original_digest: request.original.fingerprint().unwrap(),
        nonce: request.nonce.clone(),
        object: StorageObjectIdentity {
            key: request.original.key(),
            size: request.original.size,
            etag: "\"retained-strong-etag\"".into(),
            provider_version: Some("opaque-r2-version".into()),
        },
        receipt_digest: "f".repeat(64),
    };
    (request, reply)
}

fn decode(
    request: &ManagedOciCleanupRequest,
    reply: &ManagedOciCleanupReply,
) -> Result<(ManagedOciCleanupRequest, ManagedOciCleanupReply)> {
    decode_managed_oci_cleanup_observation(
        &serde_json::to_vec(request)?,
        &serde_json::to_vec(reply)?,
        "fixture",
    )
}

#[test]
fn retained_expired_pair_preserves_exact_metadata_without_live_permission() {
    let (request, reply) = pair();
    let observed = decode(&request, &reply).unwrap();

    assert_eq!(observed, (request.clone(), reply.clone()));
    assert!(request.validate("fixture", 99).is_err());
    assert!(request.validate("fixture", 100).is_ok());
    assert!(request.validate("fixture", 129).is_ok());
    assert!(request.validate("fixture", 130).is_err());
    assert!(request.validate("fixture", 131).is_err());

    let application = StorageWorkKey::new([1; 32]).unwrap();
    let physical = StorageWorkKey::new([2; 32]).unwrap();
    let (body, signature) = request.sign(&application).unwrap();
    assert!(ManagedOciCleanupRequest::authenticate(
        &application,
        &signature,
        &body,
        "fixture",
        130
    )
    .is_err());
    assert!(
        ManagedOciCleanupRequest::authenticate(&physical, &signature, &body, "fixture", 110)
            .is_err()
    );
    let (body, signature) = reply.sign(&request, &physical).unwrap();
    assert!(
        ManagedOciCleanupReply::authenticate(&request, &application, &signature, &body).is_err()
    );
}

#[test]
fn impossible_windows_audience_and_originals_refuse_historical_decoding() {
    for defect in [
        "empty",
        "reversed",
        "long",
        "zero",
        "uncertainty",
        "source",
        "original",
        "deployment",
    ] {
        let (mut request, reply) = pair();
        match defect {
            "empty" => request.expires_at = request.issued_at,
            "reversed" => request.expires_at = request.issued_at - 1,
            "long" => request.expires_at = request.issued_at + 31,
            "zero" => request.issued_at = 0,
            "uncertainty" => request.clock_uncertainty_seconds = 30,
            "source" => request.issuer.source_digest.clear(),
            "original" => request.original.terminal_state = "uploading".into(),
            "deployment" => request.deployment_id = "substituted".into(),
            _ => unreachable!(),
        }
        assert!(decode(&request, &reply).is_err(), "{defect}");
    }
}

#[test]
fn every_positive_reply_identity_stays_bound_to_the_original() {
    for defect in [
        "request",
        "original",
        "nonce",
        "key",
        "size",
        "version",
        "weak-etag",
        "receipt",
    ] {
        let (request, mut reply) = pair();
        match defect {
            "request" => reply.request_digest = "0".repeat(64),
            "original" => reply.original_digest = "0".repeat(64),
            "nonce" => reply.nonce = "0".repeat(64),
            "key" => reply.object.key.push_str("-foreign"),
            "size" => reply.object.size += 1,
            "version" => reply.object.provider_version = None,
            "weak-etag" => reply.object.etag = "W/\"weak\"".into(),
            "receipt" => reply.receipt_digest.clear(),
            _ => unreachable!(),
        }
        assert!(decode(&request, &reply).is_err(), "{defect}");
    }
}

#[test]
fn canonical_bound_and_complete_bodies_are_required_without_raw_payload_fallback() {
    let (request, reply) = pair();
    let request = serde_json::to_vec(&request).unwrap();
    let reply = serde_json::to_vec(&reply).unwrap();
    for defect in [
        "absent-request",
        "absent-reply",
        "truncated",
        "whitespace",
        "expanded",
        "oversize",
    ] {
        let mut offered = request.clone();
        let mut received = reply.clone();
        match defect {
            "absent-request" => offered.clear(),
            "absent-reply" => received.clear(),
            "truncated" => {
                received.pop();
            }
            "whitespace" => offered.push(b' '),
            "expanded" => {
                let mut value: serde_json::Value = serde_json::from_slice(&reply).unwrap();
                value["object"]["content_base64"] = serde_json::json!("cmF3");
                received = serde_json::to_vec(&value).unwrap();
            }
            "oversize" => offered.resize(MAX_MANAGED_OCI_CLEANUP_BYTES + 1, b' '),
            _ => unreachable!(),
        }
        assert!(
            decode_managed_oci_cleanup_observation(&offered, &received, "fixture").is_err(),
            "{defect}"
        );
    }
}
