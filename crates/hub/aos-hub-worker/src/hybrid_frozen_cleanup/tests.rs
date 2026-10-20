//! Frozen cleanup HEAD boundaries executable without Workers runtime bindings.

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use super::*;

fn request() -> Value {
    let credential = b"retained-access:retained-secret:fixture-region";
    let hash = "a".repeat(64);
    json!({
        "version": 1,
        "request_id": "b".repeat(32),
        "action_id": "action-1",
        "claim_token": "claim-1",
        "lease_expires_at": 200,
        "access": {
            "registry_id": 1,
            "placement_id": 2,
            "placement_name": "frozen-placement",
            "placement_prefix": "old-placement",
            "placement_resource_version": 3,
            "placement_write_spec_version": 4,
            "placement_observation_version": 5,
            "binding_id": 6,
            "binding_resource_version": 7,
            "binding_write_revision": 8,
            "delete_credential_generation": 1,
            "delete_capability_fingerprint": "conditional-delete-v1",
            "delete_capability_resource_version": 9
        },
        "publication": {
            "snapshot": {
                "version": 1,
                "deployment_id": "deployment-1",
                "binding_id": 6,
                "binding_resource_version": 7,
                "binding_stable_id": "binding-1",
                "binding_kind": "s3",
                "object_bucket": "fixture-bucket",
                "object_prefix": "binding-prefix",
                "endpoint_scheme": "https",
                "endpoint_host_kind": "dns",
                "endpoint_host_bytes": b"storage.example.test".to_vec(),
                "endpoint_port": 443,
                "signing_region": "fixture-region",
                "access_mode": "private",
                "credentials": [{
                    "purpose": "delete",
                    "generation": 1,
                    "secret_version_ref": "worker://fixture/delete/v1",
                    "fingerprint": hex::encode(Sha256::digest(credential))
                }],
                "issued_at": 100,
                "expires_at": 130
            },
            "materials": [{
                "selector": {"purpose": "delete", "generation": 1},
                "value_base64": base64::engine::general_purpose::STANDARD.encode(credential)
            }]
        },
        "path": format!("oci/blobs/sha256/{hash}"),
        "expected_hash": format!("sha256:{hash}"),
        "expected_size": 1024,
        "expected_etag": "\"reviewed-etag\"",
        "operation": "head"
    })
}

fn authorize(value: &Value) -> FrozenCleanupHead {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let body = serde_json::to_vec(value).unwrap();
    let signature = key.sign_frozen_cleanup_body(&body).unwrap();
    FrozenCleanupHead::authorize(&key, &signature, &body, "deployment-1", 101).unwrap()
}

#[test]
fn frozen_cleanup_head_signs_only_exact_key_with_retained_delete_credential() {
    let grant = authorize(&request());
    let url = url::Url::parse(grant.signed_url()).unwrap();

    assert_eq!(url.host_str(), Some("storage.example.test"));
    assert_eq!(
        url.path(),
        format!(
            "/fixture-bucket/binding-prefix/old-placement/oci/blobs/sha256/{}",
            "a".repeat(64)
        )
    );
    let credential = url
        .query_pairs()
        .find(|(name, _)| name == "X-Amz-Credential")
        .unwrap()
        .1;
    assert!(credential.starts_with("retained-access/"));
    assert!(credential.contains("/fixture-region/s3/aws4_request"));
    assert!(!grant.signed_url().contains("retained-secret"));
}

#[test]
fn frozen_cleanup_head_rejects_wrong_domain_deployment_time_and_claim_bytes() {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let body = serde_json::to_vec(&request()).unwrap();
    let signature = key.sign_frozen_cleanup_body(&body).unwrap();

    assert!(FrozenCleanupHead::authorize(
        &key,
        &key.sign_body(&body).unwrap(),
        &body,
        "deployment-1",
        101
    )
    .is_err());
    for (deployment, now) in [("other", 101), ("deployment-1", 131), ("deployment-1", 94)] {
        assert!(FrozenCleanupHead::authorize(&key, &signature, &body, deployment, now).is_err());
    }
    for field in ["request_id", "action_id", "claim_token"] {
        let mut changed = request();
        changed[field] = json!("c".repeat(32));
        let changed = serde_json::to_vec(&changed).unwrap();
        assert!(
            FrozenCleanupHead::authorize(&key, &signature, &changed, "deployment-1", 101).is_err()
        );
    }
}

#[test]
fn frozen_cleanup_head_rejects_signed_delete_and_reselected_scope() {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let mutations: &[fn(&mut Value)] = &[
        |value| value["operation"] = json!("delete_if_matches"),
        |value| value["path"] = json!(format!("oci/blobs/sha256/{}", "c".repeat(64))),
        |value| value["access"]["delete_credential_generation"] = json!(2),
        |value| value["publication"]["snapshot"]["credentials"][0]["purpose"] = json!("read"),
        |value| value["publication"]["materials"][0]["value_base64"] = json!("d3Jvbmc="),
    ];

    for mutate in mutations {
        let mut value = request();
        mutate(&mut value);
        let body = serde_json::to_vec(&value).unwrap();
        let signature = key.sign_frozen_cleanup_body(&body).unwrap();
        assert!(
            FrozenCleanupHead::authorize(&key, &signature, &body, "deployment-1", 101).is_err()
        );
    }
    let oversized = vec![b' '; MAX_FROZEN_CLEANUP_BYTES + 1];
    assert!(FrozenCleanupHead::authorize(
        &key,
        &signature_for(&key),
        &oversized,
        "deployment-1",
        101
    )
    .is_err());
}

fn signature_for(key: &StorageWorkKey) -> String {
    key.sign_frozen_cleanup_body(&serde_json::to_vec(&request()).unwrap())
        .unwrap()
}

#[test]
fn frozen_cleanup_head_correlates_replacement_metadata_and_exact_absence() {
    let value = request();
    let request: StorageFrozenCleanupRequest = serde_json::from_value(value.clone()).unwrap();
    let grant = authorize(&value);
    let body = grant
        .result(200, Some("2048"), Some("\"replacement-etag\""))
        .unwrap();
    let result: StorageFrozenCleanupHeadResult = serde_json::from_slice(&body).unwrap();

    assert!(body.len() <= MAX_FROZEN_CLEANUP_BYTES);
    result.validate_for(&request).unwrap();
    let object = result.object.as_ref().unwrap();
    assert_eq!(object.key, request.object_key().unwrap());
    assert_eq!(object.size, 2048);
    assert_eq!(object.etag, "\"replacement-etag\"");

    let absent: StorageFrozenCleanupHeadResult =
        serde_json::from_slice(&grant.result(404, None, None).unwrap()).unwrap();
    absent.validate_for(&request).unwrap();
    assert!(absent.object.is_none());

    for status in [301, 302, 307, 403, 500] {
        assert!(grant.result(status, None, None).is_err());
    }
    for (size, etag) in [
        (None, Some("\"etag\"")),
        (Some("bad"), Some("\"etag\"")),
        (Some("1"), None),
        (Some("1"), Some("W/\"etag\"")),
    ] {
        assert!(grant.result(200, size, etag).is_err());
    }
    assert!(grant
        .result(200, Some("1"), Some(&format!("\"{}\"", "x".repeat(1025))))
        .is_err());
}

#[test]
fn frozen_cleanup_head_reply_rejects_different_request_action_claim_fingerprint_or_key() {
    let value = request();
    let request: StorageFrozenCleanupRequest = serde_json::from_value(value.clone()).unwrap();
    let grant = authorize(&value);
    let original: StorageFrozenCleanupHeadResult =
        serde_json::from_slice(&grant.result(200, Some("1024"), Some("\"etag\"")).unwrap())
            .unwrap();
    let mutations: &[fn(&mut StorageFrozenCleanupHeadResult)] = &[
        |reply| reply.request_id = "c".repeat(32),
        |reply| reply.action_id = "other-action".into(),
        |reply| reply.claim_token = "other-claim".into(),
        |reply| reply.claim_fingerprint = "c".repeat(64),
        |reply| reply.object.as_mut().unwrap().key = "another-key".into(),
    ];

    for mutate in mutations {
        let mut reply = original.clone();
        mutate(&mut reply);
        assert!(reply.validate_for(&request).is_err());
    }
}
