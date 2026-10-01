//! Original challenge, secret-free replies, and independent purpose MAC tests.

use super::*;
use crate::storage_work::{StorageCredentialReference, StorageCredentialSelector};
use base64::Engine as _;

fn request() -> StorageCredentialCustodyProbe {
    StorageCredentialCustodyProbe {
        version: 1,
        nonce: "aa".repeat(32),
        issued_at: 100,
        expires_at: 130,
        operation_id: "queued-operation-original".into(),
        probe_token: "bb".repeat(32),
        head_resource_version: 7,
        snapshot: StorageBindingSnapshot {
            version: 1,
            deployment_id: "fixture-deployment".into(),
            binding_id: 2,
            binding_resource_version: 3,
            binding_stable_id: "fixture-binding".into(),
            binding_kind: "s3".into(),
            object_bucket: "private-bucket".into(),
            object_prefix: "protected".into(),
            endpoint_scheme: "https".into(),
            endpoint_host_kind: "dns".into(),
            endpoint_host_bytes: b"storage.example.test".to_vec(),
            endpoint_port: Some(443),
            signing_region: "fixture-region".into(),
            access_mode: "private".into(),
            credentials: vec![StorageCredentialReference {
                purpose: "read".into(),
                generation: 5,
                secret_version_ref: "secret://fixture/provider/v5".into(),
                fingerprint: hex::encode(Sha256::digest(b"fixture-provider-material")),
            }],
            issued_at: 100,
            expires_at: 130,
        },
    }
}

#[test]
fn stage_reply_omits_material_and_binds_complete_original() {
    let key = StorageWorkKey::new("fixture-custody-key-independent-0001").unwrap();
    let staged = StorageCredentialCustodyStage {
        request: request(),
        material_not_after: 500,
        material: StorageCredentialMaterial {
            selector: StorageCredentialSelector {
                purpose: "read".into(),
                generation: 5,
            },
            value_base64: base64::engine::general_purpose::STANDARD
                .encode(b"fixture-provider-material"),
        },
    };
    staged.validate("fixture-deployment", 110).unwrap();
    let signed_request = sign_storage_credential_custody_stage(&key, &staged).unwrap();
    let signed = sign_storage_credential_custody_stage_reply(
        &key,
        &StorageCredentialCustodyStageReply {
            request: staged.request.clone(),
            material_not_after: 500,
            stage_body_sha256: hex::encode(Sha256::digest(&signed_request.body)),
        },
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&signed.body).contains("value_base64"));
    verify_storage_credential_custody_stage_reply(
        &key,
        &signed.signature,
        &signed.body,
        &staged,
        110,
    )
    .unwrap();
    let mut wrong = staged;
    wrong.request.head_resource_version += 1;
    assert!(verify_storage_credential_custody_stage_reply(
        &key,
        &signed.signature,
        &signed.body,
        &wrong,
        110
    )
    .is_err());
}

#[test]
fn probe_reply_requires_fresh_exact_task_nonce_and_purpose() {
    let key = StorageWorkKey::new("fixture-custody-key-independent-0001").unwrap();
    let original = request();
    let signed = sign_storage_credential_custody_probe_reply(
        &key,
        &StorageCredentialCustodyProbeReply {
            request: original.clone(),
            observed_at: 110,
            evidence: StorageCredentialProbeEvidence {
                valid: true,
                conditional_writes_supported: false,
                error: None,
                evidence: serde_json::json!({"getStatus":404}),
            },
        },
    )
    .unwrap();
    verify_storage_credential_custody_probe_reply(
        &key,
        &signed.signature,
        &signed.body,
        &original,
        111,
    )
    .unwrap();
    let mut wrong = original.clone();
    wrong.nonce = "cc".repeat(32);
    assert!(verify_storage_credential_custody_probe_reply(
        &key,
        &signed.signature,
        &signed.body,
        &wrong,
        111
    )
    .is_err());
    wrong = original.clone();
    wrong.operation_id = "replacement-operation".into();
    assert!(verify_storage_credential_custody_probe_reply(
        &key,
        &signed.signature,
        &signed.body,
        &wrong,
        111
    )
    .is_err());
    assert!(verify_storage_credential_custody_probe_reply(
        &key,
        &signed.signature,
        &signed.body,
        &original,
        130
    )
    .is_err());
    assert!(verify_storage_credential_custody_probe(
        &key,
        &signed.signature,
        &signed.body,
        "fixture-deployment",
        111
    )
    .is_err());
    let mut altered = signed.body.clone();
    altered.push(b' ');
    assert!(verify_storage_credential_custody_probe_reply(
        &key,
        &signed.signature,
        &altered,
        &original,
        111
    )
    .is_err());
}

#[test]
fn cold_adoption_accepts_current_exact_snapshot_without_rotating_eligibility() {
    let key = StorageWorkKey::new("fixture-custody-key-independent-0001").unwrap();
    let mut expected = request().snapshot;
    expected.issued_at = 110;
    expected.expires_at = 3710;
    let request = StorageBindingAdoptionRequest {
        version: 1,
        nonce: "dd".repeat(32),
        issued_at: 110,
        expires_at: 140,
        expected,
    };
    let mut acknowledged = request.expected.clone();
    acknowledged.issued_at = 100;
    acknowledged.expires_at = 3700;
    let signed = sign_storage_binding_adoption_reply(
        &key,
        &StorageBindingAdoptionReply {
            request: request.clone(),
            acknowledged,
        },
    )
    .unwrap();
    verify_storage_binding_adoption_reply(&key, &signed.signature, &signed.body, &request, 115)
        .unwrap();
    let mut wrong = request.clone();
    wrong.expected.credentials[0].generation += 1;
    assert!(verify_storage_binding_adoption_reply(
        &key,
        &signed.signature,
        &signed.body,
        &wrong,
        115
    )
    .is_err());
    assert!(verify_storage_binding_adoption_reply(
        &key,
        &signed.signature,
        &signed.body,
        &request,
        140
    )
    .is_err());
}

fn adoption_observation_fixture() -> (StorageBindingAdoptionRequest, StorageBindingAdoptionReply) {
    let mut expected = request().snapshot;
    expected.issued_at = 110;
    expected.expires_at = 3710;
    let original = StorageBindingAdoptionRequest {
        version: 1,
        nonce: "dd".repeat(32),
        issued_at: 110,
        expires_at: 140,
        expected,
    };
    let mut acknowledged = original.expected.clone();
    acknowledged.issued_at = 100;
    acknowledged.expires_at = 3700;
    let reply = StorageBindingAdoptionReply {
        request: original.clone(),
        acknowledged,
    };
    (original, reply)
}

#[test]
fn retained_adoption_observation_preserves_live_deadline_and_mac_checks() {
    let key = StorageWorkKey::new("fixture-custody-key-independent-0001").unwrap();
    let (original, reply) = adoption_observation_fixture();
    let signed = sign_storage_binding_adoption_reply(&key, &reply).unwrap();

    reply.validate_observation_for(&original).unwrap();
    verify_storage_binding_adoption_reply(&key, &signed.signature, &signed.body, &original, 115)
        .unwrap();
    for now in [109, 140, 10_000] {
        assert!(verify_storage_binding_adoption_reply(
            &key,
            &signed.signature,
            &signed.body,
            &original,
            now,
        )
        .is_err());
    }
    assert!(verify_storage_binding_adoption_reply(
        &key,
        &"00".repeat(32),
        &signed.body,
        &original,
        115,
    )
    .is_err());
}

#[test]
fn adoption_observation_normalizes_only_snapshot_times() {
    let (original, reply) = adoption_observation_fixture();
    let changes: [fn(&mut StorageBindingAdoptionReply); 4] = [
        |reply: &mut StorageBindingAdoptionReply| reply.acknowledged.credentials[0].generation += 1,
        |reply: &mut StorageBindingAdoptionReply| {
            reply.acknowledged.object_prefix.push_str("/other")
        },
        |reply: &mut StorageBindingAdoptionReply| {
            reply.acknowledged.endpoint_host_bytes = b"other.example.test".to_vec();
        },
        |reply: &mut StorageBindingAdoptionReply| reply.request.nonce = "ee".repeat(32),
    ];
    for change in changes {
        let mut changed = reply.clone();
        change(&mut changed);
        assert!(changed.validate_observation_for(&original).is_err());
    }

    let mut changed = reply.clone();
    changed.acknowledged.expires_at = changed.acknowledged.issued_at + 3601;
    assert!(changed.validate_observation_for(&original).is_err());
    changed.acknowledged.expires_at = changed.acknowledged.issued_at - 1;
    assert!(changed.validate_observation_for(&original).is_err());
}

#[test]
fn adoption_observation_retains_original_nonce_audience_and_intrinsic_ttl() {
    let (original, _) = adoption_observation_fixture();
    assert!(original
        .validate_observation_shape("other-deployment")
        .is_err());
    let changes: [fn(&mut StorageBindingAdoptionRequest); 5] = [
        |request: &mut StorageBindingAdoptionRequest| request.version = 2,
        |request: &mut StorageBindingAdoptionRequest| request.nonce = "not-a-digest".into(),
        |request: &mut StorageBindingAdoptionRequest| request.issued_at = 0,
        |request: &mut StorageBindingAdoptionRequest| request.expires_at = request.issued_at,
        |request: &mut StorageBindingAdoptionRequest| request.expires_at = request.issued_at + 31,
    ];
    for change in changes {
        let mut changed = original.clone();
        change(&mut changed);
        assert!(changed
            .validate_observation_shape("fixture-deployment")
            .is_err());
    }

    let mut value = serde_json::to_value(&original).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<StorageBindingAdoptionRequest>(value).is_err());
}

#[test]
fn snapshot_live_validation_keeps_issue_skew_and_inclusive_expiry() {
    let mut snapshot = request().snapshot;
    snapshot.issued_at = 115;
    snapshot.expires_at = 130;
    snapshot.validate("fixture-deployment", 110).unwrap();
    assert!(snapshot.validate("fixture-deployment", 109).is_err());
    snapshot.validate("fixture-deployment", 130).unwrap();
    assert!(snapshot.validate("fixture-deployment", 131).is_err());
    snapshot
        .validate_observation_shape("fixture-deployment")
        .unwrap();

    snapshot.endpoint_scheme = "http".into();
    assert!(snapshot
        .validate_observation_shape("fixture-deployment")
        .is_err());
    assert!(snapshot.validate("fixture-deployment", 120).is_err());
}

fn frozen_request() -> StorageFrozenCleanupCustodyRequest {
    let mut snapshot = request().snapshot;
    snapshot.credentials[0].purpose = "delete".into();
    StorageFrozenCleanupCustodyRequest {
        version: 1,
        nonce: "dd".repeat(32),
        issued_at: 100,
        expires_at: 130,
        request_id: "aa".repeat(16),
        action_id: "original-action".into(),
        claim_token: "live-claim".into(),
        lease_expires_at: 200,
        access: crate::storage_work::StorageFrozenCleanupAccess {
            registry_id: 1,
            placement_id: 4,
            placement_name: "fixture-placement".into(),
            placement_prefix: "placement".into(),
            placement_resource_version: 5,
            placement_write_spec_version: 6,
            placement_observation_version: 7,
            binding_id: 2,
            binding_resource_version: 3,
            binding_write_revision: 8,
            delete_credential_generation: 5,
            delete_capability_fingerprint: "conditional-delete-v1".into(),
            delete_capability_resource_version: 9,
        },
        snapshot,
        path: format!("oci/blobs/sha256/{}", "ee".repeat(32)),
        expected_hash: format!("sha256:{}", "ee".repeat(32)).parse().unwrap(),
        expected_size: 1024,
        expected_etag: Some("\"original-etag\"".into()),
        operation: crate::storage_work::StorageFrozenCleanupOperation::Head,
    }
}

#[test]
fn frozen_reply_requires_exact_claim_nonce_object_and_historical_reference() {
    let key = StorageWorkKey::new("fixture-custody-key-independent-0001").unwrap();
    let original = frozen_request();
    original.validate("fixture-deployment", 110).unwrap();
    let reply = StorageFrozenCleanupCustodyReply {
        request: original.clone(),
        observed_at: 110,
        result: crate::storage_work::StorageFrozenCleanupHeadResult {
            version: 1,
            request_id: original.request_id.clone(),
            action_id: original.action_id.clone(),
            claim_token: original.claim_token.clone(),
            claim_fingerprint: original.claim_fingerprint().unwrap(),
            object: Some(crate::storage_work::StorageObjectIdentity {
                key: format!("protected/placement/{}", original.path),
                size: 1024,
                etag: "\"original-etag\"".into(),
                provider_version: None,
            }),
        },
    };
    let signed = sign_storage_frozen_cleanup_custody_reply(&key, &reply).unwrap();
    verify_storage_frozen_cleanup_custody_reply(
        &key,
        &signed.signature,
        &signed.body,
        &original,
        111,
    )
    .unwrap();
    let mutations: &[fn(&mut StorageFrozenCleanupCustodyRequest)] = &[
        |request| request.nonce = "ff".repeat(32),
        |request| request.claim_token = "replacement-claim".into(),
        |request| {
            request.snapshot.credentials[0].secret_version_ref =
                "secret://fixture/provider/v6".into()
        },
        |request| request.access.binding_write_revision += 1,
        |request| request.expected_etag = Some("\"replacement-etag\"".into()),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(verify_storage_frozen_cleanup_custody_reply(
            &key,
            &signed.signature,
            &signed.body,
            &changed,
            111
        )
        .is_err());
    }
    assert!(verify_storage_frozen_cleanup_custody_reply(
        &key,
        &signed.signature,
        &signed.body,
        &original,
        130
    )
    .is_err());
    assert!(verify_storage_frozen_cleanup_custody(
        &key,
        &signed.signature,
        &signed.body,
        "fixture-deployment",
        111
    )
    .is_err());
}

#[test]
fn historical_recovery_acknowledges_exact_material_hash_without_echoing_secret() {
    let key = StorageWorkKey::new("fixture-custody-key-independent-0001").unwrap();
    let stage = StorageFrozenCleanupCredentialStage {
        request: frozen_request(),
        material_not_after: 500,
        material: StorageCredentialMaterial {
            selector: StorageCredentialSelector {
                purpose: "delete".into(),
                generation: 5,
            },
            value_base64: base64::engine::general_purpose::STANDARD
                .encode(b"fixture-provider-material"),
        },
    };
    stage.validate("fixture-deployment", 110).unwrap();
    let original = sign_storage_frozen_cleanup_credential_stage(&key, &stage).unwrap();
    let signed = sign_storage_frozen_cleanup_credential_stage_reply(
        &key,
        &StorageFrozenCleanupCredentialStageReply {
            request: stage.request.clone(),
            material_not_after: 500,
            stage_body_sha256: hex::encode(Sha256::digest(&original.body)),
        },
    )
    .unwrap();
    verify_storage_frozen_cleanup_credential_stage_reply(
        &key,
        &signed.signature,
        &signed.body,
        &stage,
        111,
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&signed.body).contains("value_base64"));
    let mut changed = stage;
    changed.material.value_base64 =
        base64::engine::general_purpose::STANDARD.encode(b"different-provider-material");
    assert!(verify_storage_frozen_cleanup_credential_stage_reply(
        &key,
        &signed.signature,
        &signed.body,
        &changed,
        111
    )
    .is_err());
}
