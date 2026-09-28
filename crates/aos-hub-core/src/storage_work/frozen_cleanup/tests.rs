//! Validation tests for exact-key retained cleanup grants.

use base64::Engine as _;

use super::*;
use crate::storage_work::{
    StorageBindingSnapshot, StorageCredentialMaterial, StorageCredentialReference,
    StorageCredentialSelector,
};

fn request() -> StorageFrozenCleanupRequest {
    let secret = b"fixture-access:fixture-secret:fixture-region";
    let hash = "a".repeat(64);

    StorageFrozenCleanupRequest {
        version: 1,
        request_id: "b".repeat(32),
        action_id: "action-1".into(),
        claim_token: "claim-1".into(),
        lease_expires_at: 200,
        access: StorageFrozenCleanupAccess {
            registry_id: 1,
            placement_id: 2,
            placement_name: "frozen".into(),
            placement_prefix: "old-placement".into(),
            placement_resource_version: 3,
            placement_write_spec_version: 4,
            placement_observation_version: 5,
            binding_id: 6,
            binding_resource_version: 7,
            binding_write_revision: 8,
            delete_credential_generation: 1,
            delete_capability_fingerprint: "conditional-delete-v1".into(),
            delete_capability_resource_version: 9,
        },
        publication: StorageBindingPublication {
            snapshot: StorageBindingSnapshot {
                version: 1,
                deployment_id: "deployment-1".into(),
                binding_id: 6,
                binding_resource_version: 7,
                binding_stable_id: "binding-1".into(),
                binding_kind: "s3".into(),
                object_bucket: "fixture-bucket".into(),
                object_prefix: "binding-prefix".into(),
                endpoint_scheme: "https".into(),
                endpoint_host_kind: "dns".into(),
                endpoint_host_bytes: b"storage.example.test".to_vec(),
                endpoint_port: Some(443),
                signing_region: "fixture-region".into(),
                access_mode: "private".into(),
                credentials: vec![StorageCredentialReference {
                    purpose: "delete".into(),
                    generation: 1,
                    secret_version_ref: "worker://fixture/delete/v1".into(),
                    fingerprint: hex::encode(Sha256::digest(secret)),
                }],
                issued_at: 100,
                expires_at: 130,
            },
            materials: vec![StorageCredentialMaterial {
                selector: StorageCredentialSelector {
                    purpose: "delete".into(),
                    generation: 1,
                },
                value_base64: base64::engine::general_purpose::STANDARD.encode(secret),
            }],
        },
        path: format!("oci/blobs/sha256/{hash}"),
        expected_hash: format!("sha256:{hash}").parse().unwrap(),
        expected_size: 1024,
        expected_etag: Some("\"fixture-etag\"".into()),
        operation: StorageFrozenCleanupOperation::DeleteIfMatches,
    }
}

#[test]
fn retained_generation_is_self_contained_and_key_is_exact() {
    let request = request();

    assert_eq!(request.validate("deployment-1", 101), Ok(()));
    assert_eq!(
        request.object_key().unwrap(),
        format!(
            "binding-prefix/old-placement/oci/blobs/sha256/{}",
            "a".repeat(64)
        )
    );
    assert_eq!(request.publication.snapshot.credentials.len(), 1);
    assert_eq!(
        request.publication.snapshot.credentials[0].purpose,
        "delete"
    );
}

#[test]
fn absence_head_cannot_authorize_unconditional_deletion() {
    let mut request = request();
    request.expected_etag = None;
    request.operation = StorageFrozenCleanupOperation::Head;

    assert_eq!(request.validate("deployment-1", 101), Ok(()));

    request.operation = StorageFrozenCleanupOperation::DeleteIfMatches;
    assert_eq!(
        request.validate("deployment-1", 101),
        Err(StorageWorkError::InvalidPlan)
    );
}

#[test]
fn identity_and_credential_changes_fail_closed() {
    let mutations: &[fn(&mut StorageFrozenCleanupRequest)] = &[
        |request| request.path = "oci/blobs/sha256/../other".into(),
        |request| request.expected_hash = format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
        |request| request.expected_etag = Some("W/\"weak\"".into()),
        |request| request.access.placement_prefix = "old%2fplacement".into(),
        |request| request.access.binding_resource_version += 1,
        |request| request.access.delete_credential_generation += 1,
        |request| request.publication.snapshot.binding_kind = "deployment_r2".into(),
        |request| request.publication.snapshot.credentials[0].purpose = "write".into(),
        |request| request.publication.materials[0].value_base64 = "d3Jvbmc=".into(),
        |request| request.expected_size = MAX_VERIFY_SOURCE_BYTES + 1,
    ];

    for (index, mutate) in mutations.iter().enumerate() {
        let mut request = request();
        mutate(&mut request);
        assert!(
            request.validate("deployment-1", 101).is_err(),
            "mutation {index}"
        );
    }
}

#[test]
fn grant_lifetime_cannot_outlive_lease_or_short_request_window() {
    let mut request = request();
    request.lease_expires_at = 129;
    assert_eq!(
        request.validate("deployment-1", 101),
        Err(StorageWorkError::InvalidTime)
    );

    request.lease_expires_at = 200;
    request.publication.snapshot.expires_at = 131;
    assert_eq!(
        request.validate("deployment-1", 101),
        Err(StorageWorkError::InvalidTime)
    );

    request.publication.snapshot.expires_at = 130;
    assert_eq!(
        request.validate("deployment-1", 131),
        Err(StorageWorkError::InvalidTime)
    );
    assert_eq!(
        request.validate("deployment-1", 94),
        Err(StorageWorkError::InvalidTime)
    );
    assert_eq!(
        request.validate("another-deployment", 101),
        Err(StorageWorkError::DeploymentMismatch)
    );
}

#[test]
fn receipt_fingerprint_survives_lease_renewal_but_not_changed_scope() {
    let mut request = request();
    let original = request.claim_fingerprint().unwrap();

    request.request_id = "d".repeat(32);
    request.claim_token = "claim-2".into();
    request.lease_expires_at = 300;
    request.publication.snapshot.issued_at = 200;
    request.publication.snapshot.expires_at = 230;
    request.operation = StorageFrozenCleanupOperation::Head;
    assert_eq!(request.claim_fingerprint().unwrap(), original);

    request.expected_size += 1;
    assert_ne!(request.claim_fingerprint().unwrap(), original);
}

#[test]
fn cleanup_signature_is_domain_separated_and_authenticates_scope() {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let body = serde_json::to_vec(&request()).unwrap();
    let signature = key.sign_frozen_cleanup_body(&body).unwrap();

    assert!(key
        .verify_frozen_cleanup(&signature, &body, "deployment-1", 101)
        .is_ok());
    assert!(key.verify_body(&signature, &body).is_err());
    assert!(key
        .verify_frozen_cleanup(&key.sign_body(&body).unwrap(), &body, "deployment-1", 101)
        .is_err());

    let mut changed = request();
    changed.action_id = "another-action".into();
    let changed = serde_json::to_vec(&changed).unwrap();
    assert!(key
        .verify_frozen_cleanup(&signature, &changed, "deployment-1", 101)
        .is_err());
}

#[test]
fn signed_unknown_operations_fields_and_oversized_bodies_are_rejected() {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let mut value = serde_json::to_value(request()).unwrap();

    value["operation"] = "put".into();
    let body = serde_json::to_vec(&value).unwrap();
    let signature = key.sign_frozen_cleanup_body(&body).unwrap();
    assert!(key
        .verify_frozen_cleanup(&signature, &body, "deployment-1", 101)
        .is_err());

    value["operation"] = "head".into();
    value["alternate_key"] = "another-object".into();
    let body = serde_json::to_vec(&value).unwrap();
    let signature = key.sign_frozen_cleanup_body(&body).unwrap();
    assert!(key
        .verify_frozen_cleanup(&signature, &body, "deployment-1", 101)
        .is_err());

    let oversized = vec![b' '; MAX_FROZEN_CLEANUP_BYTES + 1];
    assert!(key.sign_frozen_cleanup_body(&oversized).is_err());
    assert!(key
        .verify_frozen_cleanup(&signature, &oversized, "deployment-1", 101)
        .is_err());
}

#[test]
fn head_reply_binds_request_stable_scope_and_exact_object_metadata() {
    let mut request = request();
    request.operation = StorageFrozenCleanupOperation::Head;
    let result = StorageFrozenCleanupHeadResult {
        version: 1,
        request_id: request.request_id.clone(),
        action_id: request.action_id.clone(),
        claim_token: request.claim_token.clone(),
        claim_fingerprint: request.claim_fingerprint().unwrap(),
        object: Some(super::super::StorageObjectIdentity {
            provider_version: None,
            key: request.object_key().unwrap(),
            // A replacement still counts as present for an absence check.
            etag: "\"replacement\"".into(),
            size: 2048,
        }),
    };
    assert_eq!(result.validate_for(&request), Ok(()));

    let mutations: &[fn(&mut StorageFrozenCleanupHeadResult)] = &[
        |result| result.version += 1,
        |result| result.request_id = "c".repeat(32),
        |result| result.action_id = "another-action".into(),
        |result| result.claim_token = "another-lease".into(),
        |result| result.claim_fingerprint = "d".repeat(64),
        |result| result.object.as_mut().unwrap().key = "another/key".into(),
        |result| result.object.as_mut().unwrap().etag = "W/\"weak\"".into(),
        |result| result.object.as_mut().unwrap().size = MAX_VERIFY_SOURCE_BYTES + 1,
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut changed = result.clone();
        mutate(&mut changed);
        assert!(changed.validate_for(&request).is_err(), "mutation {index}");
    }

    let absent = StorageFrozenCleanupHeadResult {
        object: None,
        ..result
    };
    assert_eq!(absent.validate_for(&request), Ok(()));
    request.expected_size += 1;
    assert!(absent.validate_for(&request).is_err());
}
