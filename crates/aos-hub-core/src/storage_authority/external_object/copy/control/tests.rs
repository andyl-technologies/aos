//! Exact current permission and closed metadata boundary regression tests.

use super::*;
use crate::storage_authority::external_object::copy::tests::original;
use crate::storage_work::StorageCredentialSelector;

fn request() -> ExternalCopyRequest {
    let original = original();
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: "e".repeat(32),
        deployment_id: original.deployment_id.clone(),
        issued_at: 100,
        expires_at: 130,
        placement_id: original.destination.placement_id.get(),
        placement_resource_version: original.destination.resource_version.get(),
        binding_id: original.binding_id.get(),
        binding_resource_version: original.binding_resource_version.get(),
        binding_kind: "s3".into(),
        binding_snapshot_revision: Some(original.snapshot_revision.clone()),
        credential_references: vec![
            StorageCredentialSelector {
                purpose: "read".into(),
                generation: original.read_generation.get(),
            },
            StorageCredentialSelector {
                purpose: "write".into(),
                generation: original.write_generation.get(),
            },
        ],
        placement_prefix: original.destination.prefix.clone(),
        operation: StorageWorkOperation::CopyObject {
            source_placement_id: original.source.placement_id.get(),
            source_placement_resource_version: original.source.resource_version.get(),
            source_prefix: original.source.prefix.clone(),
            path: original.path.clone(),
            expected_size: original.source_object.bytes.get() as u64,
            expected_etag: original.source_object.etag.clone(),
        },
    };
    ExternalCopyRequest::new(
        original,
        CopyClaim {
            operation_resource_version: LeaseInteger::new(2).unwrap(),
            claim_token: "c".repeat(32),
            expires_at: LeaseInteger::new(200).unwrap(),
        },
        plan,
        CopyControl::Advance,
        100,
    )
    .unwrap()
}

fn progress() -> CopyProgress {
    CopyProgress {
        phase: CopyPhase::Creating,
        completed_parts: 0,
        copied_bytes: LeaseInteger::new(0).unwrap(),
        pending: false,
        destination: None,
        sha256: None,
    }
}

#[test]
fn application_permission_binds_claim_snapshot_and_exact_source_selectors() {
    let original = request();
    original.validate("deployment", 100).unwrap();

    let mut changed = original.clone();
    changed.plan.binding_resource_version += 1;
    assert!(changed.validate("deployment", 100).is_err());
    changed = original.clone();
    changed.plan.credential_references[0].generation += 1;
    assert!(changed.validate("deployment", 100).is_err());
    changed = original.clone();
    changed.claim.expires_at = LeaseInteger::new(130).unwrap();
    assert!(changed.validate("deployment", 100).is_err());
    changed = original.clone();
    if let StorageWorkOperation::CopyObject { source_prefix, .. } = &mut changed.plan.operation {
        *source_prefix = "unsealed-source/".into();
    }
    assert!(changed.validate("deployment", 100).is_err());
    assert!(original.validate("another-deployment", 100).is_err());
    assert!(original.validate("deployment", 131).is_err());
}

#[test]
fn public_controls_cannot_supply_sha_continuation_or_provider_receipts() {
    for field in ["source_state", "receipt", "write_lease", "provider_body"] {
        let mut value = serde_json::to_value(request()).unwrap();
        value[field] = serde_json::json!({"forged": true});
        assert!(serde_json::from_value::<ExternalCopyRequest>(value).is_err());
    }
    let mut value = serde_json::to_value(request()).unwrap();
    value["control"] = serde_json::json!({"kind": "part", "number": 1});
    assert!(serde_json::from_value::<ExternalCopyRequest>(value).is_err());
}

#[test]
fn exact_request_reply_mac_and_time_are_checked_after_await() {
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let other = StorageWorkKey::new([8_u8; 32]).unwrap();
    let request = request();
    let (body, signature) = request.sign(&key, "deployment", 100).unwrap();
    ExternalCopyRequest::authenticate(&key, &signature, &body, "deployment", 100).unwrap();
    assert!(
        ExternalCopyRequest::authenticate(&other, &signature, &body, "deployment", 100).is_err()
    );

    let reply = ExternalCopyReply::new(&request, progress()).unwrap();
    let (body, signature) = reply.sign(&key, &request).unwrap();
    ExternalCopyReply::authenticate(&key, &signature, &body, &request, 101).unwrap();
    assert!(ExternalCopyReply::authenticate(&key, &signature, &body, &request, 131).is_err());
    assert!(ExternalCopyReply::authenticate(&other, &signature, &body, &request, 101).is_err());

    let mut changed = request.clone();
    changed.claim.claim_token = "d".repeat(32);
    assert!(ExternalCopyReply::authenticate(&key, &signature, &body, &changed, 101).is_err());
    assert!(ExternalCopyRequest::authenticate(&key, &signature, &body, "deployment", 101).is_err());
}

#[test]
fn positive_close_requires_full_ranges_hash_and_actual_provider_version() {
    let original = request().original;
    let mut value = progress();
    value.phase = CopyPhase::Closed;
    assert!(value.validate(&original).is_err());
    value.completed_parts = 1;
    value.copied_bytes = original.source_object.bytes;
    value.sha256 = Some("d".repeat(64));
    value.destination = Some(CopySourceObject {
        provider_version: "actual-positive-version".into(),
        etag: "\"actual-positive-tag\"".into(),
        bytes: original.source_object.bytes,
    });
    value.validate(&original).unwrap();
    value.pending = true;
    assert!(value.validate(&original).is_err());
    value.pending = false;
    value.destination.as_mut().unwrap().provider_version = "null".into();
    assert!(value.validate(&original).is_err());
}
