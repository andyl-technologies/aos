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
        provider_version: Some("actual-positive-version".into()),
        etag: "\"actual-positive-tag\"".into(),
        bytes: original.source_object.bytes,
        guard_stamp: None,
    });
    value.validate(&original).unwrap();
    value.pending = true;
    assert!(value.validate(&original).is_err());
    value.pending = false;
    value.destination.as_mut().unwrap().provider_version = Some("null".into());
    assert!(value.validate(&original).is_err());
}

#[test]
fn retained_copy_observation_preserves_correlation_without_renewing_permission() {
    use crate::storage_authority::external_object::copy::observation::decode_copy_control_observation;

    let request = request();
    let reply = ExternalCopyReply::new(&request, progress()).unwrap();
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let reply_bytes = serde_json::to_vec(&reply).unwrap();

    let observed =
        decode_copy_control_observation(&request_bytes, &reply_bytes, "deployment").unwrap();
    assert_eq!(observed, (request.clone(), reply.clone()));
    assert!(request.validate("deployment", 131).is_err());

    let mut changed = request.clone();
    changed.claim.claim_token = "d".repeat(32);
    let changed_bytes = serde_json::to_vec(&changed).unwrap();
    assert!(decode_copy_control_observation(&changed_bytes, &reply_bytes, "deployment").is_err());
    changed = request.clone();
    changed.plan.expires_at = changed.plan.issued_at - 1;
    assert!(changed.validate_observation_shape("deployment").is_err());
    assert!(decode_copy_control_observation(&request_bytes, &reply_bytes, "foreign").is_err());

    let mut noncanonical = request_bytes.clone();
    noncanonical.push(b' ');
    assert!(decode_copy_control_observation(&noncanonical, &reply_bytes, "deployment").is_err());
    assert!(decode_copy_control_observation(
        &request_bytes,
        &reply_bytes[..reply_bytes.len() - 1],
        "deployment"
    )
    .is_err());
    let mut reply = reply;
    reply.progress.copied_bytes = LeaseInteger::new(1).unwrap();
    assert!(decode_copy_control_observation(
        &request_bytes,
        &serde_json::to_vec(&reply).unwrap(),
        "deployment"
    )
    .is_err());
}

#[test]
fn retained_copy_metadata_observation_keeps_installed_profile_and_owner_exact() {
    use crate::storage_authority::external_object::copy::{
        metadata::{
            CopyMetadataProfile, CopyMetadataReply, CopyMetadataRequest, RetainedCopyOriginal,
        },
        observation::decode_copy_metadata_observation,
    };

    let control = request();
    let original = &control.original;
    let mut plan = control.plan.clone();
    plan.operation = StorageWorkOperation::Head {
        path: original.path.clone(),
    };
    plan.credential_references.truncate(1);
    let query = CopyMetadataRequest::new(
        original.topology.clone(),
        original.source.clone(),
        original.destination.clone(),
        Some(control.claim.clone()),
        plan,
        original.path.clone(),
        100,
    )
    .unwrap();
    let reply = CopyMetadataReply {
        version: 1,
        request_digest: canonical_digest(&query).unwrap(),
        profile: CopyMetadataProfile {
            binding_stable_id: original.binding_stable_id.clone(),
            binding_write_revision: original.binding_write_revision,
            profile_digest: original.profile_digest.clone(),
            part_bytes: original.part_bytes,
            read_generation: original.read_generation,
            write_generation: original.write_generation,
            protected_versionless: false,
        },
        retained: Some(RetainedCopyOriginal {
            original: original.clone(),
            progress: progress(),
        }),
        source_closure: None,
    };
    let request_bytes = serde_json::to_vec(&query).unwrap();
    let reply_bytes = serde_json::to_vec(&reply).unwrap();

    decode_copy_metadata_observation(&request_bytes, &reply_bytes, "deployment").unwrap();
    assert!(query.validate("deployment", 131).is_err());
    let mut changed = reply.clone();
    changed.profile.write_generation =
        LeaseInteger::new(original.write_generation.get() + 1).unwrap();
    assert!(decode_copy_metadata_observation(
        &request_bytes,
        &serde_json::to_vec(&changed).unwrap(),
        "deployment"
    )
    .is_err());
    changed = reply;
    changed.retained.as_mut().unwrap().original.path = "another-object".into();
    assert!(decode_copy_metadata_observation(
        &request_bytes,
        &serde_json::to_vec(&changed).unwrap(),
        "deployment"
    )
    .is_err());
}
