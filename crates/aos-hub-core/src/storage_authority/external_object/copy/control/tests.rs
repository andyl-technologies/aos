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
            source_binding_id: None,
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
    assert!(
        decode_copy_control_observation(
            &request_bytes,
            &reply_bytes[..reply_bytes.len() - 1],
            "deployment"
        )
        .is_err()
    );
    let mut reply = reply;
    reply.progress.copied_bytes = LeaseInteger::new(1).unwrap();
    assert!(
        decode_copy_control_observation(
            &request_bytes,
            &serde_json::to_vec(&reply).unwrap(),
            "deployment"
        )
        .is_err()
    );
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
        transfer: None,
    };
    let request_bytes = serde_json::to_vec(&query).unwrap();
    let reply_bytes = serde_json::to_vec(&reply).unwrap();

    decode_copy_metadata_observation(&request_bytes, &reply_bytes, "deployment").unwrap();
    assert!(query.validate("deployment", 131).is_err());
    let mut changed = reply.clone();
    changed.profile.write_generation =
        LeaseInteger::new(original.write_generation.get() + 1).unwrap();
    assert!(
        decode_copy_metadata_observation(
            &request_bytes,
            &serde_json::to_vec(&changed).unwrap(),
            "deployment"
        )
        .is_err()
    );
    changed = reply;
    changed.retained.as_mut().unwrap().original.path = "another-object".into();
    assert!(
        decode_copy_metadata_observation(
            &request_bytes,
            &serde_json::to_vec(&changed).unwrap(),
            "deployment"
        )
        .is_err()
    );
}

fn paired_request() -> ExternalCopyRequest {
    use crate::storage_authority::PhysicalStorageAuthorityId;
    use crate::storage_authority::external_object::copy::{
        CopyIncarnationMode, CopySourceBindingPin, CopyTransferPins,
    };
    let mut value = request();
    value.original.version = 3;
    value.original.source.binding_id = LeaseInteger::new(2).unwrap();
    value.original.source.prefix = value.original.destination.prefix.clone();
    value.original.expected_sha256 = Some("d".repeat(64));
    value.original.transfer = Some(CopyTransferPins {
        source_binding: CopySourceBindingPin {
            binding_id: value.original.source.binding_id,
            binding_stable_id: "independent-source".into(),
            binding_resource_version: LeaseInteger::new(7).unwrap(),
            snapshot_revision: "f".repeat(64),
            profile_digest: "c".repeat(64),
            binding_read_revision: LeaseInteger::new(9).unwrap(),
            read_generation: value.original.read_generation,
            physical_authority_id: PhysicalStorageAuthorityId::parse(
                "00000000-0000-4000-8000-000000000001",
            )
            .unwrap(),
        },
        source_incarnation: CopyIncarnationMode::ProviderVersion,
        destination_incarnation: CopyIncarnationMode::ProviderVersion,
        destination_physical_authority_id: PhysicalStorageAuthorityId::parse(
            "00000000-0000-4000-8000-000000000002",
        )
        .unwrap(),
        maximum_source_range_bytes: value.original.part_bytes,
    });
    if let StorageWorkOperation::CopyObject {
        source_binding_id,
        source_prefix,
        ..
    } = &mut value.plan.operation
    {
        *source_binding_id = Some(2);
        *source_prefix = value.original.source.prefix.clone();
    }
    // Destination Read is independently selected; it is not the source generation.
    value.plan.credential_references[0].generation = 19;
    let mut source = value.plan.clone();
    source.plan_id = "f".repeat(32);
    source.binding_id = 2;
    source.binding_resource_version = 7;
    source.binding_snapshot_revision = Some("f".repeat(64));
    source.placement_id = value.original.source.placement_id.get();
    source.placement_resource_version = value.original.source.resource_version.get();
    source.placement_prefix = value.original.source.prefix.clone();
    source.operation = StorageWorkOperation::Head {
        path: value.original.path.clone(),
    };
    source.credential_references = vec![StorageCredentialSelector {
        purpose: "read".into(),
        generation: value.original.read_generation.get(),
    }];
    ExternalCopyRequest::new_cross_binding(
        value.original,
        value.claim,
        value.plan,
        source,
        CopyControl::Advance,
        100,
    )
    .unwrap()
}

#[test]
fn paired_control_authenticates_both_plans_and_preserves_equal_relative_prefixes() {
    let value = paired_request();
    let key = StorageWorkKey::new("p".repeat(32)).unwrap();
    let (body, signature) = value.sign(&key, "deployment", 100).unwrap();
    assert_eq!(
        ExternalCopyRequest::authenticate(&key, &signature, &body, "deployment", 101).unwrap(),
        value
    );
    for mutate in 0..5 {
        let mut changed = value.clone();
        let source = changed.source_plan.as_mut().unwrap();
        match mutate {
            0 => source.binding_id = changed.plan.binding_id,
            1 => source.binding_snapshot_revision = changed.plan.binding_snapshot_revision.clone(),
            2 => source.credential_references[0].generation += 1,
            3 => source.expires_at -= 1,
            _ => source.placement_prefix = "other-prefix".into(),
        }
        assert!(changed.validate("deployment", 100).is_err());
    }
    let mut missing = value.clone();
    missing.source_plan = None;
    assert!(missing.validate("deployment", 100).is_err());
    if let StorageWorkOperation::CopyObject {
        source_binding_id, ..
    } = &mut missing.plan.operation
    {
        *source_binding_id = None;
    }
    assert!(missing.plan.validate("deployment", 100).is_err());
}

#[test]
fn paired_metadata_retains_independent_read_profile_and_refuses_source_drift() {
    use crate::storage_authority::external_object::copy::metadata::{
        CopyMetadataProfile, CopyMetadataReply, CopyMetadataRequest,
    };
    let value = paired_request();
    let mut destination = value.plan.clone();
    destination.operation = StorageWorkOperation::Head {
        path: value.original.path.clone(),
    };
    destination.credential_references.truncate(1);
    let query = CopyMetadataRequest::new_cross_binding(
        value.original.topology.clone(),
        value.original.source.clone(),
        value.original.destination.clone(),
        Some(value.claim.clone()),
        destination,
        value.source_plan.clone().unwrap(),
        value.original.path.clone(),
        100,
    )
    .unwrap();
    let mut reply = CopyMetadataReply {
        version: 1,
        request_digest: canonical_digest(&query).unwrap(),
        profile: CopyMetadataProfile {
            binding_stable_id: value.original.binding_stable_id.clone(),
            binding_write_revision: value.original.binding_write_revision,
            profile_digest: value.original.profile_digest.clone(),
            part_bytes: value.original.part_bytes,
            read_generation: LeaseInteger::new(19).unwrap(),
            write_generation: value.original.write_generation,
            protected_versionless: false,
        },
        retained: None,
        source_closure: None,
        transfer: value.original.transfer.clone(),
    };
    let selector = reply.selector(&query).unwrap();
    assert_eq!(selector.transfer, value.original.transfer);
    reply
        .transfer
        .as_mut()
        .unwrap()
        .source_binding
        .read_generation = LeaseInteger::new(3).unwrap();
    assert!(reply.selector(&query).is_err());
    reply.transfer = None;
    assert!(reply.selector(&query).is_err());
}

#[test]
fn legacy_control_omits_all_paired_fields() {
    let value = request();
    let json = serde_json::to_value(&value).unwrap();
    assert!(json.get("source_plan").is_none());
    assert!(json["plan"]["operation"].get("source_binding_id").is_none());
    let bytes = serde_json::to_vec(&value).unwrap();
    let decoded: ExternalCopyRequest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
}
