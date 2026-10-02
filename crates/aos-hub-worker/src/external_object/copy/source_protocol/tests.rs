//! Exact protected source selectors, response substitution and cutoff refusals.

use super::*;
use aos_hub_core::storage_work::{StorageCredentialSelector, StorageWorkPlan};

fn fixture() -> (Request, CopySourceClosure) {
    let (object, config, original) = super::super::config::tests::protected_fixture();
    let selector = CopyOriginalSelector::from_original(&original).unwrap();
    let scope = config.domains[0]
        .selector_scope_for(&object, &selector, false)
        .unwrap();
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: "b".repeat(32),
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
    let closure = CopySourceClosure {
        guard_stamp: original.source_object.guard_stamp.clone().unwrap(),
        receipt_digest: original.source_receipt_digest.clone().unwrap(),
        sha256: original.expected_sha256.clone().unwrap(),
        bytes: original.source_object.bytes,
        etag: Some(original.source_object.etag.clone()),
    };
    let request = Request {
        domain: DOMAIN.into(),
        nonce: "a".repeat(64),
        profile_digest: original.profile_digest.clone(),
        expires_at: LeaseInteger::new(130).unwrap(),
        scope,
        selector: Some(selector),
        plan,
        capacity_transfer: None,
        operation: Operation::Range {
            original,
            read_lease: "actual-read-lease".into(),
            offset: 0,
            bytes: 11,
        },
    };
    request.validate().unwrap();
    (request, closure)
}

#[tokio::test]
async fn actual_capacity_ticket_binds_the_full_private_range_without_read_authority() {
    use crate::direct_upload::provider_capacity::{self, Class, transfer};

    let (mut request, _) = fixture();
    provider_capacity::configure(3).unwrap();
    let (destination, source) = transfer::split(
        provider_capacity::acquire_class(2, Class::Bulk).await.unwrap(),
    ).unwrap();
    let reservation = transfer::register(source, request.capacity_digest().unwrap()).unwrap();
    request.capacity_transfer = Some(reservation.ticket());
    request.validate().unwrap();

    let mut changed = request.clone();
    let Operation::Range { read_lease, .. } = &mut changed.operation else { panic!("actual range fixture") };
    read_lease.push_str("-different");
    assert!(changed.validate().is_err());
    let mut changed = request.clone();
    changed.plan.plan_id = "c".repeat(32);
    assert!(changed.validate().is_err());
    let mut changed = request.clone();
    changed.nonce = "d".repeat(64);
    assert!(changed.validate().is_err());
    let mut changed = request.clone();
    changed.operation = Operation::Lookup;
    assert!(changed.validate().is_err());
    assert_eq!(provider_capacity::observation().active, 2);

    drop(reservation);
    assert!(transfer::accept(request.capacity_transfer.as_ref().unwrap(),
        &request.capacity_digest().unwrap()).is_err());
    drop(destination);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[test]
fn protected_source_reply_binds_original_receipt_and_actual_application_deadline() {
    let (request, closure) = fixture();
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let body = serde_json::to_vec(&request).unwrap();
    let signature = key.sign_body(&body).unwrap();
    let decoded = authenticate(&key, &signature, &body).unwrap();
    let (reply, signature) = sign_reply(&key, &decoded, closure.clone()).unwrap();
    assert_eq!(
        verify_reply(&key, &request, &signature, &reply).unwrap(),
        closure
    );
    assert!(request.current(129).is_ok());
    assert!(request.current(130).is_err());
    assert!(request.current(69).is_err());

    let mut changed = request.clone();
    changed.nonce = "b".repeat(64);
    assert!(verify_reply(&key, &changed, &signature, &reply).is_err());
    let mut replaced = closure.clone();
    replaced.guard_stamp.incarnation =
        aos_hub_core::storage_authority::GuardIncarnation::parse("12").unwrap();
    assert!(sign_reply(&key, &request, replaced).is_err());
    let mut changed = closure.clone();
    changed.receipt_digest = "c".repeat(64);
    assert!(sign_reply(&key, &request, changed).is_err());
    let mut changed = closure;
    changed.sha256 = "d".repeat(64);
    assert!(sign_reply(&key, &request, changed).is_err());
}

#[test]
fn source_ranges_cannot_change_part_geometry_sql_target_or_extend_permission() {
    let (request, _) = fixture();
    for mismatch in 0..4 {
        let mut changed = request.clone();
        match mismatch {
            0 => {
                if let Operation::Range { offset, .. } = &mut changed.operation {
                    *offset = 1;
                }
            }
            1 => changed.plan.placement_resource_version += 1,
            2 => changed.expires_at = LeaseInteger::new(131).unwrap(),
            _ => {
                if let StorageWorkOperation::CopyObject { source_prefix, .. } =
                    &mut changed.plan.operation
                {
                    source_prefix.push_str("replacement");
                }
            }
        }
        assert!(changed.validate().is_err());
    }
}

#[test]
fn inventory_uses_its_own_bounded_read_plan_and_no_fabricated_copy_original() {
    let (mut request, closure) = fixture();
    let selector = request.selector.take().unwrap();
    request.plan.placement_id = selector.source.placement_id.get();
    request.plan.placement_resource_version = selector.source.resource_version.get();
    request.plan.placement_prefix = selector.source.prefix;
    request.plan.credential_references.truncate(1);
    request.plan.operation = StorageWorkOperation::InspectSha256 {
        path: selector.path,
        expected_sha256: Some(closure.sha256.clone()),
        max_source_bytes: 11,
    };
    request.operation = Operation::InspectRange {
        closure: closure.clone(),
        read_lease: "read-lease".into(),
        etag: closure.etag.clone().unwrap(),
        offset: 0,
        bytes: 11,
    };
    assert!(request.validate().is_ok());
    let mut changed = request.clone();
    if let StorageWorkOperation::InspectSha256 {
        max_source_bytes, ..
    } = &mut changed.plan.operation
    {
        *max_source_bytes = 10;
    }
    assert!(changed.validate().is_err());
    if let Operation::InspectRange { etag, .. } = &mut request.operation {
        *etag = "\"changed\"".into();
    }
    assert!(request.validate().is_err());
}
