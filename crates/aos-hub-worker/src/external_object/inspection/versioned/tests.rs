//! Real canonical authentication, identity substitution and transfer admission.

use super::*;
use crate::external_object::copy::{
    config,
    source_protocol::{self, Operation},
};
use aos_hub_core::{
    storage_authority::lease::LeaseInteger,
    storage_work::{
        StorageCredentialSelector, StorageWorkKey, StorageWorkOperation, StorageWorkPlan,
    },
};

fn request() -> Request {
    let (object, config, original) = config::tests::fixture();
    let domain = &config.domains[0];
    let path = "info/refs";
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
        credential_references: vec![StorageCredentialSelector {
            purpose: "read".into(),
            generation: original.read_generation.get(),
        }],
        placement_prefix: original.destination.prefix.clone(),
        operation: StorageWorkOperation::InspectMetadata { path: path.into() },
    };
    Request {
        domain: source_protocol::DOMAIN.into(),
        nonce: "a".repeat(64),
        profile_digest: domain.commitment().unwrap(),
        expires_at: LeaseInteger::new(130).unwrap(),
        scope: object
            .scope(
                &domain.read_cohort,
                aos_hub_core::keymap::r2_key(
                    &domain.read_cohort.association.binding_prefix,
                    &plan.object_key(path).unwrap(),
                ),
            )
            .unwrap(),
        inspection: Some(super::super::selection::Selection::from_plan(&plan, path).unwrap()),
        selector: None,
        plan,
        capacity_transfer: None,
        operation: Operation::InspectVersionedLookup {
            read_lease: "unit-read-token-shape-only".into(),
        },
    }
}

fn source(request: &Request) -> StorageObjectIdentity {
    head_identity(
        request,
        200,
        Some("8"),
        Some("\"real-tag\""),
        Some("provider-version-1"),
        None,
    )
    .unwrap()
    .unwrap()
}

#[test]
fn actual_version_tag_size_and_representation_are_independent_fences() {
    let request = request();
    request.validate().unwrap();
    assert_eq!(source(&request).size, 8);
    for version in [None, Some("null"), Some("")] {
        assert!(
            head_identity(
                &request,
                200,
                Some("8"),
                Some("\"real-tag\""),
                version,
                None
            )
            .is_err()
        );
    }
    assert!(
        head_identity(
            &request,
            200,
            Some("8"),
            Some("W/\"real-tag\""),
            Some("version-1"),
            None
        )
        .is_err()
    );
    assert!(
        head_identity(
            &request,
            200,
            Some("999999999"),
            Some("\"real-tag\""),
            Some("version-1"),
            None
        )
        .is_err()
    );
    assert!(
        head_identity(
            &request,
            200,
            Some("8"),
            Some("\"real-tag\""),
            Some("version-1"),
            Some("gzip")
        )
        .is_err()
    );
    assert!(head_identity(&request, 403, None, None, None, None).is_err());
    assert!(
        head_identity(&request, 404, None, None, None, None)
            .unwrap()
            .is_none()
    );
    assert!(
        head_identity(
            &request,
            200,
            Some("0"),
            Some("\"empty-tag\""),
            Some("empty-version"),
            None
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn conditional_response_pins_every_actual_header_and_exact_interval() {
    let request = request();
    let source = source(&request);
    let check = |status, length, tag, version, range, encoding| {
        validate_range(&source, 2, 3, status, length, tag, version, range, encoding)
    };
    check(
        206,
        Some("3"),
        Some("\"real-tag\""),
        Some("provider-version-1"),
        Some("bytes 2-4/8"),
        None,
    )
    .unwrap();
    for changed in [
        check(
            200,
            Some("3"),
            Some("\"real-tag\""),
            Some("provider-version-1"),
            Some("bytes 2-4/8"),
            None,
        ),
        check(
            206,
            Some("4"),
            Some("\"real-tag\""),
            Some("provider-version-1"),
            Some("bytes 2-4/8"),
            None,
        ),
        check(
            206,
            Some("3"),
            Some("\"other\""),
            Some("provider-version-1"),
            Some("bytes 2-4/8"),
            None,
        ),
        check(
            206,
            Some("3"),
            Some("\"real-tag\""),
            Some("provider-version-2"),
            Some("bytes 2-4/8"),
            None,
        ),
        check(
            206,
            Some("3"),
            Some("\"real-tag\""),
            Some("provider-version-1"),
            Some("bytes 2-4/9"),
            None,
        ),
        check(
            206,
            Some("3"),
            Some("\"real-tag\""),
            Some("provider-version-1"),
            Some("bytes 2-4/8"),
            Some("gzip"),
        ),
    ] {
        assert!(changed.is_err());
    }
}

#[test]
fn genuine_empty_version_read_requires_a_real_conditional_eof_identity() {
    let request = request();
    let source = head_identity(
        &request,
        200,
        Some("0"),
        Some("\"empty-tag\""),
        Some("empty-version"),
        None,
    )
    .unwrap()
    .unwrap();
    validate_range(
        &source,
        0,
        0,
        200,
        Some("0"),
        Some("\"empty-tag\""),
        Some("empty-version"),
        None,
        None,
    )
    .unwrap();
    assert!(
        validate_range(
            &source,
            0,
            0,
            206,
            Some("0"),
            Some("\"empty-tag\""),
            Some("empty-version"),
            None,
            None
        )
        .is_err()
    );
    assert!(
        validate_range(
            &source,
            0,
            0,
            200,
            Some("0"),
            Some("\"empty-tag\""),
            Some("other-version"),
            None,
            None
        )
        .is_err()
    );
    assert!(
        validate_range(
            &source,
            0,
            0,
            200,
            Some("1"),
            Some("\"empty-tag\""),
            Some("empty-version"),
            None,
            None
        )
        .is_err()
    );
}

#[test]
fn authenticated_receipts_refuse_mode_nonce_and_source_substitution() {
    let request = request();
    let source = source(&request);
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let (body, signature) =
        source_protocol::sign_versioned_source(&key, &request, Some(source.clone())).unwrap();
    let reply =
        source_protocol::verify_versioned_source(&key, &request, &signature, &body).unwrap();
    assert_eq!(reply.versioned_source, Some(source.clone()));
    assert!(reply.closure.is_none());
    assert!(source_protocol::verify_inspection_lookup(&key, &request, &signature, &body).is_err());
    let mut changed = request.clone();
    changed.nonce = "c".repeat(64);
    assert!(source_protocol::verify_versioned_source(&key, &changed, &signature, &body).is_err());
    changed = request.clone();
    changed.operation = Operation::InspectLookup {
        read_lease: "shape-only".into(),
    };
    assert!(source_protocol::verify_versioned_source(&key, &changed, &signature, &body).is_err());
    let (absent, mac) = source_protocol::sign_versioned_source(&key, &request, None).unwrap();
    assert!(
        source_protocol::verify_versioned_source(&key, &request, &mac, &absent)
            .unwrap()
            .versioned_source
            .is_none()
    );
    let mut range = request;
    range.operation = Operation::InspectVersionedRange {
        source: source.clone(),
        read_lease: "shape-only".into(),
        offset: 0,
        bytes: 8,
    };
    let mut changed_source = source;
    changed_source.provider_version = Some("version-2".into());
    assert!(source_protocol::sign_versioned_source(&key, &range, Some(changed_source)).is_err());
    range.current(129).unwrap();
    assert!(range.current(130).is_err());
}

#[tokio::test]
async fn min_three_range_uses_one_real_atomic_slot_and_one_use_cancel_custody() {
    use crate::direct_upload::provider_capacity::{self, Class, transfer};
    let mut request = request();
    let source = source(&request);
    request.operation = Operation::InspectVersionedRange {
        source,
        read_lease: "shape-only".into(),
        offset: 0,
        bytes: 8,
    };
    provider_capacity::configure(3).unwrap();
    let atomic = provider_capacity::acquire_class(2, Class::Bulk)
        .await
        .unwrap();
    let (held_companion, read) = transfer::split(atomic).unwrap();
    let reservation = transfer::register(read, request.capacity_digest().unwrap()).unwrap();
    request.capacity_transfer = Some(reservation.ticket());
    request.validate().unwrap();
    let accepted = transfer::accept(&reservation.ticket(), &request.capacity_digest().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(provider_capacity::observation().active, 2);
    assert!(transfer::accept(&reservation.ticket(), &request.capacity_digest().unwrap()).is_err());
    let metadata = provider_capacity::acquire_class(1, Class::Metadata)
        .await
        .unwrap();
    assert_eq!(provider_capacity::observation().active, 3);
    let mut substituted = request.clone();
    let Operation::InspectVersionedRange { source, .. } = &mut substituted.operation else {
        panic!("range");
    };
    source.provider_version = Some("different-version".into());
    assert!(substituted.validate().is_err());
    drop(reservation);
    assert!(accepted.cancellation.check().is_err());
    drop(accepted);
    drop(metadata);
    drop(held_companion);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[test]
fn retained_mirror_owner_refuses_stage_destination_and_restored_unknown_work() {
    use crate::external_object::{mirror::state::Owner, state::Head};
    use aos_hub_core::storage_authority::lease::LeaseClock;

    let request = request();
    let (object, config, _) = config::tests::fixture();
    let fresh = Head::initialize_floor(
        &object,
        &request.scope,
        &config.domains[0].read_cohort,
        LeaseClock {
            observed_at: 101,
            uncertainty: 1,
        },
    )
    .unwrap();
    fresh.validate(&object, &request.scope).unwrap();
    require_idle(&fresh).unwrap();
    let unowned = serde_json::to_value(&fresh).unwrap();
    assert!(unowned.get("mirror").is_none());

    // The pointer is retained for unknown actions and positive completion before
    // ACK. Both physical roles must refuse without consulting time or provider.
    for destination in [false, true] {
        let owner = Owner {
            original_digest: "a".repeat(64),
            configuration: "b".repeat(64),
            destination,
        };
        owner.validate().unwrap();
        let mut retained = fresh.clone();
        retained.mirror = Some(owner.clone());
        retained.validate(&object, &request.scope).unwrap();
        assert!(require_idle(&retained).is_err());

        let restored: Head =
            serde_json::from_slice(&serde_json::to_vec(&retained).unwrap()).unwrap();
        restored.validate(&object, &request.scope).unwrap();
        assert_eq!(restored.mirror, Some(owner));
        assert!(require_idle(&restored).is_err());
    }

    // This separately initialized unowned head keeps the old omitted field;
    // the test never clears a retained owner or manufactures settlement.
    require_idle(&fresh).unwrap();
    assert_eq!(unowned, serde_json::to_value(&fresh).unwrap());
}
