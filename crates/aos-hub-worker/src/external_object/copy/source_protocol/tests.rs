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
            source_binding_id: None,
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
        inspection: None,
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
    use crate::direct_upload::provider_capacity::{self, transfer, Class};

    let (mut request, _) = fixture();
    provider_capacity::configure(3).unwrap();
    let (destination, source) = transfer::split(
        provider_capacity::acquire_class(2, Class::Bulk)
            .await
            .unwrap(),
    )
    .unwrap();
    let reservation = transfer::register(source, request.capacity_digest().unwrap()).unwrap();
    request.capacity_transfer = Some(reservation.ticket());
    request.validate().unwrap();

    let mut changed = request.clone();
    let Operation::Range { read_lease, .. } = &mut changed.operation else {
        panic!("actual range fixture")
    };
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
    assert!(transfer::accept(
        request.capacity_transfer.as_ref().unwrap(),
        &request.capacity_digest().unwrap()
    )
    .is_err());
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

fn inspection_fixture() -> (Request, CopySourceClosure) {
    let (mut request, closure) = fixture();
    let selector = request.selector.take().unwrap();
    request.plan.placement_id = selector.source.placement_id.get();
    request.plan.placement_resource_version = selector.source.resource_version.get();
    request.plan.placement_prefix = selector.source.prefix;
    request.plan.credential_references.truncate(1);
    let full_prefix = request.scope.full_key.strip_suffix(&selector.path).unwrap().to_owned();
    request.scope.full_key = format!("{full_prefix}HEAD");
    request.plan.operation = StorageWorkOperation::InspectMetadata { path: "HEAD".into() };
    request.inspection = Some(super::super::super::inspection::selection::Selection::from_plan(
        &request.plan, "HEAD").unwrap());
    request.operation = Operation::InspectLookup { read_lease: "actual-read-lease".into() };
    request.validate().unwrap();
    (request, closure)
}

#[test]
fn typed_lookup_has_separate_authentication_and_exact_physical_key_selection() {
    let (request, closure) = inspection_fixture();
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let etag = closure.etag.clone().unwrap();
    let (body, signature) = sign_inspection_lookup(&key, &request, Some(closure.clone()), Some(etag)).unwrap();
    assert_eq!(verify_inspection_lookup(&key, &request, &signature, &body).unwrap().closure,
        Some(closure));
    assert!(verify_reply(&key, &request, &signature, &body).is_err());
    let (body, signature) = sign_inspection_lookup(&key, &request, None, None).unwrap();
    assert!(verify_inspection_lookup(&key, &request, &signature, &body).unwrap().closure.is_none());

    let prefix = request.scope.full_key.strip_suffix(&request.plan.object_key(
        &request.inspection.as_ref().unwrap().path).unwrap()).unwrap().trim_end_matches('/');
    request.inspection.as_ref().unwrap().validate_scope(&request.plan, prefix, &request.scope).unwrap();
    let mut wrong = request.scope.clone();
    wrong.full_key.push_str("-wrong");
    assert!(request.inspection.as_ref().unwrap().validate_scope(&request.plan, prefix, &wrong).is_err());
    let mut changed = request.clone();
    changed.nonce = "e".repeat(64);
    assert!(verify_inspection_lookup(&key, &changed, &signature, &body).is_err());
    assert!(sign_inspection_lookup(&key, &request, None, Some("\"tag\"".into())).is_err());
}

#[tokio::test]
async fn typed_range_consumes_one_atomic_slot_at_minimum_capacity_without_reacquiring() {
    use crate::direct_upload::provider_capacity::{self, transfer, Class};
    let (mut request, closure) = inspection_fixture();
    request.operation = Operation::InspectRange { etag: closure.etag.clone().unwrap(), closure,
        read_lease: "actual-read-lease".into(), offset: 0, bytes: 11 };
    provider_capacity::configure(3).unwrap();
    let (companion, source) = transfer::split(provider_capacity::acquire_class(2, Class::Bulk).await.unwrap()).unwrap();
    let reservation = transfer::register(source, request.capacity_digest().unwrap()).unwrap();
    request.capacity_transfer = Some(reservation.ticket());
    request.validate().unwrap();
    let consumed = transfer::accept(request.capacity_transfer.as_ref().unwrap(), &request.capacity_digest().unwrap())
        .unwrap().unwrap();
    assert_eq!(provider_capacity::observation().active, 2);
    assert!(transfer::accept(request.capacity_transfer.as_ref().unwrap(), &request.capacity_digest().unwrap()).is_err());
    drop(consumed);
    drop(reservation);
    drop(companion);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[test]
fn typed_oci_chunks_keep_the_exact_signed_interval_and_source_closure() {
    let (mut request, closure) = inspection_fixture();
    let path = format!("oci/blobs/sha256/{}", closure.sha256);
    let old_path = request.inspection.as_ref().unwrap().path.clone();
    let full_prefix = request.scope.full_key.strip_suffix(&old_path).unwrap().to_owned();
    request.scope.full_key = format!("{full_prefix}{path}");
    request.plan.operation = StorageWorkOperation::InspectOciRange { path: path.clone(), start: 2, end: 8 };
    request.inspection = Some(super::super::super::inspection::selection::Selection::from_plan(&request.plan, &path).unwrap());

    for (offset, bytes) in [(2, 4), (6, 3)] {
        request.operation = Operation::InspectRange { closure: closure.clone(), read_lease: "actual-read-lease".into(),
            etag: closure.etag.clone().unwrap(), offset, bytes };
        request.validate().unwrap();
    }
    for (offset, bytes) in [(1, 1), (8, 2), (2, 0), (2, 8)] {
        request.operation = Operation::InspectRange { closure: closure.clone(), read_lease: "actual-read-lease".into(),
            etag: closure.etag.clone().unwrap(), offset, bytes };
        assert!(request.validate().is_err());
    }
    request.operation = Operation::InspectRange { closure: closure.clone(), read_lease: "actual-read-lease".into(),
        etag: closure.etag.clone().unwrap(), offset: 2, bytes: 4 };
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let mut changed = closure;
    changed.guard_stamp.incarnation = aos_hub_core::storage_authority::GuardIncarnation::parse("12").unwrap();
    assert!(sign_reply(&key, &request, changed).is_err());
}

#[test]
fn guarded_inventory_ranges_bind_portable_state_and_the_original_closed_source() {
    use aos_hub_core::db::OciSha256State;
    use aos_hub_core::storage_work::protected_inspection::ProtectedInspectionSource;

    let (mut request, closure) = inspection_fixture();
    let path = format!("oci/blobs/sha256/{}", closure.sha256);
    let full_prefix = request.scope.full_key.strip_suffix("HEAD").unwrap().to_owned();
    request.scope.full_key = format!("{full_prefix}{path}");
    let guarded = ProtectedInspectionSource {
        version: 1,
        scope: request.scope.clone(),
        closure: closure.clone(),
    };
    request.plan.operation = StorageWorkOperation::HashOciRange {
        path: path.clone(), start: 0, end: 5, total: 11,
        strong_etag: closure.etag.clone().unwrap(),
        expected_provider_version: None,
        sha256_state: OciSha256State::initial(),
        guarded_source: Some(guarded),
    };
    request.inspection = Some(super::super::super::inspection::selection::Selection::from_plan(
        &request.plan, &path).unwrap());
    request.operation = Operation::InspectRange {
        closure: closure.clone(), read_lease: "actual-read-lease".into(),
        etag: closure.etag.clone().unwrap(), offset: 0, bytes: 3,
    };
    request.validate().unwrap();

    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let body = serde_json::to_vec(&request).unwrap();
    let signature = key.sign_body(&body).unwrap();
    authenticate(&key, &signature, &body).unwrap();
    let mut changed = request.clone();
    if let StorageWorkOperation::HashOciRange { sha256_state, .. } = &mut changed.plan.operation {
        sha256_state.update(b"x").unwrap();
    }
    assert!(changed.validate().is_err());
    let mut changed = request.clone();
    if let Operation::InspectRange { closure, .. } = &mut changed.operation {
        closure.receipt_digest = "e".repeat(64);
    }
    assert!(changed.validate().is_err());
    let mut changed = request.clone();
    if let Operation::InspectRange { offset, bytes, .. } = &mut changed.operation {
        *offset = 5;
        *bytes = 2;
    }
    assert!(changed.validate().is_err());

    request.plan.operation = StorageWorkOperation::Head { path: path.clone() };
    request.inspection = Some(super::super::super::inspection::selection::Selection::from_plan(
        &request.plan, &path).unwrap());
    request.operation = Operation::InspectLookup { read_lease: "actual-read-lease".into() };
    let (body, signature) = sign_inspection_lookup(&key, &request, Some(closure.clone()), closure.etag.clone()).unwrap();
    assert_eq!(verify_inspection_lookup(&key, &request, &signature, &body).unwrap().closure, Some(closure));
}

#[test]
fn inventory_applicability_retains_expired_domain_identity_and_refuses_changed_coordinates() {
    let (object, mut config, _) = super::super::config::tests::protected_fixture();
    let snapshot = crate::external_object::tests::snapshot(&object);
    let mode = super::super::super::inspection::inventory_domain_mode;
    use super::super::super::inspection::InventoryDomainMode;

    // The configured fixture is historical. Applicability retains its physical
    // identity; actual lease acquisition still enforces the current cutoff.
    assert_eq!(mode(&snapshot, true, Some(&config)).unwrap(), InventoryDomainMode::ProtectedVersionless);
    assert!(mode(&snapshot, false, Some(&config)).is_err());
    let mut changed = snapshot.clone();
    changed.binding_resource_version += 1;
    assert!(mode(&changed, true, Some(&config)).is_err());
    let mut unrelated = snapshot;
    unrelated.binding_id += 1;
    unrelated.binding_stable_id = "unrelated-binding".into();
    assert_eq!(mode(&unrelated, false, Some(&config)).unwrap(), InventoryDomainMode::Unconfigured);
    assert!(mode(&unrelated, true, Some(&config)).is_err());

    config.domains[0].provider_contract.protected_versionless = None;
    let snapshot = crate::external_object::tests::snapshot(&object);
    assert_eq!(mode(&snapshot, true, Some(&config)).unwrap(), InventoryDomainMode::Versioned);
    assert!(mode(&snapshot, false, Some(&config)).is_err());
    config.domains.push(config.domains[0].clone());
    assert!(mode(&snapshot, true, Some(&config)).is_err());
}

#[test]
fn loose_graph_reads_share_buffer_admission_without_nesting_stored_pairs() {
    use std::future::Future as _;
    use std::task::{Context, Poll};
    use super::super::super::inspection::acquire_parser_buffer;
    use aos_hub_core::storage_work::StorageWorkOperation as Op;

    let object = Op::InspectGitObject { oid: "a".repeat(64) };
    let batch = Op::InspectMetadataObjects {
        paths: (0..32).map(|index| format!("metadata/document-{index}")).collect(),
        cursor: 0,
    };
    let pack = Op::InspectStoredGitPack {
        index_path: "git/packs/pack.idx".into(),
        selections: Vec::new(),
        protected_profile_digest: "b".repeat(64),
    };
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut first = Box::pin(acquire_parser_buffer(&object, || Ok(())));
    let Poll::Ready(Ok(Some(first))) = first.as_mut().poll(&mut context) else {
        panic!("first loose parser did not acquire its buffer");
    };

    // The source request can finish while its parser still owns this permit.
    // A second loose graph must wait; a stored pair must not nest admission.
    let expired = std::cell::Cell::new(false);
    let mut second = Box::pin(acquire_parser_buffer(&batch, || {
        anyhow::ensure!(!expired.get(), "original cutoff elapsed");
        Ok(())
    }));
    assert!(second.as_mut().poll(&mut context).is_pending());
    let mut stored = Box::pin(acquire_parser_buffer(&pack, || Ok(())));
    assert!(matches!(stored.as_mut().poll(&mut context), Poll::Ready(Ok(None))));

    expired.set(true);
    assert!(matches!(second.as_mut().poll(&mut context), Poll::Ready(Err(_))));
    drop(second);
    let mut next = Box::pin(acquire_parser_buffer(&batch, || Ok(())));
    assert!(next.as_mut().poll(&mut context).is_pending());
    drop(first);
    assert!(matches!(next.as_mut().poll(&mut context), Poll::Ready(Ok(Some(_)))));
}
