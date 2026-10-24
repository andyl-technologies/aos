//! Checks inert fresh allocation grammar, phase arithmetic and key separation.

// crucible-lint: allow panic-shortcut -- data controls panic on protocol mismatch.
#![expect(
    clippy::unwrap_used,
    reason = "closed data controls assert exact failure"
)]

use super::*;
use crucible_node_format::canonical;

fn storage() -> PacketNativeFreshRestoreAllocationStorage {
    PacketNativeFreshRestoreAllocationStorage {
        current_retained_bytes: U64::new(2),
        query_retained_growth_bytes: U64::new(3),
        prepare_retained_growth_bytes: U64::new(5),
        query_transient_bytes: U64::new(7),
        prepare_transient_bytes: U64::new(11),
        declared_counter_scratch_bytes: U64::new(13),
    }
}

fn data() -> PacketNativeFreshRestoreAllocationData {
    PacketNativeFreshRestoreAllocationData {
        scope: PacketNativeFreshRestoreAllocationScope {
            native_pid: U64::new(1),
            session: Id::new("session-1").unwrap(),
            incarnation: Id::new("incarnation-1").unwrap(),
            node: Id::new("node-1").unwrap(),
            owner: Id::new("owner-1").unwrap(),
            owner_generation: U64::new(1),
            owner_binding: canonical::json_hash("node/owner", &serde_json::json!({})).unwrap(),
            world: canonical::json_hash("node/world", &serde_json::json!({})).unwrap(),
            prepared_token: Id::new("prepared-1").unwrap(),
            admission: Id::new("admission-1").unwrap(),
            closed_gate_receipt: canonical::content_ref(b"{}", "application/json").unwrap(),
            nonce: Bytes::new(fresh_restore_allocation_nonce_data(&[17; 32]).to_vec()),
            assigned_query: Bytes::new(vec![2; 32]),
            completed_admit_request: Bytes::new(vec![3; 32]),
            completed_admit_response: Bytes::new(vec![4; 32]),
            ack_context: Bytes::new(vec![5; 32]),
        },
        storage: storage(),
    }
}

#[test]
fn requested_peak_keeps_both_retained_phases_and_one_complete_transient() {
    assert_eq!(storage().requested_peak_data().unwrap(), 34);

    let mut absent = storage();
    absent.query_retained_growth_bytes = U64::new(0);
    assert!(absent.requested_peak_data().is_err());

    let mut overflowing = storage();
    overflowing.current_retained_bytes = U64::new(u64::MAX);
    assert!(overflowing.requested_peak_data().is_err());
}

#[test]
fn query_rejects_extra_or_truncated_birth_binding_data() {
    let query = PacketNativeFreshRestoreAllocationQuery {
        schema: PACKET_FRESH_RESTORE_ALLOCATION_QUERY.to_owned(),
        nonce: Bytes::new(vec![1; 32]),
        completed_admit_request: Bytes::new(vec![2; 32]),
        completed_admit_response: Bytes::new(vec![3; 32]),
    };
    query.validate_data().unwrap();
    let mut value = serde_json::to_value(&query).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("active".into(), true.into());
    assert!(serde_json::from_value::<PacketNativeFreshRestoreAllocationQuery>(value).is_err());

    let mut truncated = query;
    truncated.completed_admit_response = Bytes::new(vec![3; 31]);
    assert!(truncated.validate_data().is_err());
}

#[test]
fn keyed_report_binds_actual_target_original_pair_and_all_storage_fields() {
    let key = [17; 32];
    let data = data();
    let proof = fresh_restore_allocation_proof_data(&key, &data).unwrap();
    verify_fresh_restore_allocation_proof_data(&key, &data, &proof).unwrap();
    assert!(verify_fresh_restore_allocation_proof_data(&[18; 32], &data, &proof).is_err());

    let mut changed = data.clone();
    changed.scope.completed_admit_response = Bytes::new(vec![9; 32]);
    assert!(verify_fresh_restore_allocation_proof_data(&key, &changed, &proof).is_err());

    changed = data.clone();
    changed.scope.incarnation = Id::new("incarnation-2").unwrap();
    assert!(verify_fresh_restore_allocation_proof_data(&key, &changed, &proof).is_err());

    changed = data;
    changed.storage.prepare_transient_bytes = U64::new(12);
    assert!(verify_fresh_restore_allocation_proof_data(&key, &changed, &proof).is_err());
    assert_ne!(
        fresh_restore_allocation_nonce_data(&key).as_slice(),
        proof.mac.as_slice()
    );
}

#[test]
fn fresh_report_projection_bounds_actual_keyed_report_without_maximum_dto() {
    let key = [17; 32];
    let mut data = data();
    data.scope.owner_binding =
        canonical::hash("cnp.owner-binding.v1", b"fresh closed scope").unwrap();
    let proof = fresh_restore_allocation_proof_data(&key, &data).unwrap();
    let report = PacketNativeFreshRestoreAllocationReport {
        schema: PACKET_FRESH_RESTORE_ALLOCATION_REPORT.to_owned(),
        data,
        proof,
    };
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    observer.observe(&report).unwrap();
    let actual =
        crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
            &report,
            observer.finish(),
            usize::MAX,
        )
        .unwrap();
    let projection = startup::report_shape_for_test(&report.data.scope, usize::MAX).unwrap();

    assert!(actual.maximum_encoded_bytes <= projection.maximum_encoded_bytes);
    assert!(actual.dom_and_canonical_scratch_bytes <= projection.dom_and_canonical_scratch_bytes);
    assert!(actual.projected_parser_requested_bytes <= projection.projected_parser_requested_bytes);
    assert!(projection.maximum_encoded_bytes <= MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES);
    assert!(
        startup::report_shape_for_test(
            &report.data.scope,
            projection.requested_total().unwrap() - 1
        )
        .is_err()
    );
}

#[test]
fn actual_fresh_report_metadata_retains_independent_digest_spare_capacity() {
    let key = [17; 32];
    let data = data();
    let proof = fresh_restore_allocation_proof_data(&key, &data).unwrap();
    let report = PacketNativeFreshRestoreAllocationReport {
        schema: PACKET_FRESH_RESTORE_ALLOCATION_REPORT.to_owned(),
        data,
        proof,
    };
    let mut before = crate::retained_metadata::MetadataObserver::new();
    before.observe(&report).unwrap();
    let before = before.finish();
    let mut changed = report.clone();
    let mut spare = Vec::with_capacity(4096);
    spare.extend_from_slice(changed.data.scope.ack_context.as_slice());
    changed.data.scope.ack_context = Bytes::new(spare);
    let mut after = crate::retained_metadata::MetadataObserver::new();
    after.observe(&changed).unwrap();
    let after = after.finish();

    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&changed).unwrap()
    );
    assert!(after.vector_capacity_bytes >= before.vector_capacity_bytes + 4096 - 32);
}
