//! UNRUN pure arithmetic and canonical-byte preservation vectors.
//!
//! Heads here are ordinary model DATA, never protected runtime fixtures.

use super::*;
use crate::mount_source_acquisition_state::{
    ProviderScopeV2, RecoveryBarrierV2, StoredRecordV2, encode_mount_source_state_record_v2,
    seal_record,
};

fn reference() -> RecordRefV2 {
    RecordRefV2 {
        id: [7; 32],
        revision: 1,
        record_digest: [8; 32],
    }
}

fn head() -> SourceProviderHeadV2 {
    SourceProviderHeadV2 {
        revision: 4,
        scope: ProviderScopeV2 {
            holder_authority_id: [1; 16],
            provider_authority_id: [2; 16],
            route_id: [3; 16],
            resource_namespace_digest: [12; 32],
        },
        holder_authority_generation: 1,
        holder_authority_digest: [4; 32],
        provider_authority_generation: 1,
        provider_authority_digest: [5; 32],
        current_session_id: [6; 32],
        current_session_record_digest: [9; 32],
        next_request_sequence: 5,
        next_response_sequence: 5,
        pending_attempt: None,
        inventory_observation_ordinal: 0,
        inventory_floor: None,
        last_inventory_attempt: None,
        current_projection_epoch: 1,
        current_projection_digest: [10; 32],
        last_reconciliation: None,
        recovery_barrier: None,
        record_digest: [11; 32],
    }
}

fn sealed_bytes(head: SourceProviderHeadV2) -> (Vec<u8>, Vec<u8>) {
    let record = seal_record(StoredRecordV2::ProviderHead { value: head }).unwrap();
    encode_mount_source_state_record_v2(&record).unwrap()
}

#[test]
fn reservation_preserves_legacy_bytes_for_ordinary_and_barrier_heads() {
    for barrier in [
        None,
        Some(RecoveryBarrierV2 {
            root_attempt: reference(),
            baseline_inventory_ordinal: 0,
            required_session_id: [6; 32],
            recovery_inventory_tail: None,
            replacement_count: 1,
        }),
    ] {
        let mut current = head();
        current.recovery_barrier = barrier;
        let mut legacy = current.clone();
        legacy.revision += 1;
        legacy.next_request_sequence += 1;
        legacy.pending_attempt = Some(reference());
        legacy.record_digest = [0; 32];

        let derived = derive_inventory_reservation_head_v2(&current, reference()).unwrap();

        assert_eq!(derived, legacy);
        assert_eq!(derived.record_digest, [0; 32]);
        assert_eq!(sealed_bytes(derived), sealed_bytes(legacy));
    }
}

#[test]
fn completed_head_preserves_legacy_equal_projection_successor() {
    let mut current = head();
    current.next_request_sequence += 1;
    current.pending_attempt = Some(reference());
    let rows = BTreeMap::new();
    let mut legacy = current.clone();
    legacy.revision += 1;
    legacy.next_response_sequence += 1;
    legacy.pending_attempt = None;
    legacy.record_digest = [0; 32];

    let derived = derive_provider_completed_head_v2(&current, &rows, &rows).unwrap();

    assert_eq!(derived, legacy);
    assert_eq!(sealed_bytes(derived), sealed_bytes(legacy));
}

#[test]
fn arithmetic_and_reachability_errors_keep_original_reasons_and_order() {
    let rows = BTreeMap::new();
    let mut current = head();
    current.next_response_sequence = u64::MAX;

    assert_eq!(
        derive_provider_completed_head_v2(&current, &rows, &rows),
        Err(Invariant("SourceProvider response sequence is exhausted")),
    );

    current = head();
    assert_eq!(
        derive_provider_completed_head_v2(&current, &rows, &rows),
        Err(Invariant("SourceProvider response head is not reachable")),
    );

    current.revision = u64::MAX;
    current.next_request_sequence = u64::MAX;
    assert_eq!(
        derive_inventory_reservation_head_v2(&current, reference()),
        Err(Invariant("AOSMSA02 record revision is exhausted")),
    );

    current.revision = 4;
    assert_eq!(
        derive_inventory_reservation_head_v2(&current, reference()),
        Err(Invariant("provider request sequence is exhausted")),
    );
}

#[test]
fn canonical_errors_retain_the_existing_display_prefix() {
    let error = MountSourceAcquisitionStateError::Invalid("projection failure");
    let wrapped = InventoryOwnerDerivationErrorV2::Canonical(error.clone());

    assert_eq!(wrapped.to_string(), error.to_string());
    assert_eq!(Invariant("owner invariant").to_string(), "owner invariant");
}
