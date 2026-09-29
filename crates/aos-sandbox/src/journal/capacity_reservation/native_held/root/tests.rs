//! Root DATA framing tests; these fixtures are not checked owner graphs.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountOperationV2, native_held_completion::RootNativeAdmissionBindingV1,
};

use super::*;
use crate::journal::encoded_transaction_append_bytes;

fn request(count: u32, bytes: u64, records: u32) -> NativeHeldCapacityRequestV3 {
    NativeHeldCapacityRequestV3 {
        purpose: NativeHeldCapacityPurposeV3::Root,
        owner_id: [1; 32],
        owner_digest: [2; 32],
        operation_id: [3; 16],
        artifact_digest: [4; 32],
        checkpoint_digest: [5; 32],
        chain_head_digest: [6; 32],
        future_transactions: count,
        terminal_records: records,
        terminal_bytes: bytes,
        poison_records: records,
        poison_bytes: bytes,
    }
}

fn proposal(kind: Kind, count: u32, widths: &[usize]) -> RootNativeHeldTransitionV1 {
    let puts = widths
        .iter()
        .map(|width| (vec![1; *width], vec![2; 16]))
        .collect::<BTreeMap<_, _>>();
    let before_images = puts
        .keys()
        .map(|key| (key.clone(), Some(vec![1; 16])))
        .collect();
    RootNativeHeldTransitionV1 {
        kind,
        transaction_id: [7; 16],
        puts,
        before_images,
        maximum_remaining_transactions: count,
        admission_binding: None,
    }
}

#[test]
fn original_root_admission_is_one_six_or_seven_record_transaction() {
    for widths in [&[68, 75, 64, 52, 66][..], &[68, 75, 64, 52, 66, 69][..]] {
        let mut proposal = proposal(Kind::PreparedAssertionRecorded, 7, widths);
        proposal.admission_binding = Some(RootNativeAdmissionBindingV1 {
            mount_operation: MountOperationV2 {
                operation_id: [3; 16],
                request_digest: [8; 32],
            },
            mount_attempt: [1; 32],
            provider_request_id: [9; 16],
            signed_request_digest: [4; 32],
            reserved_attempt_digest: [2; 32],
            reserved_head_digest: [6; 32],
            prepared_root_digest: ObjectDigest::from_bytes([5; 32]),
            session_id: [10; 32],
            provider_acquisition: [11; 32],
            flight: ObjectDigest::from_bytes([12; 32]),
        });
        let capacity = NativeHeldCapacityRecordV3::new(request(7, 100_000, 64), [7; 16]).unwrap();
        let transaction =
            root_native_capacity_admission_v3(&proposal, &capacity, JournalLimits::default())
                .unwrap();
        assert_eq!(transaction.records().len(), widths.len() + 1);
        assert_eq!(
            transaction.records().last(),
            Some(&capacity.to_journal_record())
        );
        assert!(
            super::super::require_legacy_transaction(&Default::default(), &transaction).is_err()
        );
    }
}

#[test]
fn root_admission_rejects_late_sidecar_wrong_operation_and_checkpoint() {
    let mut late = proposal(Kind::PreparedAssertionRecorded, 7, &[68]);
    let capacity = NativeHeldCapacityRecordV3::new(request(7, 100_000, 64), [7; 16]).unwrap();
    assert!(root_native_capacity_admission_v3(&late, &capacity, JournalLimits::default()).is_err());
    late.kind = Kind::PreparedStored;
    assert!(root_native_capacity_append_v3(&late).is_ok());
    let mut valid = proposal(Kind::PreparedAssertionRecorded, 7, &[68, 75, 64, 52, 66]);
    valid.admission_binding = Some(RootNativeAdmissionBindingV1 {
        mount_operation: MountOperationV2 {
            operation_id: [3; 16],
            request_digest: [8; 32],
        },
        mount_attempt: [1; 32],
        provider_request_id: [9; 16],
        signed_request_digest: [4; 32],
        reserved_attempt_digest: [2; 32],
        reserved_head_digest: [6; 32],
        prepared_root_digest: ObjectDigest::from_bytes([5; 32]),
        session_id: [10; 32],
        provider_acquisition: [11; 32],
        flight: ObjectDigest::from_bytes([12; 32]),
    });
    let mut bad = request(7, 100_000, 64);
    bad.operation_id = [13; 16];
    let changed = NativeHeldCapacityRecordV3::new(bad, [7; 16]).unwrap();
    assert!(root_native_capacity_admission_v3(&valid, &changed, JournalLimits::default()).is_err());
    bad = request(7, 100_000, 64);
    bad.checkpoint_digest = [14; 32];
    let changed = NativeHeldCapacityRecordV3::new(bad, [7; 16]).unwrap();
    assert!(root_native_capacity_admission_v3(&valid, &changed, JournalLimits::default()).is_err());
}

#[test]
fn continuation_preserves_original_admission_and_accounts_exact_full_append() {
    let proposal = proposal(Kind::PreparedStored, 6, &[68]);
    let old = NativeHeldCapacityRecordV3::new(request(7, 100_000, 64), [8; 16]).unwrap();
    let next = NativeHeldCapacityRecordV3::new(request(6, 90_000, 60), [8; 16]).unwrap();
    let transaction =
        root_native_capacity_transition_v3(&proposal, &old, Some(&next), JournalLimits::default())
            .unwrap();
    assert_eq!(transaction.records().len(), 3);
    assert_eq!(transaction.records()[1].value(), None);
    assert_eq!(transaction.records()[2], next.to_journal_record());
    assert!(encoded_transaction_append_bytes(&transaction).unwrap() > 266);

    let changed = NativeHeldCapacityRecordV3::new(next.request(), [9; 16]).unwrap();
    assert!(
        root_native_capacity_transition_v3(
            &proposal,
            &old,
            Some(&changed),
            JournalLimits::default()
        )
        .is_err()
    );
    let enlarged = NativeHeldCapacityRecordV3::new(request(6, 100_000, 64), [8; 16]).unwrap();
    assert!(
        root_native_capacity_transition_v3(
            &proposal,
            &old,
            Some(&enlarged),
            JournalLimits::default()
        )
        .is_err()
    );
    assert!(
        root_native_capacity_transition_v3(&proposal, &old, None, JournalLimits::default())
            .is_err()
    );
}

#[test]
fn native_floor_deletion_requires_actual_terminal_ack_not_settled_or_cas() {
    let old = NativeHeldCapacityRecordV3::new(request(1, 100_000, 64), [8; 16]).unwrap();
    let settled = proposal(Kind::TerminalRecorded, 0, &[68]);
    assert!(
        root_native_capacity_transition_v3(&settled, &old, None, JournalLimits::default()).is_err()
    );
    let ack = proposal(Kind::TerminalAckStored, 0, &[68]);
    let transaction =
        root_native_capacity_transition_v3(&ack, &old, None, JournalLimits::default()).unwrap();
    assert_eq!(transaction.records().len(), 2);
    assert_eq!(transaction.records()[1].value(), None);
    assert!(super::super::require_legacy_transaction(&Default::default(), &transaction).is_ok());
    // This plain deletion has no retained-state origin. With its actual old
    // native row, every legacy protected route remains explicitly closed.
    let record = old.to_journal_record();
    let state = BTreeMap::from([(
        (record.namespace(), record.key().to_vec()),
        record.value().unwrap().to_vec(),
    )]);
    assert!(super::super::require_legacy_transaction(&state, &transaction).is_err());
}
