//! Pure regressions for ordered replay mutations and original ID-set handoff.

use super::{NativeReplayBookkeeping, NativeReplayCoordinates, NativeReplayError};
use crate::framing::{Frame, FrameKind};

fn frame(sequence: u64) -> Frame {
    Frame {
        kind: FrameKind::Record,
        sequence,
        transaction_id: [7; 16],
        payload: vec![0xff],
    }
}

#[test]
fn starts_with_empty_coordinates_and_id_set() {
    let mut replay = NativeReplayBookkeeping::new();

    assert_eq!(
        replay.coordinates(),
        NativeReplayCoordinates {
            offset: 0,
            durable_end: 0,
            expected_sequence: 1,
            durable_next_sequence: 1,
            committed_transactions: 0,
            committed_records: 0,
        }
    );
    assert!(replay.take_transaction_ids().is_empty());
}

#[test]
fn frame_progress_does_not_advance_commit_boundary() {
    let mut replay = NativeReplayBookkeeping::new();

    replay.observe_frame(&frame(1), 73).unwrap();
    replay.observe_frame(&frame(2), 81).unwrap();

    assert_eq!(
        replay.coordinates(),
        NativeReplayCoordinates {
            offset: 154,
            durable_end: 0,
            expected_sequence: 3,
            durable_next_sequence: 1,
            committed_transactions: 0,
            committed_records: 0,
        }
    );
    assert!(replay.transaction_ids.is_empty());
}

#[test]
fn discontinuity_precedes_sequence_and_offset_overflow() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.coordinates.expected_sequence = u64::MAX;
    replay.coordinates.offset = u64::MAX;
    let before = replay.coordinates();

    let error = replay.observe_frame(&frame(1), 1).unwrap_err();

    assert_eq!(error, NativeReplayError::SequenceDiscontinuity(u64::MAX));
    assert_eq!(replay.coordinates(), before);
}

#[test]
fn sequence_exhaustion_precedes_offset_overflow_without_mutation() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.coordinates.expected_sequence = u64::MAX;
    replay.coordinates.offset = u64::MAX;
    let before = replay.coordinates();

    let error = replay.observe_frame(&frame(u64::MAX), 1).unwrap_err();

    assert_eq!(error, NativeReplayError::SequenceExhausted);
    assert_eq!(replay.coordinates(), before);
}

#[test]
fn offset_overflow_retains_advanced_sequence() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.coordinates.offset = u64::MAX;
    let before = replay.coordinates();

    let error = replay.observe_frame(&frame(1), 1).unwrap_err();

    assert_eq!(error, NativeReplayError::JournalTooLarge);
    assert_eq!(
        replay.coordinates(),
        NativeReplayCoordinates {
            expected_sequence: 2,
            ..before
        }
    );
}

#[test]
fn duplicate_refusal_and_handoff_retain_original_set_allocation() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.register_transaction([7; 16]).unwrap();
    replay.register_transaction([9; 16]).unwrap();
    let original_key = replay.transaction_ids.iter().next().unwrap() as *const [u8; 16];

    assert_eq!(
        replay.register_transaction([7; 16]),
        Err(NativeReplayError::DuplicateTransaction)
    );
    let ids = replay.take_transaction_ids();

    assert_eq!(ids.len(), 2);
    assert_eq!(ids.iter().next().unwrap() as *const [u8; 16], original_key);
    assert!(replay.transaction_ids.is_empty());
    assert!(ids.contains(&[7; 16]));
    assert!(ids.contains(&[9; 16]));
}

#[test]
fn transaction_count_overflow_precedes_bound_and_record_count() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.coordinates.committed_transactions = usize::MAX;
    replay.coordinates.committed_records = usize::MAX;
    let before = replay.coordinates();

    let error = replay.finish_commit(1, 0).unwrap_err();

    assert_eq!(
        error,
        NativeReplayError::LimitExceeded("committed transaction count")
    );
    assert_eq!(replay.coordinates(), before);
}

#[test]
fn transaction_limit_retains_advanced_count_before_record_overflow() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.observe_frame(&frame(1), 73).unwrap();
    replay.coordinates.committed_records = usize::MAX;
    let before = replay.coordinates();

    let error = replay.finish_commit(1, 0).unwrap_err();

    assert_eq!(
        error,
        NativeReplayError::LimitExceeded("committed transaction count")
    );
    assert_eq!(
        replay.coordinates(),
        NativeReplayCoordinates {
            committed_transactions: 1,
            ..before
        }
    );
}

#[test]
fn record_overflow_retains_advanced_transaction_count_and_old_boundary() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.observe_frame(&frame(1), 73).unwrap();
    replay.coordinates.committed_records = usize::MAX;
    let before = replay.coordinates();

    let error = replay.finish_commit(1, 1).unwrap_err();

    assert_eq!(
        error,
        NativeReplayError::LimitExceeded("committed record count")
    );
    assert_eq!(
        replay.coordinates(),
        NativeReplayCoordinates {
            committed_transactions: 1,
            ..before
        }
    );
}

#[test]
fn explicit_commit_step_updates_counts_and_current_boundary() {
    let mut replay = NativeReplayBookkeeping::new();
    replay.observe_frame(&frame(1), 73).unwrap();
    replay.register_transaction([7; 16]).unwrap();
    replay.finish_commit(2, 2).unwrap();
    replay.observe_frame(&frame(2), 81).unwrap();

    assert_eq!(
        replay.coordinates(),
        NativeReplayCoordinates {
            offset: 154,
            durable_end: 73,
            expected_sequence: 3,
            durable_next_sequence: 2,
            committed_transactions: 1,
            committed_records: 2,
        }
    );

    replay.register_transaction([9; 16]).unwrap();
    replay.finish_commit(3, 2).unwrap();

    assert_eq!(
        replay.coordinates(),
        NativeReplayCoordinates {
            offset: 154,
            durable_end: 154,
            expected_sequence: 3,
            durable_next_sequence: 3,
            committed_transactions: 2,
            committed_records: 5,
        }
    );
    assert_eq!(replay.take_transaction_ids().len(), 2);
}
