//! Checks quiescent SPSC snapshot/restore and canonical snapshot bytes.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_shmem::{
    FRAME_DELIVERY_PENDING, FRAME_DELIVERY_RETAINED, FrameDeliveryState, FrameEntry,
    MAX_FRAME_DATA, MAX_FRAME_DELIVERY_ATTEMPTS, RingHeader, SpscRingError, SpscRingSnapshot,
};

#[test]
fn snapshot_captures_fifo_after_wraparound_and_canonicalizes_entries() {
    let ring = RingHeader::new();
    let mut entries = blank_entries(4);

    let first = frame(10, 1, 0, b"first");
    let second = frame(11, 1, 1, b"second");
    let third = frame_with_unused_tail(12, 7, 2, b"third", 128, 0xa5);

    enqueue(&ring, &mut entries, &first);
    enqueue(&ring, &mut entries, &second);
    assert_eq!(dequeue(&ring, &entries), Some(first));
    enqueue(&ring, &mut entries, &third);

    let snapshot = snapshot(&ring, &entries);
    let expected = vec![second, frame(12, 7, 2, b"third")];
    assert_eq!(snapshot.frames, expected);
    assert!(
        snapshot
            .frames
            .iter()
            .all(FrameEntry::padding_bytes_are_zero)
    );
    assert_eq!(snapshot.frames[1].data[128], 0);
    let encoded = canonical_bytes(&expected);
    assert_eq!(snapshot.canonical_bytes(), Ok(encoded.clone()));
    assert_eq!(
        SpscRingSnapshot::from_canonical_bytes(&encoded, 4),
        Ok(snapshot)
    );
}

#[test]
fn restore_normalizes_indices_and_replays_snapshot_frames() {
    let original = RingHeader::new();
    let mut original_entries = blank_entries(2);
    let first = frame(20, 3, 0, b"a");
    let second = frame(21, 3, 1, b"b");
    let third = frame(22, 3, 2, b"c");

    enqueue(&original, &mut original_entries, &first);
    enqueue(&original, &mut original_entries, &second);
    assert_eq!(dequeue(&original, &original_entries), Some(first));
    enqueue(&original, &mut original_entries, &third);

    let snapshot = snapshot(&original, &original_entries);
    let restored = RingHeader::new();
    let mut restored_entries = blank_entries(2);
    restore(&restored, &mut restored_entries, &snapshot);

    assert_eq!(restored.read_index(), 0);
    assert_eq!(restored.write_index(), snapshot.frames.len() as u64);
    assert_eq!(dequeue(&restored, &restored_entries), Some(second));
    assert_eq!(dequeue(&restored, &restored_entries), Some(third));
    assert_eq!(dequeue(&restored, &restored_entries), None);
}

#[test]
fn restore_rejects_snapshot_larger_than_target_capacity() {
    let ring = RingHeader::new();
    let mut entries = blank_entries(2);
    let snapshot = SpscRingSnapshot {
        frames: vec![
            frame(30, 4, 0, b"a"),
            frame(31, 4, 1, b"b"),
            frame(32, 4, 2, b"c"),
        ],
    };

    assert_eq!(
        ring.restore(&mut entries, &snapshot),
        Err(SpscRingError::SnapshotTooLarge {
            len: 3,
            capacity: 2,
        })
    );
}

#[test]
fn snapshot_rejects_corrupt_frame_length_before_serializing() {
    let ring = RingHeader::new();
    let mut entries = blank_entries(1);
    let mut corrupt = frame(40, 5, 0, b"bad");
    corrupt.len = MAX_FRAME_DATA as u16 + 1;
    enqueue(&ring, &mut entries, &corrupt);

    assert_eq!(
        ring.snapshot(&entries),
        Err(SpscRingError::InvalidFrameLength {
            len: MAX_FRAME_DATA + 1,
            capacity: MAX_FRAME_DATA,
        })
    );
}

#[test]
fn canonical_bytes_reject_corrupt_snapshot_frame_length() {
    let mut corrupt = frame(50, 6, 0, b"bad");
    corrupt.len = MAX_FRAME_DATA as u16 + 1;
    let snapshot = SpscRingSnapshot {
        frames: vec![corrupt],
    };

    assert_eq!(
        snapshot.canonical_bytes(),
        Err(SpscRingError::InvalidFrameLength {
            len: MAX_FRAME_DATA + 1,
            capacity: MAX_FRAME_DATA,
        })
    );
}

#[test]
fn canonical_bytes_decoder_round_trips_and_normalizes_padding() {
    let mut source = frame_with_unused_tail(60, 7, 0, b"payload", 128, 0xfe);
    source.len = 7;
    let snapshot = SpscRingSnapshot {
        frames: vec![source],
    };

    let encoded = match snapshot.canonical_bytes() {
        Ok(encoded) => encoded,
        Err(error) => panic!("snapshot should encode: {error}"),
    };
    let decoded = match SpscRingSnapshot::from_canonical_bytes(&encoded, 4) {
        Ok(decoded) => decoded,
        Err(error) => panic!("snapshot should decode: {error}"),
    };

    assert_eq!(decoded.frames, vec![frame(60, 7, 0, b"payload")]);
    assert!(decoded.frames[0].padding_bytes_are_zero());
    assert_eq!(decoded.canonical_bytes(), Ok(encoded));
}

#[test]
fn canonical_bytes_round_trip_retained_delivery_state() {
    let retained = frame(61, 7, 1, b"retained");
    retained
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("frame should become retained: {error}"));
    for current_icount in [61, 62] {
        retained
            .record_delivery_attempt(current_icount, 64)
            .unwrap_or_else(|error| panic!("delivery attempt should be recorded: {error}"));
    }
    let snapshot = SpscRingSnapshot {
        frames: vec![retained],
    };

    let encoded = snapshot
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("retained snapshot should encode: {error}"));
    let decoded = SpscRingSnapshot::from_canonical_bytes(&encoded, 4)
        .unwrap_or_else(|error| panic!("retained snapshot should decode: {error}"));

    assert_eq!(
        decoded.frames[0].delivery_state(),
        Ok(FrameDeliveryState::Retained)
    );
    assert_eq!(decoded.frames[0].delivery_attempts(), 2);
    assert_eq!(decoded.frames[0].last_delivery_attempt_icount(), 62);
    assert_eq!(decoded, snapshot);
}

#[test]
fn canonical_bytes_rejects_impossible_attempt_state_combinations() {
    let pending_with_attempt = frame(70, 7, 0, b"pending");
    pending_with_attempt
        .record_delivery_attempt(70, MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap_or_else(|error| panic!("test attempt should record: {error}"));
    assert_eq!(
        (SpscRingSnapshot {
            frames: vec![pending_with_attempt],
        })
        .canonical_bytes(),
        Err(SpscRingError::InvalidFrameDeliveryAttempts {
            state: FRAME_DELIVERY_PENDING,
            attempts: 1,
        })
    );

    let retained_without_attempt = frame(71, 7, 1, b"retained");
    retained_without_attempt
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("test retained state should mark: {error}"));
    assert_eq!(
        (SpscRingSnapshot {
            frames: vec![retained_without_attempt],
        })
        .canonical_bytes(),
        Err(SpscRingError::InvalidFrameDeliveryAttempts {
            state: FRAME_DELIVERY_RETAINED,
            attempts: 0,
        })
    );

    let retained_over_limit = frame(72, 7, 2, b"over-limit");
    for offset in 0..=MAX_FRAME_DELIVERY_ATTEMPTS {
        retained_over_limit
            .record_delivery_attempt(72 + u64::from(offset), MAX_FRAME_DELIVERY_ATTEMPTS + 1)
            .unwrap_or_else(|error| panic!("test over-limit attempt should record: {error}"));
    }
    retained_over_limit
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("test retained state should mark: {error}"));
    assert_eq!(
        (SpscRingSnapshot {
            frames: vec![retained_over_limit],
        })
        .canonical_bytes(),
        Err(SpscRingError::InvalidFrameDeliveryAttempts {
            state: FRAME_DELIVERY_RETAINED,
            attempts: MAX_FRAME_DELIVERY_ATTEMPTS + 1,
        })
    );
}

#[test]
fn canonical_decoder_rejects_frame_count_before_allocation() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&1_000_000_u64.to_le_bytes());
    assert_eq!(
        SpscRingSnapshot::from_canonical_bytes(&encoded, 64),
        Err(SpscRingError::SnapshotTooLarge {
            len: 1_000_000,
            capacity: 64,
        })
    );
}

#[test]
fn canonical_decoder_rejects_amplified_truncated_ring_before_reservation() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&1_000_000_u64.to_le_bytes());
    assert_eq!(
        SpscRingSnapshot::from_canonical_bytes(&encoded, 1_048_576),
        Err(SpscRingError::SnapshotDecodeTruncated {
            offset: 8,
            needed: 31_000_000,
            available: 0,
        })
    );
}

#[test]
fn canonical_decoder_rejects_retained_attempt_before_delivery() {
    let retained = frame(100, 7, 0, b"retained");
    retained
        .record_delivery_attempt(100, MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap_or_else(|error| panic!("test attempt should record: {error}"));
    retained
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("test retained state should mark: {error}"));
    let mut encoded = (SpscRingSnapshot {
        frames: vec![retained],
    })
    .canonical_bytes()
    .unwrap_or_else(|error| panic!("valid retained state should encode: {error}"));
    encoded[31..39].copy_from_slice(&99_u64.to_le_bytes());

    assert_eq!(
        SpscRingSnapshot::from_canonical_bytes(&encoded, 4),
        Err(SpscRingError::InvalidFrameDeliveryAttemptIcount {
            delivery_icount: 100,
            attempt_icount: 99,
        })
    );
}

#[test]
fn canonical_bytes_decoder_rejects_malformed_corpus_without_panicking() {
    for case in malformed_snapshot_cases() {
        let decoded = match catch_unwind(AssertUnwindSafe(|| {
            SpscRingSnapshot::from_canonical_bytes(&case.bytes, 4)
        })) {
            Ok(decoded) => decoded,
            Err(_) => panic!("snapshot decode panicked for {}", case.name),
        };

        assert_eq!(decoded, Err(case.error), "case {}", case.name);
    }
}

struct MalformedSnapshotCase {
    name: &'static str,
    bytes: Vec<u8>,
    error: SpscRingError,
}

fn blank_entries(capacity: usize) -> Vec<FrameEntry> {
    vec![frame(0, 0, 0, b""); capacity]
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test frame should fit in payload capacity: {error}"),
    }
}

fn frame_with_unused_tail(
    delivery_icount: u64,
    src_node: u32,
    seq: u32,
    payload: &[u8],
    tail_offset: usize,
    tail_value: u8,
) -> FrameEntry {
    let mut frame = frame(delivery_icount, src_node, seq, payload);
    frame.data[tail_offset] = tail_value;
    frame
}

fn enqueue(ring: &RingHeader, entries: &mut [FrameEntry], frame: &FrameEntry) {
    if let Err(error) = ring.enqueue(entries, frame) {
        panic!("enqueue should succeed: {error}");
    }
}

fn dequeue(ring: &RingHeader, entries: &[FrameEntry]) -> Option<FrameEntry> {
    match ring.dequeue(entries) {
        Ok(frame) => frame,
        Err(error) => panic!("dequeue should succeed: {error}"),
    }
}

fn snapshot(ring: &RingHeader, entries: &[FrameEntry]) -> SpscRingSnapshot {
    match ring.snapshot(entries) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("snapshot should succeed: {error}"),
    }
}

fn restore(ring: &RingHeader, entries: &mut [FrameEntry], snapshot: &SpscRingSnapshot) {
    if let Err(error) = ring.restore(entries, snapshot) {
        panic!("restore should succeed: {error}");
    }
}

fn canonical_bytes(frames: &[FrameEntry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(frames.len() as u64).to_le_bytes());
    for frame in frames {
        bytes.extend_from_slice(&frame.delivery_icount.to_le_bytes());
        bytes.extend_from_slice(&frame.src_node.to_le_bytes());
        bytes.extend_from_slice(&frame.seq.to_le_bytes());
        bytes.extend_from_slice(&frame.len.to_le_bytes());
        bytes.push(
            frame
                .delivery_state()
                .unwrap_or_else(|error| panic!("test frame state should be valid: {error}"))
                as u8,
        );
        bytes.extend_from_slice(&frame.delivery_attempts().to_le_bytes());
        bytes.extend_from_slice(&frame.last_delivery_attempt_icount().to_le_bytes());
        bytes.extend_from_slice(payload(frame));
    }
    bytes
}

fn malformed_snapshot_cases() -> Vec<MalformedSnapshotCase> {
    let mut trailing_after_empty = Vec::new();
    trailing_after_empty.extend_from_slice(&0_u64.to_le_bytes());
    trailing_after_empty.push(0xa5);

    let mut missing_delivery_icount = Vec::new();
    missing_delivery_icount.extend_from_slice(&1_u64.to_le_bytes());

    let mut truncated_seq = missing_delivery_icount.clone();
    truncated_seq.extend_from_slice(&10_u64.to_le_bytes());
    truncated_seq.extend_from_slice(&1_u32.to_le_bytes());

    let oversized_payload = snapshot_frame_prefix(70, 8, 0, (MAX_FRAME_DATA + 1) as u16);

    let mut truncated_payload = snapshot_frame_prefix(71, 8, 1, 3);
    truncated_payload.extend_from_slice(b"ab");

    let mut invalid_delivery_state = snapshot_frame_prefix(72, 8, 2, 0);
    invalid_delivery_state[26] = 0xff;

    let huge_count_error = if usize::try_from(u64::MAX).is_ok() {
        SpscRingError::SnapshotTooLarge {
            len: usize::MAX,
            capacity: 4,
        }
    } else {
        SpscRingError::SnapshotFrameCountOverflow { count: u64::MAX }
    };
    let huge_count = u64::MAX.to_le_bytes().to_vec();

    vec![
        MalformedSnapshotCase {
            name: "empty",
            bytes: Vec::new(),
            error: SpscRingError::SnapshotDecodeTruncated {
                offset: 0,
                needed: 8,
                available: 0,
            },
        },
        MalformedSnapshotCase {
            name: "truncated-count",
            bytes: vec![1, 0, 0],
            error: SpscRingError::SnapshotDecodeTruncated {
                offset: 0,
                needed: 8,
                available: 3,
            },
        },
        MalformedSnapshotCase {
            name: "huge-count-without-frame",
            bytes: huge_count,
            error: huge_count_error,
        },
        MalformedSnapshotCase {
            name: "missing-delivery-icount",
            bytes: missing_delivery_icount,
            error: SpscRingError::SnapshotDecodeTruncated {
                offset: 8,
                needed: 31,
                available: 0,
            },
        },
        MalformedSnapshotCase {
            name: "truncated-seq",
            bytes: truncated_seq,
            error: SpscRingError::SnapshotDecodeTruncated {
                offset: 8,
                needed: 31,
                available: 12,
            },
        },
        MalformedSnapshotCase {
            name: "oversized-payload",
            bytes: oversized_payload,
            error: SpscRingError::InvalidFrameLength {
                len: MAX_FRAME_DATA + 1,
                capacity: MAX_FRAME_DATA,
            },
        },
        MalformedSnapshotCase {
            name: "truncated-payload",
            bytes: truncated_payload,
            error: SpscRingError::SnapshotDecodeTruncated {
                offset: 39,
                needed: 3,
                available: 2,
            },
        },
        MalformedSnapshotCase {
            name: "invalid-delivery-state",
            bytes: invalid_delivery_state,
            error: SpscRingError::InvalidFrameDeliveryState { state: 0xff },
        },
        MalformedSnapshotCase {
            name: "trailing-after-empty-snapshot",
            bytes: trailing_after_empty,
            error: SpscRingError::SnapshotDecodeTrailingBytes {
                offset: 8,
                available: 1,
            },
        },
    ]
}

fn snapshot_frame_prefix(delivery_icount: u64, src_node: u32, seq: u32, len: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&delivery_icount.to_le_bytes());
    bytes.extend_from_slice(&src_node.to_le_bytes());
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.push(FRAME_DELIVERY_PENDING);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes
}

fn payload(frame: &FrameEntry) -> &[u8] {
    match frame.payload() {
        Ok(payload) => payload,
        Err(error) => panic!("test frame payload should be valid: {error}"),
    }
}
