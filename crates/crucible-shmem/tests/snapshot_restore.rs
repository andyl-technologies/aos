//! Checks quiescent SPSC snapshot/restore and canonical snapshot bytes.

#![forbid(unsafe_code)]

use crucible_shmem::{FrameEntry, MAX_FRAME_DATA, RingHeader, SpscRingError, SpscRingSnapshot};

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
    assert_eq!(snapshot.canonical_bytes(), Ok(canonical_bytes(&expected)));
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
        bytes.extend_from_slice(payload(frame));
    }
    bytes
}

fn payload(frame: &FrameEntry) -> &[u8] {
    match frame.payload() {
        Ok(payload) => payload,
        Err(error) => panic!("test frame payload should be valid: {error}"),
    }
}
