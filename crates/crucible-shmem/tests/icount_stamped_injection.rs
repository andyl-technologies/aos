//! Checks the icount-stamped frame ABI contract.

#![forbid(unsafe_code)]

use crucible_shmem::{
    FrameDeliveryKey, FrameEntry, FrameEntryError, MAX_FRAME_DATA, deliverable_frames_at,
};

#[test]
fn frame_entry_carries_delivery_icount_in_band() {
    let frame = frame(37, 4, 9, b"input");

    assert_eq!(frame.delivery_icount, 37);
    assert_eq!(frame.src_node, 4);
    assert_eq!(frame.seq, 9);
    assert_eq!(payload(&frame), b"input");
    assert!(!frame.is_deliverable_at(36));
    assert!(frame.is_deliverable_at(37));
}

#[test]
fn deliverability_depends_on_consumer_icount_not_arrival_order() {
    let frames = vec![
        frame(12, 2, 0, b"late"),
        frame(8, 9, 1, b"second"),
        frame(8, 1, 7, b"first"),
        frame(8, 1, 8, b"third"),
    ];

    let early = deliverable_frames_at(&frames, 7);
    assert!(early.is_empty());

    let visible = deliverable_frames_at(&frames, 8);
    let keys = visible
        .iter()
        .map(|frame| frame.delivery_key())
        .collect::<Vec<_>>();

    assert_eq!(
        keys,
        vec![
            FrameDeliveryKey {
                delivery_icount: 8,
                src_node: 1,
                seq: 7,
            },
            FrameDeliveryKey {
                delivery_icount: 8,
                src_node: 1,
                seq: 8,
            },
            FrameDeliveryKey {
                delivery_icount: 8,
                src_node: 9,
                seq: 1,
            },
        ]
    );
    assert_eq!(
        visible
            .iter()
            .map(|frame| payload(frame))
            .collect::<Vec<_>>(),
        vec![
            b"first".as_slice(),
            b"third".as_slice(),
            b"second".as_slice(),
        ]
    );
}

#[test]
fn same_icount_frames_resolve_by_source_node_then_sequence() {
    let frames = vec![
        frame(12, 7, 2, b"source-b-second"),
        frame(12, 4, 3, b"source-a-third"),
        frame(12, 4, 1, b"source-a-first"),
    ];

    let visible = deliverable_frames_at(&frames, 12);

    assert_eq!(
        visible
            .iter()
            .map(|frame| payload(frame))
            .collect::<Vec<_>>(),
        vec![
            b"source-a-first".as_slice(),
            b"source-a-third".as_slice(),
            b"source-b-second".as_slice(),
        ]
    );
}

#[test]
fn frame_entry_rejects_oversized_payload() {
    let payload = vec![0xa5; MAX_FRAME_DATA + 1];

    assert_eq!(
        FrameEntry::new(1, 2, 3, &payload),
        Err(FrameEntryError::PayloadLengthExceedsCapacity {
            len: MAX_FRAME_DATA + 1,
            capacity: MAX_FRAME_DATA,
        })
    );
}

#[test]
fn frame_entry_rejects_malformed_payload_length() {
    let mut frame = frame(1, 2, 3, b"ok");
    frame.len = (MAX_FRAME_DATA + 1) as u16;

    assert_eq!(
        frame.payload(),
        Err(FrameEntryError::PayloadLengthExceedsCapacity {
            len: MAX_FRAME_DATA + 1,
            capacity: MAX_FRAME_DATA,
        })
    );
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("frame entry should be valid: {error}"),
    }
}

fn payload(frame: &FrameEntry) -> &[u8] {
    match frame.payload() {
        Ok(payload) => payload,
        Err(error) => panic!("frame payload should be valid: {error}"),
    }
}
