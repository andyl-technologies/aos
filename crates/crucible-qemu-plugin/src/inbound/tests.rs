//! Tests for canonical inbound-frame ordering and retained provenance.

use super::*;

#[test]
fn inbound_frame_peek_uses_minimum_head_delivery_without_consuming() {
    let ring_a = RingHeader::new();
    let ring_b = RingHeader::new();
    let mut entries_a = empty_entries();
    let mut entries_b = empty_entries();
    enqueue(&ring_a, &mut entries_a, frame(30, 1, 0, b"a"));
    enqueue(&ring_b, &mut entries_b, frame(12, 2, 0, b"b"));

    assert_eq!(
        PluginInboundFrames::peek_next_delivery_icount([
            InboundFrameRing::new(0, &ring_a, &entries_a),
            InboundFrameRing::new(1, &ring_b, &entries_b),
        ]),
        Ok(Some(12))
    );
    assert_eq!(ring_a.read_index(), 0);
    assert_eq!(ring_b.read_index(), 0);
}

#[test]
fn inbound_frame_drain_delivers_current_icount_in_total_order() {
    let ring_a = RingHeader::new();
    let ring_b = RingHeader::new();
    let mut entries_a = empty_entries();
    let mut entries_b = empty_entries();
    enqueue(&ring_a, &mut entries_a, frame(20, 9, 4, b"third"));
    enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"first"));
    enqueue(&ring_b, &mut entries_b, frame(20, 4, 1, b"second"));
    enqueue(&ring_b, &mut entries_b, frame(25, 0, 0, b"future"));

    let batch = match PluginInboundFrames::drain_deliverable(
        [
            InboundFrameRing::new(4, &ring_a, &entries_a),
            InboundFrameRing::new(5, &ring_b, &entries_b),
        ],
        20,
    ) {
        Ok(batch) => batch,
        Err(error) => panic!("current inbound frames should drain: {error}"),
    };

    assert_eq!(batch.current_icount(), 20);
    assert_eq!(
        batch
            .frames()
            .iter()
            .map(FrameEntry::delivery_key)
            .collect::<Vec<_>>(),
        vec![
            frame(20, 1, 7, b"first").delivery_key(),
            frame(20, 4, 1, b"second").delivery_key(),
            frame(20, 9, 4, b"third").delivery_key(),
        ]
    );
    assert_eq!(ring_a.read_index(), 2);
    assert_eq!(ring_b.read_index(), 1);
    assert_eq!(
        PluginInboundFrames::peek_next_delivery_icount([
            InboundFrameRing::new(4, &ring_a, &entries_a),
            InboundFrameRing::new(5, &ring_b, &entries_b),
        ]),
        Ok(Some(25))
    );
}

#[test]
fn inbound_frame_drain_since_includes_jumped_over_delivery_window() {
    let ring_a = RingHeader::new();
    let ring_b = RingHeader::new();
    let mut entries_a = empty_entries();
    let mut entries_b = empty_entries();
    enqueue(&ring_a, &mut entries_a, frame(12, 9, 4, b"third"));
    enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"second"));
    enqueue(&ring_b, &mut entries_b, frame(15, 4, 1, b"first"));
    enqueue(&ring_b, &mut entries_b, frame(25, 4, 2, b"future"));

    let preview = match PluginInboundFrames::preview_deliverable_since(
        [
            InboundFrameRing::new(4, &ring_a, &entries_a),
            InboundFrameRing::new(5, &ring_b, &entries_b),
        ],
        20,
        10,
    ) {
        Ok(batch) => batch,
        Err(error) => panic!("jump-window inbound frames should preview: {error}"),
    };
    assert_eq!(ring_a.read_index(), 0);
    assert_eq!(ring_b.read_index(), 0);
    assert_eq!(
        preview
            .frames()
            .iter()
            .map(FrameEntry::delivery_key)
            .collect::<Vec<_>>(),
        vec![
            frame(12, 9, 4, b"third").delivery_key(),
            frame(15, 4, 1, b"first").delivery_key(),
            frame(20, 1, 7, b"second").delivery_key(),
        ]
    );

    let batch = match PluginInboundFrames::drain_deliverable_since(
        [
            InboundFrameRing::new(4, &ring_a, &entries_a),
            InboundFrameRing::new(5, &ring_b, &entries_b),
        ],
        20,
        10,
    ) {
        Ok(batch) => batch,
        Err(error) => panic!("jump-window inbound frames should drain: {error}"),
    };

    assert_eq!(batch.current_icount(), 20);
    assert_eq!(batch.frames(), preview.frames());
    assert_eq!(ring_a.read_index(), 2);
    assert_eq!(ring_b.read_index(), 1);
    assert_eq!(
        PluginInboundFrames::peek_next_delivery_icount([
            InboundFrameRing::new(4, &ring_a, &entries_a),
            InboundFrameRing::new(5, &ring_b, &entries_b),
        ]),
        Ok(Some(25))
    );
}

#[test]
fn inbound_frame_drain_rejects_late_head_without_consuming() {
    let ring = RingHeader::new();
    let mut entries = empty_entries();
    enqueue(&ring, &mut entries, frame(19, 7, 2, b"late"));

    assert_eq!(
        PluginInboundFrames::drain_deliverable([InboundFrameRing::new(9, &ring, &entries)], 20),
        Err(InboundFrameError::DeliveryAlreadyPassed {
            ring_index: Some(9),
            consumer_current_icount: 20,
            frame: frame(19, 7, 2, b"late").delivery_key(),
        })
    );
    assert_eq!(ring.read_index(), 0);
}

#[test]
fn inbound_frame_drain_since_rejects_before_floor_without_consuming() {
    let ring = RingHeader::new();
    let mut entries = empty_entries();
    enqueue(&ring, &mut entries, frame(9, 7, 2, b"late"));

    assert_eq!(
        PluginInboundFrames::drain_deliverable_since(
            [InboundFrameRing::new(9, &ring, &entries)],
            20,
            10,
        ),
        Err(InboundFrameError::DeliveryAlreadyPassed {
            ring_index: Some(9),
            consumer_current_icount: 20,
            frame: frame(9, 7, 2, b"late").delivery_key(),
        })
    );
    assert_eq!(ring.read_index(), 0);
}

#[test]
fn inbound_retained_head_authorizes_blocked_fifo_backlog() {
    let ring = RingHeader::new();
    let mut entries = empty_entries();
    let retained = frame(8, 7, 2, b"retained");
    let successor = frame(9, 7, 3, b"successor");
    enqueue(&ring, &mut entries, retained.clone());
    enqueue(&ring, &mut entries, successor.clone());

    PluginInboundFrames::mark_retained_head(
        [InboundFrameRing::new(9, &ring, &entries)],
        retained.delivery_key(),
        10,
    )
    .unwrap_or_else(|error| panic!("live head should become retained: {error}"));
    let batch = PluginInboundFrames::preview_deliverable_since(
        [InboundFrameRing::new(9, &ring, &entries)],
        20,
        10,
    )
    .unwrap_or_else(|error| panic!("retained backlog should remain deliverable: {error}"));

    assert_eq!(
        batch
            .frames()
            .iter()
            .map(FrameEntry::delivery_key)
            .collect::<Vec<_>>(),
        vec![retained.delivery_key(), successor.delivery_key()]
    );
    assert_eq!(
        batch.frames()[0].delivery_state(),
        Ok(FrameDeliveryState::Retained)
    );
    assert_eq!(
        PluginInboundFrames::peek_next_delivery_icount([
            InboundFrameRing::new(9, &ring, &entries,)
        ]),
        Ok(Some(10 + crate::NETWORK_RX_RETRY_INTERVAL_ICOUNT))
    );
    assert_eq!(ring.read_index(), 0);
}

#[test]
fn inbound_rejects_retained_marker_away_from_ring_head() {
    let ring = RingHeader::new();
    let mut entries = empty_entries();
    let head = frame(10, 7, 2, b"head");
    let invalid = frame(11, 7, 3, b"invalid");
    invalid
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("test marker should set: {error}"));
    enqueue(&ring, &mut entries, head.clone());
    enqueue(&ring, &mut entries, invalid.clone());

    assert_eq!(
        PluginInboundFrames::preview_deliverable_since(
            [InboundFrameRing::new(9, &ring, &entries)],
            20,
            10,
        ),
        Err(InboundFrameError::RetainedHeadMismatch {
            expected: invalid.delivery_key(),
            actual: Some(head.delivery_key()),
        })
    );
    assert_eq!(ring.read_index(), 0);
}

#[test]
fn inbound_frame_select_rejects_late_candidate_frame() {
    assert_eq!(
        PluginInboundFrames::select_deliverable_frames([frame(7, 1, 1, b"late")], 8),
        Err(InboundFrameError::DeliveryAlreadyPassed {
            ring_index: None,
            consumer_current_icount: 8,
            frame: frame(7, 1, 1, b"late").delivery_key(),
        })
    );
}

#[test]
fn inbound_frame_ring_errors_are_fail_loud() {
    let ring = RingHeader::new();
    let entries = vec![FrameEntry::default(); 3];

    assert_eq!(
        PluginInboundFrames::peek_next_delivery_icount([InboundFrameRing::new(
            11, &ring, &entries
        )]),
        Err(InboundFrameError::RingOperation {
            ring_index: 11,
            source: SpscRingError::InvalidCapacity { capacity: 3 },
        })
    );
}

fn empty_entries() -> Vec<FrameEntry> {
    vec![FrameEntry::default(); 4]
}

fn enqueue(header: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
    if let Err(error) = PluginShmemOrdering::enqueue_outbound_frame(header, entries, &frame) {
        panic!("test frame should enqueue: {error}");
    }
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test frame should fit: {error}"),
    }
}
