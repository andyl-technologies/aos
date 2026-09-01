//! Canonical inbound retention and backpressure tests.

use super::*;

#[test]
fn qemu_quantum_preserves_backpressured_due_frame_for_retry() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    let expected = frame(5, 31, 1, b"plugin-owned");
    assert!(
        hot_path
            .enqueue_inbound_frame(QemuInboundFrame {
                delivery_icount: icount(5),
                src_node: expected.src_node,
                sequence: expected.seq,
                payload: expected.payload().unwrap_or_default().to_vec(),
            })
            .is_ok()
    );
    let pending = hot_path
        .start_quantum(horizon(5))
        .unwrap_or_else(|error| panic!("delivery quantum should start: {error}"));
    slot.publish_reached_icount(5, 0)
        .unwrap_or_else(|error| panic!("plugin boundary should publish: {error}"));
    plugin_mark_inbound_retained(&hot_path, 5);

    let report = hot_path
        .finish_quantum(pending)
        .unwrap_or_else(|error| panic!("backpressured delivery should remain canonical: {error}"));
    assert_eq!(report.inbound_frames_consumed, 0);
    assert_eq!(inbound_ring.read_index(), 0);
}

#[test]
fn qemu_quantum_caps_horizon_at_retained_fifo_head_retry() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    hot_path
        .enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 31,
            sequence: 1,
            payload: b"retained-head".to_vec(),
        })
        .unwrap_or_else(|error| panic!("retained head should enqueue: {error}"));
    let first = hot_path
        .start_quantum(horizon(5))
        .unwrap_or_else(|error| panic!("first delivery quantum should start: {error}"));
    slot.publish_reached_icount(5, 0)
        .unwrap_or_else(|error| panic!("first delivery boundary should publish: {error}"));
    plugin_mark_inbound_retained(&hot_path, 5);
    hot_path
        .finish_quantum(first)
        .unwrap_or_else(|error| panic!("retained delivery quantum should finish: {error}"));

    hot_path
        .enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT),
            src_node: 31,
            sequence: 2,
            payload: b"later-pending".to_vec(),
        })
        .unwrap_or_else(|error| panic!("later pending frame should enqueue: {error}"));
    let retry = hot_path
        .start_quantum(horizon(FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT + 10))
        .unwrap_or_else(|error| panic!("retained retry quantum should start: {error}"));

    assert_eq!(
        retry.ceiling,
        icount(5 + FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT)
    );
    let initial_publish_generation = retry.report_generation;
    assert_eq!(
        retry.completion_fence,
        Some(QemuAdvanceCompletionFence {
            initial_publish_generation,
        })
    );
}

#[test]
fn qemu_quantum_accepts_canonical_retained_frame_behind_current_icount() {
    let slot = NodeSlot::default();
    if let Err(error) = slot.publish_scheduler_ceiling(ceiling(0, 5)) {
        panic!("test ceiling should publish: {error}");
    }
    if let Err(error) = slot.publish_reached_icount(5, 0) {
        panic!("test current icount should publish: {error}");
    }
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    enqueue_raw(
        &inbound_ring,
        &mut inbound_entries,
        frame(4, 31, 7, b"retained"),
    );
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    plugin_mark_inbound_retained(&hot_path, 5);

    let pending = hot_path
        .start_quantum(horizon(5))
        .unwrap_or_else(|error| panic!("retained-frame quantum should start: {error}"));
    let report = hot_path
        .finish_quantum(pending)
        .unwrap_or_else(|error| panic!("retained late head should remain canonical: {error}"));

    assert_eq!(report.inbound_frames_consumed, 0);
    assert_eq!(inbound_ring.read_index(), 0);
}
