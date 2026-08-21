//! Scheduler-resolved QEMU frame-delivery tests.

use super::*;

#[test]
fn qemu_quantum_deliver_frame_assigns_router_sequences() {
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

    let first = QemuShmemHotPathChannel::deliver_frame(
        &mut hot_path,
        BackendInput {
            node: node_id("vm-a"),
            payload: b"first".to_vec(),
        },
    );
    assert!(first.is_ok());
    let second = QemuShmemHotPathChannel::deliver_frame(
        &mut hot_path,
        BackendInput {
            node: node_id("vm-a"),
            payload: b"second".to_vec(),
        },
    );
    assert!(second.is_ok());

    let pending = match hot_path.start_quantum(horizon(1)) {
        Ok(pending) => pending,
        Err(error) => panic!("router-delivered frames should authorize exact horizon: {error}"),
    };
    let consumed = plugin_consume_inbound(&mut hot_path, 2);
    if let Err(error) = slot.publish_reached_icount(1, 0) {
        panic!("plugin report should publish through shared node slot: {error}");
    }
    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("router-delivered frames should drain: {error}"),
    };

    assert_eq!(
        consumed
            .iter()
            .map(FrameEntry::delivery_key)
            .collect::<Vec<_>>(),
        vec![
            frame(1, 31, 0, b"first").delivery_key(),
            frame(1, 31, 1, b"second").delivery_key(),
        ]
    );
    assert_eq!(
        consumed
            .iter()
            .map(|frame| frame.payload().expect("test frame payload is valid"))
            .collect::<Vec<_>>(),
        vec![b"first".as_slice(), b"second".as_slice()]
    );
    assert_eq!(report.inbound_frames_consumed, 2);
}

#[test]
fn qemu_quantum_preserves_scheduler_resolved_delivery_icount() {
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

    let delivered = QemuShmemHotPathChannel::deliver_frame_at(
        &mut hot_path,
        BackendInput {
            node: node_id("vm-a"),
            payload: b"exact".to_vec(),
        },
        icount(7),
    );
    assert!(delivered.is_ok());
    let entry = inbound_ring
        .peek(&inbound_entries)
        .unwrap_or_else(|error| panic!("timestamped inbound frame should be readable: {error}"))
        .unwrap_or_else(|| panic!("timestamped inbound frame should be queued"));
    assert_eq!(entry.delivery_icount, 7);
}

#[test]
fn qemu_quantum_deliver_frame_fails_loud_on_sequence_overflow() {
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
    hot_path.next_router_inbound_sequence = u64::from(u32::MAX);

    let last = QemuShmemHotPathChannel::deliver_frame(
        &mut hot_path,
        BackendInput {
            node: node_id("vm-a"),
            payload: b"last".to_vec(),
        },
    );
    assert!(last.is_ok());
    assert_eq!(inbound_ring.write_index(), 1);
    let overflow = QemuShmemHotPathChannel::deliver_frame(
        &mut hot_path,
        BackendInput {
            node: node_id("vm-a"),
            payload: b"overflow".to_vec(),
        },
    );

    assert_eq!(
        overflow,
        Err(QemuNodeChannelError::new(
            "qemu_quantum_shmem_hot_path",
            "QEMU quantum inbound router sequence overflow at 4294967296",
        ))
    );
    assert_eq!(inbound_ring.write_index(), 1);
    let entry = match inbound_ring.dequeue(hot_path.view.inbound_entries) {
        Ok(Some(entry)) => entry,
        Ok(None) => panic!("last sequence frame should be queued"),
        Err(error) => panic!("last sequence frame should dequeue: {error}"),
    };
    assert_eq!(entry.seq, u32::MAX);
    assert_eq!(
        entry.delivery_key(),
        frame(1, 31, u32::MAX, b"last").delivery_key()
    );
}
