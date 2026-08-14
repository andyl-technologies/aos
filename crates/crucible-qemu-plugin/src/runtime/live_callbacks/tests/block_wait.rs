//! Block-wait and joined-completion callback cases.

use super::*;

#[test]
fn live_block_wait_defers_until_the_host_publishes_a_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(48, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(-1);
    LAST_QUEUED_ADVANCE_NS.set(-1);

    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("unpublished device deadline should defer: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), -1);
}

#[test]
fn live_block_wait_parks_when_an_advance_still_owns_the_qemu_barrier() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.store_device_completion_deadline_icount(12);
    let state = test_live_state(48, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(-1);
    LAST_QUEUED_ADVANCE_NS.set(-1);
    TEST_QUEUED_ADVANCE_STATUS.set(-libc::EBUSY);

    let result = state.on_block_wait(1);
    TEST_QUEUED_ADVANCE_STATUS.set(0);

    result.unwrap_or_else(|error| panic!("busy QEMU barrier should defer the waiter: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 12);
    assert!(
        state
            .try_pending_idle_advance()
            .unwrap_or_else(|error| panic!("pending state should remain readable: {error}"))
            .is_none()
    );
}

#[test]
fn live_block_wait_queues_and_commits_the_device_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.store_device_completion_deadline_icount(12);
    let state = test_live_state(48, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(-1);
    LAST_QUEUED_ADVANCE_NS.set(-1);

    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("device wait should queue its deadline: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 12);
    assert_eq!(slot.snapshot().current_icount, 0);
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 12))
        .unwrap_or_else(|error| panic!("device deadline completion should commit: {error}"));
    assert_eq!(slot.snapshot().current_icount, 12);
}

#[test]
fn live_block_wait_stops_at_scheduler_ceiling_before_device_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.store_device_completion_deadline_icount(50);
    let state = test_live_state(48, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(-1);
    LAST_QUEUED_ADVANCE_NS.set(-1);

    state.on_block_wait(1).unwrap_or_else(|error| {
        panic!("device wait should queue the authorized boundary: {error}")
    });
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 20);
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 20))
        .unwrap_or_else(|error| panic!("scheduler boundary should commit: {error}"));
    assert_eq!(slot.snapshot().current_icount, 20);
    assert_eq!(slot.device_completion_deadline_icount(), 50);
}

#[test]
fn live_block_wait_preserves_an_earlier_timer_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.store_device_completion_deadline_icount(12);
    let state = test_live_state(48, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(7);
    LAST_QUEUED_ADVANCE_NS.set(-1);

    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("device wait should retain exact timer ordering: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 7);
    TEST_CLOCK_DEADLINE_NS.set(-1);
}

#[test]
fn live_block_wait_arms_from_its_fresh_raw_coordinate() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.store_device_completion_deadline_icount(12);
    let state = test_live_state(48, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(-1);
    LAST_QUEUED_ADVANCE_NS.set(-1);
    TEST_ICOUNT_RAW.set(4);

    let result = state.on_block_wait(1);
    TEST_ICOUNT_RAW.set(0);

    result.unwrap_or_else(|error| panic!("device wait should arm from its sampled time: {error}"));
    assert_eq!(state.last_raw_icount.load(Ordering::Acquire), 4);
    assert_eq!(state.last_icount.load(Ordering::Acquire), 4);
    assert_eq!(slot.snapshot().current_icount, 4);
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 12);
}

#[test]
fn live_completion_joins_buffered_tx_inbound_ring_rx_and_clock_commit() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let outbound_header = RingHeader::new();
    let inbound_header = RingHeader::new();
    let mut outbound_entries = vec![FrameEntry::default(); 4];
    let mut inbound_entries = vec![FrameEntry::default(); 4];
    let inbound_frame = FrameEntry::new(7, SLOT_NET_ROUTER as u32, 0, b"inbound")
        .unwrap_or_else(|error| panic!("test inbound frame should build: {error}"));
    inbound_header
        .enqueue(&mut inbound_entries, &inbound_frame)
        .unwrap_or_else(|error| panic!("test inbound frame should enqueue: {error}"));
    let outbound = MappedDirectedRingMut {
        descriptor: DirectedRing {
            index: 0,
            src_slot: 0,
            dst_slot: SLOT_NET_ROUTER as u32,
        },
        header: &outbound_header,
        entries: &mut outbound_entries,
    };
    let inbound = MappedDirectedRingMut {
        descriptor: DirectedRing {
            index: 1,
            src_slot: SLOT_NET_ROUTER as u32,
            dst_slot: 0,
        },
        header: &inbound_header,
        entries: &mut inbound_entries,
    };
    let rx_queue =
        QemuLosslessNetworkRxQueue::require(Some(test_net_send), Some(test_reentrant_net_flush))
            .unwrap_or_else(|error| panic!("test RX queue should build: {error}"));
    let state = Box::new(
        test_live_state(49, 1, 0, 0, &slot)
            .and_then(|state| state.attach_network(0, outbound, inbound, rx_queue))
            .unwrap_or_else(|error| panic!("live network callback state should build: {error}")),
    );
    TEST_REENTRANT_RX_STATE.store(
        std::ptr::from_ref(state.as_ref()).cast_mut(),
        Ordering::Release,
    );
    state
        .on_vcpu_init(49, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(-1);
    LAST_QUEUED_ADVANCE_NS.set(-1);
    TEST_RX_SEND_COUNT.store(0, Ordering::SeqCst);
    TEST_RX_FLUSH_COUNT.store(0, Ordering::SeqCst);
    TEST_RX_LAST_LEN.store(0, Ordering::SeqCst);
    TEST_RX_SEND_STATUS.store(0, Ordering::SeqCst);

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("inbound-aware idle callback should queue: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 7);
    state
        .on_network_tx(b"timer-tx")
        .unwrap_or_else(|error| panic!("pending timer TX should buffer: {error}"));
    assert_eq!(outbound_header.write_index(), 0);
    assert_eq!(inbound_header.read_index(), 0);
    assert_eq!(slot.snapshot().current_icount, 0);
    assert_eq!(TEST_RX_SEND_COUNT.load(Ordering::SeqCst), 0);

    assert!(matches!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 8)),
        Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletion { .. })
    ));
    assert_eq!(outbound_header.write_index(), 0);
    assert_eq!(inbound_header.read_index(), 0);
    assert_eq!(slot.snapshot().current_icount, 0);
    assert_eq!(TEST_RX_SEND_COUNT.load(Ordering::SeqCst), 0);

    TEST_RX_SEND_STATUS.store(5, Ordering::SeqCst);
    assert!(matches!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 7)),
        Err(LiveVcpuTimeCallbackError::NetworkRx { .. })
    ));
    assert_eq!(outbound_header.write_index(), 0);
    assert_eq!(inbound_header.read_index(), 0);
    assert_eq!(slot.snapshot().current_icount, 0);
    TEST_RX_SEND_STATUS.store(0, Ordering::SeqCst);

    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 7))
        .unwrap_or_else(|error| panic!("exact completion should commit network state: {error}"));
    TEST_REENTRANT_RX_STATE.store(std::ptr::null_mut(), Ordering::Release);
    assert_eq!(slot.snapshot().current_icount, 7);
    assert_eq!(outbound_header.write_index(), 2);
    assert_eq!(outbound_entries[0].delivery_icount, 7);
    assert_eq!(outbound_entries[0].payload(), Ok(b"timer-tx".as_slice()));
    assert_eq!(outbound_entries[1].delivery_icount, 7);
    assert_eq!(outbound_entries[1].payload(), Ok(b"flush-tx".as_slice()));
    assert_eq!(inbound_header.read_index(), 1);
    assert_eq!(TEST_RX_SEND_COUNT.load(Ordering::SeqCst), 2);
    assert_eq!(TEST_RX_LAST_LEN.load(Ordering::SeqCst), 7);
    assert_eq!(TEST_RX_FLUSH_COUNT.load(Ordering::SeqCst), 1);
}
