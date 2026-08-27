//! Logical-time restore acknowledgement ordering tests.

use super::*;

#[test]
fn post_vmstate_pause_reconstructs_idle_jump_offset_before_acknowledging() {
    let args = crate::PluginArgs::parse(
        "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=23,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=11,app_random_cap=8,app_random_node=node-a,app_random_draw_offset=2,app_random_positions=6e6f64652d612f776f726b6c6f6164:2",
    )
    .unwrap_or_else(|error| panic!("continuation configuration should parse: {error}"));
    let config = args
        .app_random()
        .unwrap_or_else(|| panic!("continuation configuration should include app-random"));
    let mut app_random =
        super::super::super::live_whitebox::install_app_random_restore_state_for_test(config);
    app_random.set_draws(7);

    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, 0))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let priming = authorize_advance_ceiling(0, 100, None)
        .unwrap_or_else(|error| panic!("priming ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(priming)
        .unwrap_or_else(|error| panic!("priming ceiling should publish: {error}"));
    slot.publish_reached_icount(100, 0)
        .unwrap_or_else(|error| panic!("priming boundary should publish: {error}"));
    let outbound_header = RingHeader::new();
    let inbound_header = RingHeader::new();
    let mut outbound_entries = vec![FrameEntry::default(); 2];
    let mut inbound_entries = vec![FrameEntry::default(); 2];
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
    let rx_queue = QemuCanonicalNetworkRx::require(Some(test_reentrant_net_inject))
        .unwrap_or_else(|error| panic!("test RX queue should build: {error}"));
    let state = test_live_state_with_teardown(88, 1, 0, 100, &header, &slot, mpsc::channel().0)
        .and_then(|state| state.attach_network(0, outbound, inbound, rx_queue, 23))
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    let network = state
        .network
        .as_ref()
        .unwrap_or_else(|| panic!("test network state should be attached"));
    network.tx.restore_next_seq(29);
    assert_eq!(network.tx.next_seq(), 29);
    let restored_ceiling = authorize_advance_ceiling(100, 500, None)
        .unwrap_or_else(|error| panic!("restore ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(restored_ceiling)
        .unwrap_or_else(|error| panic!("restore ceiling should publish: {error}"));
    let generation = slot
        .arm_logical_time_restore(500)
        .unwrap_or_else(|error| panic!("logical-time restore should arm: {error}"));
    header
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("restore pause should publish: {error}"));
    TEST_REQUEST_VMSTOP_CALLS.set(0);

    assert_eq!(state.restore_logical_time_if_requested(40, false), Ok(()));
    let device_boundary = slot.snapshot();
    assert_ne!(device_boundary.logical_time_restore_ack, generation);
    assert_eq!(state.logical_icount_offset.load(Ordering::Acquire), 460);
    assert_eq!(network.tx.next_seq(), 23);
    assert_eq!(app_random.draws(), 2);

    network.tx.restore_next_seq(31);
    app_random.set_draws(3);
    assert_eq!(state.restore_logical_time_if_requested(40, false), Ok(()));
    assert_eq!(network.tx.next_seq(), 31);
    assert_eq!(app_random.draws(), 3);

    assert_eq!(state.publish_pause_if_requested(40), Ok(true));

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.logical_time_restore_request, generation);
    assert_eq!(snapshot.logical_time_restore_ack, generation);
    assert_eq!(snapshot.current_icount, 500);
    assert_eq!(snapshot.logical_time_raw_icount, 40);
    assert_eq!(state.logical_icount_offset.load(Ordering::Acquire), 460);
    assert_eq!(state.logical_icount_for_raw(41), Ok(501));
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
}
