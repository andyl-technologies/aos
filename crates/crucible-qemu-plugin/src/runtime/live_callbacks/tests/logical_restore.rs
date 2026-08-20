//! Logical-time restore acknowledgement ordering tests.

use super::*;

#[test]
fn post_vmstate_pause_reconstructs_idle_jump_offset_before_acknowledging() {
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
    let state = test_live_state_with_teardown(88, 1, 0, 100, &header, &slot, mpsc::channel().0)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
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
