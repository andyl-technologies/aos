//! Bounded-ceiling settlement cases (RFC-0010 SCHED-12, SCHED-28).
//!
//! A ceiling bounds a node without becoming a stop: a halted node with no wake
//! parks, and the sim loop's settled publication records the ceiling only
//! while the live advance still names it.

use super::*;

use crucible_shmem::{IDLE_WAKE_NONE, TICKS_PER_INSTRUCTION};

fn slot_with_ceiling(ceiling_icount: u64, stop: AdvanceStopCondition) -> NodeSlot {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, ceiling_icount, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, stop)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot
}

#[test]
fn halted_node_without_a_wake_parks_below_a_bare_ceiling() {
    let slot = slot_with_ceiling(10, AdvanceStopCondition::Ceiling);
    let state = test_live_state(161, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_CLOCK_DEADLINE_PS.set(-1);
    LAST_QUEUED_ADVANCE_TICK.set(-1);

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("idle callback should park: {error}"));

    let snapshot = slot.snapshot();
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
    assert!(!state.idle_advance_is_pending());
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.current_icount, 0);
    assert_eq!(snapshot.idle_wake_icount, IDLE_WAKE_NONE);
}

#[test]
fn exact_event_tick_reports_plugin_events_but_not_a_bare_ceiling() {
    let bare = slot_with_ceiling(1_000, AdvanceStopCondition::Ceiling);
    let state = test_live_state(162, 1, 0, &bare)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    assert_eq!(state.exact_event_tick(), Ok(u64::MAX));

    // A device completion counts only while device I/O is active.
    bare.store_device_completion_deadline_tick(400);
    assert_eq!(state.exact_event_tick(), Ok(u64::MAX));
    bare.mark_device_io_active();
    assert_eq!(state.exact_event_tick(), Ok(400));

    let exact = slot_with_ceiling(1_000, AdvanceStopCondition::ExactEvent);
    let state = test_live_state(163, 1, 0, &exact)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    assert_eq!(state.exact_event_tick(), Ok(1_000));
}

#[test]
fn settled_publication_records_only_the_live_ceiling() {
    let slot = slot_with_ceiling(99, AdvanceStopCondition::Ceiling);
    let state = test_live_state(164, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));

    // QEMU sampled an older ceiling: the clock publishes without settlement.
    state
        .publish_boundary_icount(1, true, "test-settled", Some(98))
        .unwrap_or_else(|error| panic!("stale settlement should publish the clock: {error}"));
    assert_eq!(slot.snapshot().current_icount, TICKS_PER_INSTRUCTION);
    assert!(!slot.snapshot().settles_current_advance());

    // The next retirement would end at 100, past the ceiling of 99.
    state
        .publish_boundary_icount(1, true, "test-settled", Some(99))
        .unwrap_or_else(|error| panic!("settlement should publish: {error}"));
    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, TICKS_PER_INSTRUCTION);
    assert!(snapshot.settles_current_advance());
    assert_eq!(snapshot.settled_ceiling_tick, 99);
}
