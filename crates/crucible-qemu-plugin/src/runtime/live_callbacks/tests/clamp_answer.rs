//! Budget-query answers to a clamp the control boundary already answered.
//!
//! The host's post-quantum clamp is a zero-length advance with a control
//! request; it completes on the request's ACK. A budget query that answers
//! the same advance afterwards republishes the clamp marker with a fresh
//! generation, which the host reads as the next RUN's report. These cases
//! pin that such a query publishes nothing, while a zero-length advance that
//! carries no request is still answered exactly once.

use super::*;
use crate::runtime::live_callbacks::tests::zero_length_idle::{
    MARKER_ICOUNT, MARKER_RAW, answer_control_request,
};

fn publish_advance(slot: &NodeSlot, current: u64, ceiling: u64) {
    let ceiling = authorize_advance_ceiling(current, ceiling, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
}

/// Builds a node that ran to `MARKER_ICOUNT` and whose clamp there the
/// control boundary answered, leaving the zero-length idle marker.
fn state_after_answered_clamp(slot: &NodeSlot) -> Box<LiveVcpuTimeCallbackState> {
    publish_advance(slot, 0, 500);
    let state = Box::new(
        test_live_state(82, 1, 0, slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .publish_current_icount(MARKER_RAW)
        .unwrap_or_else(|error| panic!("progress should publish: {error}"));

    publish_advance(slot, MARKER_ICOUNT, MARKER_ICOUNT);
    answer_control_request(&state, slot);
    let marker = slot.snapshot();
    assert_eq!(marker.status, STATUS_IDLE);
    assert_eq!(marker.current_icount, MARKER_ICOUNT);
    assert_eq!(marker.idle_wake_icount, MARKER_ICOUNT);
    state
}

/// Runs one budget query at the marker coordinate.
fn query_budget(state: &LiveVcpuTimeCallbackState) {
    TEST_ICOUNT_RAW.set(MARKER_RAW);
    let budget = state.max_advance_icount();
    TEST_ICOUNT_RAW.set(0);
    assert_eq!(budget, Ok(MARKER_RAW));
}

#[test]
fn a_budget_query_after_the_clamps_control_boundary_publishes_nothing() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state_after_answered_clamp(&slot);
    let marker = slot.snapshot();

    query_budget(&state);

    assert_eq!(slot.snapshot(), marker);
}

#[test]
fn a_zero_length_advance_without_a_request_is_still_answered_once() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state_after_answered_clamp(&slot);

    // The next RUN also ends at the marker and carries no control request.
    publish_advance(&slot, MARKER_ICOUNT, MARKER_ICOUNT);
    let before = slot.snapshot();
    query_budget(&state);

    let answered = slot.snapshot();
    assert_eq!(answered.publish_gen, before.publish_gen + 2);
    assert_eq!(answered.status, STATUS_IDLE);
    assert_eq!(answered.current_icount, MARKER_ICOUNT);

    query_budget(&state);
    assert_eq!(slot.snapshot(), answered);
}
