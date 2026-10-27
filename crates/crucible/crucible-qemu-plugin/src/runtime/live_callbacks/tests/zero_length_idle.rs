//! A control boundary below the ceiling against the zero-length idle record.
//!
//! Each case starts a RUN at the coordinate where a settled clamp left its
//! zero-length idle marker. A control boundary QEMU answers there must drop
//! that marker, while every stop the node takes for the RUN at the same
//! coordinate, with no progress, must survive the same control boundary.

use super::*;
use crate::runtime::live_callbacks::console_effect::{
    ConsoleControlDisposition, ConsoleControlEffect, ConsoleControlPreparation,
    NativeConsoleControlOwner, SettledConsoleControl,
};
use crucible_qemu_protocol::native_console::NativeConsoleError;
use crucible_qemu_shmem::{NodeBoundaryPublication, SchedulerAdvancePublication};

/// Raw retirement of the marker coordinate.
pub(in crate::runtime::live_callbacks) const MARKER_RAW: u64 = 9;
/// Logical coordinate of `MARKER_RAW` at fifty ticks per instruction.
pub(in crate::runtime::live_callbacks) const MARKER_ICOUNT: u64 = 450;

fn publish_advance(slot: &NodeSlot, ceiling: u64) {
    let ceiling = authorize_advance_ceiling(MARKER_ICOUNT, ceiling, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_qemu_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
}

pub(in crate::runtime::live_callbacks) fn answer_control_request(
    state: &LiveVcpuTimeCallbackState,
    slot: &NodeSlot,
) {
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));
    state
        .on_control_boundary(MARKER_RAW)
        .unwrap_or_else(|error| panic!("control boundary should publish: {error}"));
    assert_eq!(
        slot.snapshot().control_boundary_ack,
        request.wrapping_add(1)
    );
}

/// Builds a node that ran to `MARKER_ICOUNT`, was clamped there and settled,
/// then received the next RUN toward a later ceiling.
pub(in crate::runtime::live_callbacks) fn state_at_ceiling_marker(
    slot: &NodeSlot,
) -> Box<LiveVcpuTimeCallbackState> {
    let first = authorize_advance_ceiling(0, 500, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(first, crucible_qemu_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = Box::new(
        test_live_state(81, 1, 0, slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    state
        .publish_current_icount(MARKER_RAW)
        .unwrap_or_else(|error| panic!("progress should publish: {error}"));

    publish_advance(slot, MARKER_ICOUNT);
    answer_control_request(&state, slot);
    let marker = slot.snapshot();
    assert_eq!(marker.status, STATUS_IDLE);
    assert_eq!(marker.current_icount, MARKER_ICOUNT);
    assert_eq!(marker.idle_wake_icount, MARKER_ICOUNT);

    publish_advance(slot, 1_000);
    state
}

pub(in crate::runtime::live_callbacks) fn assert_stopped_at_marker(slot: &NodeSlot) {
    let stopped = slot.snapshot();
    assert_eq!(stopped.status, STATUS_IDLE);
    assert_eq!(stopped.current_icount, MARKER_ICOUNT);
    assert_eq!(stopped.idle_wake_icount, MARKER_ICOUNT);
    assert_eq!(stopped.max_advance_icount, 1_000);
}

#[test]
fn a_control_boundary_below_the_next_ceiling_drops_the_clamp_marker() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state_at_ceiling_marker(&slot);

    answer_control_request(&state, &slot);

    let running = slot.snapshot();
    assert_eq!(running.status, STATUS_RUNNING);
    assert_eq!(running.current_icount, MARKER_ICOUNT);
    assert!(!running.settles_current_advance());
}

#[test]
fn a_selectable_stop_at_the_marker_survives_a_control_boundary() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = state_at_ceiling_marker(&slot);
    let handoff = state.selectable_vmstop_handoff();
    assert_eq!(handoff.defer(test_force_vcpu_tb_exit), Ok(true));
    let userdata = std::ptr::from_ref(state.as_ref()).cast_mut().cast();
    crucible_qemu_plugin_live_publish_icount_cb(MARKER_RAW, userdata);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);

    answer_control_request(&state, &slot);

    assert_stopped_at_marker(&slot);
}

#[test]
fn a_campaign_marker_stop_at_the_marker_survives_a_control_boundary() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = state_at_ceiling_marker(&slot);
    let handoff = state.selectable_vmstop_handoff();
    assert_eq!(
        handoff.defer_campaign_marker(test_force_vcpu_tb_exit),
        Ok(true)
    );
    let userdata = std::ptr::from_ref(state.as_ref()).cast_mut().cast();
    crucible_qemu_plugin_live_publish_icount_cb(MARKER_RAW, userdata);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);

    answer_control_request(&state, &slot);

    assert_stopped_at_marker(&slot);
}

#[test]
fn a_checkpoint_pause_at_the_marker_survives_a_later_control_boundary() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = state_at_ceiling_marker(&slot);
    state
        .header
        .get()
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));

    answer_control_request(&state, &slot);
    assert_stopped_at_marker(&slot);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);

    // Once the pause request is withdrawn, the stop it published still
    // answers this advance; an ordinary control boundary keeps it.
    state.header.get().clear_pause();
    answer_control_request(&state, &slot);

    assert_stopped_at_marker(&slot);
}

/// A native owner that accepts every control publication.
struct AcceptingOwner;

impl NativeConsoleControlOwner for AcceptingOwner {
    fn prepare(
        &mut self,
        _settled: SettledConsoleControl,
        _logical: u64,
    ) -> Result<ConsoleControlPreparation, NativeConsoleError> {
        Ok(ConsoleControlPreparation::Prepared(
            ConsoleControlDisposition::Accepted,
        ))
    }

    fn commit(
        &mut self,
        _fields: NodeBoundaryPublication,
        _advance: SchedulerAdvancePublication,
    ) -> Result<ConsoleControlDisposition, NativeConsoleError> {
        Ok(ConsoleControlDisposition::Accepted)
    }

    fn clear(&mut self) {}
}

fn answer_console_control_request(state: &LiveVcpuTimeCallbackState, slot: &NodeSlot) {
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));
    let mut owner = AcceptingOwner;
    let mut effect = ConsoleControlEffect::new(&mut owner);
    state
        .on_control_boundary_with_console(MARKER_RAW, None, &mut |_| {}, Some(&mut effect))
        .unwrap_or_else(|error| panic!("console control boundary should publish: {error}"));
    assert!(effect.is_committed());
    assert_eq!(
        slot.snapshot().control_boundary_ack,
        request.wrapping_add(1)
    );
}

#[test]
fn a_console_control_boundary_below_the_next_ceiling_drops_the_clamp_marker() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state_at_ceiling_marker(&slot);

    answer_console_control_request(&state, &slot);

    let running = slot.snapshot();
    assert_eq!(running.status, STATUS_RUNNING);
    assert_eq!(running.current_icount, MARKER_ICOUNT);
}

#[test]
fn a_console_pause_at_the_marker_survives_a_later_console_control_boundary() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = state_at_ceiling_marker(&slot);
    state
        .header
        .get()
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));

    answer_console_control_request(&state, &slot);
    assert_stopped_at_marker(&slot);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);

    state.header.get().clear_pause();
    answer_console_control_request(&state, &slot);

    assert_stopped_at_marker(&slot);
}

#[test]
fn an_idle_wait_pause_at_the_marker_survives_a_later_control_boundary() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = state_at_ceiling_marker(&slot);
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    state
        .header
        .get()
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));

    // Every vCPU halts at the marker while the pause is requested; the idle
    // wait publishes the pause there without retiring anything.
    state
        .on_vcpu_idle(0, MARKER_RAW)
        .unwrap_or_else(|error| panic!("idle pause should publish: {error}"));
    assert_stopped_at_marker(&slot);
    // The idle callback's boundary publication and its scheduler wait each
    // publish the pause and request the stop; both write the same fields.
    assert_ne!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);

    state.header.get().clear_pause();
    answer_control_request(&state, &slot);

    assert_stopped_at_marker(&slot);
}
