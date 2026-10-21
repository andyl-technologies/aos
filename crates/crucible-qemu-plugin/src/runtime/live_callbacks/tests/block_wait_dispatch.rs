//! Device waits may arm an idle jump only while QEMU cannot dispatch a vCPU.
//!
//! The block coroutine runs on QEMU's main loop while the RR thread executes
//! guest code with the BQL released. These cases replay the interleavings in
//! which a vCPU could still retire instructions after the wait armed a jump.

use super::block_wait::park_every_vcpu;
use super::*;

const DEVICE_DEADLINE: u64 = 300;

fn device_wait_slot() -> NodeSlot {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 10_000, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.store_device_completion_deadline_tick(DEVICE_DEADLINE);
    slot
}

fn reset_queue_witnesses() {
    TEST_CLOCK_DEADLINE_PS.set(-1);
    LAST_QUEUED_ADVANCE_TICK.set(-1);
    TEST_ICOUNT_RAW.set(0);
}

fn assert_wait_did_not_arm(state: &LiveVcpuTimeCallbackState) {
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
    assert!(!state.idle_advance_is_pending());
}

fn assert_dispatchable_with_retained_halt_bit(state: &LiveVcpuTimeCallbackState) {
    let halted_vcpus = state
        .try_halted_vcpus()
        .unwrap_or_else(|error| panic!("halt tracker should be free: {error}"));
    assert!(halted_vcpus.all_halted());
    assert!(!halted_vcpus.all_halted_and_parked());
}

#[test]
fn block_wait_leaves_time_to_a_running_vcpu() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    reset_queue_witnesses();
    TEST_ICOUNT_RAW.set(4);

    // The vCPU is mid-slice when the coroutine parks on its request.
    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("running-vCPU wait should retry: {error}"));

    // The slice retires 50 more instructions; the next budget query must see
    // ordinary progress, not a jump pinned at the coroutine's sample.
    TEST_ICOUNT_RAW.set(54);
    let budget = state.max_advance_icount();
    TEST_ICOUNT_RAW.set(0);
    assert!(budget.is_ok(), "guest progress must stay legal: {budget:?}");
    assert_wait_did_not_arm(&state);
}

#[test]
fn block_wait_does_not_arm_after_a_control_deferred_resume() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    park_every_vcpu(&state);
    reset_queue_witnesses();
    slot.request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));

    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("control-deferred resume should return: {error}"));
    assert_dispatchable_with_retained_halt_bit(&state);
    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("dispatchable-vCPU wait should retry: {error}"));
    assert_wait_did_not_arm(&state);

    // Once QEMU reports the vCPU idle again, the same wait arms its deadline.
    park_every_vcpu(&state);
    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("parked wait should arm: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), DEVICE_DEADLINE as i64);
}

#[test]
fn block_wait_does_not_arm_after_a_pause_deferred_resume() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = device_wait_slot();
    let (sender, receiver) = mpsc::channel();
    std::mem::forget(receiver);
    let state = test_live_state_with_teardown(48, 1, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    park_every_vcpu(&state);
    reset_queue_witnesses();
    header
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));

    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("pause-deferred resume should return: {error}"));
    header.clear_pause();
    assert_dispatchable_with_retained_halt_bit(&state);
    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("dispatchable-vCPU wait should retry: {error}"));
    assert_wait_did_not_arm(&state);
}

#[test]
fn block_wait_does_not_arm_after_a_resume_during_a_pending_jump() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    park_every_vcpu(&state);
    reset_queue_witnesses();
    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("parked wait should arm: {error}"));
    assert!(state.idle_advance_is_pending());

    // A control boundary lets the resume return while the jump is pending.
    slot.request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));
    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("control resume should return: {error}"));
    assert_dispatchable_with_retained_halt_bit(&state);
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, DEVICE_DEADLINE as i64))
        .unwrap_or_else(|error| panic!("pending jump should complete: {error}"));

    slot.store_device_completion_deadline_tick(DEVICE_DEADLINE + 100);
    LAST_QUEUED_ADVANCE_TICK.set(-1);
    state
        .on_block_wait(2)
        .unwrap_or_else(|error| panic!("dispatchable-vCPU wait should retry: {error}"));
    assert_wait_did_not_arm(&state);
}
