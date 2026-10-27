//! Device waits may arm an idle jump only while QEMU cannot dispatch a vCPU.
//!
//! A block coroutine runs either on QEMU's main loop, while the RR thread
//! executes guest code with the BQL released, or on the RR thread itself. On
//! the RR thread its first pass runs inside the guest's queue kick, which
//! returns to the running vCPU, while a resumed pass runs in a nested poll
//! that blocks the vCPU mid-instruction. These cases replay the interleavings
//! in which a vCPU could still retire instructions after the wait armed a
//! jump, and the blocked-RR cases in which only the wait can move time.

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

/// Records another thread as the RR vCPU thread, so waits here model the main loop.
pub(super) fn run_rr_vcpu_thread_elsewhere(state: &LiveVcpuTimeCallbackState) {
    let rr_vcpu_thread = std::thread::spawn(super::super::device_wait::current_thread_identity)
        .join()
        .unwrap_or_else(|_| panic!("identity thread should finish"));
    state
        .rr_vcpu_thread
        .store(rr_vcpu_thread, Ordering::Release);
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

/// Runs a request's first wait on the RR thread, as its queue kick does.
///
/// The vCPU returns to guest code after that pass, so it must not arm.
fn submit_from_the_rr_thread(state: &LiveVcpuTimeCallbackState, request_id: u32) {
    state.note_block_poll(0, request_id, false);
    state
        .on_block_wait(request_id)
        .unwrap_or_else(|error| panic!("the first wait should retry: {error}"));
    assert_wait_did_not_arm(state);
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
    run_rr_vcpu_thread_elsewhere(&state);
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
    run_rr_vcpu_thread_elsewhere(&state);
    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("dispatchable-vCPU wait should retry: {error}"));
    assert_wait_did_not_arm(&state);

    // Once QEMU reports the vCPU idle again, the same wait arms its deadline.
    park_every_vcpu(&state);
    run_rr_vcpu_thread_elsewhere(&state);
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
    run_rr_vcpu_thread_elsewhere(&state);
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
    run_rr_vcpu_thread_elsewhere(&state);
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
    run_rr_vcpu_thread_elsewhere(&state);
    state
        .on_block_wait(2)
        .unwrap_or_else(|error| panic!("dispatchable-vCPU wait should retry: {error}"));
    assert_wait_did_not_arm(&state);
}

#[test]
fn block_wait_on_the_io_blocked_rr_thread_arms_without_halted_vcpus() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    // The vCPU initializes and submits a request from its queue kick on this
    // same RR thread; a nested poll there then resumes the parked request,
    // so the vCPU is held mid-instruction, not halted.
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    reset_queue_witnesses();
    submit_from_the_rr_thread(&state, 1);

    state
        .on_block_wait(1)
        .unwrap_or_else(|error| panic!("I/O-blocked wait should arm: {error}"));

    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), DEVICE_DEADLINE as i64);
    assert!(state.idle_advance_is_pending());
}

#[test]
fn block_wait_on_the_io_blocked_rr_thread_advances_past_an_overdue_timer() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    reset_queue_witnesses();
    // The guest sits at 200 ps with a timer already due at 100 ps. Only an
    // advance can run it while the RR thread is blocked in the I/O.
    TEST_ICOUNT_RAW.set(4);
    TEST_CLOCK_DEADLINE_PS.set(100);
    submit_from_the_rr_thread(&state, 1);

    let result = state.on_block_wait(1);
    TEST_ICOUNT_RAW.set(0);
    TEST_CLOCK_DEADLINE_PS.set(-1);

    result.unwrap_or_else(|error| panic!("I/O-blocked wait should arm: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), DEVICE_DEADLINE as i64);
}

#[test]
fn block_wait_on_the_main_loop_leaves_an_overdue_timer_to_the_idle_path() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    park_every_vcpu(&state);
    reset_queue_witnesses();
    TEST_ICOUNT_RAW.set(4);
    TEST_CLOCK_DEADLINE_PS.set(100);
    run_rr_vcpu_thread_elsewhere(&state);

    let result = state.on_block_wait(1);
    TEST_ICOUNT_RAW.set(0);
    TEST_CLOCK_DEADLINE_PS.set(-1);

    // The parked RR thread dispatches the due timer itself, at 200 ps.
    result.unwrap_or_else(|error| panic!("main-loop wait should retry: {error}"));
    assert_wait_did_not_arm(&state);
}

#[test]
fn block_wait_from_a_queue_kick_on_the_rr_thread_leaves_time_to_the_vcpu() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    // The running vCPU kicks its queue on the RR thread. The request's first
    // pass parks and returns to the vCPU, which keeps retiring instructions;
    // a jump armed here would pin a raw coordinate it passes.
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    reset_queue_witnesses();
    TEST_ICOUNT_RAW.set(4);
    state.note_block_poll(0, 1, false);

    let result = state.on_block_wait(1);
    TEST_ICOUNT_RAW.set(0);

    result.unwrap_or_else(|error| panic!("the first wait should retry: {error}"));
    assert_wait_did_not_arm(&state);
}

#[test]
fn a_completed_request_identifier_starts_again_as_a_first_pass() {
    let slot = device_wait_slot();
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    reset_queue_witnesses();
    submit_from_the_rr_thread(&state, 1);

    // The request completes, so a later request with the same identifier,
    // or any request after a transport epoch change, is a new submission.
    state.note_block_poll(0, 1, true);
    submit_from_the_rr_thread(&state, 1);
    state.note_block_poll(1, 2, false);
    submit_from_the_rr_thread(&state, 1);
}
