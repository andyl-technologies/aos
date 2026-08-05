//! Live QEMU callback integration tests.

use super::*;

use std::cell::Cell;

use crucible_shmem::{
    KIND_VM, RegionConfig, RegionHeader, RegionLayout, STATUS_IDLE, STATUS_RUNNING,
    authorize_advance_ceiling,
};

mod block_wait;
mod preemption;
mod preflight_cases;

extern "C" fn test_icount_raw() -> u64 {
    0
}

thread_local! {
    static TEST_CLOCK_DEADLINE_NS: Cell<i64> = const { Cell::new(-1) };
    static LAST_QUEUED_ADVANCE_NS: Cell<i64> = const { Cell::new(-1) };
    static TEST_QUEUED_ADVANCE_STATUS: Cell<std::os::raw::c_int> = const { Cell::new(0) };
}
static TEST_RX_SEND_COUNT: AtomicU64 = AtomicU64::new(0);
static TEST_RX_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static TEST_RX_LAST_LEN: AtomicU64 = AtomicU64::new(0);
static TEST_RX_SEND_STATUS: AtomicU64 = AtomicU64::new(0);
static TEST_REENTRANT_RX_STATE: AtomicPtr<LiveVcpuTimeCallbackState> =
    AtomicPtr::new(std::ptr::null_mut());

extern "C" fn test_clock_deadline_ns() -> i64 {
    TEST_CLOCK_DEADLINE_NS.get()
}

fn test_live_state(
    plugin_id: QemuPluginId,
    vcpu_count: u32,
    icount_shift: u8,
    initial_raw_icount: u64,
    slot: &NodeSlot,
) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, u32::from(icount_shift)))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = Box::leak(Box::new(RegionHeader::new(layout)));
    let (teardown_sender, teardown_receiver) = mpsc::channel();
    std::mem::forget(teardown_receiver);
    test_live_state_with_teardown(
        plugin_id,
        vcpu_count,
        icount_shift,
        initial_raw_icount,
        header,
        slot,
        teardown_sender,
    )
}

// crucible-lint: allow rust-allow -- test factory carries the complete live callback state boundary.
#[allow(clippy::too_many_arguments)]
fn test_live_state_with_teardown(
    plugin_id: QemuPluginId,
    vcpu_count: u32,
    icount_shift: u8,
    initial_raw_icount: u64,
    header: &RegionHeader,
    slot: &NodeSlot,
    teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
    let exact_deadline = ExactDeadlineReader::require(Some(test_clock_deadline_ns))
        .unwrap_or_else(|error| panic!("test deadline capability should validate: {error}"));
    let queued_idle_advance = QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
    LiveVcpuTimeCallbackState::new(
        plugin_id,
        test_icount_raw,
        test_force_vcpu_exit,
        test_support::test_preemption_injector(),
        vcpu_count,
        icount_shift,
        initial_raw_icount,
        exact_deadline,
        queued_idle_advance,
        None,
        header,
        slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
    )
}

extern "C" fn test_force_vcpu_exit() {}

#[test]
fn shared_shutdown_resume_signal_is_one_shot_and_defers_done_to_worker() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, 0))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    let state = test_live_state_with_teardown(70, 1, 0, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(70, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .halted_vcpus
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .mark_halted(0)
        .unwrap_or_else(|error| panic!("test vCPU should enter halted state: {error}"));
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("resume should signal shutdown: {error}"));
    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("repeated resume should be coalesced: {error}"));

    assert!(matches!(
        receiver.try_recv(),
        Ok(LiveRuntimeTeardownTrigger::SharedShutdown(_))
    ));
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
}

#[test]
fn busy_at_ceiling_publish_callback_signals_shared_shutdown_without_publication() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, 0))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    let state = Box::new(
        test_live_state_with_teardown(73, 1, 0, 0, &header, &slot, sender)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    let userdata = std::ptr::from_ref(state.as_ref()).cast_mut().cast();
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    crucible_qemu_plugin_live_publish_icount_cb(1, userdata);

    assert!(matches!(
        receiver.try_recv(),
        Ok(LiveRuntimeTeardownTrigger::SharedShutdown(_))
    ));
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
    assert_eq!(slot.snapshot().current_icount, 0);
}

#[test]
fn shared_shutdown_idle_signal_is_one_shot_and_defers_done_to_worker() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, 0))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    let state = test_live_state_with_teardown(71, 1, 0, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(71, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("idle should signal shutdown: {error}"));

    assert!(matches!(
        receiver.try_recv(),
        Ok(LiveRuntimeTeardownTrigger::SharedShutdown(_))
    ));
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
}

#[test]
fn shared_shutdown_signal_is_fail_loud_when_teardown_worker_disconnected() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, 0))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let (sender, receiver) = mpsc::channel();
    drop(receiver);
    let state = test_live_state_with_teardown(72, 1, 0, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(72, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .halted_vcpus
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .mark_halted(0)
        .unwrap_or_else(|error| panic!("test vCPU should enter halted state: {error}"));
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    assert_eq!(
        state.on_vcpu_resume(0, 0),
        Err(LiveVcpuTimeCallbackError::TeardownWorkerUnavailable)
    );
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
}

#[test]
fn live_state_dispatches_vcpu_init_publish_and_ceiling() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 12, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(41, 2, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    state
        .on_vcpu_init(41, 0)
        .unwrap_or_else(|error| panic!("vCPU 0 should initialize: {error}"));
    state
        .on_vcpu_init(41, 1)
        .unwrap_or_else(|error| panic!("vCPU 1 should initialize: {error}"));
    state
        .publish_current_icount(5)
        .unwrap_or_else(|error| panic!("sim icount should publish: {error}"));
    assert_eq!(state.max_advance_icount(), Ok(12));
    assert_eq!(slot.snapshot().current_icount, 5);
    assert!(state.initialized_vcpus[0].load(Ordering::Acquire));
    assert!(state.initialized_vcpus[1].load(Ordering::Acquire));
}

#[test]
fn every_live_callback_entry_rejects_work_after_quiescence() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 12, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = Box::new(
        test_live_state(71, 1, 0, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    let state_pointer = std::ptr::from_ref(state.as_ref()).cast_mut();
    LIVE_VCPU_TIME_STATE.store(state_pointer, Ordering::Release);
    state.quiescence.close();
    let userdata = state_pointer.cast::<c_void>();
    let before = slot.snapshot();

    crucible_qemu_plugin_live_vcpu_init_cb(71, 0);
    crucible_qemu_plugin_live_vcpu_idle_cb(0, 0, userdata);
    crucible_qemu_plugin_live_vcpu_resume_cb(0, 0, userdata);
    crucible_qemu_plugin_live_publish_icount_cb(9, userdata);
    assert_eq!(crucible_qemu_plugin_live_max_advance_icount_cb(userdata), 0);
    crucible_qemu_plugin_live_time_advance_completion_cb(0, 0, userdata);
    assert_eq!(
        crucible_qemu_plugin_live_network_tx_cb(std::ptr::null(), 0, userdata),
        -1
    );
    assert_eq!(
        devices::crucible_qemu_plugin_live_block_submit_cb(0, 0, 0, std::ptr::null(), 0, userdata,),
        -1
    );
    assert_eq!(
        devices::crucible_qemu_plugin_live_block_poll_cb(0, std::ptr::null_mut(), 0, userdata,),
        -1
    );
    crucible_qemu_plugin_live_block_wait_cb(0, userdata);
    devices::crucible_qemu_plugin_live_ninep_burst_start_cb(userdata);
    assert_eq!(
        devices::crucible_qemu_plugin_live_ninep_submit_cb(0, std::ptr::null(), 0, 0, userdata,),
        -1
    );
    assert_eq!(
        devices::crucible_qemu_plugin_live_ninep_poll_cb(0, std::ptr::null_mut(), 0, userdata,),
        -1
    );
    devices::crucible_qemu_plugin_live_ninep_burst_done_cb(userdata);

    let after = slot.snapshot();
    assert_eq!(after, before);
    LIVE_VCPU_TIME_STATE.store(std::ptr::null_mut(), Ordering::Release);
}

#[test]
fn live_time_completion_commits_logical_idle_offset_before_future_raw_progress() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(43, 1, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(4)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(20)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(4, 10, pending)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    state
        .publish_current_icount(4)
        .unwrap_or_else(|error| panic!("repeated raw boundary should be a no-op: {error}"));
    assert!(matches!(
        state.publish_current_icount(5),
        Err(
            LiveVcpuTimeCallbackError::GuestProgressWhileIdleAdvancePending {
                expected_raw_icount: 4,
                observed_raw_icount: 5,
            }
        )
    ));
    assert_eq!(slot.snapshot().current_icount, 4);

    let committed = state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 20))
        .unwrap_or_else(|error| panic!("matching completion should commit: {error}"));
    assert_eq!(committed, 10);
    assert_eq!(slot.snapshot().current_icount, 10);

    state
        .publish_current_icount(5)
        .unwrap_or_else(|error| panic!("post-jump raw progress should publish: {error}"));
    assert_eq!(slot.snapshot().current_icount, 11);
}

#[test]
fn max_advance_translates_logical_ceiling_to_raw_after_idle_jump() {
    // QEMU's sim-loop budget clamp compares max_advance_icount() against raw
    // retired instructions (`qemu_plugin_icount_raw()`), while the scheduler
    // ceiling is a logical icount that includes the accumulated idle-jump offset
    // (`logical = raw + offset`). The reported limit must therefore be in raw
    // units so the clamp stops the guest exactly at the logical authorization.
    // A live idle jump exposed this: the clamp used the raw count against a
    // logical ceiling, letting the guest retire instructions past the ceiling.
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 100, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(51, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(30)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    // Busy path: no idle-jump offset yet, so the raw limit is the ceiling.
    assert_eq!(state.max_advance_icount(), Ok(100));

    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(80)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(30, 80, pending)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 80))
        .unwrap_or_else(|error| panic!("matching completion should commit: {error}"));

    // The jump advanced the logical clock to 80 (raw 30 + offset 50) without
    // retiring instructions. The raw execution limit is ceiling(100) minus the
    // offset(50) = 50, so the guest may retire only 20 more raw instructions
    // (50 - 30) to reach logical 100 = the ceiling, and no further.
    assert_eq!(slot.snapshot().current_icount, 80);
    assert_eq!(state.max_advance_icount(), Ok(50));
}

#[test]
fn device_io_without_a_pinned_deadline_freezes_at_the_current_icount() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 100, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(52, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(30)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    slot.mark_device_io_active();
    assert_eq!(slot.device_completion_deadline_icount(), 0);
    assert_eq!(state.max_advance_icount(), Ok(30));
}

#[test]
fn device_io_advances_to_the_deadline_only_after_it_is_pinned() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 100, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(53, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(30)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    slot.mark_device_io_active();
    assert_eq!(state.max_advance_icount(), Ok(30));
    slot.store_device_completion_deadline_icount(45);
    assert_eq!(state.max_advance_icount(), Ok(45));
}

#[test]
fn live_idle_callback_queues_then_commits_only_from_normal_loop_completion() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 10, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(46, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(46, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("idle callback should queue the jump: {error}"));
    let pending_snapshot = slot.snapshot();
    assert_eq!(pending_snapshot.current_icount, 0);
    assert_eq!(pending_snapshot.status, STATUS_IDLE);

    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 10))
        .unwrap_or_else(|error| panic!("completion should commit the jump: {error}"));
    assert_eq!(slot.snapshot().current_icount, 10);
    assert_eq!(slot.snapshot().status, STATUS_RUNNING);

    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("resume should preserve logical time: {error}"));
    assert_eq!(slot.snapshot().current_icount, 10);
}

#[test]
fn live_idle_callback_parks_when_an_advance_still_owns_the_qemu_barrier() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 10, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(54, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(54, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(-1);
    TEST_QUEUED_ADVANCE_STATUS.set(-libc::EBUSY);

    let result = state.on_vcpu_idle(0, 0);
    TEST_QUEUED_ADVANCE_STATUS.set(0);

    result.unwrap_or_else(|error| panic!("busy QEMU barrier should defer the idle vCPU: {error}"));
    assert!(
        state
            .try_pending_idle_advance()
            .unwrap_or_else(|error| panic!("pending state should remain readable: {error}"))
            .is_none()
    );
}

#[test]
fn live_idle_callback_queues_the_exact_timer_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(47, 1, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(47, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_CLOCK_DEADLINE_NS.set(7);
    LAST_QUEUED_ADVANCE_NS.set(-1);

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("idle callback should queue exact timer: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 7);
    assert_eq!(slot.snapshot().current_icount, 0);
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 7))
        .unwrap_or_else(|error| panic!("exact timer completion should commit: {error}"));
    assert_eq!(slot.snapshot().current_icount, 7);
    TEST_CLOCK_DEADLINE_NS.set(-1);
}

#[test]
fn live_idle_callback_waits_for_every_vcpu_to_halt() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(73, 4, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    for vcpu_index in 0..4 {
        state
            .on_vcpu_init(73, vcpu_index)
            .unwrap_or_else(|error| panic!("vCPU {vcpu_index} should initialize: {error}"));
    }
    TEST_CLOCK_DEADLINE_NS.set(7);
    LAST_QUEUED_ADVANCE_NS.set(-1);

    for vcpu_index in 0..3 {
        state
            .on_vcpu_idle(vcpu_index, 0)
            .unwrap_or_else(|error| panic!("partial halt set should remain runnable: {error}"));
        assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), -1);
    }
    state
        .on_vcpu_idle(3, 0)
        .unwrap_or_else(|error| panic!("final vCPU halt should queue exact timer: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_NS.get(), 7);
    assert_eq!(slot.snapshot().status, STATUS_IDLE);

    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 7))
        .unwrap_or_else(|error| panic!("all-halted completion should commit: {error}"));
    assert_eq!(slot.snapshot().current_icount, 7);
    TEST_CLOCK_DEADLINE_NS.set(-1);
}

#[test]
fn live_time_completion_rejects_missing_or_mismatched_pending_state() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(44, 1, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    assert!(matches!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 20)),
        Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletionWithoutPending)
    ));
    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(20)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    assert!(matches!(
        state.arm_idle_advance(0, 9, pending),
        Err(LiveVcpuTimeCallbackError::IdleAdvancePendingTargetMismatch { .. })
    ));
    assert_eq!(slot.snapshot().current_icount, 0);

    let pending = queued
        .enqueue(16)
        .unwrap_or_else(|error| panic!("matching idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 8, pending)
        .unwrap_or_else(|error| panic!("matching idle advance should arm: {error}"));
    assert!(matches!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 14)),
        Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletion { .. })
    ));
    assert_eq!(slot.snapshot().current_icount, 0);
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 16))
        .unwrap_or_else(|error| panic!("retained pending advance should still complete: {error}"));
    assert_eq!(slot.snapshot().current_icount, 8);
}

#[test]
fn live_pending_advance_rejects_idle_resume_and_reentrant_publication() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(48, 1, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(48, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .halted_vcpus
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .mark_halted(0)
        .unwrap_or_else(|error| panic!("test vCPU should enter halted state: {error}"));
    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(16)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 8, pending)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    let pending_snapshot = slot.snapshot();

    assert_eq!(
        state.on_vcpu_resume(0, 0),
        Err(LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending)
    );
    assert_eq!(
        state.on_vcpu_idle(0, 0),
        Err(LiveVcpuTimeCallbackError::IdleAdvanceAlreadyPending)
    );
    let pending_guard = match state.pending_idle_advance.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(
        state.publish_current_icount(0),
        Err(LiveVcpuTimeCallbackError::CallbackReentered)
    );
    drop(pending_guard);
    assert_eq!(slot.snapshot(), pending_snapshot);

    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 16))
        .unwrap_or_else(|error| panic!("retained pending advance should complete: {error}"));
    assert_eq!(slot.snapshot().current_icount, 8);
}

#[test]
fn live_state_calibrates_raw_progress_against_restored_logical_time() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.publish_reached_icount(10, 0)
        .unwrap_or_else(|error| panic!("restored logical time should publish: {error}"));

    let state = test_live_state(45, 1, 0, 4, &slot)
        .unwrap_or_else(|error| panic!("live callback state should calibrate: {error}"));
    state
        .publish_current_icount(5)
        .unwrap_or_else(|error| panic!("raw progress should preserve idle offset: {error}"));
    assert_eq!(slot.snapshot().current_icount, 11);

    assert!(matches!(
        test_live_state(45, 1, 0, 12, &slot),
        Err(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
            raw_icount: 12,
            logical_icount: 11,
        })
    ));
}

#[test]
fn live_state_rejects_bad_init_and_regressing_or_excess_progress() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 8, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(42, 2, 0, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    assert!(matches!(
        state.on_vcpu_init(99, 0),
        Err(LiveVcpuTimeCallbackError::PluginIdMismatch { .. })
    ));
    assert!(matches!(
        state.on_vcpu_init(42, 2),
        Err(LiveVcpuTimeCallbackError::VcpuOutOfRange {
            vcpu_index: 2,
            vcpu_count: 2,
        })
    ));
    state
        .on_vcpu_init(42, 0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .publish_current_icount(4)
        .unwrap_or_else(|error| panic!("progress should publish: {error}"));
    assert!(matches!(
        state.publish_current_icount(3),
        Err(LiveVcpuTimeCallbackError::IcountRegressed {
            previous_icount: 4,
            current_icount: 3,
        })
    ));
    assert!(matches!(
        state.publish_current_icount(9),
        Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
            current_icount: 9,
            ceiling_icount: 8,
        })
    ));
}

extern "C" fn test_register_vcpu_init(
    _plugin_id: QemuPluginId,
    _callback: crate::QemuVcpuSimpleCbFn,
) {
}

extern "C" fn test_register_vcpu_idle_resume(
    _idle_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    _resume_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    _userdata: *mut c_void,
) {
}

extern "C" fn test_register_sim_dispatch(
    _publish: Option<crate::QemuSimShmemPublishIcountCbFn>,
    _ceiling: Option<crate::QemuSimShmemMaxAdvanceIcountCbFn>,
    _userdata: *mut c_void,
) {
}

extern "C" fn test_register_time_advance_cb(
    _callback: Option<crate::QemuTimeAdvanceCompletionCbFn>,
    _userdata: *mut c_void,
) -> std::os::raw::c_int {
    0
}

extern "C" fn test_register_net_tx(
    _callback: Option<crate::QemuNetTxCbFn>,
    _userdata: *mut c_void,
) {
}

extern "C" fn test_register_block(
    _submit: Option<crate::QemuBlkSubmitCbFn>,
    _poll: Option<crate::QemuBlkPollCbFn>,
    _userdata: *mut c_void,
) {
}

extern "C" fn test_register_block_wait(
    _wait: Option<crate::QemuBlkWaitCbFn>,
    _userdata: *mut c_void,
) {
}

extern "C" fn test_register_ninep(
    _burst_start: Option<crate::QemuNinePBurstCbFn>,
    _submit: Option<crate::QemuNinePSubmitCbFn>,
    _poll: Option<crate::QemuNinePPollCbFn>,
    _burst_done: Option<crate::QemuNinePBurstCbFn>,
    _userdata: *mut c_void,
) {
}

extern "C" fn test_net_send(payload: *const u8, payload_len: usize) -> std::os::raw::c_int {
    if payload.is_null() && payload_len != 0 {
        return 1;
    }
    TEST_RX_SEND_COUNT.fetch_add(1, Ordering::SeqCst);
    TEST_RX_LAST_LEN.store(payload_len as u64, Ordering::SeqCst);
    TEST_RX_SEND_STATUS.load(Ordering::SeqCst) as std::os::raw::c_int
}

extern "C" fn test_net_flush() -> std::os::raw::c_int {
    TEST_RX_FLUSH_COUNT.fetch_add(1, Ordering::SeqCst);
    0
}

extern "C" fn test_reentrant_net_flush() -> std::os::raw::c_int {
    let state = TEST_REENTRANT_RX_STATE.load(Ordering::Acquire);
    if state.is_null() {
        return 1;
    }
    crucible_qemu_plugin_live_publish_icount_cb(0, state.cast());
    let payload = b"flush-tx";
    let status =
        crucible_qemu_plugin_live_network_tx_cb(payload.as_ptr(), payload.len(), state.cast());
    if status != 0 {
        return status;
    }
    test_net_flush()
}

extern "C" fn test_queue_idle_advance(target_virtual_ns: i64) -> std::os::raw::c_int {
    LAST_QUEUED_ADVANCE_NS.set(target_virtual_ns);
    TEST_QUEUED_ADVANCE_STATUS.get()
}
