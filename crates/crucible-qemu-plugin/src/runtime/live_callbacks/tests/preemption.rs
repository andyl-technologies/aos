//! Live preemption mailbox callback tests.

use super::*;

use std::cell::RefCell;

type CapturedPreemption = (u64, u64, u64, std::os::raw::c_uint, u32, u32, u32);

thread_local! {
    static TEST_PREEMPTION_COMMAND: RefCell<Option<CapturedPreemption>> =
        const { RefCell::new(None) };
}

extern "C" fn capture_preemption(
    at_icount: u64,
    deadline_icount: u64,
    ceiling_icount: u64,
    kind: std::os::raw::c_uint,
    arg0: u32,
    arg1: u32,
    arg2: u32,
) -> std::os::raw::c_int {
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| {
        *command = Some((
            at_icount,
            deadline_icount,
            ceiling_icount,
            kind,
            arg0,
            arg1,
            arg2,
        ));
    });
    0
}

#[test]
fn max_advance_keeps_preemption_pending_until_its_run_ceiling_is_published() {
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = NodeSlot::new(KIND_VM);
    let completed_ceiling = authorize_advance_ceiling(0, 2500, None)
        .unwrap_or_else(|error| panic!("completed ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(
        completed_ceiling,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )
    .unwrap_or_else(|error| panic!("completed ceiling should publish: {error}"));
    slot.publish_reached_icount(2500)
        .unwrap_or_else(|error| panic!("completed icount should publish: {error}"));
    let sequence = slot
        .publish_preemption_command(crucible_shmem::SchedulerPreemptionCommand {
            at_tick: 4000,
            deadline_tick: 2500,
            ceiling_tick: 5000,
            kind: SchedulerPreemptionKind::InterruptAt {
                target_vcpu: 0,
                irq: 41,
            },
        })
        .unwrap_or_else(|error| panic!("test preemption should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let exact_deadline = ExactDeadlineReader::require(Some(test_clock_deadline_ps))
        .unwrap_or_else(|error| panic!("test deadline capability should validate: {error}"));
    let queued_idle_advance = QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
    let injector = PluginPreemptionInjector::require(Some(capture_preemption))
        .unwrap_or_else(|error| panic!("test preemption capability should validate: {error}"));
    let (teardown_sender, teardown_receiver) = mpsc::channel();
    std::mem::forget(teardown_receiver);
    let state = LiveVcpuTimeCallbackState::new(
        test_icount_raw,
        super::super::test_support::test_force_vcpu_exit,
        super::super::test_support::test_idle_wake_wait(),
        super::super::test_support::test_request_vmstop,
        injector,
        1,
        50,
        exact_deadline,
        queued_idle_advance,
        super::super::test_support::test_virtual_timer_witness(),
        Box::new(TestFaultCommandBridge::empty()),
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        LiveRuntimeTeardownRouter::new(teardown_sender),
    )
    .unwrap_or_else(|error| panic!("test live state should validate: {error}"));

    assert_eq!(state.max_advance_icount(), Ok(50));
    assert_eq!(slot.consumed_preemption_sequence(), sequence - 1);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert_eq!(*command, None));

    let owning_ceiling = authorize_advance_ceiling(2500, 5000, None)
        .unwrap_or_else(|error| panic!("owning ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(
        owning_ceiling,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )
    .unwrap_or_else(|error| panic!("owning ceiling should publish: {error}"));

    assert_eq!(state.max_advance_icount(), Ok(80));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| {
        assert_eq!(
            *command,
            Some((
                80,
                50,
                100,
                crate::QEMU_PREEMPTION_KIND_INTERRUPT_AT,
                0,
                41,
                0,
            ))
        );
    });
}

#[test]
fn max_advance_keeps_unaligned_window_inside_logical_bounds() {
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 4000, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.publish_reached_icount(501)
        .unwrap_or_else(|error| panic!("logical current should publish: {error}"));
    let sequence = slot
        .publish_preemption_command(crucible_shmem::SchedulerPreemptionCommand {
            at_tick: 3001,
            deadline_tick: 2500,
            ceiling_tick: 4000,
            kind: SchedulerPreemptionKind::InterruptAt {
                target_vcpu: 0,
                irq: 41,
            },
        })
        .unwrap_or_else(|error| panic!("test preemption should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let exact_deadline = ExactDeadlineReader::require(Some(test_clock_deadline_ps))
        .unwrap_or_else(|error| panic!("test deadline capability should validate: {error}"));
    let queued_idle_advance = QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
    let injector = PluginPreemptionInjector::require(Some(capture_preemption))
        .unwrap_or_else(|error| panic!("test preemption capability should validate: {error}"));
    let (teardown_sender, teardown_receiver) = mpsc::channel();
    std::mem::forget(teardown_receiver);
    let state = LiveVcpuTimeCallbackState::new(
        test_icount_raw,
        super::super::test_support::test_force_vcpu_exit,
        super::super::test_support::test_idle_wake_wait(),
        super::super::test_support::test_request_vmstop,
        injector,
        1,
        10,
        exact_deadline,
        queued_idle_advance,
        super::super::test_support::test_virtual_timer_witness(),
        Box::new(TestFaultCommandBridge::empty()),
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        LiveRuntimeTeardownRouter::new(teardown_sender),
    )
    .unwrap_or_else(|error| panic!("test live state should validate: {error}"));

    // At 50 logical ticks per instruction, offset 1 maps at=3001 to raw 60;
    // the inclusive [2500, 4000] window rounds inward to raw [50, 79].
    assert_eq!(crucible_shmem::TICKS_PER_INSTRUCTION, 50);
    assert_eq!(state.max_advance_icount(), Ok(60));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| {
        assert_eq!(
            *command,
            Some((
                60,
                50,
                79,
                crate::QEMU_PREEMPTION_KIND_INTERRUPT_AT,
                0,
                41,
                0,
            ))
        );
    });
    assert_eq!(state.max_advance_icount(), Ok(79));
}

#[test]
fn preemption_window_conversion_rejects_empty_interval_and_raw_origin_underflow() {
    let deadline = logical_preemption_deadline_to_raw(2, 1)
        .unwrap_or_else(|error| panic!("deadline conversion should succeed: {error}"));
    let ceiling = logical_preemption_ceiling_to_raw(49, 1)
        .unwrap_or_else(|error| panic!("ceiling conversion should succeed: {error}"));
    assert_eq!(
        PreemptionWindow::new(deadline, SchedulerCeiling::new(ceiling)),
        Err(PreemptionError::InvalidWindow {
            deadline_icount: 1,
            ceiling_icount: 0,
        })
    );
    assert!(matches!(
        logical_preemption_deadline_to_raw(0, 1),
        Err(LiveVcpuTimeCallbackError::PreemptionIcountBeforeRawOrigin { .. })
    ));
}

#[test]
fn preemption_deadline_conversion_handles_maximum_logical_tick() {
    let deadline = logical_preemption_deadline_to_raw(u64::MAX, 0)
        .unwrap_or_else(|error| panic!("maximum deadline should convert: {error}"));
    assert_eq!(
        deadline,
        u64::MAX / crucible_shmem::TICKS_PER_INSTRUCTION + 1
    );
}
