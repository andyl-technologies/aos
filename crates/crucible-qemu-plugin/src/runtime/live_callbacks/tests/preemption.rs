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

    assert_eq!(state.max_advance_icount(), Ok(100));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| {
        assert_eq!(
            *command,
            Some((
                4000,
                2500,
                5000,
                crate::QEMU_PREEMPTION_KIND_INTERRUPT_AT,
                0,
                41,
                0,
            ))
        );
    });
}

#[test]
fn max_advance_preserves_unaligned_exact_tick_window() {
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

    // The raw budget stays instruction-aligned while QEMU receives the exact
    // fractional command and authorization window.
    assert_eq!(crucible_shmem::TICKS_PER_INSTRUCTION, 50);
    assert_eq!(state.max_advance_icount(), Ok(79));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| {
        assert_eq!(
            *command,
            Some((
                3001,
                2500,
                4000,
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
fn preemption_at_ten_ps_before_first_retirement_is_forwarded_exactly() {
    super::TEST_ICOUNT_RAW.set(0);
    super::TEST_SIM_TICK.set(0);
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 10, None)
        .unwrap_or_else(|error| panic!("ten-picosecond grant should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("ten-picosecond grant should publish: {error}"));
    let sequence = slot
        .publish_preemption_command(crucible_shmem::SchedulerPreemptionCommand {
            at_tick: 10,
            deadline_tick: 10,
            ceiling_tick: 10,
            kind: SchedulerPreemptionKind::VcpuSwitch {
                from_vcpu: 0,
                to_vcpu: 1,
            },
        })
        .unwrap_or_else(|error| panic!("fractional command should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let exact_deadline = ExactDeadlineReader::require(Some(test_clock_deadline_ps))
        .unwrap_or_else(|error| panic!("deadline capability should validate: {error}"));
    let queued_idle_advance = QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("advance capability should validate: {error}"));
    let injector = PluginPreemptionInjector::require(Some(capture_preemption))
        .unwrap_or_else(|error| panic!("preemption capability should validate: {error}"));
    let (teardown_sender, teardown_receiver) = mpsc::channel();
    std::mem::forget(teardown_receiver);
    let state = LiveVcpuTimeCallbackState::new(
        test_icount_raw,
        super::super::test_support::test_force_vcpu_exit,
        super::super::test_support::test_idle_wake_wait(),
        super::super::test_support::test_request_vmstop,
        injector,
        2,
        0,
        exact_deadline,
        queued_idle_advance,
        super::super::test_support::test_virtual_timer_witness(),
        Box::new(TestFaultCommandBridge::empty()),
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        LiveRuntimeTeardownRouter::new(teardown_sender),
    )
    .unwrap_or_else(|error| panic!("live state should validate: {error}"));

    assert_eq!(state.max_advance_icount(), Ok(0));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| {
        assert_eq!(
            *command,
            Some((10, 10, 10, crate::QEMU_PREEMPTION_KIND_VCPU_SWITCH, 0, 1, 0))
        );
    });
}
