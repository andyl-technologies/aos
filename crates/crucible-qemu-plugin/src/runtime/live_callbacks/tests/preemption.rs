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
fn max_advance_enqueues_and_acknowledges_logical_preemption_in_raw_space() {
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 100, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.publish_reached_icount(50, 0)
        .unwrap_or_else(|error| panic!("logical current should publish: {error}"));
    let sequence = slot
        .publish_preemption_command(crucible_shmem::SchedulerPreemptionCommand {
            at_icount: 80,
            deadline_icount: 70,
            ceiling_icount: 100,
            kind: SchedulerPreemptionKind::InterruptAt {
                target_vcpu: 0,
                irq: 41,
            },
        })
        .unwrap_or_else(|error| panic!("test preemption should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, 0))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let exact_deadline = ExactDeadlineReader::require(Some(test_clock_deadline_ns))
        .unwrap_or_else(|error| panic!("test deadline capability should validate: {error}"));
    let queued_idle_advance = QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
    let injector = PluginPreemptionInjector::require(Some(capture_preemption))
        .unwrap_or_else(|error| panic!("test preemption capability should validate: {error}"));
    let (teardown_sender, teardown_receiver) = mpsc::channel();
    std::mem::forget(teardown_receiver);
    let state = LiveVcpuTimeCallbackState::new(
        13,
        test_icount_raw,
        super::super::test_support::test_force_vcpu_exit,
        injector,
        1,
        0,
        10,
        exact_deadline,
        queued_idle_advance,
        None,
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
    )
    .unwrap_or_else(|error| panic!("test live state should validate: {error}"));

    assert_eq!(state.max_advance_icount(), Ok(40));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| {
        assert_eq!(
            *command,
            Some((
                40,
                30,
                60,
                crate::QEMU_PREEMPTION_KIND_INTERRUPT_AT,
                0,
                41,
                0,
            ))
        );
    });
    assert_eq!(state.max_advance_icount(), Ok(60));
}
