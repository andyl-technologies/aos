//! Live preemption mailbox callback tests.

use super::*;

use std::cell::RefCell;

type CapturedPreemption = (u64, u64, u64, std::os::raw::c_uint, u32, u32, u32);

thread_local! {
    static TEST_PREEMPTION_COMMAND: RefCell<Option<CapturedPreemption>> =
        const { RefCell::new(None) };
    static TEST_PREEMPTION_PUBLICATION: RefCell<Option<Arc<std::sync::Barrier>>> =
        const { RefCell::new(None) };
}

extern "C" fn raw_icount_during_preemption_publication() -> u64 {
    TEST_PREEMPTION_PUBLICATION.with_borrow(|boundary| {
        let Some(boundary) = boundary.as_ref() else {
            panic!("preemption publication boundary should be installed");
        };
        boundary.wait();
        boundary.wait();
    });
    0
}

fn test_preemption_command() -> crucible_shmem::SchedulerPreemptionCommand {
    crucible_shmem::SchedulerPreemptionCommand {
        at_tick: 3000,
        deadline_tick: 2500,
        ceiling_tick: 5000,
        kind: SchedulerPreemptionKind::InterruptAt {
            target_vcpu: 0,
            irq: 41,
        },
    }
}

#[test]
fn preemption_published_during_query_after_empty_observation_is_consumed_once()
-> Result<(), Box<dyn std::error::Error>> {
    super::TEST_ICOUNT_RAW.set(0);
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 5000, None)?;
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    let mut state = super::test_live_state(1, 1, 0, &slot)?;
    state.preemption_injector = PluginPreemptionInjector::require(Some(capture_preemption))?;
    let boundary = Arc::new(std::sync::Barrier::new(2));

    assert_eq!(state.max_advance_icount(), Ok(100));
    state.icount_raw = raw_icount_during_preemption_publication;
    TEST_PREEMPTION_PUBLICATION.with_borrow_mut(|stored| *stored = Some(Arc::clone(&boundary)));
    let sequence = std::thread::scope(|scope| {
        let publisher = scope.spawn(|| {
            boundary.wait();
            let sequence = slot.publish_preemption_command(test_preemption_command());
            boundary.wait();
            sequence
        });

        assert_eq!(state.max_advance_icount(), Ok(100));
        publisher
            .join()
            .unwrap_or_else(|_| panic!("preemption publisher should finish"))
    })?;
    TEST_PREEMPTION_PUBLICATION.with_borrow_mut(|stored| *stored = None);
    state.icount_raw = test_icount_raw;

    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert!(command.is_some()));
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    assert_eq!(state.max_advance_icount(), Ok(100));
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert_eq!(*command, None));
    Ok(())
}

#[test]
fn nested_preemption_query_leaves_outer_enqueue_command_pending()
-> Result<(), Box<dyn std::error::Error>> {
    super::TEST_ICOUNT_RAW.set(0);
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 5000, None)?;
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    let mut state = super::test_live_state(1, 1, 0, &slot)?;
    state.preemption_injector = PluginPreemptionInjector::require(Some(capture_preemption))?;
    let sequence = slot.publish_preemption_command(test_preemption_command())?;

    // The outer enqueue owns this flag across a synchronous QEMU budget query.
    state
        .preemption_enqueue_active
        .store(true, Ordering::Release);
    assert_eq!(state.max_advance_icount(), Ok(100));
    assert!(state.preemption_enqueue_active.load(Ordering::Acquire));
    assert_eq!(slot.consumed_preemption_sequence(), sequence - 1);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert_eq!(*command, None));

    state
        .preemption_enqueue_active
        .store(false, Ordering::Release);
    assert_eq!(state.max_advance_icount(), Ok(100));
    assert!(!state.preemption_enqueue_active.load(Ordering::Acquire));
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert!(command.is_some()));
    Ok(())
}

#[test]
fn preemption_consumed_between_preflight_and_enqueue_admission_is_not_reinjected()
-> Result<(), Box<dyn std::error::Error>> {
    super::TEST_ICOUNT_RAW.set(0);
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = Arc::new(NodeSlot::new(KIND_VM));
    let ceiling = authorize_advance_ceiling(0, 5000, None)?;
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    let mut state = super::test_live_state(1, 1, 0, &slot)?;
    state.preemption_injector = PluginPreemptionInjector::require(Some(capture_preemption))?;
    let sequence = slot.publish_preemption_command(test_preemption_command())?;
    let competing_consumer = Arc::clone(&slot);

    // The competing query consumes and releases ownership after this query
    // sees the command, but before this query acquires enqueue ownership.
    super::super::preemption::PREFLIGHT_CONSUMER.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move || {
            competing_consumer
                .acknowledge_preemption_command(sequence)
                .unwrap_or_else(|error| panic!("competing consumer should acknowledge: {error}"));
        }));
    });
    assert_eq!(state.max_advance_icount(), Ok(100));

    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    assert!(!state.preemption_enqueue_active.load(Ordering::Acquire));
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert_eq!(*command, None));
    Ok(())
}

#[test]
fn preemption_republished_after_advisory_hint_is_decoded_under_enqueue_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    super::TEST_ICOUNT_RAW.set(0);
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = Arc::new(NodeSlot::new(KIND_VM));
    let ceiling = authorize_advance_ceiling(0, 5000, None)?;
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    let mut state = super::test_live_state(1, 1, 0, &slot)?;
    state.preemption_injector = PluginPreemptionInjector::require(Some(capture_preemption))?;
    let sequence = slot.publish_preemption_command(test_preemption_command())?;
    let replacement = crucible_shmem::SchedulerPreemptionCommand {
        at_tick: 3500,
        kind: SchedulerPreemptionKind::InterruptAt {
            target_vcpu: 0,
            irq: 42,
        },
        ..test_preemption_command()
    };
    let competing_consumer = Arc::clone(&slot);

    // The first consumer completes admission after our hint. Its acknowledgement
    // permits the host to replace every payload field before our guard is owned.
    super::super::preemption::PREFLIGHT_CONSUMER.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move || {
            std::thread::spawn(move || {
                competing_consumer
                    .acknowledge_preemption_command(sequence)
                    .unwrap_or_else(|error| {
                        panic!("competing consumer should acknowledge: {error}")
                    });
                assert_eq!(
                    competing_consumer
                        .publish_preemption_command(replacement)
                        .unwrap_or_else(|error| {
                            panic!("replacement command should publish: {error}")
                        }),
                    sequence.wrapping_add(1),
                );
            })
            .join()
            .unwrap_or_else(|_| panic!("competing consumer should finish"));
        }));
    });
    assert_eq!(state.max_advance_icount(), Ok(100));

    assert_eq!(
        slot.consumed_preemption_sequence(),
        sequence.wrapping_add(1)
    );
    assert!(!state.preemption_enqueue_active.load(Ordering::Acquire));
    TEST_PREEMPTION_COMMAND.with_borrow(|command| {
        assert_eq!(
            *command,
            Some((
                3500,
                2500,
                5000,
                crate::QEMU_PREEMPTION_KIND_INTERRUPT_AT,
                0,
                42,
                0
            )),
        );
    });

    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    assert_eq!(state.max_advance_icount(), Ok(100));
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert_eq!(*command, None));
    Ok(())
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
