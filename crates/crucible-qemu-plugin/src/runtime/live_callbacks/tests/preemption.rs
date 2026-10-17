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

// These controls exercise the real GPL budget path and mapped publication
// effects. The returned AUTH/phase disposition is explicitly modeled; native
// READY/inventory/RR ownership still requires the configured native callers.
fn native_result(raw: u64, logical: u64) -> crate::runtime::installed_console::DispatchResult {
    crate::runtime::installed_console::DispatchResult {
        raw_ceiling: u64::MAX,
        raw_start: raw,
        logical_start: logical,
        logical_ceiling: u64::MAX,
        authorization: [0; 128],
        publication_unavailable: false,
    }
}

#[test]
fn native_busy_advance_returns_before_original_pause_or_budget_effects()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::installed_console::DispatchAdvance;

    TEST_ICOUNT_RAW.set(0);
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(316, 1, 0, &slot)?;
    state.header.get().request_pause([&slot])?;
    let before = slot.snapshot();
    let reads = Cell::new(0);
    let mut result = native_result(0, 0);
    let mut outcome = None;

    slot.publish_scheduler_advance_with_effect(
        authorize_advance_ceiling(0, 500, None)?,
        crucible_shmem::AdvanceStopCondition::Ceiling,
        |_advance| {
            outcome = Some(state.console_dispatch_budget(&mut result, || {
                reads.set(reads.get() + 1);
                assert!(slot.try_snapshot().is_none());
                Ok(DispatchAdvance::Unavailable)
            }));
        },
    )?;
    match outcome {
        Some(result) => result?,
        None => return Err("original writer did not invoke its effect".into()),
    }

    let after = slot.snapshot();
    assert_eq!(reads.get(), 1);
    assert!(result.publication_unavailable);
    assert_eq!(result.raw_ceiling, result.raw_start);
    assert_eq!(result.authorization, [0; 128]);
    assert_eq!(after.publish_gen, before.publish_gen);
    assert_eq!(after.status, before.status);
    assert_eq!(after.current_icount, before.current_icount);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    Ok(())
}

#[test]
fn native_budget_retains_original_body_and_ceiling_across_later_regrant()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::installed_console::DispatchAdvance;

    TEST_ICOUNT_RAW.set(0);
    let slot = NodeSlot::new(KIND_VM);
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, 500, None)?,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    let state = test_live_state(316, 1, 0, &slot)?;
    let reads = Cell::new(0);
    // Deliberately modeled authority bytes: only immutable custody is tested.
    let original_body = [0xA5; 128];
    let mut result = native_result(0, 0);

    state.console_dispatch_budget(&mut result, || {
        reads.set(reads.get() + 1);
        let ceiling = slot
            .load_scheduler_advance_publication()
            .unwrap_or_else(|error| panic!("original coherent read failed: {error}"))
            .ceiling();
        slot.publish_scheduler_advance(
            authorize_advance_ceiling(0, 1000, None)
                .unwrap_or_else(|error| panic!("later ceiling failed: {error}")),
            crucible_shmem::AdvanceStopCondition::Ceiling,
        )
        .unwrap_or_else(|error| panic!("later publication failed: {error}"));
        Ok(DispatchAdvance::Owned {
            ceiling,
            authorization: original_body,
        })
    })?;

    assert_eq!(reads.get(), 1);
    assert_eq!(result.raw_ceiling, 10);
    assert_eq!(result.logical_ceiling, 500);
    assert_eq!(result.authorization, original_body);
    assert!(!result.publication_unavailable);
    assert_eq!(state.max_advance_icount()?, 20);
    Ok(())
}

#[test]
fn native_unowned_positive_budget_and_clock_drift_refuse_without_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::installed_console::DispatchAdvance;
    use crucible_protocol::native_console::NativeConsoleError;

    TEST_ICOUNT_RAW.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(316, 1, 0, &slot)?;
    let before = slot.snapshot();

    for ceiling in [0, 1, 49, 50] {
        let mut result = native_result(0, 0);
        let outcome =
            state.console_dispatch_budget(&mut result, || Ok(DispatchAdvance::Unowned { ceiling }));
        if ceiling == 0 {
            outcome?;
            assert_eq!(result.raw_ceiling, 0);
            assert_eq!(result.authorization, [0; 128]);
        } else {
            assert_eq!(
                outcome,
                Err(LiveVcpuTimeCallbackError::ConsoleDispatch {
                    source: NativeConsoleError::Binding,
                })
            );
            assert_eq!(result.raw_ceiling, u64::MAX);
            assert_eq!(result.authorization, [0; 128]);
        }
    }
    let mut drifted = native_result(0, 1);
    assert_eq!(
        state.console_dispatch_budget(&mut drifted, || {
            Ok(DispatchAdvance::Owned {
                ceiling: 500,
                authorization: [0xA5; 128],
            })
        }),
        Err(LiveVcpuTimeCallbackError::ConsoleDispatch {
            source: NativeConsoleError::Binding,
        })
    );
    assert_eq!(drifted.raw_ceiling, u64::MAX);
    assert_eq!(drifted.authorization, [0; 128]);
    assert_eq!(slot.snapshot(), before);
    Ok(())
}

#[test]
fn native_joined_budget_preserves_original_device_and_fractional_clamps()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::installed_console::DispatchAdvance;

    TEST_ICOUNT_RAW.set(20);
    let slot = NodeSlot::new(KIND_VM);
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, 5000, None)?,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    let state = test_live_state(316, 1, 0, &slot)?;
    state.publish_current_icount(20)?;
    slot.mark_device_io_active();
    let mut result = native_result(20, 1000);
    let original_body = [0xA5; 128];

    state.console_dispatch_budget(&mut result, || {
        Ok(DispatchAdvance::Owned {
            ceiling: 5000,
            authorization: original_body,
        })
    })?;
    assert_eq!(result.raw_ceiling, 20);
    assert_eq!(result.logical_ceiling, 1000);
    slot.store_device_completion_deadline_tick(1501);
    state.console_dispatch_budget(&mut result, || {
        Ok(DispatchAdvance::Owned {
            ceiling: 5000,
            authorization: original_body,
        })
    })?;

    assert_eq!(result.raw_ceiling, 30);
    assert_eq!(result.logical_ceiling, 1501);
    assert_eq!(result.authorization, original_body);
    assert_eq!(state.max_advance_icount()?, 30);
    Ok(())
}

#[test]
fn native_missing_authorization_refuses_before_pending_preemption_admission()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::installed_console::DispatchAdvance;
    use crucible_protocol::native_console::NativeConsoleError;

    TEST_ICOUNT_RAW.set(0);
    TEST_PREEMPTION_COMMAND.with_borrow_mut(|command| *command = None);
    let slot = NodeSlot::new(KIND_VM);
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, 5000, None)?,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    let sequence = slot.publish_preemption_command(test_preemption_command())?;
    let mut state = test_live_state(316, 1, 0, &slot)?;
    state.preemption_injector = PluginPreemptionInjector::require(Some(capture_preemption))?;
    let before = slot.snapshot();

    for authorization in [None, Some([0; 128])] {
        let mut result = native_result(0, 0);
        let reads = Cell::new(0);
        assert_eq!(
            state.console_dispatch_budget(&mut result, || {
                reads.set(reads.get() + 1);
                Ok(match authorization {
                    None => DispatchAdvance::Unowned { ceiling: 5000 },
                    Some(authorization) => DispatchAdvance::Owned {
                        ceiling: 5000,
                        authorization,
                    },
                })
            }),
            Err(LiveVcpuTimeCallbackError::ConsoleDispatch {
                source: NativeConsoleError::Binding,
            })
        );
        assert_eq!(reads.get(), 1);
        assert_eq!(slot.consumed_preemption_sequence(), sequence - 1);
        assert!(!state.preemption_enqueue_active.load(Ordering::Acquire));
        TEST_PREEMPTION_COMMAND.with_borrow(|command| assert_eq!(*command, None));
        assert_eq!(slot.snapshot(), before);
        assert_eq!(result.raw_ceiling, u64::MAX);
        assert_eq!(result.authorization, [0; 128]);
    }

    // The exact pending command is still consumed by the original None path.
    assert_eq!(state.max_advance_icount()?, 100);
    assert_eq!(slot.consumed_preemption_sequence(), sequence);
    TEST_PREEMPTION_COMMAND.with_borrow(|command| assert!(command.is_some()));
    Ok(())
}

#[test]
fn native_owned_fractional_budget_retains_logical_span_without_raw_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::installed_console::DispatchAdvance;

    TEST_ICOUNT_RAW.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let mut state = test_live_state(316, 1, 0, &slot)?;
    state.sim_tick_observed = Some(super::test_sim_tick_observed);
    super::TEST_SIM_TICK.set(0);
    let before = slot.snapshot();
    let mut result = native_result(0, 0);
    // This callback control models phase ownership. Native idle controls
    // separately join the actual retained writer/READY/closed-Grant bodies.
    let body = [0xA5; 128];

    state.console_dispatch_budget(&mut result, || {
        Ok(DispatchAdvance::Owned {
            ceiling: 49,
            authorization: body,
        })
    })?;

    assert_eq!(result.raw_start, 0);
    assert_eq!(result.raw_ceiling, 0);
    assert_eq!(result.logical_ceiling, 49);
    assert_eq!(result.authorization, body);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(TEST_ICOUNT_RAW.get(), 0);

    // The C bias control accounts 49ps without an instruction. The next
    // original SIM callback reconstructs that same offset before budget math.
    super::TEST_SIM_TICK.set(49);
    let mut next = native_result(0, 49);
    state.console_dispatch_budget(&mut next, || {
        Ok(DispatchAdvance::Owned {
            ceiling: 49,
            authorization: body,
        })
    })?;
    assert_eq!(next.raw_start, 0);
    assert_eq!(next.raw_ceiling, 0);
    assert_eq!(next.logical_start, 49);
    assert_eq!(next.logical_ceiling, 49);
    assert_eq!(state.logical_icount_offset.load(Ordering::Acquire), 49);
    assert_eq!(next.authorization, body);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(TEST_ICOUNT_RAW.get(), 0);
    Ok(())
}

#[test]
fn native_pending_idle_keeps_original_logical_coordinate() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::runtime::installed_console::DispatchAdvance;

    TEST_ICOUNT_RAW.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(316, 1, 0, &slot)?;
    state
        .pending_idle_advance_raw_icount
        .store(0, Ordering::Relaxed);
    state
        .pending_idle_advance_active
        .store(true, Ordering::Release);
    let before = slot.snapshot();
    let mut result = native_result(0, 0);

    state.console_dispatch_budget(&mut result, || {
        Ok(DispatchAdvance::Owned {
            ceiling: 49,
            authorization: [0xA5; 128],
        })
    })?;

    assert_eq!(result.raw_ceiling, 0);
    assert_eq!(result.logical_ceiling, 0);
    assert!(state.pending_idle_advance_active.load(Ordering::Acquire));
    assert_eq!(slot.snapshot(), before);
    Ok(())
}

#[test]
fn native_deferred_pause_keeps_original_logical_coordinate()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::installed_console::DispatchAdvance;

    TEST_ICOUNT_RAW.set(0);
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(316, 1, 0, &slot)?;
    slot.mark_device_io_active();
    state.header.get().request_pause([&slot])?;
    let before = slot.snapshot();
    let mut result = native_result(0, 0);

    state.console_dispatch_budget(&mut result, || {
        Ok(DispatchAdvance::Owned {
            ceiling: 49,
            authorization: [0xA5; 128],
        })
    })?;

    assert_eq!(result.raw_ceiling, 0);
    assert_eq!(result.logical_ceiling, 0);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    Ok(())
}
