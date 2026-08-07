//! Idle-loop wake/deadline computation, device-completion, and freeze cases.

use super::super::*;

use super::support::*;
use crucible_shmem::{KIND_VM, STATUS_DONE, STATUS_IDLE, STATUS_RUNNING};

#[cfg(target_os = "linux")]
use std::{sync::Arc, thread, time::Duration};

#[test]
fn idle_loop_computes_wake_from_timer_inbound_and_ceiling() {
    let timer_wins = match compute_idle_wake_plan(
        10,
        1,
        ExactDeadlineReport::Armed { deadline_ns: 40 },
        Some(30),
        SchedulerCeiling::new(50),
        false,
        None,
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("timer wake plan should compute: {error}"),
    };
    assert_eq!(timer_wins.timer_deadline_icount(), Some(20));
    assert_eq!(timer_wins.inbound_delivery_icount(), Some(30));
    assert_eq!(timer_wins.desired_wake_icount(), 20);
    assert_eq!(timer_wins.cause(), IdleWakeCause::TimerDeadline);
    assert!(!timer_wins.requires_scheduler_wait());

    let inbound_wins = match compute_idle_wake_plan(
        10,
        1,
        ExactDeadlineReport::Armed { deadline_ns: 80 },
        Some(30),
        SchedulerCeiling::new(20),
        false,
        None,
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("inbound wake plan should compute: {error}"),
    };
    assert_eq!(inbound_wins.desired_wake_icount(), 30);
    assert_eq!(inbound_wins.cause(), IdleWakeCause::InboundFrame);
    assert!(inbound_wins.requires_scheduler_wait());

    let ceiling_wins = match compute_idle_wake_plan(
        10,
        1,
        ExactDeadlineReport::NoArmedTimer,
        None,
        SchedulerCeiling::new(64),
        false,
        None,
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("ceiling wake plan should compute: {error}"),
    };
    assert_eq!(ceiling_wins.desired_wake_icount(), 64);
    assert_eq!(ceiling_wins.cause(), IdleWakeCause::SchedulerCeiling);
}

/// A published device-I/O completion deadline pulls the wake down to the
/// completion icount instead of freezing to the scheduler ceiling.
#[test]
fn idle_loop_device_completion_deadline_drives_wake() {
    let plan = match compute_idle_wake_plan(
        10,
        0,
        ExactDeadlineReport::NoArmedTimer,
        None,
        SchedulerCeiling::new(1_000),
        true,
        Some(200),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("device completion wake plan should compute: {error}"),
    };
    assert_eq!(plan.device_completion_deadline_icount(), Some(200));
    assert_eq!(plan.desired_wake_icount(), 200);
    assert_eq!(plan.cause(), IdleWakeCause::DeviceIoCompletion);
}

/// The merge takes the minimum of a completion deadline and an earlier timer,
/// and a completion deadline earlier than the timer wins the tie order.
#[test]
fn idle_loop_device_completion_merges_with_timer_by_min() {
    // Timer at icount 20 is earlier than the device completion at 200.
    let timer_first = match compute_idle_wake_plan(
        10,
        1,
        ExactDeadlineReport::Armed { deadline_ns: 40 },
        None,
        SchedulerCeiling::new(1_000),
        true,
        Some(200),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("timer-first merge should compute: {error}"),
    };
    assert_eq!(timer_first.timer_deadline_icount(), Some(20));
    assert_eq!(timer_first.device_completion_deadline_icount(), Some(200));
    assert_eq!(timer_first.desired_wake_icount(), 20);
    assert_eq!(timer_first.cause(), IdleWakeCause::TimerDeadline);

    // Device completion at 20 is earlier than the timer at 40.
    let device_first = match compute_idle_wake_plan(
        10,
        1,
        ExactDeadlineReport::Armed { deadline_ns: 80 },
        None,
        SchedulerCeiling::new(1_000),
        true,
        Some(20),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("device-first merge should compute: {error}"),
    };
    assert_eq!(device_first.timer_deadline_icount(), Some(40));
    assert_eq!(device_first.desired_wake_icount(), 20);
    assert_eq!(device_first.cause(), IdleWakeCause::DeviceIoCompletion);
}

/// A zero (retracted) completion deadline leaves the node frozen to the
/// ceiling with timer deadlines held, the pre-fix device-I/O behavior.
#[test]
fn idle_loop_retracted_device_completion_freezes_to_ceiling() {
    let plan = match compute_idle_wake_plan(
        10,
        1,
        ExactDeadlineReport::Armed { deadline_ns: 40 },
        None,
        SchedulerCeiling::new(1_000),
        true,
        Some(0),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("retracted completion plan should compute: {error}"),
    };
    assert_eq!(plan.timer_deadline_icount(), Some(20));
    assert_eq!(plan.device_completion_deadline_icount(), None);
    assert_eq!(plan.desired_wake_icount(), 1_000);
    assert_eq!(plan.cause(), IdleWakeCause::DeviceIoFreeze);
}

/// A stale completion deadline in the past clamps forward to the current
/// icount (wake now) rather than rewinding virtual time. This is the classic
/// first-live device-I/O hazard.
#[test]
fn idle_loop_stale_past_device_completion_clamps_to_current() {
    let plan = match compute_idle_wake_plan(
        100,
        0,
        ExactDeadlineReport::NoArmedTimer,
        None,
        SchedulerCeiling::new(1_000),
        true,
        Some(40),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("stale-past completion plan should compute: {error}"),
    };
    assert_eq!(plan.device_completion_deadline_icount(), Some(100));
    assert_eq!(plan.desired_wake_icount(), 100);
    assert_eq!(plan.cause(), IdleWakeCause::DeviceIoCompletion);
}

/// The completion deadline is ignored entirely when device I/O is not
/// holding, even if a nonzero value is present in the slot.
#[test]
fn idle_loop_completion_ignored_when_device_io_not_holding() {
    let plan = match compute_idle_wake_plan(
        10,
        1,
        ExactDeadlineReport::Armed { deadline_ns: 40 },
        None,
        SchedulerCeiling::new(1_000),
        false,
        Some(15),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("non-holding plan should compute: {error}"),
    };
    assert_eq!(plan.device_completion_deadline_icount(), None);
    assert_eq!(plan.desired_wake_icount(), 20);
    assert_eq!(plan.cause(), IdleWakeCause::TimerDeadline);
}

#[test]
fn idle_loop_device_io_freeze_suppresses_timer_deadline_until_scheduler_wake() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 0);
    publish_ceiling(&slot, ceiling(0, 50));
    let mut freeze = PluginDeviceIoFreeze::new();
    let _token = match freeze.begin_submit(&slot, clock.current_icount()) {
        Ok(token) => token,
        Err(error) => panic!("device I/O submit should activate freeze: {error}"),
    };

    let request = match PluginIdleHotLoop::begin_idle(
        &slot,
        &clock,
        &deadline_reader(deadline_20),
        None,
        Some(&freeze),
    ) {
        Ok(request) => request,
        Err(error) => panic!("device-I/O idle publish should succeed: {error}"),
    };

    assert_eq!(request.plan().timer_deadline_icount(), Some(20));
    assert!(request.plan().device_io_holding_ticks());
    assert_eq!(request.plan().desired_wake_icount(), 50);
    assert_eq!(request.plan().cause(), IdleWakeCause::DeviceIoFreeze);
    assert_eq!(slot.snapshot().idle_wake_icount, 50);
}

#[test]
fn idle_loop_device_io_freeze_uses_pending_counter_when_flag_is_stale() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 0);
    publish_ceiling(&slot, ceiling(0, 50));
    let mut freeze = PluginDeviceIoFreeze::new();
    let _token = match freeze.begin_submit(&slot, clock.current_icount()) {
        Ok(token) => token,
        Err(error) => panic!("device I/O submit should activate freeze: {error}"),
    };
    PluginShmemOrdering::clear_device_io_active(&slot);
    assert!(!PluginShmemOrdering::device_io_active(&slot));
    assert!(freeze.pending_requests() != 0);

    let request = match PluginIdleHotLoop::begin_idle(
        &slot,
        &clock,
        &deadline_reader(deadline_20),
        None,
        Some(&freeze),
    ) {
        Ok(request) => request,
        Err(error) => panic!("pending-only freeze should suppress timer: {error}"),
    };

    assert_eq!(request.plan().timer_deadline_icount(), Some(20));
    assert!(request.plan().device_io_holding_ticks());
    assert_eq!(request.plan().desired_wake_icount(), 50);
    assert_eq!(request.plan().cause(), IdleWakeCause::DeviceIoFreeze);
}

#[test]
fn idle_loop_publishes_current_then_idle_and_prepares_futex_wait() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 0);
    publish_ceiling(&slot, ceiling(0, 10));

    let request = match PluginIdleHotLoop::begin_idle(
        &slot,
        &clock,
        &deadline_reader(deadline_20),
        None,
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle publish should succeed: {error}"),
    };

    assert_eq!(request.plan().current_icount(), 10);
    assert_eq!(request.plan().desired_wake_icount(), 20);
    assert_eq!(request.plan().cause(), IdleWakeCause::TimerDeadline);
    assert_eq!(request.futex_wait(), FutexWait::Wait { expected: 1 });

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 10);
    assert_eq!(snapshot.current_ns, 10);
    assert_eq!(snapshot.idle_wake_icount, 20);
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert!(slot.futex_wait_still_valid(1));
}

#[test]
fn idle_loop_wait_uses_futex_release_without_wall_clock_timeout() {
    let slot = NodeSlot::new(KIND_VM);
    publish_ceiling(&slot, ceiling(0, 10));
    let clock = owned_clock(10, 0);
    let request = match PluginIdleHotLoop::begin_idle(
        &slot,
        &clock,
        &deadline_reader(deadline_10),
        None,
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle publish should be immediately runnable: {error}"),
    };

    assert_eq!(request.futex_wait(), FutexWait::Runnable);
    assert_eq!(
        PluginIdleHotLoop::wait_for_scheduler_release(&header(), &slot, &request),
        Ok(IdleWaitOutcome::SchedulerReleased)
    );
}

#[test]
fn idle_loop_shutdown_wake_marks_done_and_returns_teardown_outcome() {
    let header = header();
    let slot = NodeSlot::new(KIND_VM);
    publish_ceiling(&slot, ceiling(0, 10));
    let clock = owned_clock(10, 0);
    let request = match PluginIdleHotLoop::begin_idle(
        &slot,
        &clock,
        &deadline_reader(deadline_20),
        None,
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle publish should park for future timer: {error}"),
    };

    if let Err(error) = header.request_shutdown([&slot]) {
        panic!("shutdown should wake idle slot: {error}");
    }
    assert_eq!(
        PluginIdleHotLoop::wait_for_scheduler_release(&header, &slot, &request),
        Ok(IdleWaitOutcome::ShutdownRequested)
    );

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 10);
    assert_eq!(snapshot.current_ns, 10);
    assert_eq!(snapshot.status, STATUS_DONE);
    assert_eq!(clock.current_icount(), 10);
}

#[cfg(target_os = "linux")]
#[test]
fn idle_loop_pause_quiesces_without_advancing_and_returns_to_qemu() {
    let header = Arc::new(header());
    let slot = Arc::new(NodeSlot::new(KIND_VM));
    publish_ceiling(&slot, ceiling(0, 10));
    let clock = owned_clock(10, 0);
    let request =
        PluginIdleHotLoop::begin_idle(&slot, &clock, &deadline_reader(deadline_20), None, None)
            .unwrap_or_else(|error| panic!("idle publish should park: {error}"));

    header
        .request_pause([slot.as_ref()])
        .unwrap_or_else(|error| panic!("pause request should wake the idle slot: {error}"));
    assert_eq!(
        PluginIdleHotLoop::wait_for_scheduler_release(&header, &slot, &request),
        Ok(IdleWaitOutcome::CheckpointPauseRequested)
    );
    let paused = slot.snapshot();
    assert_eq!(paused.status, STATUS_IDLE);
    assert_eq!(paused.current_icount, 10);
    assert_eq!(paused.idle_wake_icount, 10);
    assert_eq!(clock.current_icount(), 10);

    header.clear_pause();
    assert_eq!(clock.current_icount(), 10);
}

#[test]
fn idle_loop_shutdown_takes_priority_over_an_active_pause() {
    let header = header();
    let slot = NodeSlot::new(KIND_VM);
    publish_ceiling(&slot, ceiling(0, 10));
    let clock = owned_clock(10, 0);
    let request =
        PluginIdleHotLoop::begin_idle(&slot, &clock, &deadline_reader(deadline_20), None, None)
            .unwrap_or_else(|error| panic!("idle publish should park: {error}"));
    header
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    assert_eq!(
        PluginIdleHotLoop::wait_for_scheduler_release(&header, &slot, &request),
        Ok(IdleWaitOutcome::ShutdownRequested)
    );
    assert_eq!(slot.snapshot().status, STATUS_DONE);
    assert_eq!(clock.current_icount(), 10);
}

#[test]
fn idle_loop_release_waits_for_qemu_completion_before_mutating_state() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 1);
    publish_ceiling(&slot, ceiling(0, 10));
    let request = match PluginIdleHotLoop::begin_idle(
        &slot,
        &clock,
        &deadline_reader(deadline_40),
        Some(40),
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle begin should succeed: {error}"),
    };
    assert!(request.plan().requires_scheduler_wait());

    publish_ceiling(&slot, ceiling(10, 20));
    let mut clock = clock;
    set_last_direct_advance_ns(-1);
    let queued_idle_advance = queued_idle_advance();
    let pending = expect_pending(PluginIdleHotLoop::complete_after_scheduler_wake(
        &slot,
        &mut clock,
        &queued_idle_advance,
        request,
        [
            frame(20, 9, 4, b"late-by-key"),
            frame(15, 4, 1, b"jumped-over"),
            frame(20, 1, 7, b"first"),
            frame(21, 1, 8, b"future"),
        ],
    ));
    assert_eq!(last_direct_advance_ns(), 40);
    assert_eq!(clock.current_icount(), 10);

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 10);
    assert_eq!(snapshot.current_ns, 20);
    assert_eq!(snapshot.status, STATUS_IDLE);

    let result = PluginIdleHotLoop::complete_after_time_advance(
        &slot,
        &mut clock,
        request,
        pending,
        successful_completion(pending),
        [
            frame(20, 9, 4, b"late-by-key"),
            frame(15, 4, 1, b"jumped-over"),
            frame(20, 1, 7, b"first"),
            frame(21, 1, 8, b"future"),
        ],
    )
    .unwrap_or_else(|error| panic!("idle completion should succeed: {error}"));
    assert_eq!(result.advance().from_icount(), 10);
    assert_eq!(result.advance().to_icount(), 20);
    assert_eq!(result.advance().virtual_ns(), 40);
    assert!(!result.pending_advance().completion_pending());
    assert_eq!(
        result
            .injected_frames()
            .iter()
            .map(FrameEntry::delivery_key)
            .collect::<Vec<_>>(),
        vec![
            frame(15, 4, 1, b"jumped-over").delivery_key(),
            frame(20, 1, 7, b"first").delivery_key(),
            frame(20, 9, 4, b"late-by-key").delivery_key(),
        ]
    );
    assert_eq!(clock.current_icount(), 20);
    assert_eq!(slot.snapshot().status, STATUS_RUNNING);
}
