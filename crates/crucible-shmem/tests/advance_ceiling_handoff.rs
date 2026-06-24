//! Checks the per-node advance-ceiling handoff.

#![forbid(unsafe_code)]

use crucible_shmem::{
    FutexWait, FutexWakeResult, KIND_VM, NODE_SLOT_ALIGN, NODE_SLOT_CURRENT_ICOUNT_OFFSET,
    NODE_SLOT_CURRENT_NS_OFFSET, NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
    NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, NODE_SLOT_KIND_OFFSET, NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
    NODE_SLOT_PUBLISH_GEN_OFFSET, NODE_SLOT_SIZE, NODE_SLOT_STATUS_OFFSET,
    NODE_SLOT_WAKE_SIGNAL_OFFSET, NodeSlot, NodeSlotError, STATUS_IDLE, STATUS_RUNNING, WakeAction,
    authorize_advance_ceiling, icount_to_virtual_ns,
};

#[cfg(target_os = "linux")]
use std::{
    fs,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

#[test]
fn node_slot_layout_matches_wire_contract() {
    assert_eq!(NODE_SLOT_SIZE, 128);
    assert_eq!(NODE_SLOT_ALIGN, 128);
    assert_eq!(NODE_SLOT_CURRENT_ICOUNT_OFFSET, 0);
    assert_eq!(NODE_SLOT_CURRENT_NS_OFFSET, 8);
    assert_eq!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, 16);
    assert_eq!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, 24);
    assert_eq!(NODE_SLOT_WAKE_SIGNAL_OFFSET, 32);
    assert_eq!(NODE_SLOT_STATUS_OFFSET, 36);
    assert_eq!(NODE_SLOT_KIND_OFFSET, 37);
    assert_eq!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET, 38);
    assert_eq!(NODE_SLOT_PUBLISH_GEN_OFFSET, 40);
}

#[test]
fn scheduler_publishes_ceiling_and_node_publishes_reached_icount() {
    let slot = NodeSlot::new(KIND_VM);
    assert_eq!(slot.snapshot().max_advance_icount, 0);

    let ceiling = ceiling(0, 12);
    assert_eq!(
        slot.publish_scheduler_ceiling(ceiling),
        Ok(wake_action(0, 1, 0))
    );
    assert_eq!(slot.load_node_ceiling(), 12);

    slot.mark_running();
    assert_eq!(slot.publish_reached_icount(12, 3), Ok(()));

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 12);
    assert_eq!(snapshot.current_ns, 96);
    assert_eq!(snapshot.max_advance_icount, 12);
    assert_eq!(snapshot.status, STATUS_RUNNING);
    assert_eq!(snapshot.kind, KIND_VM);
    assert_eq!(snapshot.publish_gen % 2, 0);
}

#[test]
fn mark_running_participates_in_publish_generation() {
    let slot = NodeSlot::new(KIND_VM);
    let before = slot.snapshot().publish_gen;

    slot.mark_running();

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.status, STATUS_RUNNING);
    assert_eq!(snapshot.publish_gen, before + 2);
    assert_eq!(snapshot.publish_gen % 2, 0);
}

#[test]
fn node_cannot_self_extend_past_published_ceiling() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = ceiling(0, 9);
    assert!(slot.publish_scheduler_ceiling(ceiling).is_ok());

    assert_eq!(slot.check_node_may_advance_to(9), Ok(()));
    assert_eq!(
        slot.check_node_may_advance_to(10),
        Err(NodeSlotError::NodeAdvancePastCeiling {
            next_icount: 10,
            max_advance_icount: 9,
        })
    );
    assert_eq!(
        slot.publish_reached_icount(10, 0),
        Err(NodeSlotError::NodeAdvancePastCeiling {
            next_icount: 10,
            max_advance_icount: 9,
        })
    );
}

#[test]
fn idle_publish_uses_race_free_futex_wait_and_wake_counter() {
    let slot = NodeSlot::new(KIND_VM);
    let first_ceiling = ceiling(0, 10);
    assert!(slot.publish_scheduler_ceiling(first_ceiling).is_ok());
    slot.mark_running();

    assert_eq!(slot.publish_reached_icount(10, 0), Ok(()));
    assert_eq!(
        slot.publish_idle(10, 20, 0),
        Ok(FutexWait::Wait { expected: 1 })
    );
    let idle = slot.snapshot();
    assert_eq!(idle.status, STATUS_IDLE);
    assert_eq!(idle.idle_wake_icount, 20);

    assert!(slot.futex_wait_still_valid(1));
    assert_eq!(
        slot.publish_scheduler_ceiling(ceiling(10, 20)),
        Ok(wake_action(1, 2, 0))
    );
    assert!(!slot.futex_wait_still_valid(1));
    assert_eq!(slot.prepare_futex_wait(), FutexWait::Runnable);
}

#[test]
fn scheduler_raise_during_idle_publish_race_bumps_wake_counter() {
    let slot = NodeSlot::new(KIND_VM);
    assert!(slot.publish_scheduler_ceiling(ceiling(0, 10)).is_ok());
    slot.mark_running();
    assert_eq!(slot.publish_reached_icount(10, 0), Ok(()));

    assert_eq!(
        slot.publish_scheduler_ceiling(ceiling(10, 20)),
        Ok(wake_action(1, 2, 0))
    );
    assert_eq!(slot.publish_idle(10, 20, 0), Ok(FutexWait::Runnable));
    assert_eq!(slot.snapshot().wake_signal, 2);
}

#[test]
fn node_reports_invalid_idle_and_time_conversion_loudly() {
    let slot = NodeSlot::new(KIND_VM);
    assert!(slot.publish_scheduler_ceiling(ceiling(0, 50)).is_ok());
    slot.mark_running();

    assert_eq!(
        slot.publish_idle(20, 19, 0),
        Err(NodeSlotError::IdleWakeBeforeCurrent {
            current_icount: 20,
            idle_wake_icount: 19,
        })
    );
    assert_eq!(
        icount_to_virtual_ns(1, 64),
        Err(NodeSlotError::InvalidShift { shift_bits: 64 })
    );
    assert_eq!(
        icount_to_virtual_ns(u64::MAX, 1),
        Err(NodeSlotError::VirtualTimeOverflow {
            icount: u64::MAX,
            shift_bits: 1,
        })
    );
}

#[test]
fn frame_delivery_wake_always_bumps_the_futex_word() {
    let slot = NodeSlot::new(KIND_VM);

    assert_eq!(slot.wake_for_frame_delivery(), Ok(wake_action(0, 1, 0)));
    assert_eq!(slot.snapshot().wake_signal, 1);
}

#[test]
#[cfg(target_os = "linux")]
fn linux_non_private_futex_syscalls_are_available() {
    let slot = NodeSlot::new(KIND_VM);

    let wake = match slot.futex_wake_nonprivate(1) {
        Ok(wake) => wake,
        Err(error) => panic!("non-private FUTEX_WAKE should be available: {error}"),
    };
    assert_eq!(wake.waiters_woken, 0);
    assert!(!wake.futex_private);
    const { assert!(!crucible_shmem::FUTEX_PRIVATE) };

    let wait = match slot.futex_wait_word_nonprivate(99) {
        Ok(wait) => wait,
        Err(error) => panic!("non-private FUTEX_WAIT should report value change: {error}"),
    };
    assert_eq!(wait, crucible_shmem::FutexWaitOutcome::ValueChanged);
}

#[test]
#[cfg(target_os = "linux")]
fn linux_scheduler_trigger_wakes_parked_waiter() {
    assert_linux_trigger_wakes_parked_waiter(|slot| slot.publish_scheduler_ceiling(ceiling(0, 1)));
}

#[test]
#[cfg(target_os = "linux")]
fn linux_frame_delivery_trigger_wakes_parked_waiter() {
    assert_linux_trigger_wakes_parked_waiter(NodeSlot::wake_for_frame_delivery);
}

#[test]
#[cfg(not(target_os = "linux"))]
fn off_linux_futex_syscalls_compile_to_noops() {
    let slot = NodeSlot::new(KIND_VM);

    let wake = match slot.futex_wake_nonprivate(1) {
        Ok(wake) => wake,
        Err(error) => panic!("off-Linux FUTEX_WAKE shim should be a no-op: {error}"),
    };
    assert_eq!(wake.waiters_woken, 0);
    assert!(!wake.futex_private);

    let wait = match slot.futex_wait_word_nonprivate(0) {
        Ok(wait) => wait,
        Err(error) => panic!("off-Linux FUTEX_WAIT shim should be a no-op: {error}"),
    };
    assert_eq!(wait, crucible_shmem::FutexWaitOutcome::Noop);
}

fn wake_action(previous: u32, new: u32, waiters_woken: u32) -> WakeAction {
    WakeAction::Wake {
        previous,
        new,
        futex: FutexWakeResult {
            waiters_woken,
            futex_private: false,
        },
    }
}

#[cfg(target_os = "linux")]
fn assert_linux_trigger_wakes_parked_waiter<E>(
    mut trigger: impl FnMut(&NodeSlot) -> Result<WakeAction, E>,
) where
    E: std::fmt::Display,
{
    let slot = Arc::new(NodeSlot::new(KIND_VM));
    let waiter_slot = Arc::clone(&slot);
    let (ready_tx, ready_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let _ = ready_tx.send(linux_thread_id());
        waiter_slot.futex_wait_word_nonprivate(0)
    });

    let waiter_tid = match ready_rx.recv_timeout(Duration::from_secs(1)) {
        Ok(tid) => tid,
        Err(error) => panic!("waiter did not reach futex wait setup: {error}"),
    };
    wait_until_linux_task_sleeps_in_futex(waiter_tid);

    let action = match trigger(&slot) {
        Ok(action) => action,
        Err(error) => panic!("wake trigger failed: {error}"),
    };
    assert_eq!(action, wake_action(0, 1, 1));

    let outcome = match waiter.join() {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => panic!("waiter futex wait failed: {error}"),
        Err(payload) => std::panic::resume_unwind(payload),
    };
    assert_eq!(outcome, crucible_shmem::FutexWaitOutcome::Woken);
}

#[cfg(target_os = "linux")]
fn linux_thread_id() -> u32 {
    let task_link = match fs::read_link("/proc/thread-self") {
        Ok(path) => path,
        Err(error) => panic!("failed to read /proc/thread-self: {error}"),
    };
    let task_name = match task_link.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => panic!("/proc/thread-self target has no UTF-8 task id: {task_link:?}"),
    };
    match task_name.parse() {
        Ok(tid) => tid,
        Err(error) => panic!("failed to parse Linux task id {task_name:?}: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn wait_until_linux_task_sleeps_in_futex(tid: u32) {
    for _ in 0..100_000 {
        if linux_task_wait_channel_contains_futex(tid) || linux_task_is_sleeping(tid) {
            return;
        }
        thread::yield_now();
    }

    panic!("Linux task {tid} did not enter a futex sleep");
}

#[cfg(target_os = "linux")]
fn linux_task_wait_channel_contains_futex(tid: u32) -> bool {
    let path = format!("/proc/self/task/{tid}/wchan");
    fs::read_to_string(path).is_ok_and(|wait_channel| wait_channel.contains("futex"))
}

#[cfg(target_os = "linux")]
fn linux_task_is_sleeping(tid: u32) -> bool {
    let path = format!("/proc/self/task/{tid}/status");
    let Ok(status) = fs::read_to_string(path) else {
        return false;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))
        .is_some_and(|state| state.contains("sleeping") || state.contains("disk sleep"))
}

fn ceiling(current_icount: u64, max_advance_icount: u64) -> crucible_shmem::AdvanceCeiling {
    match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
        Ok(ceiling) => ceiling,
        Err(error) => panic!("advance ceiling should be valid: {error}"),
    }
}
