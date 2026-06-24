//! Checks region-wide pause and shutdown control flags.

#![forbid(unsafe_code)]

use crucible_shmem::{
    KIND_VM, NodeSlot, RegionConfig, RegionControlAction, RegionHeader, RegionLayout, STATUS_DONE,
    STATUS_IDLE, WakeAllResult,
};

#[cfg(target_os = "linux")]
use std::{
    fs,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

#[test]
fn pause_request_sets_flag_and_wakes_every_slot() {
    let header = header();
    let slots = slots(3);

    assert_eq!(header.control_action(), RegionControlAction::Continue);
    assert_eq!(
        header.request_pause(slots.iter()),
        Ok(WakeAllResult {
            slots_signaled: 3,
            waiters_woken: 0,
        })
    );

    assert!(header.pause_requested());
    assert!(!header.shutdown_requested());
    assert_eq!(header.control_action(), RegionControlAction::Pause);
    assert!(slots.iter().all(|slot| slot.snapshot().wake_signal == 1));

    header.clear_pause();
    assert!(!header.pause_requested());
    assert_eq!(header.control_action(), RegionControlAction::Continue);
}

#[test]
fn shutdown_request_takes_priority_and_nodes_mark_done() {
    let header = header();
    let slots = slots(2);
    assert!(header.request_pause(slots.iter()).is_ok());

    assert_eq!(
        header.request_shutdown(slots.iter()),
        Ok(WakeAllResult {
            slots_signaled: 2,
            waiters_woken: 0,
        })
    );

    assert!(header.pause_requested());
    assert!(header.shutdown_requested());
    assert_eq!(header.control_action(), RegionControlAction::Shutdown);
    assert!(slots.iter().all(|slot| slot.snapshot().wake_signal == 2));

    slots[0].mark_done();
    let snapshot = slots[0].snapshot();
    assert_eq!(snapshot.status, STATUS_DONE);
    assert_eq!(snapshot.publish_gen % 2, 0);
}

#[test]
fn node_can_publish_pause_quiescence_at_quantum_boundary() {
    let slot = NodeSlot::new(KIND_VM);

    assert_eq!(slot.publish_pause_quiesced(42, 2), Ok(()));

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 42);
    assert_eq!(snapshot.current_ns, 168);
    assert_eq!(snapshot.idle_wake_icount, 42);
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.publish_gen % 2, 0);
}

#[test]
#[cfg(target_os = "linux")]
fn linux_shutdown_request_wakes_all_parked_waiters() {
    let header = header();
    let slots = vec![
        Arc::new(NodeSlot::new(KIND_VM)),
        Arc::new(NodeSlot::new(KIND_VM)),
    ];
    let mut waiters = Vec::new();
    let mut waiter_tids = Vec::new();

    for slot in &slots {
        let waiter_slot = Arc::clone(slot);
        let (ready_tx, ready_rx) = mpsc::channel();
        waiters.push(thread::spawn(move || {
            let _ = ready_tx.send(linux_thread_id());
            waiter_slot.futex_wait_word_nonprivate(0)
        }));
        waiter_tids.push(match ready_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(tid) => tid,
            Err(error) => panic!("waiter did not reach futex wait setup: {error}"),
        });
    }

    for tid in waiter_tids {
        wait_until_linux_task_sleeps_in_futex(tid);
    }

    let result = match header.request_shutdown(slots.iter().map(Arc::as_ref)) {
        Ok(result) => result,
        Err(error) => panic!("shutdown wake-all should succeed: {error}"),
    };
    assert_eq!(
        result,
        WakeAllResult {
            slots_signaled: 2,
            waiters_woken: 2,
        }
    );

    for waiter in waiters {
        match waiter.join() {
            Ok(Ok(outcome)) => assert_eq!(outcome, crucible_shmem::FutexWaitOutcome::Woken),
            Ok(Err(error)) => panic!("waiter futex wait failed: {error}"),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}

#[test]
#[cfg(not(target_os = "linux"))]
fn off_linux_control_wake_all_uses_noop_futex_results() {
    let header = header();
    let slots = slots(2);

    assert_eq!(
        header.request_shutdown(slots.iter()),
        Ok(WakeAllResult {
            slots_signaled: 2,
            waiters_woken: 0,
        })
    );
    assert!(slots.iter().all(|slot| slot.snapshot().wake_signal == 1));
}

fn header() -> RegionHeader {
    RegionHeader::new(layout())
}

fn layout() -> RegionLayout {
    match RegionLayout::for_config(RegionConfig::new(2, 8, 0)) {
        Ok(layout) => layout,
        Err(error) => panic!("region layout should be valid: {error}"),
    }
}

fn slots(count: usize) -> Vec<NodeSlot> {
    (0..count).map(|_| NodeSlot::new(KIND_VM)).collect()
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
