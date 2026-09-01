//! Shared advance-ceiling handoff fixtures and Linux futex helpers.

use super::*;

pub(super) fn wake_action(previous: u32, new: u32, waiters_woken: u32) -> WakeAction {
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
pub(super) fn assert_linux_trigger_wakes_parked_waiter<E>(
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
pub(super) fn linux_thread_id() -> u32 {
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
pub(super) fn wait_until_linux_task_sleeps_in_futex(tid: u32) {
    for _ in 0..100_000 {
        if linux_task_wait_channel_contains_futex(tid) || linux_task_is_sleeping(tid) {
            return;
        }
        thread::yield_now();
    }

    panic!("Linux task {tid} did not enter a futex sleep");
}

#[cfg(target_os = "linux")]
pub(super) fn linux_task_wait_channel_contains_futex(tid: u32) -> bool {
    let path = format!("/proc/self/task/{tid}/wchan");
    fs::read_to_string(path).is_ok_and(|wait_channel| wait_channel.contains("futex"))
}

#[cfg(target_os = "linux")]
pub(super) fn linux_task_is_sleeping(tid: u32) -> bool {
    let path = format!("/proc/self/task/{tid}/status");
    let Ok(status) = fs::read_to_string(path) else {
        return false;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))
        .is_some_and(|state| state.contains("sleeping") || state.contains("disk sleep"))
}

pub(super) fn ceiling(
    current_icount: u64,
    max_advance_icount: u64,
) -> crucible_shmem::AdvanceCeiling {
    match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
        Ok(ceiling) => ceiling,
        Err(error) => panic!("advance ceiling should be valid: {error}"),
    }
}

pub(super) fn region(vm_node_count: u32, queue_capacity: u32) -> RegionAllocation {
    match RegionAllocation::new_model(RegionConfig::new(vm_node_count, queue_capacity, 0)) {
        Ok(region) => region,
        Err(error) => panic!("region fixture should build: {error}"),
    }
}

pub(super) fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("frame fixture should build: {error}"),
    }
}

pub(super) fn frame_entries(capacity: usize) -> Vec<FrameEntry> {
    vec![frame(0, 0, 0, b""); capacity]
}

pub(super) fn assert_source_order(source: &str, needles: &[&str], context: &str) {
    let mut offset = 0;
    for needle in needles {
        let remaining = &source[offset..];
        let Some(relative) = remaining.find(needle) else {
            panic!("{context}: missing `{needle}` after byte offset {offset}");
        };
        offset += relative + needle.len();
    }
}

pub(super) fn function_source(signature: &str) -> &str {
    let Some(start) = SHMEM_SOURCE.find(signature) else {
        panic!("missing source signature `{signature}`");
    };
    let after_signature = &SHMEM_SOURCE[start..];
    let Some(open_relative) = after_signature.find('{') else {
        panic!("missing body for source signature `{signature}`");
    };
    let open = start + open_relative;
    let mut depth = 0_i32;
    for (relative, ch) in SHMEM_SOURCE[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &SHMEM_SOURCE[start..open + relative + ch.len_utf8()];
                }
            }
            _ => {}
        }
    }

    panic!("unterminated source body for `{signature}`");
}
