//! Genuine block callback and completion noninterference under observations.

use super::*;
use std::ffi::OsStr;
use std::io::{Read, Seek};

fn captured_witness() -> (device_wait_witness::DeviceWaitWitness, File) {
    let path = std::env::temp_dir().join(format!(
        "device-wait-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let capture = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("capture: {e}"));
    std::fs::remove_file(path).unwrap_or_else(|e| panic!("unlink: {e}"));
    let mut witness = device_wait_witness::DeviceWaitWitness::from_setting(Some(OsStr::new("256")));
    witness.destination = Some(Mutex::new(
        capture
            .try_clone()
            .unwrap_or_else(|e| panic!("capture duplicate: {e}")),
    ));
    (witness, capture)
}

#[test]
fn genuine_wait_success_busy_and_completion_refusal_keep_original_reads_and_state() {
    for enabled in [false, true] {
        for status in [0, -libc::EBUSY] {
            let slot = NodeSlot::new(KIND_VM);
            let ceiling =
                authorize_advance_ceiling(0, 20, None).unwrap_or_else(|e| panic!("ceiling: {e}"));
            slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
                .unwrap_or_else(|e| panic!("ceiling publication: {e}"));
            slot.store_device_completion_deadline_tick(12);
            let mut state =
                test_live_state(48, 1, 0, &slot).unwrap_or_else(|e| panic!("state: {e}"));
            let (witness, mut capture) = captured_witness();
            state.device_wait_witness = if enabled {
                witness
            } else {
                device_wait_witness::DeviceWaitWitness::from_setting(None)
            };
            TEST_ICOUNT_RAW_READS.set(0);
            TEST_CLOCK_DEADLINE_PS.set(-1);
            TEST_QUEUED_ADVANCE_STATUS.set(status);

            let result = state.on_block_wait(7);
            TEST_QUEUED_ADVANCE_STATUS.set(0);
            assert_eq!(result, Ok(()));
            assert_eq!(TEST_ICOUNT_RAW_READS.get(), 1);
            assert_eq!(state.idle_advance_is_pending(), status == 0);
            assert_eq!(slot.snapshot().current_icount, 0);
            if status == 0 {
                state
                    .on_block_wait(8)
                    .unwrap_or_else(|e| panic!("pending retry: {e}"));
                assert_eq!(TEST_ICOUNT_RAW_READS.get(), 1);
                assert!(
                    state
                        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 14))
                        .is_err()
                );
                assert!(state.idle_advance_is_pending());
                state
                    .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 12))
                    .unwrap_or_else(|e| panic!("completion: {e}"));
                assert_eq!(slot.snapshot().current_icount, 12);
            }
            capture.rewind().unwrap_or_else(|e| panic!("rewind: {e}"));
            let mut rows = String::new();
            capture
                .read_to_string(&mut rows)
                .unwrap_or_else(|e| panic!("capture read: {e}"));
            if enabled {
                assert!(rows.contains("phase=enqueue"));
                if status == 0 {
                    assert!(rows.contains("request=7"));
                    assert!(rows.contains("result=completed"));
                    assert!(rows.contains("phase=pending"));
                    assert!(rows.contains("result=error"));
                } else {
                    assert!(rows.contains(&format!("status={status} result=deferred")));
                    assert!(!rows.contains("phase=completion"));
                }
            } else {
                assert!(rows.is_empty());
            }
        }
    }
}

#[test]
fn genuine_local_occupied_branch_has_no_sdk_call_or_diagnostic_owner_lookup() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None).unwrap_or_else(|e| panic!("ceiling: {e}"));
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|e| panic!("publication: {e}"));
    let mut state = test_live_state(48, 1, 0, &slot).unwrap_or_else(|e| panic!("state: {e}"));
    let (witness, mut capture) = captured_witness();
    state.device_wait_witness = witness;
    let observation = state
        .device_wait_witness
        .request(9, state.control_stage_identity);
    let held = state
        .pending_idle_advance
        .lock()
        .unwrap_or_else(|e| panic!("held owner: {e}"));
    LAST_QUEUED_ADVANCE_TICK.set(-1);

    assert_eq!(
        state.arm_and_enqueue_idle_advance_observed(0, 12, None, observation),
        Ok(false)
    );
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
    assert!(held.is_none());
    drop(held);
    capture.rewind().unwrap_or_else(|e| panic!("rewind: {e}"));
    let mut row = String::new();
    capture
        .read_to_string(&mut row)
        .unwrap_or_else(|e| panic!("read: {e}"));
    assert!(row.contains("phase=local-occupied"));
    assert!(row.contains("status=unavailable result=deferred"));
}

#[cfg(target_os = "linux")]
#[test]
fn genuine_callback_ignores_full_fifo_and_busy_capture_without_changing_completion() {
    use std::os::fd::FromRawFd;
    let mut descriptors = [-1; 2];
    // SAFETY: storage owns two output slots; success transfers each descriptor
    // exactly once into a File whose lifetime covers the complete callback test.
    let status = unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(status, 0);
    // SAFETY: successful pipe2 created both distinct owned descriptors above.
    let (reader, original) = unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    };
    let mut destination = device_wait_witness::capture::destination(&original)
        .unwrap_or_else(|e| panic!("FIFO capture: {e}"));
    let bytes = [0_u8; 512];
    loop {
        match destination.write(&bytes) {
            Ok(length) => assert_eq!(length, bytes.len()),
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                break;
            }
        }
    }
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None).unwrap_or_else(|e| panic!("ceiling: {e}"));
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|e| panic!("publication: {e}"));
    slot.store_device_completion_deadline_tick(12);
    let mut state = test_live_state(48, 1, 0, &slot).unwrap_or_else(|e| panic!("state: {e}"));
    state.device_wait_witness =
        device_wait_witness::DeviceWaitWitness::from_setting(Some(OsStr::new("256")));
    state.device_wait_witness.destination = Some(Mutex::new(original));
    TEST_CLOCK_DEADLINE_PS.set(-1);
    TEST_ICOUNT_RAW_READS.set(0);

    assert_eq!(state.on_block_wait(7), Ok(()));
    assert!(state.idle_advance_is_pending());
    assert_eq!(TEST_ICOUNT_RAW_READS.get(), 1);
    let busy = state
        .device_wait_witness
        .destination
        .as_ref()
        .unwrap_or_else(|| panic!("sink"))
        .lock()
        .unwrap_or_else(|e| panic!("sink lock: {e}"));
    assert_eq!(state.on_block_wait(8), Ok(()));
    assert_eq!(TEST_ICOUNT_RAW_READS.get(), 1);
    drop(busy);
    drop(reader);
    assert_eq!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 12)),
        Ok(12)
    );
    assert_eq!(slot.snapshot().current_icount, 12);
    assert!(!state.idle_advance_is_pending());
}

#[test]
fn due_original_timer_reports_exact_deadline_and_suppressed_device_target() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling =
        authorize_advance_ceiling(0, 1000, None).unwrap_or_else(|e| panic!("ceiling: {e}"));
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|e| panic!("publication: {e}"));
    slot.store_device_completion_deadline_tick(300);
    let mut state = test_live_state(48, 1, 0, &slot).unwrap_or_else(|e| panic!("state: {e}"));
    let (witness, mut capture) = captured_witness();
    state.device_wait_witness = witness;
    TEST_ICOUNT_RAW.set(1);
    TEST_CLOCK_DEADLINE_PS.set(8);
    LAST_QUEUED_ADVANCE_TICK.set(-1);

    let result = state.on_block_wait(7);
    TEST_CLOCK_DEADLINE_PS.set(-1);
    TEST_ICOUNT_RAW.set(0);
    assert_eq!(result, Ok(()));
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
    assert!(!state.idle_advance_is_pending());
    assert_eq!(slot.snapshot().current_icount, 50);
    capture.rewind().unwrap_or_else(|e| panic!("rewind: {e}"));
    let mut rows = String::new();
    capture
        .read_to_string(&mut rows)
        .unwrap_or_else(|e| panic!("read: {e}"));
    let row = rows
        .lines()
        .find(|row| row.contains("phase=already-due"))
        .unwrap_or_else(|| panic!("already due row"));
    assert!(row.contains("current=50 deadline=300"));
    assert!(row.contains("target=50"));
    assert!(row.contains("exact_deadline=8"));
    assert!(row.ends_with("status=unavailable result=retry"));
}

thread_local! {
    static OBSERVED_ENQUEUE_STATE: Cell<*const LiveVcpuTimeCallbackState> = const { Cell::new(std::ptr::null()) };
    static OBSERVED_ENQUEUE_NESTED: Cell<bool> = const { Cell::new(false) };
}

extern "C" fn complete_original_and_enqueue_new_request(target: i64) -> i32 {
    if OBSERVED_ENQUEUE_NESTED.get() {
        return 0;
    }
    let state = OBSERVED_ENQUEUE_STATE.get();
    if state.is_null() {
        return -libc::ENODEV;
    }
    OBSERVED_ENQUEUE_NESTED.set(true);
    // SAFETY: the test pins this shared callback owner for the whole synchronous
    // provider call; original canonical guards are released before this SDK seam.
    let state = unsafe { &*state };
    let result = (|| {
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, target))?;
        state.slot.get().store_device_completion_deadline_tick(16);
        state.on_block_wait(9)
    })();
    OBSERVED_ENQUEUE_NESTED.set(false);
    if result.is_ok() { 0 } else { -libc::EIO }
}

#[test]
fn genuine_nested_enqueue_keeps_late_original_return_and_new_completion_attribution() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None).unwrap_or_else(|e| panic!("ceiling: {e}"));
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|e| panic!("publication: {e}"));
    slot.store_device_completion_deadline_tick(12);
    let mut state = test_live_state(48, 1, 0, &slot).unwrap_or_else(|e| panic!("state: {e}"));
    let (witness, mut capture) = captured_witness();
    state.device_wait_witness = witness;
    state.queued_idle_advance =
        QueuedIdleAdvance::require(Some(complete_original_and_enqueue_new_request))
            .unwrap_or_else(|e| panic!("provider: {e}"));
    let state = Box::new(state);
    TEST_CLOCK_DEADLINE_PS.set(-1);
    OBSERVED_ENQUEUE_STATE.set(std::ptr::from_ref(state.as_ref()));

    let result = state.on_block_wait(7);
    OBSERVED_ENQUEUE_STATE.set(std::ptr::null());
    assert_eq!(result, Ok(()));
    assert_eq!(slot.snapshot().current_icount, 12);
    assert!(state.idle_advance_is_pending());
    assert_eq!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 16)),
        Ok(16)
    );
    capture.rewind().unwrap_or_else(|e| panic!("rewind: {e}"));
    let mut rows = String::new();
    capture
        .read_to_string(&mut rows)
        .unwrap_or_else(|e| panic!("read: {e}"));
    let rows: Vec<_> = rows.lines().collect();
    let original = rows
        .iter()
        .position(|row| {
            row.contains("phase=enqueue")
                && row.contains("request=7")
                && row.contains("target=12 arm=0")
        })
        .unwrap_or_else(|| panic!("original return"));
    let nested = rows
        .iter()
        .position(|row| {
            row.contains("phase=enqueue")
                && row.contains("request=9")
                && row.contains("target=16 arm=1")
        })
        .unwrap_or_else(|| panic!("nested return"));
    assert!(
        nested < original,
        "original SDK return follows genuine nested enqueue"
    );
    assert!(
        rows.last()
            .is_some_and(|row| row.contains("phase=completion")
                && row.contains("request=9")
                && row.contains("target=16 arm=1")
                && row.contains("echo_target=16 status=0 result=completed"))
    );
}
