//! Original idle callback decisions with copied-value diagnostics enabled or off.
//!
//! Raw-clock and queued-advance APIs are explicit providers, not a Linux/TCG run.

use super::*;
use std::ffi::OsStr;
use std::io::{Read, Seek};

fn captured_witness() -> (idle_plan_witness::IdlePlanWitness, File) {
    let path = std::env::temp_dir().join(format!(
        "idle-plan-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let capture = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("capture: {error}"));
    std::fs::remove_file(path).unwrap_or_else(|error| panic!("unlink: {error}"));
    let mut witness = idle_plan_witness::IdlePlanWitness::from_setting(Some(OsStr::new("256")));
    witness.destination = Some(Mutex::new(
        capture
            .try_clone()
            .unwrap_or_else(|error| panic!("duplicate: {error}")),
    ));
    (witness, capture)
}

#[test]
fn genuine_due_return_and_forward_selection_keep_original_slot_and_advance_effects() {
    for deadline in [100, 200] {
        let mut without_observer = None;
        for enabled in [false, true] {
            let slot = NodeSlot::new(KIND_VM);
            let ceiling = authorize_advance_ceiling(0, 1000, None)
                .unwrap_or_else(|error| panic!("ceiling: {error}"));
            slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
                .unwrap_or_else(|error| panic!("publication: {error}"));
            let mut state =
                test_live_state(48, 1, 0, &slot).unwrap_or_else(|error| panic!("state: {error}"));
            state
                .on_vcpu_init(0)
                .unwrap_or_else(|error| panic!("init: {error}"));
            let (witness, mut capture) = captured_witness();
            state.idle_plan_witness = if enabled {
                witness
            } else {
                idle_plan_witness::IdlePlanWitness::from_setting(None)
            };
            TEST_CLOCK_DEADLINE_PS.set(deadline);
            LAST_QUEUED_ADVANCE_TICK.set(-1);
            TEST_ICOUNT_RAW_READS.set(0);
            let result = state.on_vcpu_idle(0, 2);
            TEST_CLOCK_DEADLINE_PS.set(-1);
            assert_eq!(result, Ok(()));
            let outcome = (
                slot.snapshot(),
                LAST_QUEUED_ADVANCE_TICK.get(),
                state.idle_advance_is_pending(),
                state.all_halted_idle_handled.load(Ordering::Acquire),
                TEST_ICOUNT_RAW_READS.get(),
            );
            if enabled {
                assert_eq!(Some(outcome), without_observer);
            } else {
                without_observer = Some(outcome);
            }
            assert_eq!(outcome.1, if deadline == 100 { -1 } else { 200 });
            assert_eq!(outcome.2, deadline == 200);
            capture
                .rewind()
                .unwrap_or_else(|error| panic!("rewind: {error}"));
            let mut rows = String::new();
            capture
                .read_to_string(&mut rows)
                .unwrap_or_else(|error| panic!("read: {error}"));
            if enabled {
                assert_eq!(rows.lines().count(), 2);
                assert!(rows.contains("raw=2 current_ps=100 ceiling_ps=1000 stop=Ceiling "));
                assert!(rows.contains("cause=TimerDeadline"));
                assert!(rows.contains(if deadline == 100 {
                    "outcome=Some(AlreadyDueReturn(100))"
                } else {
                    "outcome=Some(AdvanceSelected(200))"
                }));
            } else {
                assert!(rows.is_empty());
            }
        }
    }
}

#[test]
fn genuine_wait_error_preserves_original_error_and_dropped_busy_capture() {
    let mut original_error = None;
    for busy in [false, true] {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 1000, None)
            .unwrap_or_else(|error| panic!("ceiling: {error}"));
        slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::NextAuthenticatedIdle)
            .unwrap_or_else(|error| panic!("publication: {error}"));
        let mut state =
            test_live_state(48, 1, 0, &slot).unwrap_or_else(|error| panic!("state: {error}"));
        state
            .on_vcpu_init(0)
            .unwrap_or_else(|error| panic!("init: {error}"));
        let (witness, mut capture) = captured_witness();
        state.idle_plan_witness = witness;
        let held = busy.then(|| {
            state
                .idle_plan_witness
                .destination
                .as_ref()
                .unwrap_or_else(|| panic!("sink"))
                .lock()
                .unwrap_or_else(|error| panic!("capture lock: {error}"))
        });
        TEST_CLOCK_DEADLINE_PS.set(200);
        TEST_IDLE_WAKE_WAIT_STATUS.set(17);
        let result = state.on_vcpu_idle(0, 2);
        TEST_CLOCK_DEADLINE_PS.set(-1);
        TEST_IDLE_WAKE_WAIT_STATUS.set(1);
        drop(held);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("original refusal"))
            .to_string();
        if busy {
            assert_eq!(Some(error), original_error);
        } else {
            original_error = Some(error);
        }
        assert!(!state.idle_advance_is_pending());
        capture
            .rewind()
            .unwrap_or_else(|error| panic!("rewind: {error}"));
        let mut rows = String::new();
        capture
            .read_to_string(&mut rows)
            .unwrap_or_else(|error| panic!("read: {error}"));
        if busy {
            assert!(rows.is_empty());
        } else {
            assert!(rows.contains("outcome=Some(WaitError)"));
        }
    }
}
