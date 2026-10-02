//! Witness bounds and observations through the real control callback guard.

use super::super::tests::test_live_state;
use super::*;
use crucible_shmem::{AdvanceStopCondition, KIND_VM, NodeSlot, authorize_advance_ceiling};

#[test]
fn witness_is_disabled_unless_setting_is_exactly_one() {
    assert!(!ControlCallbackWitness::from_setting(None).enabled);
    for setting in ["", "0", "true", "yes", "01", "1 "] {
        assert!(!ControlCallbackWitness::from_setting(Some(std::ffi::OsStr::new(setting))).enabled);
    }
    assert!(ControlCallbackWitness::from_setting(Some(std::ffi::OsStr::new("1"))).enabled);
}

#[test]
fn each_token_epoch_permits_at_most_ten_compact_phase_records() {
    let witness = ControlCallbackWitness::new(true);
    let events = [
        Event::Entry,
        Event::Admitted,
        Event::HotFork,
        Event::Teardown,
        Event::TeardownAndHotFork,
        Event::SharedShutdown,
        Event::Pending,
        Event::Acknowledged,
        Event::NoRequest,
        Event::Error,
    ];
    for token in [u32::MAX, 0, 4432] {
        witness.observe_token(token);
        let mut emitted = 0;
        for _attempt in 0..100 {
            for event in events {
                if let Some(record) = witness.record(event, u64::MAX, Some(u32::MAX)) {
                    let mut bytes = Vec::new();
                    record
                        .write_to(&mut bytes)
                        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
                    assert!(bytes.len() <= 256);
                    emitted += 1;
                }
            }
        }
        assert_eq!(emitted, 10);
    }
}

#[test]
fn fork_identity_change_clears_inherited_token_and_phase_budget() {
    let witness = ControlCallbackWitness::new(true);
    witness.observe_token(4432);
    assert!(witness.entry_record(7).is_some());
    assert!(witness.entry_record(7).is_none());
    witness
        .process_id
        .store(std::process::id().wrapping_add(1), Ordering::Relaxed);

    let child_entry = witness
        .entry_record(7)
        .unwrap_or_else(|| panic!("child entry should be recorded"));

    assert_eq!(child_entry.process_id, std::process::id());
    assert_eq!(child_entry.token_before, None);
    assert!(witness.entry_record(7).is_none());
    witness.observe_token(4432);
    assert!(witness.record(Event::Admitted, 7, Some(4432)).is_some());
}

fn run(state: &LiveVcpuTimeCallbackState, raw: u64) -> Vec<Record> {
    let mut records = Vec::new();
    state.run_control_callback(
        raw,
        |record| records.push(record),
        |error| panic!("unexpected callback failure: {error}"),
    );
    records
}

fn state(slot: &NodeSlot, enabled: bool) -> LiveVcpuTimeCallbackState {
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, 1_000, None)
            .unwrap_or_else(|error| panic!("test operation should succeed: {error}")),
        AdvanceStopCondition::Ceiling,
    )
    .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    let mut state = test_live_state(129, 1, 0, slot)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    state.control_callback_witness = ControlCallbackWitness::new(enabled);
    state
}

#[test]
fn disabled_witness_leaves_diagnostics_untouched_and_acknowledges_normally() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, false);
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));

    assert!(run(&state, 7).is_empty());

    assert_eq!(slot.control_boundary_token(), request + 1);
    assert_eq!(
        state
            .control_callback_witness
            .token_and_events
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(state.quiescence.snapshot().in_flight, 0);

    let next = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    super::super::crucible_qemu_plugin_live_control_boundary_cb(
        0,
        7,
        std::ptr::from_ref(&state).cast_mut().cast(),
    );
    assert_eq!(slot.control_boundary_token(), next + 1);
}

#[test]
fn callback_without_a_pending_request_reports_no_request_exit() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true);

    let records = run(&state, 7);

    assert_eq!(records.len(), 3);
    assert_eq!(records[2].event, Event::NoRequest);
    assert_eq!(records[2].token_before, Some(1));
    assert_eq!(records[2].token_after, Some(1));
}

#[test]
fn stalled_callbacks_are_bounded_but_later_ack_and_requests_remain_visible() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true);
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    state
        .fault_command_pump_active
        .store(true, Ordering::Release);

    let mut records = run(&state, 7);
    for raw in 8..10_008 {
        records.extend(run(&state, raw));
    }
    assert_eq!(records.len(), 4);
    assert_eq!(records[0].event, Event::Entry);
    assert_eq!(records[0].token_before, None);
    assert_eq!(records[1].event, Event::Admitted);
    assert_eq!(records[2].event, Event::Pending);
    assert_eq!(records[2].token_before, Some(request));
    assert_eq!(records[2].token_after, Some(request));
    assert_eq!(slot.control_boundary_token(), request);

    state
        .fault_command_pump_active
        .store(false, Ordering::Release);
    let completed = run(&state, 7);
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].event, Event::Acknowledged);
    assert_eq!(completed[0].token_after, Some(request + 1));

    let next = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    let later = run(&state, 7);
    assert_eq!(later.len(), 2);
    assert_eq!(later[0].event, Event::Admitted);
    assert_eq!(later[0].token_before, Some(next));
    assert_eq!(later[1].event, Event::Acknowledged);
    for record in records.iter().chain(&completed).chain(&later) {
        let mut bytes = Vec::new();
        record
            .write_to(&mut bytes)
            .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
        assert!(bytes.len() <= 256);
        assert_eq!(bytes.iter().filter(|&&byte| byte == b'\n').count(), 1);
    }
}

#[test]
fn admission_rejections_report_exact_gate_flags_without_reading_the_token() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true);
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    state.quiescence.hold_hot_fork();

    let held = run(&state, 7);
    assert_eq!(held.len(), 2);
    assert_eq!(held[1].event, Event::HotFork);
    assert_eq!(held[1].token_before, None);
    assert_eq!(held[1].token_after, None);
    assert!(run(&state, 8).is_empty());

    state.quiescence.close();
    assert_eq!(run(&state, 9)[0].event, Event::TeardownAndHotFork);
    state.quiescence.release_hot_fork();
    assert_eq!(run(&state, 10)[0].event, Event::Teardown);
    assert_eq!(slot.control_boundary_token(), request);
    assert_eq!(state.quiescence.snapshot().in_flight, 0);
    assert_eq!(
        state
            .control_callback_witness
            .token_and_events
            .load(Ordering::Relaxed)
            & TOKEN_VALID,
        0
    );
}

#[test]
fn shared_shutdown_rejection_keeps_ack_pending_and_releases_guard() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true);
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    state
        .header
        .get()
        .request_shutdown([])
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));

    let records = run(&state, 7);

    assert_eq!(records.len(), 2);
    assert_eq!(records[1].event, Event::SharedShutdown);
    assert_eq!(records[1].token_before, None);
    assert_eq!(slot.control_boundary_token(), request);
    assert_eq!(state.quiescence.snapshot().in_flight, 0);
}

#[test]
fn callback_error_emits_exit_before_fatal_handler_with_guard_held() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true);
    let request = slot
        .request_control_boundary(0, Some(1))
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    let mut records = Vec::new();
    let mut failed = false;

    state.run_control_callback(
        7,
        |record| records.push(record),
        |_error| {
            failed = true;
            assert_eq!(state.quiescence.snapshot().in_flight, 1);
        },
    );

    assert!(failed);
    assert_eq!(
        records
            .last()
            .unwrap_or_else(|| panic!("error exit should be recorded"))
            .event,
        Event::Error
    );
    assert_eq!(
        records
            .last()
            .unwrap_or_else(|| panic!("error exit should be recorded"))
            .token_after,
        Some(request)
    );
    assert_eq!(state.quiescence.snapshot().in_flight, 0);
}

#[test]
fn failed_diagnostic_writes_leave_callback_outcome_unchanged() {
    struct FailedWriter;

    impl Write for FailedWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("diagnostic sink unavailable"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true);
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test operation should succeed: {error}"));
    state.run_control_callback(
        7,
        |record| {
            assert!(record.write_to(&mut FailedWriter).is_err());
        },
        |error| panic!("unexpected callback failure: {error}"),
    );

    assert_eq!(slot.control_boundary_token(), request + 1);
}
