//! Stage order and bounds through the original admitted control callback.

use super::super::{ControlCallbackWitness, tests::test_live_state};
use super::*;
use crucible_shmem::{AdvanceStopCondition, KIND_VM, NodeSlot, authorize_advance_ceiling};
use std::cell::{Cell, RefCell};
use std::sync::Arc;

thread_local! {
    static STOP_STATUS: Cell<i32> = const { Cell::new(0) };
    static ORDER: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    static RAW_QUERIES: Cell<u32> = const { Cell::new(0) };
}

extern "C" fn original_stop_provider() -> i32 {
    ORDER.with_borrow_mut(|order| order.push("native-stop"));
    STOP_STATUS.get()
}

extern "C" fn original_raw_provider() -> u64 {
    RAW_QUERIES.set(RAW_QUERIES.get() + 1);
    7
}

fn state(slot: &NodeSlot, enabled: bool, minimum: Option<&str>) -> LiveVcpuTimeCallbackState {
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, 1_000, None)
            .unwrap_or_else(|error| panic!("test ceiling should validate: {error}")),
        AdvanceStopCondition::Ceiling,
    )
    .unwrap_or_else(|error| panic!("test advance should publish: {error}"));
    let mut state = test_live_state(194, 1, 0, slot)
        .unwrap_or_else(|error| panic!("test callback state should construct: {error}"));
    let mut witness = ControlCallbackWitness::new(enabled);
    witness.stages = ControlCallbackStages::from_setting(minimum.map(OsStr::new));
    state.control_callback_witness = Arc::new(witness);
    state.request_vmstop = original_stop_provider;
    state.icount_raw = original_raw_provider;
    let backing = crucible_shmem::SetupRegionBackingIdentity::from_parts(1, 8, 4_096)
        .unwrap_or_else(|| panic!("nonempty backing identity should validate"));
    state.attach_control_stage_identity(backing, 0, 2)
}

fn request(slot: &NodeSlot) -> u32 {
    slot.request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("test control request should publish: {error}"))
}

fn run(state: &LiveVcpuTimeCallbackState) -> (Vec<StageRecord>, Option<String>) {
    let mut stages = Vec::new();
    let mut error = None;
    state.run_control_callback_with_stages(
        7,
        |_| {},
        |record| {
            ORDER.with_borrow_mut(|order| order.push(record.phase.label()));
            stages.push(record);
        },
        |source| error = Some(source.to_string()),
    );
    (stages, error)
}

#[test]
fn setting_filter_disabled_and_no_request_paths_preserve_original_ack() {
    for value in [
        None,
        Some(""),
        Some("+2"),
        Some("02"),
        Some("2 "),
        Some("4294967296"),
    ] {
        assert!(
            ControlCallbackStages::from_setting(value.map(OsStr::new))
                .minimum_token
                .is_none()
        );
    }
    for (enabled, minimum) in [(false, Some("0")), (true, None), (true, Some("4"))] {
        let slot = NodeSlot::new(KIND_VM);
        let state = state(&slot, enabled, minimum);
        let token = request(&slot);
        RAW_QUERIES.set(0);

        let (stages, error) = run(&state);

        assert!(stages.is_empty());
        assert!(error.is_none());
        assert_eq!(slot.control_boundary_token(), token + 1);
        assert_eq!(RAW_QUERIES.get(), 0);
        assert_eq!(
            state
                .control_callback_witness
                .stages
                .token_and_phases
                .load(Ordering::Relaxed),
            0
        );
    }
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true, Some("0"));
    let (stages, error) = run(&state);
    assert!(stages.is_empty());
    assert!(error.is_none());
    assert_eq!(slot.control_boundary_token(), 1);
}

#[test]
fn actual_pause_stage_records_enclose_original_sdk_and_bind_admitted_identity() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true, Some("2"));
    state
        .header
        .get()
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("original pause should publish: {error}"));
    let token = request(&slot);
    STOP_STATUS.set(0);
    ORDER.with_borrow_mut(Vec::clear);

    let (stages, error) = run(&state);

    assert!(error.is_none());
    assert_eq!(slot.control_boundary_token(), token + 1);
    assert_eq!(
        ORDER.with_borrow(Clone::clone),
        [
            "settle-enter",
            "settle-return",
            "pause-enter",
            "native-stop",
            "pause-return"
        ]
    );
    assert_eq!(
        stages
            .iter()
            .map(|record| record.result)
            .collect::<Vec<_>>(),
        [
            StageResult::Unavailable,
            StageResult::True,
            StageResult::Unavailable,
            StageResult::True
        ]
    );
    for record in stages {
        assert_eq!(record.invocation.callback, 1);
        assert_eq!(record.invocation.pid, std::process::id());
        assert_eq!(record.invocation.token, token);
        assert_eq!(record.invocation.raw, 7);
        assert_eq!(record.invocation.identity, state.control_stage_identity);
    }
}

#[test]
fn actual_native_error_is_unchanged_and_diagnostic_sink_failure_is_nonfatal() {
    let mut outcomes = Vec::new();
    for enabled in [false, true] {
        let slot = NodeSlot::new(KIND_VM);
        let state = state(&slot, enabled, Some("0"));
        state
            .header
            .get()
            .request_pause([&slot])
            .unwrap_or_else(|error| panic!("original pause should publish: {error}"));
        let token = request(&slot);
        STOP_STATUS.set(-17);
        ORDER.with_borrow_mut(Vec::clear);
        let mut stages = Vec::new();
        let mut error = None;

        state.run_control_callback_with_stages(
            7,
            |_| {},
            |record| {
                let _diagnostic_write = record.write_to(&mut BrokenSink);
                stages.push(record);
            },
            |source| error = Some(source.to_string()),
        );

        assert_eq!(slot.control_boundary_token(), token);
        assert_eq!(ORDER.with_borrow(Clone::clone), ["native-stop"]);
        if enabled {
            assert_eq!(stages.len(), 4);
            assert_eq!(stages[3].result, StageResult::Error);
        } else {
            assert!(stages.is_empty());
        }
        outcomes.push((error, slot.snapshot()));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    STOP_STATUS.set(0);
}

struct BrokenSink;

impl Write for BrokenSink {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "closed diagnostic sink",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn genuine_pending_repoll_is_deduplicated_without_hiding_later_request_epochs() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true, Some("10400"));
    // Advance using the real request and admitted callback, not fabricated counters.
    while request(&slot) < 10400 {
        assert!(run(&state).0.is_empty());
    }
    state
        .fault_command_pump_active
        .store(true, Ordering::Release);

    let (pending, error) = run(&state);
    assert!(error.is_none());
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[1].result, StageResult::False);
    assert_eq!(slot.control_boundary_token(), 10400);
    for _attempt in 0..100 {
        assert!(run(&state).0.is_empty());
    }
    state
        .fault_command_pump_active
        .store(false, Ordering::Release);
    let completed = run(&state).0;
    assert_eq!(completed.len(), 2);
    assert_eq!(completed[0].phase, StagePhase::PauseEnter);
    assert_eq!(completed[1].result, StageResult::False);
    assert_eq!(slot.control_boundary_token(), 10401);
    assert_ne!(
        pending[0].invocation.callback,
        completed[0].invocation.callback
    );

    let next = request(&slot);
    let later = run(&state).0;
    assert_eq!(later.len(), 4);
    assert_eq!(later[0].invocation.token, next);
    assert_eq!(slot.control_boundary_token(), next + 1);
}

#[test]
fn rejected_guard_does_not_observe_stages_or_mapping() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true, Some("0"));
    let token = request(&slot);
    state.quiescence.hold_hot_fork();
    let before = slot.snapshot();

    let (stages, error) = run(&state);

    assert!(stages.is_empty());
    assert!(error.is_none());
    assert_eq!(slot.snapshot(), before);
    assert_eq!(slot.control_boundary_token(), token);
}

#[test]
fn rows_fit_the_bound_at_maximum_width_and_mapping_unavailability_is_explicit() {
    let witness = ControlCallbackStages::from_setting(Some(OsStr::new("0")));
    let backing =
        crucible_shmem::SetupRegionBackingIdentity::from_parts(u64::MAX, u64::MAX, u64::MAX)
            .unwrap_or_else(|| panic!("maximum identity should validate"));
    for identity in [
        Some(ControlStageIdentity {
            backing,
            slot: u32::MAX,
            generation: u64::MAX,
        }),
        None,
    ] {
        witness.reset();
        let invocation = StageInvocation {
            pid: u32::MAX,
            callback: u64::MAX,
            token: u32::MAX - 1,
            raw: u64::MAX,
            identity,
        };
        for phase in [
            StagePhase::SettleEnter,
            StagePhase::SettleReturn,
            StagePhase::PauseEnter,
            StagePhase::PauseReturn,
        ] {
            let result = if matches!(phase, StagePhase::SettleEnter | StagePhase::PauseEnter) {
                StageResult::Unavailable
            } else {
                StageResult::Error
            };
            let record = witness
                .record(invocation, phase, result)
                .unwrap_or_else(|| panic!("first phase should be retained"));
            let mut bytes = Vec::new();
            record
                .write_to(&mut bytes)
                .unwrap_or_else(|error| panic!("bounded row should serialize: {error}"));
            assert!(bytes.len() <= 256);
            assert_eq!(bytes.iter().filter(|&&byte| byte == b'\n').count(), 1);
            if identity.is_none() {
                assert!(
                    String::from_utf8_lossy(&bytes).contains(
                        "dev=unavailable ino=unavailable slot=unavailable gen=unavailable"
                    )
                );
            }
            assert!(witness.record(invocation, phase, result).is_none());
        }
    }
}

#[test]
fn held_child_identity_rebind_resets_only_stage_metadata_and_phase_budget() {
    for enabled in [false, true] {
        let slot = NodeSlot::new(KIND_VM);
        let mut state = state(&slot, enabled, Some("0"));
        let token = request(&slot);
        state
            .fault_command_pump_active
            .store(true, Ordering::Release);
        let (before, error) = run(&state);
        assert!(error.is_none());
        let original = slot.snapshot();
        let child = crucible_shmem::SetupRegionBackingIdentity::from_parts(3, 10, 4_096)
            .unwrap_or_else(|| panic!("child backing should validate"));

        state.quiescence.hold_hot_fork();
        state.rebind_control_stage_identity(child, 1, 3);
        assert!(run(&state).0.is_empty());
        assert_eq!(slot.snapshot(), original);
        state.quiescence.release_hot_fork();
        let (after, error) = run(&state);

        assert!(error.is_none());
        assert_eq!(slot.snapshot(), original);
        assert_eq!(slot.control_boundary_token(), token);
        if enabled {
            assert_eq!(before.len(), 2);
            assert_eq!(after.len(), 2);
            assert_ne!(before[0].invocation.identity, after[0].invocation.identity);
            let identity = after[0]
                .invocation
                .identity
                .unwrap_or_else(|| panic!("child identity should be retained"));
            assert_eq!(identity.backing, child);
            assert_eq!(identity.slot, 1);
            assert_eq!(identity.generation, 3);
        } else {
            assert!(before.is_empty());
            assert!(after.is_empty());
            assert!(state.control_stage_identity.is_none());
        }
    }
}

#[test]
fn original_pid_epoch_reset_restores_late_stage_evidence_without_new_control_reads() {
    let slot = NodeSlot::new(KIND_VM);
    let state = state(&slot, true, Some("0"));
    request(&slot);
    state
        .fault_command_pump_active
        .store(true, Ordering::Release);
    let (first, _) = run(&state);
    assert_eq!(first.len(), 2);
    assert!(run(&state).0.is_empty());
    state
        .control_callback_witness
        .process_id
        .store(std::process::id().wrapping_add(1), Ordering::Relaxed);
    let before = slot.snapshot();
    RAW_QUERIES.set(0);

    let (fresh, error) = run(&state);

    assert!(error.is_none());
    assert_eq!(fresh.len(), 2);
    assert_eq!(fresh[0].invocation.pid, std::process::id());
    assert_eq!(fresh[0].invocation.callback, 1);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(RAW_QUERIES.get(), 0);
}
