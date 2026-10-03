//! Original stop-call result, ordering, identity and advisory-budget regressions.

use super::*;
use crate::runtime::live_callbacks::{
    LiveVcpuTimeCallbackError, crucible_qemu_plugin_live_publish_icount_cb, tests::test_live_state,
};
use crucible_shmem::{KIND_VM, NodeSlot, SetupRegionBackingIdentity};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

thread_local! {
    static RECORDS: RefCell<Vec<Notice>> = const { RefCell::new(Vec::new()) };
    static OBSERVE_SLOT: RefCell<Option<Rc<NodeSlot>>> = const { RefCell::new(None) };
    static PAUSED_AT_NATIVE: Cell<Option<(u64, u8)>> = const { Cell::new(None) };
    static PHASE_SNAPSHOTS: RefCell<Vec<(Phase, u64, u8)>> = const { RefCell::new(Vec::new()) };
    static STATUS: Cell<i32> = const { Cell::new(0) };
    static CALLS: Cell<u32> = const { Cell::new(0) };
    static AT_NATIVE_CALL: RefCell<Vec<Phase>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn retain(notice: Notice) {
    OBSERVE_SLOT.with(|slot| {
        if let Some(slot) = slot.borrow().as_ref() {
            let snapshot = slot.snapshot();
            PHASE_SNAPSHOTS.with(|snapshots| {
                snapshots.borrow_mut().push((
                    notice.phase,
                    snapshot.current_icount,
                    snapshot.status,
                ))
            });
        }
    });
    RECORDS.with(|records| records.borrow_mut().push(notice));
}

fn take() -> Vec<Notice> {
    RECORDS.with(|records| std::mem::take(&mut *records.borrow_mut()))
}

extern "C" fn native_stop() -> i32 {
    OBSERVE_SLOT.with(|slot| {
        if let Some(slot) = slot.borrow().as_ref() {
            let snapshot = slot.snapshot();
            PAUSED_AT_NATIVE.set(Some((snapshot.current_icount, snapshot.status)));
        }
    });
    CALLS.set(CALLS.get() + 1);
    RECORDS.with(|records| {
        AT_NATIVE_CALL.with(|phases| {
            *phases.borrow_mut() = records.borrow().iter().map(|record| record.phase).collect();
        });
    });
    STATUS.get()
}

fn live(slot: &NodeSlot, enabled: bool) -> LiveVcpuTimeCallbackState {
    let mut state =
        test_live_state(77, 1, 0, slot).unwrap_or_else(|error| panic!("valid live state: {error}"));
    state.stop_caller_witness = StopCallerWitness::new(enabled);
    state.request_vmstop = native_stop;
    let identity = SetupRegionBackingIdentity::from_parts(1, 27, 4096)
        .unwrap_or_else(|| panic!("nonempty original backing"));
    state.attach_stop_caller_identity(identity, 0, 2)
}

#[test]
fn original_stop_status_and_call_order_remain_exact() {
    for status in [0, -114, -7] {
        take();
        CALLS.set(0);
        STATUS.set(status);
        let slot = NodeSlot::new(KIND_VM);
        let state = live(&slot, true);

        let outcome = state.request_checkpoint_vmstop("block-wait");

        assert_eq!(CALLS.get(), 1);
        AT_NATIVE_CALL.with(|phases| assert_eq!(*phases.borrow(), [Phase::BeforeRequest]));
        if status == -7 {
            assert_eq!(
                outcome,
                Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected {
                    boundary: "block-wait",
                    status,
                })
            );
        } else {
            assert!(outcome.is_ok());
        }
        let records = take();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].phase, Phase::BeforeRequest);
        assert_eq!(records[0].status, None);
        assert_eq!(records[1].phase, Phase::AfterRequest);
        assert_eq!(records[1].status, Some(status));
        assert_eq!(
            records[1].identity.map(|identity| identity.generation),
            Some(2)
        );
    }
    STATUS.set(0);
}

#[test]
fn original_selectable_and_marker_publication_precedes_native_admission() {
    use crate::runtime::live_callbacks::tests::test_force_vcpu_tb_exit;
    for marker in [false, true] {
        take();
        CALLS.set(0);
        STATUS.set(0);
        let slot = Rc::new(NodeSlot::new(KIND_VM));
        OBSERVE_SLOT.with(|observed| *observed.borrow_mut() = Some(Rc::clone(&slot)));
        PHASE_SNAPSHOTS.with(|snapshots| snapshots.borrow_mut().clear());
        let ceiling = crucible_shmem::authorize_advance_ceiling(0, 500, None)
            .unwrap_or_else(|error| panic!("valid ceiling: {error}"));
        slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
            .unwrap_or_else(|error| panic!("publish ceiling: {error}"));
        let state = Box::new(live(&slot, true));
        let handoff = state.selectable_vmstop_handoff();
        let pending = if marker {
            handoff.defer_campaign_marker(test_force_vcpu_tb_exit)
        } else {
            handoff.defer(test_force_vcpu_tb_exit)
        };
        assert_eq!(pending, Ok(true));

        crucible_qemu_plugin_live_publish_icount_cb(
            9,
            std::ptr::from_ref(state.as_ref()).cast_mut().cast(),
        );

        assert_eq!(CALLS.get(), 1);
        assert!(!handoff.is_pending());
        assert_eq!(slot.snapshot().current_icount, 450);
        assert_eq!(
            PAUSED_AT_NATIVE.get(),
            Some((450, crucible_shmem::STATUS_IDLE))
        );
        PHASE_SNAPSHOTS.with(|snapshots| {
            assert_eq!(
                *snapshots.borrow(),
                [
                    (
                        Phase::ClaimedBeforePause,
                        450,
                        crucible_shmem::STATUS_RUNNING
                    ),
                    (Phase::BeforeRequest, 450, crucible_shmem::STATUS_IDLE),
                    (Phase::AfterRequest, 450, crucible_shmem::STATUS_IDLE),
                ]
            )
        });
        OBSERVE_SLOT.with(|observed| *observed.borrow_mut() = None);
        let records = take();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records
                .iter()
                .map(|record| record.phase)
                .collect::<Vec<_>>(),
            [
                Phase::ClaimedBeforePause,
                Phase::BeforeRequest,
                Phase::AfterRequest
            ]
        );
        AT_NATIVE_CALL.with(|phases| {
            assert_eq!(
                *phases.borrow(),
                [Phase::ClaimedBeforePause, Phase::BeforeRequest]
            )
        });
        let caller = if marker {
            "campaign-marker-sim-publication"
        } else {
            "selectable-sim-publication"
        };
        for record in records {
            assert_eq!(CALLER_LABELS[record.caller], caller);
            assert_eq!((record.raw, record.logical), (9, 450));
        }
    }
}

#[test]
fn disabled_and_unknown_callers_do_not_read_the_diagnostic_slot() {
    let witness = StopCallerWitness::new(false);
    assert!(
        witness
            .capture("block-wait", || panic!("disabled must not read slot"))
            .is_none()
    );
    let witness = StopCallerWitness::new(true);
    assert!(
        witness
            .capture("unknown-caller", || panic!("untrusted must not read slot"))
            .is_none()
    );
    take();
    STATUS.set(0);
    CALLS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let state = live(&slot, false);

    assert!(state.request_checkpoint_vmstop("block-wait").is_ok());
    assert_eq!(CALLS.get(), 1);
    assert!(take().is_empty());
}

#[test]
fn captured_return_keeps_original_identity_coordinate_and_token() {
    let slot = NodeSlot::new(KIND_VM);
    let mut state = live(&slot, true);
    let notice = state
        .capture_stop_caller("selectable-sim-publication", Some((7, 350)))
        .unwrap_or_else(|| panic!("enabled original capture"));
    let replacement = SetupRegionBackingIdentity::from_parts(9, 99, 8192)
        .unwrap_or_else(|| panic!("replacement backing"));
    state = state.attach_stop_caller_identity(replacement, 1, 3);
    state.last_raw_icount.store(8, Ordering::Release);
    state.last_icount.store(400, Ordering::Release);
    let next_token = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("new original request: {error}"));
    assert_eq!(next_token, 2);
    take();

    state.notice_stop_after(Some(notice), -114);

    let records = take();
    assert_eq!(records.len(), 1);
    let record = records[0];
    let identity = record
        .identity
        .unwrap_or_else(|| panic!("original identity"));
    assert_eq!(
        (identity.backing.inode(), identity.slot, identity.generation),
        (27, 0, 2)
    );
    assert_eq!(
        (record.raw, record.logical, record.token, record.status),
        (7, 350, 1, Some(-114))
    );
}

#[test]
fn private_binding_rebind_emits_unchanged_epoch_and_preserves_captured_return() {
    take();
    let slot = NodeSlot::new(KIND_VM);
    let mut state = live(&slot, true);
    let original = state
        .capture_stop_caller("block-wait", Some((7, 350)))
        .unwrap_or_else(|| panic!("enabled original capture"));
    state.notice_stop_after(Some(original), -114);
    state.notice_stop_after(Some(original), -114);
    assert_eq!(take().len(), 1);
    let replacement = SetupRegionBackingIdentity::from_parts(9, 99, 8192)
        .unwrap_or_else(|| panic!("validated private backing"));

    state.rebind_stop_caller_identity(replacement, 1, 3);
    let child = state
        .capture_stop_caller("block-wait", Some((7, 350)))
        .unwrap_or_else(|| panic!("enabled child capture"));
    state.notice_stop_after(Some(child), -114);

    let records = take();
    assert_eq!(records.len(), 1);
    let identity = records[0]
        .identity
        .unwrap_or_else(|| panic!("private child identity"));
    assert_eq!(
        (identity.backing, identity.slot, identity.generation),
        (replacement, 1, 3)
    );
    assert_eq!(records[0].process_id, original.process_id);
    assert_eq!(
        (
            records[0].raw,
            records[0].logical,
            records[0].token,
            records[0].status
        ),
        (7, 350, original.token, Some(-114))
    );

    state.notice_stop_after(Some(original), 0);
    let late = take();
    assert_eq!(late.len(), 1);
    let identity = late[0]
        .identity
        .unwrap_or_else(|| panic!("captured original identity"));
    assert_eq!(
        (identity.backing.inode(), identity.slot, identity.generation),
        (27, 0, 2)
    );
    assert_eq!(late[0].status, Some(0));

    let mut disabled = live(&slot, false);
    disabled.rebind_stop_caller_identity(replacement, 1, 3);
    assert!(disabled.stop_caller_witness.identity.is_none());
    assert!(disabled.capture_stop_caller("block-wait", None).is_none());
}

#[test]
fn duplicate_epochs_deduplicate_and_late_epochs_fork_and_status_remain_visible() {
    let witness = StopCallerWitness::new(true);
    let mut notice = witness
        .capture("block-wait", || (7, 350, 2))
        .unwrap_or_else(|| panic!("enabled original capture"));
    notice.phase = Phase::AfterRequest;
    notice.status = Some(0);
    take();
    witness.emit(notice);
    witness.emit(notice);
    assert_eq!(take().len(), 1);

    notice.status = Some(-114);
    witness.emit(notice);
    assert_eq!(take().len(), 1);
    for token in 3..20_000 {
        notice.token = token;
        witness.emit(notice);
        assert_eq!(take().len(), 1);
    }
    witness
        .process_id
        .store(notice.process_id.wrapping_add(1), Ordering::Relaxed);
    witness.emit(notice);
    assert_eq!(take().len(), 1);
}

#[test]
fn maximum_records_are_ascii_bounded_and_sink_errors_are_advisory() {
    let witness = StopCallerWitness::new(true);
    let mut notice = witness
        .capture("campaign-marker-sim-publication", || {
            (u64::MAX, u64::MAX, u32::MAX)
        })
        .unwrap_or_else(|| panic!("enabled capture"));
    notice.identity = Some(Identity {
        backing: SetupRegionBackingIdentity::from_parts(u64::MAX, u64::MAX, u64::MAX)
            .unwrap_or_else(|| panic!("maximal backing")),
        slot: u32::MAX,
        generation: u64::MAX,
    });
    notice.status = Some(i32::MIN);
    notice.phase = Phase::AfterRequest;
    let mut bytes = Vec::new();
    notice
        .write_to(&mut bytes)
        .unwrap_or_else(|error| panic!("bounded record: {error}"));
    assert!(bytes.len() <= 512);
    assert!(bytes.is_ascii());
    assert!(notice.write_to(&mut io::Cursor::new([])).is_err());
}
