//! Real advance-writer ordering with an explicitly substituted wake-error provider.
//!
//! The negative control exercises the original state/effect body and Result
//! path, not an actual kernel futex failure or native phase owner.

use super::*;
use crate::native_console::NativeConsoleAuthorizationTable;
use crucible_protocol::native_console::{
    NativeConsoleAuthorization, NativeConsoleOwner, NativeConsolePhase,
};
use std::cell::Cell;

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Slot(#[from] NodeSlotError),
    #[error(transparent)]
    Shape(#[from] crucible_protocol::native_console::NativeConsoleError),
    #[error(transparent)]
    Lookahead(#[from] LookaheadGateError),
    #[error("slot publication is unavailable")]
    SnapshotUnavailable,
}

fn authorization() -> NativeConsoleAuthorization {
    NativeConsoleAuthorization {
        publication: 2,
        owner: NativeConsoleOwner {
            slot: 0,
            region: [4; 16],
            process: 8,
            authorization: 10,
        },
        logical_generation: 3,
        advance: 0,
        prior_sequence: 0,
        prior_ring_end: 0,
        allowance: 2,
        phase_token: 5,
        phase: NativeConsolePhase::Grant,
    }
}

#[test]
fn original_effect_commits_auth_while_advance_is_odd_before_even_release_and_wake()
-> Result<(), FixtureError> {
    let slot = NodeSlot::new(KIND_VM);
    let table = NativeConsoleAuthorizationTable::default();
    let prepared = table.prepare_for_advance(authorization())?;
    let retained = Cell::new(None);

    slot.publish_scheduler_advance_with_effect(
        authorize_advance_ceiling(0, 100, None)?,
        AdvanceStopCondition::Ceiling,
        |advance| {
            assert_eq!(slot.advance_publication_sequence.load(Ordering::Acquire), 1);
            assert_eq!(slot.max_advance_icount.load(Ordering::Acquire), 100);
            assert_eq!(slot.wake_signal.load(Ordering::Acquire), 0);
            assert!(slot.try_snapshot().is_none());
            retained.set(Some(prepared.commit_for_advance(advance)));
        },
    )?;

    let body = table.snapshot()?;
    assert_eq!(retained.get(), Some(body));
    assert_eq!(body.advance, 2);
    assert_eq!(slot.snapshot().advance_publication_sequence, body.advance);
    assert_eq!(slot.snapshot().wake_signal, 1);
    Ok(())
}

#[test]
fn substituted_wake_failure_keeps_original_committed_auth_and_custody() -> Result<(), FixtureError>
{
    let slot = NodeSlot::new(KIND_VM);
    let table = NativeConsoleAuthorizationTable::default();
    let prepared = table.prepare_for_advance(authorization())?;
    let retained = Cell::new(None);
    let source = FutexError::Syscall {
        operation: "modeled wake refusal",
        errno: 22,
    };

    let result = slot.publish_scheduler_advance_with_test_wake(
        authorize_advance_ceiling(0, 100, None)?,
        |advance| retained.set(Some(prepared.commit_for_advance(advance))),
        || {
            // The actual original writer has already closed and retained the
            // receipt. Only this syscall result is an external provider.
            assert_eq!(slot.snapshot().advance_publication_sequence, 2);
            assert!(retained.get().is_some());
            Err(source.clone())
        },
    );

    assert!(
        matches!(result, Err(NodeSlotError::FutexWake { source: observed }) if observed == source)
    );
    assert_eq!(retained.get(), Some(table.snapshot()?));
    assert_eq!(slot.snapshot().max_advance_icount, 100);
    assert_eq!(slot.snapshot().advance_publication_sequence, 2);
    Ok(())
}

#[test]
fn effect_unwind_closes_the_original_writer_without_claiming_a_completed_wake()
-> Result<(), FixtureError> {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 100, None)?;
    let result = std::panic::catch_unwind(|| {
        slot.publish_scheduler_advance_with_effect(ceiling, AdvanceStopCondition::Ceiling, |_| {
            panic!("invalid local effect")
        })
    });

    assert!(result.is_err());
    let snapshot = slot
        .try_snapshot()
        .ok_or(FixtureError::SnapshotUnavailable)?;
    assert_eq!(snapshot.advance_publication_sequence, 2);
    assert_eq!(snapshot.max_advance_icount, 100);
    assert_eq!(snapshot.wake_signal, 0);
    Ok(())
}

#[test]
fn completed_pair_and_local_custody_are_visible_at_the_original_wake() -> Result<(), FixtureError> {
    use crate::native_console::NativeConsoleClampTable;
    use crucible_protocol::native_console::NativeConsoleClamp;

    for refuse_wake in [false, true] {
        let slot = NodeSlot::new(KIND_VM);
        let table = NativeConsoleClampTable::default();
        let prepared = table.prepare(NativeConsoleClamp {
            publication: 2,
            advance: 0,
            request: 0,
            capture: 3,
            fault_frontier: 7,
            ceiling: 0,
            stop: ADVANCE_STOP_CONDITION_CEILING,
            kind: crucible_protocol::native_console::NativeConsoleControlKind::Observation,
            last_issued: None,
        })?;
        let retained = Cell::new(None);
        let read_at_wake = Cell::new(false);
        let source = FutexError::Syscall {
            operation: "modeled request wake refusal",
            errno: 22,
        };

        let result = slot.request_control_boundary_with_fields_and_wake(
            7,
            Some(3),
            Some(|request| prepared.commit_before_request(request)),
            |request| retained.set(Some(request)),
            || {
                // This is the original wake callback interval. Only the error
                // in the negative case is supplied by an external provider.
                let snapshot = slot
                    .try_snapshot()
                    .unwrap_or_else(|| panic!("claim must close before notifying a consumer"));
                let paired = table
                    .snapshot()
                    .unwrap_or_else(|error| panic!("wake must observe the complete pair: {error}"));
                assert_eq!(snapshot.control_boundary_ack, paired.request);
                assert_eq!(paired.request, 2);
                assert_eq!(
                    snapshot.control_boundary_fault_command_frontier,
                    paired.fault_frontier
                );
                assert_eq!(snapshot.control_boundary_capture_request, paired.capture);
                assert_eq!(retained.get(), Some(2));
                read_at_wake.set(true);
                if refuse_wake {
                    Err(source.clone())
                } else {
                    slot.wake_after_signal_increment()
                }
            },
        );

        assert!(read_at_wake.get());
        if refuse_wake {
            assert!(
                matches!(result, Err(NodeSlotError::FutexWake { source: observed }) if observed == source)
            );
        } else {
            assert_eq!(result?, 2);
        }
        assert_eq!(retained.get(), Some(2));
        assert!(slot.try_snapshot().is_some());
        assert_eq!(slot.request_control_boundary(7, Some(3))?, 2);
        assert_eq!(table.snapshot()?.request, 2);
    }
    Ok(())
}

#[test]
fn completed_request_interval_refuses_an_old_ack_beside_new_pair_fields() -> Result<(), FixtureError>
{
    let slot = NodeSlot::new(KIND_VM);
    let original = slot
        .try_snapshot()
        .ok_or(FixtureError::SnapshotUnavailable)?;

    // Pause a reader after its initial claim/ACK loads, then run the actual
    // host publisher through a complete claim interval before its final check.
    assert_eq!(slot.request_control_boundary(7, Some(3))?, 2);
    assert_eq!(slot.acknowledge_control_boundary(), 3);
    assert_eq!(slot.request_control_boundary(11, Some(5))?, 4);
    let current = slot
        .try_snapshot()
        .ok_or(FixtureError::SnapshotUnavailable)?;
    assert_eq!(current.publish_gen, original.publish_gen);
    assert_eq!(
        current.advance_publication_sequence,
        original.advance_publication_sequence
    );
    assert_eq!(
        slot.control_boundary_publication_claim
            .load(Ordering::Acquire),
        0
    );

    let interrupted_read = NodeSlotSnapshot {
        control_boundary_ack: original.control_boundary_ack,
        ..current
    };
    assert_eq!(interrupted_read.control_boundary_fault_command_frontier, 11);
    assert_eq!(interrupted_read.control_boundary_capture_request, 5);
    assert_eq!(slot.finish_snapshot_read(interrupted_read), None);
    assert_eq!(slot.finish_snapshot_read(original), None);
    assert_eq!(slot.finish_snapshot_read(current), Some(current));
    Ok(())
}
