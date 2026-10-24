//! Exercises real observation, writer and inbox publication transitions.

use super::*;

fn ceiling() -> AdvanceCeiling {
    authorize_advance_ceiling(0, 12, None).unwrap()
}

#[test]
fn actual_observation_preserves_snapshot_through_commit_and_separate_wake() {
    let slot = NodeSlot::new(KIND_VM);
    let foreign = NodeSlot::new(KIND_VM);
    let initial = slot.snapshot();
    let observation = slot.observe_scheduler_advance().unwrap();
    assert_eq!(observation.snapshot(), initial);

    let prepared = observation.reserve().unwrap();
    assert_eq!(prepared.snapshot(), initial);
    assert_eq!(prepared.generation(), 2);
    assert!(prepared.belongs_to(&slot));
    assert!(!prepared.belongs_to(&foreign));
    let committed = prepared
        .commit(ceiling(), AdvanceStopCondition::Ceiling)
        .unwrap();

    let before_wake = slot.snapshot();
    assert_eq!(before_wake.max_advance_icount, 12);
    assert_eq!(before_wake.advance_publication_sequence, 2);
    assert_eq!(before_wake.wake_signal, initial.wake_signal);
    committed.wake().unwrap();
    assert_eq!(slot.snapshot().wake_signal, initial.wake_signal + 1);
}

#[test]
fn replaced_scheduler_generation_cannot_be_reserved_from_an_old_observation() {
    let slot = NodeSlot::new(KIND_VM);
    let observation = slot.observe_scheduler_advance().unwrap();
    slot.publish_scheduler_advance(ceiling(), AdvanceStopCondition::NextAuthenticatedIdle)
        .unwrap();
    let replacement = slot.snapshot();

    let error = observation.reserve().err().unwrap();

    assert_eq!(
        error,
        NodeSlotError::AdvancePublicationOccupied {
            expected: 0,
            observed: 2
        }
    );
    assert_eq!(slot.snapshot(), replacement);
}

#[test]
fn changed_actual_report_refuses_before_writer_birth() {
    let slot = NodeSlot::new(KIND_VM);
    let observation = slot.observe_scheduler_advance().unwrap();
    slot.mark_device_io_active();
    let changed = slot.snapshot();

    let error = observation.reserve().err().unwrap();

    assert_eq!(
        error,
        NodeSlotError::NodeReportChanged {
            expected: 0,
            observed: 2
        }
    );
    assert_eq!(slot.snapshot(), changed);
    assert_eq!(changed.advance_publication_sequence, 0);
}

#[test]
fn changed_actual_report_after_reservation_cannot_commit_or_wake() {
    let slot = NodeSlot::new(KIND_VM);
    let prepared = slot.observe_scheduler_advance().unwrap().reserve().unwrap();
    slot.mark_device_io_active();

    let error = prepared
        .commit(ceiling(), AdvanceStopCondition::Ceiling)
        .err()
        .unwrap();

    assert_eq!(
        error,
        NodeSlotError::NodeReportChanged {
            expected: 0,
            observed: 2
        }
    );
    let after = slot.snapshot();
    assert_eq!(after.advance_publication_sequence, 2);
    assert_eq!(after.max_advance_icount, 0);
    assert_eq!(after.wake_signal, 0);
    assert_eq!(after.device_io_active, 1);
}

#[test]
fn prepared_inbox_rejects_bad_sources_and_full_capacity_before_effects() {
    for full in [false, true] {
        let slot = NodeSlot::new(KIND_VM);
        let inbox = RingHeader::new();
        let mut entries = core::array::from_fn::<_, 2, _>(|_| FrameEntry::default());
        let input = FrameEntry::new(12, SLOT_NET_ROUTER as u32, 1, b"net").unwrap();
        if full {
            inbox.enqueue(&mut entries, &input).unwrap();
            inbox.enqueue(&mut entries, &input).unwrap();
        }
        let before = (inbox.read_index(), inbox.write_index());
        let prepared = slot.observe_scheduler_advance().unwrap().reserve().unwrap();

        let result = prepared.publish_inbox_and_advance(
            0,
            if full { SLOT_NET_ROUTER as u32 } else { 0 },
            &inbox,
            &mut entries,
            std::slice::from_ref(&input),
            ceiling(),
            AdvanceStopCondition::Ceiling,
        );

        assert!(result.is_err());
        assert_eq!((inbox.read_index(), inbox.write_index()), before);
        let after = slot.snapshot();
        assert_eq!(after.advance_publication_sequence, 2);
        assert_eq!(after.max_advance_icount, 0);
        assert_eq!(after.wake_signal, 0);
    }
}

#[test]
fn prepared_inbox_publishes_real_frame_before_tuple_and_once_wake() {
    let slot = NodeSlot::new(KIND_VM);
    let inbox = RingHeader::new();
    let mut entries = core::array::from_fn::<_, 2, _>(|_| FrameEntry::default());
    let input = FrameEntry::new(12, SLOT_NET_ROUTER as u32, 1, b"net").unwrap();
    let prepared = slot.observe_scheduler_advance().unwrap().reserve().unwrap();

    let published = prepared
        .publish_inbox_and_advance(
            0,
            SLOT_NET_ROUTER as u32,
            &inbox,
            &mut entries,
            std::slice::from_ref(&input),
            ceiling(),
            AdvanceStopCondition::NextAuthenticatedIdle,
        )
        .unwrap();

    assert_eq!(published.pending_input_count, 1);
    assert_eq!(inbox.write_index(), 1);
    assert_eq!(entries[0], input);
    let after = slot.snapshot();
    assert_eq!(after.max_advance_icount, 12);
    assert_eq!(after.advance_publication_sequence, 2);
    assert_eq!(
        after.advance_stop_condition,
        ADVANCE_STOP_CONDITION_NEXT_AUTHENTICATED_IDLE
    );
    assert_eq!(after.wake_signal, 1);
}
