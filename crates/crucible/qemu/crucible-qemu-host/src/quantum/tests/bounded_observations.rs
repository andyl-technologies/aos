//! Exercises bounded observations against the actual held scheduler writer.
//!
//! These component checks issue no Native membership or physical-return receipt.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;

#[test]
fn held_writer_refuses_channel_observers_without_allocating_or_mutating() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);

    for reader in 0..5 {
        // Each mapped channel call uses a fresh temporary adapter. Reusing one
        // would also exercise the separately allocated multi-event log spill.
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );
        let before = slot.snapshot();
        let reservation = slot.reserve_scheduler_advance().unwrap();
        let occupied = reservation.generation() - 1;

        let (error, counts) = TestAllocationObserver::count(|| match reader {
            0 => QemuShmemHotPathChannel::current_icount(&mut hot_path).unwrap_err(),
            1 => QemuShmemHotPathChannel::logical_time_calibration(&mut hot_path).unwrap_err(),
            2 => QemuShmemHotPathChannel::virtual_timer_fire_witness(&mut hot_path).unwrap_err(),
            3 => QemuShmemHotPathChannel::idle_state(&mut hot_path).unwrap_err(),
            4 => QemuShmemHotPathChannel::execution_fingerprint(&mut hot_path).unwrap_err(),
            _ => unreachable!(),
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(error.is_retryable());
        assert!(error.message.is_empty());
        assert_eq!(
            error.quantum_node_slot_source(),
            Some(&NodeSlotError::AdvancePublicationOccupied {
                expected: occupied,
                observed: occupied
            })
        );
        let source = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<NodeSlotError>());
        assert_eq!(source, error.quantum_node_slot_source());
        assert_eq!(
            hot_path.operation_log(),
            &[QemuQuantumOperation::ReadNodeReport]
        );
        assert_eq!(inbound_ring.read_index(), 0);
        assert_eq!(outbound_ring.read_index(), 0);

        drop(reservation);
        let after = slot.snapshot();
        assert_eq!(after.advance_publication_sequence, occupied + 1);
        assert_eq!(after.max_advance_icount, before.max_advance_icount);
        assert_eq!(after.wake_signal, before.wake_signal);
    }
}

#[test]
fn completion_refusal_retains_same_pending_without_republication_or_allocation() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    let mut pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        horizon(10),
        crate::QemuQuantumStopCondition::Ceiling,
    )
    .unwrap();
    let before = slot.snapshot();
    let reservation = slot.reserve_scheduler_advance().unwrap();
    let operation_count = hot_path.operation_log().len();

    let (error, counts) = TestAllocationObserver::count(|| {
        QemuShmemHotPathChannel::poll_quantum(&mut hot_path, &mut pending).unwrap_err()
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(error.is_retryable());
    assert_eq!(
        error.quantum_node_slot_source(),
        Some(&NodeSlotError::AdvancePublicationOccupied {
            expected: 3,
            observed: 3
        })
    );
    assert_eq!(
        &hot_path.operation_log()[operation_count..],
        &[QemuQuantumOperation::ObservePluginReport]
    );
    assert_eq!(inbound_ring.read_index(), 0);
    assert_eq!(outbound_ring.read_index(), 0);

    drop(reservation);
    assert_eq!(slot.snapshot().wake_signal, before.wake_signal);
    slot.publish_reached_icount(10).unwrap();
    let report = QemuShmemHotPathChannel::poll_quantum(&mut hot_path, &mut pending).unwrap();
    assert_eq!(report.outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(slot.snapshot().wake_signal, before.wake_signal);
}

#[test]
fn actual_terminal_slot_failure_keeps_diagnostic_and_cannot_request_retry() {
    let slot = NodeSlot::default();
    let source = slot.publish_reached_icount(1).unwrap_err();
    let expected = format!(
        "qemu_quantum_shmem_hot_path failed: QEMU quantum node-slot operation actual plugin report failed: {source}"
    );

    let (error, counts) = TestAllocationObserver::count(|| {
        QemuNodeChannelError::from(QemuQuantumError::NodeSlot {
            operation: "actual plugin report",
            source: source.clone(),
        })
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(!error.is_retryable());
    assert_eq!(error.quantum_node_slot_source(), Some(&source));
    assert_eq!(error.to_string(), expected);

    let (node, counts) = TestAllocationObserver::count(|| {
        crate::QemuNodeError::from_channel(crate::QemuNodeChannelPlane::ShmemHotPath, error)
    });
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(
        std::error::Error::source(&node).and_then(|source| source.downcast_ref::<NodeSlotError>()),
        Some(&source)
    );
}
