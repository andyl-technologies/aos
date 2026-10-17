//! Control lease checks against explicitly modeled native claim interleavings.
//!
//! These CAS-minted native writers model the public protocol, not a QEMU phase
//! or callback. The original native implementation remains a separate process.

use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn host(slot: &NodeSlot) -> HostControlBoundaryPublication<'_> {
    slot.try_claim_control_boundary_publication()
        .unwrap_or_else(|error| panic!("host claim refused: {error}"))
        .unwrap_or_else(|| panic!("unexpected modeled native contention"))
}

#[test]
fn modeled_native_claim_preserves_original_busy_and_one_later_commit() {
    let slot = NodeSlot::new(KIND_VM);
    let before = slot.snapshot();
    let fields = Cell::new(None);
    let effects = Cell::new(0);
    slot.control_boundary_publication_claim
        .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|value| panic!("modeled native claim refused: {value}"));

    // Original entry point retains its genuine refusal. New admission observes
    // availability without preparing fields, replacing a request, or waking.
    assert!(matches!(
        slot.request_control_boundary(9, Some(1)),
        Err(NodeSlotError::ControlBoundaryPublicationBusy)
    ));
    assert!(matches!(
        slot.try_claim_control_boundary_publication(),
        Ok(None)
    ));
    assert!(slot.try_snapshot().is_none());
    assert_eq!(slot.control_boundary_token(), before.control_boundary_ack);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 0);
    assert_eq!(slot.control_boundary_capture_request(), None);
    assert_eq!(slot.wake_signal.load(Ordering::Acquire), before.wake_signal);
    assert_eq!(
        slot.control_boundary_publication_claim
            .load(Ordering::Acquire),
        2
    );

    slot.control_boundary_publication_claim
        .compare_exchange(2, 0, Ordering::Release, Ordering::Relaxed)
        .unwrap_or_else(|value| panic!("modeled native release refused: {value}"));
    let lease = host(&slot);
    assert_eq!(lease.try_snapshot(), Some(before));
    assert!(slot.try_snapshot().is_none());
    let request = lease
        .request_with_fields_and_wake(
            9,
            Some(1),
            Some(|request: PreparedControlBoundaryRequest| fields.set(Some(request.get()))),
            |_| effects.set(effects.get() + 1),
            || {
                assert!(slot.try_snapshot().is_some(), "release must precede wake");
                assert_eq!(fields.get(), Some(2));
                assert_eq!(effects.get(), 1);
                slot.wake_after_signal_increment()
            },
        )
        .unwrap_or_else(|error| panic!("original request failed: {error}"));
    assert_eq!(request, 2);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 9);
    assert_eq!(slot.control_boundary_capture_request(), Some(1));

    let repeated_fields = Cell::new(false);
    assert_eq!(
        host(&slot)
            .request_with_prepared_fields(9, Some(1), |_| repeated_fields.set(true), |_| {})
            .unwrap_or_else(|error| panic!("rejoin failed: {error}")),
        request
    );
    assert!(
        !repeated_fields.get(),
        "pending pair must never be replaced"
    );
}

#[test]
fn owned_snapshot_keeps_node_and_advance_stability_guards() {
    let slot = NodeSlot::new(KIND_VM);
    let lease = host(&slot);
    assert!(lease.try_snapshot().is_some());
    slot.publish_gen.store(1, Ordering::Release);
    assert!(lease.try_snapshot().is_none());
    slot.publish_gen.store(2, Ordering::Release);
    slot.advance_publication_sequence
        .store(1, Ordering::Release);
    assert!(lease.try_snapshot().is_none());
    slot.advance_publication_sequence
        .store(2, Ordering::Release);
    assert!(lease.try_snapshot().is_some());
    assert!(slot.try_snapshot().is_none());
    drop(lease);
    assert!(slot.try_snapshot().is_some());
}

#[test]
fn host_and_unknown_claims_are_fatal_and_never_released() {
    for competitor in [1, 7, u32::MAX] {
        let slot = NodeSlot::new(KIND_VM);
        let before = slot.snapshot();
        slot.control_boundary_publication_claim
            .compare_exchange(0, competitor, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|value| panic!("competitor claim refused: {value}"));
        assert!(matches!(
            slot.try_claim_control_boundary_publication(),
            Err(NodeSlotError::ControlBoundaryPublicationBusy)
        ));
        assert_eq!(
            slot.control_boundary_publication_claim
                .load(Ordering::Acquire),
            competitor
        );
        assert_eq!(slot.control_boundary_token(), before.control_boundary_ack);
        assert_eq!(slot.wake_signal.load(Ordering::Acquire), before.wake_signal);
    }
}

#[test]
fn dropped_lease_does_not_clear_an_externally_changed_claim() {
    let slot = NodeSlot::new(KIND_VM);
    let lease = host(&slot);
    slot.control_boundary_publication_claim
        .compare_exchange(1, 7, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|value| panic!("fault injection refused: {value}"));
    assert!(lease.try_snapshot().is_none());
    drop(lease);
    assert_eq!(
        slot.control_boundary_publication_claim
            .load(Ordering::Acquire),
        7
    );
    assert_eq!(slot.control_boundary_token(), 1);
}

#[test]
fn dropped_or_refused_lease_does_not_prepare_paired_fields() {
    let slot = NodeSlot::new(KIND_VM);
    let before = slot.snapshot();
    drop(host(&slot));
    assert_eq!(slot.snapshot(), before);
    let fields = Cell::new(false);
    assert!(matches!(
        host(&slot).request_with_prepared_fields(
            0,
            Some(2),
            |_| fields.set(true),
            |_| panic!("invalid capture retained")
        ),
        Err(NodeSlotError::InvalidControlBoundaryCaptureRequest { request: 2 })
    ));
    assert!(!fields.get());
    assert_eq!(slot.snapshot(), before);

    let request = host(&slot)
        .request_with_effect(3, Some(1), |_| {})
        .unwrap_or_else(|error| panic!("pending request failed: {error}"));
    let pending = slot.snapshot();
    assert!(matches!(
        host(&slot).request_with_prepared_fields(
            4,
            Some(1),
            |_| fields.set(true),
            |_| panic!("mismatched pair retained")
        ),
        Err(NodeSlotError::ControlBoundaryRequestChanged { .. })
    ));
    assert!(!fields.get());
    assert_eq!(slot.snapshot(), pending);
    assert_eq!(slot.control_boundary_token(), request);
}

#[test]
fn preparation_and_retained_panics_release_only_the_host_lease() {
    let slot = NodeSlot::new(KIND_VM);
    let wake = Cell::new(false);
    let preparation = catch_unwind(AssertUnwindSafe(|| {
        host(&slot).request_with_fields_and_wake(
            0,
            None,
            Some(|_: PreparedControlBoundaryRequest| panic!("modeled preparation failure")),
            |_| panic!("request must not retain before publication"),
            || {
                wake.set(true);
                slot.wake_after_signal_increment()
            },
        )
    }));
    assert!(preparation.is_err());
    assert_eq!(slot.control_boundary_token(), 1);
    assert!(slot.try_snapshot().is_some());
    assert!(!wake.get());

    let retained = catch_unwind(AssertUnwindSafe(|| {
        host(&slot).request_with_fields_and_wake(
            0,
            None,
            None::<fn(PreparedControlBoundaryRequest)>,
            |_| panic!("modeled retained failure"),
            || {
                wake.set(true);
                slot.wake_after_signal_increment()
            },
        )
    }));
    assert!(retained.is_err());
    assert_eq!(slot.control_boundary_token(), 2);
    assert!(slot.try_snapshot().is_some());
    assert!(!wake.get());
}
