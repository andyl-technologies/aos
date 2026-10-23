//! Fallible frame input retains the explicit caller beside a foreign scope.
//!
//! Exact-layout injection applies only to the new fallible buffer reservation.
//! It establishes neither physical memory pressure nor native admission.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_qemu_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};
use std::alloc::Layout;
use std::collections::TryReserveError;
use std::io::Cursor;

fn terminal_frame() -> (RamTransferMessage, Vec<u8>) {
    let message = RamTransferMessage {
        operation: [53; 32],
        control: RamTransferControl::Canceled,
    };
    let bytes = message.encode().unwrap();
    assert_eq!(bytes.len(), 45);
    (message, bytes)
}

#[test]
fn fallible_frame_input_preserves_the_existing_portable_control() {
    let (message, bytes) = terminal_frame();
    let quota = ObservedQuota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original.charge_bytes(8197).unwrap();
    let admitted = quota.used();
    let mut reader = Cursor::new(bytes.as_slice());
    let mut callbacks = 0;

    let response = RamTransferResponse::read_bounded(
        &mut reader,
        &original,
        &mut || {
            callbacks += 1;
            Ok(())
        },
        1024,
        false,
    )
    .unwrap();

    assert_eq!(response.message(), &message);
    assert_eq!(reader.position(), bytes.len() as u64);
    assert_eq!(callbacks, 3);
    assert!(quota.used() > admitted);
    drop(response);
    assert_eq!(quota.used(), admitted);
    drop(original);
    assert_eq!(quota.used(), 0);
}

#[test]
fn frame_allocator_refusal_retains_explicit_original_without_borrowing_foreign_scope() {
    let (_, bytes) = terminal_frame();
    let quota = ObservedQuota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original.charge_bytes(8197).unwrap();
    let admitted = quota.used();
    let foreign_quota = ObservedQuota::new();
    let foreign = DecodeBudget::for_store(foreign_quota.clone()).unwrap();
    foreign.charge_bytes(239).unwrap();
    let foreign_requests = foreign_quota.reservations.load(Ordering::SeqCst);
    let foreign_scope = foreign.enter();
    let mut reader = Cursor::new(bytes.as_slice());
    let mut callbacks = 0;
    let layout = Layout::array::<u8>(bytes.len()).unwrap();

    // The 45-byte, alignment-one extent differs from the prefix's fixed array
    // and aligned loan bookkeeping. Never inject the predecessor's infallible
    // Vec allocation: only this newly fallible reservation is exercised.
    let ((result, counts), reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        TestAllocationObserver::count(|| {
            RamTransferResponse::read_bounded(
                &mut reader,
                &original,
                &mut || {
                    callbacks += 1;
                    Ok(())
                },
                1024,
                false,
            )
        })
    })
    .unwrap();
    assert!(reached);
    let error = result.err().unwrap();
    let RamStoreError::Store(StoreError::Allocation { source, custody }) = &error else {
        panic!("inline allocator refusal with explicit original custody");
    };
    assert!(custody.is_some());
    assert!(
        Error::source(&error)
            .is_some_and(|cause| cause.downcast_ref::<TryReserveError>() == Some(source))
    );
    assert!(!counts.overflow);
    assert_eq!(counts.reallocations, 0);
    assert_eq!(reader.position(), 4, "body input must not start");
    assert_eq!(callbacks, 2);
    assert_eq!(quota.used(), admitted, "temporary frame credit closes");
    assert_eq!(
        foreign_quota.reservations.load(Ordering::SeqCst),
        foreign_requests
    );

    drop(foreign_scope);
    drop(foreign);
    assert_eq!(foreign_quota.used(), 0);
    drop(original);
    assert_eq!(quota.used(), admitted);
    drop(error);
    assert_eq!(quota.used(), 0);
}
