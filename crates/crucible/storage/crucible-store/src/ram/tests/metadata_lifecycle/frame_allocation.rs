//! Fallible frame input retains the explicit caller beside a foreign scope.
//!
//! Exact-layout injection applies only to the new fallible buffer reservation.
//! It establishes neither physical memory pressure nor native admission.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_qemu_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};
use std::alloc::Layout;
use std::collections::TryReserveError;
use std::io::{Cursor, Write};

enum RefusalCut {
    ReadEntry,
    ReadBody,
    WriteEntry,
    WriteFlush,
}

struct RevokeOnFlush<'output> {
    output: Cursor<&'output mut [u8]>,
    original: &'output ObservedQuota,
    flushes: usize,
}

impl Write for RevokeOnFlush<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        self.original.revoked.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn original_refusal_beside_foreign_scope(cut: RefusalCut) {
    let (message, bytes) = terminal_frame();
    let quota = ObservedQuota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original.charge_bytes(8197).unwrap();
    let admitted = quota.used();
    let foreign_quota = ObservedQuota::new();
    let foreign = DecodeBudget::for_store(foreign_quota.clone()).unwrap();
    foreign.charge_bytes(239).unwrap();
    let foreign_requests = foreign_quota.reservations.load(Ordering::SeqCst);
    let foreign_scope = foreign.enter();
    let mut callbacks = 0;

    let error = match cut {
        RefusalCut::ReadEntry | RefusalCut::ReadBody => {
            let entry = matches!(cut, RefusalCut::ReadEntry);
            if entry {
                quota.revoked.store(true, Ordering::SeqCst);
            }
            let mut reader = Cursor::new(bytes.as_slice());
            let error = RamTransferResponse::read_bounded(
                &mut reader,
                &original,
                &mut || {
                    callbacks += 1;
                    if callbacks == 2 {
                        quota.revoked.store(true, Ordering::SeqCst);
                    }
                    Ok(())
                },
                1024,
                false,
            )
            .err()
            .unwrap();
            assert_eq!(reader.position(), if entry { 0 } else { 4 });
            assert_eq!(callbacks, if entry { 0 } else { 2 });
            error
        }
        RefusalCut::WriteEntry | RefusalCut::WriteFlush => {
            let entry = matches!(cut, RefusalCut::WriteEntry);
            if entry {
                quota.revoked.store(true, Ordering::SeqCst);
            }
            let response = RamTransferResponse::inline(message);
            let mut output = [0; 45];
            let mut writer = RevokeOnFlush {
                output: Cursor::new(output.as_mut_slice()),
                original: &quota,
                flushes: 0,
            };
            let error = response
                .write(&mut writer, &original, &mut || {
                    callbacks += 1;
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(writer.output.position(), if entry { 0 } else { 45 });
            assert_eq!(writer.flushes, usize::from(!entry));
            assert_eq!(callbacks, if entry { 0 } else { 2 });
            if !entry {
                assert_eq!(output.as_slice(), bytes.as_slice());
            }
            error
        }
    };
    let mut source = Some(&error as &(dyn Error + 'static));
    let mut actual_revocation = false;
    while let Some(cause) = source {
        if cause.is::<RevokedOriginalAuthority>() {
            actual_revocation = true;
            break;
        }
        source = cause.source();
    }
    assert!(actual_revocation);
    assert_eq!(
        foreign_quota.reservations.load(Ordering::SeqCst),
        foreign_requests
    );

    drop(foreign_scope);
    drop(foreign);
    let retained_foreign = foreign_quota.used();
    drop(original);
    let retained_original = quota.used();
    drop(error);
    assert_eq!((quota.used(), foreign_quota.used()), (0, 0));
    assert_eq!(
        (retained_original, retained_foreign),
        (admitted, 0),
        "the actual failed caller owns the diagnostic; an ambient account cannot be borrowed"
    );
}

#[test]
fn frame_read_entry_refusal_retains_explicit_original_and_releases_foreign_scope() {
    original_refusal_beside_foreign_scope(RefusalCut::ReadEntry);
}

#[test]
fn frame_read_body_admission_refusal_retains_explicit_original_and_releases_foreign_scope() {
    original_refusal_beside_foreign_scope(RefusalCut::ReadBody);
}

#[test]
fn frame_write_entry_refusal_retains_explicit_original_and_releases_foreign_scope() {
    original_refusal_beside_foreign_scope(RefusalCut::WriteEntry);
}

#[test]
fn frame_flush_refusal_retains_explicit_original_and_releases_foreign_scope() {
    original_refusal_beside_foreign_scope(RefusalCut::WriteFlush);
}

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
