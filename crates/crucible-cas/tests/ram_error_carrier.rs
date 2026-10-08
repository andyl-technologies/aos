//! Causal allocation-close evidence for the shared RAM failure carrier.
//!
//! The shared observer captures the exact original carrier layout and publishes
//! its original close flag after physical deallocation. Payload destruction and
//! original loan release follow that publication, including sixteen concurrent
//! final owners and actual payload unwind.

use std::alloc::Layout;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_cas::content_store::StoreError;
use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use crucible_cas::ram::{PreparedRamFailure, RamStoreError};

use crucible_linux_resource::test_support::{CloseMarkerOutcome, TestAllocationObserver};

static BODY_CLOSED: AtomicBool = AtomicBool::new(false);
static PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);
static LOAN_DROPS: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Loan {
    watched: bool,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.watched {
            assert!(
                BODY_CLOSED.load(Ordering::SeqCst),
                "loan refunded before shared allocation close"
            );
            assert_eq!(PAYLOAD_DROPS.load(Ordering::SeqCst), 1);
            LOAN_DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct Authority {
    watch_next: AtomicBool,
    reservations: AtomicUsize,
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        Ok(())
    }

    fn reserve(
        &self,
        _bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.reservations.fetch_add(1, Ordering::SeqCst);
        Ok(crucible_cas::owned_decode::ResourceLoan::new(Loan {
            watched: self.watch_next.swap(false, Ordering::SeqCst),
        }))
    }
}

#[derive(Debug)]
struct Payload {
    panic: bool,
}

impl fmt::Display for Payload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original typed RAM payload")
    }
}

impl Error for Payload {}

impl Drop for Payload {
    fn drop(&mut self) {
        assert!(
            BODY_CLOSED.load(Ordering::SeqCst),
            "payload dropped inside shared allocation"
        );
        assert_eq!(LOAN_DROPS.load(Ordering::SeqCst), 0);
        PAYLOAD_DROPS.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "intentional original payload unwind");
    }
}

#[derive(Debug)]
#[repr(align(64))]
struct Boundary(u32);

impl fmt::Display for Boundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "first boundary {}", self.0)
    }
}

impl Error for Boundary {}

fn reset() {
    BODY_CLOSED.store(false, Ordering::SeqCst);
    PAYLOAD_DROPS.store(0, Ordering::SeqCst);
    LOAN_DROPS.store(0, Ordering::SeqCst);
}

#[test]
fn retained_failure_closes_real_allocation_before_payload_and_credit() {
    eprintln!(
        "carrier layout: aligned boundary={}, RAM error={}, scratch={}, admitted Arc={}",
        std::mem::size_of::<Boundary>(),
        std::mem::size_of::<RamStoreError>(),
        std::mem::size_of::<crucible_cas::owned_decode::DecodeScratch>(),
        PreparedRamFailure::<Boundary>::allocation_bytes().unwrap(),
    );
    for (has_boundary, concurrent, panic) in [
        (true, false, false),
        (false, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        reset();
        let authority = Arc::new(Authority {
            watch_next: AtomicBool::new(false),
            reservations: AtomicUsize::new(0),
        });
        let original = DecodeBudget::new(authority.clone(), 16 * 1024).unwrap();
        authority.watch_next.store(true, Ordering::SeqCst);
        let prepared = PreparedRamFailure::<Boundary>::new(&original).unwrap();
        assert_eq!(authority.reservations.load(Ordering::SeqCst), 2);

        // The incoming error already owns its original payload allocation.
        // This test pays only the new shared carrier, not the synthetic source.
        let storage = RamStoreError::Store(StoreError::Supervision {
            source: Box::new(Payload { panic }),
        });
        let extent = PreparedRamFailure::<Boundary>::allocation_bytes().unwrap();
        assert!(extent > 0);
        let layout = Layout::from_size_align(usize::try_from(extent).unwrap(), 64).unwrap();
        let (cause, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout, || {
                prepared.retain(has_boundary.then_some(Boundary(7)), storage)
            });
        let identity = identity.unwrap();
        assert_eq!(counts.allocations, 1);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);

        // Constructor/account close and all final owners remain inside the
        // same original process-wide physical-close observation.
        let ((), outcome) =
            TestAllocationObserver::observe_close_marker_after_free(&BODY_CLOSED, identity, || {
                assert_eq!(
                    cause.first_boundary().map(|first| first.0),
                    has_boundary.then_some(7)
                );
                assert!(matches!(
                    cause.storage_failure(),
                    RamStoreError::Store(StoreError::Supervision { .. })
                ));

                drop(original);
                if concurrent {
                    let barrier = Arc::new(std::sync::Barrier::new(17));
                    let mut owners = Vec::new();
                    for _ in 0..16 {
                        let clone = cause.clone();
                        assert_eq!(clone, cause);
                        let barrier = barrier.clone();
                        owners.push(std::thread::spawn(move || {
                            barrier.wait();
                            drop(clone);
                        }));
                    }
                    drop(cause);
                    assert_eq!(LOAN_DROPS.load(Ordering::SeqCst), 0);
                    assert_eq!(owners.len(), 16);
                    barrier.wait();
                    for owner in owners {
                        owner.join().unwrap();
                    }
                } else {
                    let clone = cause.clone();
                    drop(cause);
                    assert_eq!(LOAN_DROPS.load(Ordering::SeqCst), 0);
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(clone)));
                    assert_eq!(result.is_err(), panic);
                }
            })
            .unwrap();
        assert_eq!(outcome, CloseMarkerOutcome::Published);
        assert!(BODY_CLOSED.load(Ordering::SeqCst));
        assert_eq!(PAYLOAD_DROPS.load(Ordering::SeqCst), 1);
        assert_eq!(LOAN_DROPS.load(Ordering::SeqCst), 1);
    }

    reset();
    let authority = Arc::new(Authority {
        watch_next: AtomicBool::new(false),
        reservations: AtomicUsize::new(0),
    });
    let original = DecodeBudget::new(authority.clone(), 16 * 1024).unwrap();
    let prepared = PreparedRamFailure::<Boundary>::new(&original).unwrap();
    let extent = PreparedRamFailure::<Boundary>::allocation_bytes().unwrap();
    let layout = Layout::from_size_align(usize::try_from(extent).unwrap(), 64).unwrap();
    let (result, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            prepared
                .run(&mut || Ok(()), |boundary| {
                    boundary()?;
                    boundary()?;
                    Ok(17)
                })
                .unwrap()
        });

    assert_eq!(result, 17);
    assert!(
        identity.is_none(),
        "successful operation allocated a carrier"
    );
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(
        authority.reservations.load(Ordering::SeqCst),
        2,
        "only account and one prepared loan"
    );
}
