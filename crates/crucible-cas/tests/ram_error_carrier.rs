//! Causal allocation-close evidence for the shared RAM failure carrier.
//!
//! The test allocator watches exactly the next carrier allocation on this
//! thread. It proves actual deallocation precedes both payload destruction and
//! release of the original loan, including concurrent final owners and unwind.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_cas::content_store::StoreError;
use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use crucible_cas::ram::{PreparedRamFailure, RamStoreError};

thread_local! {
    static WATCH_ALLOCATION: Cell<bool> = const { Cell::new(false) };
}

static EXPECTED_SIZE: AtomicUsize = AtomicUsize::new(0);
static EXPECTED_ALIGNMENT: AtomicUsize = AtomicUsize::new(0);
static BODY_POINTER: AtomicUsize = AtomicUsize::new(0);
static BODY_CLOSED: AtomicBool = AtomicBool::new(false);
static PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);
static LOAN_DROPS: AtomicUsize = AtomicUsize::new(0);

struct ObserverAllocator;

// SAFETY: Every allocation operation delegates unchanged to System. The
// observer records integer addresses and never reads or modifies allocations.
unsafe impl GlobalAlloc for ObserverAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The exact caller layout is forwarded to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        let watching = WATCH_ALLOCATION.try_with(Cell::get).unwrap_or(false);
        if watching
            && layout.size() == EXPECTED_SIZE.load(Ordering::Relaxed)
            && layout.align() == EXPECTED_ALIGNMENT.load(Ordering::Relaxed)
        {
            let _ = BODY_POINTER.compare_exchange(
                0,
                pointer as usize,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let watched = pointer as usize == BODY_POINTER.load(Ordering::SeqCst);
        // SAFETY: Pointer and original layout are forwarded unchanged; the
        // observer cannot deallocate twice or alter the allocation's contents.
        unsafe { System.dealloc(pointer, layout) };
        if watched {
            BODY_CLOSED.store(true, Ordering::SeqCst);
        }
    }
}

#[global_allocator]
static ALLOCATOR: ObserverAllocator = ObserverAllocator;

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
    BODY_POINTER.store(0, Ordering::SeqCst);
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
        EXPECTED_SIZE.store(
            PreparedRamFailure::<Boundary>::allocation_bytes().unwrap() as usize,
            Ordering::Relaxed,
        );
        EXPECTED_ALIGNMENT.store(64, Ordering::Relaxed);
        WATCH_ALLOCATION.with(|watch| watch.set(true));
        let cause = prepared.retain(has_boundary.then_some(Boundary(7)), storage);
        WATCH_ALLOCATION.with(|watch| watch.set(false));
        assert_ne!(
            BODY_POINTER.load(Ordering::SeqCst),
            0,
            "actual Arc extent differed from admitted layout"
        );
        assert_eq!(
            cause.first_boundary().map(|first| first.0),
            has_boundary.then_some(7)
        );
        assert!(matches!(
            cause.storage_failure(),
            RamStoreError::Store(StoreError::Supervision { .. })
        ));

        // Closing constructor/account scopes does not release the carrier loan.
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
            barrier.wait();
            for owner in owners {
                owner.join().unwrap();
            }
        } else {
            let clone = cause.clone();
            drop(cause);
            assert_eq!(LOAN_DROPS.load(Ordering::SeqCst), 0);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(clone)));
            assert_eq!(result.is_err(), panic);
        }
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
    WATCH_ALLOCATION.with(|watch| watch.set(true));
    let result = prepared.run(&mut || Ok(()), |boundary| {
        boundary()?;
        boundary()?;
        Ok(17)
    });
    WATCH_ALLOCATION.with(|watch| watch.set(false));

    assert!(matches!(result, Ok(17)));
    assert_eq!(
        BODY_POINTER.load(Ordering::SeqCst),
        0,
        "successful operation allocated a carrier"
    );
    assert_eq!(
        authority.reservations.load(Ordering::SeqCst),
        2,
        "only account and one prepared loan"
    );
}
