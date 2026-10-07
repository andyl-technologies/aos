//! Observes actual terminal control close, original refund, and final aliases.

// crucible-lint: allow panic-shortcut -- test fixtures intentionally localize ownership failures.
#![allow(clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use crucible_ram::{ResourceLoan, ResourceLoanSlot};

thread_local! {
    static CAPTURE: Cell<bool> = const { Cell::new(false) };
}

static EXPECTED_SIZE: AtomicUsize = AtomicUsize::new(0);
static EXPECTED_ALIGNMENT: AtomicUsize = AtomicUsize::new(0);
static TARGET: AtomicUsize = AtomicUsize::new(0);
static CLOSED: AtomicBool = AtomicBool::new(false);
static EARLY_REFUND: AtomicBool = AtomicBool::new(false);
static DROPS: AtomicUsize = AtomicUsize::new(0);

struct ObserverAllocator;

// SAFETY: Every allocator operation delegates unchanged to System. The observer
// uses integer addresses and atomics only, never touches allocation contents,
// and disarms its exact target before forwarding the actual deallocation.
unsafe impl GlobalAlloc for ObserverAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller's exact original layout is forwarded to System.
        let pointer = unsafe { System.alloc(layout) };
        if CAPTURE.try_with(Cell::get).unwrap_or(false)
            && layout.size() == EXPECTED_SIZE.load(Ordering::Relaxed)
            && layout.align() == EXPECTED_ALIGNMENT.load(Ordering::Relaxed)
        {
            let _ =
                TARGET.compare_exchange(0, pointer as usize, Ordering::SeqCst, Ordering::SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let watched = TARGET
            .compare_exchange(pointer as usize, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        // SAFETY: The original pointer and layout are forwarded exactly once.
        unsafe { System.dealloc(pointer, layout) };
        if watched {
            CLOSED.store(true, Ordering::SeqCst);
        }
    }
}

#[global_allocator]
static ALLOCATOR: ObserverAllocator = ObserverAllocator;

struct Loan {
    original_account: Arc<AtomicUsize>,
    bytes: usize,
    panic: bool,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if !CLOSED.load(Ordering::SeqCst) {
            EARLY_REFUND.store(true, Ordering::SeqCst);
        }
        self.original_account
            .fetch_sub(self.bytes, Ordering::SeqCst);
        DROPS.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "intentional concrete loan destructor unwind");
    }
}

#[repr(align(64))]
struct AlignedLoan(Loan);

fn reset<L>() {
    EXPECTED_SIZE.store(
        ResourceLoan::allocation_bytes::<L>() as usize,
        Ordering::SeqCst,
    );
    EXPECTED_ALIGNMENT.store(
        std::mem::align_of::<L>().max(std::mem::align_of::<usize>()),
        Ordering::SeqCst,
    );
    TARGET.store(0, Ordering::SeqCst);
    CLOSED.store(false, Ordering::SeqCst);
    EARLY_REFUND.store(false, Ordering::SeqCst);
    DROPS.store(0, Ordering::SeqCst);
}

fn verify_closed(account: &AtomicUsize) {
    assert!(CLOSED.load(Ordering::SeqCst));
    assert!(!EARLY_REFUND.load(Ordering::SeqCst));
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(account.load(Ordering::SeqCst), 0);
}

#[test]
fn actual_controls_close_before_concrete_refund_across_aliases_and_unwind() {
    assert_eq!(std::mem::size_of::<ResourceLoan>(), 16);
    assert_eq!(std::mem::size_of::<Option<ResourceLoan>>(), 24);
    assert_eq!(std::mem::size_of::<ResourceLoanSlot>(), 16);
    let mut empty = ResourceLoanSlot::default();
    assert!(empty.as_ref().is_none());
    assert!(empty.clone().as_ref().is_none());
    assert!(empty.take().is_none());
    assert_eq!(ResourceLoan::allocation_bytes::<()>(), 16);
    assert_eq!(ResourceLoan::allocation_bytes::<AlignedLoan>(), 128);

    // One test serializes the global exact-allocation observer's scenarios.
    for aligned in [false, true] {
        if aligned {
            reset::<AlignedLoan>();
        } else {
            reset::<Loan>();
        }
        let bytes = EXPECTED_SIZE.load(Ordering::SeqCst);
        let account = Arc::new(AtomicUsize::new(bytes));
        let credit = Loan {
            original_account: account.clone(),
            bytes,
            panic: false,
        };
        CAPTURE.with(|capture| capture.set(true));
        let loan = if aligned {
            {
                let aligned = AlignedLoan(credit);
                assert_eq!(aligned.0.bytes, bytes);
                ResourceLoan::new(aligned)
            }
        } else {
            ResourceLoan::new(credit)
        };
        CAPTURE.with(|capture| capture.set(false));
        assert_ne!(TARGET.load(Ordering::SeqCst), 0);
        let mut slot = ResourceLoanSlot::from(loan);
        assert!(slot.as_ref().is_some());
        let mut alias_slot = slot.clone();
        let loan = slot.take().unwrap();
        assert!(slot.as_ref().is_none());
        drop(slot);
        drop(loan);
        assert!(!CLOSED.load(Ordering::SeqCst));
        assert_eq!(account.load(Ordering::SeqCst), bytes);
        let alias = alias_slot.take().unwrap();
        assert!(alias_slot.as_ref().is_none());
        drop(alias_slot);
        drop(alias);
        verify_closed(&account);
    }

    reset::<Loan>();
    let bytes = EXPECTED_SIZE.load(Ordering::SeqCst);
    let account = Arc::new(AtomicUsize::new(bytes));
    CAPTURE.with(|capture| capture.set(true));
    let loan = ResourceLoan::new(Loan {
        original_account: account.clone(),
        bytes,
        panic: false,
    });
    CAPTURE.with(|capture| capture.set(false));
    let slot = ResourceLoanSlot::from(Some(loan));
    let borrowers: Vec<_> = (0..8).map(|_| slot.clone()).collect();
    let barrier = Arc::new(Barrier::new(borrowers.len()));
    drop(slot);
    std::thread::scope(|scope| {
        let workers: Vec<_> = borrowers
            .into_iter()
            .map(|borrower| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    drop(borrower);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    verify_closed(&account);

    reset::<Loan>();
    let bytes = EXPECTED_SIZE.load(Ordering::SeqCst);
    let account = Arc::new(AtomicUsize::new(bytes));
    CAPTURE.with(|capture| capture.set(true));
    let loan = ResourceLoan::new(Loan {
        original_account: account.clone(),
        bytes,
        panic: false,
    });
    CAPTURE.with(|capture| capture.set(false));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _slot = ResourceLoanSlot::from(loan);
            panic!("intentional slot borrower unwind");
        }))
        .is_err()
    );
    verify_closed(&account);

    reset::<Loan>();
    let bytes = EXPECTED_SIZE.load(Ordering::SeqCst);
    let account = Arc::new(AtomicUsize::new(bytes));
    CAPTURE.with(|capture| capture.set(true));
    let slot = ResourceLoanSlot::from(ResourceLoan::new(Loan {
        original_account: account.clone(),
        bytes,
        panic: true,
    }));
    CAPTURE.with(|capture| capture.set(false));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(slot))).is_err());
    verify_closed(&account);

    // The same observer rejects an ordinary raw Arc concrete owner. This is a
    // controlled input fault, never a production fallback or exposed handle.
    reset::<Loan>();
    let bytes = EXPECTED_SIZE.load(Ordering::SeqCst);
    let account = Arc::new(AtomicUsize::new(bytes));
    CAPTURE.with(|capture| capture.set(true));
    let old = Arc::new(Loan {
        original_account: account.clone(),
        bytes,
        panic: false,
    });
    CAPTURE.with(|capture| capture.set(false));
    drop(old);
    assert!(CLOSED.load(Ordering::SeqCst));
    assert!(EARLY_REFUND.load(Ordering::SeqCst));
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(account.load(Ordering::SeqCst), 0);
}
