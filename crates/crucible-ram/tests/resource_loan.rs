//! Observes actual terminal control close, original refund, and final aliases.

// crucible-lint: allow panic-shortcut -- test fixtures intentionally localize ownership failures.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use crucible_ram::{ResourceLoan, ResourceLoanSlot};

use crucible_linux_resource::test_support::{
    AllocationIdentity, CloseMarkerOutcome, TestAllocationObserver,
};

static CLOSED: AtomicBool = AtomicBool::new(false);
static EARLY_REFUND: AtomicBool = AtomicBool::new(false);
static DROPS: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

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

fn reset<L>() -> Layout {
    CLOSED.store(false, Ordering::SeqCst);
    EARLY_REFUND.store(false, Ordering::SeqCst);
    DROPS.store(0, Ordering::SeqCst);

    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<L>())
        .unwrap();
    let layout = layout.pad_to_align();
    assert_eq!(layout.size() as u64, ResourceLoan::allocation_bytes::<L>());
    assert_eq!(
        layout.align(),
        std::mem::align_of::<L>().max(std::mem::align_of::<usize>())
    );
    assert!(layout.size() > 0);
    layout
}

fn capture_loan<L: Send + Sync + 'static>(
    layout: Layout,
    loan: L,
) -> (ResourceLoan, AllocationIdentity) {
    let (loan, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || ResourceLoan::new(loan));
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    (loan, identity.unwrap())
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

    // One test serializes the process-wide original close-marker scenarios.
    for aligned in [false, true] {
        let layout = if aligned {
            reset::<AlignedLoan>()
        } else {
            reset::<Loan>()
        };
        let bytes = layout.size();
        let account = Arc::new(AtomicUsize::new(bytes));
        let credit = Loan {
            original_account: account.clone(),
            bytes,
            panic: false,
        };
        let (loan, identity) = if aligned {
            let aligned = AlignedLoan(credit);
            assert_eq!(aligned.0.bytes, bytes);
            capture_loan(layout, aligned)
        } else {
            capture_loan(layout, credit)
        };

        let ((), outcome) =
            TestAllocationObserver::observe_close_marker_after_free(&CLOSED, identity, || {
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
            })
            .unwrap();

        assert_eq!(outcome, CloseMarkerOutcome::Published);
        verify_closed(&account);
    }

    let layout = reset::<Loan>();
    let bytes = layout.size();
    let account = Arc::new(AtomicUsize::new(bytes));
    let (loan, identity) = capture_loan(
        layout,
        Loan {
            original_account: account.clone(),
            bytes,
            panic: false,
        },
    );
    let ((), outcome) =
        TestAllocationObserver::observe_close_marker_after_free(&CLOSED, identity, || {
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
                assert_eq!(workers.len(), 8);
                for worker in workers {
                    worker.join().unwrap();
                }
            });
        })
        .unwrap();
    assert_eq!(outcome, CloseMarkerOutcome::Published);
    verify_closed(&account);

    let layout = reset::<Loan>();
    let bytes = layout.size();
    let account = Arc::new(AtomicUsize::new(bytes));
    let (loan, identity) = capture_loan(
        layout,
        Loan {
            original_account: account.clone(),
            bytes,
            panic: false,
        },
    );
    let (result, outcome) =
        TestAllocationObserver::observe_close_marker_after_free(&CLOSED, identity, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _slot = ResourceLoanSlot::from(loan);
                panic!("intentional slot borrower unwind");
            }))
        })
        .unwrap();
    assert!(result.is_err());
    assert_eq!(outcome, CloseMarkerOutcome::Published);
    verify_closed(&account);

    let layout = reset::<Loan>();
    let bytes = layout.size();
    let account = Arc::new(AtomicUsize::new(bytes));
    let (loan, identity) = capture_loan(
        layout,
        Loan {
            original_account: account.clone(),
            bytes,
            panic: true,
        },
    );
    let slot = ResourceLoanSlot::from(loan);
    let (result, outcome) =
        TestAllocationObserver::observe_close_marker_after_free(&CLOSED, identity, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(slot)))
        })
        .unwrap();
    assert!(result.is_err());
    assert_eq!(outcome, CloseMarkerOutcome::Published);
    verify_closed(&account);

    // The actual ordinary Arc predecessor drops its credit before control free.
    // This controlled negative input never becomes a production fallback.
    let layout = reset::<Loan>();
    let bytes = layout.size();
    let account = Arc::new(AtomicUsize::new(bytes));
    let (old, identity, counts) = TestAllocationObserver::capture_layout_and_count(layout, || {
        Arc::new(Loan {
            original_account: account.clone(),
            bytes,
            panic: false,
        })
    });
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    let ((), outcome) =
        TestAllocationObserver::observe_close_marker_after_free(&CLOSED, identity.unwrap(), || {
            drop(old)
        })
        .unwrap();
    assert_eq!(outcome, CloseMarkerOutcome::Published);
    assert!(CLOSED.load(Ordering::SeqCst));
    assert!(EARLY_REFUND.load(Ordering::SeqCst));
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(account.load(Ordering::SeqCst), 0);
}
