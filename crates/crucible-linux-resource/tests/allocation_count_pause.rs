//! Keeps an original constructor count separate from its real unwind close.

use std::alloc::Layout;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_linux_resource::test_support::{
    OriginalControlSelection, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static CLOSED: AtomicBool = AtomicBool::new(false);

#[test]
fn paused_count_preserves_actual_control_close_and_fresh_capture_reset() {
    let ((result, identity, counts), report) =
        TestAllocationObserver::observe_original_controls(|session| {
            session
                .arm(
                    OriginalControlSlot::First,
                    OriginalControlSelection::FirstThreadExtent(NonZeroUsize::new(59).unwrap()),
                    OriginalStaticCounters::Bool(&CLOSED),
                    false,
                )
                .unwrap();
            TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 59]>(), || {
                std::panic::catch_unwind(|| {
                    let owner = Box::new([3u8; 59]);
                    std::hint::black_box(&owner);
                    TestAllocationObserver::pause_allocation_count();
                    let unrelated = Box::new([7u8; 79]);
                    std::hint::black_box(&unrelated);
                    panic!("actual original callback panic after counting paused");
                })
            })
        })
        .unwrap();

    assert!(result.is_err());
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let observed = report.controls[0].unwrap();
    assert_eq!(Some(observed.identity), identity);
    assert_eq!(observed.before, OriginalControlSnapshot::Bool(false));
    assert!(!CLOSED.load(Ordering::SeqCst));

    // The paused predecessor cannot suppress a later real constructor request.
    let (owner, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<[u8; 61]>(), || {
            Box::new([4u8; 61])
        });
    assert!(identity.is_some());
    assert_eq!(owner.len(), 61);
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    drop(owner);

    // Unwind resets count state without preventing a fresh observation.
    let unwind = std::panic::catch_unwind(|| {
        let _ = TestAllocationObserver::count(|| {
            TestAllocationObserver::pause_allocation_count();
            panic!("actual counting action unwind");
        });
    });
    assert!(unwind.is_err());
    let (owner, counts) = TestAllocationObserver::count(|| Box::new([8u8; 73]));
    assert_eq!(owner.len(), 73);
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
}
