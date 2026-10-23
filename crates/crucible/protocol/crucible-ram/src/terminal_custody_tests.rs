//! Observes original metadata charges through actual shared-control deallocation.
//!
//! Each constructor supplies its actual private control layout. These finite
//! logical components establish no native thread, stack or execution admission.

// crucible-lint: allow panic-shortcut -- physical lifecycle controls localize failed accounting assumptions.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::sync::Barrier;

use crucible_host_resources::test_support::TestAllocationObserver;

use crate::MetadataBudget;

pub(crate) fn shared_layout<T>() -> Layout {
    let (layout, _) = Layout::new::<[usize; 2]>()
        .extend(Layout::new::<T>())
        .unwrap();
    layout.pad_to_align()
}

pub(crate) fn assert_terminal_credit<T: Clone + Send>(
    budget: &MetadataBudget,
    layout: Layout,
    mut constructor: impl FnMut() -> T,
) {
    let baseline = budget.used_bytes();

    for concurrent in [false, true] {
        let (owner, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout, &mut constructor);
        assert!(!counts.overflow);
        let identity = identity.unwrap();
        let live_bytes = budget.used_bytes();
        assert!(live_bytes > baseline);

        let (alias, clone_counts) = TestAllocationObserver::count(|| owner.clone());
        assert_eq!(clone_counts.allocations, 0);
        assert_eq!(clone_counts.reallocations, 0);
        assert_eq!(budget.used_bytes(), live_bytes);

        if concurrent {
            // The harness owns these bounded workers outside the logical
            // metadata budget. Each watches its possible final deallocation.
            let borrowers: [T; 8] = std::array::from_fn(|_| owner.clone());
            let barrier = Barrier::new(borrowers.len());
            drop(owner);
            drop(alias);
            assert_eq!(budget.used_bytes(), live_bytes);

            let observations = std::thread::scope(|scope| {
                let workers: Vec<_> = borrowers
                    .into_iter()
                    .map(|borrower| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            barrier.wait();
                            let ((), observed) = TestAllocationObserver::observe_atomic_after_free(
                                budget.counter_for_test(),
                                identity,
                                || drop(borrower),
                            );
                            observed
                        })
                    })
                    .collect();

                workers
                    .into_iter()
                    .filter_map(|worker| worker.join().unwrap())
                    .collect::<Vec<_>>()
            });
            assert_eq!(observations, vec![live_bytes]);
        } else {
            let ((), observed) = TestAllocationObserver::observe_atomic_after_free(
                budget.counter_for_test(),
                identity,
                || {
                    drop(owner);
                    assert_eq!(budget.used_bytes(), live_bytes);
                    drop(alias);
                },
            );
            assert_eq!(observed, Some(live_bytes));
        }

        assert_eq!(budget.used_bytes(), baseline);
    }
}
