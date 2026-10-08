//! Exercises the fixed paired-account sampler and native entry counts.
//!
//! This finite component witness uses the existing single test allocator. It
//! covers sample ordering and reset only, not production namespace authority.

#![cfg(feature = "test-support")]
// crucible-lint: allow panic-shortcut -- finite observer setup uses panics to signal invalid custody and intentional unwind.
#![allow(clippy::unwrap_used)]
// crucible-lint: allow panic-shortcut -- observer fixtures intentionally signal invalid custody and valid action unwind.

use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::test_support::TestAllocationObserver;
use std::sync::atomic::AtomicBool;

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Pair(Option<(HostServiceLease, HostServiceLease)>);

impl Drop for Pair {
    fn drop(&mut self) {
        if let Some((first, second)) = self.0.take() {
            HostServiceLease::close_pair(first, second);
        }
    }
}

#[test]
fn both_original_counters_remain_live_before_and_after_both_controls_close() {
    for unwind in [false, true] {
        let first = HostServiceAllocator::new(1, 1, 96).unwrap();
        let second = HostServiceAllocator::new(1, 1, 96).unwrap();
        let occupied = AtomicBool::new(true);
        let (pair, identities) = TestAllocationObserver::capture_controls([48, 48, 0], || {
            Pair(Some(first.reserve_paired_bytes(&second, 96).unwrap()))
        });
        assert!(identities[0].is_some());
        assert!(identities[1].is_some());
        let (result, records) = TestAllocationObserver::observe_controls(
            [&first, &second],
            Some(&occupied),
            identities,
            || {
                std::panic::catch_unwind(move || {
                    let _pair = pair;
                    if unwind {
                        panic!("intentional complete pair action unwind");
                    }
                })
            },
        );
        assert_eq!(result.is_err(), unwind);
        for record in records[..2].iter() {
            let record = record.unwrap();
            assert_eq!(record.before.original_bytes, [Some(96); 2]);
            assert_eq!(record.after.original_bytes, [Some(96); 2]);
            assert_eq!(record.before.occupied, Some(true));
            assert_eq!(record.after.occupied, Some(true));
        }
        assert!(first.reserve_resources(0, 0, 96).is_ok());
        assert!(second.reserve_resources(0, 0, 96).is_ok());
    }
}

#[test]
fn native_allocation_and_reallocation_entries_are_counted_separately() {
    let ((first, second), counts) = TestAllocationObserver::count(|| {
        let mut first = Vec::<u8>::with_capacity(1);
        first.push(1);
        first.reserve_exact(31);
        let second = vec![0u8; 32];
        std::hint::black_box((first, second))
    });
    assert!(!counts.overflow);
    assert_eq!(counts.allocations, 2);
    assert_eq!(counts.reallocations, 1);
    assert_eq!(first, [1]);
    assert_eq!(second, [0; 32]);
}
