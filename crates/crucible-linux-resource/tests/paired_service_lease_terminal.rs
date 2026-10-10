//! Observes both original grants at both private paired-control deallocations.
//!
//! Both actual counters are sampled before and after each System close. This
//! replaces the earlier owned fixture's custom admission-probe allocator; the
//! immutable probe evidence remains separate. Counter samples establish the
//! retained charges, not the availability of a concurrent admission probe.
//! Model enclosing/thread controls remain outside the funding scope.

#![cfg(feature = "test-support")]
// crucible-lint: allow panic-shortcut -- finite fixtures intentionally signal invalid custody and the explicit unwind action.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Barrier};

use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::test_support::{
    AllocationIdentity, ControlObservation, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct PrivatePair {
    leases: Option<(HostServiceLease, HostServiceLease)>,
}

impl Drop for PrivatePair {
    fn drop(&mut self) {
        if let Some((first, second)) = self.leases.take() {
            HostServiceLease::close_pair(first, second);
        }
    }
}

fn capture(
    first: &HostServiceAllocator,
    second: &HostServiceAllocator,
) -> (PrivatePair, [Option<AllocationIdentity>; 3]) {
    let (pair, identities) =
        TestAllocationObserver::capture_controls([48, 48, 0], || PrivatePair {
            leases: Some(first.reserve_paired_bytes(second, 96).unwrap()),
        });
    assert!(identities[..2].iter().all(Option::is_some));
    (pair, identities)
}

fn assert_retained(records: &[Option<ControlObservation>; 3]) {
    for (index, record) in records[..2].iter().enumerate() {
        let record = record.unwrap();
        assert_eq!(record.before.original_bytes, [Some(96); 2]);
        assert_eq!(record.after.original_bytes, [Some(96); 2]);
        assert_eq!(record.ordinal, (index + 1) as u8);
    }
}

fn refunded(first: &HostServiceAllocator, second: &HostServiceAllocator) {
    let (first, second) = first.reserve_paired_bytes(second, 96).unwrap();
    HostServiceLease::close_pair(first, second);
}

#[test]
fn both_controls_close_before_either_original_bank_refunds() {
    assert_eq!(std::mem::size_of::<HostServiceLease>(), 8);
    assert_eq!(std::mem::size_of::<PrivatePair>(), 24);
    assert_eq!(
        std::mem::size_of::<Option<(HostServiceLease, HostServiceLease)>>(),
        24
    );
    eprintln!(
        "lease8/private Option pair24/alignment{}",
        std::mem::align_of::<PrivatePair>()
    );
    let first = HostServiceAllocator::new(1, 1, 96).unwrap();
    let second = HostServiceAllocator::new(1, 1, 96).unwrap();
    let (pair, identities) = capture(&first, &second);

    let (_, records) =
        TestAllocationObserver::observe_controls([&first, &second], None, identities, || {
            drop(pair)
        });

    assert_retained(&records);
    refunded(&first, &second);
}

#[test]
fn unwind_closes_both_controls_before_either_refund() {
    let first = HostServiceAllocator::new(1, 1, 96).unwrap();
    let second = HostServiceAllocator::new(1, 1, 96).unwrap();
    let (pair, identities) = capture(&first, &second);
    let (result, records) =
        TestAllocationObserver::observe_controls([&first, &second], None, identities, || {
            std::panic::catch_unwind(move || {
                let _pair = pair;
                panic!("intentional private paired-owner unwind");
            })
        });

    assert!(result.is_err());
    assert_retained(&records);
    refunded(&first, &second);
}

#[test]
fn concurrent_complete_pair_owners_close_once_without_half_aliases() {
    let first = HostServiceAllocator::new(1, 1, 96).unwrap();
    let second = HostServiceAllocator::new(1, 1, 96).unwrap();
    let (pair, identities) = capture(&first, &second);
    let pair = Arc::new(pair);
    let barrier = Barrier::new(8);
    let owners: Vec<_> = (0..8).map(|_| pair.clone()).collect();
    drop(pair);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = owners
            .into_iter()
            .map(|owner| {
                let first = &first;
                let second = &second;
                let barrier = &barrier;
                scope.spawn(move || {
                    TestAllocationObserver::observe_controls(
                        [first, second],
                        None,
                        identities,
                        || {
                            barrier.wait();
                            drop(owner);
                        },
                    )
                    .1
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(
        results
            .iter()
            .filter(|result| result[..2].iter().all(Option::is_some))
            .count(),
        1
    );
    assert_retained(
        results
            .iter()
            .find(|result| result[..2].iter().all(Option::is_some))
            .unwrap(),
    );
    refunded(&first, &second);
}
