//! Observes actual cleanup-record deallocation with paired mechanism funding.
//!
//! The fixture registrar retains real service charges for the cleanup record.
//! It supplies no authenticated Main, Source purpose or native return authority.

use super::*;
use crucible_host_resources::test_support::{AllocationIdentity, TestAllocationObserver};
use std::alloc::Layout;

/// Owns the actual cleanup allocation and its paired component service accounts.
pub(crate) struct Fixture {
    pub(crate) cleanup: LaunchCleanup,
    pub(crate) accounts: [HostServiceAllocator; 2],
    pub(crate) bytes: u64,
    allocation: AllocationIdentity,
}

fn allocation_layout() -> Layout {
    Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<CleanupRecord>())
        .unwrap()
        .0
        .pad_to_align()
}

/// Funds one complete cleanup allocation without issuing native launch authority.
///
/// # Panics
/// Panics if component funding or the allocation observer cannot be established.
pub(crate) fn fixture() -> Fixture {
    let bytes = LaunchCleanup::retained_control_bytes().unwrap();
    let accounts = [
        HostServiceAllocator::new(1, 1, bytes).unwrap(),
        HostServiceAllocator::new(1, 1, bytes).unwrap(),
    ];
    let funding = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, bytes).unwrap(),
        accounts[1].reserve_resources(0, 0, bytes).unwrap(),
    );
    let (registration, registrar) = registration_with_funding(false, None, Some(funding));
    let (cleanup, allocation, counts) =
        TestAllocationObserver::capture_layout_and_count(allocation_layout(), || {
            LaunchCleanup::new(&registration)
        });

    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    // Only the actual cleanup record keeps this registrar and its real charges.
    drop(registration);
    drop(registrar);

    Fixture {
        cleanup,
        accounts,
        bytes,
        allocation: allocation.unwrap(),
    }
}

fn assert_refunded(accounts: &[HostServiceAllocator; 2], bytes: u64) {
    for account in accounts {
        let complete = account.reserve_resources(0, 0, bytes).unwrap();
        drop(complete);
    }
}

#[test]
fn cleanup_record_keeps_paired_credit_through_its_actual_free() {
    let Fixture {
        cleanup,
        accounts,
        bytes,
        allocation,
    } = fixture();
    let (last, counts) = TestAllocationObserver::count(|| cleanup.clone());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    drop(cleanup);

    for account in &accounts {
        assert!(account.reserve_resources(0, 0, 1).is_err());
    }
    let (_, observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        [Some(allocation), None, None],
        || drop(last),
    );

    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    assert_refunded(&accounts, bytes);
}

#[test]
fn concurrent_cleanup_observers_free_once_before_paired_refund() {
    let Fixture {
        cleanup,
        accounts,
        bytes,
        allocation,
    } = fixture();
    let aliases: Vec<_> = (0..8).map(|_| cleanup.clone()).collect();
    let barrier = std::sync::Barrier::new(8);
    drop(cleanup);

    let observations = std::thread::scope(|scope| {
        let workers: Vec<_> = aliases
            .into_iter()
            .map(|alias| {
                let accounts = &accounts;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    TestAllocationObserver::observe_controls(
                        [&accounts[0], &accounts[1]],
                        None,
                        [Some(allocation), None, None],
                        || drop(alias),
                    )
                    .1[0]
                })
            })
            .collect();
        workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(observations.len(), 1);
    let observed = observations[0];
    assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    assert_refunded(&accounts, bytes);
}

#[test]
fn cleanup_extent_covers_allocation_and_extracted_destruction_frame() {
    let physical_peak = allocation_layout()
        .size()
        .checked_add(std::mem::size_of::<CleanupRecord>())
        .unwrap();

    assert!(LaunchCleanup::retained_control_bytes().unwrap() >= physical_peak as u64);
}
