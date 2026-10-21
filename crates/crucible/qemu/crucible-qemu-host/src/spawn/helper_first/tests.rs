//! Observes the helper cause's closed allocation with real paired service loans.
//!
//! The generic funding field uses mechanism credit here. It cannot construct
//! the public Source-funded helper failure or issue a Native process family.

use super::*;
use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_host_resources::test_support::{AllocationIdentity, TestAllocationObserver};
use std::alloc::Layout;
use std::sync::atomic::AtomicUsize;

struct Fixture {
    accounts: [HostServiceAllocator; 2],
    bytes: u64,
    allocation: AllocationIdentity,
    cause: SharedOperationalCause<HelperCause<HostServiceLeasePair>>,
}

fn fixture() -> Fixture {
    let accounts = [
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
    ];
    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<HelperCause<HostServiceLeasePair>>())
        .unwrap();
    let layout = layout.pad_to_align();
    let bytes = u64::try_from(layout.size()).unwrap();
    let funding = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, bytes).unwrap(),
        accounts[1].reserve_resources(0, 0, bytes).unwrap(),
    );
    let source = QemuSpawnError::Io {
        operation: "actual helper cause",
        source: std::io::Error::from_raw_os_error(libc::EIO),
    };
    let (cause, allocation, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            SharedOperationalCause::new(HelperCause {
                source,
                _funding: funding,
            })
        });

    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let original = cause.source_ref().source().unwrap();
    assert!(matches!(original.downcast_ref::<QemuSpawnError>(),
        Some(QemuSpawnError::Io { source, .. }) if source.raw_os_error() == Some(libc::EIO)));

    Fixture {
        accounts,
        bytes,
        allocation: allocation.unwrap(),
        cause,
    }
}

#[test]
fn helper_first_control_retains_paired_credit_through_its_actual_free() {
    let Fixture {
        accounts,
        bytes,
        allocation,
        cause,
    } = fixture();
    let (last, counts) = TestAllocationObserver::count(|| cause.clone());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(std::ptr::eq(cause.source_ref(), last.source_ref()));

    drop(cause);
    let ((), observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        [Some(allocation), None, None],
        || drop(last),
    );

    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    assert_returned(&accounts);
}

#[test]
fn concurrent_helper_first_observers_close_once_before_paired_refund() {
    let Fixture {
        accounts,
        bytes,
        allocation,
        cause,
    } = fixture();
    let aliases: Vec<_> = (0..8).map(|_| cause.clone()).collect();
    let barrier = std::sync::Barrier::new(8);
    drop(cause);

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
    assert_eq!(observations[0].before.original_bytes, [Some(bytes); 2]);
    assert_eq!(observations[0].after.original_bytes, [Some(bytes); 2]);
    assert_returned(&accounts);
}

fn assert_returned(accounts: &[HostServiceAllocator; 2]) {
    for account in accounts {
        let complete = account.reserve_resources(0, 0, 4096).unwrap();
        drop(complete);
    }
}
