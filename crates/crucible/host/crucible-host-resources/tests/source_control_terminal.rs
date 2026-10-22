//! Observes control deallocation before its original paired service loans return.
//!
//! This exercises the production control owner with actual service accounting.
//! It constructs no Native Source, process family, or physical-return evidence.

use std::alloc::Layout;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_host_resources::test_support::{AllocationIdentity, TestAllocationObserver};

#[path = "../src/host_services/process_birth/executor_purpose/source_host/retained_control.rs"]
mod retained_control;

use retained_control::RetainedControl;

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct PrepaidControl {
    returns: Arc<AtomicUsize>,
    _credit: HostServiceLeasePair,
}

impl Drop for PrepaidControl {
    fn drop(&mut self) {
        self.returns.fetch_add(1, Ordering::SeqCst);
    }
}

struct Fixture {
    accounts: [HostServiceAllocator; 2],
    returns: Arc<AtomicUsize>,
    bytes: u64,
    allocation: AllocationIdentity,
    control: RetainedControl<PrepaidControl>,
}

#[expect(
    clippy::unwrap_used,
    reason = "Failed allocation/accounting fixture setup must fail its calling test."
)]
fn fixture() -> Fixture {
    let accounts = [
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
    ];
    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<PrepaidControl>())
        .unwrap();
    let layout = layout.pad_to_align();
    let bytes = u64::try_from(layout.size()).unwrap();
    let credit = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, bytes).unwrap(),
        accounts[1].reserve_resources(0, 0, bytes).unwrap(),
    );
    let returns = Arc::new(AtomicUsize::new(0));
    let payload = PrepaidControl {
        returns: Arc::clone(&returns),
        _credit: credit,
    };
    let (control, allocation, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || RetainedControl::new(payload));

    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    Fixture {
        accounts,
        returns,
        bytes,
        allocation: allocation.unwrap(),
        control,
    }
}

#[test]
fn final_control_header_closes_before_original_paired_credit_returns() {
    let Fixture {
        accounts,
        returns,
        bytes,
        allocation,
        control,
    } = fixture();
    let last = control.clone();
    assert!(control.same_owner(&last));

    drop(control);
    assert_eq!(returns.load(Ordering::SeqCst), 0);
    let ((), observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        [Some(allocation), None, None],
        || drop(last),
    );

    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
    assert_eq!(returns.load(Ordering::SeqCst), 1);
    for account in &accounts {
        // The original account grants its complete allowance again only after
        // the final observed control and its real paired loans have closed.
        drop(
            account
                .reserve_resources(0, 0, account.maximum_resident_bytes())
                .unwrap(),
        );
    }
}

#[test]
fn concurrent_control_observers_close_before_one_paired_refund() {
    let Fixture {
        accounts,
        returns,
        bytes,
        allocation,
        control,
    } = fixture();
    let aliases: Vec<_> = (0..8).map(|_| control.clone()).collect();
    let barrier = std::sync::Barrier::new(aliases.len());
    drop(control);

    let observations = std::thread::scope(|scope| {
        let workers: Vec<_> = aliases
            .into_iter()
            .map(|alias| {
                let accounts = &accounts;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let ((), observed) = TestAllocationObserver::observe_controls(
                        [&accounts[0], &accounts[1]],
                        None,
                        [Some(allocation), None, None],
                        || drop(alias),
                    );
                    observed[0]
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
    assert_eq!(returns.load(Ordering::SeqCst), 1);
    for account in &accounts {
        // The original account grants its complete allowance again only after
        // the final observed control and its real paired loans have closed.
        drop(
            account
                .reserve_resources(0, 0, account.maximum_resident_bytes())
                .unwrap(),
        );
    }
}
