//! Observes lifecycle error deallocation while its original paired loans live.
//!
//! These controls use actual service accounting and allocator observations.
//! They create no Native Source, process family, or physical-return receipt.

use std::alloc::Layout;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_control_api::LifecycleBackendConstructionError;
use crucible_engine::SharedOperationalCause;
use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_host_resources::test_support::{AllocationIdentity, TestAllocationObserver};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct PrepaidFailure {
    returns: Arc<AtomicUsize>,
    _credit: HostServiceLeasePair,
}

impl fmt::Debug for PrepaidFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrepaidFailure")
    }
}

impl fmt::Display for PrepaidFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original paired lifecycle failure")
    }
}

impl Error for PrepaidFailure {}

impl Drop for PrepaidFailure {
    fn drop(&mut self) {
        self.returns.fetch_add(1, Ordering::SeqCst);
    }
}

enum Observer {
    Typed(SharedOperationalCause<PrepaidFailure>),
    Api(LifecycleBackendConstructionError),
}

impl Observer {
    fn close(self) {
        match self {
            Self::Typed(cause) => drop(cause),
            Self::Api(error) => drop(error),
        }
    }
}

struct Fixture {
    accounts: [HostServiceAllocator; 2],
    returns: Arc<AtomicUsize>,
    bytes: u64,
    allocation: AllocationIdentity,
    typed: Option<SharedOperationalCause<PrepaidFailure>>,
    error: LifecycleBackendConstructionError,
}

fn fixture(
    make: impl FnOnce(
        PrepaidFailure,
    ) -> (
        Option<SharedOperationalCause<PrepaidFailure>>,
        LifecycleBackendConstructionError,
    ),
) -> Fixture {
    let accounts = [
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
    ];
    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<PrepaidFailure>())
        .unwrap();
    let layout = layout.pad_to_align();
    let bytes = u64::try_from(layout.size()).unwrap();
    let credit = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, bytes).unwrap(),
        accounts[1].reserve_resources(0, 0, bytes).unwrap(),
    );
    let returns = Arc::new(AtomicUsize::new(0));
    let payload = PrepaidFailure {
        returns: Arc::clone(&returns),
        _credit: credit,
    };
    let ((typed, error), allocation, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || make(payload));

    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(error.source().unwrap().is::<PrepaidFailure>());
    assert_eq!(error.to_string(), "original paired lifecycle failure");

    Fixture {
        accounts,
        returns,
        bytes,
        allocation: allocation.unwrap(),
        typed,
        error,
    }
}

#[test]
fn lifecycle_error_frees_its_control_before_returning_original_paired_credit() {
    let Fixture {
        accounts,
        returns,
        bytes,
        allocation,
        typed,
        error,
    } = fixture(|cause| (None, LifecycleBackendConstructionError::new(cause)));
    assert!(typed.is_none());
    let last = error.clone();
    assert_eq!(error, last);

    drop(error);
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
    assert_returned(&accounts);
}

#[test]
fn mixed_typed_and_lifecycle_observers_close_once_before_the_paired_refund() {
    let Fixture {
        accounts,
        returns,
        bytes,
        allocation,
        typed,
        error,
    } = fixture(|cause| {
        let typed = SharedOperationalCause::new(cause);
        let error = LifecycleBackendConstructionError::from_operational(typed.backend_cause());
        (Some(typed), error)
    });
    let typed = typed.unwrap();
    assert!(std::ptr::eq(
        typed.source_ref(),
        error
            .source()
            .unwrap()
            .downcast_ref::<PrepaidFailure>()
            .unwrap(),
    ));
    let typed_observers: Vec<_> = (0..4).map(|_| typed.clone()).collect();
    let api_observers: Vec<_> = (0..4).map(|_| error.clone()).collect();
    let barrier = std::sync::Barrier::new(8);
    drop((typed, error));

    let observations = std::thread::scope(|scope| {
        let workers: Vec<_> = typed_observers
            .into_iter()
            .map(Observer::Typed)
            .chain(api_observers.into_iter().map(Observer::Api))
            .map(|observer| {
                let accounts = &accounts;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let ((), observed) = TestAllocationObserver::observe_controls(
                        [&accounts[0], &accounts[1]],
                        None,
                        [Some(allocation), None, None],
                        || observer.close(),
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
    assert_returned(&accounts);
}

fn assert_returned(accounts: &[HostServiceAllocator; 2]) {
    for account in accounts {
        drop(
            account
                .reserve_resources(0, 0, account.maximum_resident_bytes())
                .unwrap(),
        );
    }
}
