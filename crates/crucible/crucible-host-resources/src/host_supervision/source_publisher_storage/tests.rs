//! Observes publisher storage under actual paired mechanism charges.
//!
//! These controls issue no authenticated Main, Source or operation membership.

// crucible-lint: allow panic-shortcut -- component assertions localize actual allocation and original charge ordering failures.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crate::test_support::{AllocationIdentity, TestAllocationObserver};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
struct Body {
    dropped: Arc<AtomicBool>,
    // Distinct full allocation extent makes value and funding observations exact.
    _payload: [u8; 4096],
}

impl SourceSupervisionPublisher for Body {
    fn publish(
        &self,
        _: super::super::SourceSupervisionSnapshot,
    ) -> Result<(), super::super::HostSupervisionError> {
        Err(super::super::HostSupervisionError::Unavailable)
    }

    fn invalidate(&self) {}
}

impl Drop for Body {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct Fixture {
    owner: FundedSourcePublisher<Body>,
    accounts: [HostServiceAllocator; 2],
    identities: [Option<AllocationIdentity>; 3],
    dropped: Arc<AtomicBool>,
    bytes: u64,
}

struct RefusedBody {
    accounts: [HostServiceAllocator; 2],
    bytes: u64,
    dropped_while_funded: Arc<AtomicBool>,
}

impl Drop for RefusedBody {
    fn drop(&mut self) {
        let funded = self
            .accounts
            .iter()
            .all(|account| account.reserve_resources(0, 0, self.bytes).is_err());
        self.dropped_while_funded.store(funded, Ordering::SeqCst);
    }
}

#[test]
fn refused_publisher_closes_value_before_returning_original_charge() {
    let bytes = 4096;
    let accounts: [HostServiceAllocator; 2] =
        std::array::from_fn(|_| HostServiceAllocator::new(1, 1, bytes).unwrap());
    let charge = AllocationCharge::Component {
        _lease: HostServiceLeasePair::new(
            accounts[0].reserve_resources(0, 0, bytes).unwrap(),
            accounts[1].reserve_resources(0, 0, bytes).unwrap(),
        ),
    };
    let dropped_while_funded = Arc::new(AtomicBool::new(false));
    let body = RefusedBody {
        accounts: accounts.clone(),
        bytes,
        dropped_while_funded: dropped_while_funded.clone(),
    };

    let (result, counts) = TestAllocationObserver::count(|| {
        FundedSourcePublisher::construct_after_validation(
            body,
            charge,
            Err(HostSupervisionError::CapacityExhausted),
        )
    });

    assert!(matches!(
        result,
        Err(HostSupervisionError::CapacityExhausted)
    ));
    assert!(dropped_while_funded.load(Ordering::SeqCst));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    verify_refunded(&accounts, bytes);
}

fn fixture() -> Fixture {
    let bytes = FundedSourcePublisher::<Body>::allocation_bytes().unwrap() as u64;
    let accounts: [HostServiceAllocator; 2] =
        std::array::from_fn(|_| HostServiceAllocator::new(1, 1, bytes).unwrap());
    let pair = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, bytes).unwrap(),
        accounts[1].reserve_resources(0, 0, bytes).unwrap(),
    );
    let dropped = Arc::new(AtomicBool::new(false));
    let body = Body {
        dropped: dropped.clone(),
        _payload: [0; 4096],
    };
    let header = Layout::new::<[AtomicUsize; 2]>();
    let (value, _) = header.extend(Layout::new::<Body>()).unwrap();
    let (funding, _) = header.extend(Layout::new::<AllocationCharge>()).unwrap();
    let (owner, identities) = TestAllocationObserver::capture_controls(
        [
            value.pad_to_align().size(),
            funding.pad_to_align().size(),
            0,
        ],
        || FundedSourcePublisher::component(body, pair),
    );
    assert!(identities[0].is_some());
    assert!(identities[1].is_some());

    Fixture {
        owner,
        accounts,
        identities,
        dropped,
        bytes,
    }
}

fn verify_charged(fixture: &Fixture) {
    for account in &fixture.accounts {
        assert!(account.reserve_resources(0, 0, fixture.bytes).is_err());
    }
}

fn verify_refunded(accounts: &[HostServiceAllocator; 2], bytes: u64) {
    for account in accounts {
        assert!(account.reserve_resources(0, 0, bytes).is_ok());
    }
}

#[test]
fn final_publisher_and_funding_allocations_close_before_original_refund() {
    let fixture = fixture();
    let Fixture {
        owner,
        accounts,
        identities,
        dropped,
        bytes,
    } = fixture;
    let (_, observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        identities,
        || drop(owner),
    );

    assert!(dropped.load(Ordering::SeqCst));
    for observation in observations[..2].iter().flatten() {
        assert_eq!(observation.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observation.after.original_bytes, [Some(bytes); 2]);
    }
    assert!(observations[0].is_some());
    assert!(observations[1].is_some());
    verify_refunded(&accounts, bytes);
}

#[test]
fn dead_publisher_weak_retains_complete_storage_charge_until_actual_free() {
    let fixture = fixture();
    let weak = fixture.owner.downgrade();
    let other = weak.clone();
    let Fixture {
        owner,
        accounts,
        identities,
        dropped,
        bytes,
    } = fixture;
    drop(owner);

    assert!(dropped.load(Ordering::SeqCst));
    assert!(weak.upgrade().is_none());
    for account in &accounts {
        assert!(account.reserve_resources(0, 0, bytes).is_err());
    }
    drop(weak);
    let (_, observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        identities,
        || drop(other),
    );

    for observation in observations[..2].iter() {
        let observation = observation.unwrap();
        assert_eq!(observation.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observation.after.original_bytes, [Some(bytes); 2]);
    }
    verify_refunded(&accounts, bytes);
}

#[test]
fn publisher_upgrade_and_cloning_allocate_nothing_and_retain_same_charge() {
    let fixture = fixture();
    let weak = fixture.owner.downgrade();
    let ((strong, borrowed_weak), counts) =
        TestAllocationObserver::count(|| (weak.upgrade().unwrap(), weak.clone()));

    assert!(fixture.owner.same_owner(&strong));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    verify_charged(&fixture);
    drop(strong);
    drop(borrowed_weak);
    drop(weak);
    drop(fixture.owner);
    verify_refunded(&fixture.accounts, fixture.bytes);
}

#[test]
fn concurrent_publisher_observers_return_one_original_charge_after_join() {
    let fixture = fixture();
    let weak = fixture.owner.downgrade();
    let borrowers: Vec<_> = (0..8).map(|_| fixture.owner.clone()).collect();
    drop(fixture.owner);

    std::thread::scope(|scope| {
        for borrower in borrowers {
            scope.spawn(move || drop(borrower));
        }
    });
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert!(weak.upgrade().is_none());
    for account in &fixture.accounts {
        assert!(account.reserve_resources(0, 0, fixture.bytes).is_err());
    }
    drop(weak);
    verify_refunded(&fixture.accounts, fixture.bytes);
}

#[test]
fn erased_standing_and_weak_observers_keep_the_same_original_allocation() {
    let fixture = fixture();
    let standing = fixture.owner.standing();
    let weak = standing.downgrade();
    let (copy, counts) = TestAllocationObserver::count(|| standing.clone());
    assert!(copy.same_owner(&standing));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    drop(fixture.owner);

    assert!(!fixture.dropped.load(Ordering::SeqCst));
    assert!(weak.upgrade().unwrap().same_owner(&standing));
    drop(copy);
    drop(standing);
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert!(weak.upgrade().is_none());
    for account in &fixture.accounts {
        assert!(account.reserve_resources(0, 0, fixture.bytes).is_err());
    }
    drop(weak);
    verify_refunded(&fixture.accounts, fixture.bytes);
}

#[test]
fn publisher_unwind_closes_both_allocations_before_refunding_original_charge() {
    let Fixture {
        owner,
        accounts,
        identities,
        dropped,
        bytes,
    } = fixture();
    let (result, observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        identities,
        || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _held = owner;
                panic!("unwind through the actual publisher owner");
            }))
        },
    );

    assert!(result.is_err());
    assert!(dropped.load(Ordering::SeqCst));
    for observation in observations[..2].iter() {
        let observation = observation.unwrap();
        assert_eq!(observation.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observation.after.original_bytes, [Some(bytes); 2]);
    }
    verify_refunded(&accounts, bytes);
}

#[test]
fn publisher_recipe_covers_both_actual_allocations_and_funding_constructor() {
    let bytes = FundedSourcePublisher::<Body>::allocation_bytes().unwrap();
    let accounts: [HostServiceAllocator; 2] =
        std::array::from_fn(|_| HostServiceAllocator::new(1, 1, bytes as u64).unwrap());
    let pair = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, bytes as u64).unwrap(),
        accounts[1].reserve_resources(0, 0, bytes as u64).unwrap(),
    );
    let body = Body {
        dropped: Arc::new(AtomicBool::new(false)),
        _payload: [0; 4096],
    };
    let (owner, events) = TestAllocationObserver::capture_allocation_events(|| {
        FundedSourcePublisher::component(body, pair)
    })
    .unwrap();

    assert!(!events.overflow);
    assert_eq!(events.reallocations, 0);
    let allocated: Vec<_> = events.entries().filter(|event| event.allocated).collect();
    assert_eq!(allocated.len(), 2);
    assert_eq!(events.count, 2);
    let actual_bytes: usize = allocated.iter().map(|event| event.bytes).sum();
    assert!(bytes >= actual_bytes + std::mem::size_of::<AllocationCharge>());
    assert!(allocated.iter().any(|event| event.bytes > 4096));

    drop(owner);
    verify_refunded(&accounts, bytes as u64);
}
