//! Observes real roster allocation closure under independent paired funding.
//!
//! The private component publisher pays actual storage with mechanism pairs.
//! It cannot authenticate a Main, Source, installed process or native action.

use super::*;
use super::super::{OriginalNativeAccountCredit, OriginalNativeAccountRoster};
use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use crucible_host_resources::test_support::{AllocationIdentity, TestAllocationObserver};

struct Fixture {
    roster: OriginalNativeAccountRoster,
    binding: super::super::OriginalNativeAccountFactoryBinding,
    accounts: [HostServiceAllocator; 2],
    bytes: u64,
    allocation: AllocationIdentity,
    native: [HostServiceAllocator; 2],
    _supervisor: HostOperationSupervisor,
}

fn fixture() -> Fixture {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let (credit, resident, metadata) =
        OriginalNativeAccountCredit::mechanism_credit(original).unwrap();
    let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<Mutex<NativeRoster>>())
        .unwrap();
    let layout = layout.pad_to_align();
    // The extra control allowance also covers the funding token's own storage.
    let bytes = layout.size() as u64 + 4096;
    let accounts = std::array::from_fn(|_| HostServiceAllocator::new(1, 1, bytes).unwrap());
    let funding = NativeRosterAllocationFunding::component_payer(HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, bytes).unwrap(),
        accounts[1].reserve_resources(0, 0, bytes).unwrap(),
    ));
    let ((roster, binding), allocation, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            OriginalNativeAccountRoster::publish_allocated(
                [Some(credit), None, None, None],
                1,
                Some(funding),
            )
        });
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    Fixture {
        roster,
        binding,
        accounts,
        bytes,
        allocation: allocation.unwrap(),
        native: [resident, metadata],
        _supervisor: supervisor,
    }
}

#[test]
fn funded_roster_returns_native_body_credit_while_weak_allocation_stays_paid() {
    let mut fixture = fixture();
    fixture.roster.try_close().unwrap();

    assert!(fixture.roster.is_physically_returned());
    assert!(fixture.binding.roster.upgrade().is_none());
    drop(
        OriginalNativeAccountCredit::reserve_mechanism_pair(&fixture.native[0], &fixture.native[1])
            .unwrap(),
    );
    assert!(
        fixture.accounts[0]
            .reserve_resources(0, 0, fixture.bytes)
            .is_err()
    );

    let ((), observations) = TestAllocationObserver::observe_controls(
        [&fixture.accounts[0], &fixture.accounts[1]],
        None,
        [Some(fixture.allocation), None, None],
        || drop(fixture.binding),
    );
    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(fixture.bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(fixture.bytes); 2]);
    for account in fixture.accounts {
        assert!(account.reserve_resources(0, 0, fixture.bytes).is_ok());
    }
}

#[test]
fn real_strong_borrow_refuses_retirement_without_sealing_later_cleanup() {
    let mut fixture = fixture();
    let borrower = fixture.binding.roster.upgrade().unwrap();
    assert!(fixture.roster.try_close().is_err());
    assert!(fixture.binding.roster.upgrade().is_some());
    assert!(
        OriginalNativeAccountCredit::reserve_mechanism_pair(&fixture.native[0], &fixture.native[1])
            .is_err()
    );

    drop(borrower);
    fixture.roster.try_close().unwrap();
    assert!(fixture.binding.roster.upgrade().is_none());
}

#[test]
fn live_native_slot_refuses_retirement_without_sealing_its_physical_cleanup() {
    let mut fixture = fixture();
    let attempt = fixture.binding.claim(1, 512 << 20, 1 << 30).unwrap();
    assert!(fixture.roster.try_close().is_err());
    assert!(attempt.roster.upgrade().is_some());

    let cleanup = attempt.cleanup().unwrap();
    drop(cleanup);
    attempt.close_vector().unwrap();
    fixture.roster.try_close().unwrap();
    assert!(fixture.binding.roster.upgrade().is_none());
}

#[test]
fn weak_clones_allocate_nothing_and_keep_charge_through_last_real_free() {
    let mut fixture = fixture();
    let (last, counts) = TestAllocationObserver::count(|| fixture.binding.roster.clone());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    fixture.roster.try_close().unwrap();
    drop(fixture.binding);
    assert!(
        fixture.accounts[0]
            .reserve_resources(0, 0, fixture.bytes)
            .is_err()
    );

    let ((), observations) = TestAllocationObserver::observe_controls(
        [&fixture.accounts[0], &fixture.accounts[1]],
        None,
        [Some(fixture.allocation), None, None],
        || drop(last),
    );
    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(fixture.bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(fixture.bytes); 2]);
}

#[test]
fn active_upgrade_gate_refuses_retirement_and_preserves_native_credit() {
    let mut fixture = fixture();
    let funding = fixture.binding.roster.funding.as_ref().unwrap().clone();
    let gate = funding.try_open().unwrap();
    assert!(fixture.roster.try_close().is_err());
    assert!(
        OriginalNativeAccountCredit::reserve_mechanism_pair(&fixture.native[0], &fixture.native[1])
            .is_err()
    );
    drop(gate);
    fixture.roster.try_close().unwrap();
}

#[test]
fn sealed_retirement_excludes_real_weak_upgrade_before_sole_body_drop() {
    let accounts =
        std::array::from_fn::<_, 2, _>(|_| HostServiceAllocator::new(1, 1, 1 << 20).unwrap());
    let funding = NativeRosterAllocationFunding::component_payer(HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, 1 << 20).unwrap(),
        accounts[1].reserve_resources(0, 0, 1 << 20).unwrap(),
    ));
    let (mut roster, binding) =
        OriginalNativeAccountRoster::publish_allocated([None, None, None, None], 0, Some(funding));

    roster
        .held
        .as_mut()
        .unwrap()
        .retire_body(
            |_| Ok(()),
            |_| {
                assert!(binding.roster.upgrade().is_none());
            },
        )
        .unwrap();
    drop(roster.held.take());
    assert!(binding.roster.upgrade().is_none());
    assert!(accounts[0].reserve_resources(0, 0, 1 << 20).is_err());
    drop(binding);
    for account in accounts {
        assert!(account.reserve_resources(0, 0, 1 << 20).is_ok());
    }
}

#[test]
fn sole_roster_owner_keeps_main_allocation_charge_through_actual_deallocation() {
    let mut fixture = fixture();
    drop(fixture.binding);
    let (result, observations) = TestAllocationObserver::observe_controls(
        [&fixture.accounts[0], &fixture.accounts[1]],
        None,
        [Some(fixture.allocation), None, None],
        || fixture.roster.try_close(),
    );

    result.unwrap();
    let observed = observations[0].unwrap();
    assert_eq!(observed.before.original_bytes, [Some(fixture.bytes); 2]);
    assert_eq!(observed.after.original_bytes, [Some(fixture.bytes); 2]);
    for account in fixture.accounts {
        assert!(account.reserve_resources(0, 0, fixture.bytes).is_ok());
    }
}
