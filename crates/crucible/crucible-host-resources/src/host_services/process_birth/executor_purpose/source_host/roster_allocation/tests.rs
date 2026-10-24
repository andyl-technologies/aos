//! Exercises allocation-only funding and its real exclusion gate.
//!
//! Mechanism pairs here issue no authenticated Main or native subdivision.

use super::*;
use crate::host_services::HostServiceAllocator;

fn fixture() -> ([HostServiceAllocator; 2], NativeRosterAllocationFunding) {
    let accounts = std::array::from_fn(|_| HostServiceAllocator::new(1, 1, 4096).unwrap());
    let pair = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, 4096).unwrap(),
        accounts[1].reserve_resources(0, 0, 4096).unwrap(),
    );
    (
        accounts,
        NativeRosterAllocationFunding::component_payer(pair),
    )
}

#[test]
fn sealed_roster_funding_excludes_all_later_upgrade_intervals() {
    let (accounts, funding) = fixture();
    let observer = funding.clone();
    let gate = funding.try_open().unwrap();
    assert!(observer.try_open().is_err());
    gate.seal();

    assert!(funding.try_open().is_err());
    assert!(observer.try_open().is_err());
    drop(funding);
    assert!(accounts[0].reserve_resources(0, 0, 4096).is_err());
    drop(observer);
    for account in accounts {
        assert!(account.reserve_resources(0, 0, 4096).is_ok());
    }
}

#[test]
fn poisoned_roster_upgrade_gate_retains_original_funding() {
    let (accounts, funding) = fixture();
    let observer = funding.clone();
    let result = std::thread::spawn(move || {
        let _gate = observer.try_open().unwrap();
        panic!("poison the actual allocation upgrade gate");
    })
    .join();

    assert!(result.is_err());
    assert!(funding.try_open().is_err());
    assert!(accounts[0].reserve_resources(0, 0, 4096).is_err());
    drop(funding);
    for account in accounts {
        assert!(account.reserve_resources(0, 0, 4096).is_ok());
    }
}

#[test]
fn roster_funding_prices_full_retained_allocation_and_its_control() {
    let allocation = 1 << 20;
    let extent = funding_extent(allocation).unwrap();
    let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<AllocationState>())
        .unwrap();
    assert_eq!(
        extent,
        allocation
            + layout.pad_to_align().size() as u64
            + std::mem::size_of::<AllocationState>() as u64
            + 2 * HostServiceLease::metadata_bytes()
    );
    assert!(funding_extent(0).is_err());
    assert!(funding_extent(u64::MAX).is_err());
}
