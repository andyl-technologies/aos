//! Actual checked Packed fence allocation and external original-credit controls.
//!
//! The runner, directory and fixed observer are outside the finite model. The
//! actual fence, native descriptors and index buffers use one 4 MiB/8 FD bank.
//! Before-System sampling proves the targeted control tail, not whole funding.

// crucible-lint: allow panic-shortcut -- fixture failures and deliberate owner unwind must stop this allocation control.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{PackedBlobBackend, StorePhysicalQuotaGuard};
use crate::owned_decode::DecodeBudget;
use crucible_linux_resource::test_support::{
    AllocationRosterOutcome, BeforeFreeMarkerOutcome, TestAllocationObserver,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

static WATCH: AtomicBool = AtomicBool::new(false);
static LOANS: AtomicUsize = AtomicUsize::new(0);
static FIRST_BYTES: AtomicU64 = AtomicU64::new(0);
static CLOSED: AtomicBool = AtomicBool::new(false);

struct Quota(Arc<FixtureResourceBudget>);

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let loan = self.0.reserve(descriptors, bytes)?;
        let target = WATCH.load(Ordering::SeqCst) && LOANS.fetch_add(1, Ordering::SeqCst) == 0;
        if target {
            FIRST_BYTES.store(bytes, Ordering::SeqCst);
        }
        Ok(ResourceLoan::new(ObservedLoan {
            _loan: loan,
            target,
        }))
    }
}

struct ObservedLoan {
    _loan: ResourceLoan,
    target: bool,
}

impl Drop for ObservedLoan {
    fn drop(&mut self) {
        if self.target {
            CLOSED.store(true, Ordering::SeqCst);
        }
    }
}

#[test]
fn actual_packed_inventory_box_keeps_original_credit_through_free_and_unwind() {
    let directory = tempfile::tempdir().unwrap();
    let backend =
        Arc::new(PackedBlobBackend::open("fence-control", directory.path(), 65_536).unwrap());
    let resources = Arc::new(FixtureResourceBudget::new(8, 4 * 1024 * 1024));
    let quota = Arc::new(Quota(resources.clone()));
    let physical = crate::content_store::physical_quota::PhysicalQuotaStore::new(
        "physical-fence",
        backend.clone(),
        backend.clone(),
        quota.clone(),
    )
    .unwrap();
    let original = DecodeBudget::for_store(quota).unwrap();
    let _scope = original.enter();
    let baseline = resources.usage().unwrap();

    for outer in [false, true] {
        let admin: &dyn BlobStoreAdmin = if outer { &physical } else { backend.as_ref() };
        for (unwind, wrong_order) in [(false, false), (true, false), (false, true)] {
            LOANS.store(0, Ordering::SeqCst);
            FIRST_BYTES.store(0, Ordering::SeqCst);
            CLOSED.store(false, Ordering::SeqCst);
            let (fence, roster) = TestAllocationObserver::capture_allocation_roster(|| {
                WATCH.store(true, Ordering::SeqCst);
                let result = admin.acquire_inventory_fence_with_boundary(&mut || Ok(()));
                WATCH.store(false, Ordering::SeqCst);
                result
            })
            .unwrap();
            let mut fence = fence.unwrap();
            assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
            assert!(!roster.overflow);
            assert_eq!(roster.reallocations, 0);
            let address = std::ptr::from_ref(fence.fence.as_deref().unwrap()).addr();
            let allocation = roster
                .entries()
                .find(|entry| entry.contains_address(address))
                .unwrap();
            assert_eq!(
                allocation.bytes() as u64,
                FIRST_BYTES.load(Ordering::SeqCst)
            );
            assert!(!CLOSED.load(Ordering::SeqCst));
            assert_eq!(
                resources.usage().unwrap().0 - baseline.0,
                if outer { 3 } else { 2 }
            );
            println!(
                "checked_fence_geometry outer={outer} owner={} result={} payload={} original_loan={}",
                std::mem::size_of::<CheckedInventoryFence<'_>>(),
                std::mem::size_of::<Result<CheckedInventoryFence<'_>, StoreError>>(),
                allocation.bytes(),
                FIRST_BYTES.load(Ordering::SeqCst)
            );

            let ((), outcome) = TestAllocationObserver::observe_close_marker_before_free(
                &CLOSED,
                allocation.identity(),
                || {
                    if wrong_order {
                        // Sole negative ordering delta: refund the exact original
                        // metadata loan while the same real Box still exists.
                        drop(fence._credit.take());
                        drop(fence);
                    } else if unwind {
                        let result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                                let _fence = fence;
                                panic!("intentional actual checked-fence owner unwind");
                            }));
                        assert!(result.is_err());
                    } else {
                        drop(fence);
                    }
                },
            )
            .unwrap();

            assert_eq!(
                outcome,
                if wrong_order {
                    BeforeFreeMarkerOutcome::Closed
                } else {
                    BeforeFreeMarkerOutcome::Open
                },
            );
            assert!(CLOSED.load(Ordering::SeqCst));
            assert_eq!(resources.usage().unwrap(), baseline);
            original.verify_live().unwrap();
        }
    }
}
