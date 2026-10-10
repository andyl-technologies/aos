//! Observes allocation-close ordering for an actual owning checked reader.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_cas::content_store::{BlobHandle, BlobSource, StoreError, StorePhysicalQuotaGuard};
use crucible_cas::owned_decode::DecodeBudget;
use crucible_linux_resource::test_support::{
    AllocationRosterOutcome, BeforeFreeMarkerOutcome, TestAllocationObserver,
};

const OBSERVATION_CAPACITY: usize = 64;
static WATCH: AtomicBool = AtomicBool::new(false);
static LOAN_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAN_SIZES: [AtomicUsize; OBSERVATION_CAPACITY] =
    [const { AtomicUsize::new(0) }; OBSERVATION_CAPACITY];
static TARGET_LOAN: AtomicUsize = AtomicUsize::new(usize::MAX);
static LOAN_CLOSED: AtomicBool = AtomicBool::new(false);

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Loan {
    observed_index: Option<usize>,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.observed_index == Some(TARGET_LOAN.load(Ordering::SeqCst)) {
            LOAN_CLOSED.store(true, Ordering::SeqCst);
        }
    }
}

struct Quota;

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(
        &self,
        _descriptors: u64,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        let observed_index = if WATCH.load(Ordering::SeqCst) {
            let index = LOAN_COUNT.fetch_add(1, Ordering::SeqCst);
            if index < OBSERVATION_CAPACITY {
                LOAN_SIZES[index].store(bytes as usize, Ordering::SeqCst);
            }
            Some(index)
        } else {
            None
        };
        Ok(crucible_cas::owned_decode::ResourceLoan::new(Loan {
            observed_index,
        }))
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

fn reset_observation() {
    WATCH.store(false, Ordering::SeqCst);
    TARGET_LOAN.store(usize::MAX, Ordering::SeqCst);
    LOAN_COUNT.store(0, Ordering::SeqCst);
    LOAN_CLOSED.store(false, Ordering::SeqCst);
}

#[test]
fn owning_reader_box_closes_before_its_exact_original_loan_on_drop_and_unwind()
-> Result<(), Box<dyn std::error::Error>> {
    for unwind in [false, true] {
        reset_observation();
        let caller = DecodeBudget::for_store(Arc::new(Quota))?;
        let handle = BlobHandle::from_bytes([7]);

        let (reader, roster) = TestAllocationObserver::capture_allocation_roster(|| {
            WATCH.store(true, Ordering::SeqCst);
            let reader = BlobSource::open_with_boundary(&handle, &caller, &mut || Ok(()));
            WATCH.store(false, Ordering::SeqCst);
            reader
        })?;
        let reader = reader?;
        assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
        assert!(!roster.overflow);
        assert_eq!(roster.reallocations, 0);

        // The account reference is an actual field of the outer HandleReader.
        // Containment identifies its Box without exposing a production pointer.
        let account_address = std::ptr::from_ref(reader.original_account()).addr();
        let allocation_count = roster.allocations;
        let loan_count = LOAN_COUNT.load(Ordering::SeqCst);
        assert!(allocation_count <= OBSERVATION_CAPACITY);
        assert!(loan_count <= OBSERVATION_CAPACITY);
        let allocation = roster
            .entries()
            .find(|entry| entry.contains_address(account_address))
            .ok_or("original account lies outside the observed outer reader Box")?;
        let bytes = allocation.bytes();
        let loans: Vec<_> = (0..loan_count)
            .filter(|&index| LOAN_SIZES[index].load(Ordering::SeqCst) == bytes)
            .collect();
        assert_eq!(loans.len(), 1, "one exact original loan funds this Box");
        TARGET_LOAN.store(loans[0], Ordering::SeqCst);
        let ((), outcome) = TestAllocationObserver::observe_close_marker_before_free(
            &LOAN_CLOSED,
            allocation.identity(),
            || {
                if unwind {
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            let _reader = reader;
                            panic!("intentional reader-owner unwind");
                        }));
                    assert!(result.is_err());
                } else {
                    drop(reader);
                }
            },
        )?;

        assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
        assert!(LOAN_CLOSED.load(Ordering::SeqCst));
        drop(caller);
        drop(handle);
    }
    Ok(())
}
