//! Observes allocation-close ordering for an actual owning checked reader.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_cas::content_store::{BlobHandle, BlobSource, StoreError, StorePhysicalQuotaGuard};
use crucible_cas::owned_decode::DecodeBudget;

const OBSERVATION_CAPACITY: usize = 64;
static WATCH: AtomicBool = AtomicBool::new(false);
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static ADDRESSES: [AtomicUsize; OBSERVATION_CAPACITY] =
    [const { AtomicUsize::new(0) }; OBSERVATION_CAPACITY];
static SIZES: [AtomicUsize; OBSERVATION_CAPACITY] =
    [const { AtomicUsize::new(0) }; OBSERVATION_CAPACITY];
static LOAN_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAN_SIZES: [AtomicUsize; OBSERVATION_CAPACITY] =
    [const { AtomicUsize::new(0) }; OBSERVATION_CAPACITY];
static TARGET_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static TARGET_LOAN: AtomicUsize = AtomicUsize::new(usize::MAX);
static LOAN_CLOSED: AtomicBool = AtomicBool::new(false);
static DEALLOCATION_OBSERVED: AtomicBool = AtomicBool::new(false);
static FUNDED_AT_DEALLOCATION: AtomicBool = AtomicBool::new(false);

struct ObservingAllocator;

// SAFETY: Allocation and deallocation delegate unchanged pointer/layout pairs
// to System. Observation uses fixed atomics, cannot allocate or panic, and
// reads no allocated storage. Only the bound target pointer affects assertions.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies a valid allocation layout.
        let allocation = unsafe { System.alloc(layout) };
        if !allocation.is_null() && WATCH.load(Ordering::SeqCst) {
            let index = ALLOCATION_COUNT.fetch_add(1, Ordering::SeqCst);
            if index < OBSERVATION_CAPACITY {
                ADDRESSES[index].store(allocation.addr(), Ordering::SeqCst);
                SIZES[index].store(layout.size(), Ordering::SeqCst);
            }
        }
        allocation
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let target = TARGET_ADDRESS.load(Ordering::SeqCst);
        if target != 0
            && pointer.addr() == target
            && DEALLOCATION_OBSERVED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            FUNDED_AT_DEALLOCATION.store(!LOAN_CLOSED.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        // SAFETY: The caller supplies the live pointer and its original layout;
        // observation above neither changes nor dereferences that allocation.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

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
    TARGET_ADDRESS.store(0, Ordering::SeqCst);
    TARGET_LOAN.store(usize::MAX, Ordering::SeqCst);
    ALLOCATION_COUNT.store(0, Ordering::SeqCst);
    LOAN_COUNT.store(0, Ordering::SeqCst);
    LOAN_CLOSED.store(false, Ordering::SeqCst);
    DEALLOCATION_OBSERVED.store(false, Ordering::SeqCst);
    FUNDED_AT_DEALLOCATION.store(false, Ordering::SeqCst);
}

#[test]
fn owning_reader_box_closes_before_its_exact_original_loan_on_drop_and_unwind()
-> Result<(), Box<dyn std::error::Error>> {
    for unwind in [false, true] {
        reset_observation();
        let caller = DecodeBudget::for_store(Arc::new(Quota))?;
        let handle = BlobHandle::from_bytes([7]);

        WATCH.store(true, Ordering::SeqCst);
        let reader = BlobSource::open_with_boundary(&handle, &caller, &mut || Ok(()))?;
        WATCH.store(false, Ordering::SeqCst);

        // The account reference is an actual field of the outer HandleReader.
        // Containment identifies its Box without exposing a production pointer.
        let account_address = std::ptr::from_ref(reader.original_account()).addr();
        let allocation_count = ALLOCATION_COUNT.load(Ordering::SeqCst);
        let loan_count = LOAN_COUNT.load(Ordering::SeqCst);
        assert!(allocation_count <= OBSERVATION_CAPACITY);
        assert!(loan_count <= OBSERVATION_CAPACITY);
        let allocation = (0..allocation_count)
            .find(|&index| {
                let start = ADDRESSES[index].load(Ordering::SeqCst);
                let bytes = SIZES[index].load(Ordering::SeqCst);
                start <= account_address && account_address - start < bytes
            })
            .ok_or("original account lies outside the observed outer reader Box")?;
        let bytes = SIZES[allocation].load(Ordering::SeqCst);
        let loans: Vec<_> = (0..loan_count)
            .filter(|&index| LOAN_SIZES[index].load(Ordering::SeqCst) == bytes)
            .collect();
        assert_eq!(loans.len(), 1, "one exact original loan funds this Box");
        TARGET_LOAN.store(loans[0], Ordering::SeqCst);
        TARGET_ADDRESS.store(
            ADDRESSES[allocation].load(Ordering::SeqCst),
            Ordering::SeqCst,
        );

        if unwind {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _reader = reader;
                panic!("intentional reader-owner unwind");
            }));
            assert!(result.is_err());
        } else {
            drop(reader);
        }
        TARGET_ADDRESS.store(0, Ordering::SeqCst);

        assert!(DEALLOCATION_OBSERVED.load(Ordering::SeqCst));
        assert!(FUNDED_AT_DEALLOCATION.load(Ordering::SeqCst));
        assert!(LOAN_CLOSED.load(Ordering::SeqCst));
        drop(caller);
        drop(handle);
    }
    Ok(())
}
