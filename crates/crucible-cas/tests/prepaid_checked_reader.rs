//! Original prepayment and real Box-close ordering for custom checked readers.

use std::alloc::Layout;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_cas::content_store::{
    CheckedBlobReader, CheckedReader, StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, ResourceLoan};
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease,
};
use crucible_linux_resource::test_support::{BeforeFreeMarkerOutcome, TestAllocationObserver};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static SERIAL: Mutex<()> = Mutex::new(());
static WATCH: AtomicBool = AtomicBool::new(false);
static LOAN_CLOSED: AtomicBool = AtomicBool::new(false);

struct Loan {
    _lease: HostServiceLease,
    watched: bool,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.watched {
            LOAN_CLOSED.store(true, Ordering::SeqCst);
        }
    }
}

struct Quota(HostServiceAllocator);

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let lease = self
            .0
            .reserve_resources(0, descriptors, bytes)
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(Loan {
            _lease: lease,
            watched: WATCH.load(Ordering::SeqCst) && bytes == std::mem::size_of::<Reader>() as u64,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
enum OriginalFixtureError {
    #[error(transparent)]
    Allocator(#[from] HostServiceError),
    #[error(transparent)]
    Admission(#[from] DecodeAdmissionError),
}

fn original() -> Result<DecodeBudget, OriginalFixtureError> {
    // This finite component model observes the wrapper loan, not native quota
    // installation or the independent allocator/authority constructor costs.
    let allocator = HostServiceAllocator::new(1, 8, 4 * 1024 * 1024)?;
    Ok(DecodeBudget::for_store(Arc::new(Quota(allocator)))?)
}

struct Reader {
    original: DecodeBudget,
    _padding: [u8; 64],
}

impl Reader {
    fn new(original: &DecodeBudget) -> Self {
        Self {
            original: original.clone(),
            _padding: [0; 64],
        }
    }
}

impl CheckedBlobReader for Reader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        _: &mut [u8],
        _: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        panic!("this control-lifetime witness does not read or grant EOF identity")
    }
}

#[test]
fn exact_original_loan_survives_actual_reader_box_free_normal_and_unwind() {
    let _serial = SERIAL.lock().unwrap();
    for unwind in [false, true] {
        WATCH.store(false, Ordering::SeqCst);
        LOAN_CLOSED.store(false, Ordering::SeqCst);
        let original = original().unwrap();
        let (reader, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(Layout::new::<Reader>(), || {
                WATCH.store(true, Ordering::SeqCst);
                let reader = CheckedReader::new_prepaid(Reader::new(&original), &original);
                WATCH.store(false, Ordering::SeqCst);
                reader
            });
        let reader = reader.unwrap();
        assert!(!counts.overflow);
        assert_eq!(counts.reallocations, 0);
        assert!(!LOAN_CLOSED.load(Ordering::SeqCst));
        let identity = identity.expect("capture the actual concrete reader Box");
        let ((), outcome) = TestAllocationObserver::observe_close_marker_before_free(
            &LOAN_CLOSED,
            identity,
            || {
                if unwind {
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            let _reader = reader;
                            panic!("intentional custom reader unwind");
                        }));
                    assert!(result.is_err());
                } else {
                    drop(reader);
                }
            },
        )
        .unwrap();
        assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
        assert!(LOAN_CLOSED.load(Ordering::SeqCst));
        original.verify_live().unwrap();
    }
}

#[test]
fn a_different_or_poisoned_original_refuses_before_reader_box_allocation() {
    let _serial = SERIAL.lock().unwrap();
    let first = original().unwrap();
    let other = original().unwrap();
    let (result, identity, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<Reader>(), || {
            CheckedReader::new_prepaid(Reader::new(&first), &other)
        });
    assert!(matches!(result, Err(StoreError::InvalidComposition { .. })));
    assert!(identity.is_none());

    let refusal = DecodeAdmissionError::new(StoreError::Quota);
    first.record_failure(refusal.clone());
    let (result, identity, _) =
        TestAllocationObserver::capture_layout_and_count(Layout::new::<Reader>(), || {
            CheckedReader::new_prepaid(Reader::new(&first), &first)
        });
    let Err(StoreError::DecodeAdmission { source, .. }) = result else {
        panic!("retain the actual first refusal")
    };
    assert_eq!(source, refusal);
    assert!(identity.is_none());
    other.verify_live().unwrap();
}
