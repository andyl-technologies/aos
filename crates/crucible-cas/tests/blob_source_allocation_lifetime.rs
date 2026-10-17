//! Concrete source allocation closure under its original finite resource loan.

use crucible_cas::content_store::{BlobHandle, BlobSource, StoreError};
use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScratch, ResourceLoan,
};
use std::alloc::Layout;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_linux_resource::test_support::{
    OriginalControlSelection, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};

static USED: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);
static EXTENT: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Credit(usize);

impl Drop for Credit {
    fn drop(&mut self) {
        USED.fetch_sub(self.0, Ordering::SeqCst);
    }
}

struct Authority;

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        let bytes = usize::try_from(bytes)
            .map_err(|_| DecodeAdmissionError::new(std::io::Error::from_raw_os_error(12)))?;
        // This test authority also pays its own loan allocation before creating
        // it. Only the separately identified source control is observed below.
        let total = bytes
            .checked_add(ResourceLoan::allocation_bytes::<Credit>() as usize)
            .ok_or_else(|| DecodeAdmissionError::new(std::io::Error::from_raw_os_error(12)))?;
        USED.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
            used.checked_add(total).filter(|next| *next <= 4096)
        })
        .map_err(|_| DecodeAdmissionError::new(std::io::Error::from_raw_os_error(12)))?;
        Ok(ResourceLoan::new(Credit(total)))
    }
}

struct Source {
    panic_on_length: bool,
    _credit: DecodeScratch,
}

impl BlobSource for Source {
    fn logical_length(&self) -> u64 {
        assert!(!self.panic_on_length, "source callback unwind");
        0
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        Ok(Box::new(std::io::empty()))
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn source_control_closes_before_credit_on_drop_callback_unwind_and_concurrent_last_aliases() {
    let extent = BlobHandle::source_allocation_bytes::<Source>() as usize;
    EXTENT.store(extent, Ordering::SeqCst);

    for mode in ["reference", "drop", "callback-unwind", "concurrent"] {
        assert_eq!(USED.load(Ordering::SeqCst), 0);
        let original = DecodeBudget::new(Arc::new(Authority), 4096).unwrap();
        let baseline = USED.load(Ordering::SeqCst);
        BASELINE.store(baseline, Ordering::SeqCst);
        let credit = original.reserve_scratch_bytes(extent as u64).unwrap();
        let source = Source {
            panic_on_length: mode == "callback-unwind",
            _credit: credit,
        };

        DROPS.store(0, Ordering::SeqCst);
        let layout = Layout::from_size_align(extent, std::mem::align_of::<Source>()).unwrap();
        let ((identity, counts), report) =
            TestAllocationObserver::observe_original_controls(|session| {
                session
                    .arm(
                        OriginalControlSlot::First,
                        OriginalControlSelection::FirstThreadExtent(
                            NonZeroUsize::new(extent).unwrap(),
                        ),
                        OriginalStaticCounters::UsageAndDrops {
                            used: &USED,
                            baseline: &BASELINE,
                            extent: &EXTENT,
                            drops: &DROPS,
                        },
                        false,
                    )
                    .unwrap();
                if mode == "reference" {
                    let (reference, identity, counts) =
                        TestAllocationObserver::capture_layout_and_count(layout, || {
                            let reference: Arc<dyn BlobSource> = Arc::new(source);
                            reference
                        });
                    drop(reference);
                    (identity, counts)
                } else if mode == "callback-unwind" {
                    // The original callback stops only constructor counting.
                    // Actual unwind closes the selected source while its watch
                    // and original usage/drop counters remain armed.
                    struct CallbackSource(Source);
                    impl BlobSource for CallbackSource {
                        fn logical_length(&self) -> u64 {
                            TestAllocationObserver::pause_allocation_count();
                            self.0.logical_length()
                        }

                        fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
                            self.0.open()
                        }
                    }
                    let (result, identity, counts) =
                        TestAllocationObserver::capture_layout_and_count(layout, || {
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                let _handle = BlobHandle::new(CallbackSource(source));
                            }))
                        });
                    assert!(result.is_err());
                    (identity, counts)
                } else {
                    let (handle, identity, counts) =
                        TestAllocationObserver::capture_layout_and_count(layout, || {
                            BlobHandle::new(source)
                        });
                    if mode == "concurrent" {
                        let first = handle.clone();
                        let second = handle.clone();
                        drop(handle);
                        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
                        std::thread::scope(|scope| {
                            scope.spawn(move || drop(first));
                            scope.spawn(move || drop(second));
                        });
                    } else {
                        drop(handle);
                    }
                    (identity, counts)
                }
            })
            .unwrap();

        assert_eq!(counts.allocations, 1, "{mode}");
        assert_eq!(counts.reallocations, 0, "{mode}");
        assert!(!counts.overflow, "{mode}");
        assert_eq!(report.outcome, OriginalControlsOutcome::Complete, "{mode}");
        let observed = report.controls[0].unwrap();
        assert_eq!(Some(observed.identity), identity, "{mode}");
        let OriginalControlSnapshot::UsageAndDrops {
            used,
            baseline: sampled_baseline,
            extent: sampled_extent,
            drops,
        } = observed.before
        else {
            panic!("actual original source usage and drop sample missing");
        };
        assert_eq!(sampled_baseline, baseline, "{mode}");
        assert_eq!(sampled_extent, extent, "{mode}");
        assert_eq!(DROPS.load(Ordering::SeqCst), 1, "{mode}");
        if mode == "reference" {
            assert!(used < baseline + extent, "{mode}");
            assert_ne!(drops, 0, "{mode}");
        } else {
            assert!(used >= baseline + extent, "{mode}");
            assert_eq!(drops, 0, "{mode}");
        }
        assert_eq!(USED.load(Ordering::SeqCst), baseline, "{mode}");
        drop(original);
        assert_eq!(USED.load(Ordering::SeqCst), 0, "{mode}");
    }

    println!(
        "source body={} alignment={} allocation={} reference_allocations=1 terminal_allocations=1",
        std::mem::size_of::<Source>(),
        std::mem::align_of::<Source>(),
        extent,
    );
}
