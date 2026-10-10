//! Observes original source/file credit through both concrete allocation closes.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_cas::content_store::{
    BlobHandle, BlobSource, ContentId, DirectoryBlobBackend, ImmutableBlobBackend, ObjectKind,
    StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use crucible_linux_resource::test_support::{
    AllocationRosterOutcome, AllocationTrace, GlobalAllocationTraceSession,
    OriginalControlSelection, OriginalControlSession, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};

const CAPACITY: usize = 32;
const LIMIT: usize = 8 * 1024 * 1024;
static WATCH: AtomicBool = AtomicBool::new(false);
static TRACE: AllocationTrace<CAPACITY> = AllocationTrace::new();
static ALLOCATION_FUNDED: [AtomicBool; CAPACITY] = [const { AtomicBool::new(false) }; CAPACITY];
static LOANS: AtomicUsize = AtomicUsize::new(0);
static LOAN_BYTES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static SOURCE_LOAN_LIVE: AtomicBool = AtomicBool::new(false);
#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Quota {
    source: bool,
    live: AtomicBool,
    used: Arc<AtomicUsize>,
}

struct Loan {
    bytes: usize,
    used: Arc<AtomicUsize>,
    combined_source: bool,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.combined_source {
            SOURCE_LOAN_LIVE.store(false, Ordering::SeqCst);
        }
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(LIMIT as u64)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unavailable)
        }
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        if descriptors != 0 {
            return Err(StoreError::Quota);
        }
        let bytes = usize::try_from(bytes).map_err(|_| StoreError::Quota)?;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|sum| *sum <= LIMIT)
            })
            .map_err(|_| StoreError::Quota)?;
        let mut combined_source = false;
        if self.source && WATCH.load(Ordering::SeqCst) {
            let index = LOANS.fetch_add(1, Ordering::SeqCst);
            if index < CAPACITY {
                LOAN_BYTES[index].store(bytes, Ordering::SeqCst);
            }
            combined_source = index == 1;
            if combined_source {
                SOURCE_LOAN_LIVE.store(true, Ordering::SeqCst);
            }
        }
        Ok(ResourceLoan::new(Loan {
            bytes,
            used: self.used.clone(),
            combined_source,
        }))
    }
}

fn account(source: bool) -> Result<(Arc<Quota>, DecodeBudget), Box<dyn std::error::Error>> {
    let quota = Arc::new(Quota {
        source,
        live: AtomicBool::new(true),
        used: Arc::new(AtomicUsize::new(0)),
    });
    let original = DecodeBudget::for_store(quota.clone())?;
    Ok((quota, original))
}

struct Observation<'a> {
    capture: &'a GlobalAllocationTraceSession,
    controls: &'a OriginalControlSession,
}

impl<'a> Observation<'a> {
    fn begin(
        controls: &'a OriginalControlSession,
        capture: &'a GlobalAllocationTraceSession,
    ) -> Self {
        LOANS.store(0, Ordering::SeqCst);
        WATCH.store(true, Ordering::SeqCst);
        Self { capture, controls }
    }

    fn capture(&self) -> (usize, usize) {
        WATCH.store(false, Ordering::SeqCst);
        assert_eq!(
            self.capture
                .pause()
                .unwrap_or_else(|error| panic!("original global32 capture: {error}")),
            AllocationRosterOutcome::Complete
        );
        let allocations = TRACE.allocation_count();
        assert!((2..=CAPACITY).contains(&allocations));
        assert!(!TRACE.overflowed());
        assert_eq!(TRACE.reallocations(), 0);
        assert_eq!(TRACE.entries().count(), allocations);
        assert_eq!(LOANS.load(Ordering::SeqCst), 2);
        let file = TRACE
            .entries()
            .nth(allocations - 2)
            .unwrap_or_else(|| panic!("actual original file allocation must be recorded"));
        let source = TRACE
            .entries()
            .nth(allocations - 1)
            .unwrap_or_else(|| panic!("actual original source allocation must be recorded"));
        assert_eq!(
            LOAN_BYTES[1].load(Ordering::SeqCst),
            file.bytes() + source.bytes()
        );
        assert!(SOURCE_LOAN_LIVE.load(Ordering::SeqCst));
        for (slot, index, extent) in [
            (OriginalControlSlot::First, allocations - 2, file),
            (OriginalControlSlot::Second, allocations - 1, source),
        ] {
            assert!(ALLOCATION_FUNDED[index].load(Ordering::SeqCst));
            self.controls
                .arm(
                    slot,
                    OriginalControlSelection::Explicit(extent.identity()),
                    OriginalStaticCounters::Bool(&SOURCE_LOAN_LIVE),
                    false,
                )
                .unwrap_or_else(|error| panic!("original Directory control arm: {error}"));
        }
        (file.bytes(), source.bytes())
    }

    fn assert_closed(&self) {
        let report = self
            .controls
            .report()
            .unwrap_or_else(|error| panic!("original Directory close report: {error}"));
        assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
        assert!(report.controls.iter().all(|observed| {
            observed.is_some_and(|observed| observed.before == OriginalControlSnapshot::Bool(true))
        }));
        assert!(!SOURCE_LOAN_LIVE.load(Ordering::SeqCst));
    }
}

impl Drop for Observation<'_> {
    fn drop(&mut self) {
        WATCH.store(false, Ordering::SeqCst);
    }
}

#[test]
fn original_source_loan_closes_after_both_controls_in_every_alias_order()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let (source_bank, original) = account(true)?;
    let (_, caller) = account(false)?;
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"bytes");
    backend.put_many_if_absent_with_boundary(
        &original,
        &[(id, BlobHandle::from_bytes(b"bytes"))],
        &mut || Ok(()),
    )?;

    let mut geometry = None;
    for mode in 0..4 {
        let (captured, original_report) = TestAllocationObserver::observe_original_controls(
            |controls| {
                TestAllocationObserver::capture_global_allocation_trace32(
                    &TRACE,
                    &SOURCE_LOAN_LIVE,
                    &ALLOCATION_FUNDED,
                    |capture| -> Result<(), Box<dyn std::error::Error>> {
                        let observation = Observation::begin(controls, capture);
                        let handle =
                            backend.read_with_boundary(&original, id, None, &mut || Ok(()))?;
                        let (file, source) = observation.capture();
                        println!(
                            "mode={mode} actual file control={file} source control={source} original loan={}",
                            file + source
                        );
                        if let Some(previous) = geometry {
                            assert_eq!((file, source), previous);
                        } else {
                            geometry = Some((file, source));
                        }
                        let mut reader =
                            BlobSource::open_with_boundary(&handle, &caller, &mut || Ok(()))?;
                        source_bank.live.store(false, Ordering::SeqCst);

                        match mode {
                            0 => {
                                drop(reader);
                                assert!(SOURCE_LOAN_LIVE.load(Ordering::SeqCst));
                                drop(handle);
                            }
                            1 => {
                                drop(handle);
                                let intermediate = observation.controls.report().unwrap();
                                assert!(intermediate.controls[1].is_some());
                                assert!(intermediate.controls[0].is_none());
                                let mut bytes = [0; 5];
                                assert_eq!(
                                    reader.read_with_boundary(&mut bytes, &mut || Ok(()))?,
                                    5
                                );
                                assert_eq!(&bytes, b"bytes");
                                drop(reader);
                            }
                            2 => {
                                let alias = handle.clone();
                                let other =
                                    BlobSource::open_with_boundary(&handle, &caller, &mut || {
                                        Ok(())
                                    })?;
                                drop(handle);
                                std::thread::scope(|scope| {
                                    scope.spawn(move || drop(alias));
                                    scope.spawn(move || drop(reader));
                                    scope.spawn(move || drop(other));
                                });
                            }
                            _ => {
                                let unwind = catch_unwind(AssertUnwindSafe(move || {
                                    let _source = handle;
                                    let mut reader = reader;
                                    let _ = reader.read_with_boundary(&mut [0; 1], &mut || {
                                        panic!("actual caller boundary unwind")
                                    });
                                }));
                                assert!(unwind.is_err());
                            }
                        }
                        observation.assert_closed();
                        source_bank.live.store(true, Ordering::SeqCst);
                        Ok(())
                    },
                )
            },
        )?;
        let (result, outcome) = captured?;
        result?;
        assert_eq!(outcome, AllocationRosterOutcome::Complete);
        assert_eq!(original_report.outcome, OriginalControlsOutcome::Complete);
    }

    // This separately covers unwind after both actual controls are published,
    // before lookup returns an owned source to its caller.
    let (file, source) = geometry.ok_or("missing observed source geometry")?;
    let (captured, original_report) =
        TestAllocationObserver::observe_original_controls(|controls| {
            TestAllocationObserver::capture_global_allocation_trace32(
                &TRACE,
                &SOURCE_LOAN_LIVE,
                &ALLOCATION_FUNDED,
                |capture| {
                    let observation = Observation::begin(controls, capture);
                    let mut captured = false;
                    let unwind = catch_unwind(AssertUnwindSafe(|| {
                        let _ = backend.read_with_boundary(&original, id, None, &mut || {
                            let count = TRACE.allocation_count();
                            if (2..=CAPACITY).contains(&count)
                                && TRACE
                                    .entries()
                                    .nth(count - 2)
                                    .is_some_and(|entry| entry.bytes() == file)
                                && TRACE
                                    .entries()
                                    .nth(count - 1)
                                    .is_some_and(|entry| entry.bytes() == source)
                            {
                                observation.capture();
                                captured = true;
                                panic!("actual post-publication lookup boundary unwind");
                            }
                            Ok(())
                        });
                    }));
                    assert!(captured && unwind.is_err());
                    observation.assert_closed();
                    drop(observation);
                },
            )
        })?;
    let (_, outcome) = captured?;
    assert_eq!(outcome, AllocationRosterOutcome::Complete);
    assert_eq!(original_report.outcome, OriginalControlsOutcome::Complete);
    drop(original);
    assert_eq!(source_bank.used.load(Ordering::SeqCst), 0);
    Ok(())
}
