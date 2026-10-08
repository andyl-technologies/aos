//! Observes original source/file credit through both concrete allocation closes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_cas::content_store::{
    BlobHandle, BlobSource, ContentId, DirectoryBlobBackend, ImmutableBlobBackend, ObjectKind,
    StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};

const CAPACITY: usize = 32;
const LIMIT: usize = 8 * 1024 * 1024;
static WATCH: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_BYTES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static ALLOCATION_FUNDED: [AtomicBool; CAPACITY] = [const { AtomicBool::new(false) }; CAPACITY];
static ALLOCATION_POINTERS: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static LOANS: AtomicUsize = AtomicUsize::new(0);
static LOAN_BYTES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static SOURCE_LOAN_LIVE: AtomicBool = AtomicBool::new(false);
static TARGETS: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static FREED: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
static EARLY_REFUND: AtomicBool = AtomicBool::new(false);

struct ObservingAllocator;

// SAFETY: System receives the original pointer/layout. Fixed atomic observations
// neither access allocated storage nor allocate, acquire locks, or panic.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplied the valid allocation layout.
        let allocation = unsafe { System.alloc(layout) };
        if !allocation.is_null() && WATCH.load(Ordering::SeqCst) {
            let index = ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            if index < CAPACITY {
                ALLOCATION_BYTES[index].store(layout.size(), Ordering::SeqCst);
                ALLOCATION_POINTERS[index].store(allocation as usize, Ordering::SeqCst);
                ALLOCATION_FUNDED[index]
                    .store(SOURCE_LOAN_LIVE.load(Ordering::SeqCst), Ordering::SeqCst);
            }
        }
        allocation
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        for index in 0..2 {
            if TARGETS[index].load(Ordering::SeqCst) == pointer as usize
                && !FREED[index].swap(true, Ordering::SeqCst)
                && !SOURCE_LOAN_LIVE.load(Ordering::SeqCst)
            {
                EARLY_REFUND.store(true, Ordering::SeqCst);
            }
        }
        // SAFETY: The caller supplied this live pointer and its original layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

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

struct Observation;

impl Observation {
    fn begin() -> Self {
        ALLOCATIONS.store(0, Ordering::SeqCst);
        LOANS.store(0, Ordering::SeqCst);
        EARLY_REFUND.store(false, Ordering::SeqCst);
        for index in 0..2 {
            TARGETS[index].store(0, Ordering::SeqCst);
            FREED[index].store(false, Ordering::SeqCst);
        }
        WATCH.store(true, Ordering::SeqCst);
        Self
    }

    fn capture(&self) -> (usize, usize) {
        WATCH.store(false, Ordering::SeqCst);
        let allocations = ALLOCATIONS.load(Ordering::SeqCst);
        assert!((2..=CAPACITY).contains(&allocations));
        assert_eq!(LOANS.load(Ordering::SeqCst), 2);
        let file = ALLOCATION_BYTES[allocations - 2].load(Ordering::SeqCst);
        let source = ALLOCATION_BYTES[allocations - 1].load(Ordering::SeqCst);
        assert_eq!(LOAN_BYTES[1].load(Ordering::SeqCst), file + source);
        assert!(SOURCE_LOAN_LIVE.load(Ordering::SeqCst));
        for index in 0..2 {
            assert!(ALLOCATION_FUNDED[allocations - 2 + index].load(Ordering::SeqCst));
            TARGETS[index].store(
                ALLOCATION_POINTERS[allocations - 2 + index].load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
        }
        (file, source)
    }

    fn assert_closed(&self) {
        assert!(FREED.iter().all(|freed| freed.load(Ordering::SeqCst)));
        assert!(!EARLY_REFUND.load(Ordering::SeqCst));
        assert!(!SOURCE_LOAN_LIVE.load(Ordering::SeqCst));
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        WATCH.store(false, Ordering::SeqCst);
        for target in &TARGETS {
            target.store(0, Ordering::SeqCst);
        }
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
        let observation = Observation::begin();
        let handle = backend.read_with_boundary(&original, id, None, &mut || Ok(()))?;
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
        let mut reader = BlobSource::open_with_boundary(&handle, &caller, &mut || Ok(()))?;
        source_bank.live.store(false, Ordering::SeqCst);

        match mode {
            0 => {
                drop(reader);
                assert!(SOURCE_LOAN_LIVE.load(Ordering::SeqCst));
                drop(handle);
            }
            1 => {
                drop(handle);
                assert!(FREED[1].load(Ordering::SeqCst));
                assert!(!FREED[0].load(Ordering::SeqCst));
                let mut bytes = [0; 5];
                assert_eq!(reader.read_with_boundary(&mut bytes, &mut || Ok(()))?, 5);
                assert_eq!(&bytes, b"bytes");
                drop(reader);
            }
            2 => {
                let alias = handle.clone();
                let other = BlobSource::open_with_boundary(&handle, &caller, &mut || Ok(()))?;
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
    }

    // This separately covers unwind after both actual controls are published,
    // before lookup returns an owned source to its caller.
    let (file, source) = geometry.ok_or("missing observed source geometry")?;
    let observation = Observation::begin();
    let mut captured = false;
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        let _ = backend.read_with_boundary(&original, id, None, &mut || {
            let count = ALLOCATIONS.load(Ordering::SeqCst);
            if (2..=CAPACITY).contains(&count)
                && ALLOCATION_BYTES[count - 2].load(Ordering::SeqCst) == file
                && ALLOCATION_BYTES[count - 1].load(Ordering::SeqCst) == source
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
    drop(original);
    assert_eq!(source_bank.used.load(Ordering::SeqCst), 0);
    Ok(())
}
