//! Concrete source allocation closure under its original finite resource loan.

use crucible_cas::content_store::{BlobHandle, BlobSource, StoreError};
use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScratch, ResourceLoan,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static USED: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);
static EXTENT: AtomicUsize = AtomicUsize::new(0);
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_SIZE: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATED: AtomicBool = AtomicBool::new(false);
static FUNDED_AT_CLOSE: AtomicBool = AtomicBool::new(false);
static VALUE_LIVE_AT_CLOSE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static WATCH: Cell<bool> = const { Cell::new(false) };
}

struct Observer;

// SAFETY: Pointer/layout pairs are forwarded unchanged to System. Callbacks
// use only fixed atomics and an allocation-free TLS flag, never inspect memory,
// and neither allocate nor panic.
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies a valid allocation layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && WATCH.try_with(Cell::get).unwrap_or(false) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            ADDRESS.store(pointer.addr(), Ordering::SeqCst);
            ALLOCATION_SIZE.store(layout.size(), Ordering::SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if pointer.addr() != 0
            && pointer.addr() == ADDRESS.load(Ordering::SeqCst)
            && DEALLOCATED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            FUNDED_AT_CLOSE.store(
                USED.load(Ordering::SeqCst)
                    >= BASELINE.load(Ordering::SeqCst) + EXTENT.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            VALUE_LIVE_AT_CLOSE.store(DROPS.load(Ordering::SeqCst) == 0, Ordering::SeqCst);
        }
        // SAFETY: The caller supplies the live allocation and original layout;
        // observation neither changes nor dereferences either.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Observer = Observer;

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

struct Observation;

impl Observation {
    fn arm() -> Self {
        ADDRESS.store(0, Ordering::SeqCst);
        ALLOCATIONS.store(0, Ordering::SeqCst);
        ALLOCATION_SIZE.store(0, Ordering::SeqCst);
        DROPS.store(0, Ordering::SeqCst);
        DEALLOCATED.store(false, Ordering::SeqCst);
        FUNDED_AT_CLOSE.store(false, Ordering::SeqCst);
        VALUE_LIVE_AT_CLOSE.store(false, Ordering::SeqCst);
        WATCH.with(|watch| watch.set(true));
        Self
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        WATCH.with(|watch| watch.set(false));
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

        if mode == "reference" {
            let observation = Observation::arm();
            let reference: Arc<dyn BlobSource> = Arc::new(source);
            drop(observation);
            drop(reference);
            assert!(!FUNDED_AT_CLOSE.load(Ordering::SeqCst));
            assert!(!VALUE_LIVE_AT_CLOSE.load(Ordering::SeqCst));
        } else if mode == "callback-unwind" {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _observation = Observation::arm();
                // Disable allocation recording before the real callback panic
                // creates its runtime payload; source deallocation stays armed.
                struct CallbackSource(Source);
                impl BlobSource for CallbackSource {
                    fn logical_length(&self) -> u64 {
                        WATCH.with(|watch| watch.set(false));
                        self.0.logical_length()
                    }

                    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
                        self.0.open()
                    }
                }
                let _handle = BlobHandle::new(CallbackSource(source));
            }));
            assert!(result.is_err());
        } else {
            let observation = Observation::arm();
            let handle = BlobHandle::new(source);
            drop(observation);
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
        }

        assert_eq!(ALLOCATIONS.load(Ordering::SeqCst), 1, "{mode}");
        assert_eq!(ALLOCATION_SIZE.load(Ordering::SeqCst), extent, "{mode}");
        assert!(DEALLOCATED.load(Ordering::SeqCst), "{mode}");
        assert_eq!(DROPS.load(Ordering::SeqCst), 1, "{mode}");
        if mode != "reference" {
            assert!(FUNDED_AT_CLOSE.load(Ordering::SeqCst), "{mode}");
            assert!(VALUE_LIVE_AT_CLOSE.load(Ordering::SeqCst), "{mode}");
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
