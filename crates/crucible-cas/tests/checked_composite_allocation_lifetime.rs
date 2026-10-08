//! Proves real composite failure allocation free precedes its prepaid loan close.

use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind, StoreError, StoreGraph,
    StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers,
    StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreNodeId, StoreNodeSpec,
    StorePhysicalQuotaBinder, StorePhysicalQuotaBinderHandle, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const CAPACITY: usize = 512;
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static ADDRESSES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static SIZES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static ALIGNS: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static LOAN_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAN_SIZES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static LOAN_CLOSED: [AtomicBool; CAPACITY] = [const { AtomicBool::new(false) }; CAPACITY];
static OVERFLOW: AtomicBool = AtomicBool::new(false);
static TARGET: AtomicUsize = AtomicUsize::new(0);
static TARGET_LOAN: AtomicUsize = AtomicUsize::new(CAPACITY);
static DEALLOCATED: AtomicBool = AtomicBool::new(false);
static FUNDED_BEFORE: AtomicBool = AtomicBool::new(false);
static FUNDED_AFTER: AtomicBool = AtomicBool::new(false);

thread_local! {
    static WATCH: Cell<bool> = const { Cell::new(false) };
}

struct Observer;

// SAFETY: All allocator requests delegate unchanged pointer/layout pairs to
// System. Observation uses only fixed atomics and a fallible thread-local flag;
// it reads no allocated memory, acquires no locks, allocates nothing, and cannot
// panic. A compare_exchange consumes the specific target once, preventing reuse
// of its address from producing a second or unrelated deallocation observation.
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The allocator caller supplies a valid layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && WATCH.try_with(Cell::get).unwrap_or(false) {
            let index = ALLOCATION_COUNT.fetch_add(1, Ordering::SeqCst);
            if index < CAPACITY {
                ADDRESSES[index].store(pointer.addr(), Ordering::SeqCst);
                SIZES[index].store(layout.size(), Ordering::SeqCst);
                ALIGNS[index].store(layout.align(), Ordering::SeqCst);
            } else {
                OVERFLOW.store(true, Ordering::SeqCst);
            }
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observed = TARGET
            .compare_exchange(pointer.addr(), 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        let loan = TARGET_LOAN.load(Ordering::SeqCst);
        if observed {
            FUNDED_BEFORE.store(
                loan < CAPACITY && !LOAN_CLOSED[loan].load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
        }
        // SAFETY: The caller supplies the original live pointer and its layout.
        unsafe { System.dealloc(pointer, layout) };
        if observed {
            FUNDED_AFTER.store(
                loan < CAPACITY && !LOAN_CLOSED[loan].load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            DEALLOCATED.store(true, Ordering::SeqCst);
        }
    }
}

#[global_allocator]
static ALLOCATOR: Observer = Observer;

struct Quota {
    used: Arc<AtomicUsize>,
}

struct Loan {
    used: Arc<AtomicUsize>,
    bytes: usize,
    observed_index: Option<usize>,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if let Some(index) = self.observed_index {
            LOAN_CLOSED[index].store(true, Ordering::SeqCst);
        }
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(8 * 1024 * 1024)
    }
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn reserve_resources(&self, _descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let bytes = usize::try_from(bytes).map_err(|_| StoreError::Quota)?;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= 8 * 1024 * 1024)
            })
            .map_err(|_| StoreError::Quota)?;
        let observed_index = if WATCH.try_with(Cell::get).unwrap_or(false) {
            let index = LOAN_COUNT.fetch_add(1, Ordering::SeqCst);
            if index < CAPACITY {
                LOAN_SIZES[index].store(bytes, Ordering::SeqCst);
                Some(index)
            } else {
                OVERFLOW.store(true, Ordering::SeqCst);
                None
            }
        } else {
            None
        };
        Ok(ResourceLoan::new(Loan {
            used: self.used.clone(),
            bytes,
            observed_index,
        }))
    }
}

// This model forwards the existing finite guard before graph effects. It adds
// no bank or writer-derived authority. Its opaque fixture control remains
// outside the observed composite error allocation scope.
struct NamespaceBinder(Arc<Quota>);

impl StorePhysicalQuotaBinder for NamespaceBinder {
    fn reserve_memory_namespace(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.reserve_resources(0, bytes)
    }

    fn verify_memory_namespace(&self) -> Result<(), StoreError> {
        self.0.verify()
    }

    fn bind(
        &self,
        _root: &std::path::Path,
        _project_id: u32,
        _maximum_physical_bytes: u64,
        _maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "component-memory-disk-binding",
        })
    }
}

fn graph(original: Arc<Quota>) -> Result<StoreGraph, StoreError> {
    let namespace = StorePhysicalQuotaBinderHandle::new(NamespaceBinder(original));
    let first = StoreNodeId::new("first")?;
    let second = StoreNodeId::new("second")?;
    let root = StoreNodeId::new("root")?;
    StoreGraph::build_with_all_capabilities(
        StoreGraphConfig {
            root: root.clone(),
            gc_mark_root: None,
            admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
            nodes: BTreeMap::from([
                (
                    first.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 4096,
                        max_objects: 2,
                    },
                ),
                (
                    second.clone(),
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1,
                        max_objects: 2,
                    },
                ),
                (
                    root,
                    StoreNodeSpec::WriteThrough {
                        children: vec![first, second],
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &StoreGraphPhysicalQuotaBinders::new(),
        &StoreGraphS3Clients::new(),
        Some(&namespace),
    )
}

fn reset() {
    ALLOCATION_COUNT.store(0, Ordering::SeqCst);
    LOAN_COUNT.store(0, Ordering::SeqCst);
    TARGET.store(0, Ordering::SeqCst);
    TARGET_LOAN.store(CAPACITY, Ordering::SeqCst);
    DEALLOCATED.store(false, Ordering::SeqCst);
    FUNDED_BEFORE.store(false, Ordering::SeqCst);
    FUNDED_AFTER.store(false, Ordering::SeqCst);
    OVERFLOW.store(false, Ordering::SeqCst);
    for closed in &LOAN_CLOSED {
        closed.store(false, Ordering::SeqCst);
    }
}

#[test]
fn same_failure_box_is_funded_through_system_free_on_drop_and_unwind() {
    let mut outcomes = Vec::new();
    for unwind in [false, true] {
        let quota = Arc::new(Quota {
            used: Arc::new(AtomicUsize::new(0)),
        });
        let store = graph(quota.clone()).unwrap();
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        let bytes = vec![29; 1024];
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
        let inputs = [(id, BlobHandle::from_bytes(bytes))];
        reset();
        WATCH.with(|watch| watch.set(true));
        let result = store.put_many_if_absent_with_boundary(&original, &inputs, &mut || Ok(()));
        // Do not assert or panic while the observation is armed. The real error
        // is closed in every branch before thread-local/global targets disarm.
        let mut binding = None;
        let mut prior_count = None;
        if let Err(StoreError::CompositeScope { source }) = &result {
            prior_count = Some(source.prior_publications().len());
            if let Some(work) = source.work_failure() {
                let address = std::ptr::from_ref(work).addr();
                for index in 0..ALLOCATION_COUNT.load(Ordering::SeqCst).min(CAPACITY) {
                    let start = ADDRESSES[index].load(Ordering::SeqCst);
                    let size = SIZES[index].load(Ordering::SeqCst);
                    if start <= address && address < start.saturating_add(size) {
                        let mut matched_loan = None;
                        let mut matching_loans = 0;
                        for (loan, loan_size) in LOAN_SIZES
                            .iter()
                            .enumerate()
                            .take(LOAN_COUNT.load(Ordering::SeqCst).min(CAPACITY))
                        {
                            if loan_size.load(Ordering::SeqCst) == size {
                                matching_loans += 1;
                                matched_loan = Some(loan);
                            }
                        }
                        if matching_loans == 1 && binding.is_none() {
                            if let Some(loan) = matched_loan {
                                binding =
                                    Some((start, size, ALIGNS[index].load(Ordering::SeqCst), loan));
                            }
                        } else {
                            binding = None;
                            break;
                        }
                    }
                }
            }
        }
        if let Some((address, _, _, loan)) = binding {
            TARGET_LOAN.store(loan, Ordering::SeqCst);
            TARGET.store(address, Ordering::SeqCst);
        }
        WATCH.with(|watch| watch.set(false));
        let closed = if unwind {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _result = result;
                panic!("causal composite unwind");
            }))
            .is_err()
        } else {
            drop(result);
            true
        };
        TARGET.store(0, Ordering::SeqCst);
        let observed = DEALLOCATED.load(Ordering::SeqCst);
        let funded_before = FUNDED_BEFORE.load(Ordering::SeqCst);
        let funded_after = FUNDED_AFTER.load(Ordering::SeqCst);
        let body_closed =
            binding.is_some_and(|(_, _, _, loan)| LOAN_CLOSED[loan].load(Ordering::SeqCst));
        let overflow = OVERFLOW.load(Ordering::SeqCst);
        drop(store);
        drop(inputs);
        drop(original);
        assert!(closed);
        assert!(!overflow);
        assert_eq!(prior_count, Some(1));
        let (_, size, align, _) =
            binding.expect("exact failure allocation and original loan identity");
        println!("actual composite failure: size={size} align={align} unwind={unwind}");
        outcomes.push((unwind, observed, funded_before, funded_after));
        assert!(
            body_closed,
            "original failure loan closes after heap allocation"
        );
        assert_eq!(quota.used.load(Ordering::SeqCst), 0);
    }
    for (unwind, observed, funded_before, funded_after) in &outcomes {
        println!(
            "actual free funding: unwind={unwind} observed={observed} before={funded_before} after={funded_after}"
        );
    }
    for (_, observed, funded_before, funded_after) in outcomes {
        assert!(observed, "actual System free observed");
        assert!(
            funded_before && funded_after,
            "same prepaid Box credit remains live through actual System free"
        );
    }
}
