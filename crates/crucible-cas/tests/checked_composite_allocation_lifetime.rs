//! Proves real composite failure allocation free precedes its prepaid loan close.

use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind, StoreError, StoreGraph,
    StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers,
    StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreNodeId, StoreNodeSpec,
    StorePhysicalQuotaBinder, StorePhysicalQuotaBinderHandle, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use crucible_linux_resource::test_support::{
    AllocationTrace, TestAllocationObserver, ThroughFreeMarkerOutcome,
};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const CAPACITY: usize = 512;
static TRACE: AllocationTrace<CAPACITY> = AllocationTrace::new();
static LOAN_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAN_SIZES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static LOAN_CLOSED: [AtomicBool; CAPACITY] = [const { AtomicBool::new(false) }; CAPACITY];
static OVERFLOW: AtomicBool = AtomicBool::new(false);

thread_local! {
    // This original fixture flag selects loan bookkeeping on the constructor
    // thread; allocation requests use the shared trace's independent arm.
    static WATCH: Cell<bool> = const { Cell::new(false) };
}

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

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
    LOAN_COUNT.store(0, Ordering::SeqCst);
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
        let (result, binding, prior_count) = TRACE
            .capture(|| {
                WATCH.with(|watch| watch.set(true));
                let result =
                    store.put_many_if_absent_with_boundary(&original, &inputs, &mut || Ok(()));
                // Identify the actual error field inside its enclosing allocation
                // and the uniquely matching original loan before closing either.
                let mut binding = None;
                let mut prior_count = None;
                if let Err(StoreError::CompositeScope { source }) = &result {
                    prior_count = Some(source.prior_publications().len());
                    if let Some(work) = source.work_failure() {
                        let address = std::ptr::from_ref(work).addr();
                        for entry in TRACE.entries() {
                            if entry.contains_address(address) {
                                let size = entry.bytes();
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
                                            Some((entry.identity(), size, entry.alignment(), loan));
                                    }
                                } else {
                                    binding = None;
                                    break;
                                }
                            }
                        }
                    }
                }
                WATCH.with(|watch| watch.set(false));
                (result, binding, prior_count)
            })
            .unwrap();

        let close = move || {
            if unwind {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _result = result;
                    panic!("causal composite unwind");
                }))
                .is_err()
            } else {
                drop(result);
                true
            }
        };
        let (closed, observation) = if let Some((identity, _, _, loan)) = binding {
            TestAllocationObserver::observe_close_marker_through_free(
                &LOAN_CLOSED[loan],
                identity,
                close,
            )
            .unwrap()
        } else {
            (close(), ThroughFreeMarkerOutcome::Missing)
        };
        let (observed, funded_before, funded_after) = match observation {
            ThroughFreeMarkerOutcome::Sampled { before, after } => (true, !before, !after),
            _ => (false, false, false),
        };
        let body_closed =
            binding.is_some_and(|(_, _, _, loan)| LOAN_CLOSED[loan].load(Ordering::SeqCst));
        let overflow = OVERFLOW.load(Ordering::SeqCst) || TRACE.overflowed();
        let reallocations = TRACE.reallocations();
        drop(store);
        drop(inputs);
        drop(original);
        assert!(closed);
        assert!(!overflow);
        assert_eq!(reallocations, 0);
        assert_eq!(TRACE.entries().count(), TRACE.allocation_count());
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
