//! Actual immutable body/payload deallocation under distinct original bank loans.

use crucible_cas::content_store::{
    BlobHandle, BlobSource, BlobStoreAdmin, CheckedReadAccess, ContentId, ImmutableBlobBackend,
    MemoryBlobBackend, ObjectKind, OwnedBlobBytes, StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, atomic::Ordering};

const CAPACITY: usize = 64;
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static ADDRESSES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static SIZES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static LOAN_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAN_SIZES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static LOAN_AFTER_ALLOCATION: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static COPIED_PAYLOAD: AtomicUsize = AtomicUsize::new(0);
static LOAN_BANKS: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static BODY_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static PAYLOAD_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static BODY_LOAN: AtomicUsize = AtomicUsize::new(usize::MAX);
static PAYLOAD_LOAN: AtomicUsize = AtomicUsize::new(usize::MAX);
static BODY_CLOSED: AtomicBool = AtomicBool::new(false);
static PAYLOAD_CLOSED: AtomicBool = AtomicBool::new(false);
static BODY_DEALLOCATED: AtomicBool = AtomicBool::new(false);
static PAYLOAD_DEALLOCATED: AtomicBool = AtomicBool::new(false);
static BODY_FUNDED: AtomicBool = AtomicBool::new(false);
static PAYLOAD_FUNDED: AtomicBool = AtomicBool::new(false);
static NAMESPACE_CLOSED: AtomicBool = AtomicBool::new(false);
static NODES_FUNDED: AtomicBool = AtomicBool::new(true);
static NODE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static NODE_DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static NODE_ADDRESSES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static NODE_OVERFLOW: AtomicBool = AtomicBool::new(false);
static PANIC_ON_BODY_REFUND: AtomicBool = AtomicBool::new(false);
static BODY_CREDIT_EXTENT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static WATCH: Cell<bool> = const { Cell::new(false) };
}

struct Observer;

// SAFETY: Allocation/deallocation delegate unchanged pointer/layout pairs to
// System. Observation uses fixed atomics and thread-local flags, reads no
// allocated memory, and cannot allocate or panic in allocator callbacks.
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The allocator caller supplies a valid allocation layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && WATCH.try_with(Cell::get).unwrap_or(false) {
            if matches!(layout.size(), 544 | 640) {
                NODE_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
                if !NODE_ADDRESSES.iter().any(|entry| {
                    entry
                        .compare_exchange(0, pointer.addr(), Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                }) {
                    NODE_OVERFLOW.store(true, Ordering::SeqCst);
                }
            }
            let index = ALLOCATION_COUNT.fetch_add(1, Ordering::SeqCst);
            if index < CAPACITY {
                ADDRESSES[index].store(pointer.addr(), Ordering::SeqCst);
                SIZES[index].store(layout.size(), Ordering::SeqCst);
            }
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let address = pointer.addr();
        if address != 0
            && NODE_ADDRESSES.iter().any(|entry| {
                entry
                    .compare_exchange(address, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            })
        {
            NODE_DEALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            if NAMESPACE_CLOSED.load(Ordering::SeqCst) {
                NODES_FUNDED.store(false, Ordering::SeqCst);
            }
        }
        if address != 0
            && address == BODY_ADDRESS.load(Ordering::SeqCst)
            && BODY_DEALLOCATED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            BODY_FUNDED.store(
                !BODY_CLOSED.load(Ordering::SeqCst) && !PAYLOAD_CLOSED.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
        }
        if address != 0
            && address == PAYLOAD_ADDRESS.load(Ordering::SeqCst)
            && PAYLOAD_DEALLOCATED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            PAYLOAD_FUNDED.store(!PAYLOAD_CLOSED.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        // SAFETY: The caller supplies the live pointer and its original layout;
        // observation neither changes nor dereferences the allocation.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Observer = Observer;

struct Loan {
    bank: usize,
    usage: Arc<AtomicUsize>,
    bytes: usize,
    observation: Option<usize>,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.bank == 4 {
            NAMESPACE_CLOSED.store(true, Ordering::SeqCst);
        }
        if self.observation == Some(BODY_LOAN.load(Ordering::SeqCst)) {
            BODY_CLOSED.store(true, Ordering::SeqCst);
        }
        if self.observation == Some(PAYLOAD_LOAN.load(Ordering::SeqCst)) {
            PAYLOAD_CLOSED.store(true, Ordering::SeqCst);
        }
        self.usage.fetch_sub(self.bytes, Ordering::SeqCst);
        if self.bank == 1
            && self.bytes == BODY_CREDIT_EXTENT.load(Ordering::SeqCst)
            && PANIC_ON_BODY_REFUND.swap(false, Ordering::SeqCst)
        {
            panic!("actual Memory body-loan unwind");
        }
    }
}

struct Quota {
    bank: usize,
    usage: Arc<AtomicUsize>,
}

struct NamespaceBinder(Arc<Quota>);

fn namespace_binder(
    original: Arc<Quota>,
) -> crucible_cas::content_store::StorePhysicalQuotaBinderHandle {
    // This fixture observes actual map nodes. Model binder controls remain
    // outside its production funding claim, as do its original Quota controls.
    crucible_cas::content_store::StorePhysicalQuotaBinderHandle::new(NamespaceBinder(original))
}

impl crucible_cas::content_store::StorePhysicalQuotaBinder for NamespaceBinder {
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
            capability: "namespace-model-disk-binding",
        })
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        if descriptors != 0 {
            return Err(StoreError::Quota);
        }
        let bytes = usize::try_from(bytes).map_err(|_| StoreError::Quota)?;
        self.usage
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= 4 * 1024 * 1024)
            })
            .map_err(|_| StoreError::Quota)?;
        let index = if WATCH.try_with(Cell::get).unwrap_or(false) {
            let index = LOAN_COUNT.fetch_add(1, Ordering::SeqCst);
            if index < CAPACITY {
                LOAN_SIZES[index].store(bytes, Ordering::SeqCst);
                LOAN_BANKS[index].store(self.bank, Ordering::SeqCst);
            }
            Some(index)
        } else {
            None
        };
        let loan = ResourceLoan::new(Loan {
            bank: self.bank,
            usage: self.usage.clone(),
            bytes,
            observation: index,
        });
        if let Some(index) = index.filter(|index| *index < CAPACITY) {
            LOAN_AFTER_ALLOCATION[index]
                .store(ALLOCATION_COUNT.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        Ok(loan)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

impl DecodeResourceAuthority for Quota {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.verify().map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.reserve_resources(0, bytes)
            .map_err(DecodeAdmissionError::new)
    }
}

struct Source {
    handle: BlobHandle,
    original: DecodeBudget,
}

impl BlobSource for Source {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Whole
    }

    fn logical_length(&self) -> u64 {
        self.handle.logical_length()
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "raw-observed-memory-source",
        })
    }

    fn read_all_with_boundary(
        &self,
        caller: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        let mut check = || {
            caller
                .verify_live()
                .map_err(|source| StoreError::DecodeAdmission {
                    source,
                    custody: Some(caller.custody()),
                })?;
            boundary()?;
            caller
                .verify_live()
                .map_err(|source| StoreError::DecodeAdmission {
                    source,
                    custody: Some(caller.custody()),
                })
        };
        let output = self
            .handle
            .read_all_with_boundary(&self.original, maximum, &mut check)?;
        COPIED_PAYLOAD.store(output.as_ptr().addr(), Ordering::SeqCst);
        Ok(output)
    }
}

fn reset() {
    BODY_ADDRESS.store(0, Ordering::SeqCst);
    PAYLOAD_ADDRESS.store(0, Ordering::SeqCst);
    BODY_LOAN.store(usize::MAX, Ordering::SeqCst);
    PAYLOAD_LOAN.store(usize::MAX, Ordering::SeqCst);
    ALLOCATION_COUNT.store(0, Ordering::SeqCst);
    LOAN_COUNT.store(0, Ordering::SeqCst);
    BODY_CLOSED.store(false, Ordering::SeqCst);
    PAYLOAD_CLOSED.store(false, Ordering::SeqCst);
    BODY_DEALLOCATED.store(false, Ordering::SeqCst);
    PAYLOAD_DEALLOCATED.store(false, Ordering::SeqCst);
    BODY_FUNDED.store(false, Ordering::SeqCst);
    PAYLOAD_FUNDED.store(false, Ordering::SeqCst);
    NAMESPACE_CLOSED.store(false, Ordering::SeqCst);
    NODES_FUNDED.store(true, Ordering::SeqCst);
    NODE_ALLOCATIONS.store(0, Ordering::SeqCst);
    NODE_DEALLOCATIONS.store(0, Ordering::SeqCst);
    NODE_OVERFLOW.store(false, Ordering::SeqCst);
    PANIC_ON_BODY_REFUND.store(false, Ordering::SeqCst);
    BODY_CREDIT_EXTENT.store(0, Ordering::SeqCst);
    for address in &NODE_ADDRESSES {
        address.store(0, Ordering::SeqCst);
    }
}

#[test]
fn body_and_payload_loans_close_after_actual_allocations_on_drop_unwind_and_concurrent_last_owners()
{
    for mode in ["drop", "unwind", "concurrent"] {
        reset();
        let source_quota = Arc::new(Quota {
            bank: 1,
            usage: Arc::new(AtomicUsize::new(0)),
        });
        let publication_quota = Arc::new(Quota {
            bank: 2,
            usage: Arc::new(AtomicUsize::new(0)),
        });
        let source_original = DecodeBudget::for_store(source_quota.clone()).unwrap();
        let publication_original = DecodeBudget::for_store(publication_quota.clone()).unwrap();
        let namespace_quota = Arc::new(Quota {
            bank: 4,
            usage: Arc::new(AtomicUsize::new(0)),
        });
        let backend = MemoryBlobBackend::new_admitted(
            "memory",
            1024 * 1024,
            64,
            namespace_binder(namespace_quota.clone()),
        )
        .unwrap();
        let bytes = vec![17; 65_539];
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let source = BlobHandle::new(Source {
            handle: BlobHandle::from_bytes(bytes),
            original: source_original.clone(),
        });

        WATCH.with(|watch| watch.set(true));
        let receipt = backend
            .put_many_if_absent_with_boundary(
                &publication_original,
                &[(id, source.clone())],
                &mut || Ok(()),
            )
            .unwrap();
        WATCH.with(|watch| watch.set(false));
        let allocations = ALLOCATION_COUNT.load(Ordering::SeqCst);
        let loans = LOAN_COUNT.load(Ordering::SeqCst);
        assert!(allocations <= CAPACITY);
        assert!(loans <= CAPACITY);
        let body_loan = (0..loans)
            .find(|&index| {
                let allocation = LOAN_AFTER_ALLOCATION[index].load(Ordering::SeqCst);
                LOAN_BANKS[index].load(Ordering::SeqCst) == 2
                    && allocation + 1 < allocations
                    && SIZES[allocation].load(Ordering::SeqCst)
                        == LOAN_SIZES[index].load(Ordering::SeqCst)
                    && SIZES[allocation + 1].load(Ordering::SeqCst) == 544
            })
            .expect("actual original A control loan");
        // Returning the actual control loan allocates no additional control:
        // the next allocation is Memory's body Arc, followed by its map node.
        // The independent N owns every node; A owns just this body allocation.
        let body_allocation = LOAN_AFTER_ALLOCATION[body_loan].load(Ordering::SeqCst);
        assert!(body_allocation < allocations);
        let body_extent = SIZES[body_allocation].load(Ordering::SeqCst);
        assert_eq!(LOAN_SIZES[body_loan].load(Ordering::SeqCst), body_extent);
        println!(
            "actual Memory {mode}: body_arc={} namespace_escrow=8544 body_control_loan={body_extent} copied_payload=65539 original_control_bank=A original_payload_bank=S original_node_bank=N",
            SIZES[body_allocation].load(Ordering::SeqCst)
        );
        let payload_address = COPIED_PAYLOAD.load(Ordering::SeqCst);
        let payload_allocation = (0..allocations)
            .find(|&index| ADDRESSES[index].load(Ordering::SeqCst) == payload_address)
            .expect("actual copied S payload moved unchanged into Memory");
        assert_eq!(SIZES[payload_allocation].load(Ordering::SeqCst), 65_539);
        let payload_loans: Vec<_> = (0..loans)
            .filter(|&index| {
                LOAN_BANKS[index].load(Ordering::SeqCst) == 1
                    && LOAN_SIZES[index].load(Ordering::SeqCst) == 65_539
            })
            .collect();
        assert_eq!(payload_loans.len(), 1, "one independently funded S copy");
        BODY_LOAN.store(body_loan, Ordering::SeqCst);
        PAYLOAD_LOAN.store(payload_loans[0], Ordering::SeqCst);
        BODY_ADDRESS.store(
            ADDRESSES[body_allocation].load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        PAYLOAD_ADDRESS.store(payload_address, Ordering::SeqCst);

        let read_quota = Arc::new(Quota {
            bank: 3,
            usage: Arc::new(AtomicUsize::new(0)),
        });
        let read_original = DecodeBudget::for_store(read_quota.clone()).unwrap();
        // Independent actual lookups create distinct body aliases. Merely
        // cloning one BlobHandle would test only the outer Source owner.
        let first_body = backend
            .read_with_boundary(&read_original, id, None, &mut || Ok(()))
            .unwrap();
        let second_body = backend
            .read_with_boundary(&read_original, id, None, &mut || Ok(()))
            .unwrap();
        backend
            .acquire_inventory_fence()
            .unwrap()
            .delete_candidate(id)
            .unwrap();
        drop(backend);
        drop(receipt);
        drop(source);
        drop(source_original);
        drop(publication_original);
        drop(read_original);
        assert!(!BODY_CLOSED.load(Ordering::SeqCst));
        assert!(!PAYLOAD_CLOSED.load(Ordering::SeqCst));
        match mode {
            "drop" => {
                drop(first_body);
                drop(second_body);
            }
            "unwind" => {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        drop(first_body);
                        let _body = second_body;
                        panic!("intentional immutable body unwind");
                    }))
                    .is_err()
                );
            }
            "concurrent" => {
                let barrier = Arc::new(std::sync::Barrier::new(2));
                let other_barrier = barrier.clone();
                let first = std::thread::spawn(move || {
                    barrier.wait();
                    drop(first_body);
                });
                let second = std::thread::spawn(move || {
                    other_barrier.wait();
                    drop(second_body);
                });
                first.join().unwrap();
                second.join().unwrap();
            }
            _ => unreachable!("fixed test modes"),
        }
        BODY_ADDRESS.store(0, Ordering::SeqCst);
        PAYLOAD_ADDRESS.store(0, Ordering::SeqCst);
        assert!(BODY_DEALLOCATED.load(Ordering::SeqCst), "{mode}");
        assert!(PAYLOAD_DEALLOCATED.load(Ordering::SeqCst), "{mode}");
        assert!(BODY_FUNDED.load(Ordering::SeqCst), "{mode}");
        assert!(PAYLOAD_FUNDED.load(Ordering::SeqCst), "{mode}");
        assert!(BODY_CLOSED.load(Ordering::SeqCst), "{mode}");
        assert!(PAYLOAD_CLOSED.load(Ordering::SeqCst), "{mode}");
        assert_eq!(source_quota.usage.load(Ordering::SeqCst), 0);
        assert_eq!(publication_quota.usage.load(Ordering::SeqCst), 0);
        assert_eq!(read_quota.usage.load(Ordering::SeqCst), 0);
        assert_eq!(namespace_quota.usage.load(Ordering::SeqCst), 0);
        assert!(NODES_FUNDED.load(Ordering::SeqCst));
        assert_eq!(
            NODE_ALLOCATIONS.load(Ordering::SeqCst),
            NODE_DEALLOCATIONS.load(Ordering::SeqCst)
        );
    }
    // One test owns these fixed observer slots; cohorts cannot race one another.
    for mode in [
        "populated-drop",
        "populated-unwind",
        "concurrent-backend-close",
    ] {
        actual_namespace_nodes(mode);
    }
}

fn actual_namespace_nodes(mode: &str) {
    reset();
    let first = Arc::new(Quota {
        bank: 1,
        usage: Arc::new(AtomicUsize::new(0)),
    });
    let second = Arc::new(Quota {
        bank: 2,
        usage: Arc::new(AtomicUsize::new(0)),
    });
    let namespace = Arc::new(Quota {
        bank: 4,
        usage: Arc::new(AtomicUsize::new(0)),
    });
    let first_original = DecodeBudget::for_store(first.clone())
        .unwrap_or_else(|error| panic!("capture first original caller: {error:?}"));
    let second_original = DecodeBudget::for_store(second.clone())
        .unwrap_or_else(|error| panic!("capture second original caller: {error:?}"));
    let backend =
        MemoryBlobBackend::new_admitted("nodes", 0, 64, namespace_binder(namespace.clone()))
            .unwrap_or_else(|error| panic!("admit actual node namespace: {error:?}"));
    assert_eq!(namespace.usage.load(Ordering::SeqCst), 8544);
    let original_control_credit = first.usage.load(Ordering::SeqCst);

    WATCH.set(true);
    for schema in 0..64 {
        let original = if schema % 2 == 0 {
            &first_original
        } else {
            &second_original
        };
        publish_empty(&backend, original, schema);
        if schema == 0 {
            // Bind the empty body's original loan to its actual allocation,
            // followed by the first544 map node; never reuse an older layout.
            let loans = LOAN_COUNT.load(Ordering::SeqCst).min(CAPACITY);
            let allocations = ALLOCATION_COUNT.load(Ordering::SeqCst).min(CAPACITY);
            let body_loan = (0..loans)
                .find(|&index| {
                    let allocation = LOAN_AFTER_ALLOCATION[index].load(Ordering::SeqCst);
                    LOAN_BANKS[index].load(Ordering::SeqCst) == 1
                        && allocation + 1 < allocations
                        && SIZES[allocation].load(Ordering::SeqCst)
                            == LOAN_SIZES[index].load(Ordering::SeqCst)
                        && SIZES[allocation + 1].load(Ordering::SeqCst) == 544
                })
                .unwrap_or_else(|| panic!("actual empty-body loan/allocation pair"));
            let extent = LOAN_SIZES[body_loan].load(Ordering::SeqCst);
            assert_eq!(
                first.usage.load(Ordering::SeqCst),
                original_control_credit + extent
            );
            BODY_CREDIT_EXTENT.store(extent, Ordering::SeqCst);
        }
    }
    assert_eq!(
        backend
            .object_count()
            .unwrap_or_else(|error| panic!("count populated objects: {error:?}")),
        64
    );
    assert_eq!(
        backend
            .logical_bytes()
            .unwrap_or_else(|error| panic!("read empty-body logical usage: {error:?}")),
        0
    );
    let baseline = first.usage.load(Ordering::SeqCst);
    let body_extent = BODY_CREDIT_EXTENT.load(Ordering::SeqCst);
    assert_eq!(baseline, original_control_credit + 32 * body_extent);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    backend
        .acquire_inventory_fence()
        .unwrap_or_else(|error| panic!("acquire first deletion fence: {error:?}"))
        .delete_candidate(id)
        .unwrap_or_else(|error| panic!("delete first existing object: {error:?}"));
    assert_eq!(first.usage.load(Ordering::SeqCst), baseline - body_extent);
    assert_eq!(namespace.usage.load(Ordering::SeqCst), 8544);
    assert!(!NAMESPACE_CLOSED.load(Ordering::SeqCst));
    publish_empty(&backend, &first_original, 0);

    for round in 0..4 {
        for offset in 0..64 {
            let schema = (offset * 37 + round) % 64;
            let id = ContentId::for_bytes(ObjectKind::Trace, schema + 1, &[]);
            backend
                .acquire_inventory_fence()
                .unwrap_or_else(|error| panic!("acquire churn deletion fence: {error:?}"))
                .delete_candidate(id)
                .unwrap_or_else(|error| panic!("delete churn object: {error:?}"));
            let original = if schema % 2 == 0 {
                &first_original
            } else {
                &second_original
            };
            publish_empty(&backend, original, schema);
            assert_eq!(namespace.usage.load(Ordering::SeqCst), 8544);
            assert_eq!(
                backend
                    .object_count()
                    .unwrap_or_else(|error| panic!("count churn objects: {error:?}")),
                64
            );
        }
    }
    WATCH.set(false);

    match mode {
        "populated-drop" => drop(backend),
        "populated-unwind" => {
            PANIC_ON_BODY_REFUND.store(true, Ordering::SeqCst);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(backend))).is_err()
            );
            assert!(
                !PANIC_ON_BODY_REFUND.load(Ordering::SeqCst),
                "actual body loan must unwind"
            );
        }
        "concurrent-backend-close" => {
            let backend = Arc::new(backend);
            let other = backend.clone();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let other_barrier = barrier.clone();
            let first = std::thread::spawn(move || {
                barrier.wait();
                drop(backend);
            });
            let second = std::thread::spawn(move || {
                other_barrier.wait();
                drop(other);
            });
            first
                .join()
                .unwrap_or_else(|error| panic!("join first complete backend owner: {error:?}"));
            second
                .join()
                .unwrap_or_else(|error| panic!("join second complete backend owner: {error:?}"));
        }
        _ => unreachable!("fixed namespace witness modes"),
    }

    assert!(!NODE_OVERFLOW.load(Ordering::SeqCst));
    assert!(
        NODE_ALLOCATIONS.load(Ordering::SeqCst) > 1,
        "exercise actual splits"
    );
    assert_eq!(
        NODE_ALLOCATIONS.load(Ordering::SeqCst),
        NODE_DEALLOCATIONS.load(Ordering::SeqCst),
        "{mode}"
    );
    assert!(
        NODES_FUNDED.load(Ordering::SeqCst),
        "{mode}: original N survives every deallocation"
    );
    assert!(NAMESPACE_CLOSED.load(Ordering::SeqCst));
    assert_eq!(namespace.usage.load(Ordering::SeqCst), 0);
    drop(first_original);
    drop(second_original);
    assert_eq!(first.usage.load(Ordering::SeqCst), 0);
    assert_eq!(second.usage.load(Ordering::SeqCst), 0);
    println!(
        "actual Memory {mode}: leaf544/internal640, originalN8544, mixedA zero-byte objects/churn, node allocations/deallocations={}",
        NODE_ALLOCATIONS.load(Ordering::SeqCst)
    );
}

fn publish_empty(backend: &MemoryBlobBackend, original: &DecodeBudget, schema: u32) {
    let id = ContentId::for_bytes(ObjectKind::Trace, schema + 1, &[]);
    let receipt = backend
        .put_many_if_absent_with_boundary(
            original,
            &[(id, BlobHandle::from_bytes(Vec::new()))],
            &mut || Ok(()),
        )
        .unwrap_or_else(|error| panic!("publish authenticated empty object: {error:?}"))
        .accept_with_boundary(&mut || Ok(()))
        .unwrap_or_else(|error| panic!("accept authenticated empty object: {error:?}"));
    drop(receipt);
}
