//! Private linear continuation geometry and causal allocation-close witnesses.
//!
//! These modeled owners exercise existing typed causes and original credit.
//! They do not activate a public error variant or a RAM provider dispatch path.
//! Causal allocation observations use the existing reviewed shared test
//! allocator; this integration target adds no allocator implementation.

use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, DirectoryBlobBackend,
    DurabilityRequirement, ImmutableBlobBackend, PutBatchReceipt, PutReceipt, StoreError,
    StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScratch, ResourceLoan,
};
use crucible_cas::ram::{
    BoundedReadRequest, PreparedRamFailure, RamFailureCause, RamRetention, RamRootLease, RamStore,
    RamStoreError, RamStoreLimits,
};
use crucible_linux_resource::test_support::TestAllocationObserver;
use std::alloc::Layout;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

static LOAN_CLOSED: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Authority {
    used: Arc<AtomicUsize>,
    watch_next: AtomicBool,
}

struct Loan {
    used: Arc<AtomicUsize>,
    bytes: usize,
    watched: bool,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.watched {
            LOAN_CLOSED.store(1, Ordering::SeqCst);
        }
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        let bytes =
            usize::try_from(bytes).map_err(|_| DecodeAdmissionError::new(StoreError::Quota))?;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= 16 * 1024)
            })
            .map_err(|_| DecodeAdmissionError::new(StoreError::Quota))?;
        Ok(ResourceLoan::new(Loan {
            used: self.used.clone(),
            bytes,
            watched: self.watch_next.swap(false, Ordering::SeqCst),
        }))
    }
}

#[derive(Clone, PartialEq)]
enum FirstCause {
    Boundary(RamFailureCause<RamStoreError>),
    Validation(RamFailureCause<Infallible>),
}

impl FirstCause {
    fn storage_failure(&self) -> &RamStoreError {
        match self {
            Self::Boundary(cause) => cause.storage_failure(),
            Self::Validation(cause) => cause.storage_failure(),
        }
    }

    fn is_boundary(&self) -> bool {
        match self {
            Self::Boundary(cause) => {
                matches!(cause.first_boundary(), Some(RamStoreError::Canceled))
            }
            Self::Validation(cause) => cause.first_boundary().is_some(),
        }
    }
}

struct Pair {
    first: FirstCause,
    returned: StoreError,
}

struct LinearFailure {
    // Ordinary field drop closes the Box before releasing its external credit,
    // including when a payload destructor unwinds.
    body: Box<Pair>,
    _credit: DecodeScratch,
}

struct RawFailure {
    pair: Pair,
    _credit: DecodeScratch,
}

#[derive(Debug)]
struct UnwindPayload;

impl fmt::Display for UnwindPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("distinct original cleanup failure")
    }
}

impl Error for UnwindPayload {}

impl Drop for UnwindPayload {
    fn drop(&mut self) {
        panic!("intentional original cleanup payload unwind");
    }
}

#[test]
fn linear_pair_preserves_causes_and_credit_through_real_free() {
    let existing = PreparedRamFailure::<Infallible>::allocation_bytes().unwrap();
    let pair_layout = Layout::new::<Pair>();
    assert!(u64::try_from(pair_layout.size()).unwrap() <= existing);
    assert!(std::mem::size_of::<LinearFailure>() <= std::mem::size_of::<RamStoreError>());
    println!(
        "pair={} align={} linear_owner={} ram_error={} store_error={} scratch={} existing_validation={existing} result_unit_linear={} first_cause={}",
        pair_layout.size(),
        pair_layout.align(),
        std::mem::size_of::<LinearFailure>(),
        std::mem::size_of::<RamStoreError>(),
        std::mem::size_of::<StoreError>(),
        std::mem::size_of::<DecodeScratch>(),
        std::mem::size_of::<Result<(), LinearFailure>>(),
        std::mem::size_of::<FirstCause>(),
    );

    for (raw, unwind, has_boundary) in [
        (true, false, false),
        (true, false, true),
        (false, false, false),
        (false, false, true),
        (false, true, false),
        (false, true, true),
    ] {
        LOAN_CLOSED.store(0, Ordering::SeqCst);

        let used = Arc::new(AtomicUsize::new(0));
        let authority = Arc::new(Authority {
            used: used.clone(),
            watch_next: AtomicBool::new(false),
        });
        let original = DecodeBudget::new(authority.clone(), 16 * 1024).unwrap();
        // Both actual existing Work extents are prepaid before the first
        // modeled failure allocation. The second slot is consumed linearly,
        // not reserved again after the provider has produced its failure.
        let prepared_boundary =
            has_boundary.then(|| PreparedRamFailure::<RamStoreError>::new(&original).unwrap());
        let prepared_validation =
            (!has_boundary).then(|| PreparedRamFailure::<Infallible>::new(&original).unwrap());
        let remaining_extent = if has_boundary {
            existing
        } else {
            PreparedRamFailure::<RamStoreError>::allocation_bytes().unwrap()
        };
        authority.watch_next.store(true, Ordering::SeqCst);
        let credit = original.reserve_scratch_bytes(remaining_extent).unwrap();
        let first = match (prepared_boundary, prepared_validation) {
            (Some(slot), None) => FirstCause::Boundary(slot.retain(
                Some(RamStoreError::Canceled),
                StoreError::Unavailable.into(),
            )),
            (None, Some(slot)) => FirstCause::Validation(
                slot.retain(None, RamStoreError::Invalid("original fixed tree failure")),
            ),
            _ => unreachable!("one original failure slot is selected"),
        };
        let retained_first = first.clone();
        let returned = if unwind {
            // Incoming fixture payload custody is independent of the modeled
            // outer Box; it is allocated before observation is armed.
            StoreError::Supervision {
                source: Box::new(UnwindPayload),
            }
        } else {
            StoreError::Quota
        };
        let pair = Pair { first, returned };
        let (closed, original_identity, categories, after_free, counts) = if raw {
            let (body, identity, counts) = TestAllocationObserver::capture_layout_and_count(
                Layout::new::<RawFailure>(),
                || {
                    Box::new(RawFailure {
                        pair,
                        _credit: credit,
                    })
                },
            );
            let original_identity = body.pair.first == retained_first;
            let categories = matches!(body.pair.returned, StoreError::Quota);
            let after_free = match identity {
                Some(identity) => {
                    let ((), observed) = TestAllocationObserver::observe_atomic_after_free(
                        &LOAN_CLOSED,
                        identity,
                        || drop(body),
                    );
                    observed
                }
                None => {
                    drop(body);
                    None
                }
            };
            (true, original_identity, categories, after_free, counts)
        } else {
            let (body, identity, counts) =
                TestAllocationObserver::capture_layout_and_count(Layout::new::<Pair>(), || {
                    Box::new(pair)
                });
            let owner = LinearFailure {
                body,
                _credit: credit,
            };
            let original_identity = owner.body.first == retained_first;
            let categories = matches!(
                owner.body.returned,
                StoreError::Quota | StoreError::Supervision { .. }
            );
            // The caught destructor panic stays inside the observer's action,
            // so it can return its exact post-System sample before disarming.
            let (panicked, after_free) = match identity {
                Some(identity) => TestAllocationObserver::observe_atomic_after_free(
                    &LOAN_CLOSED,
                    identity,
                    || {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(owner)))
                            .is_err()
                    },
                ),
                None => (
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(owner))).is_err(),
                    None,
                ),
            };
            (
                panicked == unwind,
                original_identity,
                categories,
                after_free,
                counts,
            )
        };
        let loan_closed = LOAN_CLOSED.load(Ordering::SeqCst) == 1;

        assert!(closed && original_identity && categories);
        assert!(loan_closed);
        assert_eq!(after_free, Some(u64::from(raw)));
        assert!(!counts.overflow);
        assert_eq!(counts.allocations, 1);
        assert_eq!(counts.reallocations, 0);
        assert_eq!(retained_first.is_boundary(), has_boundary);
        assert!(match retained_first.storage_failure() {
            RamStoreError::Store(StoreError::Unavailable) => has_boundary,
            RamStoreError::Invalid("original fixed tree failure") => !has_boundary,
            _ => false,
        });
        println!(
            "raw={raw} unwind={unwind} boundary={has_boundary} remaining_extent={remaining_extent} loan_closed_at_actual_after_free={after_free:?}"
        );
        drop(retained_first);
        original.verify_live().unwrap();
        drop(original);
        assert_eq!(used.load(Ordering::SeqCst), 0);
    }
}

struct SourceQuota(Arc<AtomicU64>);

struct SourceLoan {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for SourceLoan {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl StorePhysicalQuotaGuard for SourceQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(8 * 1024 * 1024)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn reserve_resources(&self, _: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= 8 * 1024 * 1024)
            })
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(SourceLoan {
            used: self.0.clone(),
            bytes,
        }))
    }
}

struct Retention;
struct Lease(ContentId);

impl RamRootLease for Lease {
    fn root(&self) -> ContentId {
        self.0
    }
}

impl RamRetention for Retention {
    fn retain_object(&self, _: ContentId) -> Result<(), RamStoreError> {
        Ok(())
    }

    fn retain_root(&self, id: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        Ok(Arc::new(Lease(id)))
    }
}

struct Provider {
    inner: Arc<dyn ImmutableBlobBackend>,
    corrupt: AtomicBool,
    returned: Mutex<Option<StoreError>>,
}

impl ImmutableBlobBackend for Provider {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn admit_object_graph(
        &self,
        objects: &[(crucible_cas::content_store::ObjectKind, u64)],
    ) -> Result<(), StoreError> {
        self.inner.admit_object_graph(objects)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, _: ContentId, _: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        panic!("the actual RAM Work cannot fall back to a raw reader")
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        if self.corrupt.load(Ordering::SeqCst) {
            return Err(StoreError::Corrupt { id });
        }
        self.inner.read_with_boundary(original, id, range, boundary)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.inner
            .put_many_if_absent_with_boundary(original, objects, boundary)
    }

    fn read_bounded_with_boundary(
        &self,
        request: &mut BoundedReadRequest<'_, '_>,
    ) -> Result<(), StoreError> {
        // This private modeled child inherits the actual nominal default, so
        // its checked metadata failure seals E before this provider consumes it.
        struct Child<'a>(&'a Provider);
        impl ImmutableBlobBackend for Child<'_> {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn capabilities(&self) -> BackendCapabilities {
                self.0.capabilities()
            }
            fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
                self.0.contains(id)
            }
            fn read(
                &self,
                id: ContentId,
                range: Option<ByteRange>,
            ) -> Result<BlobHandle, StoreError> {
                self.0.read(id, range)
            }
            fn put_if_absent(
                &self,
                id: ContentId,
                source: &BlobHandle,
            ) -> Result<PutReceipt, StoreError> {
                self.0.put_if_absent(id, source)
            }
            fn read_with_boundary(
                &self,
                original: &DecodeBudget,
                id: ContentId,
                range: Option<ByteRange>,
                boundary: &mut dyn FnMut() -> Result<(), StoreError>,
            ) -> Result<BlobHandle, StoreError> {
                self.0.read_with_boundary(original, id, range, boundary)
            }
        }
        let first = Child(self).read_bounded_with_boundary(request);
        assert!(matches!(first, Err(StoreError::RamValidation { .. })));
        self.returned
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .take()
            .ok_or(StoreError::Unavailable)
            .and_then(Err)
    }
}

#[test]
fn actual_work_continuation_credit_outlives_production_box_free() {
    use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};

    let directory = tempfile::tempdir().unwrap();
    let source_quota = Arc::new(SourceQuota(Arc::new(AtomicU64::new(0))));
    let source_original = DecodeBudget::for_store(source_quota.clone()).unwrap();
    let backend = DirectoryBlobBackend::new_with_physical_quota(
        "actual-source",
        directory.path(),
        source_quota,
    )
    .unwrap();
    let provider = Arc::new(Provider {
        inner: backend,
        corrupt: AtomicBool::new(false),
        returned: Mutex::new(None),
    });
    let store = RamStore::new(
        provider.clone(),
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    let topology = Topology::new(
        vec![RegionDescriptor::new("main", RegionClass::MutableMain, 4096).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let root = store
        .capture(
            topology,
            Scope::Exact,
            &mut |_, _, bytes| {
                bytes.fill(7);
                Ok(())
            },
            &Retention,
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    provider.corrupt.store(true, Ordering::SeqCst);

    for unwind in [false, true] {
        LOAN_CLOSED.store(0, Ordering::SeqCst);
        let used = Arc::new(AtomicUsize::new(0));
        let authority = Arc::new(Authority {
            used: used.clone(),
            watch_next: AtomicBool::new(false),
        });
        let original = DecodeBudget::new(authority.clone(), 16 * 1024).unwrap();
        *provider.returned.lock().unwrap() = Some(if unwind {
            StoreError::Supervision {
                source: Box::new(UnwindPayload),
            }
        } else {
            StoreError::Quota
        });
        // The SAME real Work prepays its boundary slot first. A pure failure
        // consumes validation, leaving that watched boundary loan for the Box.
        authority.watch_next.store(true, Ordering::SeqCst);
        let layout = Layout::from_size_align(72, 8).unwrap();
        let (error, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout, || {
                store
                    .verify(&root, &original, &mut || Ok(()))
                    .err()
                    .unwrap()
            });
        let RamStoreError::Store(StoreError::RamReadContinuation { source }) = &error else {
            panic!("the real Work must retain both original errors in the production owner");
        };
        assert!(matches!(
            source.first_failure(),
            RamStoreError::Store(StoreError::Corrupt { .. })
        ));
        assert!(matches!(
            source.returned_failure(),
            StoreError::Quota | StoreError::Supervision { .. }
        ));
        let (panicked, after_free) = match identity {
            Some(identity) => {
                TestAllocationObserver::observe_atomic_after_free(&LOAN_CLOSED, identity, || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(error))).is_err()
                })
            }
            None => (
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(error))).is_err(),
                None,
            ),
        };
        assert_eq!(panicked, unwind);
        assert_eq!(
            after_free,
            Some(0),
            "actual System free precedes original Work credit close"
        );
        assert_eq!(LOAN_CLOSED.load(Ordering::SeqCst), 1);
        assert!(counts.allocations >= 1);
        drop(original);
        assert_eq!(used.load(Ordering::SeqCst), 0);
    }
}
