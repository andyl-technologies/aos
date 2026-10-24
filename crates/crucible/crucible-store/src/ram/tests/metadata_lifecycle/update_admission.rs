//! Refuses revoked publication originals before backend or successor effects.
//!
//! Publication uses an independently live backend. Its finite caller prepays
//! the existing output bound, then revokes that same authority. Update controls
//! start from a genuinely captured root.
//! The actual admission-refusal prefix distinguishes diagnostic allocations
//! from copies of successor vectors; no native resources are qualified.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;

fn contains_original_revocation(error: &(dyn Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(current) = source {
        if current.is::<RevokedOriginalAuthority>() {
            return true;
        }
        source = current.source();
    }
    false
}

#[test]
fn revoked_update_original_refuses_before_successor_vector_copies() {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let retention = Retention::default();
    let root = store
        .capture(
            topology(8193),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let backend_baseline = backend_quota.used();
    let caller_quota = ObservedQuota::with_limit(32 << 20);
    let original = DecodeBudget::for_store(caller_quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let admitted = caller_quota.used();
    let requests = caller_quota.reservations.load(Ordering::SeqCst);
    caller_quota.revoked.store(true, Ordering::SeqCst);

    // Compare the real same-account refusal, including its typed diagnostic,
    // rather than assuming that operational refusal itself allocates nothing.
    let (prefix_error, prefix_counts) = TestAllocationObserver::count(|| {
        Work::new(store.limits, &original, &mut || Ok(()))
            .err()
            .unwrap()
    });
    assert!(contains_original_revocation(&prefix_error));
    assert_eq!(caller_quota.used(), admitted);
    drop(prefix_error);

    let mut reads = 0;
    let mut callbacks = 0;
    let (result, counts) = TestAllocationObserver::count(|| {
        store.update_with_reader(
            &root,
            &mut || {
                reads += 1;
                Ok(None)
            },
            &retention,
            &original,
            &mut || {
                callbacks += 1;
                Ok(())
            },
        )
    });
    let error = result.unwrap_err();

    assert!(contains_original_revocation(&error));
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::DecodeAdmission { .. })
    ));
    assert_eq!((reads, callbacks), (0, 0));
    assert!(!counts.overflow && !prefix_counts.overflow);
    assert_eq!(
        (counts.allocations, counts.reallocations),
        (prefix_counts.allocations, prefix_counts.reallocations),
        "successor vectors must not precede original admission"
    );
    assert_eq!(caller_quota.reservations.load(Ordering::SeqCst), requests);
    assert_eq!(caller_quota.used(), admitted);
    assert_eq!(backend_quota.used(), backend_baseline);
    assert!(!backend_quota.revoked.load(Ordering::SeqCst));

    drop(error);
    drop(original);
    assert_eq!(caller_quota.used(), 0);
}

/// Closes the actual caller only after the real backend admits its headroom.
struct HeadroomRevocation {
    backend: Arc<dyn ImmutableBlobBackend>,
    caller: Arc<ObservedQuota>,
    admissions: AtomicU64,
}

impl ImmutableBlobBackend for HeadroomRevocation {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }

    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<crate::content_store::CheckedPublicationMetadata, StoreError> {
        self.backend.checked_publication_metadata(kind)
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.backend.metadata_resources()
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.backend.admit_object_graph(objects)?;
        self.admissions.fetch_add(1, Ordering::SeqCst);
        self.caller.revoked.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.backend.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.backend.read(id, range)
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        self.backend
            .read_with_boundary(original, id, range, boundary)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.backend.put_if_absent(id, source)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crate::content_store::PutBatchReceipt, StoreError> {
        self.backend
            .put_many_if_absent_with_boundary(original, objects, boundary)
    }
}

#[test]
fn update_rechecks_original_after_backend_headroom_before_successor_effects() {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let retention = Retention::default();
    let root = store
        .capture(
            topology(8193),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let backend_baseline = backend_quota.used();
    let caller_quota = ObservedQuota::with_limit(32 << 20);
    let original = DecodeBudget::for_store(caller_quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let admitted = caller_quota.used();
    let requests = caller_quota.reservations.load(Ordering::SeqCst);

    let (prefix, prefix_counts) = TestAllocationObserver::count(|| {
        let mut boundary = || Ok(());
        let _work = Work::new(store.limits, &original, &mut boundary)?;
        store.admit_ram_publication(root.record.topology(), root.record.scope())
    });
    prefix.unwrap();
    assert_eq!(caller_quota.used(), admitted);
    assert!(!caller_quota.revoked.load(Ordering::SeqCst));
    let admission_requests = caller_quota.reservations.load(Ordering::SeqCst) - requests;
    let before_update = caller_quota.reservations.load(Ordering::SeqCst);
    let backend = Arc::new(HeadroomRevocation {
        backend: store.backend.clone(),
        caller: caller_quota.clone(),
        admissions: AtomicU64::new(0),
    });
    let update_store = RamStore::new(backend.clone(), store.durability, store.limits).unwrap();

    let mut reads = 0;
    let mut callbacks = 0;
    let (result, counts) = TestAllocationObserver::count(|| {
        update_store.update_with_reader(
            &root,
            &mut || {
                reads += 1;
                Ok(None)
            },
            &retention,
            &original,
            &mut || {
                callbacks += 1;
                Ok(())
            },
        )
    });
    let error = result.unwrap_err();
    assert!(contains_original_revocation(&error));
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::DecodeAdmission { .. })
    ));
    assert_eq!(backend.admissions.load(Ordering::SeqCst), 1);
    assert!(caller_quota.revoked.load(Ordering::SeqCst));

    // Observe refusal only after genuine revocation. This account is never
    // reactivated, replaced or credited to prepare the diagnostic comparison.
    let (diagnostic, diagnostic_counts) = TestAllocationObserver::count(|| {
        original
            .verify_live()
            .map_err(|source| RamStoreError::from_admission(&original, source))
            .unwrap_err()
    });
    assert!(contains_original_revocation(&diagnostic));
    drop(diagnostic);

    assert!(!counts.overflow && !prefix_counts.overflow && !diagnostic_counts.overflow);
    assert_eq!(
        (counts.allocations, counts.reallocations),
        (
            prefix_counts.allocations + diagnostic_counts.allocations,
            prefix_counts.reallocations + diagnostic_counts.reallocations
        ),
        "revocation must precede successor copies and callbacks"
    );
    assert_eq!((reads, callbacks), (0, 0));
    assert_eq!(
        caller_quota.reservations.load(Ordering::SeqCst),
        before_update + admission_requests
    );
    assert_eq!(caller_quota.used(), admitted);
    assert_eq!(backend_quota.used(), backend_baseline);
    assert!(!backend_quota.revoked.load(Ordering::SeqCst));

    drop(original);
    assert_eq!(caller_quota.used(), admitted);
    drop(error);
    assert_eq!(caller_quota.used(), 0);
}

#[test]
fn revoked_capture_original_refuses_before_backend_headroom_admission() {
    capture_refusal_at_backend_admission(true);
}

#[test]
fn capture_rechecks_original_after_backend_headroom_before_page_publication() {
    capture_refusal_at_backend_admission(false);
}

fn capture_refusal_at_backend_admission(revoked_before_entry: bool) {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let backend_baseline = backend_quota.used();
    let caller_quota = ObservedQuota::with_limit(32 << 20);
    let original = DecodeBudget::for_store(caller_quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let admitted = caller_quota.used();
    let requests = caller_quota.reservations.load(Ordering::SeqCst);
    let backend = Arc::new(HeadroomRevocation {
        backend: store.backend.clone(),
        caller: caller_quota.clone(),
        admissions: AtomicU64::new(0),
    });
    let capture_store = RamStore::new(backend.clone(), store.durability, store.limits).unwrap();
    let topology = topology(4097);
    let retention = Retention::default();
    // Entry preparation legitimately reserves two diagnostic carriers. Measure
    // that actual prefix while the caller is live, before irreversible closure.
    let admission_requests = if revoked_before_entry {
        0
    } else {
        let mut boundary = || Ok(());
        let work = Work::new(store.limits, &original, &mut boundary).unwrap();
        drop(work);
        assert_eq!(caller_quota.used(), admitted);
        caller_quota.reservations.load(Ordering::SeqCst) - requests
    };
    let before_capture = caller_quota.reservations.load(Ordering::SeqCst);
    if revoked_before_entry {
        caller_quota.revoked.store(true, Ordering::SeqCst);
    }

    let mut reads = 0;
    let mut callbacks = 0;
    let error = capture_store
        .capture(
            topology,
            Scope::Exact,
            &mut |region, index, bytes| {
                reads += 1;
                patterned(region, index, bytes)
            },
            &retention,
            &original,
            &mut || {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();

    assert!(contains_original_revocation(&error));
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::DecodeAdmission { .. })
    ));
    assert_eq!(
        backend.admissions.load(Ordering::SeqCst),
        u64::from(!revoked_before_entry)
    );
    assert!(caller_quota.revoked.load(Ordering::SeqCst));
    assert_eq!((reads, callbacks), (0, 0));
    assert!(retention.objects.lock().unwrap().is_empty());
    assert_eq!(
        caller_quota.reservations.load(Ordering::SeqCst),
        before_capture + admission_requests
    );
    assert_eq!(caller_quota.used(), admitted);
    assert_eq!(backend_quota.used(), backend_baseline);
    assert!(!backend_quota.revoked.load(Ordering::SeqCst));

    drop(original);
    assert_eq!(caller_quota.used(), admitted);
    drop(error);
    assert_eq!(caller_quota.used(), 0);
}

fn transfer_refusal_at_backend_admission(revoke_source: bool, revoked_before_entry: bool) {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source_backend_quota = ObservedQuota::with_limit(32 << 20);
    let destination_backend_quota = ObservedQuota::with_limit(32 << 20);
    let source_store = directory_store(source_directory.path(), &source_backend_quota);
    let destination_store =
        directory_store(destination_directory.path(), &destination_backend_quota);
    let source_retention = Retention::default();
    let destination_retention = Retention::default();
    let topology = Topology::new(
        vec![RegionDescriptor::new("main", RegionClass::MutableMain, 17).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let root = source_store
        .capture(
            topology,
            Scope::Exact,
            &mut patterned,
            &source_retention,
            &fixture_original(&source_store),
            &mut || Ok(()),
        )
        .unwrap();
    let source_backend_baseline = source_backend_quota.used();
    let destination_backend_baseline = destination_backend_quota.used();
    let source_quota = ObservedQuota::with_limit(32 << 20);
    let destination_quota = ObservedQuota::with_limit(32 << 20);
    let source_original = DecodeBudget::for_store(source_quota.clone()).unwrap();
    let destination_original = DecodeBudget::for_store(destination_quota.clone()).unwrap();
    for original in [&source_original, &destination_original] {
        original
            .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
            .unwrap();
    }
    let source_admitted = source_quota.used();
    let destination_admitted = destination_quota.used();
    let (revoked_quota, live_quota, retained) = if revoke_source {
        (&source_quota, &destination_quota, source_admitted)
    } else {
        (&destination_quota, &source_quota, destination_admitted)
    };
    let backend = Arc::new(HeadroomRevocation {
        backend: destination_store.backend.clone(),
        caller: revoked_quota.clone(),
        admissions: AtomicU64::new(0),
    });
    let destination = RamStore::new(
        backend.clone(),
        destination_store.durability,
        destination_store.limits,
    )
    .unwrap();

    // Observe legitimate entry preparation while both callers are live. A
    // refusal may stop earlier, but cannot request more than this real prefix.
    let source_requests = source_quota.reservations.load(Ordering::SeqCst);
    let destination_requests = destination_quota.reservations.load(Ordering::SeqCst);
    let mut boundary = || Ok(());
    let mut work = Work::new(source_store.limits, &source_original, &mut boundary).unwrap();
    work.destination(&destination_original).unwrap();
    drop(work);
    let source_prefix = source_quota.reservations.load(Ordering::SeqCst) - source_requests;
    let destination_prefix =
        destination_quota.reservations.load(Ordering::SeqCst) - destination_requests;
    assert_eq!(source_quota.used(), source_admitted);
    assert_eq!(destination_quota.used(), destination_admitted);
    let source_before = source_quota.reservations.load(Ordering::SeqCst);
    let destination_before = destination_quota.reservations.load(Ordering::SeqCst);
    if revoked_before_entry {
        revoked_quota.revoked.store(true, Ordering::SeqCst);
    }

    let mut callbacks = 0;
    let error = source_store
        .transfer_to(
            &root,
            &destination,
            &destination_retention,
            &source_original,
            &destination_original,
            &mut || {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();

    assert!(contains_original_revocation(&error));
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::DecodeAdmission { .. })
    ));
    assert_eq!(
        backend.admissions.load(Ordering::SeqCst),
        u64::from(!revoked_before_entry)
    );
    assert!(revoked_quota.revoked.load(Ordering::SeqCst));
    assert!(!live_quota.revoked.load(Ordering::SeqCst));
    assert_eq!(callbacks, 0);
    assert!(destination_retention.objects.lock().unwrap().is_empty());
    assert!(source_quota.reservations.load(Ordering::SeqCst) <= source_before + source_prefix);
    assert!(
        destination_quota.reservations.load(Ordering::SeqCst)
            <= destination_before + destination_prefix
    );
    assert_eq!(source_quota.used(), source_admitted);
    assert_eq!(destination_quota.used(), destination_admitted);
    assert_eq!(source_backend_quota.used(), source_backend_baseline);
    assert_eq!(
        destination_backend_quota.used(),
        destination_backend_baseline
    );

    drop(source_original);
    drop(destination_original);
    assert_eq!(revoked_quota.used(), retained);
    assert_eq!(live_quota.used(), 0);
    drop(error);
    assert_eq!(source_quota.used(), 0);
    assert_eq!(destination_quota.used(), 0);
}

#[test]
fn revoked_transfer_source_refuses_before_destination_headroom_admission() {
    transfer_refusal_at_backend_admission(true, true);
}

#[test]
fn revoked_transfer_destination_refuses_before_headroom_admission() {
    transfer_refusal_at_backend_admission(false, true);
}

#[test]
fn transfer_rechecks_source_after_destination_headroom_admission() {
    transfer_refusal_at_backend_admission(true, false);
}

#[test]
fn transfer_rechecks_destination_after_headroom_admission() {
    transfer_refusal_at_backend_admission(false, false);
}
