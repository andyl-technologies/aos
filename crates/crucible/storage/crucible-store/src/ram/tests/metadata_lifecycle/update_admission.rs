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
