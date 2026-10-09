//! Checked mark-page equivalence, bounded storage work and failed-root custody.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible_cas::content_store::{
    BlobHandle, ByteRange, ObjectKind, PutBatchReceipt, PutReceipt, StorePhysicalQuotaGuard,
};

use super::*;

struct CountedBackend {
    inner: Arc<dyn ImmutableBlobBackend>,
    reads: AtomicU64,
    publications: AtomicU64,
    objects: AtomicU64,
    refuse_after_publication: AtomicBool,
}

impl ImmutableBlobBackend for CountedBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.inner.metadata_resources()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read(id, range)
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read_with_boundary(original, id, range, boundary)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }

    fn put_many_if_absent(
        &self,
        objects: &[(ContentId, BlobHandle)],
    ) -> Result<Vec<PutReceipt>, StoreError> {
        self.publications.fetch_add(1, Ordering::Relaxed);
        self.objects
            .fetch_add(objects.len() as u64, Ordering::Relaxed);
        self.inner.put_many_if_absent(objects)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.publications.fetch_add(1, Ordering::Relaxed);
        self.objects
            .fetch_add(objects.len() as u64, Ordering::Relaxed);
        let receipt = self
            .inner
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        if self.refuse_after_publication.load(Ordering::Relaxed) {
            return Err(StoreError::Unsupported {
                capability: "actual-mark-publication-then-refusal",
            });
        }
        Ok(receipt)
    }
}

fn counted(inner: Arc<dyn ImmutableBlobBackend>) -> Arc<CountedBackend> {
    Arc::new(CountedBackend {
        inner,
        reads: AtomicU64::new(0),
        publications: AtomicU64::new(0),
        objects: AtomicU64::new(0),
        refuse_after_publication: AtomicBool::new(false),
    })
}

fn page(index: u64) -> ContentId {
    ContentId::for_bytes(ObjectKind::RamExtent, 1, &index.to_be_bytes())
}

#[test]
fn batched_marks_match_point_roots_with_fewer_real_reads_and_publications() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let source_operation = fixture.context();
    let original = source_operation.original();
    let backend = counted(source_operation.marks());
    let resources = backend.metadata_resources().unwrap();
    let mut point = Reachability::with_backend(backend.clone(), original).unwrap();
    let mut batch = Reachability::with_backend(backend.clone(), original).unwrap();
    let mut boundary = || source_operation.check();
    let operation =
        CampaignGcOperationContext::new(backend.clone(), original, &mut boundary).unwrap();
    let mut pending = PendingMarks::new(&operation).unwrap();

    for index in 0..128 {
        point.insert(page(index)).unwrap();
    }
    let point_reads = backend.reads.swap(0, Ordering::Relaxed);
    let point_puts = backend.publications.swap(0, Ordering::Relaxed);
    let point_objects = backend.objects.swap(0, Ordering::Relaxed);
    for index in 0..128 {
        pending.insert(&mut batch, page(index), &operation).unwrap();
    }
    pending.flush(&mut batch, &operation).unwrap();

    assert_eq!(batch.root, point.root);
    assert_eq!(batch.len(), 128);
    let batch_reads = backend.reads.load(Ordering::Relaxed);
    let batch_puts = backend.publications.load(Ordering::Relaxed);
    let batch_objects = backend.objects.load(Ordering::Relaxed);
    eprintln!(
        "actual mark storage: point reads={point_reads} batches={point_puts} objects={point_objects}; checked page reads={batch_reads} batches={batch_puts} objects={batch_objects}"
    );
    assert!(batch_reads < point_reads);
    assert!(batch_puts < point_puts);
    assert!(batch_objects < point_objects);
    for index in 0..128 {
        assert!(batch.contains(&page(index)).unwrap());
    }
    assert!(!batch.contains(&page(1000)).unwrap());

    drop(pending);
    drop(operation);
    drop(point);
    drop(batch);
    drop(backend);
    drop(source_operation);
    drop(fixture);
    resources.reserve_resources(128, 256 * 1024 * 1024).unwrap();
}

#[test]
fn partial_checked_publication_does_not_install_a_mark_root_and_can_retry() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let source_operation = fixture.context();
    let original = source_operation.original();
    let backend = counted(source_operation.marks());
    let mut marks = Reachability::with_backend(backend.clone(), original).unwrap();
    let prior = marks.root;
    let mut boundary = || source_operation.check();
    let operation =
        CampaignGcOperationContext::new(backend.clone(), original, &mut boundary).unwrap();
    let mut pending = PendingMarks::new(&operation).unwrap();
    for index in 0..63 {
        pending.insert(&mut marks, page(index), &operation).unwrap();
    }
    backend
        .refuse_after_publication
        .store(true, Ordering::Relaxed);

    let error = pending.flush(&mut marks, &operation).unwrap_err();

    assert!(
        matches!(&error,
            StoreError::StreamIo { source, .. }
            if matches!(source.get_ref().and_then(|source| source.downcast_ref::<crucible_campaign::CampaignStoreError>()),
                Some(crucible_campaign::CampaignStoreError::Store(StoreError::Unsupported {
                    capability: "actual-mark-publication-then-refusal"
                })))
        ),
        "actual typed first publication refusal: {error:?}"
    );
    assert_eq!(marks.root, prior);
    assert!(backend.objects.load(Ordering::Relaxed) > 0);
    assert!(!marks.contains(&page(0)).unwrap());
    original.verify_live().unwrap();
    backend
        .refuse_after_publication
        .store(false, Ordering::Relaxed);
    pending.flush(&mut marks, &operation).unwrap();
    assert_eq!(marks.len(), 63);
    assert!(marks.contains(&page(0)).unwrap());
}

#[test]
fn original_boundary_refuses_before_any_checked_mark_publication() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let source_operation = fixture.context();
    let original = source_operation.original();
    let backend = counted(source_operation.marks());
    let mut marks = Reachability::with_backend(backend.clone(), original).unwrap();
    let prior = marks.root;
    let refuse = AtomicBool::new(false);
    let mut boundary = || {
        if refuse.load(Ordering::Relaxed) {
            Err(StoreError::Unsupported {
                capability: "original-mark-boundary",
            })
        } else {
            source_operation.check()
        }
    };
    let operation =
        CampaignGcOperationContext::new(backend.clone(), original, &mut boundary).unwrap();
    let mut pending = PendingMarks::new(&operation).unwrap();
    pending.insert(&mut marks, page(1), &operation).unwrap();
    let before = backend.publications.load(Ordering::Relaxed);
    refuse.store(true, Ordering::Relaxed);

    assert!(matches!(
        pending.flush(&mut marks, &operation),
        Err(StoreError::Unsupported {
            capability: "original-mark-boundary"
        })
    ));
    assert_eq!(marks.root, prior);
    assert_eq!(backend.publications.load(Ordering::Relaxed), before);
}

#[test]
fn checked_batch_preserves_final_nibble_and_rejects_invalid_pages_before_storage() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let operation = fixture.context();
    let backend = counted(operation.marks());
    let marks = Reachability::with_backend(backend.clone(), operation.original()).unwrap();
    let original = mark_account(operation.original()).unwrap();
    let _scope = original.enter();
    let mut adjacent = [0_u8; 32];
    adjacent[31] = 1;
    let entries = [
        (CampaignHash::from_bytes([0; 32]), page(0)),
        (CampaignHash::from_bytes(adjacent), page(1)),
    ];
    let mut point = marks.root;
    for (key, value) in entries {
        point = marks.map.insert(point.content_id(), key, value).unwrap();
    }
    let batch = marks
        .map
        .insert_batch_with_boundary(marks.root.content_id(), &entries, &original, &mut || {
            operation.check()
        })
        .unwrap();
    assert_eq!(batch, point);
    assert_eq!(batch.entry_count(), 2);

    let reads = backend.reads.load(Ordering::Relaxed);
    let puts = backend.publications.load(Ordering::Relaxed);
    for invalid in [[entries[0], entries[0]], [entries[1], entries[0]]] {
        assert!(matches!(
            marks.map.insert_batch_with_boundary(
                marks.root.content_id(),
                &invalid,
                &original,
                &mut || operation.check(),
            ),
            Err(crucible_campaign::CampaignStoreError::InvalidMerkle { .. })
        ));
    }
    let oversized = [entries[0]; MerkleMap::MAX_CHECKED_BATCH_UPSERTS + 1];
    assert!(
        marks
            .map
            .insert_batch_with_boundary(marks.root.content_id(), &oversized, &original, &mut || {
                operation.check()
            },)
            .is_err()
    );
    assert!(matches!(
        marks
            .map
            .insert_batch_with_boundary(page(2), &entries, &original, &mut || operation.check(),),
        Err(crucible_campaign::CampaignStoreError::InvalidMerkle {
            reason: "root-or-child-kind"
        })
    ));
    assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
    assert_eq!(backend.publications.load(Ordering::Relaxed), puts);
}
