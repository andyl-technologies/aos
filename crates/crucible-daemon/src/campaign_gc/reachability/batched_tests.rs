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

// Probes the same portable account with temporary real loans. This does not
// measure allocator payloads or certify a deployed physical quota.
fn available_resident_bytes(resources: &dyn StorePhysicalQuotaGuard) -> u64 {
    let mut accepted = 0;
    let mut refused = 256 * 1024 * 1024 + 1;
    while refused - accepted > 1 {
        let candidate = accepted + (refused - accepted) / 2;
        match resources.reserve_resources(0, candidate) {
            Ok(loan) => {
                drop(loan);
                accepted = candidate;
            }
            Err(StoreError::Quota) => refused = candidate,
            Err(error) => panic!("healthy original counter probe: {error:?}"),
        }
    }
    accepted
}

#[test]
fn prefix_staging_prepays_fixed_capacity_and_returns_original_credit() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let operation = fixture.context();
    let resources = operation.marks().metadata_resources().unwrap();
    let before = available_resident_bytes(resources.as_ref());
    let initial = PendingMarks::initial_bytes().unwrap();
    let promoted = PendingMarks::prefix_bytes().unwrap();
    let mut pending = PendingMarks::new(&operation).unwrap();

    assert!(pending.slots.is_empty());
    assert_eq!(pending.page.capacity(), MARK_PAGE);
    assert_eq!(
        available_resident_bytes(resources.as_ref()),
        before - initial
    );
    let held = resources
        .reserve_resources(0, before - initial - promoted + 1)
        .unwrap();
    assert!(matches!(
        pending.promote(&operation),
        Err(StoreError::Quota)
    ));
    assert!(pending.slots.is_empty());
    assert!(pending._prefix_credit.is_none());
    assert_eq!(available_resident_bytes(resources.as_ref()), promoted - 1);
    drop(held);
    pending.promote(&operation).unwrap();

    assert_eq!(pending.slots.len(), MARK_SLOTS);
    assert_eq!(pending.slots.capacity(), MARK_SLOTS);
    assert_eq!(pending.page.capacity(), MARK_GROUP_PAGE);
    assert_eq!(
        available_resident_bytes(resources.as_ref()),
        before - initial - promoted
    );
    assert!(
        resources
            .reserve_resources(0, before - initial - promoted + 1)
            .is_err()
    );
    drop(pending);
    assert_eq!(available_resident_bytes(resources.as_ref()), before);

    let held = resources
        .reserve_resources(0, before - initial + 1)
        .unwrap();
    assert!(matches!(
        PendingMarks::new(&operation),
        Err(StoreError::Quota)
    ));
    assert_eq!(available_resident_bytes(resources.as_ref()), initial - 1);
    drop(held);
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut pending = PendingMarks::new(&operation).unwrap();
        pending.promote(&operation).unwrap();
        panic!("original staging credit unwind control");
    }));
    assert!(observed.is_err());
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
    eprintln!(
        "actual prefix credit initial={initial} promotion={promoted} owner={} entry={}",
        std::mem::size_of::<PendingMarks>(),
        std::mem::size_of::<Option<MarkEntry>>()
    );
    operation.check().unwrap();
}

#[test]
fn mature_prefix_pages_preserve_canonical_root_with_less_storage_work() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let source = fixture.context();
    let backend = counted(source.marks());
    let mut boundary = || source.check();
    let operation =
        CampaignGcOperationContext::new(backend.clone(), source.original(), &mut boundary).unwrap();
    let mut prefix = Reachability::with_backend(backend.clone(), source.original()).unwrap();
    let mut pending = PendingMarks::new(&operation).unwrap();
    for index in 0..4096 {
        pending
            .insert(&mut prefix, page(index), &operation)
            .unwrap();
    }
    pending.flush(&mut prefix, &operation).unwrap();
    let mut consecutive = Reachability::with_backend(backend.clone(), source.original()).unwrap();
    consecutive.root = prefix.root;
    backend.reads.store(0, Ordering::Relaxed);
    backend.publications.store(0, Ordering::Relaxed);
    backend.objects.store(0, Ordering::Relaxed);

    // Retains one original 64-entry page for the predecessor's actual algorithm.
    let _page_credit = operation.reserve_array::<MarkEntry>(MARK_PAGE).unwrap();
    let mut entries = Vec::with_capacity(MARK_PAGE);
    for start in (4096..8192).step_by(MARK_PAGE) {
        entries.clear();
        entries.extend(
            (start..start + MARK_PAGE as u64).map(|index| (mark_key(page(index)), page(index))),
        );
        entries.sort_unstable_by_key(|entry| entry.0);
        let child = mark_account(source.original()).unwrap();
        consecutive.root = consecutive
            .map
            .insert_batch_with_boundary(
                consecutive.root.content_id(),
                &entries,
                &child,
                &mut || operation.check(),
            )
            .unwrap();
        operation.check().unwrap();
    }
    let consecutive_reads = backend.reads.swap(0, Ordering::Relaxed);
    let consecutive_puts = backend.publications.swap(0, Ordering::Relaxed);
    let consecutive_nodes = backend.objects.swap(0, Ordering::Relaxed);
    for index in 4096..8192 {
        pending
            .insert(&mut prefix, page(index), &operation)
            .unwrap();
    }
    pending.flush(&mut prefix, &operation).unwrap();
    let prefix_reads = backend.reads.load(Ordering::Relaxed);
    let prefix_puts = backend.publications.load(Ordering::Relaxed);
    let prefix_nodes = backend.objects.load(Ordering::Relaxed);

    assert_eq!(prefix.root, consecutive.root);
    assert_eq!(prefix.len(), 8192);
    assert!(pending.slots.iter().all(Option::is_none));
    assert!(pending.counts.iter().all(|count| *count == 0));
    eprintln!(
        "mature mark work: consecutive reads={consecutive_reads} publications={consecutive_puts} nodes={consecutive_nodes}; prefix reads={prefix_reads} publications={prefix_puts} nodes={prefix_nodes}"
    );
    assert!(prefix_reads < consecutive_reads);
    assert!(prefix_puts < consecutive_puts);
    assert!(prefix_nodes < consecutive_nodes);
    for index in [0, 4095, 4096, 8191] {
        assert!(prefix.contains(&page(index)).unwrap());
    }
}

#[test]
fn full_prefix_publication_refusal_retains_every_slot_and_the_prior_root() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let source = fixture.context();
    let backend = counted(source.marks());
    let mut boundary = || source.check();
    let operation =
        CampaignGcOperationContext::new(backend.clone(), source.original(), &mut boundary).unwrap();
    let mut marks = Reachability::with_backend(backend.clone(), source.original()).unwrap();
    let prior = marks.root;
    let mut pending = PendingMarks::new(&operation).unwrap();
    pending.promote(&operation).unwrap();
    let prefix = mark_key(page(0)).as_bytes()[0];
    let _selected_credit = operation.reserve_array::<ContentId>(MARK_PAGE).unwrap();
    let mut selected = Vec::with_capacity(MARK_PAGE);
    for index in 0..65536 {
        let id = page(index);
        if mark_key(id).as_bytes()[0] == prefix {
            selected.push(id);
            if selected.len() == MARK_PAGE {
                break;
            }
        }
    }
    assert_eq!(selected.len(), MARK_PAGE);
    for id in &selected[..MARK_PAGE - 1] {
        pending.insert(&mut marks, *id, &operation).unwrap();
    }
    assert_eq!(marks.root, prior);
    backend
        .refuse_after_publication
        .store(true, Ordering::Relaxed);

    let error = pending
        .insert(&mut marks, selected[MARK_PAGE - 1], &operation)
        .unwrap_err();

    assert!(matches!(&error,
        StoreError::StreamIo { source, .. }
        if matches!(source.get_ref().and_then(|source| source.downcast_ref::<crucible_campaign::CampaignStoreError>()),
            Some(crucible_campaign::CampaignStoreError::Store(StoreError::Unsupported {
                capability: "actual-mark-publication-then-refusal"
            })))
    ));
    assert_eq!(marks.root, prior);
    assert_eq!(usize::from(pending.counts[usize::from(prefix)]), MARK_PAGE);
    assert_eq!(
        pending.slots.iter().filter(|entry| entry.is_some()).count(),
        MARK_PAGE
    );
    assert!(backend.objects.load(Ordering::Relaxed) > 0);
    operation.check().unwrap();
    backend
        .refuse_after_publication
        .store(false, Ordering::Relaxed);
    pending.flush(&mut marks, &operation).unwrap();
    assert_eq!(marks.len(), MARK_PAGE as u64);
    assert!(pending.slots.iter().all(Option::is_none));
    for id in selected {
        assert!(marks.contains(&id).unwrap());
    }
}

#[test]
fn promotion_refusal_keeps_the_committed_small_root_and_original_page() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let operation = fixture.context();
    let resources = operation.marks().metadata_resources().unwrap();
    let mut marks = Reachability::with_backend(operation.marks(), operation.original()).unwrap();
    let mut pending = PendingMarks::new(&operation).unwrap();
    for index in 0..MARK_PROMOTION as u64 {
        pending.insert(&mut marks, page(index), &operation).unwrap();
    }
    assert_eq!(marks.len(), MARK_PROMOTION as u64);
    assert!(pending.slots.is_empty());
    assert_eq!(pending.staged, 0);
    let prior = marks.root;
    let available = available_resident_bytes(resources.as_ref());
    let held = resources
        .reserve_resources(0, available - PendingMarks::prefix_bytes().unwrap() + 1)
        .unwrap();
    let next = page(MARK_PROMOTION as u64);

    assert!(matches!(
        pending.insert(&mut marks, next, &operation),
        Err(StoreError::Quota)
    ));

    assert_eq!(marks.root, prior);
    assert_eq!(pending.observed, MARK_PROMOTION);
    assert!(pending.slots.is_empty());
    assert!(pending.page.is_empty());
    drop(held);
    operation.check().unwrap();
    pending.insert(&mut marks, next, &operation).unwrap();
    assert_eq!(pending.slots.len(), MARK_SLOTS);
    assert_eq!(marks.root, prior);
    pending.flush(&mut marks, &operation).unwrap();
    assert_eq!(marks.len(), MARK_PROMOTION as u64 + 1);
    assert!(marks.contains(&next).unwrap());
}

#[test]
fn first_nibble_group_matches_point_and_page_roots_and_rejects_invalid_input() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let operation = fixture.context();
    let backend = counted(operation.marks());
    let marks = Reachability::with_backend(backend.clone(), operation.original()).unwrap();
    let account = mark_account(operation.original()).unwrap();
    let _scope = account.enter();
    let _credit = operation
        .reserve_array::<MarkEntry>(MARK_GROUP_PAGE + 1)
        .unwrap();
    let mut entries = Vec::with_capacity(MARK_GROUP_PAGE + 1);
    for index in 0..MARK_GROUP_PAGE as u64 {
        let id = page(index);
        let mut digest = mark_key(id).as_bytes();
        digest[0] &= 0x0f;
        entries.push((CampaignHash::from_bytes(digest), id));
    }
    entries.sort_unstable_by_key(|entry| entry.0);
    assert!(entries.windows(2).all(|pair| pair[0].0 < pair[1].0));

    let mut point = marks.root;
    for (key, value) in &entries {
        point = marks.map.insert(point.content_id(), *key, *value).unwrap();
    }
    let mut pages = marks.root;
    for chunk in entries.chunks(MARK_PAGE) {
        pages = marks
            .map
            .insert_batch_with_boundary(pages.content_id(), chunk, &account, &mut || {
                operation.check()
            })
            .unwrap();
    }
    backend.publications.store(0, Ordering::Relaxed);
    backend.objects.store(0, Ordering::Relaxed);
    let grouped = marks
        .map
        .insert_prefix_batch_with_boundary(marks.root.content_id(), &entries, &account, &mut || {
            operation.check()
        })
        .unwrap();

    assert_eq!(grouped, point);
    assert_eq!(grouped, pages);
    assert_eq!(grouped.entry_count(), MARK_GROUP_PAGE as u64);
    let nodes = backend.objects.load(Ordering::Relaxed);
    assert!(nodes > MARK_PAGE as u64);
    assert_eq!(
        backend.publications.load(Ordering::Relaxed),
        nodes.div_ceil(MARK_PAGE as u64)
    );
    // A new reader authenticates nodes in the final partial publication too.
    assert_eq!(
        marks
            .map
            .get(grouped.content_id(), entries.last().unwrap().0)
            .unwrap(),
        Some(entries.last().unwrap().1)
    );

    let reads = backend.reads.load(Ordering::Relaxed);
    let publications = backend.publications.load(Ordering::Relaxed);
    let mut other = entries[1].0.as_bytes();
    other[0] |= 0x10;
    for invalid in [
        [entries[0], entries[0]],
        [entries[1], entries[0]],
        [entries[0], (CampaignHash::from_bytes(other), entries[1].1)],
    ] {
        assert!(matches!(
            marks.map.insert_prefix_batch_with_boundary(
                marks.root.content_id(),
                &invalid,
                &account,
                &mut || operation.check(),
            ),
            Err(crucible_campaign::CampaignStoreError::InvalidMerkle { .. })
        ));
    }
    entries.push(*entries.last().unwrap());
    assert!(matches!(
        marks.map.insert_prefix_batch_with_boundary(
            marks.root.content_id(),
            &entries,
            &account,
            &mut || operation.check(),
        ),
        Err(crucible_campaign::CampaignStoreError::InvalidMerkle { .. })
    ));
    assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
    assert_eq!(backend.publications.load(Ordering::Relaxed), publications);
}

#[test]
fn mixed_prefix_group_keeps_duplicate_positions_until_final_acceptance() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let source = fixture.context();
    let backend = counted(source.marks());
    let refuse_after_commit = AtomicBool::new(false);
    let mut boundary = || {
        source.check()?;
        if refuse_after_commit.load(Ordering::Relaxed)
            && backend.publications.load(Ordering::Relaxed) > 0
        {
            return Err(StoreError::Unsupported {
                capability: "original-after-group-publication",
            });
        }
        Ok(())
    };
    let operation =
        CampaignGcOperationContext::new(backend.clone(), source.original(), &mut boundary).unwrap();
    let mut marks = Reachability::with_backend(backend.clone(), source.original()).unwrap();
    let prior = marks.root;
    let mut pending = PendingMarks::new(&operation).unwrap();
    pending.promote(&operation).unwrap();
    let first = page(0);
    let prefix = mark_key(first).as_bytes()[0];
    let neighbor = (1..65536)
        .map(page)
        .find(|id| {
            let candidate = mark_key(*id).as_bytes()[0];
            candidate != prefix && candidate / 16 == prefix / 16
        })
        .unwrap();
    let outside = (1..65536)
        .map(page)
        .find(|id| mark_key(*id).as_bytes()[0] / 16 != prefix / 16)
        .unwrap();
    for id in [first, first, neighbor, outside] {
        pending.insert(&mut marks, id, &operation).unwrap();
    }
    backend.publications.store(0, Ordering::Relaxed);
    refuse_after_commit.store(true, Ordering::Relaxed);

    let error = pending
        .publish_group(&mut marks, usize::from(prefix) / 16, &operation)
        .unwrap_err();
    assert!(
        matches!(&error,
            StoreError::StreamIo { source, .. }
            if matches!(source.get_ref().and_then(|source| source.downcast_ref::<crucible_campaign::CampaignStoreError>()),
                Some(crucible_campaign::CampaignStoreError::Store(StoreError::Unsupported {
                    capability: "original-after-group-publication"
                })))
        ),
        "typed first original post-publication refusal: {error:?}"
    );
    assert_eq!(marks.root, prior);
    assert_eq!(pending.staged, 4);
    assert_eq!(pending.slots.iter().flatten().count(), 4);
    assert_eq!(pending.counts[usize::from(prefix)], 2);
    assert!(backend.objects.load(Ordering::Relaxed) > 0);
    refuse_after_commit.store(false, Ordering::Relaxed);
    operation.check().unwrap();
    pending
        .publish_group(&mut marks, usize::from(prefix) / 16, &operation)
        .unwrap();

    assert_eq!(marks.len(), 2);
    assert_eq!(pending.staged, 1);
    assert_eq!(pending.slots.iter().flatten().count(), 1);
    assert_eq!(pending.counts[usize::from(prefix)], 0);
    assert!(!marks.contains(&outside).unwrap());
    pending.flush(&mut marks, &operation).unwrap();
    assert_eq!(pending.staged, 0);
    assert_eq!(marks.len(), 3);
    for id in [first, neighbor, outside] {
        assert!(marks.contains(&id).unwrap());
    }
}
