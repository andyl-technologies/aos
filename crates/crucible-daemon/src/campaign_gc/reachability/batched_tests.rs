//! Checked mark-page equivalence, bounded storage work and failed-root custody.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible_cas::content_store::{
    BlobHandle, ByteRange, ObjectKind, OwnedBlobBytes, PutBatchReceipt, PutReceipt,
    StorePhysicalQuotaGuard,
};

use super::*;

pub(super) struct CountedBackend {
    inner: Arc<dyn ImmutableBlobBackend>,
    pub(super) reads: AtomicU64,
    checked_generic_reads: AtomicU64,
    checked_native_reads: AtomicU64,
    refuse_native_read: AtomicBool,
    pub(super) publications: AtomicU64,
    pub(super) objects: AtomicU64,
    pub(super) refuse_after_publication: AtomicBool,
    pub(super) refuse_read: AtomicBool,
    pub(super) refuse_on_publication: AtomicU64,
}

impl ImmutableBlobBackend for CountedBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn admit_object_graph(&self, kinds: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.inner.admit_object_graph(kinds)
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.inner.metadata_resources()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.refuse_read.load(Ordering::Relaxed) {
            return Err(StoreError::Unsupported {
                capability: "actual-run-read-refusal",
            });
        }
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
        self.checked_generic_reads.fetch_add(1, Ordering::Relaxed);
        if self.refuse_read.load(Ordering::Relaxed) {
            return Err(StoreError::Unsupported {
                capability: "actual-run-read-refusal",
            });
        }
        self.inner.read_with_boundary(original, id, range, boundary)
    }

    fn read_merkle_node_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.checked_native_reads.fetch_add(1, Ordering::Relaxed);
        if self.refuse_native_read.load(Ordering::Relaxed) {
            return Err(StoreError::Unsupported {
                capability: "actual-native-mark-read-refusal",
            });
        }
        self.inner
            .read_merkle_node_with_boundary(original, id, boundary)
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
        let ordinal = self.publications.fetch_add(1, Ordering::Relaxed) + 1;
        self.objects
            .fetch_add(objects.len() as u64, Ordering::Relaxed);
        let receipt = self
            .inner
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        if self.refuse_after_publication.load(Ordering::Relaxed)
            || self.refuse_on_publication.load(Ordering::Relaxed) == ordinal
        {
            return Err(StoreError::Unsupported {
                capability: "actual-mark-publication-then-refusal",
            });
        }
        Ok(receipt)
    }
}

pub(super) fn counted(inner: Arc<dyn ImmutableBlobBackend>) -> Arc<CountedBackend> {
    Arc::new(CountedBackend {
        inner,
        reads: AtomicU64::new(0),
        checked_generic_reads: AtomicU64::new(0),
        checked_native_reads: AtomicU64::new(0),
        refuse_native_read: AtomicBool::new(false),
        publications: AtomicU64::new(0),
        objects: AtomicU64::new(0),
        refuse_after_publication: AtomicBool::new(false),
        refuse_read: AtomicBool::new(false),
        refuse_on_publication: AtomicU64::new(0),
    })
}

pub(super) fn page(index: u64) -> ContentId {
    ContentId::for_bytes(ObjectKind::RamExtent, 1, &index.to_be_bytes())
}

const MARK_PAGE: usize = MerkleMap::MAX_CHECKED_BATCH_UPSERTS;
const MARK_GROUP_PAGE: usize = MerkleMap::MAX_CHECKED_PREFIX_UPSERTS;

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

// Probes the same portable account with temporary real loans. This does not
// measure allocator payloads or certify a deployed physical quota.
pub(super) fn available_resident_bytes(resources: &dyn StorePhysicalQuotaGuard) -> u64 {
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
fn checked_mark_updates_forward_actual_native_reads_without_deferred_sources() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let operation = fixture.context();
    let backend = counted(operation.marks());
    let marks = Reachability::with_backend(backend.clone(), operation.original()).unwrap();
    let account = mark_account(operation.original()).unwrap();
    let _scope = account.enter();
    let _credit = operation.reserve_array::<MarkEntry>(MARK_PAGE).unwrap();
    let mut entries = Vec::with_capacity(MARK_PAGE);
    let mut root = marks.root;

    for start in [0, MARK_PAGE as u64] {
        entries.clear();
        entries.extend((start..start + MARK_PAGE as u64).map(|index| {
            let id = page(index);
            (mark_key(id), id)
        }));
        entries.sort_unstable_by_key(|entry| entry.0);
        root = marks
            .map
            .insert_batch_with_boundary(root.content_id(), &entries, &account, &mut || {
                operation.check()
            })
            .unwrap();
    }

    let reads = backend.checked_native_reads.load(Ordering::Relaxed);
    assert!(
        reads > 1,
        "authenticates existing children, not only the empty root"
    );
    assert_eq!(backend.checked_generic_reads.load(Ordering::Relaxed), 0);
    assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
    assert_eq!(root.entry_count(), 2 * MARK_PAGE as u64);
    eprintln!(
        "actual native mark work: reads={reads} publications={} nodes={}",
        backend.publications.load(Ordering::Relaxed),
        backend.objects.load(Ordering::Relaxed)
    );
    for index in [
        0,
        MARK_PAGE as u64 - 1,
        MARK_PAGE as u64,
        2 * MARK_PAGE as u64 - 1,
    ] {
        assert_eq!(
            marks
                .map
                .get_with_boundary(
                    root.content_id(),
                    mark_key(page(index)),
                    &account,
                    &mut || operation.check(),
                )
                .unwrap(),
            Some(page(index))
        );
    }
    operation.check().unwrap();
}

#[test]
fn checked_mark_native_read_refusal_precedes_replacement_publication() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let operation = fixture.context();
    let backend = counted(operation.marks());
    let marks = Reachability::with_backend(backend.clone(), operation.original()).unwrap();
    let account = mark_account(operation.original()).unwrap();
    let prior = marks.root;
    let publications = backend.publications.load(Ordering::Relaxed);
    backend.refuse_native_read.store(true, Ordering::Relaxed);

    let error = marks
        .map
        .insert_batch_with_boundary(
            prior.content_id(),
            &[(mark_key(page(1)), page(1))],
            &account,
            &mut || operation.check(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        crucible_campaign::CampaignStoreError::Store(StoreError::Unsupported {
            capability: "actual-native-mark-read-refusal"
        })
    ));
    assert_eq!(marks.root, prior);
    assert_eq!(backend.publications.load(Ordering::Relaxed), publications);
    assert_eq!(backend.checked_native_reads.load(Ordering::Relaxed), 1);
    assert_eq!(backend.checked_generic_reads.load(Ordering::Relaxed), 0);
    operation.check().unwrap();
}
