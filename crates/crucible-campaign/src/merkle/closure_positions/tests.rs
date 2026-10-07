//! Genuine backend reads and position/count refusals for complete closure walks.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_cas::content_store::{
    BackendCapabilities, ByteRange, MemoryBlobBackend, PutReceipt, StoreError,
};

use super::*;

struct CountingBackend {
    inner: MemoryBlobBackend,
    reads: AtomicUsize,
    fault: AtomicUsize,
}

impl ImmutableBlobBackend for CountingBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        if self.fault.load(Ordering::Relaxed) == 4 {
            return Ok(false);
        }
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        match self.fault.load(Ordering::Relaxed) {
            1 => Err(StoreError::NotFound { id }),
            2 => {
                let handle = self.inner.read(id, range)?;
                let mut bytes = handle.read_all(MAX_MERKLE_NODE_ENVELOPE_BYTES as u64)?;
                bytes[0] ^= 1;
                Ok(BlobHandle::from_bytes(bytes))
            }
            3 => Err(StoreError::Unavailable),
            _ => self.inner.read(id, range),
        }
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

fn hash(first_byte: u8) -> CampaignHash {
    let mut bytes = [0; 32];
    bytes[0] = first_byte;
    CampaignHash::from_bytes(bytes)
}

fn fixture() -> (Arc<CountingBackend>, MerkleMap, ContentId, ContentId) {
    let backend = Arc::new(CountingBackend {
        inner: MemoryBlobBackend::new("closure-count-ledger", 16 * 1024 * 1024),
        reads: AtomicUsize::new(0),
        fault: AtomicUsize::new(0),
    });
    let map = MerkleMap::new(backend.clone());
    let mut entries = Vec::new();
    for number in [0x10, 0x11, 0x20] {
        let bytes = vec![number];
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("real leaf object");
        entries.push((hash(number), id));
    }
    let first = map
        .build_from_sorted(entries[..2].iter().copied())
        .expect("first canonical root")
        .content_id();
    let second = map
        .build_from_sorted(entries)
        .expect("second canonical root")
        .content_id();
    backend.reads.store(0, Ordering::Relaxed);
    (backend, map, first, second)
}

#[test]
fn shared_subtrees_preserve_the_canonical_union_with_fewer_reads() {
    let (backend, map, first, second) = fixture();
    let mut expected_values = BTreeSet::new();
    for root in [first, second] {
        let verified = map.verify_closure_objects(root).expect("independent walk");
        expected_values.extend(verified.values);
    }
    let independent_reads = backend.reads.load(Ordering::Relaxed);

    backend.reads.store(0, Ordering::Relaxed);
    let mut positions = VerifiedMerklePositions::objects();
    let mut actual_values = BTreeSet::new();
    for (root, count) in [(first, 2), (second, 3)] {
        let verified = map
            .verify_closure_objects_cached(root, &mut positions)
            .expect("shared complete walks");
        assert_eq!(verified.root.content_id(), root);
        assert_eq!(verified.root.entry_count(), count);
        actual_values.extend(verified.values);
    }
    let shared_reads = backend.reads.load(Ordering::Relaxed);
    assert_eq!(actual_values, expected_values);
    assert_eq!(actual_values.len(), 3);
    assert_eq!(positions.len(), 3);
    assert_eq!(shared_reads, positions.len());
    assert!(shared_reads < independent_reads);

    let repeated = map
        .verify_closure_objects_cached(second, &mut positions)
        .expect("already complete exact root");
    assert_eq!(repeated.root.entry_count(), 3);
    assert!(repeated.values.is_empty());
    assert_eq!(backend.reads.load(Ordering::Relaxed), shared_reads);
    eprintln!(
        "closure-count-ledger: independent_reads={independent_reads} shared_reads={shared_reads} unique_positions={}",
        positions.len()
    );
}

#[test]
fn retained_counts_do_not_hide_wrong_parent_counts_prefixes_or_depth() {
    let (backend, map, first, second) = fixture();
    let mut positions = VerifiedMerklePositions::objects();
    map.verify_closure_objects_cached(first, &mut positions)
        .expect("complete original prefix");
    let original_positions = positions.counts.clone();

    let mut wrong_count = map.read_node(second, 0).expect("original parent");
    let MerkleEntry::Node { entry_count, .. } =
        wrong_count.entries.get_mut(&1).expect("shared subtree")
    else {
        panic!("shared subtree is a node");
    };
    *entry_count += 1;
    wrong_count
        .recompute_count()
        .expect("self-consistent parent");
    let wrong_count_id = map.persist_node(&wrong_count).expect("real wrong parent");
    assert!(matches!(
        map.verify_closure_objects_cached(wrong_count_id, &mut positions),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "child-entry-count-mismatch"
        })
    ));
    assert_eq!(positions.counts, original_positions);

    let mut wrong_prefix = map.read_node(first, 0).expect("original parent");
    let child = wrong_prefix.entries.remove(&1).expect("shared subtree");
    wrong_prefix.entries.insert(2, child.clone());
    let wrong_prefix_id = map
        .persist_node(&wrong_prefix)
        .expect("real grafted parent");
    let before = backend.reads.load(Ordering::Relaxed);
    assert!(matches!(
        map.verify_closure_objects_cached(wrong_prefix_id, &mut positions),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "leaf-ancestor-prefix-mismatch"
        })
    ));
    assert!(backend.reads.load(Ordering::Relaxed) >= before + 2);
    assert_eq!(positions.counts, original_positions);

    let MerkleEntry::Node { content_id, .. } = child else {
        panic!("shared subtree is a node");
    };
    assert!(
        map.verify_closure_objects_cached(content_id, &mut positions)
            .is_err()
    );
    assert_eq!(positions.counts, original_positions);
}

#[test]
fn first_authentication_refuses_missing_corrupt_and_unavailable_nodes() {
    for fault in [1, 2, 3] {
        let (backend, map, first, _) = fixture();
        backend.fault.store(fault, Ordering::Relaxed);
        let mut positions = VerifiedMerklePositions::objects();
        assert!(
            map.verify_closure_objects_cached(first, &mut positions)
                .is_err()
        );
        assert_eq!(backend.reads.load(Ordering::Relaxed), 1);
        assert_eq!(positions.len(), 0);
    }
}

#[test]
fn failed_leaf_presence_walk_preserves_only_prior_completed_positions() {
    let (backend, map, first, _) = fixture();
    let empty = map.empty().expect("canonical empty root").content_id();
    let mut positions = VerifiedMerklePositions::objects();
    map.verify_closure_objects_cached(empty, &mut positions)
        .expect("complete empty root");
    let prior = positions.counts.clone();

    backend.fault.store(4, Ordering::Relaxed);
    assert!(matches!(
        map.verify_closure_objects_cached(first, &mut positions),
        Err(CampaignStoreError::Store(StoreError::NotFound { .. }))
    ));
    assert_eq!(positions.counts, prior);

    backend.fault.store(0, Ordering::Relaxed);
    let before = backend.reads.load(Ordering::Relaxed);
    assert_eq!(
        map.verify_closure_objects_cached(first, &mut positions)
            .expect("independent successful authentication")
            .root
            .entry_count(),
        2
    );
    assert_eq!(backend.reads.load(Ordering::Relaxed), before + 2);
}

#[test]
fn a_new_walk_authenticates_again_and_never_upgrades_structure_only_proofs() {
    let (backend, map, first, _) = fixture();
    let mut completed = VerifiedMerklePositions::objects();
    map.verify_closure_objects_cached(first, &mut completed)
        .expect("first full walk");
    backend.fault.store(2, Ordering::Relaxed);
    let mut fresh = VerifiedMerklePositions::objects();
    assert!(
        map.verify_closure_objects_cached(first, &mut fresh)
            .is_err()
    );
    assert_eq!(fresh.len(), 0);

    backend.fault.store(4, Ordering::Relaxed);
    let mut structure = VerifiedMerklePositions::structure();
    map.verify_closure_structure_cached(first, &mut structure)
        .expect("enclosing walk owns leaf reads");
    assert!(matches!(
        map.verify_closure_objects_cached(first, &mut structure),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "closure-verification-mode-mismatch"
        })
    ));
    assert!(map.verify_closure_objects(first).is_err());
}
