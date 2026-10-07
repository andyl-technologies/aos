//! Genuine node reads, FIFO custody, and caller-specific traversal refusals.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ImmutableBlobBackend, MemoryBlobBackend,
    PutReceipt, StoreError,
};

use super::*;
use crate::merkle::{
    CampaignHash, CampaignRecordKind, MerkleEntry, ObjectEnvelope, ObjectKind, codec,
};

struct CountingBackend {
    inner: MemoryBlobBackend,
    reads: AtomicUsize,
    corrupt: AtomicBool,
}

impl ImmutableBlobBackend for CountingBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let handle = self.inner.read(id, range)?;
        if self.corrupt.load(Ordering::Relaxed) {
            let mut bytes = handle.read_all(64 * 1024)?;
            bytes[0] ^= 1;
            return Ok(BlobHandle::from_bytes(bytes));
        }
        Ok(handle)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

fn fixture() -> (Arc<CountingBackend>, MerkleMap) {
    let backend = Arc::new(CountingBackend {
        inner: MemoryBlobBackend::new("merkle-validation-reads", 16 * 1024 * 1024),
        reads: AtomicUsize::new(0),
        corrupt: AtomicBool::new(false),
    });
    let map = MerkleMap::new(backend.clone());
    (backend, map)
}

fn hash(first_byte: u8) -> CampaignHash {
    let mut bytes = [0; 32];
    bytes[0] = first_byte;
    CampaignHash::from_bytes(bytes)
}

fn value(name: &str) -> ContentId {
    ContentId::for_bytes(ObjectKind::CampaignFact, 1, name.as_bytes())
}

fn singleton(map: &MerkleMap, number: usize) -> ContentId {
    map.build_from_sorted([(hash(0x10), value(&format!("value-{number}")))])
        .expect("canonical singleton")
        .content_id()
}

#[test]
fn shared_reads_preserve_lookup_and_unpublished_overlay_identity() {
    let (backend, map) = fixture();
    let root = map
        .build_from_sorted([(hash(0x10), value("first")), (hash(0x11), value("second"))])
        .expect("split trie")
        .content_id();
    let updates = BTreeMap::from([(hash(0x12), value("third"))]);
    let next = map.root_after_upserts(root, &updates).expect("preview");

    backend.reads.store(0, Ordering::Relaxed);
    let mut ordinary = MerkleReadSession::new(&map, None);
    let expected = [0x10, 0x11, 0x12].map(|key| ordinary.get(root, hash(key)).expect("lookup"));
    assert!(
        ordinary
            .equals_after_upserts(root, next, &updates)
            .expect("overlay")
    );
    let original_reads = backend.reads.load(Ordering::Relaxed);

    backend.reads.store(0, Ordering::Relaxed);
    let mut retained = MerkleValidationReads::default();
    let mut shared = MerkleReadSession::new(&map, Some(&mut retained));
    let actual = [0x10, 0x11, 0x12].map(|key| shared.get(root, hash(key)).expect("lookup"));
    assert_eq!(actual, expected);
    assert_eq!(actual, [Some(value("first")), Some(value("second")), None]);
    assert!(
        shared
            .equals_after_upserts(root, next, &updates)
            .expect("overlay")
    );
    assert!(
        !shared
            .equals_after_upserts(root, root, &updates)
            .expect("different root")
    );
    assert!(backend.reads.load(Ordering::Relaxed) < original_reads);
}

#[test]
fn node_limit_uses_fifo_without_promoting_hits() {
    let (backend, map) = fixture();
    let roots: Vec<_> = (0..=MAX_RETAINED_NODES)
        .map(|number| singleton(&map, number))
        .collect();
    let mut retained = MerkleValidationReads::default();
    for root in &roots[..MAX_RETAINED_NODES] {
        retained
            .read_node(&map, *root, 0)
            .expect("authenticated root");
    }
    assert_eq!(retained.retained_usage().0, MAX_RETAINED_NODES);
    assert!(retained.retained_usage().1 <= MAX_RETAINED_BYTES);

    let before = backend.reads.load(Ordering::Relaxed);
    retained
        .read_node(&map, roots[0], 0)
        .expect("FIFO oldest hit");
    assert_eq!(backend.reads.load(Ordering::Relaxed), before);
    retained
        .read_node(&map, roots[MAX_RETAINED_NODES], 0)
        .expect("one additional root");
    assert!(!retained.nodes.contains_key(&roots[0]));
    assert_eq!(retained.retained_id(), Some(roots[1]));
    assert_eq!(retained.retained_usage().0, MAX_RETAINED_NODES);

    let before = backend.reads.load(Ordering::Relaxed);
    retained
        .read_node(&map, roots[0], 0)
        .expect("evicted root reread");
    assert_eq!(backend.reads.load(Ordering::Relaxed), before + 1);
    retained.clear();
    assert_eq!(retained.retained_usage(), (0, 0));
    assert!(retained.order.is_empty());
}

#[test]
fn canonical_byte_limit_evicts_once_and_bypasses_oversized_nodes() {
    let (backend, map) = fixture();
    let roots = [singleton(&map, 0), singleton(&map, 1), singleton(&map, 2)];
    let charge = map
        .read_node_with_bytes(roots[0], 0)
        .expect("canonical bytes")
        .1
        .len();
    for root in roots {
        assert_eq!(
            map.read_node_with_bytes(root, 0)
                .expect("same-sized bytes")
                .1
                .len(),
            charge
        );
    }
    let mut retained = MerkleValidationReads::with_limits(MAX_RETAINED_NODES, 2 * charge);
    retained.read_node(&map, roots[0], 0).expect("first charge");
    retained
        .read_node(&map, roots[1], 0)
        .expect("second charge");
    retained
        .read_node(&map, roots[0], 0)
        .expect("single-charge hit");
    assert_eq!(retained.retained_usage(), (2, 2 * charge));
    retained
        .read_node(&map, roots[2], 0)
        .expect("cumulative byte eviction");
    assert_eq!(retained.retained_id(), Some(roots[1]));
    assert_eq!(retained.retained_usage(), (2, 2 * charge));

    let mut too_small = MerkleValidationReads::with_limits(MAX_RETAINED_NODES, charge - 1);
    let before = backend.reads.load(Ordering::Relaxed);
    for _ in 0..2 {
        too_small
            .read_node(&map, roots[0], 0)
            .expect("uncached oversized node");
    }
    assert_eq!(backend.reads.load(Ordering::Relaxed), before + 2);
    assert_eq!(too_small.retained_usage(), (0, 0));
}

#[test]
fn cache_hits_recheck_depth_child_counts_and_ancestor_prefix() {
    let (_, map) = fixture();
    let root = map
        .build_from_sorted([(hash(0x10), value("first")), (hash(0x11), value("second"))])
        .expect("split trie")
        .content_id();
    let mut retained = MerkleValidationReads::default();
    retained.read_node(&map, root, 0).expect("warm root");
    assert!(matches!(
        retained.read_node(&map, root, 1),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "node-depth-mismatch"
        })
    ));

    let mut parent = map.read_node(root, 0).expect("original parent");
    let MerkleEntry::Node {
        content_id: child_id,
        entry_count,
    } = parent.entries.get_mut(&1).expect("split child")
    else {
        panic!("expected split child");
    };
    let original_child = retained.read_node(&map, *child_id, 1).expect("warm child");
    *entry_count += 1;
    parent.recompute_count().expect("parent count");
    let forged = map
        .persist_node(&parent)
        .expect("canonical wrong parent count");
    assert!(matches!(
        map.get_with_validation_reads(forged, hash(0x10), &mut retained),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "child-entry-count-mismatch"
        })
    ));

    let mut child = original_child;
    child.entries.insert(
        0,
        MerkleEntry::Leaf {
            key: hash(0x20),
            value: value("wrong-prefix"),
        },
    );
    child.recompute_count().expect("unchanged count");
    let wrong_child = map
        .persist_node(&child)
        .expect("valid local slot with wrong ancestor");
    retained
        .read_node(&map, wrong_child, 1)
        .expect("warm locally valid child");
    parent.entries.insert(
        1,
        MerkleEntry::Node {
            content_id: wrong_child,
            entry_count: child.entry_count,
        },
    );
    parent.recompute_count().expect("matching parent count");
    let wrong_prefix = map.persist_node(&parent).expect("canonical wrong ancestor");
    assert!(matches!(
        map.get_with_validation_reads(wrong_prefix, hash(0x10), &mut retained),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "leaf-ancestor-prefix-mismatch"
        })
    ));
}

#[test]
fn missing_corrupt_or_mismatched_child_table_never_enters_custody() {
    let (backend, map) = fixture();
    let root = singleton(&map, 0);
    let node = map.read_node(root, 0).expect("original node");
    let envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::MerkleNode,
        Default::default(),
        codec::encode(&node),
    )
    .expect("wrong child table envelope");
    let wrong_table = envelope.content_id();
    backend
        .put_if_absent(
            wrong_table,
            &BlobHandle::from_bytes(envelope.canonical_bytes()),
        )
        .expect("store wrong table");
    let missing = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"absent node");
    let mut retained = MerkleValidationReads::default();
    assert!(retained.read_node(&map, missing, 0).is_err());
    assert!(matches!(
        retained.read_node(&map, wrong_table, 0),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "node-child-table-mismatch"
        })
    ));
    assert_eq!(retained.retained_usage(), (0, 0));

    backend.corrupt.store(true, Ordering::Relaxed);
    assert!(retained.read_node(&map, root, 0).is_err());
    assert_eq!(retained.retained_usage(), (0, 0));
    backend.corrupt.store(false, Ordering::Relaxed);
    retained
        .read_node(&map, root, 0)
        .expect("new authentic read after corruption");
    assert_eq!(retained.retained_usage().0, 1);
}
