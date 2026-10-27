//! Genuine backend reads and count/prefix refusals for lazily advanced closure cursors.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_store::content_store::{
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
        inner: MemoryBlobBackend::new("closure-cursor", 16 * 1024 * 1024),
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

fn drain(
    map: &MerkleMap,
    root: ContentId,
) -> Result<(Vec<ContentId>, Vec<ContentId>), CampaignStoreError> {
    let mut cursor = map.closure_cursor(root)?;
    let mut nodes = Vec::new();
    let mut values = Vec::new();
    while let Some(step) = map.advance_closure_cursor(&mut cursor)? {
        nodes.push(step.node);
        values.extend(step.values);
    }
    Ok((nodes, values))
}

#[test]
fn cursor_yields_every_node_and_value_once_with_one_read_per_node() {
    let (backend, map, first, second) = fixture();

    let (first_nodes, first_values) = drain(&map, first).expect("first complete walk");
    assert_eq!(first_nodes.len(), 2);
    assert_eq!(first_nodes[0], first);
    assert_eq!(first_values.len(), 2);
    assert_eq!(backend.reads.load(Ordering::Relaxed), first_nodes.len());

    backend.reads.store(0, Ordering::Relaxed);
    let (second_nodes, second_values) = drain(&map, second).expect("second complete walk");
    assert_eq!(second_nodes.len(), 2);
    assert_eq!(second_values.len(), 3);
    assert!(
        first_values
            .iter()
            .all(|value| second_values.contains(value))
    );
    assert_eq!(backend.reads.load(Ordering::Relaxed), second_nodes.len());
}

#[test]
fn cursor_refuses_wrong_parent_counts_and_grafted_prefixes() {
    let (_, map, first, second) = fixture();

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
        drain(&map, wrong_count_id),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "child-entry-count-mismatch"
        })
    ));

    let mut wrong_prefix = map.read_node(first, 0).expect("original parent");
    let child = wrong_prefix.entries.remove(&1).expect("shared subtree");
    wrong_prefix.entries.insert(2, child.clone());
    let wrong_prefix_id = map
        .persist_node(&wrong_prefix)
        .expect("real grafted parent");
    assert!(matches!(
        drain(&map, wrong_prefix_id),
        Err(CampaignStoreError::InvalidMerkle {
            reason: "leaf-ancestor-prefix-mismatch"
        })
    ));

    // A subtree read as a root fails its exact depth check.
    let MerkleEntry::Node { content_id, .. } = child else {
        panic!("shared subtree is a node");
    };
    assert!(drain(&map, content_id).is_err());
}

#[test]
fn cursor_refuses_missing_corrupt_and_unavailable_nodes() {
    for fault in [1, 2, 3] {
        let (backend, map, first, _) = fixture();
        backend.fault.store(fault, Ordering::Relaxed);

        assert!(drain(&map, first).is_err());
        assert_eq!(backend.reads.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn streaming_verification_checks_leaf_presence_through_the_cursor() {
    let (backend, map, first, _) = fixture();
    backend.fault.store(4, Ordering::Relaxed);

    assert!(matches!(
        map.verify_closure_streaming(first),
        Err(CampaignStoreError::Store(StoreError::NotFound { .. }))
    ));

    backend.fault.store(0, Ordering::Relaxed);
    assert_eq!(
        map.verify_closure_streaming(first)
            .expect("complete authentication")
            .entry_count(),
        2
    );
}
