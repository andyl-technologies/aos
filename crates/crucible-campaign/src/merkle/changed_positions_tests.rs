//! Checks authenticated child reuse and retained changed-child validation.

// crucible-lint: allow panic-shortcut -- fixtures localize exact read and authentication failures.
#![allow(clippy::expect_used)]

use super::*;
use crucible_cas::content_store::{
    BackendCapabilities, ByteRange, ImmutableBlobBackend, MemoryBlobBackend, PutReceipt, StoreError,
};
use std::sync::Mutex;

/// Observes real immutable reads and injects one explicitly malformed body.
struct ReadObservedBackend {
    inner: MemoryBlobBackend,
    reads: Mutex<BTreeMap<ContentId, usize>>,
    malformed: Mutex<Option<ContentId>>,
}

impl ImmutableBlobBackend for ReadObservedBackend {
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
        *self
            .reads
            .lock()
            .expect("read counts")
            .entry(id)
            .or_default() += 1;
        if *self.malformed.lock().expect("malformed source") == Some(id) {
            return Ok(BlobHandle::from_bytes(vec![0]));
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

struct Fixture {
    backend: Arc<ReadObservedBackend>,
    map: MerkleMap,
    prior: ContentId,
    third_value: ContentId,
    original_child: ContentId,
}

fn key(first_byte: u8) -> CampaignHash {
    let mut bytes = [0; 32];
    bytes[0] = first_byte;
    CampaignHash::from_bytes(bytes)
}

fn fixture() -> Fixture {
    let backend = Arc::new(ReadObservedBackend {
        inner: MemoryBlobBackend::new("changed-position-reads", 1024 * 1024),
        reads: Mutex::new(BTreeMap::new()),
        malformed: Mutex::new(None),
    });
    let map = MerkleMap::new(backend.clone());
    let mut values = Vec::new();
    for name in ["first", "second", "third"] {
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, name.as_bytes());
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(name.as_bytes().to_vec()))
            .expect("publish actual leaf");
        values.push(id);
    }
    let empty = map.empty().expect("empty map");
    let first = map
        .insert(empty.content_id(), key(0x10), values[0])
        .expect("first leaf");
    let prior = map
        .insert(first.content_id(), key(0x11), values[1])
        .expect("second colliding leaf")
        .content_id();

    // Production acceptance authenticates the complete parent head before
    // calling this walk. Reproduce the complete prior-trie premise here.
    map.verify_closure(prior)
        .expect("authenticate prior closure");
    let node = map.read_node(prior, 0).expect("prior root");
    let MerkleEntry::Node {
        content_id: original_child,
        entry_count: 2,
    } = node.entries[&1]
    else {
        panic!("prior root must contain a two-entry child");
    };
    Fixture {
        backend,
        map,
        prior,
        third_value: values[2],
        original_child,
    }
}

#[test]
fn unchanged_authenticated_child_is_not_read_again() {
    let fixture = fixture();
    let next = fixture
        .map
        .insert(fixture.prior, key(0x20), fixture.third_value)
        .expect("add a different branch")
        .content_id();
    fixture.backend.reads.lock().expect("read counts").clear();
    let mut positions = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut values = BTreeSet::new();

    fixture
        .map
        .collect_changed_node_positions(
            fixture.prior,
            next,
            &mut positions,
            &mut roots,
            &mut values,
            100,
        )
        .expect("charge changed positions");

    assert_eq!(positions, BTreeSet::from([(next, Vec::new())]));
    assert_eq!(roots, BTreeSet::from([next]));
    assert_eq!(values, BTreeSet::from([fixture.third_value]));
    assert!(
        !fixture
            .backend
            .reads
            .lock()
            .expect("read counts")
            .contains_key(&fixture.original_child)
    );
}

#[test]
fn changed_count_for_reused_child_still_reads_and_refuses() {
    let fixture = fixture();
    let next = fixture
        .map
        .insert(fixture.prior, key(0x20), fixture.third_value)
        .expect("add a different branch")
        .content_id();
    let mut forged = fixture.map.read_node(next, 0).expect("new root");
    let MerkleEntry::Node { entry_count, .. } = forged.entries.get_mut(&1).expect("child") else {
        panic!("existing branch must remain a child");
    };
    *entry_count += 1;
    forged.recompute_count().expect("consistent parent total");
    let forged_id = fixture
        .map
        .persist_node(&forged)
        .expect("publish forged root");
    fixture.backend.reads.lock().expect("read counts").clear();

    let result = fixture.map.collect_changed_node_positions(
        fixture.prior,
        forged_id,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        100,
    );

    assert!(matches!(
        result,
        Err(CampaignStoreError::InvalidMerkle {
            reason: "child-entry-count-mismatch"
        })
    ));
    assert_eq!(
        fixture.backend.reads.lock().expect("read counts")[&fixture.original_child],
        1
    );
}

#[test]
fn changed_child_body_is_still_read_and_authenticated() {
    let fixture = fixture();
    let next = fixture
        .map
        .insert(fixture.prior, key(0x10), fixture.third_value)
        .expect("replace a leaf without changing the child count")
        .content_id();
    let node = fixture.map.read_node(next, 0).expect("new root");
    let MerkleEntry::Node { content_id, .. } = node.entries[&1] else {
        panic!("changed branch must remain a child");
    };
    assert_ne!(content_id, fixture.original_child);
    *fixture.backend.malformed.lock().expect("malformed source") = Some(content_id);
    fixture.backend.reads.lock().expect("read counts").clear();

    let result = fixture.map.collect_changed_node_positions(
        fixture.prior,
        next,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        100,
    );

    assert!(result.is_err());
    assert_eq!(
        fixture.backend.reads.lock().expect("read counts")[&content_id],
        1
    );
}
