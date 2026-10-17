//! Stored canonical child-table mutations and validation-priority controls.

// crucible-lint: allow panic-shortcut -- fixtures require exact stored validation failures.
#![allow(clippy::expect_used)]

use super::*;
use crucible_cas::content_store::DirectoryBlobBackend;

fn full_node() -> MerkleNode {
    let entries = (0_u8..16)
        .map(|slot| {
            let entry = if slot % 2 == 0 {
                let mut key = [0; 32];
                key[0] = slot << 4;
                MerkleEntry::Leaf {
                    key: CampaignHash::from_bytes(key),
                    value: ContentId::for_bytes(ObjectKind::RamExtent, 1, &[slot]),
                }
            } else {
                MerkleEntry::Node {
                    content_id: ContentId::for_bytes(ObjectKind::MerkleNode, 1, &[slot]),
                    entry_count: 1,
                }
            };
            (slot, entry)
        })
        .collect();
    MerkleNode {
        schema_version: MERKLE_NODE_SCHEMA_VERSION,
        depth: 0,
        entry_count: 16,
        entries,
    }
}

fn publish(
    backend: &DirectoryBlobBackend,
    node: &MerkleNode,
    children: BTreeSet<ChildReference>,
) -> ContentId {
    let envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::MerkleNode,
        children,
        codec::encode(node),
    )
    .expect("structural envelope");
    let id = envelope.content_id();
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(envelope.canonical_bytes()))
        .expect("publish real directory bytes");
    id
}

fn assert_invalid(map: &MerkleMap, id: ContentId, depth: u8, expected: &'static str) {
    assert!(matches!(
        map.read_node(id, depth),
        Err(CampaignStoreError::InvalidMerkle { reason }) if reason == expected
    ));
}

#[test]
fn stored_tables_match_original_derivation_at_every_slot_and_empty_root() {
    let temporary = tempfile::tempdir().expect("directory");
    let backend = Arc::new(DirectoryBlobBackend::new("role-table", temporary.path()));
    let map = MerkleMap::new(backend.clone());
    let node = full_node();
    node.validate().expect("all slots validated");
    let children = node.child_references().expect("original owning derivation");
    assert!(child_table_matches(&node, &children));

    let id = publish(&backend, &node, children);
    assert_eq!(map.read_node(id, 0).expect("stored mixed table"), node);
    let empty = MerkleNode::empty();
    let empty_id = publish(&backend, &empty, BTreeSet::new());
    assert_eq!(map.read_node(empty_id, 0).expect("empty root"), empty);
}

#[test]
fn stored_table_mutations_cannot_change_role_suffix_slot_count_or_identity() {
    let temporary = tempfile::tempdir().expect("directory");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "role-mutations",
        temporary.path(),
    ));
    let map = MerkleMap::new(backend.clone());
    let node = full_node();
    let original = node.child_references().expect("original table");
    let original_id = publish(&backend, &node, original.clone());
    let victim = original.iter().next().expect("slot zero").clone();

    let mut missing = original.clone();
    assert!(missing.remove(&victim));
    let missing_id = publish(&backend, &node, missing.clone());
    assert_invalid(&map, missing_id, 0, "node-child-table-mismatch");

    for role in [
        "slot.00.node",
        "slot.0.value",
        "slot.10.value",
        "slot.00.value.extra",
    ] {
        let mut changed = missing.clone();
        changed.insert(ChildReference::new(role, victim.id()).expect("valid forged role"));
        let id = publish(&backend, &node, changed);
        assert_invalid(&map, id, 0, "node-child-table-mismatch");
    }

    let mut changed_id = missing;
    changed_id.insert(
        ChildReference::new(
            victim.role(),
            ContentId::for_bytes(ObjectKind::RamExtent, 1, b"other"),
        )
        .expect("changed child identity"),
    );
    assert_invalid(
        &map,
        publish(&backend, &node, changed_id),
        0,
        "node-child-table-mismatch",
    );

    let mut extra = original;
    extra.insert(ChildReference::new("extra", victim.id()).expect("extra edge"));
    assert_invalid(
        &map,
        publish(&backend, &node, extra),
        0,
        "node-child-table-mismatch",
    );
    assert_eq!(
        map.read_node(original_id, 0).expect("prior unchanged"),
        node
    );
}

#[test]
fn stored_schema_structure_and_depth_fail_before_child_table_comparison() {
    let temporary = tempfile::tempdir().expect("directory");
    let backend = Arc::new(DirectoryBlobBackend::new("role-priority", temporary.path()));
    let map = MerkleMap::new(backend.clone());
    let mut node = full_node();
    let valid_id = publish(&backend, &node, node.child_references().expect("table"));

    node.schema_version += 1;
    assert_invalid(
        &map,
        publish(&backend, &node, BTreeSet::new()),
        1,
        "unsupported-node-schema",
    );
    node.schema_version = MERKLE_NODE_SCHEMA_VERSION;
    node.entry_count += 1;
    assert_invalid(
        &map,
        publish(&backend, &node, BTreeSet::new()),
        1,
        "node-entry-count-mismatch",
    );
    node.entry_count = 16;
    let wrong_table = publish(&backend, &node, BTreeSet::new());
    assert_invalid(&map, wrong_table, 1, "node-depth-mismatch");
    assert_invalid(&map, wrong_table, 0, "node-child-table-mismatch");
    assert_eq!(
        map.read_node(valid_id, 0).expect("valid root unchanged"),
        node
    );
}

#[test]
fn same_directory_reader_rejects_mutated_bytes_before_table_semantics() {
    let temporary = tempfile::tempdir().expect("directory");
    let backend = Arc::new(DirectoryBlobBackend::new("role-current", temporary.path()));
    let map = MerkleMap::new(backend.clone());
    let node = full_node();
    let envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::MerkleNode,
        node.child_references().expect("table"),
        codec::encode(&node),
    )
    .expect("valid envelope");
    let id = publish(&backend, &node, envelope.children().clone());
    assert_eq!(map.read_node(id, 0).expect("initial read"), node);

    let digest = id
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = temporary
        .path()
        .join("objects")
        .join(&digest[..2])
        .join(id.encode());
    let prior = std::fs::read(&path).expect("stored bytes");
    let mut mutated = prior.clone();
    mutated.push(0);
    std::fs::write(&path, mutated).expect("append actual stored byte");
    assert!(
        map.read_node(id, 0).is_err(),
        "current bytes must authenticate"
    );
    std::fs::write(&path, prior).expect("restore exact stored bytes");
    assert_eq!(map.read_node(id, 0).expect("restored current read"), node);
}
