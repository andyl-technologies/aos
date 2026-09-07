//! Unit tests for connection-scoped inode identity and file-open state.

use std::io::Cursor as IoCursor;

use aos_sandbox_core::model::{ContentLayout, FilesystemMetadata};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, PathName, RelativePath, descriptor_for_bytes,
    hardlink_group_digest,
};

use super::*;
use crate::index::{IndexNode, IndexRecord, StructuralIndexBuilder};
use crate::{INDEX_MEDIA_TYPE_V2, IndexExpectation, IndexStaging, validate_index};

struct Fixture {
    bytes: Vec<u8>,
    tree: ObjectDescriptor,
    root: ObjectDescriptor,
    v3: bool,
}

impl Fixture {
    fn validate(&self) -> ValidatedIndex<'_> {
        let media_type = if self.v3 {
            crate::INDEX_MEDIA_TYPE_V3
        } else {
            INDEX_MEDIA_TYPE_V2
        };
        let media =
            MediaType::new(media_type).unwrap_or_else(|error| panic!("media failed: {error}"));
        let descriptor = descriptor_for_bytes(media, &self.bytes);
        validate_index(
            &self.bytes,
            16 * 1024,
            1_048_576,
            &IndexExpectation {
                index: &descriptor,
                compiler_abi: [7; 32],
                tree: &self.tree,
                root: &self.root,
                tree_features: 0,
            },
        )
        .unwrap_or_else(|error| panic!("validation failed: {error}"))
    }
}

fn fixture() -> Fixture {
    fixture_with_format([3; 32], false)
}

fn fixture_v3() -> Fixture {
    fixture_with_format([3; 32], true)
}

fn fixture_with_content_digest(content_digest: [u8; 32]) -> Fixture {
    fixture_with_format(content_digest, false)
}

fn fixture_with_format(content_digest: [u8; 32], v3: bool) -> Fixture {
    let tree = descriptor("application/vnd.aos.sandbox.tree.v1+cbor", [1; 32]);
    let root = descriptor("application/vnd.aos.sandbox.directory.v1+cbor", [2; 32]);
    let content_descriptor = descriptor("application/vnd.aos.sandbox.content.v1", content_digest);
    let content = ContentLayout::whole(content_descriptor);
    let directory_metadata = FilesystemMetadata::new(0o755, 10, 20, 30, 40, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let file_metadata = FilesystemMetadata::new(0o644, 11, 21, 31, 41, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let paths = [b"a".as_slice(), b"b".as_slice()]
        .into_iter()
        .map(|name| {
            RelativePath::new(vec![
                PathName::new(name.to_vec()).unwrap_or_else(|error| panic!("name failed: {error}")),
            ])
            .unwrap_or_else(|error| panic!("path failed: {error}"))
        })
        .collect::<Vec<_>>();
    let hardlink = hardlink_group_digest(&paths, &file_metadata, &content)
        .unwrap_or_else(|error| panic!("hardlink failed: {error}"));
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 16 * 1024, 4096);
    let mut builder = if v3 {
        StructuralIndexBuilder::new_v3(staging, [7; 32], tree.clone(), root.clone(), 0)
    } else {
        StructuralIndexBuilder::new(staging, [7; 32], tree.clone(), root.clone(), 0)
    }
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &directory_metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
    for (ordinal, name) in [b"a".as_slice(), b"b".as_slice()].into_iter().enumerate() {
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: ordinal as u32,
                name,
                metadata: &file_metadata,
                node: IndexNode::File {
                    content: &content,
                    hardlink_group: Some(hardlink),
                },
            })
            .unwrap_or_else(|error| panic!("hardlink push failed: {error}"));
    }
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 2,
            name: b"c",
            metadata: &file_metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: None,
            },
        })
        .unwrap_or_else(|error| panic!("file push failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 3,
            name: b"d",
            metadata: &file_metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: None,
            },
        })
        .unwrap_or_else(|error| panic!("file push failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 4,
            name: b"e",
            metadata: &directory_metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("directory push failed: {error}"));
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    Fixture {
        bytes: writer.into_inner(),
        tree,
        root,
        v3,
    }
}

fn fixture_v3_names(names: &[Vec<u8>]) -> Fixture {
    let tree = descriptor("application/vnd.aos.sandbox.tree.v1+cbor", [51; 32]);
    let root = descriptor("application/vnd.aos.sandbox.directory.v1+cbor", [52; 32]);
    let content_descriptor = descriptor("application/vnd.aos.sandbox.content.v1", [53; 32]);
    let content = ContentLayout::whole(content_descriptor);
    let directory_metadata = FilesystemMetadata::new(0o755, 1, 2, 3, 4, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let file_metadata = FilesystemMetadata::new(0o644, 5, 6, 7, 8, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 1_048_576, 4096);
    let mut builder =
        StructuralIndexBuilder::new_v3(staging, [7; 32], tree.clone(), root.clone(), 0)
            .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &directory_metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
    for (ordinal, name) in names.iter().enumerate() {
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: u32::try_from(ordinal)
                    .unwrap_or_else(|_| panic!("ordinal overflow")),
                name,
                metadata: &file_metadata,
                node: IndexNode::File {
                    content: &content,
                    hardlink_group: None,
                },
            })
            .unwrap_or_else(|error| panic!("file push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    Fixture {
        bytes: writer.into_inner(),
        tree,
        root,
        v3: true,
    }
}

fn descriptor(media: &str, digest: [u8; 32]) -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new(media).unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes(digest),
        0,
    )
}

fn generous_limits() -> InodeTableLimits {
    InodeTableLimits::new(32, 1_048_576, 16, 16, 16)
}

fn name(value: &[u8]) -> PathName {
    PathName::new(value.to_vec()).unwrap_or_else(|error| panic!("name failed: {error}"))
}

fn positive_parts(value: InodeLookup) -> (InodeAttributes, u64) {
    match value {
        InodeLookup::Positive {
            attributes,
            lookup_references,
        } => (attributes, lookup_references),
        InodeLookup::Negative => panic!("expected positive lookup"),
    }
}

#[test]
fn root_getattr_and_negative_lookup_do_not_grow_state() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [9; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let root = table
        .getattr(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("getattr failed: {error}"));
    assert_eq!(root.record_id, 0);
    assert_eq!(root.kind, IndexNodeKind::Directory);
    assert_eq!(table.live_nodes(), 1);
    table
        .forget(&mut [ForgetRequest::new(ROOT_NODE_ID, 1)])
        .unwrap_or_else(|error| panic!("root forget failed: {error}"));
    assert_eq!(table.total_lookup_references(), 0);
    assert!(table.getattr(ROOT_NODE_ID).is_ok());
    assert!(matches!(
        table.lookup(ROOT_NODE_ID, &name(b"a")),
        Ok(InodeLookup::Positive { .. })
    ));
    assert_eq!(
        table
            .lookup(ROOT_NODE_ID, &name(b"missing"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        InodeLookup::Negative
    );
    assert_eq!(table.live_nodes(), 2);
}

#[test]
fn byte_lookup_validates_without_owned_names_or_partial_mutation() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [31; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));

    let found = table
        .lookup_bytes(ROOT_NODE_ID, b"c")
        .unwrap_or_else(|error| panic!("byte lookup failed: {error}"));
    assert!(matches!(found, InodeLookup::Positive { .. }));
    let nodes = table.live_nodes();
    let references = table.total_lookup_references();
    let oversized = [b'a'; 256];
    for invalid in [
        &b""[..],
        &b"."[..],
        &b".."[..],
        &b"a/b"[..],
        &b"a\0b"[..],
        &oversized,
    ] {
        assert!(matches!(
            table.lookup_bytes(ROOT_NODE_ID, invalid),
            Err(InodeError::Index(IndexError::InvalidPathName(_)))
        ));
        assert_eq!(table.live_nodes(), nodes);
        assert_eq!(table.total_lookup_references(), references);
    }
}

#[test]
fn live_inode_reauthenticates_and_bounds_all_borrowed_views() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [32; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );

    {
        let live = table
            .live_inode(file.node_id)
            .unwrap_or_else(|error| panic!("live inode failed: {error}"));
        assert_eq!(live.attributes(), file);
        assert_eq!(live.record().record_id(), file.record_id);
        assert_eq!(
            live.semantics()
                .unwrap_or_else(|error| panic!("semantics failed: {error}"))
                .logical_size(),
            Some(0)
        );
    }

    table
        .forget(&mut [ForgetRequest::new(file.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    assert!(matches!(
        table.live_inode(file.node_id),
        Err(InodeError::StaleNode)
    ));

    let root = table
        .live_inode(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("root live inode failed: {error}"));
    assert!(matches!(
        root.directory_range(),
        Err(InodeError::Index(IndexError::DirectoryIterationUnavailable))
    ));
}

#[test]
fn live_inode_exposes_a_canonical_v3_directory_range() {
    let fixture = fixture_v3();
    let index = fixture.validate();
    let table = InodeTable::new(&index, [40; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let root = table
        .live_inode(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("root live inode failed: {error}"));
    let range = root
        .directory_range()
        .unwrap_or_else(|error| panic!("directory range failed: {error}"));
    assert_eq!(range.len(), 5);
    let names = range
        .iter()
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("directory entry failed: {error}"))
                .node()
                .name()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            b"a".as_slice(),
            b"b".as_slice(),
            b"c".as_slice(),
            b"d".as_slice(),
            b"e".as_slice(),
        ]
    );
}

#[test]
fn live_inode_rejects_a_foreign_retained_record() {
    let first_fixture = fixture();
    let second_fixture = fixture_with_content_digest([33; 32]);
    let first_index = first_fixture.validate();
    let second_index = second_fixture.validate();
    let foreign_root = second_index
        .root()
        .unwrap_or_else(|error| panic!("foreign root failed: {error}"));
    let mut table = InodeTable::new(&first_index, [34; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let slot =
        find_node(&table.nodes, ROOT_NODE_ID).unwrap_or_else(|| panic!("root node slot missing"));
    let NodeSlot::Occupied(mut entry) = table.nodes[slot] else {
        panic!("root node entry missing");
    };
    entry.record = foreign_root;
    table.nodes[slot] = NodeSlot::Occupied(entry);

    assert!(matches!(
        table.live_inode(ROOT_NODE_ID),
        Err(InodeError::Index(IndexError::ForeignNode))
    ));
}

#[test]
fn live_inode_rejects_same_artifact_identity_and_reverse_map_corruption() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [35; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (first, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("first lookup failed: {error}")),
    );
    let (second, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"d")
            .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
    );
    let first_slot =
        find_node(&table.nodes, first.node_id).unwrap_or_else(|| panic!("first node slot missing"));
    let second_entry = table
        .node_entry(second.node_id)
        .unwrap_or_else(|| panic!("second node missing"));
    let NodeSlot::Occupied(original) = table.nodes[first_slot] else {
        panic!("first node missing");
    };
    let live_nodes = table.live_nodes();
    let references = table.total_lookup_references();

    table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
        record: second_entry.record,
        ..original
    });
    assert!(matches!(
        table.live_inode(first.node_id),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(table.live_nodes(), live_nodes);
    assert_eq!(table.total_lookup_references(), references);

    table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
        semantic: second_entry.semantic,
        ..original
    });
    assert!(matches!(
        table.live_inode(first.node_id),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(table.live_nodes(), live_nodes);
    assert_eq!(table.total_lookup_references(), references);

    table.nodes[first_slot] = NodeSlot::Occupied(original);
    let hash = semantic_hash(&table.connection_key, original.semantic);
    let semantic_slot = find_semantic_slot(&table.semantics, &hash, original.semantic)
        .unwrap_or_else(|| panic!("first semantic slot missing"));
    table.semantics[semantic_slot] = SemanticSlot::Tombstone;
    assert!(matches!(
        table.live_inode(first.node_id),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(table.live_nodes(), live_nodes);
    assert_eq!(table.total_lookup_references(), references);
}

#[test]
fn lookup_rejects_same_artifact_directory_swap_before_admission() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [36; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (directory, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"e")
            .unwrap_or_else(|error| panic!("directory lookup failed: {error}")),
    );
    assert_eq!(directory.kind, IndexNodeKind::Directory);
    let directory_entry = table
        .node_entry(directory.node_id)
        .unwrap_or_else(|| panic!("directory entry missing"));
    let root_slot =
        find_node(&table.nodes, ROOT_NODE_ID).unwrap_or_else(|| panic!("root node slot missing"));
    let NodeSlot::Occupied(root_entry) = table.nodes[root_slot] else {
        panic!("root node entry missing");
    };
    table.nodes[root_slot] = NodeSlot::Occupied(NodeEntry {
        record: directory_entry.record,
        ..root_entry
    });
    let live_nodes = table.live_nodes();
    let references = table.total_lookup_references();
    let next_node_id = table.next_node_id;

    assert!(matches!(
        table.lookup_bytes(ROOT_NODE_ID, b"c"),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(table.live_nodes(), live_nodes);
    assert_eq!(table.total_lookup_references(), references);
    assert_eq!(table.next_node_id, next_node_id);
}

#[test]
fn lookup_reuse_reauthenticates_the_existing_inode_before_increment() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [37; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (first, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("first lookup failed: {error}")),
    );
    let (second, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"d")
            .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
    );
    let first_slot =
        find_node(&table.nodes, first.node_id).unwrap_or_else(|| panic!("first node slot missing"));
    let second_entry = table
        .node_entry(second.node_id)
        .unwrap_or_else(|| panic!("second node missing"));
    let NodeSlot::Occupied(first_entry) = table.nodes[first_slot] else {
        panic!("first node missing");
    };
    table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
        record: second_entry.record,
        ..first_entry
    });
    let entry_references = first_entry.lookup_references;
    let total_references = table.total_lookup_references();
    let live_nodes = table.live_nodes();
    let next_node_id = table.next_node_id;

    assert!(matches!(
        table.lookup_bytes(ROOT_NODE_ID, b"c"),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(
        table
            .node_entry(first.node_id)
            .map(|entry| entry.lookup_references),
        Some(entry_references)
    );
    assert_eq!(table.total_lookup_references(), total_references);
    assert_eq!(table.live_nodes(), live_nodes);
    assert_eq!(table.next_node_id, next_node_id);
}

#[test]
fn public_inode_reads_and_open_authorization_reject_record_substitution() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [38; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (first, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("first lookup failed: {error}")),
    );
    let (second, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"d")
            .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
    );
    let first_slot =
        find_node(&table.nodes, first.node_id).unwrap_or_else(|| panic!("first node slot missing"));
    let NodeSlot::Occupied(first_entry) = table.nodes[first_slot] else {
        panic!("first node missing");
    };
    let second_record = table
        .node_entry(second.node_id)
        .unwrap_or_else(|| panic!("second node missing"))
        .record;
    table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
        record: second_record,
        ..first_entry
    });
    let heap_bytes = table.heap_bytes();
    let live_nodes = table.live_nodes();
    let references = table.total_lookup_references();
    let live_opens = table.live_open_handles();
    let pending_opens = table.pending_open_handles();
    let next_node_id = table.next_node_id;
    let next_handle_id = table.next_handle_id;

    assert!(matches!(
        table.getattr(first.node_id),
        Err(InodeError::InternalInvariant)
    ));
    assert!(matches!(
        table.reserve_open(first.node_id),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(table.heap_bytes(), heap_bytes);
    assert_eq!(table.live_nodes(), live_nodes);
    assert_eq!(table.total_lookup_references(), references);
    assert_eq!(table.live_open_handles(), live_opens);
    assert_eq!(table.pending_open_handles(), pending_opens);
    assert_eq!(table.next_node_id, next_node_id);
    assert_eq!(table.next_handle_id, next_handle_id);
    assert_eq!(
        table
            .node_entry(first.node_id)
            .map(|entry| entry.handle_pins),
        Some(first_entry.handle_pins)
    );

    let mut active_table = InodeTable::new(&index, [39; 32], generous_limits())
        .unwrap_or_else(|error| panic!("active table failed: {error}"));
    let (active_file, _) = positive_parts(
        active_table
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("active-file lookup failed: {error}")),
    );
    let (replacement, _) = positive_parts(
        active_table
            .lookup_bytes(ROOT_NODE_ID, b"d")
            .unwrap_or_else(|error| panic!("replacement lookup failed: {error}")),
    );
    let mut reservation = active_table
        .reserve_open(active_file.node_id)
        .unwrap_or_else(|error| panic!("reservation failed: {error}"));
    let handle = active_table
        .activate_open(&mut reservation)
        .unwrap_or_else(|error| panic!("activation failed: {error}"));
    let active_slot = find_node(&active_table.nodes, active_file.node_id)
        .unwrap_or_else(|| panic!("active node slot missing"));
    let NodeSlot::Occupied(active_entry) = active_table.nodes[active_slot] else {
        panic!("active node missing");
    };
    let replacement_record = active_table
        .node_entry(replacement.node_id)
        .unwrap_or_else(|| panic!("replacement node missing"))
        .record;
    active_table.nodes[active_slot] = NodeSlot::Occupied(NodeEntry {
        record: replacement_record,
        ..active_entry
    });
    let active_heap = active_table.heap_bytes();
    let active_nodes = active_table.live_nodes();
    let active_references = active_table.total_lookup_references();
    let active_opens = active_table.live_open_handles();
    let active_pending = active_table.pending_open_handles();
    let active_next_node = active_table.next_node_id;
    let active_next_open = active_table.next_handle_id;

    assert!(matches!(
        active_table.active_open(handle),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(active_table.heap_bytes(), active_heap);
    assert_eq!(active_table.live_nodes(), active_nodes);
    assert_eq!(active_table.total_lookup_references(), active_references);
    assert_eq!(active_table.live_open_handles(), active_opens);
    assert_eq!(active_table.pending_open_handles(), active_pending);
    assert_eq!(active_table.next_node_id, active_next_node);
    assert_eq!(active_table.next_handle_id, active_next_open);
    assert_eq!(
        active_table
            .node_entry(active_file.node_id)
            .map(|entry| entry.handle_pins),
        Some(active_entry.handle_pins)
    );
}

#[test]
fn hardlinks_coalesce_and_evicted_ids_are_never_reused() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [4; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (first, first_refs) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"a"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let (second, second_refs) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"b"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    assert_eq!(first.node_id, second.node_id);
    assert_eq!((first_refs, second_refs), (1, 2));
    assert_eq!(table.total_lookup_references(), 3);
    assert_eq!(table.live_nodes(), 2);

    let summary = table
        .forget(&mut [
            ForgetRequest::new(first.node_id, 1),
            ForgetRequest::new(first.node_id, 1),
        ])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    assert_eq!(summary.nodes_evicted, 1);
    assert_eq!(table.total_lookup_references(), 1);
    assert!(matches!(
        table.getattr(first.node_id),
        Err(InodeError::StaleNode)
    ));
    let (replacement, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"a"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    assert!(replacement.node_id > first.node_id);
}

#[test]
fn forget_batch_preflight_is_all_or_nothing() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [5; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (a, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"a"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let (c, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    assert!(matches!(
        table.forget(&mut [
            ForgetRequest::new(a.node_id, 1),
            ForgetRequest::new(c.node_id, 2),
        ]),
        Err(InodeError::ForgetUnderflow)
    ));
    assert_eq!(table.total_lookup_references(), 3);
    assert!(matches!(
        table.getattr(a.node_id),
        Ok(value) if value.node_id == a.node_id
    ));
    assert!(matches!(
        table.getattr(c.node_id),
        Ok(value) if value.node_id == c.node_id
    ));
    assert!(matches!(
        table.forget(&mut [ForgetRequest::new(a.node_id, 0)]),
        Err(InodeError::ZeroForgetCount)
    ));
    assert!(matches!(
        table.forget(&mut [ForgetRequest::new(u64::MAX, 1)]),
        Err(InodeError::StaleNode)
    ));
    table.limits.maximum_forget_batch = 1;
    assert!(matches!(
        table.forget(&mut [
            ForgetRequest::new(a.node_id, 1),
            ForgetRequest::new(c.node_id, 1),
        ]),
        Err(InodeError::LimitExceeded("FORGET batch"))
    ));
    assert_eq!(table.total_lookup_references(), 3);
}

#[test]
fn non_directory_parent_is_refused_and_ungrouped_records_stay_distinct() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [11; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (c, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let (d, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"d"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    assert_ne!(c.node_id, d.node_id);
    assert_eq!(c.mode, d.mode);
    assert!(matches!(
        table.lookup(c.node_id, &name(b"child")),
        Err(InodeError::ParentNotDirectory)
    ));
    assert_eq!(table.total_lookup_references(), 3);
}

#[test]
fn growth_peak_and_reference_limits_fail_without_partial_identity() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut count_limited = InodeTable::new(
        &index,
        [6; 32],
        InodeTableLimits::new(1, 1_048_576, 8, 8, 8),
    )
    .unwrap_or_else(|error| panic!("table failed: {error}"));
    assert!(matches!(
        count_limited.lookup(ROOT_NODE_ID, &name(b"a")),
        Err(InodeError::LimitExceeded("nodes"))
    ));
    assert_eq!(count_limited.live_nodes(), 1);
    assert_eq!(count_limited.total_lookup_references(), 1);

    let mut exact_boundary = InodeTable::new(
        &index,
        [6; 32],
        InodeTableLimits::new(2, 1_048_576, 8, 8, 8),
    )
    .unwrap_or_else(|error| panic!("table failed: {error}"));
    assert!(matches!(
        exact_boundary.lookup(ROOT_NODE_ID, &name(b"a")),
        Ok(InodeLookup::Positive { .. })
    ));
    assert_eq!(exact_boundary.live_nodes(), 2);
    assert!(matches!(
        exact_boundary.lookup(ROOT_NODE_ID, &name(b"c")),
        Err(InodeError::LimitExceeded("nodes"))
    ));
    assert_eq!(exact_boundary.live_nodes(), 2);

    let initial_heap =
        table_bytes(INITIAL_CAPACITY).unwrap_or_else(|error| panic!("accounting failed: {error}"));
    let limits = InodeTableLimits::new(8, initial_heap, 8, 8, 8);
    let mut table = InodeTable::new(&index, [6; 32], limits)
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    assert!(matches!(
        table.lookup(ROOT_NODE_ID, &name(b"a")),
        Err(InodeError::LimitExceeded("heap bytes"))
    ));
    assert_eq!(table.live_nodes(), 1);
    assert!(matches!(table.getattr(2), Err(InodeError::StaleNode)));

    let mut id_exhausted = InodeTable::new(&index, [6; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    id_exhausted.next_node_id = u64::MAX;
    assert!(matches!(
        id_exhausted.lookup(ROOT_NODE_ID, &name(b"a")),
        Err(InodeError::LimitExceeded("node IDs"))
    ));
    assert_eq!(id_exhausted.live_nodes(), 1);
    assert_eq!(id_exhausted.total_lookup_references(), 1);

    let reference_limits = InodeTableLimits::new(8, 1_048_576, 2, 8, 8);
    let mut table = InodeTable::new(&index, [6; 32], reference_limits)
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (a, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"a"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    assert!(matches!(
        table.lookup(ROOT_NODE_ID, &name(b"b")),
        Err(InodeError::LimitExceeded("lookup references"))
    ));
    assert_eq!(table.total_lookup_references(), 2);
    table
        .forget(&mut [ForgetRequest::new(a.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    assert!(matches!(
        table.getattr(a.node_id),
        Err(InodeError::StaleNode)
    ));
}

#[test]
fn tombstone_churn_compacts_with_monotonic_ids() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [8; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (first, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    table
        .forget(&mut [ForgetRequest::new(first.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    let retained_heap = table.heap_bytes();
    table.limits.maximum_heap_bytes = retained_heap;
    let rebuilds = table.rebuilds;
    let (second, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup under retained heap failed: {error}")),
    );
    assert_eq!(table.rebuilds, rebuilds);
    table
        .forget(&mut [ForgetRequest::new(second.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));

    table.limits.maximum_heap_bytes = generous_limits().maximum_heap_bytes;
    let mut previous = second.node_id;
    let rebuilds_before = table.rebuilds;
    for _ in 0..32 {
        let (entry, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert!(entry.node_id > previous);
        previous = entry.node_id;
        assert!(table.live <= table.nodes.len() / 2);
        assert!(table.live + table.node_tombstones <= table.nodes.len() * 3 / 4);
        assert!(table.live + table.semantic_tombstones <= table.nodes.len() * 3 / 4);
        table
            .forget(&mut [ForgetRequest::new(entry.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        assert_eq!(table.live_nodes(), 1);
    }
    assert!(table.rebuilds - rebuilds_before < 32);
}

#[test]
fn duplicate_overflow_and_reverse_map_corruption_fail_before_mutation() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [10; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (a, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"a"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    assert!(matches!(
        table.forget(&mut [
            ForgetRequest::new(a.node_id, u64::MAX),
            ForgetRequest::new(a.node_id, 1),
        ]),
        Err(InodeError::ForgetUnderflow)
    ));
    assert_eq!(table.total_lookup_references(), 2);

    let semantic = table
        .node_entry(a.node_id)
        .unwrap_or_else(|| panic!("node missing"))
        .semantic;
    let hash = semantic_hash(&table.connection_key, semantic);
    let semantic_slot = find_semantic_slot(&table.semantics, &hash, semantic)
        .unwrap_or_else(|| panic!("semantic missing"));
    table.semantics[semantic_slot] = SemanticSlot::Tombstone;
    assert!(matches!(
        table.forget(&mut [
            ForgetRequest::new(ROOT_NODE_ID, 1),
            ForgetRequest::new(a.node_id, 1),
        ]),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(table.total_lookup_references(), 2);
    assert_eq!(
        table
            .node_entry(ROOT_NODE_ID)
            .map(|entry| entry.lookup_references),
        Some(1)
    );
    assert_eq!(
        table
            .node_entry(a.node_id)
            .map(|entry| entry.lookup_references),
        Some(1)
    );
}

#[test]
fn actual_first_capacity_is_charged_before_second_allocation() {
    assert!(admit_second_allocation(100, 80, 40, 220).is_ok());
    assert!(matches!(
        admit_second_allocation(100, 81, 40, 220),
        Err(InodeError::LimitExceeded("heap bytes"))
    ));
    assert!(matches!(
        admit_second_allocation(u64::MAX, 1, 1, u64::MAX),
        Err(InodeError::LimitExceeded("heap bytes"))
    ));
}

#[test]
fn pending_and_active_opens_pin_an_inode_until_release() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [12; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let raw_handle = reservation.raw_protocol_handle();
    assert_eq!(reservation.raw_protocol_handle(), raw_handle);
    assert_eq!(table.live_open_handles(), 1);
    assert_eq!(table.pending_open_handles(), 1);
    assert!(matches!(
        table.resolve_active_handle(raw_handle),
        Err(InodeError::OpenStillPending)
    ));

    let forgotten = table
        .forget(&mut [ForgetRequest::new(file.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    assert_eq!(forgotten.nodes_evicted, 0);
    assert!(table.getattr(file.node_id).is_ok());

    let active = table
        .activate_open(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    assert_eq!(active.get(), raw_handle);
    assert_eq!(reservation.raw_protocol_handle(), raw_handle);
    let resolved = table
        .resolve_active_handle(raw_handle)
        .unwrap_or_else(|error| panic!("resolve failed: {error}"));
    assert_eq!(resolved, active);
    assert_eq!(
        format!("{active:?}"),
        format!("OpenHandleId {{ raw: {raw_handle}, connection: \"<redacted>\" }}")
    );
    assert_eq!(table.pending_open_handles(), 0);
    assert_eq!(
        table
            .active_open(active)
            .unwrap_or_else(|error| panic!("active lookup failed: {error}"))
            .node_id,
        file.node_id
    );
    table
        .release_open(active)
        .unwrap_or_else(|error| panic!("release failed: {error}"));
    assert_eq!(table.live_open_handles(), 0);
    assert!(matches!(
        table.active_open(active),
        Err(InodeError::StaleOpenHandle)
    ));
    assert!(matches!(
        table.release_open(active),
        Err(InodeError::StaleOpenHandle)
    ));
    assert!(matches!(
        table.getattr(file.node_id),
        Err(InodeError::StaleNode)
    ));
}

#[test]
fn abort_releases_pending_pin_and_reservation_is_single_use() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [13; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let raw_handle = reservation.raw_protocol_handle();
    assert!(matches!(
        table.resolve_active_handle(raw_handle),
        Err(InodeError::OpenStillPending)
    ));
    table
        .forget(&mut [ForgetRequest::new(file.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    table
        .abort_open(&mut reservation)
        .unwrap_or_else(|error| panic!("abort failed: {error}"));
    assert_eq!(reservation.raw_protocol_handle(), raw_handle);
    assert!(matches!(
        table.resolve_active_handle(raw_handle),
        Err(InodeError::StaleOpenHandle)
    ));
    assert!(matches!(
        table.abort_open(&mut reservation),
        Err(InodeError::InvalidOpenReservation)
    ));
    assert_eq!(table.live_open_handles(), 0);
    assert_eq!(table.pending_open_handles(), 0);
    assert!(matches!(
        table.getattr(file.node_id),
        Err(InodeError::StaleNode)
    ));
}

#[test]
fn reservation_and_typed_handle_are_bound_to_unique_connection() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut first = InodeTable::new(&index, [14; 32], generous_limits())
        .unwrap_or_else(|error| panic!("first table failed: {error}"));
    let mut second = InodeTable::new(&index, [20; 32], generous_limits())
        .unwrap_or_else(|error| panic!("second table failed: {error}"));
    let (file, _) = positive_parts(
        first
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = first
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let authenticator = reservation.authenticator;
    reservation.authenticator[0] ^= 1;
    assert!(matches!(
        first.activate_open(&mut reservation),
        Err(InodeError::InvalidOpenReservation)
    ));
    reservation.authenticator = authenticator;
    assert!(matches!(
        second.activate_open(&mut reservation),
        Err(InodeError::InvalidOpenReservation)
    ));
    assert_eq!(second.live_open_handles(), 0);
    let first_handle = first
        .activate_open(&mut reservation)
        .unwrap_or_else(|error| panic!("origin activate failed: {error}"));
    let (second_file, _) = positive_parts(
        second
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
    );
    let mut second_reservation = second
        .reserve_open(second_file.node_id)
        .unwrap_or_else(|error| panic!("second reserve failed: {error}"));
    let second_handle = second
        .activate_open(&mut second_reservation)
        .unwrap_or_else(|error| panic!("second activate failed: {error}"));
    assert_eq!(first_handle.get(), second_handle.get());
    assert_ne!(first_handle, second_handle);
    assert!(matches!(
        first.active_open(second_handle),
        Err(InodeError::ForeignOpenHandle)
    ));
    assert!(matches!(
        first.release_open(second_handle),
        Err(InodeError::ForeignOpenHandle)
    ));
    assert!(first.active_open(first_handle).is_ok());
    first
        .release_open(first_handle)
        .unwrap_or_else(|error| panic!("first release failed: {error}"));
    second
        .release_open(second_handle)
        .unwrap_or_else(|error| panic!("second release failed: {error}"));
}

#[test]
fn open_admission_failures_leave_inode_and_handle_state_unchanged() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut disabled_limits = generous_limits();
    disabled_limits.maximum_open_handles = 0;
    let mut disabled = InodeTable::new(&index, [15; 32], disabled_limits)
        .unwrap_or_else(|error| panic!("disabled table failed: {error}"));
    assert!(matches!(
        disabled.reserve_open(ROOT_NODE_ID),
        Err(InodeError::OpenTargetNotFile)
    ));
    let (file, _) = positive_parts(
        disabled
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    assert!(matches!(
        disabled.reserve_open(file.node_id),
        Err(InodeError::LimitExceeded("open handles"))
    ));
    assert_eq!(disabled.live_open_handles(), 0);

    let mut one_limit = generous_limits();
    one_limit.maximum_open_handles = 1;
    let mut one = InodeTable::new(&index, [19; 32], one_limit)
        .unwrap_or_else(|error| panic!("single-handle table failed: {error}"));
    let (file, _) = positive_parts(
        one.lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut first = one
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("first reserve failed: {error}"));
    let first_id = first.raw_handle_id;
    assert!(matches!(
        one.reserve_open(file.node_id),
        Err(InodeError::LimitExceeded("open handles"))
    ));
    one.abort_open(&mut first)
        .unwrap_or_else(|error| panic!("abort failed: {error}"));
    let second = one
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("second reserve failed: {error}"));
    assert!(second.raw_handle_id > first_id);

    let mut heap_limited = InodeTable::new(&index, [16; 32], generous_limits())
        .unwrap_or_else(|error| panic!("heap table failed: {error}"));
    let (file, _) = positive_parts(
        heap_limited
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    heap_limited.limits.maximum_heap_bytes = heap_limited.heap_bytes();
    assert!(matches!(
        heap_limited.reserve_open(file.node_id),
        Err(InodeError::LimitExceeded("heap bytes"))
    ));
    assert_eq!(heap_limited.live_open_handles(), 0);
    assert!(heap_limited.getattr(file.node_id).is_ok());

    let mut allocation_refused = InodeTable::new(&index, [17; 32], generous_limits())
        .unwrap_or_else(|error| panic!("allocation table failed: {error}"));
    let (file, _) = positive_parts(
        allocation_refused
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    allocation_refused.refuse_next_open_allocation = true;
    assert!(matches!(
        allocation_refused.reserve_open(file.node_id),
        Err(InodeError::AllocationRefused)
    ));
    assert_eq!(allocation_refused.live_open_handles(), 0);
    assert!(allocation_refused.getattr(file.node_id).is_ok());

    allocation_refused.next_handle_id = u64::MAX;
    assert!(matches!(
        allocation_refused.reserve_open(file.node_id),
        Err(InodeError::LimitExceeded("open handle IDs"))
    ));
    assert_eq!(allocation_refused.live_open_handles(), 0);
}

#[test]
fn lookup_reference_revival_defers_reap_after_release() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [18; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let handle = table
        .activate_open(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    table
        .forget(&mut [ForgetRequest::new(file.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    let (revived, references) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("revival failed: {error}")),
    );
    assert_eq!(revived.node_id, file.node_id);
    assert_eq!(references, 1);
    table
        .release_open(handle)
        .unwrap_or_else(|error| panic!("release failed: {error}"));
    assert!(table.getattr(file.node_id).is_ok());
    table
        .forget(&mut [ForgetRequest::new(file.node_id, 1)])
        .unwrap_or_else(|error| panic!("final forget failed: {error}"));
    assert!(matches!(
        table.getattr(file.node_id),
        Err(InodeError::StaleNode)
    ));
}

#[test]
fn open_churn_preserves_load_bounds_and_never_reuses_ids() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [21; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );

    let mut reservations = Vec::new();
    for _ in 0..8 {
        reservations.push(
            table
                .reserve_open(file.node_id)
                .unwrap_or_else(|error| panic!("reserve failed: {error}")),
        );
    }
    let mut handles = Vec::new();
    for reservation in &mut reservations {
        handles.push(
            table
                .activate_open(reservation)
                .unwrap_or_else(|error| panic!("activate failed: {error}")),
        );
    }
    assert!(handles.windows(2).all(|pair| pair[0].get() < pair[1].get()));
    assert!(table.live_opens <= table.opens.len() / 2);
    for handle in handles {
        table
            .release_open(handle)
            .unwrap_or_else(|error| panic!("release failed: {error}"));
    }

    let mut previous = 8;
    let rebuilds_before = table.open_rebuilds;
    for _ in 0..128 {
        let mut reservation = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("churn reserve failed: {error}"));
        let handle = table
            .activate_open(&mut reservation)
            .unwrap_or_else(|error| panic!("churn activate failed: {error}"));
        assert!(handle.get() > previous);
        previous = handle.get();
        assert!(table.live_opens <= table.opens.len() / 2);
        assert!(table.live_opens + table.open_tombstones <= table.opens.len() * 3 / 4);
        table
            .release_open(handle)
            .unwrap_or_else(|error| panic!("churn release failed: {error}"));
        assert_eq!(table.live_open_handles(), 0);
        assert!(table.live_opens + table.open_tombstones <= table.opens.len() * 3 / 4);
    }
    assert!(table.open_rebuilds - rebuilds_before < 128);
}

#[test]
fn open_growth_and_compaction_charge_retained_plus_replacement() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut growth = InodeTable::new(&index, [22; 32], generous_limits())
        .unwrap_or_else(|error| panic!("growth table failed: {error}"));
    let (file, _) = positive_parts(
        growth
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut first = growth
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("first reserve failed: {error}"));
    let first_handle = growth
        .activate_open(&mut first)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    let replacement = modeled_bytes::<OpenSlot>(growth.opens.len() * 2)
        .unwrap_or_else(|error| panic!("model failed: {error}"));
    growth.limits.maximum_heap_bytes = growth.heap_bytes() + replacement - 1;
    assert!(matches!(
        growth.reserve_open(file.node_id),
        Err(InodeError::LimitExceeded("heap bytes"))
    ));
    assert_eq!(growth.live_open_handles(), 1);
    assert!(growth.active_open(first_handle).is_ok());

    let mut compaction = InodeTable::new(&index, [23; 32], generous_limits())
        .unwrap_or_else(|error| panic!("compaction table failed: {error}"));
    let (file, _) = positive_parts(
        compaction
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    compaction.opens =
        allocate_open_slots(4).unwrap_or_else(|error| panic!("fixture allocation failed: {error}"));
    compaction.opens.fill(OpenSlot::Tombstone);
    let empty = open_bucket(compaction.next_handle_id, compaction.opens.len());
    compaction.opens[empty] = OpenSlot::Empty;
    compaction.open_tombstones = 3;
    let replacement = modeled_bytes::<OpenSlot>(compaction.opens.len())
        .unwrap_or_else(|error| panic!("model failed: {error}"));
    compaction.limits.maximum_heap_bytes = compaction.heap_bytes() + replacement - 1;
    let heap_before = compaction.heap_bytes();
    assert!(matches!(
        compaction.reserve_open(file.node_id),
        Err(InodeError::LimitExceeded("heap bytes"))
    ));
    assert_eq!(compaction.heap_bytes(), heap_before);
    assert_eq!(compaction.live_open_handles(), 0);
    assert_eq!(compaction.open_tombstones, 3);
    assert!(compaction.getattr(file.node_id).is_ok());
}

#[test]
fn open_tombstone_reuse_needs_no_replacement_admission() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [25; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut first = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("first reserve failed: {error}"));
    table
        .abort_open(&mut first)
        .unwrap_or_else(|error| panic!("abort failed: {error}"));
    table.opens.fill(OpenSlot::Empty);
    let tombstone = open_bucket(table.next_handle_id, table.opens.len());
    table.opens[tombstone] = OpenSlot::Tombstone;
    table.open_tombstones = 1;
    table.limits.maximum_heap_bytes = table.heap_bytes();
    table.refuse_next_open_allocation = true;

    let mut second = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("tombstone reserve failed: {error}"));
    assert!(table.refuse_next_open_allocation);
    assert_eq!(table.open_tombstones, 0);
    table
        .abort_open(&mut second)
        .unwrap_or_else(|error| panic!("second abort failed: {error}"));
}

#[test]
fn release_cross_map_corruption_fails_before_any_removal() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [24; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let handle = table
        .activate_open(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    table
        .forget(&mut [ForgetRequest::new(file.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));

    let node = table
        .node_entry(file.node_id)
        .unwrap_or_else(|| panic!("pinned node missing"));
    let hash = semantic_hash(&table.connection_key, node.semantic);
    let semantic_slot = find_semantic_slot(&table.semantics, &hash, node.semantic)
        .unwrap_or_else(|| panic!("semantic missing"));
    table.semantics[semantic_slot] = SemanticSlot::Tombstone;
    let live_before = table.live;
    let live_opens_before = table.live_opens;
    let open_tombstones_before = table.open_tombstones;
    assert!(matches!(
        table.release_open(handle),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(table.live, live_before);
    assert_eq!(table.live_opens, live_opens_before);
    assert_eq!(table.open_tombstones, open_tombstones_before);
    assert!(matches!(
        table.active_open(handle),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(
        table
            .node_entry(file.node_id)
            .map(|entry| (entry.lookup_references, entry.handle_pins)),
        Some((0, 1))
    );
}

#[test]
fn release_zero_pin_corruption_leaves_slots_and_counters_unchanged() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [26; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let handle = table
        .activate_open(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    let node_slot =
        find_node(&table.nodes, file.node_id).unwrap_or_else(|| panic!("node slot missing"));
    let NodeSlot::Occupied(mut node) = table.nodes[node_slot] else {
        panic!("node slot not occupied");
    };
    node.handle_pins = 0;
    table.nodes[node_slot] = NodeSlot::Occupied(node);
    let open_slot =
        find_open(&table.opens, handle.get()).unwrap_or_else(|| panic!("open slot missing"));
    let OpenSlot::Occupied {
        raw_handle_id,
        node_id,
        state,
    } = table.opens[open_slot]
    else {
        panic!("open slot not occupied");
    };
    let counters_before = [
        table.live,
        table.node_tombstones,
        table.semantic_tombstones,
        table.live_opens,
        table.pending_opens,
        table.open_tombstones,
    ];
    let ids_before = [
        table.total_lookup_references,
        table.next_node_id,
        table.next_handle_id,
    ];

    assert!(matches!(
        table.release_open(handle),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(
        [
            table.live,
            table.node_tombstones,
            table.semantic_tombstones,
            table.live_opens,
            table.pending_opens,
            table.open_tombstones,
        ],
        counters_before
    );
    assert_eq!(
        [
            table.total_lookup_references,
            table.next_node_id,
            table.next_handle_id,
        ],
        ids_before
    );
    assert!(matches!(
        table.opens[open_slot],
        OpenSlot::Occupied {
            raw_handle_id: candidate_raw,
            node_id: candidate_node,
            state: candidate_state,
        } if (candidate_raw, candidate_node, candidate_state)
            == (raw_handle_id, node_id, state)
    ));
    assert_eq!(
        table
            .node_entry(file.node_id)
            .map(|entry| (entry.lookup_references, entry.handle_pins)),
        Some((node.lookup_references, 0))
    );
}

#[test]
fn abort_zero_pending_counter_leaves_slots_and_counters_unchanged() {
    let fixture = fixture();
    let index = fixture.validate();
    let mut table = InodeTable::new(&index, [27; 32], generous_limits())
        .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup(ROOT_NODE_ID, &name(b"c"))
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let open_slot = find_open(&table.opens, reservation.raw_handle_id)
        .unwrap_or_else(|| panic!("open slot missing"));
    let OpenSlot::Occupied {
        raw_handle_id,
        node_id,
        state,
    } = table.opens[open_slot]
    else {
        panic!("open slot not occupied");
    };
    let node_before = table
        .node_entry(file.node_id)
        .map(|entry| (entry.lookup_references, entry.handle_pins));
    table.pending_opens = 0;
    let counters_before = [
        table.live,
        table.node_tombstones,
        table.semantic_tombstones,
        table.live_opens,
        table.pending_opens,
        table.open_tombstones,
    ];
    let ids_before = [
        table.total_lookup_references,
        table.next_node_id,
        table.next_handle_id,
    ];

    assert!(matches!(
        table.abort_open(&mut reservation),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(
        [
            table.live,
            table.node_tombstones,
            table.semantic_tombstones,
            table.live_opens,
            table.pending_opens,
            table.open_tombstones,
        ],
        counters_before
    );
    assert_eq!(
        [
            table.total_lookup_references,
            table.next_node_id,
            table.next_handle_id,
        ],
        ids_before
    );
    assert!(matches!(
        table.opens[open_slot],
        OpenSlot::Occupied {
            raw_handle_id: candidate_raw,
            node_id: candidate_node,
            state: candidate_state,
        } if (candidate_raw, candidate_node, candidate_state)
            == (raw_handle_id, node_id, state)
    ));
    assert_eq!(
        table
            .node_entry(file.node_id)
            .map(|entry| (entry.lookup_references, entry.handle_pins)),
        node_before
    );
    assert!(!reservation.consumed);
}

#[test]
fn directory_handle_cookies_are_stable_stateless_and_do_not_intern_children() {
    let fixture = fixture_v3();
    let index = fixture.validate();
    let directory_limits = DirectoryHandleLimits::new(8, 16);
    let mut table = InodeTable::new_with_directory_limits(
        &index,
        [40; 32],
        generous_limits(),
        directory_limits,
    )
    .unwrap_or_else(|error| panic!("table failed: {error}"));
    let mut reservation = table
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let raw = reservation.raw_protocol_handle();
    let authenticator = reservation.authenticator;
    reservation.authenticator[0] ^= 1;
    assert!(matches!(
        table.activate_directory(&mut reservation),
        Err(InodeError::InvalidDirectoryReservation)
    ));
    assert!(!reservation.consumed);
    reservation.authenticator = authenticator;
    assert!(matches!(
        table.resolve_active_directory(raw),
        Err(InodeError::DirectoryHandleStillPending)
    ));
    let handle = table
        .activate_directory(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    assert_eq!(handle.get(), raw);
    assert_eq!(reservation.raw_protocol_handle(), raw);

    let nodes = table.live_nodes();
    let references = table.total_lookup_references();
    let entries = table
        .directory_entries(handle, 0)
        .unwrap_or_else(|error| panic!("entries failed: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("iteration failed: {error}"));
    assert_eq!(
        entries
            .iter()
            .map(DirectoryReadEntry::name)
            .collect::<Vec<_>>(),
        [b".".as_slice(), b"..", b"a", b"b", b"c", b"d", b"e"]
    );
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.next_cookie().get())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(entries[0].kind(), DirectoryReadKind::Dot);
    assert_eq!(
        entries[0].inode().map(|value| value.node_id),
        Some(ROOT_NODE_ID)
    );
    assert!(entries[1].inode().is_none());
    assert!(entries[2..].iter().all(|entry| entry.child().is_some()));
    assert_eq!(table.live_nodes(), nodes);
    assert_eq!(table.total_lookup_references(), references);

    for cookie in 0..=7_i64 {
        let suffix = table
            .directory_entries(handle, cookie)
            .unwrap_or_else(|error| panic!("seek {cookie} failed: {error}"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("seek iteration failed: {error}"));
        assert_eq!(suffix.len(), 7 - cookie as usize);
        if let Some(first) = suffix.first() {
            assert_eq!(first.next_cookie().get(), cookie as u64 + 1);
        }
    }
    assert!(matches!(
        table.directory_entries(handle, -1),
        Err(InodeError::InvalidDirectoryCookie)
    ));
    assert!(matches!(
        table.directory_entries_raw(handle, i64::MAX as u64 + 1),
        Err(InodeError::InvalidDirectoryCookie)
    ));
    assert!(matches!(
        table.directory_entries(handle, 8),
        Err(InodeError::InvalidDirectoryCookie)
    ));
    table
        .release_directory(handle)
        .unwrap_or_else(|error| panic!("release failed: {error}"));
    assert!(matches!(
        table.release_directory(handle),
        Err(InodeError::StaleDirectoryHandle)
    ));
}

#[test]
fn directory_handles_are_opt_in_v3_only_and_share_raw_identity_with_files() {
    let v3_fixture = fixture_v3();
    let v3_index = v3_fixture.validate();
    let mut disabled = InodeTable::new(&v3_index, [41; 32], generous_limits())
        .unwrap_or_else(|error| panic!("disabled table failed: {error}"));
    assert!(matches!(
        disabled.reserve_directory(ROOT_NODE_ID),
        Err(InodeError::DirectoryHandlesDisabled)
    ));
    assert_eq!(disabled.next_handle_id, 1);

    let v2_fixture = fixture();
    let v2_index = v2_fixture.validate();
    let mut v2 = InodeTable::new_with_directory_limits(
        &v2_index,
        [42; 32],
        generous_limits(),
        DirectoryHandleLimits::new(2, 4),
    )
    .unwrap_or_else(|error| panic!("v2 table failed: {error}"));
    assert!(matches!(
        v2.reserve_directory(ROOT_NODE_ID),
        Err(InodeError::Index(IndexError::DirectoryIterationUnavailable))
    ));
    assert_eq!((v2.live_directory_handles(), v2.next_handle_id), (0, 1));

    let mut table = InodeTable::new_with_directory_limits(
        &v3_index,
        [43; 32],
        generous_limits(),
        DirectoryHandleLimits::new(2, 4),
    )
    .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (file, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut file_reservation = table
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("file reserve failed: {error}"));
    let file_raw = file_reservation.raw_protocol_handle();
    let file_handle = table
        .activate_open(&mut file_reservation)
        .unwrap_or_else(|error| panic!("file activate failed: {error}"));
    let mut directory_reservation = table
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("directory reserve failed: {error}"));
    let directory_raw = directory_reservation.raw_protocol_handle();
    assert!(directory_raw > file_raw);
    let mut foreign_table = InodeTable::new_with_directory_limits(
        &v3_index,
        [54; 32],
        generous_limits(),
        DirectoryHandleLimits::new(2, 4),
    )
    .unwrap_or_else(|error| panic!("foreign table failed: {error}"));
    assert!(matches!(
        foreign_table.activate_directory(&mut directory_reservation),
        Err(InodeError::InvalidDirectoryReservation)
    ));
    assert!(!directory_reservation.consumed);
    assert!(matches!(
        table.resolve_active_directory(file_raw),
        Err(InodeError::WrongHandleKind)
    ));
    assert!(matches!(
        table.resolve_active_handle(directory_raw),
        Err(InodeError::WrongHandleKind)
    ));
    let directory_handle = table
        .activate_directory(&mut directory_reservation)
        .unwrap_or_else(|error| panic!("directory activate failed: {error}"));
    table
        .release_directory(directory_handle)
        .unwrap_or_else(|error| panic!("directory release failed: {error}"));
    table
        .release_open(file_handle)
        .unwrap_or_else(|error| panic!("file release failed: {error}"));
}

#[test]
fn directory_pin_survives_forget_and_abort_or_release_reaps() {
    let fixture = fixture_v3();
    let index = fixture.validate();
    let mut table = InodeTable::new_with_directory_limits(
        &index,
        [44; 32],
        generous_limits(),
        DirectoryHandleLimits::new(4, 4),
    )
    .unwrap_or_else(|error| panic!("table failed: {error}"));
    let (directory, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"e")
            .unwrap_or_else(|error| panic!("lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_directory(directory.node_id)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    table
        .forget(&mut [ForgetRequest::new(directory.node_id, 1)])
        .unwrap_or_else(|error| panic!("forget failed: {error}"));
    assert!(table.getattr(directory.node_id).is_ok());
    let handle = table
        .activate_directory(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    assert_eq!(
        table
            .directory_entries(handle, 0)
            .unwrap_or_else(|error| panic!("entries failed: {error}"))
            .len(),
        2
    );
    table
        .release_directory(handle)
        .unwrap_or_else(|error| panic!("release failed: {error}"));
    assert!(matches!(
        table.getattr(directory.node_id),
        Err(InodeError::StaleNode)
    ));

    let (directory, _) = positive_parts(
        table
            .lookup_bytes(ROOT_NODE_ID, b"e")
            .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
    );
    let mut reservation = table
        .reserve_directory(directory.node_id)
        .unwrap_or_else(|error| panic!("second reserve failed: {error}"));
    table
        .forget(&mut [ForgetRequest::new(directory.node_id, 1)])
        .unwrap_or_else(|error| panic!("second forget failed: {error}"));
    table
        .abort_directory(&mut reservation)
        .unwrap_or_else(|error| panic!("abort failed: {error}"));
    assert!(matches!(
        table.abort_directory(&mut reservation),
        Err(InodeError::InvalidDirectoryReservation)
    ));
    assert!(matches!(
        table.getattr(directory.node_id),
        Err(InodeError::StaleNode)
    ));
}

#[test]
fn directory_seek_is_page_local_for_high_fanout_and_preserves_byte_names() {
    let mut names = (0_u32..32)
        .map(|value| format!("n{value:04}").into_bytes())
        .collect::<Vec<_>>();
    names.push(vec![b'x'; 255]);
    names.push(vec![0x80]);
    let fixture = fixture_v3_names(&names);
    let index = fixture.validate();
    let mut table = InodeTable::new_with_directory_limits(
        &index,
        [45; 32],
        InodeTableLimits::new(256, 4 * 1_048_576, 256, 16, 8),
        DirectoryHandleLimits::new(2, 8),
    )
    .unwrap_or_else(|error| panic!("table failed: {error}"));
    let mut reservation = table
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    let handle = table
        .activate_directory(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    let offset = 2 + 20;
    let mut page = table
        .directory_entries(handle, offset)
        .unwrap_or_else(|error| panic!("seek failed: {error}"));
    assert_eq!(page.len(), names.len() - 20);
    assert_eq!(
        page.next()
            .transpose()
            .unwrap_or_else(|error| panic!("entry failed: {error}"))
            .map(|entry| entry.name().to_vec()),
        Some(names[20].clone())
    );
    let tail = table
        .directory_entries(handle, 2 + 32)
        .unwrap_or_else(|error| panic!("tail failed: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("tail iteration failed: {error}"));
    assert_eq!(tail[0].name(), vec![b'x'; 255]);
    assert_eq!(tail[1].name(), &[0x80]);

    let empty_fixture = fixture_v3_names(&[]);
    let empty_index = empty_fixture.validate();
    let mut empty_table = InodeTable::new_with_directory_limits(
        &empty_index,
        [46; 32],
        generous_limits(),
        DirectoryHandleLimits::new(1, 1),
    )
    .unwrap_or_else(|error| panic!("empty table failed: {error}"));
    let mut empty_reservation = empty_table
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("empty reserve failed: {error}"));
    let empty_handle = empty_table
        .activate_directory(&mut empty_reservation)
        .unwrap_or_else(|error| panic!("empty activate failed: {error}"));
    assert_eq!(
        empty_table
            .directory_entries(empty_handle, 0)
            .unwrap_or_else(|error| panic!("empty entries failed: {error}"))
            .len(),
        2
    );
    assert_eq!(
        empty_table
            .directory_entries(empty_handle, 2)
            .unwrap_or_else(|error| panic!("empty EOF failed: {error}"))
            .len(),
        0
    );
}

#[test]
fn directory_limits_foreign_handles_and_cached_substitution_fail_closed() {
    let fixture = fixture_v3();
    let index = fixture.validate();
    let directory_limits = DirectoryHandleLimits::new(1, 2);
    let mut first = InodeTable::new_with_directory_limits(
        &index,
        [47; 32],
        generous_limits(),
        directory_limits,
    )
    .unwrap_or_else(|error| panic!("first table failed: {error}"));
    let second = InodeTable::new_with_directory_limits(
        &index,
        [48; 32],
        generous_limits(),
        directory_limits,
    )
    .unwrap_or_else(|error| panic!("second table failed: {error}"));
    let mut reservation = first
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("reserve failed: {error}"));
    assert!(matches!(
        first.reserve_directory(ROOT_NODE_ID),
        Err(InodeError::LimitExceeded("directory handles"))
    ));
    let handle = first
        .activate_directory(&mut reservation)
        .unwrap_or_else(|error| panic!("activate failed: {error}"));
    assert!(matches!(
        second.directory_entries(handle, 0),
        Err(InodeError::ForeignDirectoryHandle)
    ));

    let (nested, _) = positive_parts(
        first
            .lookup_bytes(ROOT_NODE_ID, b"e")
            .unwrap_or_else(|error| panic!("nested lookup failed: {error}")),
    );
    first
        .release_directory(handle)
        .unwrap_or_else(|error| panic!("root release failed: {error}"));
    let mut root_reservation = first
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("root reserve failed: {error}"));
    let root_handle = first
        .activate_directory(&mut root_reservation)
        .unwrap_or_else(|error| panic!("root activate failed: {error}"));
    first
        .release_directory(root_handle)
        .unwrap_or_else(|error| panic!("second root release failed: {error}"));
    let mut nested_reservation = first
        .reserve_directory(nested.node_id)
        .unwrap_or_else(|error| panic!("nested reserve failed: {error}"));
    let nested_handle = first
        .activate_directory(&mut nested_reservation)
        .unwrap_or_else(|error| panic!("nested activate failed: {error}"));
    let nested_slot = find_directory(&first.directories, nested_handle.get())
        .unwrap_or_else(|| panic!("nested slot missing"));
    let DirectorySlot::Occupied {
        raw_handle_id,
        node_id,
        record_id,
        range,
        state,
    } = first.directories[nested_slot]
    else {
        panic!("nested slot not occupied");
    };
    first.directories[nested_slot] = DirectorySlot::Occupied {
        raw_handle_id,
        node_id,
        record_id: record_id + 1,
        range,
        state,
    };
    assert!(matches!(
        first.directory_entries(nested_handle, 0),
        Err(InodeError::InternalInvariant)
    ));
    assert!(matches!(
        first.release_directory(nested_handle),
        Err(InodeError::InternalInvariant)
    ));

    let root_range = index
        .retained_directory_range(
            &index
                .root()
                .unwrap_or_else(|error| panic!("root failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("root range failed: {error}"));
    first.directories[nested_slot] = DirectorySlot::Occupied {
        raw_handle_id,
        node_id,
        record_id,
        range: root_range,
        state,
    };
    let before_release = (
        first.live_directory_handles(),
        first.pending_directory_handles(),
        first.live_nodes(),
        first.directory_tombstones,
    );
    assert!(matches!(
        first.directory_entries(nested_handle, 0),
        Err(InodeError::InternalInvariant)
    ));
    assert!(matches!(
        first.release_directory(nested_handle),
        Err(InodeError::InternalInvariant)
    ));
    assert_eq!(
        (
            first.live_directory_handles(),
            first.pending_directory_handles(),
            first.live_nodes(),
            first.directory_tombstones,
        ),
        before_release
    );

    let mut refused = InodeTable::new_with_directory_limits(
        &index,
        [49; 32],
        generous_limits(),
        DirectoryHandleLimits::new(1, 1),
    )
    .unwrap_or_else(|error| panic!("refused table failed: {error}"));
    refused.refuse_next_directory_allocation = true;
    let next_id = refused.next_handle_id;
    assert!(matches!(
        refused.reserve_directory(ROOT_NODE_ID),
        Err(InodeError::AllocationRefused)
    ));
    assert_eq!(refused.next_handle_id, next_id);
    assert_eq!(refused.live_directory_handles(), 0);

    let retained_heap = refused.heap_bytes();
    let heap_limited = InodeTableLimits::new(32, retained_heap, 16, 16, 16);
    let mut exact_heap = InodeTable::new_with_directory_limits(
        &index,
        [55; 32],
        heap_limited,
        DirectoryHandleLimits::new(1, 1),
    )
    .unwrap_or_else(|error| panic!("exact-heap table failed: {error}"));
    assert!(matches!(
        exact_heap.reserve_directory(ROOT_NODE_ID),
        Err(InodeError::LimitExceeded("heap bytes"))
    ));
    assert_eq!(exact_heap.heap_bytes(), retained_heap);
    assert_eq!(exact_heap.live_directory_handles(), 0);

    let mut aggregate = InodeTable::new_with_directory_limits(
        &index,
        [50; 32],
        generous_limits(),
        DirectoryHandleLimits::new(2, 1),
    )
    .unwrap_or_else(|error| panic!("aggregate table failed: {error}"));
    let (file, _) = positive_parts(
        aggregate
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("file lookup failed: {error}")),
    );
    let _file_reservation = aggregate
        .reserve_open(file.node_id)
        .unwrap_or_else(|error| panic!("file reserve failed: {error}"));
    assert!(matches!(
        aggregate.reserve_directory(ROOT_NODE_ID),
        Err(InodeError::LimitExceeded("total handles"))
    ));
}

#[test]
fn directory_churn_rebuilds_and_exact_tombstone_reuse_needs_no_heap_growth() {
    let fixture = fixture_v3();
    let index = fixture.validate();
    let mut table = InodeTable::new_with_directory_limits(
        &index,
        [62; 32],
        generous_limits(),
        DirectoryHandleLimits::new(4, 4),
    )
    .unwrap_or_else(|error| panic!("table failed: {error}"));
    let mut previous = 0;
    for _ in 0..64 {
        let mut reservation = table
            .reserve_directory(ROOT_NODE_ID)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        assert!(reservation.raw_protocol_handle() > previous);
        previous = reservation.raw_protocol_handle();
        table
            .abort_directory(&mut reservation)
            .unwrap_or_else(|error| panic!("abort failed: {error}"));
        assert_eq!(table.live_directory_handles(), 0);
        assert!(table.heap_bytes() <= table.limits.maximum_heap_bytes);
    }
    assert!(table.directory_rebuilds > 0);

    let tombstone = table
        .directories
        .iter()
        .position(|slot| matches!(slot, DirectorySlot::Tombstone))
        .unwrap_or_else(|| panic!("directory tombstone missing"));
    while node_bucket(table.next_handle_id, table.directories.len()) != tombstone {
        table.next_handle_id = table
            .next_handle_id
            .checked_add(1)
            .unwrap_or_else(|| panic!("handle ID overflow"));
    }
    table.limits.maximum_heap_bytes = table.heap_bytes();
    let rebuilds = table.directory_rebuilds;
    let mut reservation = table
        .reserve_directory(ROOT_NODE_ID)
        .unwrap_or_else(|error| panic!("tombstone reserve failed: {error}"));
    assert_eq!(table.directory_rebuilds, rebuilds);
    table
        .abort_directory(&mut reservation)
        .unwrap_or_else(|error| panic!("tombstone abort failed: {error}"));
}

#[test]
fn prepared_forget_commit_matches_the_public_atomic_operation() {
    let fixture = fixture_v3();
    let index = fixture.validate();
    let mut public = InodeTable::new(&index, [72; 32], generous_limits())
        .unwrap_or_else(|error| panic!("public table failed: {error}"));
    let mut prepared = InodeTable::new(&index, [73; 32], generous_limits())
        .unwrap_or_else(|error| panic!("prepared table failed: {error}"));
    let (public_file, _) = positive_parts(
        public
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("public lookup failed: {error}")),
    );
    let (prepared_file, _) = positive_parts(
        prepared
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("prepared lookup failed: {error}")),
    );
    assert_eq!(public_file.node_id, prepared_file.node_id);

    let mut public_batch = [ForgetRequest::new(public_file.node_id, 1)];
    let mut prepared_batch = [ForgetRequest::new(prepared_file.node_id, 1)];
    let public_summary = public
        .forget(&mut public_batch)
        .unwrap_or_else(|error| panic!("public forget failed: {error}"));
    let transaction = prepared
        .prepare_forget(&mut prepared_batch)
        .unwrap_or_else(|error| panic!("prepare failed: {error}"));
    let prepared_summary = transaction.commit();

    assert_eq!(public_summary, prepared_summary);
    assert_eq!(
        (
            public.live_nodes(),
            public.total_lookup_references(),
            public_batch,
        ),
        (
            prepared.live_nodes(),
            prepared.total_lookup_references(),
            prepared_batch,
        )
    );
}
