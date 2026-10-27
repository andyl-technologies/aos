//! Exercises canonical entries and local node invariants.

use alloc::vec;
use alloc::vec::Vec;

use super::{
    ChildRef, ContentRef, Decoder, Entry, EntryKind, Error, LeafItem, Node, NodeItems, Property,
    TreeUse, decode_entry_bytes, decode_node, decode_node_for, encode_node, encode_node_for,
    property_value, validate_graft_chain, validate_index_key, validate_key, validate_tree_entries,
    verify_child_ref,
};

const MIN_CHUNK: u64 = 262_144;

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("ASCII test vector");
            u8::from_str_radix(text, 16).expect("hex test vector")
        })
        .collect()
}

fn file<'a>(link_id: Option<&'a [u8]>) -> Entry<'a> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: 15,
            content: ContentRef::Inline([7; 32]),
            link_id,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn directory() -> Entry<'static> {
    Entry {
        kind: EntryKind::Directory { mode: 0o755 },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn item<'a>(key: &[u8], entry: Entry<'a>) -> LeafItem<'a> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

#[test]
fn golden_leaf_round_trips_byte_exactly() {
    let encoded = hex_bytes(concat!(
        "a201000281834968656c6c6f2e74787400a40101021901a4030f048200582094",
        "79e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0",
    ));
    let node = decode_node(&encoded, true, MIN_CHUNK).expect("golden node decodes");
    assert_eq!(
        encode_node(&node, true, MIN_CHUNK).expect("re-encodes"),
        encoded
    );
}

#[test]
fn empty_leaf_is_the_only_empty_tree_node() {
    let empty = [0xa2, 1, 0, 2, 0x80];
    let node = decode_node(&empty, true, MIN_CHUNK).expect("empty root");
    assert_eq!(encode_node(&node, true, MIN_CHUNK).expect("encode"), empty);
    assert_eq!(decode_node(&empty, false, MIN_CHUNK), Err(Error::Node));
}

#[test]
fn rejects_malformed_paths_and_missing_ancestors() {
    for key in [
        &b""[..],
        b"/a",
        b"a/",
        b"a//b",
        b"a/./b",
        b"a/../b",
        b"a\0b",
    ] {
        assert_eq!(validate_key(key), Err(Error::Key), "{key:?}");
    }
    assert_eq!(validate_key(&vec![b'a'; 256]), Err(Error::Key));
    let entries = [item(b"a/b", file(None))];
    assert_eq!(
        validate_tree_entries(&entries, TreeUse::Ordinary),
        Err(Error::Tree)
    );

    let entries = [item(b"a", directory()), item(b"a/b", file(None))];
    validate_tree_entries(&entries, TreeUse::Ordinary).expect("explicit ancestor");
}

#[test]
fn only_directory_conflicts_permit_conditional_descendants() {
    let mut ancestor = directory();
    ancestor.kind = EntryKind::Conflict {
        candidates: vec![file(None), directory()],
        base: None,
    };
    let mut entries = [item(b"a", ancestor), item(b"a/b", file(None))];

    validate_tree_entries(&entries, TreeUse::Ordinary).expect("conditional directory");
    validate_tree_entries(&entries, TreeUse::ConflictSurface).expect("conflict-aware view");
    assert_eq!(
        validate_tree_entries(&entries, TreeUse::Surface),
        Err(Error::Tree)
    );

    entries[0].entry.kind = EntryKind::Conflict {
        candidates: vec![file(None), file(None)],
        base: None,
    };
    assert_eq!(
        validate_tree_entries(&entries, TreeUse::Ordinary),
        Err(Error::Tree)
    );

    entries[0].entry = file(None);
    assert_eq!(
        validate_tree_entries(&entries, TreeUse::Ordinary),
        Err(Error::Tree)
    );
}

#[test]
fn rejects_reserved_and_unknown_entry_fields() {
    assert_eq!(
        decode_entry_bytes(&[0xa1, 1, 8], MIN_CHUNK),
        Err(Error::ReservedType)
    );
    assert_eq!(
        decode_entry_bytes(&[0xa2, 1, 5, 15, 0], MIN_CHUNK),
        Err(Error::Entry)
    );
    assert_eq!(
        decode_entry_bytes(&[0xa2, 1, 5, 1, 0], MIN_CHUNK),
        Err(Error::Entry)
    );
}

#[test]
fn file_content_form_tracks_profile_minimum() {
    let inline = file(None);
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"f", inline)]),
        props: None,
    };
    let encoded = encode_node(&node, true, MIN_CHUNK).expect("small file inline");
    assert!(decode_node(&encoded, true, 14).is_err());
}

#[test]
fn entry_limits_and_type_fields_fail_at_decode() {
    let mut invalid_mode = file(None);
    if let EntryKind::File { mode, .. } = &mut invalid_mode.kind {
        *mode = 0x1000;
    }
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"f", invalid_mode)]),
        props: None,
    };
    assert!(encode_node(&node, true, MIN_CHUNK).is_err());

    let symlink = Entry {
        kind: EntryKind::Symlink {
            target: b"\xff/../raw",
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"link", symlink)]),
        props: None,
    };
    assert!(encode_node(&node, true, MIN_CHUNK).is_ok());

    let long_target = vec![b'x'; 4097];
    let symlink = Entry {
        kind: EntryKind::Symlink {
            target: &long_target,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"link", symlink)]),
        props: None,
    };
    assert!(encode_node(&node, true, MIN_CHUNK).is_err());
}

#[test]
fn prefix_compression_must_use_full_common_prefix() {
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"a1", file(None)), item(b"a2", file(None))]),
        props: None,
    };
    let mut encoded = encode_node(&node, true, MIN_CHUNK).expect("canonical node");
    let second = encoded
        .windows(4)
        .position(|window| window == [0x83, 0x41, b'2', 0x01])
        .expect("stored suffix and shared length");
    encoded.splice(second..second + 4, [0x83, 0x42, b'a', b'2', 0x00]);
    assert!(decode_node(&encoded, true, MIN_CHUNK).is_err());
}

#[test]
fn whiteout_and_index_forms_are_strict() {
    let whiteout_with_attrs = [0xa2, 1, 5, 9, 0xa0];
    assert_eq!(
        decode_entry_bytes(&whiteout_with_attrs, MIN_CHUNK),
        Err(Error::Entry)
    );

    let index_with_duplicate_targets = {
        let mut bytes = vec![0xa2, 1, 7, 14, 0x82];
        for _ in 0..2 {
            bytes.extend_from_slice(&[0x58, 32]);
            bytes.extend_from_slice(&[3; 32]);
        }
        bytes
    };
    assert_eq!(
        decode_entry_bytes(&index_with_duplicate_targets, MIN_CHUNK),
        Err(Error::Entry)
    );
}

#[test]
fn conflicts_reject_conflict_candidates() {
    let nested = Entry {
        kind: EntryKind::Conflict {
            candidates: vec![file(None), file(None)],
            base: Some(None),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let outer = Entry {
        kind: EntryKind::Conflict {
            candidates: vec![file(None), nested],
            base: Some(None),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    assert!(super::encode_entry(&outer, MIN_CHUNK).is_err());
}

#[test]
fn properties_are_root_only_and_preserve_presence() {
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"f", file(None))]),
        props: Some(Vec::new()),
    };
    let encoded = encode_node(&node, true, MIN_CHUNK).expect("root property map");
    assert_eq!(
        encode_node(
            &decode_node(&encoded, true, MIN_CHUNK).expect("decode"),
            true,
            MIN_CHUNK
        )
        .expect("encode"),
        encoded
    );
    assert_eq!(decode_node(&encoded, false, MIN_CHUNK), Err(Error::Node));
}

#[test]
fn root_properties_and_items_share_the_node_payload_cap() {
    let mut value = Vec::new();
    crate::cbor::write_argument(&mut value, 3, 65_500);
    value.extend_from_slice(&vec![b'x'; 65_500]);
    let props = vec![super::Property {
        name: "p",
        value: &value,
    }];

    let root = Node {
        level: 0,
        items: NodeItems::Leaf(Vec::new()),
        props: Some(props.clone()),
    };
    encode_node(&root, true, MIN_CHUNK).expect("properties fit alone");

    let oversized = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"file", file(None))]),
        props: Some(props),
    };
    assert_eq!(encode_node(&oversized, true, MIN_CHUNK), Err(Error::Limit));
}

#[test]
fn child_summary_binds_identity_count_and_weight() {
    let child = Node {
        level: 0,
        items: NodeItems::Leaf(vec![item(b"f", file(None))]),
        props: None,
    };
    let encoded = encode_node(&child, false, MIN_CHUNK).expect("child encoding");
    let identity = crate::identity::TERRANE_V1
        .calculate(crate::identity::IdentityKind::Node, &encoded)
        .expect("node identity")
        .terrane_v1_digest()
        .expect("profile digest");
    let mut reference = ChildRef {
        last_key: b"f".to_vec(),
        child: identity,
        count: 1,
        weight: encoded.len() as u64,
    };
    verify_child_ref(1, &reference, &child, &encoded, MIN_CHUNK).expect("exact child");

    reference.count = 2;
    assert_eq!(
        verify_child_ref(1, &reference, &child, &encoded, MIN_CHUNK),
        Err(Error::Node)
    );
    reference.count = 1;
    reference.weight += 1;
    assert_eq!(
        verify_child_ref(1, &reference, &child, &encoded, MIN_CHUNK),
        Err(Error::Node)
    );
}

#[test]
fn hardlink_set_uses_first_key_and_identical_values() {
    let entries = [item(b"a", file(Some(b"a"))), item(b"b", file(Some(b"a")))];
    validate_tree_entries(&entries, TreeUse::Ordinary).expect("equal hardlinks");

    let wrong = [item(b"a", file(Some(b"b"))), item(b"b", file(Some(b"b")))];
    assert_eq!(
        validate_tree_entries(&wrong, TreeUse::Ordinary),
        Err(Error::Tree)
    );

    let mut changed = file(Some(b"a"));
    if let EntryKind::File { mode, .. } = &mut changed.kind {
        *mode = 0o600;
    }
    let divergent = [item(b"a", file(Some(b"a"))), item(b"b", changed)];
    assert_eq!(
        validate_tree_entries(&divergent, TreeUse::Ordinary),
        Err(Error::Tree)
    );
}

#[test]
fn grafts_and_algebra_entries_are_contextual() {
    let graft = Entry {
        kind: EntryKind::Tree {
            root: [3; 32],
            props: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let entries = [item(b"a", graft), item(b"a/b", file(None))];
    assert_eq!(
        validate_tree_entries(&entries, TreeUse::Ordinary),
        Err(Error::Tree)
    );

    let whiteout = Entry {
        kind: EntryKind::Whiteout,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let entries = [item(b"a", whiteout)];
    validate_tree_entries(&entries, TreeUse::OverlayLayer).expect("layer marker");
    assert_eq!(
        validate_tree_entries(&entries, TreeUse::Surface),
        Err(Error::Tree)
    );
}

#[test]
fn index_keys_are_opaque_bytes_at_construction_and_decode() {
    let index = || Entry {
        kind: EntryKind::Index {
            targets: vec![[1; 32]],
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let entries = [
        item(b"\0", index()),
        item(b"a\0b", index()),
        item(b"a/b", index()),
    ];
    validate_tree_entries(&entries, TreeUse::Index).expect("opaque keys in byte order");
    assert_eq!(validate_index_key(b""), Err(Error::Key));
    assert_eq!(validate_index_key(&vec![b'x'; 4097]), Err(Error::Key));

    let node = Node {
        level: 0,
        items: NodeItems::Leaf(entries.to_vec()),
        props: None,
    };
    let encoded =
        encode_node_for(&node, true, MIN_CHUNK, TreeUse::Index).expect("opaque index node");
    let decoded =
        decode_node_for(&encoded, true, MIN_CHUNK, TreeUse::Index).expect("opaque index decode");
    assert_eq!(decoded, node);
    assert_eq!(decode_node(&encoded, true, MIN_CHUNK), Err(Error::Key));
    assert_eq!(encode_node(&node, true, MIN_CHUNK), Err(Error::Key));

    let ordinary_entries = [item(b"a/b", file(None))];
    assert_eq!(
        validate_tree_entries(&ordinary_entries, TreeUse::Ordinary),
        Err(Error::Tree)
    );
    let ordinary = Node {
        level: 0,
        items: NodeItems::Leaf(ordinary_entries.to_vec()),
        props: None,
    };
    let ordinary_bytes =
        encode_node(&ordinary, true, MIN_CHUNK).expect("single node checks local path grammar");
    assert!(decode_node(&ordinary_bytes, true, MIN_CHUNK).is_ok());
}

#[test]
fn internal_index_keys_preserve_binary_last_key_order() {
    let node = Node {
        level: 1,
        items: NodeItems::Internal(vec![ChildRef {
            last_key: b"part/\0hash".to_vec(),
            child: [9; 32],
            count: 1,
            weight: 40,
        }]),
        props: None,
    };
    let encoded = encode_node_for(&node, true, MIN_CHUNK, TreeUse::Index).expect("binary last key");
    assert_eq!(
        decode_node_for(&encoded, true, MIN_CHUNK, TreeUse::Index),
        Ok(node)
    );
    assert_eq!(decode_node(&encoded, true, MIN_CHUNK), Err(Error::Key));
}

#[test]
fn graft_chain_rejects_cycles_and_excessive_depth() {
    assert_eq!(validate_graft_chain(&[[1; 32], [1; 32]]), Err(Error::Tree));
    let roots: Vec<_> = (0..=64).map(|index| [index; 32]).collect();
    assert_eq!(validate_graft_chain(&roots), Ok(()));

    let mut too_deep = roots;
    too_deep.push([65; 32]);
    assert_eq!(validate_graft_chain(&too_deep), Err(Error::Limit));
}

#[test]
fn property_nesting_is_distinct_from_graft_depth() {
    let mut value = vec![0x81; 4096];
    value.push(1);
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(Vec::new()),
        props: Some(vec![Property {
            name: "future",
            value: &value,
        }]),
    };
    let encoded = encode_node(&node, true, MIN_CHUNK).expect("input-bounded property");
    assert_eq!(decode_node(&encoded, true, MIN_CHUNK), Ok(node));

    let mut truncated = Decoder::new(&value[..value.len() - 1]);
    assert!(property_value(&mut truncated).is_err());
    let mut invalid = vec![0x81; 4096];
    invalid.push(0xf6);
    assert!(property_value(&mut Decoder::new(&invalid)).is_err());
}

fn conflict_chain_bytes(depth: usize, terminal: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..depth {
        bytes.extend_from_slice(&[0xa3, 1, 6, 12, 0x82, 0xa1, 1, 5, 0xa1, 1, 5, 13]);
    }
    bytes.extend_from_slice(terminal);
    bytes
}

#[test]
fn full_conflict_bases_exceed_graft_depth_and_round_trip() {
    // Each smallest valid frame consumes twelve encoded bytes (TREE-31).
    let depth = (super::MAX_NODE_ITEMS_BYTES - 3) / 12;
    let bytes = conflict_chain_bytes(depth, &[0xa1, 1, 5]);
    assert!(depth > super::MAX_GRAFT_DEPTH);

    let entry = decode_entry_bytes(&bytes, MIN_CHUNK).expect("valid entry fixture");
    let copy = entry.clone();
    assert!(entry == copy);
    assert!(alloc::format!("{entry:?}").contains("Whiteout"));
    assert_eq!(
        super::encode_entry(&copy, MIN_CHUNK).expect("valid entry fixture"),
        bytes
    );
    drop(copy);
    drop(entry);
}

#[test]
fn conflict_base_distinguishes_absent_null_and_full_entry() {
    let absent = decode_entry_bytes(&[0xa2, 1, 6, 12, 0x82, 0xa1, 1, 5, 0xa1, 1, 5], MIN_CHUNK)
        .expect("valid entry fixture");
    let null_bytes = conflict_chain_bytes(1, &[0xf6]);
    let null = decode_entry_bytes(&null_bytes, MIN_CHUNK).expect("valid entry fixture");
    let full_bytes = conflict_chain_bytes(1, &[0xa1, 1, 5]);
    let full = decode_entry_bytes(&full_bytes, MIN_CHUNK).expect("valid entry fixture");

    assert!(absent != null);
    assert!(null != full);
    assert!(absent == absent.clone());
    assert!(null == null.clone());
    assert!(full == full.clone());
}

#[test]
fn deep_invalid_conflict_bases_reject_without_panicking() {
    let invalid = [
        &[0xa1, 1, 8][..],
        &[0xa1, 1, 16][..],
        &[0xa2, 1, 5, 14, 0x80][..],
        &[0xa2, 1, 6, 12, 0x81, 0xa1, 1, 5][..],
        &[
            0xa2, 1, 6, 12, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ][..],
    ];
    for terminal in invalid {
        let bytes = conflict_chain_bytes(5000, terminal);
        assert!(decode_entry_bytes(&bytes, MIN_CHUNK).is_err());
    }
    let bytes = conflict_chain_bytes(5000, &[0xa1, 1, 5]);
    for end in bytes.len() - 15..bytes.len() {
        assert!(decode_entry_bytes(&bytes[..end], MIN_CHUNK).is_err());
    }
}

#[test]
fn conflict_entries_enforce_encoded_size_at_construction_and_decode() {
    let valid_bytes = conflict_chain_bytes(5461, &[0xa1, 1, 5]);
    let oversized_bytes = conflict_chain_bytes(5462, &[0xa1, 1, 5]);
    let mut entry = decode_entry_bytes(&valid_bytes, MIN_CHUNK).expect("valid entry fixture");
    entry.kind = EntryKind::Conflict {
        candidates: vec![directory(), directory()],
        base: Some(Some(alloc::boxed::Box::new(entry.clone()))),
    };

    assert_eq!(super::encode_entry(&entry, MIN_CHUNK), Err(Error::Limit));
    assert_eq!(
        decode_entry_bytes(&oversized_bytes, MIN_CHUNK),
        Err(Error::Limit)
    );
}

#[test]
fn max_claimed_entry_collection_counts_fail_before_materialization() {
    for field in [12, 14] {
        let mut bytes = vec![0xa2, 1, if field == 12 { 6 } else { 7 }, field, 0x9b];
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode_entry_bytes(&bytes, MIN_CHUNK).is_err());
    }
}

#[test]
fn invalid_candidate_payload_cannot_recurse_through_nonconflict_entries() {
    let mut bytes = Vec::new();
    for _ in 0..5000 {
        bytes.extend_from_slice(&[0xa2, 1, 5, 12, 0x82]);
    }
    assert_eq!(decode_entry_bytes(&bytes, MIN_CHUNK), Err(Error::Entry));
}

#[test]
fn conflict_base_can_fill_the_complete_entry_byte_budget() {
    let mut terminal = vec![0xa2, 1, 3, 5, 0x4b];
    terminal.extend_from_slice(b"elevenbytes");
    let bytes = conflict_chain_bytes(5460, &terminal);
    assert_eq!(bytes.len(), super::MAX_NODE_ITEMS_BYTES);

    let entry = decode_entry_bytes(&bytes, MIN_CHUNK).expect("exact-limit base chain");
    assert_eq!(
        super::encode_entry(&entry, MIN_CHUNK).expect("exact-limit encoding"),
        bytes
    );
}
