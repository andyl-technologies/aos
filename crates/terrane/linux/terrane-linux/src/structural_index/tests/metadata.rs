//! Checks recorded fields, canonical link identities and hostile metadata arenas.

use std::collections::BTreeMap;

use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{
    Attribute, Entry as TreeEntry, EntryKind, ExtendedAttribute, LeafItem, Property, TreeUse,
};

use super::super::*;
use crate::inode_policy::InodeTable;

fn file(path: &[u8], link_id: Option<&'static [u8]>) -> LeafItem<'static> {
    LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::File {
                mode: 0o640,
                size: 1,
                content: ContentRef::Inline([2; 32]),
                link_id,
            },
            attrs: vec![
                Attribute {
                    name: "uid",
                    value: b"\x18\x2a",
                },
                Attribute {
                    name: "unknown",
                    value: b"\x81\xf5",
                },
            ],
            attrs_present: true,
            xattrs: vec![ExtendedAttribute {
                name: b"user.\xff",
                value: b"raw\0value",
            }],
            xattrs_present: true,
            provenance: None,
        },
    }
}

fn linked_tree() -> Tree<'static> {
    Tree::build(
        vec![
            file(b"a", Some(b"a")),
            file(b"b", Some(b"a")),
            file(b"c", None),
        ],
        Some(vec![Property {
            name: "x.recorded",
            value: b"\x01",
        }]),
        4096,
        TreeUse::Ordinary,
    )
    .unwrap()
}

fn graft(path: &[u8], root: Digest) -> LeafItem<'static> {
    LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::Tree {
                root,
                props: Some(vec![Property {
                    name: "x.override",
                    value: b"\x02",
                }]),
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: true,
            provenance: None,
        },
    }
}

#[test]
fn canonical_tree_preserves_modes_unknown_fields_and_graft_properties() {
    let child = linked_tree();
    let child_hash = child.root_identity();
    let mut directory = file(b"directory", None);
    directory.entry.kind = EntryKind::Directory { mode: 0o1750 };
    let mut symlink = file(b"link", None);
    symlink.entry.kind = EntryKind::Symlink {
        target: b"./graft/a",
    };
    let root = Tree::build(
        vec![directory, graft(b"graft", child_hash), symlink],
        Some(vec![Property {
            name: "x.outer",
            value: b"\x03",
        }]),
        4096,
        TreeUse::Ordinary,
    )
    .unwrap();
    let grafts = BTreeMap::from([(child_hash, child)]);
    let bytes = compile_tree(&root, &grafts, 10, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();

    let root_metadata = index.lookup(b"").unwrap().metadata().unwrap();
    assert_eq!(root_metadata.mode, None);
    assert_eq!(
        root_metadata.root_properties.get(b"x.outer"),
        Some(b"\x03".as_slice())
    );
    let graft_metadata = index.lookup(b"graft").unwrap().metadata().unwrap();
    assert_eq!(
        graft_metadata.root_properties.get(b"x.recorded"),
        Some(b"\x01".as_slice())
    );
    assert_eq!(
        graft_metadata.graft_overrides.get(b"x.override"),
        Some(b"\x02".as_slice())
    );
    assert!(graft_metadata.xattrs_present);
    assert!(graft_metadata.xattrs.is_empty());
    assert_eq!(
        index.lookup(b"directory").unwrap().metadata().unwrap().mode,
        Some(0o1750)
    );
    let symlink = index.lookup(b"link").unwrap();
    assert_eq!(symlink.metadata().unwrap().mode, None);
    assert_eq!(
        symlink.metadata().unwrap().attributes.get(b"uid"),
        Some(b"\x18\x2a".as_slice())
    );
    assert_eq!(symlink.link_count().unwrap(), 1);

    let file = index.lookup(b"graft/b").unwrap();
    let metadata = file.metadata().unwrap();
    assert_eq!(metadata.mode, Some(0o640));
    assert!(metadata.attributes_present && metadata.xattrs_present);
    assert_eq!(
        metadata.attributes.get(b"uid"),
        Some(b"\x18\x2a".as_slice())
    );
    assert_eq!(
        metadata.attributes.get(b"unknown"),
        Some(b"\x81\xf5".as_slice())
    );
    assert_eq!(
        metadata.xattrs.get(b"user.\xff"),
        Some(b"raw\0value".as_slice())
    );
    assert_eq!(metadata.attributes.iter().len(), 2);
    assert!(metadata.attributes.get(b"absent").is_none());
    assert!(metadata.root_properties.is_empty() && metadata.graft_overrides.is_empty());
    // Views point into the index itself, without reconstructing CBOR objects.
    let value = metadata.attributes.get(b"unknown").unwrap();
    assert!(value.as_ptr() >= bytes.as_ptr() && value.as_ptr() < bytes.as_ptr_range().end);
    assert_eq!(
        compile_tree(&root, &grafts, index.len(), bytes.len()).unwrap(),
        bytes
    );
    assert_eq!(
        compile_tree(&root, &grafts, index.len(), bytes.len() - 1),
        Err(Error::Limit)
    );
}

#[test]
fn hardlinks_share_checked_inodes_but_repeated_grafts_and_equal_content_do_not() {
    let child = linked_tree();
    let child_hash = child.root_identity();
    let root = Tree::build(
        vec![graft(b"left", child_hash), graft(b"right", child_hash)],
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap();
    let bytes = compile_tree(&root, &BTreeMap::from([(child_hash, child)]), 10, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    let mut table = InodeTable::new(4).unwrap();

    // Start with an alias to establish independence from first lookup order.
    let left = table.touch_entry(index.lookup(b"left/b").unwrap()).unwrap();
    assert_eq!(
        left,
        table.touch_entry(index.lookup(b"left/a").unwrap()).unwrap()
    );
    assert_eq!(left.1.links(), 2);
    let equal_content = table.touch_entry(index.lookup(b"left/c").unwrap()).unwrap();
    let right = table
        .touch_entry(index.lookup(b"right/a").unwrap())
        .unwrap();
    assert_ne!(left.0, equal_content.0);
    assert_ne!(left.0, right.0);
    assert_ne!(left.1.number(), right.1.number());
    assert_eq!(table.len(), 3);
    assert_eq!(equal_content.1.links(), 1);
    assert_eq!(
        index
            .lookup(b"left/b")
            .unwrap()
            .canonical_inode()
            .unwrap()
            .path(),
        b"left/a"
    );
    assert_eq!(index.lookup(b"").unwrap().link_count().unwrap(), 4);
    assert_eq!(index.lookup(b"left").unwrap().link_count().unwrap(), 2);
}

#[test]
fn malformed_metadata_maps_modes_and_cursors_are_refused() {
    let tree = linked_tree();
    let bytes = compile_tree(&tree, &BTreeMap::new(), 4, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    let entry = index.entries + ENTRY;
    let metadata = index.metadata + offset(&bytes, entry + 52).unwrap();
    for (start, replacement) in [
        (metadata, vec![0, 0x10]), // permission bits exceed the recorded mode domain
        (metadata + 2, vec![0x80, 0]), // reserved flags
        (metadata + 4, u32::MAX.to_le_bytes().to_vec()), // impossible field count
        (metadata + 8, u32::MAX.to_le_bytes().to_vec()), // escaped map length
        (metadata + 12, vec![0, 0]), // empty attribute name
        (metadata + 14, u32::MAX.to_le_bytes().to_vec()), // escaped value length
        (metadata + 18, vec![0xff]), // text attribute name is not UTF-8
        (metadata + 21, vec![0x18, 0x01]), // noncanonical CBOR integer
        (entry + 52, u64::MAX.to_le_bytes().to_vec()), // escaped metadata offset
        (entry + 60, u32::MAX.to_le_bytes().to_vec()), // escaped record length
    ] {
        let mut malformed = bytes.clone();
        malformed[start..start + replacement.len()].copy_from_slice(&replacement);
        assert!(
            Index::open(&malformed).is_err(),
            "accepted mutation at {start}"
        );
    }
    let mut missing_presence = bytes.clone();
    missing_presence[metadata + 2] &= !2;
    assert!(Index::open(&missing_presence).is_err());
}

#[test]
fn forged_link_runs_counts_and_canonical_entries_are_refused() {
    let tree = linked_tree();
    let bytes = compile_tree(&tree, &BTreeMap::new(), 4, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    for (start, value) in [
        (index.entries + 64, 0),                // root is not a hard-linked file
        (index.entries + ENTRY + 64, 2),        // canonical must be the first member
        (index.entries + ENTRY + 68, 1),        // skipped membership
        (index.entries + ENTRY + 72, 0),        // empty canonical set
        (index.entries + ENTRY + 72, u32::MAX), // escaped membership run
        (index.entries + 2 * ENTRY + 72, 1),    // alias cannot own a run
        (index.entries + 2 * ENTRY + 16, 0),    // alias has a different logical size
        (index.links, 2),                       // canonical omitted from its run
        (index.links + 4, 1),                   // duplicate membership
        (index.links + 4, 3),                   // member belongs to another set
    ] {
        let mut malformed = bytes.clone();
        malformed[start..start + 4].copy_from_slice(&value.to_le_bytes());
        assert!(
            Index::open(&malformed).is_err(),
            "accepted link mutation at {start}"
        );
    }
    let mut changed_mode = bytes.clone();
    let alias_metadata = index.metadata + offset(&bytes, index.entries + 2 * ENTRY + 52).unwrap();
    changed_mode[alias_metadata] ^= 1;
    assert!(
        Index::open(&changed_mode).is_err(),
        "aliases must retain identical metadata"
    );
}

#[test]
fn metadata_key_order_duplicate_names_and_old_format_are_refused() {
    use super::super::compile::compile_metadata;
    use super::super::metadata::Input;

    let records = [Record {
        path: b"file",
        kind: Kind::File {
            content: ContentRef::Inline([1; 32]),
            size: 1,
        },
    }];
    for attributes in [
        vec![
            Attribute {
                name: "z",
                value: b"\x01",
            },
            Attribute {
                name: "a",
                value: b"\x02",
            },
        ],
        vec![
            Attribute {
                name: "a",
                value: b"\x01",
            },
            Attribute {
                name: "a",
                value: b"\x02",
            },
        ],
        vec![Attribute {
            name: "a",
            value: b"\x18\x01",
        }],
    ] {
        let input = Input {
            attributes,
            attributes_present: true,
            ..Input::default()
        };
        assert!(
            compile_metadata([0; 32], &records, &Input::default(), &[&input], 2, 65536).is_err()
        );
    }
    // Unrecognized properties still obey the tree codec's value vocabulary.
    let invalid_property = Input {
        root_properties: vec![Property {
            name: "x.unknown",
            value: b"\x41x",
        }],
        ..Input::default()
    };
    assert!(
        compile_metadata(
            [0; 32],
            &records,
            &invalid_property,
            &[&Input::default()],
            2,
            65536
        )
        .is_err()
    );
    let first = Input::default();
    let alias = Input {
        canonical_path: Some(b"left/file".to_vec()),
        ..Input::default()
    };
    let cross_graft = [
        Record {
            path: b"left",
            kind: Kind::Directory {
                governing_root: Some([1; 32]),
            },
        },
        Record {
            path: b"left/file",
            kind: records[0].kind,
        },
        Record {
            path: b"right",
            kind: Kind::Directory {
                governing_root: Some([1; 32]),
            },
        },
        Record {
            path: b"right/file",
            kind: records[0].kind,
        },
    ];
    assert!(
        compile_metadata(
            [0; 32],
            &cross_graft,
            &Input::default(),
            &[&first, &first, &first, &alias],
            5,
            65536
        )
        .is_err()
    );
    let mut old = compile([0; 32], &records, 2, 65536).unwrap();
    old[4] = 1;
    assert!(Index::open(&old).is_err());
}
