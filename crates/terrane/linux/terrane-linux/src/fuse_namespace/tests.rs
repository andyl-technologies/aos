//! Checks original-node reverse lookup and direct-child namespace boundaries.

#![allow(
    clippy::unwrap_used,
    reason = "Namespace fixtures panic on unexpected construction or lookup failures."
)]

use super::*;
use crate::structural_index::{Record, compile, compile_tree};
use std::collections::BTreeMap;
use terrane_format::{
    tree_builder::Tree,
    tree_format::{ContentRef, Entry as TreeEntry, EntryKind, LeafItem, TreeUse},
};

fn records() -> Vec<Record<'static>> {
    vec![
        Record {
            path: b"dir",
            kind: Kind::Directory {
                governing_root: None,
            },
        },
        Record {
            path: b"dir/a",
            kind: Kind::File {
                content: ContentRef::Inline([2; 32]),
                size: 3,
            },
        },
        Record {
            path: b"dir/z",
            kind: Kind::Symlink(b"../other"),
        },
        Record {
            path: b"other",
            kind: Kind::Directory {
                governing_root: None,
            },
        },
    ]
}

fn node(entry: Entry<'_>) -> u64 {
    if entry.path().is_empty() {
        return 1;
    }
    let canonical = entry.canonical_inode().unwrap();
    NodeIdentity::new(canonical.governing_root().unwrap(), canonical.path())
        .unwrap()
        .node_id()
}

#[test]
fn child_lookup_resolves_only_direct_names_and_namespace_dot_components() {
    let bytes = compile([7; 32], &records(), 16, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    let namespace = Namespace::new(index, 16, 65536).unwrap();
    let directory = namespace.lookup(1, b"dir").unwrap().unwrap();
    let id = node(directory);
    assert_eq!(
        namespace.lookup(id, b"a").unwrap().unwrap().path(),
        b"dir/a"
    );
    assert_eq!(
        namespace.lookup(id, b"z").unwrap().unwrap().path(),
        b"dir/z"
    );
    assert_eq!(namespace.lookup(id, b".").unwrap().unwrap().path(), b"dir");
    assert_eq!(namespace.lookup(id, b"..").unwrap().unwrap().path(), b"");
    assert_eq!(namespace.lookup(1, b"..").unwrap().unwrap().path(), b"");
    assert!(namespace.lookup(1, b"a").unwrap().is_none());
    assert!(namespace.lookup(id, b"other").unwrap().is_none());
    assert!(namespace.lookup(id, b"missing").unwrap().is_none());
    let link = namespace.lookup(id, b"z").unwrap().unwrap();
    assert!(matches!(
        namespace.lookup(node(link), b"a"),
        Err(Error::NotDirectory)
    ));
    assert_eq!(crate::fuse_metadata::readlink(link).unwrap(), b"../other");
}

#[test]
fn reverse_lookup_preserves_canonical_hardlinks_and_distinct_equal_content() {
    let file = |path: &[u8], link_id| LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::File {
                mode: 0o444,
                size: 3,
                content: ContentRef::Inline([2; 32]),
                link_id,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    };
    let tree = Tree::build(
        vec![
            file(b"a", Some(b"a")),
            file(b"b", Some(b"a")),
            file(b"c", None),
        ],
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap();
    let bytes = compile_tree(&tree, &BTreeMap::new(), 16, 65536).unwrap();
    let namespace = Namespace::new(Index::open(&bytes).unwrap(), 16, 65536).unwrap();
    let a = namespace.lookup(1, b"a").unwrap().unwrap();
    let b = namespace.lookup(1, b"b").unwrap().unwrap();
    let c = namespace.lookup(1, b"c").unwrap().unwrap();
    assert_eq!(node(a), node(b));
    assert_ne!(node(a), node(c));
    assert_eq!(namespace.entry(node(b)).unwrap().path(), b"a");
    assert_eq!(namespace.entry(node(c)).unwrap().path(), b"c");
    assert_eq!(namespace.entry(node(b)).unwrap().link_count().unwrap(), 2);
    assert_eq!(namespace.nodes.len(), 3);
}

#[test]
fn graft_reverse_nodes_and_dotdot_keep_original_namespace_prefixes() {
    let mut records = records();
    records[0].kind = Kind::Directory {
        governing_root: Some([9; 32]),
    };
    records.push(Record {
        path: b"other/a",
        kind: Kind::File {
            content: ContentRef::Inline([2; 32]),
            size: 3,
        },
    });
    records[3].kind = Kind::Directory {
        governing_root: Some([9; 32]),
    };
    let bytes = compile([7; 32], &records, 16, 65536).unwrap();
    let namespace = Namespace::new(Index::open(&bytes).unwrap(), 16, 65536).unwrap();
    let left = namespace.lookup(1, b"dir").unwrap().unwrap();
    let right = namespace.lookup(1, b"other").unwrap().unwrap();
    let a = namespace.lookup(node(left), b"a").unwrap().unwrap();
    let b = namespace.lookup(node(right), b"a").unwrap().unwrap();
    assert_eq!(a.governing_root().unwrap(), b.governing_root().unwrap());
    assert_ne!(node(a), node(b));
    assert_eq!(namespace.entry(node(a)).unwrap().path(), b"dir/a");
    assert_eq!(namespace.entry(node(b)).unwrap().path(), b"other/a");
    assert_eq!(
        namespace.lookup(node(left), b"..").unwrap().unwrap().path(),
        b""
    );
    assert_eq!(
        namespace
            .lookup(node(right), b"..")
            .unwrap()
            .unwrap()
            .path(),
        b""
    );
}

#[test]
fn raw_names_and_unknown_nodes_never_escape_the_original_index() {
    let name = vec![0xff; MAX_COMPONENT];
    let bytes = compile(
        [7; 32],
        &[Record {
            path: &name,
            kind: Kind::Symlink(b"/unresolved"),
        }],
        2,
        65536,
    )
    .unwrap();
    let namespace = Namespace::new(Index::open(&bytes).unwrap(), 2, 65536).unwrap();
    assert_eq!(namespace.lookup(1, &name).unwrap().unwrap().path(), name);
    for bad in [
        b"".as_slice(),
        b"a/b",
        b"bad\0name",
        &[b'x'; MAX_COMPONENT + 1],
    ] {
        assert!(matches!(namespace.lookup(1, bad), Err(Error::Name)));
    }
    for unknown in [0, 2, u64::MAX] {
        assert!(namespace.entry(unknown).is_none());
        assert!(matches!(
            namespace.lookup(unknown, b"a"),
            Err(Error::UnknownNode)
        ));
    }
    assert!(namespace.lookup(1, b"not-there").unwrap().is_none());
}

#[test]
fn startup_budgets_include_every_original_path_and_the_synthesized_root() {
    let bytes = compile([7; 32], &records(), 16, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    let count = index.len();
    let budget = count as usize * size_of::<Node>();
    assert!(Namespace::new(index, count, budget).is_ok());
    assert!(matches!(
        Namespace::new(index, count - 1, budget),
        Err(Error::Budget)
    ));
    assert!(matches!(
        Namespace::new(index, count, budget - 1),
        Err(Error::Budget)
    ));
    assert!(matches!(
        Namespace::new(index, 0, usize::MAX),
        Err(Error::Budget)
    ));
}

#[test]
fn touched_nodes_bound_storage_independently_of_paths_and_share_hardlink_records() {
    let file = |path: &[u8], link_id| LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::File {
                mode: 0o444,
                size: 3,
                content: ContentRef::Inline([2; 32]),
                link_id,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    };
    let tree = Tree::build(
        vec![
            file(b"a", Some(b"a")),
            file(b"b", Some(b"a")),
            file(b"c", None),
        ],
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap();
    let bytes = compile_tree(&tree, &BTreeMap::new(), 16, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    let budget = 2 * size_of::<Node>();
    assert!(matches!(
        Namespace::new(index, 2, budget),
        Err(Error::Budget)
    ));
    let mut namespace = Namespace::with_touched_nodes(index, 2, budget).unwrap();
    let capacity = namespace.nodes.capacity();
    let empty_bytes = compile([7; 32], &[], 1, 65536).unwrap();
    let empty =
        Namespace::with_touched_nodes(Index::open(&empty_bytes).unwrap(), 2, budget).unwrap();
    assert_eq!(empty.nodes.capacity(), capacity);
    assert_eq!(empty.nodes.len(), 1);
    assert_eq!(namespace.nodes.len(), 1);
    let a = index.lookup(b"a").unwrap();
    let b = index.lookup(b"b").unwrap();
    let c = index.lookup(b"c").unwrap();
    assert!(namespace.entry(node(a)).is_none());

    assert_eq!(namespace.remember(b.position()).unwrap(), node(a));
    assert_eq!(namespace.remember(a.position()).unwrap(), node(a));
    assert_eq!(namespace.entry(node(b)).unwrap().path(), b"a");
    assert_eq!(namespace.nodes.len(), 2);
    assert!(matches!(
        namespace.remember(c.position()),
        Err(Error::Budget)
    ));
    assert!(namespace.entry(node(c)).is_none());
    assert_eq!(namespace.entry(node(a)).unwrap().path(), b"a");
    assert_eq!(namespace.entry(1).unwrap().path(), b"");
    assert_eq!(namespace.nodes.capacity(), capacity);
}

#[test]
fn touched_node_refusals_preserve_existing_mappings_and_reserved_capacity() {
    let bytes = compile([7; 32], &records(), 16, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    assert!(matches!(
        Namespace::with_touched_nodes(index, 0, usize::MAX),
        Err(Error::Budget)
    ));
    assert!(matches!(
        Namespace::with_touched_nodes(index, 2, size_of::<Node>()),
        Err(Error::Budget)
    ));
    let mut namespace = Namespace::with_touched_nodes(index, 3, 4096).unwrap();
    let directory = index.lookup(b"dir").unwrap();
    let other = index.lookup(b"other").unwrap();
    let id = namespace.remember(directory.position()).unwrap();
    let capacity = namespace.nodes.capacity();
    assert!(matches!(
        namespace.remember(index.len()),
        Err(Error::Index(_))
    ));
    assert_eq!(namespace.nodes.len(), 2);
    assert_eq!(namespace.entry(id).unwrap().path(), b"dir");

    // Inject the otherwise impractical hash collision at the reverse-table boundary.
    let position = namespace
        .nodes
        .binary_search_by_key(&id, |entry| entry.id)
        .unwrap();
    namespace.nodes[position].position = other.position();
    assert!(matches!(
        namespace.remember(directory.position()),
        Err(Error::Collision)
    ));
    assert_eq!(namespace.entry(id).unwrap().path(), b"other");
    assert_eq!(namespace.nodes.len(), 2);
    assert_eq!(namespace.nodes.capacity(), capacity);
    assert_eq!(namespace.entry(1).unwrap().path(), b"");
}
