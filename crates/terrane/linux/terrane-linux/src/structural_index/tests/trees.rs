//! Checks compilation from canonical tree graphs without plaintext inputs.

use std::collections::BTreeMap;

use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{self, Entry as TreeEntry, EntryKind, LeafItem, TreeUse};

use super::super::*;

const MINIMUM: u64 = 4096;

fn item(path: &[u8], kind: EntryKind<'static>) -> LeafItem<'static> {
    LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind,
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    }
}

fn tree(entries: Vec<LeafItem<'static>>) -> Tree<'static> {
    Tree::build(entries, None, MINIMUM, TreeUse::Ordinary).unwrap()
}

fn graft(path: &[u8], root: Digest) -> LeafItem<'static> {
    item(path, EntryKind::Tree { root, props: None })
}

#[test]
fn canonical_nested_grafts_compile_without_any_file_content_input() {
    let nested = tree(vec![item(
        b"large",
        EntryKind::File {
            mode: 0o444,
            size: 8192,
            content: ContentRef::Manifest([1; 32]),
            link_id: None,
        },
    )]);
    let nested_hash = nested.root_identity();
    let child = tree(vec![
        graft(b"nested", nested_hash),
        item(
            b"small",
            EntryKind::File {
                mode: 0o444,
                size: 1,
                content: ContentRef::Inline([2; 32]),
                link_id: None,
            },
        ),
    ]);
    let child_hash = child.root_identity();
    let root = tree(vec![
        graft(b"graft", child_hash),
        item(
            b"link",
            EntryKind::Symlink {
                target: b"graft/nested/large",
            },
        ),
    ]);
    let grafts = BTreeMap::from([(nested_hash, nested), (child_hash, child)]);

    let bytes = compile_tree(&root, &grafts, 32, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();

    assert_eq!(index.root_hash(), root.root_identity());
    assert_eq!(
        index.lookup(b"graft/nested/large").unwrap().kind(),
        Kind::File {
            content: ContentRef::Manifest([1; 32]),
            size: 8192
        }
    );
    assert_eq!(
        index.lookup(b"graft/small").unwrap().kind(),
        Kind::File {
            content: ContentRef::Inline([2; 32]),
            size: 1
        }
    );
    assert_eq!(
        index
            .lookup(b"graft/nested/large")
            .unwrap()
            .governing_root()
            .unwrap(),
        nested_hash
    );
    assert_eq!(
        index
            .lookup(b"graft/small")
            .unwrap()
            .governing_root()
            .unwrap(),
        child_hash
    );
    assert_eq!(
        index.lookup(b"link").unwrap().governing_root().unwrap(),
        root.root_identity()
    );
    assert_eq!(
        index
            .lookup(b"graft")
            .unwrap()
            .children()
            .unwrap()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        [b"graft/nested".as_slice(), b"graft/small".as_slice()]
    );
    assert_eq!(
        compile_tree(&root, &grafts, index.len(), bytes.len()).unwrap(),
        bytes
    );
}

#[test]
fn repeated_grafts_expand_at_distinct_paths_with_one_governing_root() {
    let child = tree(vec![item(
        b"file",
        EntryKind::File {
            mode: 0o444,
            size: 1,
            content: ContentRef::Inline([2; 32]),
            link_id: None,
        },
    )]);
    let child_hash = child.root_identity();
    let root = tree(vec![graft(b"a", child_hash), graft(b"b", child_hash)]);

    let bytes = compile_tree(&root, &BTreeMap::from([(child_hash, child)]), 5, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();

    assert_eq!(index.len(), 5);
    for path in [b"a/file".as_slice(), b"b/file".as_slice()] {
        assert_eq!(
            index.lookup(path).unwrap().governing_root().unwrap(),
            child_hash
        );
    }
    assert_eq!(
        index
            .lookup(b"")
            .unwrap()
            .children()
            .unwrap()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        [b"a".as_slice(), b"b".as_slice()]
    );
}

#[test]
fn absent_misbound_nonordinary_and_wrong_geometry_grafts_are_refused() {
    let child = tree(Vec::new());
    let child_hash = child.root_identity();
    let root = tree(vec![graft(b"a", child_hash)]);
    assert_eq!(
        compile_tree(&root, &BTreeMap::new(), 10, 65536),
        Err(Error::Tree)
    );
    let different = tree(vec![item(b"dir", EntryKind::Directory { mode: 0o755 })]);
    assert_eq!(
        compile_tree(&root, &BTreeMap::from([(child_hash, different)]), 10, 65536),
        Err(Error::Tree)
    );

    let wrong_geometry = Tree::build(Vec::new(), None, MINIMUM * 2, TreeUse::Ordinary).unwrap();
    assert_eq!(wrong_geometry.root_identity(), child_hash);
    assert_eq!(
        compile_tree(
            &root,
            &BTreeMap::from([(child_hash, wrong_geometry)]),
            10,
            65536
        ),
        Err(Error::Tree)
    );
    let overlay = Tree::build(
        vec![item(b"removed", EntryKind::Whiteout)],
        None,
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    assert_eq!(
        compile_tree(&overlay, &BTreeMap::new(), 10, 65536),
        Err(Error::Tree)
    );
}

#[test]
fn expanded_entries_bytes_and_full_paths_obey_compiler_limits() {
    let child = tree(vec![item(
        b"file",
        EntryKind::File {
            mode: 0o444,
            size: 1,
            content: ContentRef::Inline([2; 32]),
            link_id: None,
        },
    )]);
    let child_hash = child.root_identity();
    let root = tree(vec![graft(b"a", child_hash), graft(b"b", child_hash)]);
    let grafts = BTreeMap::from([(child_hash, child)]);
    let bytes = compile_tree(&root, &grafts, 5, 65536).unwrap();
    assert_eq!(compile_tree(&root, &grafts, 4, 65536), Err(Error::Limit));
    assert_eq!(
        compile_tree(&root, &grafts, 5, bytes.len() - 1),
        Err(Error::Limit)
    );
    assert_eq!(compile_tree(&root, &grafts, 0, 65536), Err(Error::Limit));

    let component = vec![b'x'; 255];
    let mut key = Vec::new();
    let mut entries = Vec::new();
    for _ in 0..16 {
        if !key.is_empty() {
            key.push(b'/');
        }
        key.extend_from_slice(&component);
        entries.push(item(&key, EntryKind::Directory { mode: 0o755 }));
    }
    // Each source key is valid, but prefixing this graft exceeds MAX_KEY.
    let child = tree(entries);
    let child_hash = child.root_identity();
    let root = tree(vec![graft(b"prefix", child_hash)]);
    assert_eq!(
        compile_tree(&root, &BTreeMap::from([(child_hash, child)]), 32, 65536),
        Err(Error::Tree)
    );
}

#[test]
fn maximum_graft_depth_is_supported_and_the_next_edge_is_refused() {
    let mut grafts = BTreeMap::new();
    let mut current = tree(Vec::new());
    for _ in 0..tree_format::MAX_GRAFT_DEPTH {
        let hash = current.root_identity();
        grafts.insert(hash, current);
        current = tree(vec![graft(b"next", hash)]);
    }
    let bytes = compile_tree(&current, &grafts, 128, 65536).unwrap();
    assert_eq!(Index::open(&bytes).unwrap().len(), 65);

    let hash = current.root_identity();
    grafts.insert(hash, current);
    let excessive = tree(vec![graft(b"next", hash)]);
    assert_eq!(
        compile_tree(&excessive, &grafts, 128, 65536),
        Err(Error::Limit)
    );
}

fn nodes(trees: &[&Tree<'_>]) -> BTreeMap<Digest, Vec<u8>> {
    trees
        .iter()
        .flat_map(|tree| {
            tree.nodes()
                .map(|node| (node.identity(), node.encoded().to_vec()))
        })
        .collect()
}

#[test]
fn raw_nodes_compile_only_after_actual_identity_and_graft_validation() {
    let child = tree(vec![item(
        b"large",
        EntryKind::File {
            mode: 0o444,
            size: 8192,
            content: ContentRef::Manifest([1; 32]),
            link_id: None,
        },
    )]);
    let child_hash = child.root_identity();
    let root = tree(vec![graft(b"a", child_hash), graft(b"b", child_hash)]);
    let mut inventory = nodes(&[&root, &child]);
    assert!(
        !inventory.contains_key(&[1; 32]),
        "file manifest is deliberately unavailable"
    );
    let bytes = compile_nodes(root.root_identity(), &inventory, MINIMUM, 5, 65536, 65536).unwrap();
    assert_eq!(
        bytes,
        compile_tree(&root, &BTreeMap::from([(child_hash, child)]), 5, 65536).unwrap()
    );
    assert_eq!(
        Index::open(&bytes)
            .unwrap()
            .lookup(b"a/large")
            .unwrap()
            .kind(),
        Kind::File {
            content: ContentRef::Manifest([1; 32]),
            size: 8192
        }
    );

    let child_bytes = inventory.remove(&child_hash).unwrap();
    assert_eq!(
        compile_nodes(root.root_identity(), &inventory, MINIMUM, 5, 65536, 65536),
        Err(Error::Tree)
    );
    inventory.insert(
        child_hash,
        b"malformed under the original identity".to_vec(),
    );
    assert_eq!(
        compile_nodes(root.root_identity(), &inventory, MINIMUM, 5, 65536, 65536),
        Err(Error::Tree)
    );
    inventory.insert(child_hash, child_bytes);
    assert_eq!(
        compile_nodes([0; 32], &inventory, MINIMUM, 5, 65536, 65536),
        Err(Error::Tree)
    );
}

#[test]
fn raw_nodes_check_internal_summaries_after_individual_hashes_match() {
    let root = tree(
        (0..10000)
            .map(|index| {
                item(
                    format!("key-{index:08}").as_bytes(),
                    EntryKind::Directory { mode: 0o755 },
                )
            })
            .collect(),
    );
    assert!(root.root().level() > 0);
    let mut inventory = nodes(&[&root]);
    let mut node = tree_format::decode_node(root.root().encoded(), true, MINIMUM).unwrap();
    let tree_format::NodeItems::Internal(children) = &mut node.items else {
        panic!("expected genuine internal root");
    };
    children[0].count += 1;
    let forged = tree_format::encode_node(&node, true, MINIMUM).unwrap();
    let identity: Digest = terrane_format::identity::TERRANE_V1
        .calculate(terrane_format::identity::IdentityKind::Node, &forged)
        .unwrap()
        .digest()
        .try_into()
        .unwrap();
    inventory.remove(&root.root_identity());
    inventory.insert(identity, forged);

    // Each inventory member has its actual Node identity. Only rebuilding the
    // complete canonical tree exposes the false internal subtree summary.
    for (identity, bytes) in &inventory {
        assert_eq!(
            terrane_format::identity::TERRANE_V1
                .calculate(terrane_format::identity::IdentityKind::Node, bytes)
                .unwrap()
                .digest(),
            identity
        );
    }
    assert_eq!(
        compile_nodes(
            identity,
            &inventory,
            MINIMUM,
            10001,
            2 * 1024 * 1024,
            2 * 1024 * 1024
        ),
        Err(Error::Tree)
    );

    let valid = nodes(&[&root]);
    let bytes = compile_nodes(
        root.root_identity(),
        &valid,
        MINIMUM,
        10001,
        2 * 1024 * 1024,
        2 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(Index::open(&bytes).unwrap().len(), 10001);
}

#[test]
fn raw_node_budget_charges_all_keys_before_decoding_or_expansion() {
    let root = tree(Vec::new());
    let mut inventory = nodes(&[&root]);
    let budget: usize = inventory.values().map(|bytes| 32 + bytes.len()).sum();
    let bytes = compile_nodes(root.root_identity(), &inventory, MINIMUM, 1, 65536, budget).unwrap();
    assert_eq!(Index::open(&bytes).unwrap().len(), 1);
    assert_eq!(
        compile_nodes(
            root.root_identity(),
            &inventory,
            MINIMUM,
            1,
            65536,
            budget - 1
        ),
        Err(Error::Limit)
    );
    assert_eq!(
        compile_nodes(root.root_identity(), &inventory, 0, 1, 65536, budget),
        Err(Error::Limit)
    );
    assert_eq!(
        compile_nodes(root.root_identity(), &inventory, MINIMUM, 0, 65536, budget),
        Err(Error::Limit)
    );

    inventory.insert([0; 32], Vec::new());
    assert_eq!(
        compile_nodes(root.root_identity(), &inventory, MINIMUM, 1, 65536, budget),
        Err(Error::Limit)
    );
    assert!(
        compile_nodes(
            root.root_identity(),
            &inventory,
            MINIMUM,
            1,
            65536,
            budget + 32
        )
        .is_ok(),
        "unreachable bytes grant no trust but consume inventory budget"
    );
}
