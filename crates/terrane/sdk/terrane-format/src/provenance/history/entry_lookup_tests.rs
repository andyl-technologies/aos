//! Checks immutable leaf lookup equivalence and independent evidence validation.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::tree_builder::Tree;
use crate::tree_format::{Attribute, ExtendedAttribute, LeafItem, TreeUse};

const MINIMUM: u64 = 256;

fn entry(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: vec![Attribute {
            name: "example",
            value: &[1],
        }],
        attrs_present: true,
        xattrs: vec![ExtendedAttribute {
            name: b"user.example",
            value: b"value",
        }],
        xattrs_present: true,
        provenance: Some([7; 32]),
    }
}

fn evidence(tree: &Tree<'_>) -> Vec<(Digest, Vec<u8>)> {
    tree.nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect()
}

#[test]
fn canonical_lookup_preserves_values_in_each_tree_context() {
    for (kind, usage) in [
        (EntryKind::Symlink { target: b"target" }, TreeUse::Ordinary),
        (
            EntryKind::Index {
                targets: vec![[3; 32], [4; 32]],
            },
            TreeUse::Index,
        ),
        (EntryKind::Whiteout, TreeUse::OverlayLayer),
    ] {
        let mut expected = entry(kind);
        if matches!(expected.kind, EntryKind::Whiteout) {
            expected.attrs.clear();
            expected.attrs_present = false;
            expected.xattrs.clear();
            expected.xattrs_present = false;
        }
        let tree = Tree::build(
            vec![LeafItem {
                key: b"key".to_vec(),
                entry: expected.clone(),
            }],
            None,
            MINIMUM,
            usage,
        )
        .unwrap();
        let mut history = VerifiedHistory::new(MINIMUM);
        history
            .insert_tree_for(tree.root_identity(), &evidence(&tree), usage)
            .unwrap();

        assert_eq!(
            history.root_entry(tree.root_identity(), b"key").unwrap(),
            expected
        );
        assert!(
            history
                .root_entry(tree.root_identity(), b"missing")
                .is_err()
        );
        assert!(
            history
                .entry(&EntryLocation {
                    commit: [9; 32],
                    root: tree.root_identity(),
                    path: b"key".to_vec()
                })
                .is_err()
        );

        let before = history.leaf_entries.clone();
        history
            .insert_tree_for(tree.root_identity(), &evidence(&tree), usage)
            .unwrap();
        assert_eq!(history.leaf_entries, before);
        assert!(
            history
                .insert_tree_for(tree.root_identity(), &[], TreeUse::Surface)
                .is_err()
        );
        assert_eq!(history.leaf_entries, before);
    }
}

#[test]
fn shared_leaf_maps_do_not_bypass_new_root_validation() {
    // Encoded provenance exceeds the 64 KiB leaf cap, so this fixture requires
    // multiple leaves independently of probabilistic content boundaries.
    let items: Vec<_> = (0..2048)
        .map(|index| LeafItem {
            key: alloc::format!("key-{index:04}").into_bytes(),
            entry: entry(EntryKind::Symlink { target: b"target" }),
        })
        .collect();
    let first = Tree::build(items.clone(), None, MINIMUM, TreeUse::Ordinary).unwrap();
    let second = Tree::build(items, Some(vec![]), MINIMUM, TreeUse::Ordinary).unwrap();
    assert_ne!(first.root_identity(), second.root_identity());
    assert!(first.root().level() > 0);
    let mut history = VerifiedHistory::new(MINIMUM);
    history
        .insert_tree(first.root_identity(), &evidence(&first))
        .unwrap();
    let maps = history.leaf_entries.clone();
    history
        .insert_tree(second.root_identity(), &evidence(&second))
        .unwrap();
    assert_eq!(history.leaf_entries, maps);
    assert_eq!(
        history.root_entry(first.root_identity(), b"key-0064"),
        history.root_entry(second.root_identity(), b"key-0064")
    );

    let before_nodes = history.nodes.clone();
    let before_roots = history.roots.clone();
    let before_usage = history.usage.clone();
    let mut bad_root = second.root().node().clone();
    let NodeItems::Internal(children) = &mut bad_root.items else {
        panic!("internal root required")
    };
    children[0].count += 1;
    let bytes = tree_format::encode_node(&bad_root, true, MINIMUM).unwrap();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();

    assert!(history.insert_tree(identity, &[(identity, bytes)]).is_err());
    assert!(
        history
            .insert_tree_for(identity, &[], TreeUse::Index)
            .is_err()
    );
    assert_eq!(history.nodes, before_nodes);
    assert_eq!(history.roots, before_roots);
    assert_eq!(history.usage, before_usage);
    assert_eq!(history.leaf_entries, maps);
    assert!(history.root_entry(identity, b"key-0064").is_err());
}

#[test]
fn empty_optional_maps_retain_their_presence_bits() {
    for present in [false, true] {
        let mut expected = entry(EntryKind::Symlink { target: b"target" });
        expected.attrs.clear();
        expected.xattrs.clear();
        expected.attrs_present = present;
        expected.xattrs_present = present;
        let tree = Tree::build(
            vec![LeafItem {
                key: b"key".to_vec(),
                entry: expected.clone(),
            }],
            None,
            MINIMUM,
            TreeUse::Ordinary,
        )
        .unwrap();
        let mut history = VerifiedHistory::new(MINIMUM);
        history
            .insert_tree(tree.root_identity(), &evidence(&tree))
            .unwrap();

        assert_eq!(
            history.root_entry(tree.root_identity(), b"key").unwrap(),
            expected
        );
    }
}
