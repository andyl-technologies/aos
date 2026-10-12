//! Counts changed leaf ancestors independently of the merge cursor algorithm.

use alloc::vec;
use alloc::vec::Vec;

use super::{EntryKind, Map, assert_map, build, entry, model};
use crate::algebra::tests::{Forest, untrusted};
use crate::algebra::{MergePolicy, merge};
use crate::tree_builder::{StoredNode, Tree};

fn path<'t>(tree: &'t Tree<'static>, key: &[u8]) -> Vec<&'t StoredNode<'static>> {
    let mut result = vec![tree.root()];
    let mut node = tree.root();
    while node.level() > 0 {
        node = node
            .children()
            .iter()
            .find(|child| child.first_key().unwrap() <= key && key <= child.last_key().unwrap())
            .unwrap();
        result.push(node);
    }
    result
}

/// Requires unequal roots to expand exactly the three changed ancestor paths.
///
/// # Panics
/// Panics if the canonical fixture layout, modeled merge, or exact work differs.
pub(in crate::algebra::tests) fn equal_internal_subtree_witness() {
    static BASE: [u8; 512] = [b'b'; 512];
    static OURS: [u8; 512] = [b'o'; 512];
    static THEIRS: [u8; 512] = [b't'; 512];
    let base: Map<'static> = (0..24000)
        .map(|number| {
            (
                alloc::format!("{number:08}").into_bytes(),
                entry(EntryKind::Symlink { target: &BASE }),
            )
        })
        .collect();
    let mut ours = base.clone();
    let mut theirs = base.clone();
    let key = b"00000000";
    ours.insert(key.to_vec(), entry(EntryKind::Symlink { target: &OURS }));
    theirs.insert(key.to_vec(), entry(EntryKind::Symlink { target: &THEIRS }));
    let trees = [build(&base), build(&ours), build(&theirs)];
    let paths = trees.each_ref().map(|tree| path(tree, key));

    // Equal-length edits precede MIN_NODE at every first item. No cut moves.
    let layout = |tree: &Tree<'static>| {
        tree.nodes()
            .map(|node| {
                (
                    node.level(),
                    node.first_key().unwrap().to_vec(),
                    node.last_key().unwrap().to_vec(),
                    node.count(),
                    node.encoded().len(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(layout(&trees[0]), layout(&trees[1]));
    assert_eq!(layout(&trees[0]), layout(&trees[2]));
    assert!(trees[0].root().level() >= 2);
    assert_eq!(paths[0].len(), paths[1].len());
    assert_eq!(paths[0].len(), paths[2].len());
    for ((base, ours), theirs) in paths[0].iter().zip(&paths[1]).zip(&paths[2]) {
        assert_ne!(base.identity(), ours.identity());
        assert_ne!(base.identity(), theirs.identity());
        assert_ne!(ours.identity(), theirs.identity());
    }

    let sibling = trees[0].root().children().get(1).unwrap();
    assert!(sibling.level() >= 1);
    assert!(sibling.children().len() > 1);
    for tree in &trees[1..] {
        let common = tree.root().children().get(1).unwrap();
        assert_eq!(common.identity(), sibling.identity());
        assert_eq!(common.first_key(), sibling.first_key());
        assert_eq!(common.last_key(), sibling.last_key());
    }

    let expected = model::merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::PreferOurs],
        model::Evidence {
            baseline: [false; 2],
            timestamps: [0; 2],
        },
    )
    .unwrap();
    let actual = merge(
        &trees[0],
        &trees[1],
        &trees[2],
        &[MergePolicy::PreferOurs],
        &untrusted(),
        &Forest(vec![]),
    )
    .unwrap();
    assert_map(&actual.tree, &expected);
    assert_eq!(
        actual.expanded_nodes,
        paths.iter().map(Vec::len).sum::<usize>()
    );
    let retained = actual
        .tree
        .nodes()
        .find(|node| node.identity() == sibling.identity())
        .unwrap();
    assert!(core::ptr::eq(
        retained,
        trees[1].root().children()[1].as_ref()
    ));
}
