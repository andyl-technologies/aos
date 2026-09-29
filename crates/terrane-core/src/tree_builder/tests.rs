//! Exercises deterministic construction, persistent edits, and exact summaries.

use super::Tree;
use crate::tree_format::{Entry, EntryKind, LeafItem, TreeUse};
use alloc::{vec, vec::Vec};

fn directory(key: &[u8]) -> LeafItem<'static> {
    LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Directory { mode: 0o755 },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    }
}

#[test]
fn tree_boundaries_empty_and_single_leaf() {
    let tree = Tree::build(Vec::new(), None, 262144, TreeUse::Ordinary).unwrap();
    assert_eq!(tree.root().encoded(), [0xa2, 1, 0, 2, 0x80]);
    assert_eq!(tree.len(), 0);
    let tree = Tree::build(vec![directory(b"a")], None, 262144, TreeUse::Ordinary).unwrap();
    assert_eq!(tree.root().level(), 0);
    assert_eq!(tree.len(), 1);
    assert_eq!(tree.iter().count(), 1);
}

#[test]
fn tree_history_independence_insert_remove() {
    let entries: Vec<_> = (0..2000)
        .map(|index| directory(alloc::format!("key-{index:08}").as_bytes()))
        .collect();
    let tree = Tree::build(entries.clone(), None, 262144, TreeUse::Ordinary).unwrap();
    let mut edited = tree.clone();
    for index in (0..2000).step_by(199) {
        let key = alloc::format!("key-{index:08}");
        edited = edited.remove(key.as_bytes()).unwrap().tree;
    }
    for index in (0..2000).step_by(199).rev() {
        let key = alloc::format!("key-{index:08}");
        edited = edited.insert(directory(key.as_bytes())).unwrap().tree;
    }
    assert_eq!(edited.root_identity(), tree.root_identity());
    assert_eq!(edited.iter().cloned().collect::<Vec<_>>(), entries);
}
