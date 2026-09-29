//! Tests canonical whole-subtree adoption and explicit incompatible outcomes.

#![allow(clippy::unwrap_used)]

use super::{SpliceOutcome, SubtreeReplacement, Tree};
use crate::tree_format::{Entry, EntryKind, LeafItem, TreeUse};
use alloc::{rc::Rc, vec, vec::Vec};

fn item(number: u64, value: u8) -> LeafItem<'static> {
    let mut key = number.to_be_bytes().to_vec();
    let mut suffix = [0; 232];
    blake3::Hasher::new()
        .update(&number.to_le_bytes())
        .finalize_xof()
        .fill(&mut suffix);
    key.extend_from_slice(&suffix);
    LeafItem {
        key,
        entry: Entry {
            kind: EntryKind::Index {
                targets: vec![[value; 32]],
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    }
}

fn matching<'a>(
    tree: &Tree<'a>,
    target: &super::StoredNode<'a>,
) -> Option<Rc<super::StoredNode<'a>>> {
    let mut stack = vec![tree.root_rc()];
    while let Some(node) = stack.pop() {
        if node.level() == target.level()
            && node.first_key() == target.first_key()
            && node.last_key() == target.last_key()
        {
            return Some(node);
        }
        stack.extend(node.children().iter().cloned());
    }
    None
}

#[test]
fn tree_history_independence_splice_adopts_internal_target_whole() {
    let entries: Vec<_> = (0..30000)
        .map(|number| item(number, (number % 251) as u8))
        .collect();
    let original = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
    assert!(original.root().level() >= 2);
    let mut changed = entries.clone();
    let midpoint = original.root().children()[original.root().children().len() / 2].clone();
    let key = midpoint.children()[midpoint.children().len() / 2]
        .first_key()
        .unwrap()
        .to_vec();
    let position = changed.binary_search_by(|item| item.key.cmp(&key)).unwrap() + 1;
    changed[position].entry.kind = EntryKind::Index {
        targets: vec![[255; 32]],
    };
    let target_tree = Tree::build(changed, None, 262144, TreeUse::Index).unwrap();
    let target = matching(&target_tree, &midpoint).unwrap();
    let outcome = original
        .splice_subtrees(&[SubtreeReplacement {
            old_identity: midpoint.identity(),
            target: Rc::clone(&target),
        }])
        .unwrap();
    let SpliceOutcome::Applied(result) = outcome else {
        panic!("matching interior subtree should adopt whole");
    };
    assert_eq!(result.tree.root_identity(), target_tree.root_identity());
    let adopted = matching(&result.tree, &target).unwrap();
    assert!(Rc::ptr_eq(&adopted, &target));
    assert!(
        !result
            .emitted
            .iter()
            .any(|node| node.identity() == target.identity())
    );
    assert!(result.work.node_encodings < 30);
    assert!(result.work.validation_reads < 300);
}

#[test]
fn tree_history_independence_splice_batch_reuses_disjoint_targets() {
    let entries: Vec<_> = (0..30000)
        .map(|number| item(number, (number % 251) as u8))
        .collect();
    let original = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
    let mut changed = entries;
    let left = original.root().children()[1].clone();
    let right = original.root().children()[original.root().children().len() - 2].clone();
    for node in [&left, &right] {
        let key = node.children()[node.children().len() / 2]
            .first_key()
            .unwrap();
        let index = changed
            .binary_search_by(|item| item.key.as_slice().cmp(key))
            .unwrap()
            + 1;
        changed[index].entry.kind = EntryKind::Index {
            targets: vec![[255; 32]],
        };
    }
    let source = Tree::build(changed, None, 262144, TreeUse::Index).unwrap();
    let left_target = matching(&source, &left).unwrap();
    let right_target = matching(&source, &right).unwrap();
    let patches = [
        SubtreeReplacement {
            old_identity: left.identity(),
            target: Rc::clone(&left_target),
        },
        SubtreeReplacement {
            old_identity: right.identity(),
            target: Rc::clone(&right_target),
        },
    ];
    let SpliceOutcome::Applied(result) = original.splice_subtrees(&patches).unwrap() else {
        panic!("disjoint interior subtrees should adopt whole");
    };
    assert_eq!(result.tree.root_identity(), source.root_identity());
    assert!(Rc::ptr_eq(
        &matching(&result.tree, &left_target).unwrap(),
        &left_target
    ));
    assert!(Rc::ptr_eq(
        &matching(&result.tree, &right_target).unwrap(),
        &right_target
    ));
    assert!(
        !result
            .emitted
            .iter()
            .any(|node| node.identity() == left_target.identity()
                || node.identity() == right_target.identity())
    );
}

#[test]
fn tree_history_independence_splice_rejects_wrong_identity_and_overlap() {
    let entries: Vec<_> = (0..4000)
        .map(|number| item(number, (number % 251) as u8))
        .collect();
    let original = Tree::build(entries, None, 262144, TreeUse::Index).unwrap();
    let target = original.root().children()[0].clone();
    assert!(
        original
            .splice_subtrees(&[SubtreeReplacement {
                old_identity: [0; 32],
                target: Rc::clone(&target)
            }])
            .is_err()
    );
    let patch = SubtreeReplacement {
        old_identity: target.identity(),
        target,
    };
    assert!(original.splice_subtrees(&[patch.clone(), patch]).is_err());
}

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
fn tree_history_independence_splice_reports_incompatible_overflow_edges() {
    use crate::tree_format::ExtendedAttribute;
    let mut value = vec![7; 65500];
    loop {
        let mut large = directory(b"b");
        large.entry.xattrs_present = true;
        large.entry.xattrs = vec![ExtendedAttribute {
            name: b"user.blob",
            value: &value,
        }];
        let length = super::chunk::leaf_bytes(&large, &[], 262144).unwrap().len();
        if length == 65536 {
            break;
        }
        value.resize((value.len() as isize + 65536 - length as isize) as usize, 7);
    }
    for adjacent in [b"a".as_slice(), b"c".as_slice()] {
        let mut large = directory(b"b");
        large.entry.xattrs_present = true;
        large.entry.xattrs = vec![ExtendedAttribute {
            name: b"user.blob",
            value: &value,
        }];
        let mut entries = vec![large, directory(adjacent)];
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let original = Tree::build(entries, None, 262144, TreeUse::Ordinary).unwrap();
        let old = original
            .root()
            .children()
            .iter()
            .find(|node| node.first_key() == Some(b"b".as_slice()))
            .unwrap();
        let target = Tree::build(vec![directory(b"b")], None, 262144, TreeUse::Ordinary)
            .unwrap()
            .root_rc();
        let SpliceOutcome::RechunkRequired(work) = original
            .splice_subtrees(&[SubtreeReplacement {
                old_identity: old.identity(),
                target,
            }])
            .unwrap()
        else {
            panic!("smaller item invalidates the surrounding overflow cut");
        };
        assert!(work.item_encodings > 0);
        assert!(work.validation_reads > 0);
        assert_eq!(work.node_encodings, 0);
        assert_eq!(original.len(), 2);
    }
}

fn linked(key: &[u8], mode: u16) -> LeafItem<'static> {
    let mut item = directory(key);
    item.entry.kind = EntryKind::File {
        mode,
        size: 15,
        content: crate::tree_format::ContentRef::Inline([7; 32]),
        link_id: Some(b"a"),
    };
    item
}

#[test]
fn tree_history_independence_splice_updates_complete_link_sets_atomically() {
    let original = Tree::build(
        vec![linked(b"a", 0o644), linked(b"b", 0o644)],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let target = Tree::build(
        vec![linked(b"a", 0o600), linked(b"b", 0o600)],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap()
    .root_rc();
    let SpliceOutcome::Applied(result) = original
        .splice_subtrees(&[SubtreeReplacement {
            old_identity: original.root_identity(),
            target: Rc::clone(&target),
        }])
        .unwrap()
    else {
        panic!("a whole root has no external boundary cuts");
    };
    assert!(Rc::ptr_eq(&result.tree.root_rc(), &target));
    assert!(result.emitted.is_empty());
    assert_eq!(result.work.node_encodings, 0);
    assert!(result.tree.remove(b"a").is_err());
    assert!(
        result
            .tree
            .remove(b"b")
            .unwrap()
            .tree
            .remove(b"a")
            .unwrap()
            .tree
            .is_empty()
    );
}

#[test]
fn tree_history_independence_splice_rejects_partial_link_set_changes() {
    let mut entries = vec![linked(b"a", 0o644)];
    entries.extend((0..6000).map(|number| directory(alloc::format!("m-{number:08}").as_bytes())));
    entries.push(linked(b"z", 0o644));
    let original = Tree::build(entries.clone(), None, 262144, TreeUse::Ordinary).unwrap();
    entries[0] = linked(b"a", 0o600);
    let last = entries.len() - 1;
    entries[last] = linked(b"z", 0o600);
    let source = Tree::build(entries, None, 262144, TreeUse::Ordinary).unwrap();
    let old = original.root().children()[0].clone();
    let target = matching(&source, &old).unwrap();
    assert!(
        original
            .splice_subtrees(&[SubtreeReplacement {
                old_identity: old.identity(),
                target
            }])
            .is_err()
    );
    assert!(original.remove(b"a").is_err());
}
