//! Exercises deterministic construction, persistent edits, and exact summaries.

#![allow(clippy::unwrap_used)]

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

fn index(key: Vec<u8>, value: u8) -> LeafItem<'static> {
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

fn fixture(count: usize, style: u8) -> Vec<LeafItem<'static>> {
    let mut entries = Vec::new();
    for number in 0..count {
        let number = number as u64;
        let mut key = number.to_be_bytes().to_vec();
        match style {
            0 => key.extend_from_slice(alloc::format!("-{number:08}").as_bytes()),
            1 => {
                key = vec![b'p'; 220];
                key.extend_from_slice(&number.to_be_bytes());
            }
            _ => {
                let mut suffix = [0; 232];
                blake3::Hasher::new()
                    .update(&number.to_le_bytes())
                    .finalize_xof()
                    .fill(&mut suffix);
                key.extend_from_slice(&suffix);
            }
        }
        entries.push(index(key, (number % 251) as u8));
    }
    entries
}

fn item_bytes(item: &LeafItem<'_>, previous: &[u8]) -> Vec<u8> {
    let shared = previous
        .iter()
        .zip(&item.key)
        .take_while(|(a, b)| a == b)
        .count();
    let mut output = Vec::new();
    crate::cbor::write_array(&mut output, 3);
    crate::cbor::write_bytes(&mut output, &item.key[shared..]);
    crate::cbor::write_uint(&mut output, shared as u64);
    output.extend_from_slice(&crate::tree_format::encode_entry(&item.entry, 262144).unwrap());
    output
}

fn child_bytes(child: &crate::tree_format::ChildRef) -> Vec<u8> {
    let mut output = Vec::new();
    crate::cbor::write_array(&mut output, 4);
    crate::cbor::write_bytes(&mut output, &child.last_key);
    crate::cbor::write_bytes(&mut output, &child.child);
    crate::cbor::write_uint(&mut output, child.count);
    crate::cbor::write_uint(&mut output, child.weight);
    output
}

// The oracle expands the specification arithmetic independently of boundary.rs.
fn oracle_cut(size: usize, length: usize, canonical: &[u8]) -> bool {
    if size == 65536 {
        return true;
    }
    if size < 4096 {
        return false;
    }
    let base = if size >= 32768 {
        1 << 24
    } else {
        (1_u64 << 20) + (size as u64 - 4096) * ((1 << 24) - (1 << 20)) / 28672
    };
    let threshold = (base * length as u64 / 8).min(1 << 32);
    let hash = blake3::hash(canonical);
    let bytes = hash.as_bytes();
    let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    u64::from(low) < threshold
}

fn assert_boundaries(tree: &Tree<'_>) {
    use crate::tree_format::NodeItems;
    for level in 0..=tree.root().level() {
        let mut nodes: Vec<_> = tree.nodes().filter(|node| node.level() == level).collect();
        nodes.sort_by(|left, right| left.first_key().cmp(&right.first_key()));
        let expected_ends: Vec<_> = nodes
            .iter()
            .map(|node| node.last_key().unwrap().to_vec())
            .collect();
        let mut observed_ends = Vec::new();
        let mut bytes = 0;
        let mut previous = Vec::new();
        let mut last = Vec::new();

        for node in nodes {
            let encodings: Vec<_> = match node.items() {
                NodeItems::Leaf(items) => items
                    .iter()
                    .map(|item| (item.key.clone(), item_bytes(item, &[]), Some(item)))
                    .collect(),
                NodeItems::Internal(items) => items
                    .iter()
                    .map(|item| (item.last_key.clone(), child_bytes(item), None))
                    .collect(),
            };
            for (key, canonical, leaf) in encodings {
                let mut length =
                    leaf.map_or(canonical.len(), |item| item_bytes(item, &previous).len());
                if bytes + length > 65536 {
                    assert!(bytes != 0);
                    observed_ends.push(last.clone());
                    bytes = 0;
                    previous.clear();
                    length = canonical.len();
                }
                assert!(length <= 65536);
                bytes += length;
                previous = key.clone();
                last = key;
                if oracle_cut(bytes, length, &canonical) {
                    observed_ends.push(last.clone());
                    bytes = 0;
                    previous.clear();
                }
            }
        }
        if bytes != 0 {
            observed_ends.push(last);
        }
        assert_eq!(observed_ends, expected_ends, "level {level}");
    }
}

fn assert_summaries(tree: &Tree<'_>) {
    use crate::tree_format::{NodeItems, verify_child_ref_for};
    for node in tree.nodes() {
        assert!(node.node().props.is_none() || node.identity() == tree.root_identity());
        assert_eq!(
            crate::tree_format::encode_node_for(
                node.node(),
                node.identity() == tree.root_identity(),
                262144,
                tree.usage()
            )
            .unwrap(),
            node.encoded()
        );
        match node.items() {
            NodeItems::Leaf(items) => {
                assert_eq!(node.level(), 0);
                assert_eq!(node.count(), items.len() as u64);
                assert_eq!(node.weight(), node.encoded().len() as u64);
            }
            NodeItems::Internal(items) => {
                assert_eq!(items.len(), node.children().len());
                let mut count = 0;
                let mut weight = node.encoded().len() as u64;
                for (reference, child) in items.iter().zip(node.children()) {
                    verify_child_ref_for(
                        node.level(),
                        reference,
                        child.node(),
                        child.encoded(),
                        262144,
                        tree.usage(),
                    )
                    .unwrap();
                    count += child.count();
                    weight += child.weight();
                }
                assert_eq!(node.count(), count);
                assert_eq!(node.weight(), weight);
            }
        }
    }
}

#[test]
fn tree_boundaries_replay_every_fixture_level_and_summary() {
    for style in 0..3 {
        let entries = fixture(18000, style);
        let tree = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
        assert!(tree.root().level() >= 1);
        if style == 2 {
            assert!(tree.root().level() >= 2);
        }
        assert_boundaries(&tree);
        assert_summaries(&tree);
        assert_eq!(tree.iter().cloned().collect::<Vec<_>>(), entries);
    }
}

#[test]
fn tree_boundaries_golden_leaf_identity() {
    use crate::tree_format::ContentRef;
    let chunk = hex("9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0");
    let mut entry = directory(b"hello.txt");
    entry.entry.kind = EntryKind::File {
        mode: 0o644,
        size: 15,
        content: ContentRef::Inline(chunk.try_into().unwrap()),
        link_id: None,
    };
    let tree = Tree::build(vec![entry], None, 262144, TreeUse::Ordinary).unwrap();
    assert_eq!(
        tree.root().encoded(),
        hex(concat!(
            "a201000281834968656c6c6f2e74787400a40101021901a4030f048200582094",
            "79e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0"
        ))
    );
    assert_eq!(
        tree.root_identity().as_slice(),
        hex("9366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c20bbc392")
    );
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn tree_history_independence_randomized_multilevel_edits() {
    use alloc::collections::BTreeMap;
    let entries = fixture(15000, 2);
    let keys: Vec<_> = entries.iter().map(|item| item.key.clone()).collect();
    let original = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
    assert!(original.root().level() >= 2);
    let mut tree = original.clone();
    let mut map: BTreeMap<_, _> = entries
        .into_iter()
        .map(|item| (item.key.clone(), item))
        .collect();
    let mut seed = 0x0918_abcd_3344_u64;

    for step in 0..80 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let number = (seed % 15000) as usize;
        let mut key = keys[number].clone();
        if step % 4 == 1 || step % 4 == 3 {
            key.push(0);
        }
        if step % 4 == 0 || step % 4 == 3 {
            tree = tree.remove(&key).unwrap().tree;
            map.remove(&key);
        } else {
            let item = index(key.clone(), (step % 251) as u8);
            tree = tree.insert(item.clone()).unwrap().tree;
            map.insert(key, item);
        }
        if step % 10 == 0 {
            let rebuilt = Tree::build(
                map.values().cloned().collect(),
                None,
                262144,
                TreeUse::Index,
            )
            .unwrap();
            assert_eq!(tree.root_identity(), rebuilt.root_identity(), "edit {step}");
            assert_summaries(&tree);
        }
    }
    assert_eq!(original.len(), 15000);
    assert_boundaries(&tree);
}

#[test]
fn tree_history_independence_build_orders_and_root_growth_collapse() {
    let entries = fixture(500, 0);
    let built = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
    for order in [
        entries.clone(),
        entries.iter().rev().cloned().collect::<Vec<_>>(),
    ] {
        let mut tree = Tree::build(Vec::new(), None, 262144, TreeUse::Index).unwrap();
        for item in &order {
            tree = tree.insert(item.clone()).unwrap().tree;
        }
        assert_eq!(tree.root_identity(), built.root_identity());
        assert!(tree.root().level() >= 1);
        for item in &order {
            tree = tree.remove(&item.key).unwrap().tree;
        }
        assert!(tree.is_empty());
        assert_eq!(tree.root().level(), 0);
        assert_eq!(tree.root().encoded(), [0xa2, 1, 0, 2, 0x80]);
    }
}

#[test]
fn tree_history_independence_local_edits_share_unaffected_nodes() {
    use alloc::{collections::BTreeSet, rc::Rc};
    let entries = fixture(30000, 2);
    let original = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
    let old_nodes: BTreeSet<_> = original.nodes().map(|node| node.identity()).collect();
    let mut item = entries[entries.len() / 2].clone();
    item.entry.kind = EntryKind::Index {
        targets: vec![[255; 32]],
    };
    let mutation = original.insert(item).unwrap();
    assert!(mutation.work.node_reads < 100);
    assert!(mutation.work.item_encodings < 5000);
    assert!(mutation.work.node_encodings < 100);
    let shared = mutation
        .tree
        .nodes()
        .filter(|node| old_nodes.contains(&node.identity()))
        .count();
    assert!(shared > old_nodes.len() * 9 / 10);
    let old_first = original.root().children().first().unwrap();
    let new_first = mutation.tree.root().children().first().unwrap();
    assert!(Rc::ptr_eq(old_first, new_first));
    assert_summaries(&mutation.tree);
    for node in &mutation.emitted {
        assert_eq!(
            node.identity(),
            crate::identity::TERRANE_V1
                .calculate(crate::identity::IdentityKind::Node, node.encoded())
                .unwrap()
                .terrane_v1_digest()
                .unwrap()
        );
    }
}

#[test]
fn tree_boundaries_cursor_seeks_and_crosses_nodes() {
    let entries = fixture(4000, 2);
    let tree = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
    for position in [0, 1, 99, 1999, 3999] {
        let key = &entries[position].key;
        assert_eq!(tree.get(key), Some(&entries[position].entry));
        assert_eq!(
            tree.cursor_from(key).cloned().collect::<Vec<_>>(),
            entries[position..]
        );
        let mut between = key.clone();
        between.push(0);
        assert_eq!(
            tree.cursor_from(&between).next().map(|item| &item.key),
            entries.get(position + 1).map(|item| &item.key)
        );
    }
    assert!(tree.cursor_from(&vec![255; 4096]).next().is_none());
    assert!(tree.get(&vec![255; 4096]).is_none());
}

#[test]
fn tree_history_independence_properties_survive_edits() {
    use crate::tree_format::Property;
    use alloc::rc::Rc;
    let entries = fixture(4000, 2);
    let tree = Tree::build(
        entries.clone(),
        Some(vec![Property {
            name: "p",
            value: &[0x01],
        }]),
        262144,
        TreeUse::Index,
    )
    .unwrap();
    let absent = tree.with_properties(None).unwrap();
    let empty = tree.with_properties(Some(Vec::new())).unwrap();
    assert_ne!(tree.root_identity(), absent.tree.root_identity());
    assert_ne!(empty.tree.root_identity(), absent.tree.root_identity());
    assert_eq!(absent.work.node_encodings, 1);
    assert!(Rc::ptr_eq(
        &tree.root().children()[0],
        &absent.tree.root().children()[0]
    ));
    let mutation = tree.remove(&entries[0].key).unwrap();
    let rebuilt = Tree::build(
        entries[1..].to_vec(),
        tree.props().map(<[_]>::to_vec),
        262144,
        TreeUse::Index,
    )
    .unwrap();
    assert_eq!(mutation.tree.root_identity(), rebuilt.root_identity());
    assert_summaries(&mutation.tree);
}

#[test]
fn tree_boundaries_exact_cap_resets_compression_and_rejects_oversize() {
    use crate::tree_format::ExtendedAttribute;
    let mut value = vec![7; 65500];
    loop {
        let mut item = directory(b"prefix-b");
        item.entry.xattrs_present = true;
        item.entry.xattrs = vec![ExtendedAttribute {
            name: b"user.blob",
            value: &value,
        }];
        let length = item_bytes(&item, &[]).len();
        if length == 65536 {
            break;
        }
        value.resize((value.len() as isize + 65536 - length as isize) as usize, 7);
    }
    let mut large = directory(b"prefix-b");
    large.entry.xattrs_present = true;
    large.entry.xattrs = vec![ExtendedAttribute {
        name: b"user.blob",
        value: &value,
    }];
    let tree = Tree::build(
        vec![directory(b"prefix-a"), large],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert_eq!(tree.root().level(), 1);
    assert_eq!(tree.root().children().len(), 2);
    assert_eq!(tree.root().children()[1].encoded().len(), 65541);
    assert_boundaries(&tree);
    assert_summaries(&tree);

    let smaller = tree.insert(directory(b"prefix-b")).unwrap().tree;
    let rebuilt = Tree::build(
        vec![directory(b"prefix-a"), directory(b"prefix-b")],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert_eq!(smaller.root_identity(), rebuilt.root_identity());
    assert_eq!(smaller.root().level(), 0);
    let deleted = tree.remove(b"prefix-b").unwrap().tree;
    let rebuilt = Tree::build(
        vec![directory(b"prefix-a")],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert_eq!(deleted.root_identity(), rebuilt.root_identity());

    let oversized = vec![7; value.len() + 1];
    let mut large = directory(b"prefix-b");
    large.entry.xattrs_present = true;
    large.entry.xattrs = vec![ExtendedAttribute {
        name: b"user.blob",
        value: &oversized,
    }];
    assert!(Tree::build(vec![large], None, 262144, TreeUse::Ordinary).is_err());
}

#[test]
fn tree_history_independence_point_edits_preserve_path_invariants() {
    let tree = Tree::build(
        vec![directory(b"a"), directory(b"a!"), directory(b"a/b")],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert!(tree.remove(b"a").is_err());
    let mut file = directory(b"a");
    file.entry.kind = EntryKind::Symlink { target: b"raw" };
    assert!(tree.insert(file).is_err());
    assert!(tree.insert(directory(b"missing/child")).is_err());
    let removed = tree.remove(b"a/b").unwrap().tree.remove(b"a").unwrap().tree;
    assert_eq!(
        removed
            .iter()
            .map(|item| item.key.as_slice())
            .collect::<Vec<_>>(),
        [b"a!".as_slice()]
    );
    let duplicate = vec![directory(b"a"), directory(b"a")];
    assert!(Tree::build(duplicate, None, 262144, TreeUse::Ordinary).is_err());
    assert!(
        Tree::build(
            vec![directory(b"b"), directory(b"a")],
            None,
            262144,
            TreeUse::Ordinary
        )
        .is_err()
    );
}

fn linked<'a>(key: &[u8], id: &'a [u8]) -> LeafItem<'a> {
    let mut item = directory(key);
    item.entry.kind = EntryKind::File {
        mode: 0o644,
        size: 15,
        content: crate::tree_format::ContentRef::Inline([7; 32]),
        link_id: Some(id),
    };
    item
}

#[test]
fn tree_history_independence_hardlinks_are_incremental_and_exact() {
    let ids: Vec<_> = (0..2000)
        .map(|number| alloc::format!("a-{number:08}").into_bytes())
        .collect();
    let mut entries: Vec<_> = ids.iter().map(|id| linked(id, id)).collect();
    entries.extend(
        ids.iter()
            .enumerate()
            .map(|(number, id)| linked(alloc::format!("b-{number:08}").as_bytes(), id)),
    );
    let tree = Tree::build(entries, None, 262144, TreeUse::Ordinary).unwrap();
    assert!(tree.remove(&ids[1000]).is_err());
    let mut different = linked(&ids[1000], &ids[1000]);
    if let EntryKind::File { mode, .. } = &mut different.entry.kind {
        *mode = 0o600;
    }
    assert!(tree.insert(different).is_err());
    assert!(tree.insert(linked(b"0-earlier", &ids[1000])).is_err());
    assert!(tree.insert(linked(b"z-new", b"missing-id")).is_err());

    let removed = tree.remove(b"b-00001000").unwrap();
    assert!(removed.work.validation_reads < 100);
    let removed = removed.tree.remove(&ids[1000]).unwrap();
    assert!(removed.work.validation_reads < 100);
    let restored = removed
        .tree
        .insert(linked(&ids[1000], &ids[1000]))
        .unwrap()
        .tree
        .insert(linked(b"b-00001000", &ids[1000]))
        .unwrap()
        .tree;
    assert_eq!(restored.root_identity(), tree.root_identity());
}

#[test]
fn tree_history_independence_conflict_summary_and_context_widening() {
    use alloc::rc::Rc;
    let tree = Tree::build(vec![directory(b"a")], None, 262144, TreeUse::Surface).unwrap();
    let ordinary = tree.with_usage(TreeUse::Ordinary).unwrap();
    assert!(Rc::ptr_eq(&tree.root_rc(), &ordinary.root_rc()));
    let mut conflict = directory(b"a");
    conflict.entry.kind = EntryKind::Conflict {
        candidates: vec![directory(b"a").entry, directory(b"b").entry],
        base: None,
    };
    assert!(tree.insert(conflict.clone()).is_err());
    let conflicted = ordinary.insert(conflict).unwrap().tree;
    assert!(conflicted.has_conflicts());
    assert!(conflicted.with_usage(TreeUse::Surface).is_err());
    assert!(!conflicted.remove(b"a").unwrap().tree.has_conflicts());
}

#[test]
fn tree_history_independence_multilevel_root_collapse() {
    let entries = fixture(6000, 2);
    let mut tree = Tree::build(entries.clone(), None, 262144, TreeUse::Index).unwrap();
    assert!(tree.root().level() >= 2);
    for (position, item) in entries.iter().enumerate() {
        tree = tree.remove(&item.key).unwrap().tree;
        if position % 1000 == 0 {
            let rebuilt = Tree::build(
                entries[position + 1..].to_vec(),
                None,
                262144,
                TreeUse::Index,
            )
            .unwrap();
            assert_eq!(tree.root_identity(), rebuilt.root_identity());
        }
    }
    assert!(tree.is_empty());
    assert_eq!(tree.root().level(), 0);
    assert_eq!(tree.root().encoded(), [0xa2, 1, 0, 2, 0x80]);
}

#[test]
fn tree_history_independence_noop_preserves_root_and_emits_nothing() {
    use alloc::rc::Rc;
    let tree = Tree::build(vec![directory(b"a")], None, 262144, TreeUse::Ordinary).unwrap();
    let same = tree.insert(directory(b"a")).unwrap();
    assert!(same.emitted.is_empty());
    assert_eq!(same.work.node_encodings, 0);
    assert!(same.work.validation_reads > 0);
    assert!(Rc::ptr_eq(&tree.root_rc(), &same.tree.root_rc()));
    let absent = tree.remove(b"missing").unwrap();
    assert!(absent.emitted.is_empty());
    assert_eq!(absent.work.node_encodings, 0);
    assert!(absent.work.validation_reads > 0);
    assert!(Rc::ptr_eq(&tree.root_rc(), &absent.tree.root_rc()));
}

#[test]
fn tree_history_independence_conditional_directory_ancestors() {
    let mut parent = directory(b"a");
    parent.entry.kind = EntryKind::Conflict {
        candidates: vec![directory(b"a").entry, linked(b"a", b"a").entry],
        base: None,
    };
    let tree = Tree::build(
        vec![parent.clone(), directory(b"a/b")],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert!(tree.insert(directory(b"a/c")).is_ok());
    assert!(tree.remove(b"a").is_err());
    assert!(tree.insert(linked(b"a", b"a")).is_err());
    let ordinary = Tree::build(
        vec![directory(b"a"), directory(b"a/b")],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert_eq!(
        ordinary.insert(parent).unwrap().tree.root_identity(),
        tree.root_identity()
    );
}
