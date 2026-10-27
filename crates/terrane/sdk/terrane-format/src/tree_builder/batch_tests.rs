//! Checks sparse batch shape, immutable reuse, atomicity, and physical work.

use alloc::{collections::BTreeMap, format, vec, vec::Vec};

use super::{Error, Tree};
use crate::tree_format::{Entry, EntryKind, LeafItem, TreeUse};

/// Constructs a plain directory entry with the supplied key and mode.
pub(super) fn directory(key: Vec<u8>, mode: u16) -> LeafItem<'static> {
    LeafItem {
        key,
        entry: Entry {
            kind: EntryKind::Directory { mode },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    }
}

/// Constructs a strictly ordered directory fixture with long common keys.
pub(super) fn fixture(count: usize) -> Vec<LeafItem<'static>> {
    (0..count)
        .map(|number| {
            directory(
                format!("item-{number:08}-{}", "x".repeat(180)).into_bytes(),
                0o755,
            )
        })
        .collect()
}

/// Rebuilds the complete final map independently of incremental editing.
///
/// # Errors
/// Rejects invalid final entries, ancestors, hard links, properties, or limits.
pub(super) fn oracle(
    tree: &Tree<'static>,
    edits: &[(Vec<u8>, Option<Entry<'static>>)],
) -> Result<Tree<'static>, Error> {
    let mut map: BTreeMap<_, _> = tree
        .iter()
        .map(|item| (item.key.clone(), item.entry.clone()))
        .collect();
    for (key, value) in edits {
        if let Some(value) = value {
            map.insert(key.clone(), value.clone());
        } else {
            map.remove(key);
        }
    }
    Tree::build(
        map.into_iter()
            .map(|(key, entry)| LeafItem { key, entry })
            .collect(),
        tree.props().map(<[_]>::to_vec),
        tree.min_chunk_size(),
        tree.usage(),
    )
}

/// Compares complete canonical node encodings and the root identity.
///
/// # Panics
/// Panics when either canonical representation differs.
pub(super) fn assert_bytes(actual: &Tree<'_>, expected: &Tree<'_>) {
    assert_eq!(actual.root_identity(), expected.root_identity());
    assert_eq!(
        actual
            .nodes()
            .map(|node| node.encoded())
            .collect::<Vec<_>>(),
        expected
            .nodes()
            .map(|node| node.encoded())
            .collect::<Vec<_>>()
    );
}

#[test]
fn tree_history_independence_batches_overlapping_sparse_edits() -> Result<(), Error> {
    let entries = fixture(24000);
    let tree = Tree::build(entries.clone(), None, 262144, TreeUse::Ordinary)?;
    assert!(tree.root().level() >= 2);
    let edits: Vec<_> = entries[11000..11100]
        .iter()
        .map(|item| {
            let replacement = directory(item.key.clone(), 0o700);
            (item.key.clone(), Some(replacement.entry))
        })
        .collect();
    let result = tree.edit_entries(&edits)?;
    assert_partition(&result.work);
    assert_bytes(&result.tree, &oracle(&tree, &edits)?);
    for level in 0..=tree.root().level() {
        let regions: Vec<_> = result
            .work
            .regions
            .iter()
            .filter(|region| region.level == level)
            .collect();
        assert_eq!(regions.len(), 1, "shared suffix at level {level}");
    }
    let mut sequential = tree.clone();
    let mut encoded = 0;
    for (key, value) in &edits {
        let next = sequential.insert(LeafItem {
            key: key.clone(),
            entry: value.clone().ok_or(Error::Node)?,
        })?;
        encoded += next.work.stream.item_bytes_encoded;
        sequential = next.tree;
    }
    assert!(result.work.stream.item_bytes_encoded < encoded);
    assert_bytes(&result.tree, &sequential);
    Ok(())
}

#[test]
fn tree_history_independence_preserves_distant_subtrees_and_atomic_validation() -> Result<(), Error>
{
    let entries = fixture(24000);
    let tree = Tree::build(entries.clone(), Some(Vec::new()), 262144, TreeUse::Ordinary)?;
    let edits = vec![
        (entries[100].key.clone(), None),
        (entries[23000].key.clone(), None),
    ];
    let result = tree.edit_entries(&edits)?;
    assert_partition(&result.work);
    assert_bytes(&result.tree, &oracle(&tree, &edits)?);
    let middle = tree
        .nodes()
        .find(|node| {
            node.level() == 1
                && node
                    .first_key()
                    .is_some_and(|key| key > entries[10000].key.as_slice())
                && node
                    .last_key()
                    .is_some_and(|key| key < entries[14000].key.as_slice())
        })
        .ok_or(Error::Node)?;
    let retained = result
        .tree
        .nodes()
        .find(|node| node.identity() == middle.identity())
        .ok_or(Error::Node)?;
    assert!(core::ptr::eq(retained, middle));
    assert_eq!(result.tree.props(), Some([].as_slice()));
    assert!(
        result
            .work
            .regions
            .iter()
            .filter(|region| region.level == 0)
            .count()
            >= 2
    );

    let small = Tree::build(
        vec![
            directory(b"a".to_vec(), 0o755),
            directory(b"a/b".to_vec(), 0o755),
        ],
        None,
        262144,
        TreeUse::Ordinary,
    )?;
    let root = small.root_rc();
    assert!(small.edit_entries(&[(b"a".to_vec(), None)]).is_err());
    assert!(alloc::rc::Rc::ptr_eq(&root, &small.root_rc()));
    let removed = small.edit_entries(&[(b"a".to_vec(), None), (b"a/b".to_vec(), None)])?;
    assert!(removed.tree.is_empty());
    let no_op =
        tree.edit_entries(&[(entries[100].key.clone(), Some(entries[100].entry.clone()))])?;
    assert!(alloc::rc::Rc::ptr_eq(
        &tree.root_rc(),
        &no_op.tree.root_rc()
    ));
    assert!(no_op.emitted.is_empty());
    Ok(())
}

#[test]
fn tree_history_independence_accounts_for_actual_boundary_work() -> Result<(), Error> {
    // One tiny leaf never enters a hash branch. The two item outputs differ
    // only when a prefix is present; Node identity adds its domain framing.
    let old = directory(b"abcdef".to_vec(), 0o755);
    let tree = Tree::build(vec![old.clone()], None, 262144, TreeUse::Ordinary)?;
    let new = directory(old.key.clone(), 0o700);
    let edits = [(new.key.clone(), Some(new.entry.clone()))];
    let result = tree.edit_entries(&edits)?;
    assert_partition(&result.work);
    assert_bytes(&result.tree, &oracle(&tree, &edits)?);
    assert_eq!(result.work.stream.item_bytes_hashed, 0);
    assert_eq!(result.work.stream.item_bytes_encoded, 32);
    assert_eq!(result.work.stream.comparisons, 3);
    assert_eq!(result.work.stream.frontier_checks, 4);
    assert_eq!(result.work.node_reads, 1);
    assert_eq!(result.work.stream.item_reads, 2);
    assert_eq!(result.work.item_encodings, 2);
    assert_eq!(result.work.node_encodings, 1);
    assert_eq!(
        result.work.stream.node_bytes_encoded,
        result.tree.root().encoded().len()
    );
    assert_eq!(
        result.work.stream.node_bytes_hashed,
        result.tree.root().encoded().len() + b"terrane-node-v1\0".len()
    );
    assert_eq!(result.work.regions.len(), 1);
    assert_eq!(result.work.regions[0].resynchronized, None);
    assert_partition(&result.work);
    assert_eq!(result.work.completion.frontier_checks, 2);
    Ok(())
}

fn item_bytes(item: &LeafItem<'_>, previous: &[u8]) -> Result<Vec<u8>, Error> {
    let shared = previous
        .iter()
        .zip(&item.key)
        .take_while(|(a, b)| a == b)
        .count();
    let mut bytes = Vec::new();
    crate::cbor::write_array(&mut bytes, 3);
    crate::cbor::write_bytes(&mut bytes, &item.key[shared..]);
    crate::cbor::write_uint(&mut bytes, shared as u64);
    bytes.extend(crate::tree_format::encode_entry(&item.entry, 262144)?);
    Ok(bytes)
}

// This oracle uses BLAKE3 directly and expands the specification arithmetic;
// it does not call boundary::decide, boundary::threshold, or the editor.
fn content_cut(size: usize, length: usize, bytes: &[u8]) -> bool {
    if !(4096..65536).contains(&size) {
        return false;
    }
    let base = if size >= 32768 {
        1_u64 << 24
    } else {
        (1_u64 << 20) + (size as u64 - 4096) * ((1 << 24) - (1 << 20)) / 28672
    };
    let digest = blake3::hash(bytes);
    let hash = digest.as_bytes();
    u64::from(u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]))
        < (base * length as u64 / 8).min(1 << 32)
}

#[test]
fn generated_leaf_and_child_content_cut_witnesses_are_real() -> Result<(), Error> {
    use crate::tree_format::NodeItems;
    let tree = Tree::build(fixture(24000), None, 262144, TreeUse::Ordinary)?;
    let mut witness = None;
    let mut child_cut = false;
    for node in tree.nodes() {
        match node.items() {
            NodeItems::Leaf(items) if node.last_key() != tree.root().last_key() => {
                let mut size = 0;
                let mut previous: &[u8] = &[];
                for item in items {
                    let stored = item_bytes(item, previous)?;
                    size += stored.len();
                    let canonical = item_bytes(item, &[])?;
                    if content_cut(size, stored.len(), &canonical) && witness.is_none() {
                        for mode in 0o600..0o777 {
                            let candidate = directory(item.key.clone(), mode);
                            let new_stored = item_bytes(&candidate, previous)?;
                            let new_canonical = item_bytes(&candidate, &[])?;
                            if new_stored.len() == stored.len()
                                && !content_cut(size, stored.len(), &new_canonical)
                            {
                                witness = Some((candidate.key, Some(candidate.entry)));
                                break;
                            }
                        }
                    }
                    previous = &item.key;
                }
            }
            NodeItems::Internal(refs) => {
                let mut size = 0;
                for reference in refs {
                    let mut bytes = Vec::new();
                    crate::cbor::write_array(&mut bytes, 4);
                    crate::cbor::write_bytes(&mut bytes, &reference.last_key);
                    crate::cbor::write_bytes(&mut bytes, &reference.child);
                    crate::cbor::write_uint(&mut bytes, reference.count);
                    crate::cbor::write_uint(&mut bytes, reference.weight);
                    size += bytes.len();
                    child_cut |= content_cut(size, bytes.len(), &bytes);
                }
            }
            _ => {}
        }
    }
    assert!(child_cut, "actual canonical child-reference content cut");
    let edit = witness.ok_or(Error::Node)?;
    let result = tree.edit_entries(core::slice::from_ref(&edit))?;
    assert_bytes(&result.tree, &oracle(&tree, core::slice::from_ref(&edit))?);
    assert!(result.work.stream.item_bytes_hashed > 0);
    Ok(())
}

fn large_item<'a>(key: &[u8], value: &'a [u8]) -> LeafItem<'a> {
    LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Directory { mode: 0o700 },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: vec![crate::tree_format::ExtendedAttribute { name: b"x", value }],
            xattrs_present: true,
            provenance: None,
        },
    }
}

#[test]
fn split_before_and_prefix_reset_have_literal_physical_costs() -> Result<(), Error> {
    let first = directory(b"prefix-a".to_vec(), 0o700);
    let mut payload = vec![b'z'; 65500];
    let initial_length = item_bytes(&large_item(b"prefix-b", &payload), &[])?.len();
    payload.resize(payload.len() + 65536 - initial_length, b'z');
    let large = large_item(b"prefix-b", &payload);
    let full = item_bytes(&large, &[])?;
    let compressed = item_bytes(&large, &first.key)?;
    let first_full = item_bytes(&first, &[])?;
    assert_eq!(full.len(), 65536);
    assert_eq!(compressed.len(), 65529);
    assert_eq!(first_full.len(), 18);
    assert!(first_full.len() + compressed.len() > 65536);

    // Event schedule: tiny item below MIN; large item split before; reset
    // item fits MAX exactly. None of these three decisions hashes an item.
    // The precomputed canonical full-key bytes are reused at reset, so there
    // is no fabricated third encoding of the large item.
    let mut factory = super::Factory::new(262144, TreeUse::Ordinary);
    let nodes = super::chunk::leaves(vec![first.clone(), large.clone()], &mut factory)?;
    assert_eq!(nodes.len(), 2);
    assert_eq!(factory.work.stream.item_reads, 2);
    assert_eq!(factory.work.stream.comparisons, 0);
    assert_eq!(factory.work.stream.frontier_checks, 3);
    assert_eq!(factory.work.item_encodings, 4);
    assert_eq!(
        factory.work.stream.item_bytes_encoded,
        18 * 2 + 65536 + 65529
    );
    assert_eq!(factory.work.stream.item_bytes_hashed, 0);
    assert_eq!(factory.work.node_encodings, 2);
    assert_eq!(factory.work.stream.node_bytes_encoded, 18 + 5 + 65536 + 5);
    assert_eq!(
        factory.work.stream.node_bytes_hashed,
        18 + 5 + 65536 + 5 + 2 * 16
    );
    // A complete sparse edit repeats this exact leaf stream and propagates
    // two real child references once. Their literal CBOR lengths are 46 and
    // 50 bytes: the latter has a five-byte subtree weight of 65541.
    let tree = Tree::build(vec![first, large.clone()], None, 262144, TreeUse::Ordinary)?;
    let replacement = directory(b"prefix-a".to_vec(), 0o755);
    let result =
        tree.edit_entries(&[(replacement.key.clone(), Some(replacement.entry.clone()))])?;
    let rebuilt = Tree::build(vec![replacement, large], None, 262144, TreeUse::Ordinary)?;
    assert_bytes(&result.tree, &rebuilt);
    assert_eq!(result.work.regions.len(), 2);
    assert_eq!(result.work.regions[0].level, 0);
    assert_eq!(result.work.regions[1].level, 1);
    assert!(
        result
            .work
            .regions
            .iter()
            .all(|region| region.resynchronized.is_none())
    );
    assert_eq!(result.work.node_reads, 4);
    assert_eq!(result.work.stream.item_reads, 8);
    assert_eq!(result.work.stream.comparisons, 9);
    assert_eq!(result.work.stream.frontier_checks, 10);
    assert_eq!(result.work.item_encodings, 6);
    assert_eq!(result.work.node_encodings, 3);
    assert_eq!(result.work.stream.item_bytes_encoded, 131197);
    assert_eq!(result.work.stream.item_bytes_hashed, 0);
    assert_eq!(result.work.stream.node_bytes_encoded, 65665);
    assert_eq!(result.work.stream.node_bytes_hashed, 65713);
    assert_eq!(result.work.regions[0].work.item_reads, 4);
    assert_eq!(result.work.regions[0].work.comparisons, 4);
    assert_eq!(result.work.regions[0].work.frontier_checks, 5);
    assert_eq!(result.work.regions[1].work.item_reads, 4);
    assert_eq!(result.work.regions[1].work.comparisons, 5);
    assert_eq!(result.work.regions[1].work.frontier_checks, 3);
    assert_eq!(result.work.completion.frontier_checks, 2);
    assert_partition(&result.work);
    Ok(())
}

#[test]
fn randomized_sparse_batches_match_independent_complete_map() -> Result<(), Error> {
    let mut tree = Tree::build(fixture(4000), None, 262144, TreeUse::Ordinary)?;
    let mut random = 19_u64;
    for round in 0..32 {
        let mut edits = BTreeMap::new();
        for _ in 0..80 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let number = (random >> 32) as usize % 5000;
            let item = directory(
                format!("item-{number:08}-{}", "x".repeat(180)).into_bytes(),
                0o700,
            );
            edits.insert(
                item.key,
                if round % 3 == 0 {
                    None
                } else {
                    Some(item.entry)
                },
            );
        }
        let edits: Vec<_> = edits.into_iter().collect();
        let expected = oracle(&tree, &edits)?;
        let result = tree.edit_entries(&edits)?;
        assert_partition(&result.work);
        assert_bytes(&result.tree, &expected);
        for level in 0..=tree.root().level() {
            let regions: Vec<_> = result
                .work
                .regions
                .iter()
                .filter(|region| region.level == level)
                .collect();
            for pair in regions.windows(2) {
                assert!(
                    pair[0].last < pair[1].invalidated,
                    "shared suffix repeated at level {level}"
                );
            }
        }
        tree = result.tree;
    }
    let edits: Vec<_> = tree.iter().map(|item| (item.key.clone(), None)).collect();
    let empty = tree.edit_entries(&edits)?;
    assert!(empty.tree.is_empty());
    assert_bytes(&empty.tree, &oracle(&tree, &edits)?);
    let grown = empty.tree.edit_entries(
        &fixture(4000)
            .into_iter()
            .map(|item| (item.key, Some(item.entry)))
            .collect::<Vec<_>>(),
    )?;
    assert_bytes(
        &grown.tree,
        &Tree::build(fixture(4000), None, 262144, TreeUse::Ordinary)?,
    );
    Ok(())
}

#[test]
fn failed_adoption_and_repeated_attempts_retain_their_physical_costs() -> Result<(), Error> {
    let first = directory(b"a".to_vec(), 0o700);
    let mut payload = vec![b'z'; 65500];
    let length = item_bytes(&large_item(b"b", &payload), &[])?.len();
    payload.resize(payload.len() + 65536 - length, b'z');
    let tree = Tree::build(
        vec![first, large_item(b"b", &payload)],
        None,
        262144,
        TreeUse::Ordinary,
    )?;
    let old = tree.root().children().last().ok_or(Error::Node)?;
    let target = Tree::build(
        vec![directory(b"b".to_vec(), 0o700)],
        None,
        262144,
        TreeUse::Ordinary,
    )?
    .root_rc();
    let patch = super::SubtreeReplacement {
        old_identity: old.identity(),
        target,
    };
    let root = tree.root_rc();
    let mut total = super::Work::default();
    for _ in 0..2 {
        let super::SpliceOutcome::RechunkRequired(work) =
            tree.splice_subtrees(core::slice::from_ref(&patch))?
        else {
            return Err(Error::Node);
        };
        // The preceding 11-byte directory is encoded canonical+stored; the
        // proposed next directory contributes one 11-byte stored encoding.
        // All sizes are below MIN, and no node is emitted by failed adoption.
        assert_eq!(work.adoption.item_bytes_encoded, 33);
        assert_eq!(work.adoption.item_bytes_hashed, 0);
        assert_eq!(work.adoption.item_reads, 2);
        assert_eq!(work.adoption.frontier_checks, 2);
        assert_eq!(work.item_encodings, 3);
        assert_eq!(work.node_encodings, 0);
        assert_eq!(work.stream, super::StreamWork::default());
        assert_partition(&work);
        total.combine(work);
        assert!(alloc::rc::Rc::ptr_eq(&root, &tree.root_rc()));
    }
    assert_eq!(total.adoption.item_bytes_encoded, 66);
    assert_eq!(total.adoption.item_reads, 4);
    assert_eq!(total.item_encodings, 6);
    Ok(())
}

fn child_bytes(child: &super::StoredNode<'_>) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    crate::cbor::write_array(&mut bytes, 4);
    crate::cbor::write_bytes(&mut bytes, child.last_key().ok_or(Error::Node)?);
    crate::cbor::write_bytes(&mut bytes, &child.identity());
    crate::cbor::write_uint(&mut bytes, child.count());
    crate::cbor::write_uint(&mut bytes, child.weight());
    Ok(bytes)
}

#[test]
fn changed_child_reference_invalidates_real_internal_content_cut() -> Result<(), Error> {
    let tree = Tree::build(fixture(24000), None, 262144, TreeUse::Ordinary)?;
    let mut parents: Vec<_> = tree.nodes().filter(|node| node.level() == 1).collect();
    parents.sort_by(|a, b| a.last_key().cmp(&b.last_key()));
    let mut witness = None;
    for (index, parent) in parents.iter().enumerate().skip(1) {
        if parent.last_key() == tree.root().last_key() {
            continue;
        }
        let child = parent.children().last().ok_or(Error::Node)?;
        let old_bytes = child_bytes(child)?;
        let size = parent.children().iter().try_fold(0, |sum, child| {
            child_bytes(child).map(|bytes| sum + bytes.len())
        })?;
        if !content_cut(size, old_bytes.len(), &old_bytes) {
            continue;
        }
        let crate::tree_format::NodeItems::Leaf(items) = child.items() else {
            return Err(Error::Node);
        };
        for mode in 0o400..0o777 {
            let mut entries = items.clone();
            let first = entries.first_mut().ok_or(Error::Node)?;
            let replacement = directory(first.key.clone(), mode);
            first.entry = replacement.entry.clone();
            let candidate = Tree::build(entries, None, 262144, TreeUse::Ordinary)?;
            let actual = candidate.root();
            if actual.level() != 0
                || actual.first_key() != child.first_key()
                || actual.last_key() != child.last_key()
                || actual.count() != child.count()
                || actual.weight() != child.weight()
            {
                continue;
            }
            let new_bytes = child_bytes(actual)?;
            if new_bytes.len() == old_bytes.len() && !content_cut(size, new_bytes.len(), &new_bytes)
            {
                witness = Some((
                    index,
                    replacement,
                    child.identity(),
                    actual.identity(),
                    old_bytes,
                    new_bytes,
                    size,
                ));
                break;
            }
        }
        if witness.is_some() {
            break;
        }
    }
    let (index, replacement, old_identity, new_identity, old_bytes, new_bytes, size) =
        witness.ok_or(Error::Node)?;
    assert_ne!(old_identity, new_identity);
    assert_ne!(old_bytes, new_bytes);
    assert!(content_cut(size, old_bytes.len(), &old_bytes));
    assert!(!content_cut(size, new_bytes.len(), &new_bytes));
    let edit = (replacement.key, Some(replacement.entry));
    let result = tree.edit_entries(core::slice::from_ref(&edit))?;
    let rebuilt = oracle(&tree, core::slice::from_ref(&edit))?;
    assert_bytes(&result.tree, &rebuilt);
    let actual_child = result
        .tree
        .nodes()
        .find(|node| node.identity() == new_identity)
        .ok_or(Error::Node)?;
    let rebuilt_child = rebuilt
        .nodes()
        .find(|node| node.identity() == new_identity)
        .ok_or(Error::Node)?;
    assert_eq!(child_bytes(actual_child)?, new_bytes);
    assert_eq!(child_bytes(rebuilt_child)?, new_bytes);

    let region = result
        .work
        .regions
        .iter()
        .find(|region| region.level == 1)
        .ok_or(Error::Node)?;
    assert_eq!(
        region.invalidated.as_slice(),
        parents[index - 1].last_key().ok_or(Error::Node)?
    );
    let invalidated_cut = parents[index].last_key().ok_or(Error::Node)?;
    assert!(
        region.last.as_slice() > invalidated_cut,
        "the changed actual ChildRef crosses the old content cut"
    );
    assert!(region.work.item_bytes_hashed > 0);
    assert!(
        parents
            .iter()
            .any(|node| node.last_key() == Some(region.last.as_slice()))
    );
    if let Some(recovered) = &region.resynchronized {
        assert_eq!(recovered, &region.last);
        let endpoint = result
            .tree
            .nodes()
            .find(|node| node.level() == 1 && node.last_key() == Some(recovered.as_slice()))
            .ok_or(Error::Node)?;
        let total = endpoint.children().iter().try_fold(0, |sum, child| {
            child_bytes(child).map(|bytes| sum + bytes.len())
        })?;
        let last = child_bytes(endpoint.children().last().ok_or(Error::Node)?)?;
        assert!(
            total == 65536 || content_cut(total, last.len(), &last),
            "actual compatible recovered content cut"
        );
    } else {
        assert_eq!(
            region.last.as_slice(),
            tree.root().last_key().ok_or(Error::Node)?
        );
        assert_eq!(result.tree.root().last_key(), tree.root().last_key());
    }
    assert_partition(&result.work);
    Ok(())
}

/// Checks that explicit canonical phases partition the measured total once.
///
/// # Panics
/// Panics if phase totals differ or counter arithmetic overflows with checks enabled.
pub(super) fn assert_partition(work: &super::Work) {
    let mut sum = super::StreamWork::default();
    for region in &work.regions {
        sum.combine(region.work);
    }
    for level in &work.new_levels {
        sum.combine(level.work);
    }
    sum.combine(work.completion);
    sum.combine(work.root_properties);
    sum.combine(work.preparation);
    assert_eq!(
        sum, work.stream,
        "every canonical operation belongs to exactly one explicit phase"
    );
}

#[test]
fn completion_phases_measure_growth_collapse_and_final_properties() -> Result<(), Error> {
    let empty = Tree::build(Vec::new(), Some(Vec::new()), 262144, TreeUse::Ordinary)?;
    let edits: Vec<_> = fixture(24000)
        .into_iter()
        .map(|item| (item.key, Some(item.entry)))
        .collect();
    let growth = empty.edit_entries(&edits)?;
    assert_bytes(&growth.tree, &oracle(&empty, &edits)?);
    assert_partition(&growth.work);
    assert_eq!(growth.work.regions.len(), 1);
    assert_eq!(
        growth.work.new_levels.len(),
        usize::from(growth.tree.root().level())
    );
    for (index, level) in growth.work.new_levels.iter().enumerate() {
        assert_eq!(usize::from(level.level), index + 1);
        assert_eq!(
            level.first.as_slice(),
            growth.tree.root().first_key().ok_or(Error::Node)?
        );
        assert_eq!(
            level.last.as_slice(),
            growth.tree.root().last_key().ok_or(Error::Node)?
        );
        assert!(level.work.item_reads > 0);
        assert!(level.work.item_bytes_encoded > 0);
        assert!(level.work.node_bytes_encoded > 0);
        let outputs: Vec<_> = growth
            .emitted
            .iter()
            .filter(|node| node.level() == level.level && node.node().props.is_none())
            .collect();
        let mut expected_items = 0;
        let mut expected_item_bytes = 0;
        let mut expected_item_hash_bytes = 0;
        let mut expected_node_bytes = 0;
        let mut split_before_checks = 0;
        let mut previous_size = 0;
        for node in &outputs {
            expected_node_bytes += node.encoded().len();
            let mut size = 0;
            for (position, child) in node.children().iter().enumerate() {
                let bytes = child_bytes(child)?;
                if position == 0 && previous_size + bytes.len() > 65536 {
                    split_before_checks += 1;
                }
                expected_items += 1;
                expected_item_bytes += bytes.len();
                size += bytes.len();
                if (4096..65536).contains(&size) {
                    expected_item_hash_bytes += bytes.len();
                }
            }
            previous_size = size;
        }
        assert_eq!(level.work.item_reads, expected_items);
        assert_eq!(level.work.comparisons, 0);
        assert_eq!(
            level.work.frontier_checks,
            expected_items + split_before_checks
        );
        assert_eq!(level.work.item_bytes_encoded, expected_item_bytes);
        assert_eq!(level.work.item_bytes_hashed, expected_item_hash_bytes);
        assert_eq!(level.work.node_bytes_encoded, expected_node_bytes);
        assert_eq!(
            level.work.node_bytes_hashed,
            expected_node_bytes + outputs.len() * 16
        );
    }
    assert_eq!(
        growth.work.root_properties.node_bytes_encoded,
        growth.tree.root().encoded().len()
    );
    assert_eq!(
        growth.work.root_properties.node_bytes_hashed,
        growth.tree.root().encoded().len() + 16
    );
    assert_eq!(growth.work.root_properties.item_reads, 0);
    assert_eq!(growth.work.completion.item_bytes_encoded, 0);
    assert_eq!(growth.work.completion.node_bytes_encoded, 0);
    assert_eq!(
        growth.work.completion.frontier_checks,
        growth.work.new_levels.len() + 2
    );

    let edits: Vec<_> = growth
        .tree
        .iter()
        .map(|item| (item.key.clone(), None))
        .collect();
    let collapse = growth.tree.edit_entries(&edits)?;
    assert_bytes(&collapse.tree, &empty);
    assert_partition(&collapse.work);
    assert!(collapse.work.new_levels.is_empty());
    assert_eq!(collapse.work.completion.node_bytes_encoded, 5);
    assert_eq!(collapse.work.completion.node_bytes_hashed, 21);
    assert_eq!(
        collapse.work.root_properties.node_bytes_encoded,
        empty.root().encoded().len()
    );

    let changed = growth.tree.with_properties(None)?;
    assert_partition(&changed.work);
    assert!(changed.work.regions.is_empty());
    assert!(changed.work.new_levels.is_empty());
    assert_eq!(changed.work.completion, super::StreamWork::default());
    assert_eq!(
        changed.work.root_properties.node_bytes_encoded,
        changed.tree.root().encoded().len()
    );
    assert_eq!(
        changed.work.root_properties.node_bytes_hashed,
        changed.tree.root().encoded().len() + 16
    );
    assert_eq!(changed.work.stream, changed.work.root_properties);
    let inert = changed
        .tree
        .with_properties(Some(vec![crate::tree_format::Property {
            name: "p",
            value: &[0x01],
        }]))?;
    assert_partition(&inert.work);
    assert_eq!(inert.work.stream, inert.work.root_properties);
    assert!(alloc::rc::Rc::ptr_eq(
        &changed.tree.root().children()[0],
        &inert.tree.root().children()[0]
    ));
    let unchanged = changed.tree.with_properties(None)?;
    assert_partition(&unchanged.work);
    assert_eq!(unchanged.work, super::Work::default());
    Ok(())
}

#[test]
fn tree_history_independence_bounds_adoption_frontier_work() -> Result<(), Error> {
    super::frontier_tests::run()
}
