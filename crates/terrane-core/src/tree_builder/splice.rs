//! Adopts aligned immutable subtrees after certifying their canonical edges.
//!
//! A split-before boundary depends on the next item's stored length. Matching
//! key ranges alone therefore cannot authorize subtree adoption. Edge cuts are
//! checked at every descendant level, and all adopted nodes must survive the
//! ancestor rechunking performed for a batch.

use alloc::{rc::Rc, vec::Vec};

use crate::{
    boundary::{self, BoundaryDecision},
    tree_format::{Entry, LeafItem, NodeItems},
};

use super::{
    Error, Factory, Mutation, StoredNode, Tree, Work,
    chunk::{self, Item},
    cursor::LevelCursor,
    links,
    mutation::{self, Replacement},
};

/// Identifies an existing subtree and a replacement with identical bounds.
#[derive(Clone, Debug)]
pub struct SubtreeReplacement<'a> {
    /// Canonical identity of the subtree currently present in the map.
    pub old_identity: crate::identity::Digest,
    /// Immutable replacement node with matching first key, last key, and level.
    pub target: Rc<StoredNode<'a>>,
}

/// Reports whether whole-subtree adoption preserved canonical boundaries.
#[derive(Clone, Debug)]
pub enum SpliceOutcome<'a> {
    /// Contains the persistent result and actual work, with targets shared whole.
    Applied(Mutation<'a>),
    /// Reports actual work when canonical cuts require finer-grained rechunking.
    ///
    /// The original map is unchanged. A caller must descend into smaller
    /// aligned ranges or use entry edits instead of adopting these targets.
    RechunkRequired(Work),
}

pub(super) struct Change<'a> {
    pub(super) key: Vec<u8>,
    pub(super) old: Option<Entry<'a>>,
    pub(super) new: Option<Entry<'a>>,
}

fn combine(total: &mut Work, work: Work) {
    total.node_reads += work.node_reads;
    total.validation_reads += work.validation_reads;
    total.item_encodings += work.item_encodings;
    total.node_encodings += work.node_encodings;
}

fn locate<'tree, 'a>(
    tree: &'tree Tree<'a>,
    target: &StoredNode<'a>,
    reads: &mut usize,
) -> Result<&'tree StoredNode<'a>, Error> {
    if target.level() > tree.root().level() {
        return Err(Error::Node);
    }
    let key = target.first_key().ok_or(Error::Node)?;
    let mut cursor = LevelCursor::seek(tree.root(), target.level(), key);
    let node = cursor.next().ok_or(Error::Node)?;
    *reads += cursor.reads;
    Ok(node)
}

pub(super) fn apply<'a>(
    tree: &Tree<'a>,
    patches: &[SubtreeReplacement<'a>],
) -> Result<SpliceOutcome<'a>, Error> {
    apply_edits(tree, patches, &[])
}

pub(super) fn apply_edits<'a>(
    tree: &Tree<'a>,
    patches: &[SubtreeReplacement<'a>],
    edits: &[(Vec<u8>, Option<Entry<'a>>)],
) -> Result<SpliceOutcome<'a>, Error> {
    if patches.is_empty() && edits.is_empty() {
        return Ok(SpliceOutcome::Applied(tree.unchanged()));
    }
    let mut ordered: Vec<_> = patches.iter().collect();
    ordered.sort_by(|left, right| left.target.first_key().cmp(&right.target.first_key()));
    let mut previous_last = None;
    let mut work = Work::default();
    let mut changes = Vec::new();

    for patch in &ordered {
        let old = locate(tree, &patch.target, &mut work.validation_reads)?;
        if old.identity() != patch.old_identity
            || old.first_key() != patch.target.first_key()
            || old.last_key() != patch.target.last_key()
            || old.level() != patch.target.level()
        {
            return Err(Error::Node);
        }
        let first = old.first_key().ok_or(Error::Node)?;
        if previous_last.is_some_and(|last| last >= first) {
            return Err(Error::Tree);
        }
        previous_last = old.last_key();
        if patch.target.node().props.is_some() && old.identity() != tree.root_identity() {
            return Err(Error::Node);
        }
        collect_changes(old, &patch.target, &mut changes, &mut work.validation_reads)?;
    }

    let mut previous_key = None;
    let mut range_index = 0;
    for (key, _) in edits {
        if previous_key.is_some_and(|previous: &[u8]| previous >= key.as_slice()) {
            return Err(Error::Tree);
        }
        while ordered.get(range_index).is_some_and(|patch| {
            patch
                .target
                .last_key()
                .is_some_and(|last| last < key.as_slice())
        }) {
            range_index += 1;
        }
        if ordered.get(range_index).is_some_and(|patch| {
            patch
                .target
                .first_key()
                .is_some_and(|first| first <= key.as_slice())
        }) {
            return Err(Error::Tree);
        }
        previous_key = Some(key.as_slice());
    }

    // Higher-level replacements go first. Their descendants remain available
    // by identity for subsequent disjoint lower-level replacements.
    ordered.sort_by_key(|patch| core::cmp::Reverse(patch.target.level()));
    let mut result = tree.clone();
    let mut emitted = Vec::new();
    for patch in &ordered {
        let Ok(old) = locate(&result, &patch.target, &mut work.validation_reads) else {
            return Ok(SpliceOutcome::RechunkRequired(work));
        };
        if old.identity() != patch.old_identity {
            return Ok(SpliceOutcome::RechunkRequired(work));
        }
        let mut factory = Factory::new(tree.min_chunk_size, tree.usage);
        if !compatible(&result, &patch.target, &mut factory)? {
            combine(&mut work, factory.work);
            return Ok(SpliceOutcome::RechunkRequired(work));
        }
        let mutation = adopt(&result, Rc::clone(&patch.target), &mut factory)?;
        result.root = mutation;
        combine(&mut work, factory.work);
        emitted.extend(factory.emitted);
    }

    // Only the final map is admitted. A hard-link set or directory subtree
    // can have invalid intermediate states while its complete delta is applied.
    for (key, new) in edits {
        let old = mutation::lookup(tree, key, &mut work.validation_reads);
        if old == new.as_ref() {
            continue;
        }
        changes.push(Change {
            key: key.clone(),
            old: old.cloned(),
            new: new.clone(),
        });
        let item = new.as_ref().map(|entry| LeafItem {
            key: key.clone(),
            entry: entry.clone(),
        });
        let next = mutation::edit(&result, key, item)?;
        combine(&mut work, next.work);
        emitted.extend(next.emitted);
        result = next.tree;
    }

    for patch in &ordered {
        let Ok(present) = locate(&result, &patch.target, &mut work.validation_reads) else {
            return Ok(SpliceOutcome::RechunkRequired(work));
        };
        if present.identity() != patch.target.identity()
            || !core::ptr::eq(present, patch.target.as_ref())
        {
            return Ok(SpliceOutcome::RechunkRequired(work));
        }
    }
    for change in &changes {
        mutation::validate_map_entry(
            &result,
            &change.key,
            change.new.as_ref(),
            &mut work.validation_reads,
        )?;
    }
    result.links =
        links::replace_changes(&tree.links, &changes, &result, &mut work.validation_reads)?;
    Ok(SpliceOutcome::Applied(Mutation {
        tree: result,
        emitted,
        work,
    }))
}

fn adopt<'a>(
    tree: &Tree<'a>,
    target: Rc<StoredNode<'a>>,
    factory: &mut Factory<'a>,
) -> Result<Rc<StoredNode<'a>>, Error> {
    let last = target.last_key().ok_or(Error::Node)?.to_vec();
    let level = target.level();
    let mut replacement = Replacement {
        first: last.clone(),
        last,
        nodes: alloc::vec![target],
    };
    for parent_level in level + 1..=tree.root().level() {
        replacement = mutation::edit_parents(tree, parent_level, replacement, factory)?;
    }
    mutation::finish_nodes(tree, replacement.nodes, factory)
}

fn edge<'node, 'a>(
    mut node: &'node StoredNode<'a>,
    level: u8,
    first: bool,
    reads: &mut usize,
) -> Result<&'node StoredNode<'a>, Error> {
    while node.level() > level {
        *reads += 1;
        node = if first {
            node.children().first()
        } else {
            node.children().last()
        }
        .ok_or(Error::Node)?;
    }
    *reads += 1;
    Ok(node)
}

fn compatible(
    tree: &Tree<'_>,
    target: &StoredNode<'_>,
    factory: &mut Factory<'_>,
) -> Result<bool, Error> {
    for level in 0..=target.level() {
        let first = edge(target, level, true, &mut factory.work.validation_reads)?;
        let last = edge(target, level, false, &mut factory.work.validation_reads)?;
        let first_key = first.first_key().ok_or(Error::Node)?;
        let last_key = last.last_key().ok_or(Error::Node)?;
        let mut left = LevelCursor::seek(tree.root(), level, first_key).with_predecessor();
        let preceding = left.next().ok_or(Error::Node)?;
        factory.work.validation_reads += left.reads;
        if preceding.last_key().is_some_and(|key| key < first_key)
            && !cut_before(preceding, Some(first), factory)?
        {
            return Ok(false);
        }
        let mut right = LevelCursor::seek(tree.root(), level, last_key);
        right.next().ok_or(Error::Node)?;
        let following = right.next();
        factory.work.validation_reads += right.reads;
        if !cut_before(last, following, factory)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn cut_before(
    node: &StoredNode<'_>,
    following: Option<&StoredNode<'_>>,
    factory: &mut Factory<'_>,
) -> Result<bool, Error> {
    let Some(following) = following else {
        return Ok(true);
    };
    let mut size = 0;
    let mut previous = &[][..];
    let mut last_decision = BoundaryDecision::Continue;
    match node.items() {
        NodeItems::Leaf(items) => {
            for item in items {
                let canonical = chunk::leaf_bytes(item, &[], factory.min_chunk_size)?;
                let stored = chunk::leaf_bytes(item, previous, factory.min_chunk_size)?;
                factory.work.item_encodings += 2;
                last_decision = boundary::decide(size, stored.len() as u64, &canonical)
                    .map_err(|_| Error::Limit)?;
                size += stored.len() as u64;
                previous = &item.key;
            }
            if last_decision == BoundaryDecision::CloseAfter {
                return Ok(true);
            }
            let NodeItems::Leaf(next) = following.items() else {
                return Err(Error::Node);
            };
            let next = next.first().ok_or(Error::Node)?;
            let stored = chunk::leaf_bytes(next, previous, factory.min_chunk_size)?;
            factory.work.item_encodings += 1;
            Ok(size + stored.len() as u64 > boundary::MAX_NODE)
        }
        NodeItems::Internal(_) => {
            for child in node.children() {
                let canonical = Item::Child(Rc::clone(child)).canonical(factory.min_chunk_size)?;
                factory.work.item_encodings += 1;
                last_decision = boundary::decide(size, canonical.len() as u64, &canonical)
                    .map_err(|_| Error::Limit)?;
                size += canonical.len() as u64;
            }
            if last_decision == BoundaryDecision::CloseAfter {
                return Ok(true);
            }
            let next = following.children().first().ok_or(Error::Node)?;
            let canonical = Item::Child(Rc::clone(next)).canonical(factory.min_chunk_size)?;
            factory.work.item_encodings += 1;
            Ok(size + canonical.len() as u64 > boundary::MAX_NODE)
        }
    }
}

#[derive(Clone, Copy)]
enum Part<'tree, 'a> {
    Node(&'tree StoredNode<'a>),
    Item(&'tree LeafItem<'a>),
}

impl<'tree, 'a> Part<'tree, 'a> {
    fn key(self) -> Option<&'tree [u8]> {
        match self {
            Self::Node(node) => node.first_key(),
            Self::Item(item) => Some(&item.key),
        }
    }
}

fn expand<'tree, 'a>(stack: &mut Vec<Part<'tree, 'a>>, reads: &mut usize) {
    let Some(Part::Node(node)) = stack.pop() else {
        return;
    };
    *reads += 1;
    match node.items() {
        NodeItems::Leaf(items) => stack.extend(items.iter().rev().map(Part::Item)),
        NodeItems::Internal(_) => {
            stack.extend(node.children().iter().rev().map(|child| Part::Node(child)))
        }
    }
}

fn collect_changes<'a>(
    old: &StoredNode<'a>,
    target: &StoredNode<'a>,
    changes: &mut Vec<Change<'a>>,
    reads: &mut usize,
) -> Result<(), Error> {
    let mut left = alloc::vec![Part::Node(old)];
    let mut right = alloc::vec![Part::Node(target)];
    loop {
        let a = left.last().copied();
        let b = right.last().copied();
        if let (Some(Part::Node(a)), Some(Part::Node(b))) = (a, b) {
            *reads += 2;
            if a.identity() == b.identity() {
                left.pop();
                right.pop();
                continue;
            }
        }
        match (a, b) {
            (None, None) => return Ok(()),
            (Some(Part::Node(_)), None) => expand(&mut left, reads),
            (None, Some(Part::Node(_))) => expand(&mut right, reads),
            (Some(Part::Node(_)), Some(b)) if a.and_then(Part::key) <= b.key() => {
                expand(&mut left, reads)
            }
            (Some(a), Some(Part::Node(_))) if b.and_then(Part::key) <= a.key() => {
                expand(&mut right, reads)
            }
            (Some(Part::Item(item)), None) => {
                changes.push(Change {
                    key: item.key.clone(),
                    old: Some(item.entry.clone()),
                    new: None,
                });
                left.pop();
            }
            (None, Some(Part::Item(item))) => {
                changes.push(Change {
                    key: item.key.clone(),
                    old: None,
                    new: Some(item.entry.clone()),
                });
                right.pop();
            }
            (Some(Part::Item(a)), Some(Part::Item(b))) if a.key == b.key => {
                if a.entry != b.entry {
                    changes.push(Change {
                        key: a.key.clone(),
                        old: Some(a.entry.clone()),
                        new: Some(b.entry.clone()),
                    });
                }
                left.pop();
                right.pop();
            }
            (Some(Part::Item(a)), Some(b)) if Some(a.key.as_slice()) < b.key() => {
                changes.push(Change {
                    key: a.key.clone(),
                    old: Some(a.entry.clone()),
                    new: None,
                });
                left.pop();
            }
            (Some(a), Some(Part::Item(b))) if a.key() > Some(b.key.as_slice()) => {
                changes.push(Change {
                    key: b.key.clone(),
                    old: None,
                    new: Some(b.entry.clone()),
                });
                right.pop();
            }
            _ => return Err(Error::Node),
        }
    }
}
