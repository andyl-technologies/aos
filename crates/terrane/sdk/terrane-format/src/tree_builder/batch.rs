//! Processes connected sparse-edit streams once at leaves and each ancestor level.
//!
//! A recovered cut is accepted only after probing the next invalidated node's
//! predecessor. If that predecessor is already in the active region, the same
//! stream continues. Otherwise a fresh seek jumps over the unaffected interval.

use alloc::{rc::Rc, vec::Vec};

use crate::tree_format::{Entry, LeafItem, NodeItems};

use super::{
    BoundaryRegion, Error, Factory, Mutation, StoredNode, StreamWork, Tree,
    chunk::{Chunker, Item},
    cursor::LevelCursor,
    mutation::{self, Replacement},
};

pub(super) fn record(
    factory: &mut Factory<'_>,
    level: u8,
    first: &[u8],
    last: &[u8],
    recovered: bool,
    before: StreamWork,
) {
    factory.work.regions.push(BoundaryRegion {
        level,
        invalidated: first.to_vec(),
        resynchronized: recovered.then(|| last.to_vec()),
        last: last.to_vec(),
        work: factory.work.stream.since(before),
    });
}

fn seek<'tree, 'a>(
    tree: &'tree Tree<'a>,
    level: u8,
    key: &[u8],
    factory: &mut Factory<'a>,
) -> LevelCursor<'tree, 'a> {
    let cursor = LevelCursor::seek(tree.root(), level, key).with_predecessor();
    factory.work.seek_comparisons += cursor.comparisons;
    cursor
}

/// Keeps a probed seek only when the next invalidation is genuinely distant.
fn separated<'tree, 'a>(
    tree: &'tree Tree<'a>,
    level: u8,
    key: &[u8],
    last: &[u8],
    factory: &mut Factory<'a>,
) -> Option<LevelCursor<'tree, 'a>> {
    let cursor = seek(tree, level, key, factory);
    factory.work.stream.frontier_checks += 1;
    factory.work.stream.comparisons += 1;
    factory.work.node_reads += usize::from(cursor.next.is_some());
    if cursor
        .next
        .and_then(|node| node.last_key())
        .is_some_and(|key| key > last)
    {
        Some(cursor)
    } else {
        // A failed probe really read its seek path, even though its cursor is
        // discarded and the original stream continues without restarting.
        factory.work.node_reads += cursor.reads;
        None
    }
}

pub(super) fn edit<'a>(
    tree: &Tree<'a>,
    edits: &[(Vec<u8>, Option<Entry<'a>>)],
) -> Result<Mutation<'a>, Error> {
    if edits.is_empty() {
        return Ok(tree.unchanged());
    }
    let mut factory = Factory::new(tree.min_chunk_size, tree.usage);
    let root = rechunk(tree, edits, &[], &mut factory)?.ok_or(Error::Node)?;
    Ok(tree.finish(root, factory))
}

/// Injects adopted nodes into the same replacement stream as sparse changes.
pub(super) fn rechunk<'a>(
    tree: &Tree<'a>,
    edits: &[(Vec<u8>, Option<Entry<'a>>)],
    patches: &[Rc<StoredNode<'a>>],
    factory: &mut Factory<'a>,
) -> Result<Option<Rc<StoredNode<'a>>>, Error> {
    let mut replacements = if edits.is_empty() {
        Vec::new()
    } else {
        leaves(tree, edits, factory)?
    };
    for level in 0..=tree.root().level() {
        let Some(injected) = inject(tree, level, replacements, patches, factory)? else {
            return Ok(None);
        };
        replacements = injected;
        if level < tree.root().level() && !replacements.is_empty() {
            replacements = parents(tree, level + 1, replacements, factory)?;
        }
    }
    if replacements.len() != 1 {
        return Err(Error::Node);
    }
    let replacement = replacements.pop().ok_or(Error::Node)?;
    mutation::finish_nodes(tree, replacement.nodes, factory).map(Some)
}

/// Merges increasing targets with disjoint canonical replacement spans once.
///
/// Returns `None` when a covered predecessor no longer survives with its exact
/// identity, so the caller can refuse whole-subtree adoption without mutation.
///
/// # Errors
/// Rejects missing key boundaries, failed predecessor lookups, or malformed frontiers.
///
/// # Panics
/// Panics if a work counter overflows when overflow checks are enabled.
pub(super) fn inject<'a>(
    tree: &Tree<'a>,
    level: u8,
    replacements: Vec<Replacement<'a>>,
    patches: &[Rc<StoredNode<'a>>],
    factory: &mut Factory<'a>,
) -> Result<Option<Vec<Replacement<'a>>>, Error> {
    let before = factory.work.stream;
    let result = inject_ordered(tree, level, replacements, patches, factory);
    factory
        .work
        .preparation
        .combine(factory.work.stream.since(before));
    result
}

fn inject_ordered<'a>(
    tree: &Tree<'a>,
    level: u8,
    mut replacements: Vec<Replacement<'a>>,
    patches: &[Rc<StoredNode<'a>>],
    factory: &mut Factory<'a>,
) -> Result<Option<Vec<Replacement<'a>>>, Error> {
    let mut position = 0;
    let mut standalone = Vec::new();
    for patch in patches.iter().filter(|patch| patch.level() == level) {
        factory.work.stream.frontier_checks += 1;
        factory.work.node_reads += 1;
        let key = patch.last_key().ok_or(Error::Node)?;
        while let Some(replacement) = replacements.get(position) {
            factory.work.stream.comparisons += 1;
            if replacement.last.as_slice() >= key {
                break;
            }
            position += 1;
        }
        let covered = if let Some(replacement) = replacements.get(position) {
            factory.work.stream.comparisons += 1;
            replacement.first.as_slice() <= key
        } else {
            false
        };
        if covered {
            let old = mutation::lookup_node(tree, level, key, &mut factory.work.validation_reads)?;
            // Last keys identify the candidate frontier, but never authorize
            // adoption: the exact old canonical identity must also survive.
            let index = replacements[position].nodes.binary_search_by(|node| {
                factory.work.stream.comparisons += 1;
                factory.work.stream.frontier_checks += 1;
                factory.work.node_reads += 1;
                node.last_key().cmp(&Some(key))
            });
            let Ok(index) = index else {
                return Ok(None);
            };
            let node = &mut replacements[position].nodes[index];
            factory.work.stream.frontier_checks += 1;
            factory.work.node_reads += 1;
            if node.identity() != old.identity() {
                return Ok(None);
            }
            *node = Rc::clone(patch);
        } else {
            // This ordered run never becomes part of later coverage searches.
            standalone.push(Replacement {
                first: key.to_vec(),
                last: key.to_vec(),
                nodes: alloc::vec![Rc::clone(patch)],
            });
        }
    }

    let mut spans = replacements.into_iter().peekable();
    let mut targets = standalone.into_iter().peekable();
    let mut merged = Vec::new();
    while let (Some(span), Some(target)) = (spans.peek(), targets.peek()) {
        factory.work.stream.comparisons += 1;
        if span.first < target.first {
            merged.push(spans.next().ok_or(Error::Node)?);
        } else {
            merged.push(targets.next().ok_or(Error::Node)?);
        }
    }
    merged.extend(spans);
    merged.extend(targets);
    Ok(Some(merged))
}

fn leaves<'a>(
    tree: &Tree<'a>,
    edits: &[(Vec<u8>, Option<Entry<'a>>)],
    factory: &mut Factory<'a>,
) -> Result<Vec<Replacement<'a>>, Error> {
    let mut output = Vec::new();
    let mut position = 0;
    let mut pending = Some(seek(tree, 0, &edits[0].0, factory));
    while let Some(mut cursor) = pending.take() {
        let before = factory.work.stream;
        let mut chunker = Chunker::new(0);
        let mut first = None;
        let mut last = Vec::new();
        let mut recovered = false;
        for node in cursor.by_ref() {
            let node_last = node.last_key().unwrap_or_default();
            first.get_or_insert_with(|| node_last.to_vec());
            last = node_last.to_vec();
            let NodeItems::Leaf(items) = node.items() else {
                return Err(Error::Node);
            };
            factory.work.stream.comparisons += 1;
            let tail = node.last_key() == tree.root().last_key();
            for item in items {
                let mut changed = false;
                factory.work.stream.item_reads += 1;
                while let Some((key, value)) = edits.get(position) {
                    factory.work.stream.comparisons += 1;
                    if key > &item.key {
                        break;
                    }
                    if let Some(entry) = value {
                        chunker.push(
                            Item::Leaf(LeafItem {
                                key: key.clone(),
                                entry: entry.clone(),
                            }),
                            factory,
                        )?;
                    }
                    position += 1;
                    factory.work.stream.comparisons += 1;
                    if key == &item.key {
                        changed = true;
                        break;
                    }
                }
                // A consumed edit may remove this item or replace it.
                if !changed {
                    chunker.push(Item::Leaf(item.clone()), factory)?;
                }
            }
            if tail {
                for (key, value) in &edits[position..] {
                    if let Some(entry) = value {
                        chunker.push(
                            Item::Leaf(LeafItem {
                                key: key.clone(),
                                entry: entry.clone(),
                            }),
                            factory,
                        )?;
                    }
                }
                position = edits.len();
            }
            factory.work.stream.frontier_checks += 1;
            if chunker.is_empty() {
                if let Some((key, _)) = edits.get(position) {
                    if let Some(next) = separated(tree, 0, key, &last, factory) {
                        pending = Some(next);
                        recovered = !tail;
                        break;
                    }
                } else {
                    recovered = !tail;
                    break;
                }
            }
        }
        factory.work.node_reads += cursor.reads;
        let nodes = chunker.finish(factory)?;
        let first = first.ok_or(Error::Node)?;
        record(factory, 0, &first, &last, recovered, before);
        output.push(Replacement { first, last, nodes });
    }
    Ok(output)
}

pub(super) fn parents<'a>(
    tree: &Tree<'a>,
    level: u8,
    replacements: Vec<Replacement<'a>>,
    factory: &mut Factory<'a>,
) -> Result<Vec<Replacement<'a>>, Error> {
    let mut output = Vec::new();
    let mut position = 0;
    let mut inserted = false;
    let mut pending = Some(seek(tree, level, &replacements[0].first, factory));
    while let Some(mut cursor) = pending.take() {
        let before = factory.work.stream;
        let mut chunker = Chunker::new(level);
        let mut first = None;
        let mut last = Vec::new();
        let mut recovered = false;
        for node in cursor.by_ref() {
            let node_last = node.last_key().ok_or(Error::Node)?;
            first.get_or_insert_with(|| node_last.to_vec());
            last = node_last.to_vec();
            for child in node.children() {
                factory.work.stream.item_reads += 1;
                let child_key = child.last_key().ok_or(Error::Node)?;
                while let Some(replacement) = replacements.get(position) {
                    factory.work.stream.comparisons += 1;
                    if child_key <= replacement.last.as_slice() {
                        break;
                    }
                    if !inserted {
                        return Err(Error::Node);
                    }
                    position += 1;
                    inserted = false;
                }
                let replacement = replacements.get(position);
                factory.work.stream.comparisons += usize::from(replacement.is_some());
                let replaced = replacement
                    .is_some_and(|replacement| child_key >= replacement.first.as_slice());
                if replaced {
                    if !inserted {
                        for new in &replacements[position].nodes {
                            chunker.push(Item::Child(Rc::clone(new)), factory)?;
                        }
                        inserted = true;
                    }
                } else {
                    chunker.push(Item::Child(Rc::clone(child)), factory)?;
                }
            }
            if let Some(replacement) = replacements.get(position) {
                factory.work.stream.comparisons += usize::from(inserted);
                if inserted && node_last >= replacement.last.as_slice() {
                    position += 1;
                    inserted = false;
                }
            }
            factory.work.stream.frontier_checks += 1;
            if chunker.is_empty() {
                if let Some(replacement) = replacements.get(position) {
                    if let Some(next) = separated(tree, level, &replacement.first, &last, factory) {
                        pending = Some(next);
                        factory.work.stream.comparisons += 1;
                        recovered = node.last_key() != tree.root().last_key();
                        break;
                    }
                } else {
                    factory.work.stream.comparisons += 1;
                    recovered = node.last_key() != tree.root().last_key();
                    break;
                }
            }
        }
        factory.work.node_reads += cursor.reads;
        let nodes = chunker.finish(factory)?;
        let first = first.ok_or(Error::Node)?;
        record(factory, level, &first, &last, recovered, before);
        output.push(Replacement { first, last, nodes });
    }
    if position != replacements.len() {
        return Err(Error::Node);
    }
    Ok(output)
}
