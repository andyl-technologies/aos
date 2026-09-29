//! Replaces one sorted key interval with one localized leaf-stream edit.
//!
//! Validation indexes the replacement's directory ancestors locally and only
//! seeks outside ancestors once. Descendant checks use the replacement slice
//! when its interval covers the whole component-prefix range. Only boundary
//! ancestors require additional seeks into the final persistent tree.

use alloc::{collections::BTreeMap, vec::Vec};

use crate::tree_format::{
    EntryKind, LeafItem, NodeItems, TreeUse, encode_entry, validate_index_key, validate_key,
};

use super::{
    Error, Factory, Mutation, Tree,
    chunk::{Chunker, Item},
    cursor::LevelCursor,
    links,
    mutation::{self, Replacement},
    splice::Change,
};

pub(super) fn replace<'a>(
    tree: &Tree<'a>,
    start: &[u8],
    end: Option<&[u8]>,
    entries: Vec<LeafItem<'a>>,
) -> Result<Mutation<'a>, Error> {
    if end.is_some_and(|end| end <= start) {
        return Err(Error::Tree);
    }
    let mut previous = None;
    for entry in &entries {
        if entry.key.as_slice() < start
            || end.is_some_and(|end| entry.key.as_slice() >= end)
            || previous.is_some_and(|previous: &[u8]| previous >= entry.key.as_slice())
        {
            return Err(Error::Tree);
        }
        previous = Some(entry.key.as_slice());
    }
    let mut factory = Factory::new(tree.min_chunk_size, tree.usage);
    let mut cursor = tree.cursor_from(start);
    let mut old = Vec::new();
    for item in cursor.by_ref() {
        if end.is_some_and(|end| item.key.as_slice() >= end) {
            break;
        }
        old.push(item.clone());
    }
    factory.work.validation_reads += cursor.node_reads();
    let changes = changes(&old, &entries)?;
    if changes.is_empty() {
        let mut result = tree.unchanged();
        result.work = factory.work;
        return Ok(result);
    }

    let mut replacement = rechunk(tree, start, end, &entries, &mut factory)?;
    for level in 1..=tree.root().level() {
        replacement = mutation::edit_parents(tree, level, replacement, &mut factory)?;
    }
    let root = mutation::finish_nodes(tree, replacement.nodes, &mut factory)?;
    let mut result = tree.finish(root, factory);
    validate(
        &result.tree,
        start,
        end,
        &entries,
        &changes,
        &mut result.work.validation_reads,
    )?;
    result.tree.links = links::replace_changes(
        &tree.links,
        &changes,
        &result.tree,
        &mut result.work.validation_reads,
    )?;
    result.tree.members =
        links::replace_members(&tree.members, &changes, &mut result.work.validation_reads);
    Ok(result)
}

fn rechunk<'a>(
    tree: &Tree<'a>,
    start: &[u8],
    end: Option<&[u8]>,
    entries: &[LeafItem<'a>],
    factory: &mut Factory<'a>,
) -> Result<Replacement<'a>, Error> {
    let mut cursor = LevelCursor::seek(tree.root(), 0, start).with_predecessor();
    let mut chunker = Chunker::new(0);
    let mut inserted = false;
    let mut passed_end = false;
    let mut first = None;
    let mut last = Vec::new();
    for node in cursor.by_ref() {
        let node_last = node.last_key().map_or(&[][..], |key| key);
        if first.is_none() {
            first = Some(node_last.to_vec());
        }
        last = node_last.to_vec();
        let NodeItems::Leaf(items) = node.items() else {
            return Err(Error::Node);
        };
        for item in items {
            if item.key.as_slice() < start {
                chunker.push(Item::Leaf(item.clone()), factory)?;
                continue;
            }
            if !inserted {
                for entry in entries {
                    chunker.push(Item::Leaf(entry.clone()), factory)?;
                }
                inserted = true;
            }
            if end.is_some_and(|end| item.key.as_slice() >= end) {
                chunker.push(Item::Leaf(item.clone()), factory)?;
                passed_end = true;
            }
        }
        if inserted && passed_end && chunker.is_empty() {
            break;
        }
    }
    if !inserted {
        for entry in entries {
            chunker.push(Item::Leaf(entry.clone()), factory)?;
        }
    }
    factory.work.node_reads += cursor.reads;
    Ok(Replacement {
        first: first.ok_or(Error::Node)?,
        last,
        nodes: chunker.finish(factory)?,
    })
}

fn changes<'a>(old: &[LeafItem<'a>], entries: &[LeafItem<'a>]) -> Result<Vec<Change<'a>>, Error> {
    let mut changes = Vec::new();
    let mut old_index = 0;
    let mut new_index = 0;
    loop {
        match (old.get(old_index), entries.get(new_index)) {
            (None, None) => return Ok(changes),
            (Some(old), Some(new)) if old.key == new.key => {
                if old.entry != new.entry {
                    changes.push(Change {
                        key: old.key.clone(),
                        old: Some(old.entry.clone()),
                        new: Some(new.entry.clone()),
                    });
                }
                old_index += 1;
                new_index += 1;
            }
            (Some(old), new) if new.is_none_or(|new| old.key < new.key) => {
                changes.push(Change {
                    key: old.key.clone(),
                    old: Some(old.entry.clone()),
                    new: None,
                });
                old_index += 1;
            }
            (_, Some(new)) => {
                changes.push(Change {
                    key: new.key.clone(),
                    old: None,
                    new: Some(new.entry.clone()),
                });
                new_index += 1;
            }
            _ => return Err(Error::Node),
        }
    }
}

fn validate<'a>(
    tree: &Tree<'a>,
    start: &[u8],
    end: Option<&[u8]>,
    entries: &[LeafItem<'a>],
    changes: &[Change<'a>],
    reads: &mut usize,
) -> Result<(), Error> {
    let mut ancestors: BTreeMap<&[u8], bool> = entries
        .iter()
        .map(|item| (item.key.as_slice(), item.entry.kind.permits_descendants()))
        .collect();
    for item in entries {
        if tree.usage == TreeUse::Index {
            validate_index_key(&item.key)?;
        } else {
            validate_key(&item.key)?;
        }
        encode_entry(&item.entry, tree.min_chunk_size)?;
        match (&item.entry.kind, tree.usage) {
            (EntryKind::Index { .. }, TreeUse::Index)
            | (EntryKind::Whiteout, TreeUse::OverlayLayer) => {}
            (EntryKind::Index { .. }, _)
            | (_, TreeUse::Index)
            | (EntryKind::Whiteout, _)
            | (EntryKind::Conflict { .. }, TreeUse::Surface) => return Err(Error::Tree),
            _ => {}
        }
        if tree.usage == TreeUse::Index {
            continue;
        }
        for (position, byte) in item.key.iter().enumerate() {
            if *byte != b'/' {
                continue;
            }
            let ancestor = &item.key[..position];
            let permits = if let Some(permits) = ancestors.get(ancestor) {
                *permits
            } else {
                let permits = mutation::lookup(tree, ancestor, reads)
                    .is_some_and(|entry| entry.kind.permits_descendants());
                ancestors.insert(ancestor, permits);
                permits
            };
            if !permits {
                return Err(Error::Tree);
            }
        }
    }
    if tree.usage == TreeUse::Index {
        return Ok(());
    }
    for change in changes {
        if change
            .new
            .as_ref()
            .is_some_and(|entry| entry.kind.permits_descendants())
            || !change
                .old
                .as_ref()
                .is_some_and(|entry| entry.kind.permits_descendants())
        {
            continue;
        }
        let mut prefix = change.key.clone();
        prefix.push(b'/');
        let mut upper = prefix.clone();
        if let Some(last) = upper.last_mut() {
            *last += 1;
        }
        let fully_replaced =
            prefix.as_slice() >= start && end.is_none_or(|end| upper.as_slice() <= end);
        let has_descendants = if fully_replaced {
            let index = entries.partition_point(|item| item.key.as_slice() < prefix.as_slice());
            entries
                .get(index)
                .is_some_and(|item| item.key.starts_with(&prefix))
        } else {
            let mut descendants = tree.cursor_from(&prefix);
            let has_descendants = descendants
                .next()
                .is_some_and(|item| item.key.starts_with(&prefix));
            *reads += descendants.node_reads();
            has_descendants
        };
        if has_descendants {
            return Err(Error::Tree);
        }
    }
    Ok(())
}
