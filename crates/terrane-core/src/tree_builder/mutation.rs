//! Rechunks edited key ranges until canonical boundaries resynchronize.

use alloc::{rc::Rc, vec::Vec};

use crate::tree_format::{
    Entry, EntryKind, LeafItem, NodeItems, TreeUse, encode_entry, validate_index_key, validate_key,
};

use super::{
    Error, Factory, Mutation, StoredNode, Tree,
    chunk::{self, Chunker, Item},
    cursor::LevelCursor,
    links,
};

fn lookup<'tree, 'a>(
    tree: &'tree Tree<'a>,
    key: &[u8],
    reads: &mut usize,
) -> Option<&'tree Entry<'a>> {
    let mut node = tree.root();
    loop {
        *reads += 1;
        match node.items() {
            NodeItems::Leaf(items) => {
                return items
                    .binary_search_by(|item| item.key.as_slice().cmp(key))
                    .ok()
                    .map(|index| &items[index].entry);
            }
            NodeItems::Internal(items) => {
                let index = items.partition_point(|item| item.last_key.as_slice() < key);
                node = node.children().get(index)?;
            }
        }
    }
}

fn validate<'a>(
    tree: &Tree<'a>,
    key: &[u8],
    new: Option<&Entry<'a>>,
    reads: &mut usize,
) -> Result<links::Links<'a>, Error> {
    if tree.usage == TreeUse::Index {
        validate_index_key(key)?;
    } else {
        validate_key(key)?;
    }
    let old = lookup(tree, key, reads);
    if let Some(entry) = new {
        encode_entry(entry, tree.min_chunk_size)?;
        match (&entry.kind, tree.usage) {
            (EntryKind::Index { .. }, TreeUse::Index)
            | (EntryKind::Whiteout, TreeUse::OverlayLayer) => {}
            (EntryKind::Index { .. }, _)
            | (_, TreeUse::Index)
            | (EntryKind::Whiteout, _)
            | (EntryKind::Conflict { .. }, TreeUse::Surface) => return Err(Error::Tree),
            _ => {}
        }
        if tree.usage != TreeUse::Index {
            for (position, byte) in key.iter().enumerate() {
                if *byte == b'/'
                    && !lookup(tree, &key[..position], reads)
                        .is_some_and(|entry| entry.kind.permits_descendants())
                {
                    return Err(Error::Tree);
                }
            }
        }
    }

    if tree.usage != TreeUse::Index && !new.is_some_and(|entry| entry.kind.permits_descendants()) {
        let mut prefix = key.to_vec();
        prefix.push(b'/');
        // A component-prefix range starts at key + '/', not at key itself:
        // keys such as 'a!' may sort between 'a' and its descendants.
        let mut descendants = tree.cursor_from(&prefix);
        let has_descendants = descendants
            .next()
            .is_some_and(|item| item.key.starts_with(&prefix));
        *reads += descendants.node_reads();
        if has_descendants {
            return Err(Error::Tree);
        }
    }
    links::update(&tree.links, key, old, new, reads)
}

pub(super) fn insert<'a>(tree: &Tree<'a>, item: LeafItem<'a>) -> Result<Mutation<'a>, Error> {
    let mut reads = 0;
    if lookup(tree, &item.key, &mut reads) == Some(&item.entry) {
        let mut result = tree.unchanged();
        result.work.validation_reads = reads;
        return Ok(result);
    }
    let links = validate(tree, &item.key, Some(&item.entry), &mut reads)?;
    let key = item.key.clone();
    let mut result = edit(tree, &key, Some(item))?;
    result.tree.links = links;
    result.work.validation_reads = reads;
    Ok(result)
}

pub(super) fn remove<'a>(tree: &Tree<'a>, key: &[u8]) -> Result<Mutation<'a>, Error> {
    let mut reads = 0;
    if lookup(tree, key, &mut reads).is_none() {
        let mut result = tree.unchanged();
        result.work.validation_reads = reads;
        return Ok(result);
    }
    let links = validate(tree, key, None, &mut reads)?;
    let mut result = edit(tree, key, None)?;
    result.tree.links = links;
    result.work.validation_reads = reads;
    Ok(result)
}

struct Replacement<'a> {
    first: Vec<u8>,
    last: Vec<u8>,
    nodes: Vec<Rc<StoredNode<'a>>>,
}

fn edit<'a>(
    tree: &Tree<'a>,
    key: &[u8],
    item: Option<LeafItem<'a>>,
) -> Result<Mutation<'a>, Error> {
    let mut factory = Factory::new(tree.min_chunk_size, tree.usage);
    let mut replacement = edit_leaves(tree, key, item, &mut factory)?;
    for level in 1..=tree.root().level() {
        replacement = edit_parents(tree, level, replacement, &mut factory)?;
    }

    let mut nodes = replacement.nodes;
    let mut level = tree.root().level();
    if nodes.is_empty() {
        nodes = chunk::leaves(Vec::new(), &mut factory)?;
    }
    while nodes.len() > 1 {
        level = level.checked_add(1).ok_or(Error::Limit)?;
        nodes = chunk::parents(nodes, level, &mut factory)?;
    }
    let mut root = nodes.pop().ok_or(Error::Node)?;
    // A single node at the preceding level is already the canonical root.
    while root.children().len() == 1 {
        root = Rc::clone(&root.children()[0]);
    }
    let root = factory.root(root, tree.root.node.props.clone())?;
    Ok(tree.finish(root, factory))
}

fn edit_leaves<'a>(
    tree: &Tree<'a>,
    key: &[u8],
    item: Option<LeafItem<'a>>,
    factory: &mut Factory<'a>,
) -> Result<Replacement<'a>, Error> {
    let target_cursor = LevelCursor::seek(tree.root(), 0, key);
    let target = target_cursor.next.ok_or(Error::Node)?;
    let mut cursor = target_cursor.with_predecessor();
    let mut first = None;
    let mut last = Vec::new();
    let mut changed = false;
    let mut chunker = Chunker::new(0);
    let mut replacement_item = item;

    for node in cursor.by_ref() {
        let node_last = node.last_key().map_or(&[][..], |key| key);
        if first.is_none() {
            first = Some(node_last.to_vec());
        }
        last = node_last.to_vec();
        let NodeItems::Leaf(entries) = node.items() else {
            return Err(Error::Node);
        };
        let mut entries = entries.clone();
        if core::ptr::eq(node, target) {
            match entries.binary_search_by(|entry| entry.key.as_slice().cmp(key)) {
                Ok(index) => {
                    if let Some(item) = replacement_item.take() {
                        entries[index] = item;
                    } else {
                        entries.remove(index);
                    }
                }
                Err(index) => {
                    if let Some(item) = replacement_item.take() {
                        entries.insert(index, item);
                    }
                }
            }
            changed = true;
        }
        for item in entries {
            chunker.push(Item::Leaf(item), factory)?;
        }
        if changed && chunker.is_empty() {
            break;
        }
    }
    factory.work.node_reads += cursor.reads;
    Ok(Replacement {
        first: first.ok_or(Error::Node)?,
        last,
        nodes: chunker.finish(factory)?,
    })
}

fn edit_parents<'a>(
    tree: &Tree<'a>,
    level: u8,
    replacement: Replacement<'a>,
    factory: &mut Factory<'a>,
) -> Result<Replacement<'a>, Error> {
    let mut cursor = LevelCursor::seek(tree.root(), level, &replacement.first).with_predecessor();
    let mut chunker = Chunker::new(level);
    let mut inserted = false;
    let mut first = None;
    let mut last = Vec::new();

    for node in cursor.by_ref() {
        let node_last = node.last_key().ok_or(Error::Node)?;
        if first.is_none() {
            first = Some(node_last.to_vec());
        }
        last = node_last.to_vec();
        for child in node.children() {
            let child_key = child.last_key().ok_or(Error::Node)?;
            if child_key >= replacement.first.as_slice() && child_key <= replacement.last.as_slice()
            {
                if !inserted {
                    for new_child in &replacement.nodes {
                        chunker.push(Item::Child(Rc::clone(new_child)), factory)?;
                    }
                    inserted = true;
                }
            } else {
                chunker.push(Item::Child(Rc::clone(child)), factory)?;
            }
        }
        if inserted && node_last >= replacement.last.as_slice() && chunker.is_empty() {
            break;
        }
    }
    if !inserted {
        return Err(Error::Node);
    }
    factory.work.node_reads += cursor.reads;
    Ok(Replacement {
        first: first.ok_or(Error::Node)?,
        last,
        nodes: chunker.finish(factory)?,
    })
}
