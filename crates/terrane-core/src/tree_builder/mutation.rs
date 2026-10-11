//! Rechunks edited key ranges until canonical boundaries resynchronize.

use alloc::{rc::Rc, vec::Vec};

use crate::tree_format::{
    Entry, EntryKind, LeafItem, NodeItems, TreeUse, encode_entry, validate_index_key, validate_key,
};

use super::{
    Error, Factory, Mutation, NewLevelWork, StoredNode, Tree, chunk, cursor::LevelCursor, links,
};

pub(super) fn lookup<'tree, 'a>(
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
    validate_map_entry(tree, key, new, reads)?;
    let old = lookup(tree, key, reads);
    links::update(&tree.links, key, old, new, reads)
}

pub(super) fn validate_map_entry<'a>(
    tree: &Tree<'a>,
    key: &[u8],
    new: Option<&Entry<'a>>,
    reads: &mut usize,
) -> Result<(), Error> {
    if tree.usage == TreeUse::Index {
        validate_index_key(key)?;
    } else {
        validate_key(key)?;
    }
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
    Ok(())
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
    let members = links::update_members(
        &tree.members,
        &key,
        lookup(tree, &key, &mut reads),
        Some(&item.entry),
        &mut reads,
    );
    let mut result = edit(tree, &key, Some(item))?;
    result.tree.members = members;
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
    let members = links::update_members(
        &tree.members,
        key,
        lookup(tree, key, &mut reads),
        None,
        &mut reads,
    );
    let mut result = edit(tree, key, None)?;
    result.tree.members = members;
    result.tree.links = links;
    result.work.validation_reads = reads;
    Ok(result)
}

pub(super) struct Replacement<'a> {
    pub(super) first: Vec<u8>,
    pub(super) last: Vec<u8>,
    pub(super) nodes: Vec<Rc<StoredNode<'a>>>,
}

pub(super) fn edit<'a>(
    tree: &Tree<'a>,
    key: &[u8],
    item: Option<LeafItem<'a>>,
) -> Result<Mutation<'a>, Error> {
    let edits = alloc::vec![(key.to_vec(), item.map(|item| item.entry))];
    super::batch::edit(tree, &edits)
}

pub(super) fn finish_nodes<'a>(
    tree: &Tree<'a>,
    mut nodes: Vec<Rc<StoredNode<'a>>>,
    factory: &mut Factory<'a>,
) -> Result<Rc<StoredNode<'a>>, Error> {
    let mut level = tree.root().level();
    if nodes.is_empty() {
        let before = factory.work.stream;
        nodes = chunk::leaves(Vec::new(), factory)?;
        factory
            .work
            .completion
            .combine(factory.work.stream.since(before));
    }
    loop {
        factory.work.stream.frontier_checks += 1;
        factory.work.completion.frontier_checks += 1;
        if nodes.len() <= 1 {
            break;
        }
        level = level.checked_add(1).ok_or(Error::Limit)?;
        let first = nodes
            .first()
            .and_then(|node| node.first_key())
            .ok_or(Error::Node)?
            .to_vec();
        let last = nodes
            .last()
            .and_then(|node| node.last_key())
            .ok_or(Error::Node)?
            .to_vec();
        let before = factory.work.stream;
        nodes = chunk::parents(nodes, level, factory)?;
        factory.work.new_levels.push(NewLevelWork {
            level,
            first,
            last,
            work: factory.work.stream.since(before),
        });
    }
    let mut root = nodes.pop().ok_or(Error::Node)?;
    // A single node at the preceding level is already the canonical root.
    loop {
        factory.work.stream.frontier_checks += 1;
        factory.work.completion.frontier_checks += 1;
        if root.children().len() != 1 {
            break;
        }
        factory.work.stream.item_reads += 1;
        factory.work.completion.item_reads += 1;
        root = Rc::clone(&root.children()[0]);
    }
    let root = factory.root(root, tree.root.node.props.clone())?;
    Ok(root)
}

pub(super) fn edit_parents<'a>(
    tree: &Tree<'a>,
    level: u8,
    replacement: Replacement<'a>,
    factory: &mut Factory<'a>,
) -> Result<Replacement<'a>, Error> {
    let mut replacements = super::batch::parents(tree, level, alloc::vec![replacement], factory)?;
    if replacements.len() != 1 {
        return Err(Error::Node);
    }
    replacements.pop().ok_or(Error::Node)
}

/// Locates a known old node while accounting for the certification seek.
pub(super) fn lookup_node<'tree, 'a>(
    tree: &'tree Tree<'a>,
    level: u8,
    key: &[u8],
    reads: &mut usize,
) -> Result<&'tree StoredNode<'a>, Error> {
    let mut cursor = LevelCursor::seek(tree.root(), level, key);
    let node = cursor.next().ok_or(Error::Node)?;
    *reads += cursor.reads;
    Ok(node)
}
