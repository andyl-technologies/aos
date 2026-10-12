//! Encodes specialized rows and resolves only affected local namespace paths.

use alloc::vec::Vec;

use super::{ByteArena, Error, RouteValue, UpdateWork};
use crate::{
    cbor,
    identity::Digest,
    indexing::{
        carrier::{SemanticContext, classify_entry, validate_namespace_attributes},
        incremental::SourceLookup,
    },
    tree_builder::Tree,
    tree_format::{Attribute, Entry, EntryKind, NodeItems, TreeUse},
};

/// Classifies an optional carrier entry into its logical row value.
///
/// # Errors
/// Rejects entries outside the closed carrier shape or malformed continuation bytes.
pub(super) fn value(
    context: SemanticContext,
    entry: Option<&Entry<'_>>,
) -> Result<Option<RouteValue>, Error> {
    entry
        .map(|entry| {
            let row = classify_entry(context, entry)?;
            Ok(RouteValue::Row {
                object: row.object(),
                route: row.route(),
            })
        })
        .transpose()
}

/// Builds a specialized row, copying any encoded continuation into stable storage.
///
/// # Errors
/// Rejects binding values, structural-byte count overflow or arena allocation refusal.
pub(super) fn entry<'a>(
    arena: &'a ByteArena,
    value: &RouteValue,
    work: &mut UpdateWork,
) -> Result<Entry<'a>, Error> {
    let RouteValue::Row { object, route } = value else {
        return Err(Error::Transition);
    };
    let attrs = if let Some(route) = route {
        let mut bytes = Vec::new();
        cbor::write_bytes(&mut bytes, route);
        super::accounting::add(&mut work.structural_bytes_encoded, bytes.len())?;
        alloc::vec![Attribute {
            name: "index.occurrences",
            value: arena.copy(&bytes)?
        }]
    } else {
        Vec::new()
    };
    Ok(Entry {
        kind: EntryKind::Index {
            targets: alloc::vec![*object],
        },
        attrs,
        attrs_present: route.is_some(),
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    })
}

/// Resolves local graft hops through checked source Trees, returning absent paths.
///
/// # Errors
/// Rejects unavailable sources, mismatched identities/use/geometry, conflicts,
/// invalid graft attributes and lookup or path-accounting overflow.
pub(super) fn resolve(
    sources: &SourceLookup<'_, '_>,
    owner: Digest,
    hops: &[Vec<u8>],
    minimum: u64,
    work: &mut UpdateWork,
) -> Result<Option<Digest>, Error> {
    let mut root = owner;
    for key in hops {
        let tree = checked_tree(sources, root, minimum, work)?;
        let entry = get(tree, key, work)?;
        match entry.map(|entry| &entry.kind) {
            Some(EntryKind::Tree { root: child, .. }) => {
                if let Some(entry) = entry {
                    validate_namespace_attributes(2, entry)?;
                }
                root = *child;
            }
            _ => return Ok(None),
        }
    }
    checked_tree(sources, root, minimum, work)?;
    Ok(Some(root))
}

fn checked_tree<'graph, 'a>(
    sources: &SourceLookup<'graph, 'a>,
    root: Digest,
    minimum: u64,
    work: &mut UpdateWork,
) -> Result<&'graph Tree<'a>, Error> {
    let tree = sources.tree(root, &mut work.source_lookups)?;
    super::accounting::add(&mut work.source_roots_checked, 1)?;
    if tree.root_identity() != root
        || !matches!(tree.usage(), TreeUse::Ordinary | TreeUse::OverlayLayer)
        || tree.min_chunk_size() != minimum
        || tree.has_conflicts()
    {
        return Err(Error::Binding);
    }
    Ok(tree)
}

fn get<'tree, 'a>(
    tree: &'tree Tree<'a>,
    key: &[u8],
    work: &mut UpdateWork,
) -> Result<Option<&'tree Entry<'a>>, Error> {
    search(
        tree,
        key,
        &mut work.source_path_nodes,
        &mut work.source_path_comparisons,
    )
}

/// Borrows an auxiliary row through a measured physical path search.
///
/// # Errors
/// Rejects path-node or key-comparison count overflow.
pub(super) fn auxiliary<'tree, 'a>(
    tree: &'tree Tree<'a>,
    key: &[u8],
    work: &mut UpdateWork,
) -> Result<Option<&'tree Entry<'a>>, Error> {
    search(
        tree,
        key,
        &mut work.auxiliary_path_nodes,
        &mut work.auxiliary_path_comparisons,
    )
}

fn search<'tree, 'a>(
    tree: &'tree Tree<'a>,
    key: &[u8],
    nodes: &mut usize,
    comparisons: &mut usize,
) -> Result<Option<&'tree Entry<'a>>, Error> {
    let mut node = tree.root();
    loop {
        super::accounting::add(nodes, 1)?;
        match node.items() {
            NodeItems::Leaf(items) => {
                let mut low = 0;
                let mut high = items.len();
                while low < high {
                    let middle = low + (high - low) / 2;
                    super::accounting::add(comparisons, 1)?;
                    match items[middle].key.as_slice().cmp(key) {
                        core::cmp::Ordering::Less => low = middle + 1,
                        core::cmp::Ordering::Greater => high = middle,
                        core::cmp::Ordering::Equal => return Ok(Some(&items[middle].entry)),
                    }
                }
                return Ok(None);
            }
            NodeItems::Internal(items) => {
                let mut low = 0;
                let mut high = items.len();
                while low < high {
                    let middle = low + (high - low) / 2;
                    super::accounting::add(comparisons, 1)?;
                    if items[middle].last_key.as_slice() < key {
                        low = middle + 1;
                    } else {
                        high = middle;
                    }
                }
                let Some(child) = node.children().get(low) else {
                    return Ok(None);
                };
                node = child.as_ref();
            }
        }
    }
}
