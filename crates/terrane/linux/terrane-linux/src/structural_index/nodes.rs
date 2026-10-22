//! Reconstructs canonical node graphs before compiling structural metadata.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{self, EntryKind, NodeItems, TreeUse};

use super::{Error, compile_tree};

/// Compiles a complete raw node inventory under the Terrane v1 identity profile.
///
/// The compiler verifies each reached Node's domain-separated identity and
/// canonical encoding, rebuilds each ordinary tree to check its complete
/// cross-node shape and summaries, and recursively resolves graft roots.
/// Chunk and manifest content is neither accepted as a dependency nor fetched.
/// Unreachable inventory members are ignored but charged to the metadata bound.
///
/// The metadata budget counts each inventory key's 32 bytes plus its encoded
/// value, before decoding or tree reconstruction. Entry and output-byte bounds
/// additionally apply to the fully expanded structural index, including root.
/// A caller must independently authenticate the selected root, configure its
/// immutable chunk geometry, and authorize disclosure of its metadata.
///
/// # Errors
/// Refuses excessive metadata or expansion, missing or mismatched Nodes,
/// malformed or noncanonical trees, incompatible ordinary entries, invalid
/// graft graphs and exceeded output limits. No partial index is returned.
pub fn compile_nodes(
    root: Digest,
    nodes: &BTreeMap<Digest, Vec<u8>>,
    minimum_chunk_size: u64,
    max_entries: u32,
    max_bytes: usize,
    max_metadata_bytes: usize,
) -> Result<Vec<u8>, Error> {
    if max_entries == 0 || minimum_chunk_size == 0 {
        return Err(Error::Limit);
    }
    let mut metadata_bytes = 0usize;
    for bytes in nodes.values() {
        metadata_bytes = metadata_bytes
            .checked_add(32)
            .and_then(|size| size.checked_add(bytes.len()))
            .ok_or(Error::Limit)?;
        if metadata_bytes > max_metadata_bytes {
            return Err(Error::Limit);
        }
    }

    let mut pending = vec![root];
    let mut trees = BTreeMap::new();
    let mut reconstructed_entries = 0u64;
    while let Some(identity) = pending.pop() {
        if trees.contains_key(&identity) {
            continue;
        }
        let tree = reconstruct(identity, nodes, minimum_chunk_size, max_entries)?;
        // Every distinct reached tree contributes its entries at least once to
        // the expansion. Bound shared-subtree reconstruction before retaining
        // another complete tree, rather than relying on the later output check.
        reconstructed_entries = reconstructed_entries
            .checked_add(tree.len())
            .ok_or(Error::Limit)?;
        if reconstructed_entries >= u64::from(max_entries) {
            return Err(Error::Limit);
        }
        for item in tree.iter() {
            if let EntryKind::Tree { root, .. } = &item.entry.kind {
                pending.push(*root);
            }
        }
        trees.insert(identity, tree);
    }
    let root = trees.remove(&root).ok_or(Error::Tree)?;
    compile_tree(&root, &trees, max_entries, max_bytes)
}

fn reconstruct<'a>(
    root: Digest,
    nodes: &'a BTreeMap<Digest, Vec<u8>>,
    minimum: u64,
    max_entries: u32,
) -> Result<Tree<'a>, Error> {
    let mut pending = vec![(root, true)];
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    let mut properties = None;
    while let Some((identity, is_root)) = pending.pop() {
        if !seen.insert(identity) {
            return Err(Error::Tree);
        }
        let bytes = nodes.get(&identity).ok_or(Error::Tree)?;
        let actual = TERRANE_V1
            .calculate(IdentityKind::Node, bytes)
            .map_err(|_| Error::Tree)?;
        if actual.digest() != identity {
            return Err(Error::Tree);
        }
        let node = tree_format::decode_node(bytes, is_root, minimum).map_err(|_| Error::Tree)?;
        if is_root {
            properties = node.props.clone();
        }
        match node.items {
            NodeItems::Leaf(items) => {
                if entries
                    .len()
                    .checked_add(items.len())
                    .is_none_or(|count| count >= max_entries as usize)
                {
                    return Err(Error::Limit);
                }
                entries.extend(items);
            }
            NodeItems::Internal(children) => {
                pending.extend(children.into_iter().rev().map(|child| (child.child, false)));
            }
        }
    }
    let tree =
        Tree::build(entries, properties, minimum, TreeUse::Ordinary).map_err(|_| Error::Tree)?;
    if tree.root_identity() != root {
        return Err(Error::Tree);
    }
    Ok(tree)
}
