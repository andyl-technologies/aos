//! Derives canonical target markers while preserving every actual graft occurrence.
//!
//! These transformations provide no disclosure authority. The paired producer
//! derives markers from completed source history, then signs and fully verifies
//! the rebuilt destination and its exact certificates before publication.

use std::collections::{BTreeMap, BTreeSet};

use crate::guard::{StagedUpload, TreeEvidence};
use crate::store::StoreFailure;
use terrane_core::identity::{Digest, IdentityKind};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{Entry, EntryKind, LeafItem, Property};

use super::invalid;

enum Stage {
    Enter(Digest),
    Finish(Digest),
}

/// Holds rebuilt canonical objects and the exact old-to-new root correspondence.
pub(super) struct MarkerTrees {
    pub(super) root: Digest,
    pub(super) roots: BTreeMap<Digest, Digest>,
    pub(super) uploads: Vec<StagedUpload>,
}

/// Installs only independently derived public-introducer marker values.
pub(super) fn normalize_markers(
    evidence: &TreeEvidence,
    markers: &BTreeMap<(Digest, Vec<u8>), Digest>,
    minimum_chunk_size: u64,
) -> Result<MarkerTrees, StoreFailure> {
    let mut encoded_markers = BTreeMap::new();
    for ((root, path), introducer) in markers {
        if !evidence.roots.contains(root) {
            return Err(invalid());
        }
        let tree = evidence.tree(*root, minimum_chunk_size)?;
        let entry = tree.get(path).ok_or_else(invalid)?;
        if !matches!(
            entry.kind,
            EntryKind::File { .. } | EntryKind::Directory | EntryKind::Symlink { .. }
        ) {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        terrane_core::cbor::write_bytes(&mut bytes, introducer);
        encoded_markers.insert((*root, path.clone()), bytes);
    }

    let mut roots = BTreeMap::new();
    let mut nodes = BTreeMap::new();
    let mut active = BTreeSet::new();
    let mut pending = vec![Stage::Enter(evidence.root)];
    while let Some(stage) = pending.pop() {
        match stage {
            Stage::Enter(root) => {
                if roots.contains_key(&root) {
                    continue;
                }
                if !active.insert(root) {
                    return Err(invalid());
                }
                pending.push(Stage::Finish(root));
                let tree = evidence.tree(root, minimum_chunk_size)?;
                let mut children = BTreeSet::new();
                for item in tree.iter() {
                    collect_roots(&item.entry, &mut children);
                }
                pending.extend(children.into_iter().rev().map(Stage::Enter));
            }
            Stage::Finish(root) => {
                let tree = evidence.tree(root, minimum_chunk_size)?;
                let mut entries = Vec::new();
                for item in tree.iter() {
                    let mut entry = item.entry.clone();
                    replace_roots(&mut entry, &roots)?;
                    if let Some(marker) = encoded_markers.get(&(root, item.key.clone())) {
                        entry
                            .attrs
                            .retain(|attribute| attribute.name != "provenance.reintroduced-from");
                        entry.attrs.push(Property {
                            name: "provenance.reintroduced-from",
                            value: marker,
                        });
                        entry.attrs.sort_by_key(|attribute| attribute.name);
                        entry.attrs_present = true;
                    }
                    entries.push(LeafItem {
                        key: item.key.clone(),
                        entry,
                    });
                }
                let rebuilt = Tree::build(
                    entries,
                    tree.props().map(<[_]>::to_vec),
                    minimum_chunk_size,
                    tree.usage(),
                )
                .map_err(|_| invalid())?;
                for node in rebuilt.nodes() {
                    let bytes = node.encoded().to_vec();
                    if nodes
                        .get(&node.identity())
                        .is_some_and(|prior| prior != &bytes)
                    {
                        return Err(invalid());
                    }
                    nodes.insert(node.identity(), bytes);
                }
                roots.insert(root, rebuilt.root_identity());
                active.remove(&root);
            }
        }
    }

    Ok(MarkerTrees {
        root: *roots.get(&evidence.root).ok_or_else(invalid)?,
        roots,
        uploads: nodes
            .into_values()
            .map(|bytes| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            })
            .collect(),
    })
}

fn collect_roots(entry: &Entry<'_>, roots: &mut BTreeSet<Digest>) {
    match &entry.kind {
        EntryKind::Tree { root, .. } => {
            roots.insert(*root);
        }
        EntryKind::Conflict { candidates, base } => {
            for candidate in candidates {
                collect_roots(candidate, roots);
            }
            if let Some(Some(base)) = base {
                collect_roots(base, roots);
            }
        }
        _ => {}
    }
}

fn replace_roots(
    entry: &mut Entry<'_>,
    roots: &BTreeMap<Digest, Digest>,
) -> Result<(), StoreFailure> {
    match &mut entry.kind {
        EntryKind::Tree { root, .. } => {
            *root = *roots.get(root).ok_or_else(invalid)?;
        }
        EntryKind::Conflict { candidates, base } => {
            for candidate in candidates {
                replace_roots(candidate, roots)?;
            }
            if let Some(Some(base)) = base {
                replace_roots(base, roots)?;
            }
        }
        _ => {}
    }
    Ok(())
}
