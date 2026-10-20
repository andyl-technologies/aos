//! Derives canonical target markers while preserving every actual graft occurrence.
//!
//! These transformations provide no disclosure authority. The paired producer
//! derives markers from completed source history, then signs and fully verifies
//! the rebuilt destination and its exact certificates before publication.

use std::collections::{BTreeMap, BTreeSet};

use crate::guard::{StagedUpload, TreeEvidence};
use crate::store::StoreFailure;
use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Attribute, Entry, EntryKind, LeafItem};

use super::invalid;

enum Stage {
    Enter(Digest),
    Finish(Digest),
}

/// Holds rebuilt canonical objects and the exact old-to-new root correspondence.
pub(super) struct MarkerTrees {
    /// Identifies the rebuilt canonical view root after marker and graft replacement.
    pub(super) root: Digest,
    /// Maps each traversed original canonical root to its rebuilt canonical root.
    ///
    /// Shared graft targets have one mapping; unchanged roots may map to themselves.
    pub(super) roots: BTreeMap<Digest, Digest>,
    /// Carries deduplicated encoded Node uploads emitted by the rebuilt trees.
    ///
    /// These staged bytes require separate admission and publication checks.
    pub(super) uploads: Vec<StagedUpload>,
}

/// Describes one actual destination occurrence selected by the private producer.
pub(super) struct MarkerOccurrence {
    /// Identifies the original canonical root containing the selected destination entry.
    pub(super) root: Digest,
    /// Names the entry's complete tree key relative to its containing root.
    ///
    /// This key has no leading slash. The absolute destination path is the root
    /// occurrence's absolute path joined with this key, including nested components.
    pub(super) path: Vec<u8>,
    /// Identifies the source entry's historical introducer encoded into its marker.
    ///
    /// The digest alone supplies no signature, Original evidence or current permission.
    pub(super) introducer: Digest,
    /// Records the destination occurrence's effective domain under authoring policy.
    ///
    /// Normalization rejects conflicting introducer/domain pairs for a shared root/key;
    /// this label supplies no disclosure authority.
    pub(super) destination_domain: String,
}

/// Installs only independently derived public-introducer marker values.
///
/// # Errors
/// Rejects missing or unsupported entries, incomplete grafts, cyclic topology
/// and invalid rebuilt canonical trees.
pub(super) fn normalize_markers(
    evidence: &TreeEvidence,
    occurrences: &[MarkerOccurrence],
    minimum_chunk_size: u64,
) -> Result<MarkerTrees, StoreFailure> {
    let mut encoded_markers = BTreeMap::new();
    let mut marker_scopes = BTreeMap::new();
    for occurrence in occurrences {
        let MarkerOccurrence {
            root,
            path,
            introducer,
            destination_domain,
        } = occurrence;
        let selector = (*root, path.clone());
        let scope = (*introducer, destination_domain.as_str());
        if marker_scopes
            .get(&selector)
            .is_some_and(|prior| prior != &scope)
        {
            // A shared canonical root cannot encode different markers or
            // destination domains for its separate graft occurrences.
            return Err(invalid());
        }
        marker_scopes.insert(selector.clone(), scope);
        if !evidence.roots.contains(root) {
            return Err(invalid());
        }
        let tree = evidence.tree(*root, minimum_chunk_size)?;
        let entry = tree.get(path).ok_or_else(invalid)?;
        if !matches!(
            entry.kind,
            EntryKind::File { .. } | EntryKind::Directory { .. } | EntryKind::Symlink { .. }
        ) {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        terrane_format::cbor::write_bytes(&mut bytes, introducer);
        encoded_markers.insert(selector, bytes);
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
                        entry.attrs.push(Attribute {
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
    let mut pending = vec![entry];
    while let Some(entry) = pending.pop() {
        match &entry.kind {
            EntryKind::Tree { root, .. } => {
                roots.insert(*root);
            }
            EntryKind::Conflict { candidates, base } => {
                if let Some(Some(base)) = base {
                    pending.push(base);
                }
                pending.extend(candidates.iter().rev());
            }
            _ => {}
        }
    }
}

fn replace_roots(
    entry: &mut Entry<'_>,
    roots: &BTreeMap<Digest, Digest>,
) -> Result<(), StoreFailure> {
    let mut pending = vec![entry];
    while let Some(entry) = pending.pop() {
        match &mut entry.kind {
            EntryKind::Tree { root, .. } => {
                *root = *roots.get(root).ok_or_else(invalid)?;
            }
            EntryKind::Conflict { candidates, base } => {
                if let Some(Some(base)) = base {
                    pending.push(base.as_mut());
                }
                pending.extend(candidates.iter_mut().rev());
            }
            _ => {}
        }
    }
    Ok(())
}
