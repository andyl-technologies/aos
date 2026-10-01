//! Loads complete canonical tree witnesses anchored to immutable commit identities.

use std::collections::{BTreeMap, BTreeSet};

use terrane_core::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_core::refs::Commit;
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{self, EntryKind, NodeItems, Property, TreeUse};

use super::StagedUpload;
use crate::store::{ContentStore, InvalidReason, StoreErrorKind, StoreFailure};

/// Complete immutable metadata, whose IDs and canonical structure are checked.
pub(crate) struct TreeEvidence {
    pub(crate) commit: Option<Commit>,
    pub(crate) root: Digest,
    /// Root-identity default used only when no raw or inherited domain resolves.
    pub(crate) default_domain: String,
    pub(crate) nodes: BTreeMap<Digest, Vec<u8>>,
    pub(crate) roots: BTreeSet<Digest>,
}

type PolicyLayers<'a> = Vec<(Vec<Property<'a>>, Vec<Property<'a>>)>;

/// One root occurrence retains its full graft path, even when hashes repeat.
pub(crate) struct RootOccurrence<'a> {
    pub(crate) root: Digest,
    pub(crate) path: Vec<u8>,
    pub(crate) layers: Vec<(Vec<Property<'a>>, Vec<Property<'a>>)>,
}

impl TreeEvidence {
    pub(crate) async fn load_commit<S: ContentStore>(
        store: &S,
        identity: Digest,
        min_chunk_size: u64,
    ) -> Result<Self, StoreFailure> {
        let id = TERRANE_V1
            .from_digest(IdentityKind::Commit, &identity)
            .map_err(|_| invalid())?;
        let bytes = store.get(&id, None).await?;
        TERRANE_V1.verify(&id, &bytes).map_err(|_| invalid())?;
        let commit = Commit::decode(&bytes).map_err(|_| invalid())?;
        let mut evidence = Self::load_tree(store, commit.tree, &[], min_chunk_size).await?;
        evidence.commit = Some(commit);
        Ok(evidence)
    }

    pub(crate) async fn load_tree<S: ContentStore>(
        store: &S,
        root: Digest,
        uploads: &[StagedUpload],
        min_chunk_size: u64,
    ) -> Result<Self, StoreFailure> {
        let mut staged = BTreeMap::new();
        for upload in uploads {
            if let StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } = upload
            {
                let identity = TERRANE_V1
                    .calculate(IdentityKind::Node, bytes)
                    .and_then(|value| value.terrane_v1_digest())
                    .map_err(|_| invalid())?;
                if staged.insert(identity, bytes.clone()).is_some() {
                    return Err(invalid());
                }
            }
        }
        let mut evidence = Self {
            commit: None,
            root,
            default_domain: crate::domain::private_default(
                &TERRANE_V1
                    .from_digest(IdentityKind::Node, &root)
                    .map_err(|_| invalid())?,
            ),
            nodes: BTreeMap::new(),
            roots: BTreeSet::from([root]),
        };
        let mut pending = vec![(root, true)];
        while let Some((identity, is_root)) = pending.pop() {
            if evidence.nodes.contains_key(&identity) {
                continue;
            }
            let id = TERRANE_V1
                .from_digest(IdentityKind::Node, &identity)
                .map_err(|_| invalid())?;
            let bytes = match staged.remove(&identity) {
                Some(bytes) => bytes,
                None => store.get(&id, None).await?,
            };
            TERRANE_V1.verify(&id, &bytes).map_err(|_| invalid())?;
            let node =
                tree_format::decode_node_for(&bytes, is_root, min_chunk_size, TreeUse::Ordinary)
                    .map_err(|_| invalid())?;
            match &node.items {
                NodeItems::Internal(children) => {
                    pending.extend(children.iter().rev().map(|child| (child.child, false)))
                }
                NodeItems::Leaf(items) => {
                    for item in items {
                        let mut entries = vec![&item.entry];
                        while let Some(entry) = entries.pop() {
                            match &entry.kind {
                                EntryKind::Tree { root, .. } => {
                                    evidence.roots.insert(*root);
                                    pending.push((*root, true));
                                }
                                EntryKind::Conflict { candidates, base } => {
                                    entries.extend(candidates);
                                    if let Some(Some(base)) = base {
                                        entries.push(base);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            drop(node);
            evidence.nodes.insert(identity, bytes);
        }
        // Rebuilding checks complete summaries, key order, hard links and the
        // canonical boundaries, rather than trusting individually valid nodes.
        for root in &evidence.roots {
            evidence.tree(*root, min_chunk_size)?;
        }
        Ok(evidence)
    }

    pub(crate) fn tree(&self, root: Digest, min_chunk_size: u64) -> Result<Tree<'_>, StoreFailure> {
        let root_bytes = self.nodes.get(&root).ok_or_else(invalid)?;
        let root_node =
            tree_format::decode_node_for(root_bytes, true, min_chunk_size, TreeUse::Ordinary)
                .map_err(|_| invalid())?;
        let properties = root_node.props.clone();
        let mut entries = Vec::new();
        let mut pending = vec![(root, true)];
        let mut seen = BTreeSet::new();
        while let Some((id, is_root)) = pending.pop() {
            if !seen.insert(id) {
                return Err(invalid());
            }
            let bytes = self.nodes.get(&id).ok_or_else(invalid)?;
            let node =
                tree_format::decode_node_for(bytes, is_root, min_chunk_size, TreeUse::Ordinary)
                    .map_err(|_| invalid())?;
            match node.items {
                NodeItems::Leaf(items) => entries.extend(items),
                NodeItems::Internal(children) => {
                    pending.extend(children.into_iter().rev().map(|child| (child.child, false)))
                }
            }
        }
        let tree = Tree::build(entries, properties, min_chunk_size, TreeUse::Ordinary)
            .map_err(|_| invalid())?;
        if tree.root_identity() != root {
            return Err(invalid());
        }
        Ok(tree)
    }

    pub(crate) fn policy_path(
        &self,
        path: &[u8],
        min_chunk_size: u64,
    ) -> Result<PolicyLayers<'_>, StoreFailure> {
        if path.first() != Some(&b'/') || path.windows(2).any(|pair| pair == b"//") {
            return Err(invalid());
        }
        let mut relative = path.strip_prefix(b"/").ok_or_else(invalid)?;
        if !relative.is_empty() {
            tree_format::validate_key(relative).map_err(|_| invalid())?;
        }
        let mut root = self.root;
        let mut layers = Vec::new();
        let mut seen = BTreeSet::new();
        let mut overrides = Vec::new();
        loop {
            if !seen.insert(root) || seen.len() > tree_format::MAX_GRAFT_DEPTH + 1 {
                return Err(invalid());
            }
            let tree = self.tree(root, min_chunk_size)?;
            layers.push((tree.props().map_or_else(Vec::new, <[_]>::to_vec), overrides));
            let selected = tree
                .iter()
                .filter_map(|item| {
                    let EntryKind::Tree { root, props } = &item.entry.kind else {
                        return None;
                    };
                    let remainder = relative.strip_prefix(item.key.as_slice())?;
                    if remainder.is_empty() {
                        Some((
                            *root,
                            &[][..],
                            props.clone().unwrap_or_default(),
                            item.key.len(),
                        ))
                    } else {
                        Some((
                            *root,
                            remainder.strip_prefix(b"/")?,
                            props.clone().unwrap_or_default(),
                            item.key.len(),
                        ))
                    }
                })
                .max_by_key(|(_, _, _, length)| *length);
            let Some((next_root, remainder, next_overrides, _)) = selected else {
                return Ok(layers);
            };
            root = next_root;
            relative = remainder;
            overrides = next_overrides;
        }
    }

    pub(crate) fn occurrences(
        &self,
        min_chunk_size: u64,
    ) -> Result<Vec<RootOccurrence<'_>>, StoreFailure> {
        let mut output = Vec::new();
        let mut pending = vec![(self.root, b"/".to_vec(), Vec::new(), Vec::new(), Vec::new())];
        while let Some((root, path, mut layers, overrides, mut ancestors)) = pending.pop() {
            if ancestors.contains(&root) || ancestors.len() > tree_format::MAX_GRAFT_DEPTH {
                return Err(invalid());
            }
            ancestors.push(root);
            let tree = self.tree(root, min_chunk_size)?;
            layers.push((tree.props().map_or_else(Vec::new, <[_]>::to_vec), overrides));
            for item in tree.iter() {
                let mut candidates = vec![&item.entry];
                while let Some(entry) = candidates.pop() {
                    match &entry.kind {
                        EntryKind::Tree { root, props } => {
                            let mut target_path = path.clone();
                            if target_path != b"/" {
                                target_path.push(b'/');
                            }
                            target_path.extend_from_slice(&item.key);
                            pending.push((
                                *root,
                                target_path,
                                layers.clone(),
                                props.clone().unwrap_or_default(),
                                ancestors.clone(),
                            ));
                        }
                        EntryKind::Conflict {
                            candidates: sides,
                            base,
                        } => {
                            candidates.extend(sides);
                            if let Some(Some(base)) = base {
                                candidates.push(base);
                            }
                        }
                        _ => {}
                    }
                }
            }
            output.push(RootOccurrence { root, path, layers });
        }
        Ok(output)
    }
}

pub(crate) fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
}
