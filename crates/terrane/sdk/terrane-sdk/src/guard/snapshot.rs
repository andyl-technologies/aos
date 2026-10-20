//! Loads complete canonical tree witnesses anchored to immutable commit identities.

#[cfg(all(feature = "std", unix))]
pub(crate) mod layers;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

// Captures addresses within the existing complete canonical validator.
mod grafts;
pub use grafts::IndexGraftValidationWork;
pub(crate) use grafts::ValidatedGrafts;

use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::refs::Commit;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{self, EntryKind, NodeItems, Property, TreeUse};

use super::StagedUpload;
use crate::store::{ContentStore, InvalidReason, StoreErrorKind, StoreFailure};

/// Complete immutable metadata, whose IDs and canonical structure are checked.
pub(crate) struct TreeEvidence {
    /// Records the explicit operation context; ordinary loading never selects a layer.
    pub(crate) usage: TreeUse,
    /// Roots proven completely compatible with ordinary canonical tree semantics.
    pub(crate) ordinary_roots: BTreeSet<Digest>,
    /// Retains the decoded commit when loading through an addressed commit.
    pub(crate) commit: Option<Commit>,
    /// Identifies the canonical namespace root addressed by this evidence.
    pub(crate) root: Digest,
    /// Root-identity default used only when no raw or inherited domain resolves.
    pub(crate) default_domain: String,
    /// Retains exact addressed Node buffers for canonical reconstruction.
    pub(crate) nodes: BTreeMap<Digest, Vec<u8>>,
    /// Lists the physically reached tree roots in the complete metadata graph.
    pub(crate) roots: BTreeSet<Digest>,
    /// Root/usage/geometry-bound addresses installed only after canonical validation.
    pub(crate) grafts: Option<Arc<ValidatedGrafts>>,
}

type PolicyLayers<'a> = Vec<(Vec<Property<'a>>, Vec<Property<'a>>)>;

/// Caches physical-owner metadata without rebuilding canonical namespace trees.
struct OwnerMetadata<'a> {
    properties: Vec<Property<'a>>,
    grafts: Vec<GraftMetadata<'a>>,
}

struct GraftMetadata<'a> {
    key: Vec<u8>,
    root: Digest,
    overrides: Vec<Property<'a>>,
}

/// One root occurrence retains its full graft path, even when hashes repeat.
pub(crate) struct RootOccurrence<'a> {
    /// Identifies the canonical tree root at this particular occurrence.
    pub(crate) root: Digest,
    /// Names the absolute path of this particular root occurrence.
    pub(crate) path: Vec<u8>,
    /// Retains ancestor-first root properties paired with each graft override.
    pub(crate) layers: Vec<(Vec<Property<'a>>, Vec<Property<'a>>)>,
}

impl TreeEvidence {
    /// Loads an addressed commit and its complete ordinary canonical tree metadata.
    ///
    /// Signature and current authority checks remain separate.
    ///
    /// # Errors
    /// Rejects malformed or mismatched identities and incomplete canonical trees;
    /// preserves originating metadata read failures.
    pub(crate) async fn load_commit<S: ContentStore>(
        store: &S,
        identity: Digest,
        min_chunk_size: u64,
    ) -> Result<Self, StoreFailure> {
        Self::load_commit_for(store, identity, min_chunk_size, TreeUse::Ordinary).await
    }

    /// Loads an addressed signed object under an explicit owning namespace context.
    ///
    /// # Errors
    /// Rejects identity mismatch, malformed canonical metadata, missing dependencies
    /// and metadata invalid for the supplied tree use. Signature authority is separate.
    pub(super) async fn load_commit_for<S: ContentStore>(
        store: &S,
        identity: Digest,
        min_chunk_size: u64,
        usage: TreeUse,
    ) -> Result<Self, StoreFailure> {
        let id = TERRANE_V1
            .from_digest(IdentityKind::Commit, &identity)
            .map_err(|_| invalid())?;
        let bytes = store.get(&id, None).await?;
        TERRANE_V1.verify(&id, &bytes).map_err(|_| invalid())?;
        let commit = Commit::decode(&bytes).map_err(|_| invalid())?;
        let mut evidence =
            Self::load_tree_for(store, commit.tree, &[], min_chunk_size, usage).await?;
        evidence.commit = Some(commit);
        Ok(evidence)
    }

    /// Loads a complete ordinary tree from exact staged Nodes and backend metadata.
    ///
    /// # Errors
    /// Rejects duplicate or invalid staged Nodes and incomplete or contradictory
    /// canonical metadata; preserves backend read failures.
    pub(crate) async fn load_tree<S: ContentStore>(
        store: &S,
        root: Digest,
        uploads: &[StagedUpload],
        min_chunk_size: u64,
    ) -> Result<Self, StoreFailure> {
        Self::load_tree_for(store, root, uploads, min_chunk_size, TreeUse::Ordinary).await
    }

    /// Reconstructs the complete canonical namespace in an explicit operation context.
    ///
    /// # Errors
    /// Rejects duplicate staged Nodes, identity mismatch, missing dependencies,
    /// invalid tree roles and inconsistent canonical summaries or boundaries.
    pub(crate) async fn load_tree_for<S: ContentStore>(
        store: &S,
        root: Digest,
        uploads: &[StagedUpload],
        min_chunk_size: u64,
        usage: TreeUse,
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
            usage,
            ordinary_roots: BTreeSet::new(),
            commit: None,
            root,
            default_domain: crate::domain::private_default(
                &TERRANE_V1
                    .from_digest(IdentityKind::Node, &root)
                    .map_err(|_| invalid())?,
            ),
            nodes: BTreeMap::new(),
            roots: BTreeSet::from([root]),
            grafts: None,
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
            let node = tree_format::decode_node_for(&bytes, is_root, min_chunk_size, usage)
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
        evidence.validate_namespace(min_chunk_size)?;
        Ok(evidence)
    }

    /// Validates every reached canonical owner before retaining shared addresses.
    ///
    /// # Errors
    /// Rejects malformed, missing or contradictory physical roots and
    /// noncanonical Trees. Occurrence validation retains cycle/depth refusal;
    /// such inputs receive no usable depth certificate. Grants no authority.
    pub(crate) fn validate_namespace(&mut self, min_chunk_size: u64) -> Result<(), StoreFailure> {
        self.grafts = None;
        let usage = self.usage;
        let mut capture = grafts::Capture::default();
        let mut ordinary_roots = BTreeSet::new();
        for root in &self.roots {
            capture.begin(*root)?;
            self.tree_for_recording(*root, min_chunk_size, usage, Some(&mut capture))?;
            if usage == TreeUse::Ordinary
                || (usage == TreeUse::OverlayLayer
                    && self
                        .tree_for(*root, min_chunk_size, TreeUse::Ordinary)
                        .is_ok())
            {
                ordinary_roots.insert(*root);
            }
        }
        if usage == TreeUse::OverlayLayer {
            // A compatible wrapper cannot turn a grafted deletion layer into an
            // ordinary namespace. Propagate incompatibility through reverse
            // graft edges instead of repeatedly scanning deep graft chains.
            let mut parents: BTreeMap<Digest, Vec<Digest>> = BTreeMap::new();
            for root in &ordinary_roots {
                let tree = self.tree_for(*root, min_chunk_size, usage)?;
                for item in tree.iter() {
                    let mut entries = vec![&item.entry];
                    while let Some(entry) = entries.pop() {
                        match &entry.kind {
                            EntryKind::Tree { root: child, .. } => {
                                parents.entry(*child).or_default().push(*root);
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
            let mut incompatible = self
                .roots
                .difference(&ordinary_roots)
                .copied()
                .collect::<Vec<_>>();
            while let Some(child) = incompatible.pop() {
                for parent in parents.get(&child).into_iter().flatten() {
                    if ordinary_roots.remove(parent) {
                        incompatible.push(*parent);
                    }
                }
            }
        }
        // The explicit layer loader first validates every addressed dependency.
        // Narrowing compatible roots preserves the core history's one-usage
        // invariant; this proof never makes an ordinary loader accept whiteouts.
        if usage == TreeUse::OverlayLayer && ordinary_roots == self.roots {
            self.usage = TreeUse::Ordinary;
        }
        let grafts = capture.finish(self.root, min_chunk_size, self.usage)?;
        self.ordinary_roots = ordinary_roots;
        self.grafts = Some(Arc::new(grafts));
        Ok(())
    }

    /// Borrows addresses only under their exact validated immutable interpretation.
    ///
    /// # Errors
    /// Rejects unavailable addresses or a changed root, Tree use or chunk geometry.
    pub(crate) fn validated_grafts(
        &self,
        minimum: u64,
    ) -> Result<Arc<ValidatedGrafts>, StoreFailure> {
        let grafts = self.grafts.as_ref().ok_or_else(invalid)?;
        if !grafts.matches(self.root, minimum, self.usage) {
            return Err(invalid());
        }
        Ok(Arc::clone(grafts))
    }

    /// Reconstructs a canonical root under its independently recorded decoding usage.
    ///
    /// # Errors
    /// Rejects absent, malformed or inconsistent metadata and incompatible geometry.
    pub(crate) fn tree(&self, root: Digest, min_chunk_size: u64) -> Result<Tree<'_>, StoreFailure> {
        self.tree_for(root, min_chunk_size, self.root_usage(root))
    }

    /// Returns the root context after complete canonical ordinary-compatibility checks.
    pub(crate) fn root_usage(&self, root: Digest) -> TreeUse {
        if self.ordinary_roots.contains(&root) {
            TreeUse::Ordinary
        } else {
            self.usage
        }
    }

    fn tree_for(
        &self,
        root: Digest,
        min_chunk_size: u64,
        usage: TreeUse,
    ) -> Result<Tree<'_>, StoreFailure> {
        self.tree_for_recording(root, min_chunk_size, usage, None)
    }

    fn tree_for_recording(
        &self,
        root: Digest,
        min_chunk_size: u64,
        usage: TreeUse,
        mut capture: Option<&mut grafts::Capture>,
    ) -> Result<Tree<'_>, StoreFailure> {
        let root_bytes = self.nodes.get(&root).ok_or_else(invalid)?;
        let root_node = tree_format::decode_node_for(root_bytes, true, min_chunk_size, usage)
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
            let node = tree_format::decode_node_for(bytes, is_root, min_chunk_size, usage)
                .map_err(|_| invalid())?;
            if let Some(capture) = capture.as_deref_mut() {
                capture.node()?;
            }
            match node.items {
                NodeItems::Leaf(items) => {
                    for item in items {
                        if let Some(capture) = capture.as_deref_mut() {
                            capture.item(root, &item.key, &item.entry)?;
                        }
                        entries.push(item);
                    }
                }
                NodeItems::Internal(children) => {
                    pending.extend(children.into_iter().rev().map(|child| (child.child, false)))
                }
            }
        }
        let tree =
            Tree::build(entries, properties, min_chunk_size, usage).map_err(|_| invalid())?;
        if tree.root_identity() != root {
            return Err(invalid());
        }
        Ok(tree)
    }

    /// Collects ordered root and graft layers for an absolute namespace path.
    ///
    /// # Errors
    /// Rejects invalid paths, cycles, excessive graft depth or malformed root metadata.
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

    /// Reads properties from an already authenticated physical root Node.
    ///
    /// # Errors
    /// Rejects an absent root or malformed metadata under its verified tree use.
    pub(crate) fn root_properties(
        &self,
        root: Digest,
        min_chunk_size: u64,
    ) -> Result<Vec<Property<'_>>, StoreFailure> {
        if !self.roots.contains(&root) {
            return Err(invalid());
        }
        let bytes = self.nodes.get(&root).ok_or_else(invalid)?;
        let node = tree_format::decode_node_for(bytes, true, min_chunk_size, self.root_usage(root))
            .map_err(|_| invalid())?;
        Ok(node.props.unwrap_or_default())
    }

    /// Enumerates qualified graft occurrences without reconstructing namespaces.
    ///
    /// # Errors
    /// Rejects missing or malformed Nodes, repeated physical dependencies,
    /// graft cycles and excessive graft depth.
    pub(crate) fn occurrences(
        &self,
        min_chunk_size: u64,
    ) -> Result<Vec<RootOccurrence<'_>>, StoreFailure> {
        let mut output = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut pending = vec![(self.root, b"/".to_vec(), Vec::new(), Vec::new(), Vec::new())];
        while let Some((root, path, mut layers, overrides, mut ancestors)) = pending.pop() {
            if ancestors.contains(&root) || ancestors.len() > tree_format::MAX_GRAFT_DEPTH {
                return Err(invalid());
            }
            ancestors.push(root);
            if let std::collections::btree_map::Entry::Vacant(entry) = metadata.entry(root) {
                entry.insert(self.owner_metadata(root, min_chunk_size)?);
            }
            let owner = metadata.get(&root).ok_or_else(invalid)?;
            layers.push((owner.properties.clone(), overrides));
            for graft in &owner.grafts {
                let mut target_path = path.clone();
                if target_path != b"/" {
                    target_path.push(b'/');
                }
                target_path.extend_from_slice(&graft.key);
                pending.push((
                    graft.root,
                    target_path,
                    layers.clone(),
                    graft.overrides.clone(),
                    ancestors.clone(),
                ));
            }
            output.push(RootOccurrence { root, path, layers });
        }
        Ok(output)
    }

    /// Traverses qualified physical Nodes, retaining only owner metadata and grafts.
    fn owner_metadata(
        &self,
        root: Digest,
        min_chunk_size: u64,
    ) -> Result<OwnerMetadata<'_>, StoreFailure> {
        let properties = self.root_properties(root, min_chunk_size)?;
        let usage = self.root_usage(root);
        let mut grafts = Vec::new();
        let mut pending = vec![(root, true)];
        let mut seen = BTreeSet::new();
        while let Some((identity, is_root)) = pending.pop() {
            if !seen.insert(identity) {
                return Err(invalid());
            }
            let bytes = self.nodes.get(&identity).ok_or_else(invalid)?;
            let node = tree_format::decode_node_for(bytes, is_root, min_chunk_size, usage)
                .map_err(|_| invalid())?;
            match node.items {
                NodeItems::Internal(children) => {
                    pending.extend(children.into_iter().rev().map(|child| (child.child, false)));
                }
                NodeItems::Leaf(items) => {
                    for item in items {
                        let mut candidates = vec![&item.entry];
                        while let Some(entry) = candidates.pop() {
                            match &entry.kind {
                                EntryKind::Tree { root, props } => grafts.push(GraftMetadata {
                                    key: item.key.clone(),
                                    root: *root,
                                    overrides: props.clone().unwrap_or_default(),
                                }),
                                EntryKind::Conflict {
                                    candidates: sides,
                                    base,
                                } => {
                                    candidates.extend(sides);
                                    if let Some(Some(base)) = base {
                                        candidates.push(base.as_ref());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        Ok(OwnerMetadata { properties, grafts })
    }
}

/// Constructs the source-less malformed-request refusal used by tree evidence checks.
pub(crate) fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane_format::tree_format::{Entry, LeafItem};

    /// Refuses stale interpretation and invalid revalidation without retained addresses.
    ///
    /// # Errors
    /// Preserves canonical fixture and actual validation errors.
    /// # Panics
    /// Panics if stale or invalid bytes retain a usable address certificate.
    #[test]
    fn retained_graft_addresses_bind_canonical_root_usage_and_geometry()
    -> Result<(), Box<dyn std::error::Error>> {
        let minimum = 262144;
        let tree = Tree::build(Vec::new(), None, minimum, TreeUse::Ordinary)?;
        let root = tree.root_identity();
        let mut evidence = TreeEvidence {
            usage: TreeUse::Ordinary,
            ordinary_roots: BTreeSet::new(),
            commit: None,
            root,
            default_domain: String::new(),
            nodes: BTreeMap::from([(root, tree.root().encoded().to_vec())]),
            roots: BTreeSet::from([root]),
            grafts: None,
        };
        evidence.validate_namespace(minimum)?;
        let retained = evidence.validated_grafts(minimum)?;
        assert!(Arc::ptr_eq(&retained, &evidence.validated_grafts(minimum)?));
        assert!(evidence.validated_grafts(minimum + 1).is_err());

        evidence.root = [0; 32];
        assert!(evidence.validated_grafts(minimum).is_err());
        evidence.root = root;
        evidence.usage = TreeUse::OverlayLayer;
        assert!(evidence.validated_grafts(minimum).is_err());
        evidence.usage = TreeUse::Ordinary;

        evidence.nodes.insert(root, vec![0]);
        assert!(evidence.validate_namespace(minimum).is_err());
        assert!(evidence.grafts.is_none());
        assert!(evidence.validated_grafts(minimum).is_err());
        Ok(())
    }

    /// Preserves distinct occurrence overrides when a contextual target is shared.
    ///
    /// # Errors
    /// Preserves canonical fixture construction and qualified traversal failures.
    ///
    /// # Panics
    /// Panics if independent occurrence paths, policies or refusal assertions differ.
    #[test]
    fn qualified_occurrences_preserve_shared_layer_contexts()
    -> Result<(), Box<dyn std::error::Error>> {
        let minimum = 262_144;
        let child = Tree::build(
            vec![LeafItem {
                key: b"removed".to_vec(),
                entry: entry(EntryKind::Whiteout),
            }],
            Some(vec![Property {
                name: "domain",
                value: b"\x65child",
            }]),
            minimum,
            TreeUse::OverlayLayer,
        )?;
        let root = Tree::build(
            vec![
                LeafItem {
                    key: b"a".to_vec(),
                    entry: entry(EntryKind::Tree {
                        root: child.root_identity(),
                        props: Some(vec![Property {
                            name: "store",
                            value: b"\x61a",
                        }]),
                    }),
                },
                LeafItem {
                    key: b"b".to_vec(),
                    entry: entry(EntryKind::Tree {
                        root: child.root_identity(),
                        props: Some(vec![Property {
                            name: "store",
                            value: b"\x61b",
                        }]),
                    }),
                },
            ],
            Some(vec![Property {
                name: "domain",
                value: b"\x64root",
            }]),
            minimum,
            TreeUse::OverlayLayer,
        )?;
        let nodes = root
            .nodes()
            .chain(child.nodes())
            .map(|node| (node.identity(), node.encoded().to_vec()))
            .collect();
        let mut evidence = TreeEvidence {
            usage: TreeUse::OverlayLayer,
            ordinary_roots: BTreeSet::new(),
            commit: None,
            root: root.root_identity(),
            default_domain: String::new(),
            nodes,
            roots: BTreeSet::from([root.root_identity(), child.root_identity()]),
            grafts: None,
        };

        let mut occurrences = evidence.occurrences(minimum)?;
        occurrences.sort_by(|left, right| left.path.cmp(&right.path));
        assert_eq!(
            occurrences
                .iter()
                .map(|value| value.path.as_slice())
                .collect::<Vec<_>>(),
            vec![b"/".as_slice(), b"/a", b"/b"]
        );
        assert_eq!(occurrences[1].root, child.root_identity());
        assert_eq!(occurrences[2].root, child.root_identity());
        assert_eq!(occurrences[1].layers[1].0[0].value, b"\x65child");
        assert_eq!(occurrences[1].layers[1].1[0].value, b"\x61a");
        assert_eq!(occurrences[2].layers[1].1[0].value, b"\x61b");
        assert!(evidence.root_properties([0; 32], minimum).is_err());

        // An ordinary context still refuses the actual Whiteout target bytes.
        evidence.usage = TreeUse::Ordinary;
        assert!(evidence.occurrences(minimum).is_err());
        Ok(())
    }

    fn entry(kind: EntryKind<'_>) -> Entry<'_> {
        Entry {
            kind,
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        }
    }
}
