//! Resolves provenance through authenticated commits and canonical tree witnesses.
//!
//! The caller supplies stored node bytes, never an arbitrary entry lookup
//! callback. Nodes are checked against their immutable identities and child
//! summaries before they become usable evidence.

use super::{Rejected, VerifiedCommit};
use crate::{
    identity::{Digest, IdentityKind, TERRANE_V1},
    refs::{CommitGraph, CommitParents, EntryOrigin},
    tree_format::{self, Entry, EntryKind, NodeItems},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

/// Names an entry in the immutable tree evidence of a signed commit.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EntryLocation {
    /// Signed commit containing the selected tree.
    pub commit: Digest,
    /// Root containing the relative entry key.
    pub root: Digest,
    /// Canonical relative key bytes in that root.
    pub path: Vec<u8>,
}

/// Stores authenticated commit records and fully checked Merkle tree witnesses.
#[derive(Clone, Debug)]
pub struct VerifiedHistory {
    pub(super) commits: BTreeMap<Digest, VerifiedCommit>,
    pub(super) graph: CommitGraph,
    nodes: BTreeMap<Digest, Vec<u8>>,
    roots: BTreeMap<Digest, BTreeSet<Digest>>,
    min_chunk_size: u64,
    usage: BTreeMap<Digest, tree_format::TreeUse>,
}

impl VerifiedHistory {
    pub(super) const fn min_chunk_size(&self) -> u64 {
        self.min_chunk_size
    }

    /// Creates a history using the configured chunk profile's minimum size.
    pub fn new(min_chunk_size: u64) -> Self {
        Self {
            commits: BTreeMap::new(),
            graph: CommitGraph::new(),
            nodes: BTreeMap::new(),
            roots: BTreeMap::new(),
            usage: BTreeMap::new(),
            min_chunk_size,
        }
    }

    /// Adds a commit whose signature and authorizing capability were verified.
    ///
    /// # Errors
    /// Returns [`Rejected`] for a cycle or conflicting immutable record.
    pub fn insert_commit(&mut self, commit: VerifiedCommit) -> Result<(), Rejected> {
        let identity = commit.identity();
        self.graph
            .insert(CommitParents {
                identity,
                parents: commit.commit().parents.clone(),
            })
            .map_err(|_| Rejected)?;
        self.commits.insert(identity, commit);
        Ok(())
    }

    /// Adds a complete canonical node witness for one root.
    ///
    /// Verification checks every node hash, child level, summary, and boundary
    /// range. Graft targets are recorded as edges and may be supplied later.
    /// Existing evidence remains unchanged on validation failure.
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing, malformed, noncanonical, misidentified,
    /// overlapping, or inconsistent nodes and arithmetic failures.
    pub fn insert_tree(
        &mut self,
        root: Digest,
        nodes: &[(Digest, Vec<u8>)],
    ) -> Result<(), Rejected> {
        self.insert_tree_for(root, nodes, tree_format::TreeUse::Ordinary)
    }

    /// Adds canonical index-tree evidence with opaque attribute-value keys.
    ///
    /// # Errors
    /// Returns [`Rejected`] for invalid index entries, incomplete or inconsistent
    /// Merkle witnesses, or a conflicting interpretation of existing evidence.
    pub fn insert_index_tree(
        &mut self,
        root: Digest,
        nodes: &[(Digest, Vec<u8>)],
    ) -> Result<(), Rejected> {
        self.insert_tree_for(root, nodes, tree_format::TreeUse::Index)
    }

    /// Adds a checked overlay-layer witness, including deletion markers.
    ///
    /// # Errors
    /// Returns [`Rejected`] for malformed or inconsistent tree evidence,
    /// invalid layer entries, or a conflicting existing root interpretation.
    pub fn insert_overlay_tree(
        &mut self,
        root: Digest,
        nodes: &[(Digest, Vec<u8>)],
    ) -> Result<(), Rejected> {
        self.insert_tree_for(root, nodes, tree_format::TreeUse::OverlayLayer)
    }

    fn insert_tree_for(
        &mut self,
        root: Digest,
        nodes: &[(Digest, Vec<u8>)],
        usage: tree_format::TreeUse,
    ) -> Result<(), Rejected> {
        if self
            .usage
            .get(&root)
            .is_some_and(|previous| *previous != usage)
        {
            return Err(Rejected);
        }
        let mut candidate = self.nodes.clone();
        for (identity, bytes) in nodes {
            let actual = TERRANE_V1
                .calculate(IdentityKind::Node, bytes)
                .and_then(|value| value.terrane_v1_digest())
                .map_err(|_| Rejected)?;
            if actual != *identity {
                return Err(Rejected);
            }
            if let Some(previous) = candidate.get(identity)
                && previous != bytes
            {
                return Err(Rejected);
            }
            candidate.insert(*identity, bytes.clone());
        }

        let mut pending = vec![(root, true)];
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        let mut grafts = BTreeSet::new();
        while let Some((identity, is_root)) = pending.pop() {
            if !seen.insert(identity) {
                return Err(Rejected);
            }
            let bytes = candidate.get(&identity).ok_or(Rejected)?;
            let node = tree_format::decode_node_for(bytes, is_root, self.min_chunk_size, usage)
                .map_err(|_| Rejected)?;
            match &node.items {
                NodeItems::Leaf(items) => {
                    entries.extend(items.iter().cloned());
                    for item in items {
                        if let EntryKind::Tree { root, .. } = item.entry.kind {
                            grafts.insert(root);
                        }
                    }
                }
                NodeItems::Internal(children) => {
                    // Descendant leaf ordering is validated globally below;
                    // an internal child's first separator is not its first key.
                    for child in children.iter().rev() {
                        let child_bytes = candidate.get(&child.child).ok_or(Rejected)?;
                        let child_node = tree_format::decode_node_for(
                            child_bytes,
                            false,
                            self.min_chunk_size,
                            usage,
                        )
                        .map_err(|_| Rejected)?;
                        tree_format::verify_child_ref_for(
                            node.level,
                            child,
                            &child_node,
                            child_bytes,
                            self.min_chunk_size,
                            usage,
                        )
                        .map_err(|_| Rejected)?;
                        pending.push((child.child, false));
                    }
                }
            }
        }

        tree_format::validate_tree_entries(&entries, usage).map_err(|_| Rejected)?;

        self.nodes = candidate;
        self.roots.insert(root, grafts);
        self.usage.insert(root, usage);
        Ok(())
    }

    /// Returns a previously authenticated signed commit record.
    pub fn commit(&self, identity: &Digest) -> Option<&VerifiedCommit> {
        self.commits.get(identity)
    }

    pub(super) fn root_reachable(&self, commit: Digest, root: Digest) -> bool {
        self.root_presence(commit, root) == Ok(true)
    }

    pub(super) fn root_presence(&self, commit: Digest, root: Digest) -> Result<bool, Rejected> {
        let commit = self.commits.get(&commit).ok_or(Rejected)?;
        let mut pending = vec![commit.commit().tree];
        let mut seen = BTreeSet::new();
        let mut incomplete = false;
        while let Some(candidate) = pending.pop() {
            if !seen.insert(candidate) {
                continue;
            }
            if candidate == root {
                return self
                    .roots
                    .contains_key(&root)
                    .then_some(true)
                    .ok_or(Rejected);
            }
            let Some(children) = self.roots.get(&candidate) else {
                incomplete = true;
                continue;
            };
            pending.extend(children.iter().copied());
        }
        if incomplete {
            return Err(Rejected);
        }
        Ok(false)
    }

    /// Fetches an entry only from checked tree evidence reachable from its commit.
    ///
    /// # Errors
    /// Returns [`Rejected`] for invalid keys, missing evidence, inaccessible
    /// roots, malformed witness nodes, or absent entries.
    pub fn entry(&self, location: &EntryLocation) -> Result<Entry<'_>, Rejected> {
        if !self.root_reachable(location.commit, location.root) {
            return Err(Rejected);
        }
        if self.usage.get(&location.root) == Some(&tree_format::TreeUse::Index) {
            tree_format::validate_index_key(&location.path).map_err(|_| Rejected)?;
        } else {
            tree_format::validate_key(&location.path).map_err(|_| Rejected)?;
        }
        self.root_entry(location.root, &location.path)
    }

    pub(super) fn root_entry(&self, root: Digest, path: &[u8]) -> Result<Entry<'_>, Rejected> {
        let usage = *self.usage.get(&root).ok_or(Rejected)?;
        let mut current = root;
        let mut is_root = true;
        loop {
            let bytes = self.nodes.get(&current).ok_or(Rejected)?;
            let node = tree_format::decode_node_for(bytes, is_root, self.min_chunk_size, usage)
                .map_err(|_| Rejected)?;
            match node.items {
                NodeItems::Leaf(items) => {
                    return items
                        .into_iter()
                        .find(|item| item.key == path)
                        .map(|item| item.entry)
                        .ok_or(Rejected);
                }
                NodeItems::Internal(children) => {
                    current = children
                        .iter()
                        .find(|child| child.last_key.as_slice() >= path)
                        .ok_or(Rejected)?
                        .child;
                    is_root = false;
                }
            }
        }
    }

    pub(super) fn root_properties(
        &self,
        root: Digest,
    ) -> Result<Vec<crate::tree_format::Property<'_>>, Rejected> {
        let bytes = self.nodes.get(&root).ok_or(Rejected)?;
        let usage = *self.usage.get(&root).ok_or(Rejected)?;
        let node = tree_format::decode_node_for(bytes, true, self.min_chunk_size, usage)
            .map_err(|_| Rejected)?;
        Ok(node.props.unwrap_or_default())
    }

    /// Resolves a full view path through authenticated grafts and root policies.
    ///
    /// # Errors
    /// Returns [`Rejected`] for absent paths, missing evidence, invalid keys,
    /// or a graft cycle. Policy values are returned in ancestor-to-child order.
    pub fn locate(
        &self,
        view: Digest,
        path: &[u8],
    ) -> Result<(EntryLocation, Vec<crate::tree_format::Property<'_>>), Rejected> {
        let (location, properties) = self.locate_policies(view, path)?;
        Ok((location, properties.into_iter().flatten().collect()))
    }

    pub(super) fn locate_policies(
        &self,
        view: Digest,
        path: &[u8],
    ) -> Result<(EntryLocation, Vec<Vec<crate::tree_format::Property<'_>>>), Rejected> {
        let mut root = self.commits.get(&view).ok_or(Rejected)?.commit().tree;
        if self.usage.get(&root) == Some(&tree_format::TreeUse::Index) {
            tree_format::validate_index_key(path).map_err(|_| Rejected)?;
        } else {
            tree_format::validate_key(path).map_err(|_| Rejected)?;
        }
        let mut relative = path;
        let mut roots = BTreeSet::new();
        let mut properties = Vec::new();
        let mut pending_overrides: Option<Vec<crate::tree_format::Property<'_>>> = None;
        loop {
            if !roots.insert(root) || roots.len() > tree_format::MAX_GRAFT_DEPTH + 1 {
                return Err(Rejected);
            }
            let mut root_properties = self.root_properties(root)?;
            if let Some(overrides) = pending_overrides.take() {
                // TREE-13 defines graft props as this target root's properties
                // in the current view. Ancestor requirements stay separate.
                for replacement in overrides {
                    root_properties.retain(|property| property.name != replacement.name);
                    root_properties.push(replacement);
                }
            }
            properties.push(root_properties);
            if self.root_entry(root, relative).is_ok() {
                return Ok((
                    EntryLocation {
                        commit: view,
                        root,
                        path: relative.to_vec(),
                    },
                    properties,
                ));
            }

            let mut selected = None;
            for (position, byte) in relative.iter().enumerate() {
                if *byte != b'/' {
                    continue;
                }
                let Ok(entry) = self.root_entry(root, &relative[..position]) else {
                    continue;
                };
                if let EntryKind::Tree {
                    root: target,
                    props,
                } = &entry.kind
                {
                    selected = Some((*target, &relative[position + 1..], props.clone()));
                    break;
                }
            }
            let (target, remaining, overrides) = selected.ok_or(Rejected)?;
            pending_overrides = overrides;
            root = target;
            relative = remaining;
        }
    }

    fn dependencies(
        &self,
        location: &EntryLocation,
    ) -> Result<Option<Vec<EntryLocation>>, Rejected> {
        let record = self.commits.get(&location.commit).ok_or(Rejected)?.commit();
        let entry = self.entry(location)?;
        let receipt = record
            .profile_pair
            .entry_receipts
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .find(|receipt| receipt.root == location.root && receipt.path == location.path);
        if let Some(receipt) = receipt {
            match &receipt.origin {
                EntryOrigin::Current => {
                    if entry.provenance.is_some() {
                        return Err(Rejected);
                    }
                    // Current markers on unchanged content are reintroductions,
                    // and require the explicit original-introduction attribute.
                    let mut unchanged = self.unchanged_parents(location)?;
                    if let Some(original) = &receipt.reintroduced_from {
                        let original = EntryLocation {
                            commit: original.commit,
                            root: original.root,
                            path: original.path.clone(),
                        };
                        if original.commit == location.commit
                            || !same_content(&entry, &self.entry(&original)?)
                        {
                            return Err(Rejected);
                        }
                        unchanged = vec![original];
                    } else if entry
                        .attrs
                        .iter()
                        .any(|attribute| attribute.name == "provenance.reintroduced-from")
                    {
                        return Err(Rejected);
                    }
                    if !unchanged.is_empty()
                        && (receipt.reintroduced_from.is_none()
                            || !entry
                                .attrs
                                .iter()
                                .any(|attribute| attribute.name == "provenance.reintroduced-from"))
                    {
                        return Err(Rejected);
                    }
                    return Ok(Some(unchanged));
                }
                EntryOrigin::Source(source) => {
                    let crate::refs::EntrySource { commit, root, path } = source;
                    if *commit == location.commit {
                        return Err(Rejected);
                    }
                    let source = EntryLocation {
                        commit: *commit,
                        root: *root,
                        path: path.clone(),
                    };
                    if !same_content(&entry, &self.entry(&source)?) {
                        return Err(Rejected);
                    }
                    return Ok(Some(vec![source]));
                }
            }
        }
        let parents = self.unchanged_parents(location)?;
        if parents.is_empty() {
            return Err(Rejected);
        }
        Ok(Some(parents))
    }

    fn unchanged_parents(&self, location: &EntryLocation) -> Result<Vec<EntryLocation>, Rejected> {
        let commit = self.commits.get(&location.commit).ok_or(Rejected)?.commit();
        let entry = self.entry(location)?;
        let mut result = Vec::new();
        for parent in &commit.parents {
            let parent_commit = self.commits.get(parent).ok_or(Rejected)?.commit();
            // A missing witness is not evidence that the key was absent in a
            // parent. Fresh introduction receipts must not hide that uncertainty.
            if !self.roots.contains_key(&parent_commit.tree) {
                return Err(Rejected);
            }

            let root = if location.root == commit.tree {
                parent_commit.tree
            } else {
                location.root
            };
            if !self.root_presence(*parent, root)? {
                continue;
            }
            let source = EntryLocation {
                commit: *parent,
                root,
                path: location.path.clone(),
            };
            if let Ok(previous) = self.entry(&source)
                && same_content(&entry, &previous)
            {
                result.push(source);
            }
        }
        Ok(result)
    }

    /// Resolves the actual introducing signed commit through receipts and parents.
    ///
    /// Missing commits or ambiguous unchanged-parent introductions fail closed.
    /// Explicit entry digests are checked against graph-derived provenance.
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing evidence, invalid source selection,
    /// ambiguous ancestry, circular receipts, or mismatched introducing claims.
    pub fn introducing_commit(&self, location: &EntryLocation) -> Result<Digest, Rejected> {
        let mut pending = vec![(location.clone(), false)];
        let mut active = BTreeSet::new();
        let mut resolved = BTreeMap::new();
        while let Some((current, finishing)) = pending.pop() {
            if resolved.contains_key(&current) {
                continue;
            }
            let dependencies = self.dependencies(&current)?;
            if !finishing {
                if !active.insert(current.clone()) {
                    return Err(Rejected);
                }
                pending.push((current.clone(), true));
                if let Some(dependencies) = &dependencies {
                    for source in dependencies.iter().rev() {
                        pending.push((source.clone(), false));
                    }
                }
                continue;
            }

            let current_receipt = self
                .commits
                .get(&current.commit)
                .ok_or(Rejected)?
                .commit()
                .profile_pair
                .entry_receipts
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|receipt| {
                    receipt.root == current.root
                        && receipt.path == current.path
                        && receipt.origin == EntryOrigin::Current
                });
            let identity = if current_receipt {
                let entry = self.entry(&current)?;
                if let Some(dependencies) = &dependencies
                    && !dependencies.is_empty()
                {
                    let attribute = entry
                        .attrs
                        .iter()
                        .find(|attribute| attribute.name == "provenance.reintroduced-from")
                        .ok_or(Rejected)?;
                    let mut decoder = crate::cbor::Decoder::new(attribute.value);
                    let original: Digest = decoder
                        .bytes(32)
                        .map_err(|_| Rejected)?
                        .try_into()
                        .map_err(|_| Rejected)?;
                    decoder.finish().map_err(|_| Rejected)?;
                    for source in dependencies {
                        if resolved.get(source) != Some(&original) {
                            return Err(Rejected);
                        }
                    }
                }
                current.commit
            } else if let Some(dependencies) = dependencies {
                let mut identities = dependencies
                    .iter()
                    .map(|source| resolved.get(source).copied().ok_or(Rejected));
                let first = identities.next().ok_or(Rejected)??;
                for identity in identities {
                    if identity? != first {
                        return Err(Rejected);
                    }
                }
                first
            } else {
                current.commit
            };
            if self
                .entry(&current)?
                .provenance
                .is_some_and(|claimed| claimed != identity)
            {
                return Err(Rejected);
            }
            active.remove(&current);
            resolved.insert(current, identity);
        }
        resolved.get(location).copied().ok_or(Rejected)
    }

    pub(super) fn acceptance_commits(
        &self,
        location: &EntryLocation,
        introducing: Digest,
    ) -> Vec<Digest> {
        let Ok(entry) = self.entry(location) else {
            return Vec::new();
        };
        let Some(view) = self.commits.get(&location.commit) else {
            return Vec::new();
        };
        let mut accepted = BTreeSet::new();

        // Receipts preserve carried-entry evidence when grafts or transforms
        // change a key/root. Source edges preserve introduction evidence, but only
        // actual view ancestors can establish acceptance.
        let mut pending = vec![location.clone()];
        let mut seen = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if !seen.insert(current.clone()) || self.introducing_commit(&current) != Ok(introducing)
            {
                continue;
            }
            if current.commit != introducing
                && self.graph.is_ancestor(current.commit, location.commit) == Ok(true)
            {
                accepted.insert(current.commit);
            }
            if let Ok(Some(dependencies)) = self.dependencies(&current) {
                pending.extend(dependencies);
            }
        }

        // A merge can also retain an entry through another unchanged input
        // besides its selected source receipt. Check those real ancestor views.
        for (identity, commit) in &self.commits {
            if *identity == introducing
                || self.graph.is_ancestor(*identity, location.commit) != Ok(true)
            {
                continue;
            }
            let root = if location.root == view.commit().tree {
                commit.commit().tree
            } else {
                location.root
            };
            let candidate = EntryLocation {
                commit: *identity,
                root,
                path: location.path.clone(),
            };
            if let Ok(carried) = self.entry(&candidate)
                && same_content(&entry, &carried)
                && self.introducing_commit(&candidate) == Ok(introducing)
            {
                accepted.insert(*identity);
            }
        }
        accepted.into_iter().collect()
    }

    /// Returns reachable signed records that actually carried the selected entry.
    ///
    /// The view and introducing records are included. This pure evidence walk
    /// is intended for later repository protocol and CLI audit operations.
    ///
    /// # Errors
    /// Returns [`Rejected`] if introducing provenance cannot be resolved.
    pub fn provenance_walk(
        &self,
        location: &EntryLocation,
    ) -> Result<Vec<&VerifiedCommit>, Rejected> {
        let introducing = self.introducing_commit(location)?;
        let mut identities = self.acceptance_commits(location, introducing);
        if !identities.contains(&location.commit) {
            identities.insert(0, location.commit);
        }
        if !identities.contains(&introducing) {
            identities.push(introducing);
        }
        identities
            .into_iter()
            .map(|identity| self.commits.get(&identity).ok_or(Rejected))
            .collect()
    }
}

/// Compares content identity without attributes, POSIX modes, or provenance.
pub fn same_content(left: &Entry<'_>, right: &Entry<'_>) -> bool {
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        let equal = match (&left.kind, &right.kind) {
            (
                EntryKind::File {
                    size: left_size,
                    content: left_content,
                    ..
                },
                EntryKind::File {
                    size: right_size,
                    content: right_content,
                    ..
                },
            ) => left_size == right_size && left_content == right_content,
            (EntryKind::Directory { .. }, EntryKind::Directory { .. }) => true,
            (EntryKind::Symlink { target: left }, EntryKind::Symlink { target: right }) => {
                left == right
            }
            (EntryKind::Tree { root: left, .. }, EntryKind::Tree { root: right, .. }) => {
                left == right
            }
            (EntryKind::Whiteout, EntryKind::Whiteout) => true,
            (EntryKind::Index { targets: left }, EntryKind::Index { targets: right }) => {
                left == right
            }
            (
                EntryKind::Conflict {
                    candidates: left,
                    base: left_base,
                },
                EntryKind::Conflict {
                    candidates: right,
                    base: right_base,
                },
            ) => {
                if left.len() != right.len() {
                    return false;
                }
                pending.extend(left.iter().zip(right));
                match (left_base, right_base) {
                    (None, None) | (Some(None), Some(None)) => {}
                    (Some(Some(left)), Some(Some(right))) => pending.push((left, right)),
                    _ => return false,
                }
                true
            }
            _ => false,
        };
        if !equal {
            return false;
        }
    }
    true
}

/// Iterates source commits retained by an authenticated record's entry receipts.
///
/// References include content origins, attribute producers, and explicit
/// reintroduction evidence. They are garbage-collection edges even when the
/// source is outside parent ancestry. Duplicates are allowed; collectors also
/// retain introducing identities found in their checked live entry witnesses.
pub fn source_commit_references(commit: &VerifiedCommit) -> impl Iterator<Item = Digest> + '_ {
    commit
        .commit()
        .profile_pair
        .entry_receipts
        .iter()
        .flat_map(|receipts| receipts.iter())
        .flat_map(|receipt| {
            core::iter::once(&receipt.origin)
                .chain(
                    receipt
                        .attributes
                        .iter()
                        .flat_map(|attributes| attributes.iter().map(|(_, origin)| origin)),
                )
                .filter_map(|origin| match origin {
                    EntryOrigin::Current => None,
                    EntryOrigin::Source(source) => Some(source.commit),
                })
                .chain(receipt.reintroduced_from.iter().map(|source| source.commit))
        })
}
