//! Replaces graft entries through persistent edits and reusable graph admission.
//!
//! Prepared grafts retain canonical bytes for surviving hard-link relabels and
//! ownership bindings; ordinary grafts reuse unaffected Merkle frontiers.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{Error, MaterializedRoot, Roots, beneath};
use crate::identity::Digest;
use crate::tree_builder::Tree;
use crate::tree_format::{self, Entry, EntryKind, LeafItem};

/// Replaces a path with a graft after validating root-graph admission.
///
/// Target graph validation is a separate admission phase; local namespace edits
/// share unaffected Merkle nodes and never rewrite target keys.
/// Replacing a canonical hard-link member with surviving members requires
/// [`prepare_graft`], whose owner keeps their new identities alive.
///
/// # Errors
/// Returns errors for invalid keys, inline descendants without replacement
/// permission, malformed ancestor structure, unavailable targets, or a cyclic
/// or excessively deep root graph. An input without an explicit domain requires
/// [`graft_with_domains`]; otherwise the edit returns `DomainContext`.
pub fn graft<'a>(
    parent: &Tree<'a>,
    at: &[u8],
    entry: Entry<'a>,
    replace: bool,
    roots: &impl Roots<'a>,
) -> Result<Tree<'a>, Error> {
    Ok(graft_certified(
        parent,
        at,
        entry,
        replace,
        roots,
        &mut super::RootGraph::new(),
    )?
    .tree)
}

/// Replaces a graft while preserving trusted effective ownership.
///
/// # Errors
/// Returns the structural and graph errors of [`graft`] and `DomainContext`
/// when the source has no resolved or explicit disclosure-domain evidence.
pub fn graft_with_domains<'a>(
    parent: &Tree<'a>,
    at: &[u8],
    entry: Entry<'a>,
    replace: bool,
    roots: &impl Roots<'a>,
    domains: &'a super::OperationDomains,
) -> Result<Tree<'a>, Error> {
    Ok(graft_certified_with_domains(
        parent,
        at,
        entry,
        replace,
        roots,
        &mut super::RootGraph::new(),
        domains,
    )?
    .tree)
}

/// A graft result with separately measured mutation and graph admission work.
#[derive(Clone, Debug)]
pub struct GraftResult<'a> {
    /// Canonical parent result, sharing unchanged Merkle nodes.
    pub tree: Tree<'a>,
    /// Canonical graft inputs and complete entry metadata for recomputation.
    pub recipe: Vec<u8>,
    /// Work rewriting the local map.
    pub mutation: crate::tree_builder::Work,
    /// Work admitting previously uncertified root and node frontiers.
    pub admission: super::GraphWork,
}

impl GraftResult<'_> {
    /// Records the graft recipe and certified conflict state on an unsigned commit.
    ///
    /// # Errors
    /// Rejects a result not admitted to the supplied immutable graph registry.
    pub fn bind_commit(
        &self,
        commit: &mut crate::refs::Commit,
        graph: &super::RootGraph,
    ) -> Result<(), Error> {
        MaterializedRoot {
            tree: self.tree.clone(),
            recipe: self.recipe.clone(),
        }
        .bind_commit(commit, graph)
    }
}

/// Owns canonical edits for a graft that relabels surviving hard-link groups.
///
/// Keep this owner alive while using the materialized tree, whose entry fields
/// borrow these encoded values. All edits are validated as one final map.
#[derive(Clone, Debug)]
pub struct PreparedGraft {
    parent: Digest,
    edits: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    hardlink_index_reads: usize,
    recipe: Vec<u8>,
    domains: super::OperationDomains,
}

impl PreparedGraft {
    /// Returns nodes read while seeking and iterating affected hard-link groups.
    pub fn hardlink_index_reads(&self) -> usize {
        self.hardlink_index_reads
    }

    /// Applies the prepared edits and admits the resulting graft graph.
    ///
    /// # Errors
    /// Rejects another parent identity, invalid entry encoding, an invalid final
    /// namespace, missing roots, cyclic grafts, or excessive graft depth.
    pub fn materialize<'a>(
        &'a self,
        parent: &Tree<'a>,
        roots: &impl Roots<'a>,
        graph: &mut super::RootGraph,
    ) -> Result<GraftResult<'a>, Error> {
        if parent.root_identity() != self.parent {
            return Err(Error::RootIdentity);
        }
        let mut admission = graph.admit(parent, roots)?;
        let edits = self
            .edits
            .iter()
            .map(|(key, encoded)| {
                let entry = encoded
                    .as_ref()
                    .map(|bytes| {
                        tree_format::decode_entry_bytes(bytes, parent.min_chunk_size())
                            .map_err(Error::Key)
                    })
                    .transpose()?;
                Ok((key.clone(), entry))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut mutation = parent.edit_entries(&edits)?;
        let ownership = super::domain::preserve(parent, mutation.tree, Some(&self.domains))?;
        add_work(&mut mutation.work, ownership.work);
        mutation.tree = ownership.tree;
        let added = graph.admit(&mutation.tree, roots)?;
        admission.nodes += added.nodes;
        admission.roots += added.roots;
        Ok(GraftResult {
            tree: mutation.tree,
            recipe: self.recipe.clone(),
            mutation: mutation.work,
            admission,
        })
    }
}

/// Prepares graft replacement while preserving valid surviving hard-link groups.
///
/// Only groups whose canonical first member is replaced need relabeling.
/// The persistent member index visits affected groups without scanning unrelated
/// entries. Other grafts can use [`graft_certified`] without an owned preparation.
///
/// # Errors
/// Rejects invalid paths, nongraft entries, inline children without replacement
/// permission, or entries that cannot be canonically encoded.
pub fn prepare_graft(
    parent: &Tree<'_>,
    at: &[u8],
    entry: &Entry<'_>,
    replace: bool,
) -> Result<PreparedGraft, Error> {
    prepare_graft_inner(parent, at, entry, replace, None)
}

/// Prepares a hard-link-aware graft with trusted effective ownership.
///
/// # Errors
/// Returns the errors of [`prepare_graft`] and missing ownership context.
pub fn prepare_graft_with_domains(
    parent: &Tree<'_>,
    at: &[u8],
    entry: &Entry<'_>,
    replace: bool,
    domains: &super::OperationDomains,
) -> Result<PreparedGraft, Error> {
    prepare_graft_inner(parent, at, entry, replace, Some(domains))
}

fn prepare_graft_inner(
    parent: &Tree<'_>,
    at: &[u8],
    entry: &Entry<'_>,
    replace: bool,
    domains: Option<&super::OperationDomains>,
) -> Result<PreparedGraft, Error> {
    tree_format::validate_key(at).map_err(Error::Key)?;
    let EntryKind::Tree { root: target, .. } = entry.kind else {
        return Err(Error::Structure);
    };

    let mut edits = BTreeMap::new();
    let mut displaced = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut start = at.to_vec();
    start.push(b'/');
    for item in parent
        .cursor_from(&start)
        .take_while(|item| beneath(&item.key, at))
    {
        if !replace {
            return Err(Error::InlineChildren);
        }
        if let EntryKind::File {
            link_id: Some(id), ..
        } = item.entry.kind
            && id == item.key
        {
            displaced.insert(id.to_vec(), Vec::new());
        }
        edits.insert(item.key.clone(), None);
    }

    if let Some(old) = parent.get(at)
        && let EntryKind::File {
            link_id: Some(id), ..
        } = old.kind
        && id == at
    {
        displaced.insert(id.to_vec(), Vec::new());
    }

    let mut hardlink_index_reads = 0;
    for (identity, first) in &mut displaced {
        let mut members = parent.hardlink_members(identity);
        for key in members.by_ref() {
            if key == at || beneath(key, at) {
                continue;
            }
            if first.is_empty() {
                *first = key.to_vec();
            }
            let mut relabeled = parent.get(key).ok_or(Error::Structure)?.clone();
            if let EntryKind::File { link_id, .. } = &mut relabeled.kind {
                *link_id = Some(first);
            }
            edits.insert(
                key.to_vec(),
                Some(
                    tree_format::encode_entry(&relabeled, parent.min_chunk_size())
                        .map_err(Error::Key)?,
                ),
            );
        }
        hardlink_index_reads += members.node_reads();
    }

    let encoded_entry =
        tree_format::encode_entry(entry, parent.min_chunk_size()).map_err(Error::Key)?;
    let recipe = super::Recipe::Graft {
        parent: parent.root_identity(),
        target,
        at,
        entry: &encoded_entry,
        replace,
        domains,
    }
    .encode();
    edits.insert(at.to_vec(), Some(encoded_entry));
    Ok(PreparedGraft {
        parent: parent.root_identity(),
        edits: edits.into_iter().collect(),
        hardlink_index_reads,
        recipe,
        domains: super::domain::owned_context(parent, domains)?,
    })
}

/// Grafts using reusable certificates for unchanged root and node graphs.
///
/// # Errors
/// Returns the same structural and graph errors as [`graft`].
pub fn graft_certified<'a>(
    parent: &Tree<'a>,
    at: &[u8],
    entry: Entry<'a>,
    replace: bool,
    roots: &impl Roots<'a>,
    graph: &mut super::RootGraph,
) -> Result<GraftResult<'a>, Error> {
    graft_certified_inner(parent, at, entry, replace, roots, graph, None)
}

/// Replaces a graft with reusable graph certificates and resolved ownership.
///
/// # Errors
/// Returns the errors of [`graft_with_domains`] and malformed graph errors.
pub fn graft_certified_with_domains<'a>(
    parent: &Tree<'a>,
    at: &[u8],
    entry: Entry<'a>,
    replace: bool,
    roots: &impl Roots<'a>,
    graph: &mut super::RootGraph,
    domains: &'a super::OperationDomains,
) -> Result<GraftResult<'a>, Error> {
    graft_certified_inner(parent, at, entry, replace, roots, graph, Some(domains))
}

fn graft_certified_inner<'a>(
    parent: &Tree<'a>,
    at: &[u8],
    entry: Entry<'a>,
    replace: bool,
    roots: &impl Roots<'a>,
    graph: &mut super::RootGraph,
    domains: Option<&'a super::OperationDomains>,
) -> Result<GraftResult<'a>, Error> {
    let EntryKind::Tree { root: target, .. } = entry.kind else {
        return Err(Error::Structure);
    };
    let encoded_entry =
        tree_format::encode_entry(&entry, parent.min_chunk_size()).map_err(Error::Key)?;
    let recipe = super::Recipe::Graft {
        parent: parent.root_identity(),
        target,
        at,
        entry: &encoded_entry,
        replace,
        domains,
    }
    .encode();
    let mut admission = graph.admit(parent, roots)?;
    let (tree, mut mutation) = graft_mutate(parent, at, entry, replace)?;
    let ownership = super::domain::preserve(parent, tree, domains)?;
    add_work(&mut mutation, ownership.work);
    let tree = ownership.tree;
    let added = graph.admit(&tree, roots)?;
    admission.nodes += added.nodes;
    admission.roots += added.roots;
    Ok(GraftResult {
        tree,
        recipe,
        mutation,
        admission,
    })
}

/// Replaces a path with a graft without rewriting the target's keys.
///
/// # Errors
/// Returns a key error for an invalid path, `InlineChildren` when descendants
/// exist without replacement permission, or a builder error for invalid
/// ancestor structure. The caller validates newly admitted root graphs with
/// [`crate::algebra::validate_acyclic`] before making them reachable from a ref.
fn graft_mutate<'a>(
    parent: &Tree<'a>,
    at: &[u8],
    entry: Entry<'a>,
    replace: bool,
) -> Result<(Tree<'a>, crate::tree_builder::Work), Error> {
    tree_format::validate_key(at).map_err(Error::Key)?;
    if !matches!(entry.kind, EntryKind::Tree { .. }) {
        return Err(Error::Structure);
    }

    let mut start = at.to_vec();
    start.push(b'/');
    let descendants = parent
        .cursor_from(&start)
        .next()
        .is_some_and(|item| beneath(&item.key, at));
    if !replace && descendants {
        return Err(Error::InlineChildren);
    }

    let mut result = parent.clone();
    let mut work = crate::tree_builder::Work::default();
    if descendants {
        let mut end = at.to_vec();
        end.push(b'0');
        let mutation = result.replace_range(&start, Some(&end), Vec::new())?;
        add_work(&mut work, mutation.work);
        result = mutation.tree;
    }
    let mutation = result.insert(LeafItem {
        key: at.to_vec(),
        entry,
    })?;
    add_work(&mut work, mutation.work);
    Ok((mutation.tree, work))
}

fn add_work(total: &mut crate::tree_builder::Work, added: crate::tree_builder::Work) {
    total.node_reads += added.node_reads;
    total.validation_reads += added.validation_reads;
    total.item_encodings += added.item_encodings;
    total.node_encodings += added.node_encodings;
}
