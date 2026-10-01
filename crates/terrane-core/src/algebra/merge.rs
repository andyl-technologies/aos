//! Combines three immutable Merkle cursors under explicit conflict policies.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;

use super::compare::{Frontier, Part};
use super::{Error, MergePolicy, Roots};
use crate::tree_builder::{SpliceOutcome, SubtreeReplacement, Tree, Work};
use crate::tree_format::{Entry, EntryKind};

#[cfg(test)]
#[path = "merge_tests.rs"]
mod tests;

/// A materialized merge and its explicit unresolved-conflict state.
#[derive(Clone, Debug)]
pub struct MergeResult<'a> {
    /// Canonical merged tree.
    pub tree: Tree<'a>,
    /// Canonical operation inputs and trust context for commit recomputation.
    pub recipe: Vec<u8>,
    /// Whether any conflict value remains in the result.
    pub conflicted: bool,
    /// Whether the destination had not changed since the merge base.
    pub fast_forward: bool,
    /// Intermediate recipe inputs and graft targets published with the result.
    pub derived_roots: Vec<Tree<'a>>,
    /// Merkle nodes expanded across the three input cursors.
    pub expanded_nodes: usize,
    /// Whole incoming subtrees adopted without reconstructing their nodes.
    pub reused_subtrees: usize,
    /// Actual map mutation and canonical edge-certification work.
    pub mutation_work: Work,
    /// Previously uncertified graph frontiers admitted separately from map edits.
    pub admission_work: super::GraphWork,
}

fn whiteout<'a>() -> Entry<'a> {
    Entry {
        kind: EntryKind::Whiteout,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn resolve<'a>(
    base: Option<&Entry<'a>>,
    ours: Option<&Entry<'a>>,
    theirs: Option<&Entry<'a>>,
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    input_roots: [crate::identity::Digest; 2],
    path: &[u8],
) -> Result<Option<Entry<'a>>, Error> {
    if ours == theirs {
        return Ok(ours.cloned());
    }
    if ours == base {
        return Ok(theirs.cloned());
    }
    if theirs == base {
        return Ok(ours.cloned());
    }

    for policy in policies {
        match policy {
            MergePolicy::PreferOurs => return Ok(ours.cloned()),
            MergePolicy::PreferTheirs => return Ok(theirs.cloned()),
            MergePolicy::PreferTrusted => {
                // Absent values carry no provenance and cannot satisfy trust.
                match (
                    ours.is_some_and(|entry| trusted.accepts_path(0, input_roots[0], path, entry)),
                    theirs
                        .is_some_and(|entry| trusted.accepts_path(1, input_roots[1], path, entry)),
                ) {
                    (true, false) => return Ok(ours.cloned()),
                    (false, true) => return Ok(theirs.cloned()),
                    _ => {}
                }
            }
            MergePolicy::PreferNewer => {
                if let (Some(ours), Some(theirs)) = (ours, theirs)
                    && let (Some(our_time), Some(their_time)) = (
                        trusted.timestamp_path(0, input_roots[0], path, ours),
                        trusted.timestamp_path(1, input_roots[1], path, theirs),
                    )
                {
                    match our_time.cmp(&their_time) {
                        core::cmp::Ordering::Greater => return Ok(Some(ours.clone())),
                        core::cmp::Ordering::Less => return Ok(Some(theirs.clone())),
                        core::cmp::Ordering::Equal => {}
                    }
                }
            }
            MergePolicy::KeepConflict => break,
            MergePolicy::Error => return Err(Error::Conflict),
        }
    }

    let mut candidates = Vec::new();
    for candidate in [ours, theirs] {
        match candidate {
            Some(Entry {
                kind:
                    EntryKind::Conflict {
                        candidates: previous,
                        ..
                    },
                ..
            }) => candidates.extend(previous.iter().cloned()),
            Some(entry) => candidates.push(entry.clone()),
            None => candidates.push(whiteout()),
        }
    }
    Ok(Some(Entry {
        kind: EntryKind::Conflict {
            candidates,
            base: Some(base.cloned().map(Box::new)),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }))
}

fn graft_metadata_equal(a: &Entry<'_>, b: &Entry<'_>) -> bool {
    let (EntryKind::Tree { props: ap, .. }, EntryKind::Tree { props: bp, .. }) = (&a.kind, &b.kind)
    else {
        return false;
    };
    ap == bp
        && a.attrs == b.attrs
        && a.attrs_present == b.attrs_present
        && a.xattrs == b.xattrs
        && a.xattrs_present == b.xattrs_present
        && a.provenance == b.provenance
}

/// Merges three ordered Merkle frontiers without scanning shared subtrees.
///
/// Trust-sensitive policies require ordered authenticated signed views. Their
/// evaluators enforce effective root selectors and signed entry-origin receipts.
/// Grafts recurse only when their non-target fields agree on all three sides.
///
/// # Errors
/// Returns `Conflict` only when the explicit `error` policy is reached,
/// `MissingRoot` for unavailable nested merge targets, `RootPropertiesConflict`
/// for unresolved typed metadata, or a builder error for malformed inputs or
/// incompatible entry encoding contexts. Unverified or mismatched trust evidence
/// produces `Trust`. A changed destination without an explicit domain requires
/// [`merge_with_domains`] or returns `DomainContext`. Entry conflicts otherwise
/// remain values.
pub fn merge<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
) -> Result<MergeResult<'a>, Error> {
    merge_certified(
        base,
        ours,
        theirs,
        policies,
        trusted,
        roots,
        &mut super::RootGraph::new(),
    )
}

/// Merges with reusable graph certificates and exact enclosing conflict summaries.
///
/// Previously admitted unchanged DAGs need no traversal, including fast-forward
/// merges. First-time admission is reported separately from cursor/edit work.
///
/// # Errors
/// Returns the errors of [`merge`] and graph admission errors for unavailable,
/// cyclic, or identity-mismatched graft roots.
#[allow(clippy::too_many_arguments)]
pub fn merge_certified<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    graph: &mut super::RootGraph,
) -> Result<MergeResult<'a>, Error> {
    merge_certified_inner(base, ours, theirs, policies, trusted, roots, graph, None)
}

/// Merges immutable roots with trusted effective disclosure ownership.
///
/// # Errors
/// Returns the errors of [`merge`] and missing or ambiguous ownership context
/// for any changed destination root, including recursively merged grafts.
#[allow(clippy::too_many_arguments)]
pub fn merge_with_domains<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    domains: &'a super::OperationDomains,
) -> Result<MergeResult<'a>, Error> {
    merge_certified_with_domains(
        base,
        ours,
        theirs,
        policies,
        trusted,
        roots,
        &mut super::RootGraph::new(),
        domains,
    )
}

/// Merges with reusable graph certificates and trusted ownership bindings.
///
/// # Errors
/// Returns the errors of [`merge_with_domains`] and graph admission errors.
#[allow(clippy::too_many_arguments)]
pub fn merge_certified_with_domains<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    graph: &mut super::RootGraph,
    domains: &'a super::OperationDomains,
) -> Result<MergeResult<'a>, Error> {
    merge_certified_inner(
        base,
        ours,
        theirs,
        policies,
        trusted,
        roots,
        graph,
        Some(domains),
    )
}

#[allow(clippy::too_many_arguments)]
fn merge_certified_inner<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    graph: &mut super::RootGraph,
    domains: Option<&'a super::OperationDomains>,
) -> Result<MergeResult<'a>, Error> {
    trusted.authorize_policies(policies).map_err(Error::Trust)?;
    trusted
        .bind_inputs([
            base.root_identity(),
            ours.root_identity(),
            theirs.root_identity(),
        ])
        .map_err(Error::Trust)?;
    let mut admission = super::GraphWork::default();
    for tree in [base, ours, theirs] {
        let work = graph.admit(tree, roots)?;
        admission.roots += work.roots;
        admission.nodes += work.nodes;
    }
    let mut result = merge_at(
        base,
        ours,
        theirs,
        policies,
        trusted,
        roots,
        0,
        true,
        [ours.root_identity(), theirs.root_identity()],
        &[],
        domains,
    )?;
    struct Derived<'t, 'a, R> {
        trees: &'t [Tree<'a>],
        roots: &'t R,
    }
    impl<'a, R: Roots<'a>> Roots<'a> for Derived<'_, 'a, R> {
        fn resolve(&self, identity: &crate::identity::Digest) -> Option<&Tree<'a>> {
            self.trees
                .iter()
                .find(|tree| tree.root_identity() == *identity)
                .or_else(|| self.roots.resolve(identity))
        }
    }
    let targets = Derived {
        trees: &result.derived_roots,
        roots,
    };
    let work = graph.admit(&result.tree, &targets)?;
    admission.roots += work.roots;
    admission.nodes += work.nodes;
    result.conflicted = graph
        .conflicted(&result.tree.root_identity())
        .ok_or(Error::Structure)?;
    result.admission_work = admission;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn merge_at<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    depth: usize,
    allow_splice: bool,
    input_roots: [crate::identity::Digest; 2],
    prefix: &[u8],
    domains: Option<&'a super::OperationDomains>,
) -> Result<MergeResult<'a>, Error> {
    if depth > crate::tree_format::MAX_GRAFT_DEPTH {
        return Err(Error::Cycle);
    }
    let recipe = super::Recipe::Merge {
        base: base.root_identity(),
        ours: ours.root_identity(),
        theirs: theirs.root_identity(),
        policies,
        trust: trusted,
        domains,
    }
    .encode();
    if base.root_identity() == ours.root_identity() {
        return Ok(MergeResult {
            tree: theirs.clone(),
            recipe,
            conflicted: has_conflicts(theirs),
            fast_forward: true,
            derived_roots: Vec::new(),
            expanded_nodes: 0,
            reused_subtrees: 0,
            mutation_work: Work::default(),
            admission_work: super::GraphWork::default(),
        });
    }
    if ours.root_identity() == theirs.root_identity()
        || base.root_identity() == theirs.root_identity()
    {
        return Ok(MergeResult {
            tree: ours.clone(),
            recipe,
            conflicted: has_conflicts(ours),
            fast_forward: false,
            derived_roots: Vec::new(),
            expanded_nodes: 0,
            reused_subtrees: 0,
            mutation_work: Work::default(),
            admission_work: super::GraphWork::default(),
        });
    }

    let properties = super::domain::preserved_properties(
        ours,
        super::metadata::merge_properties(base, ours, theirs, policies)?,
        domains,
    )?;
    let mut cursors = [
        Frontier::new(base),
        Frontier::new(ours),
        Frontier::new(theirs),
    ];
    let mut updates = Vec::new();
    let mut patches = Vec::new();
    let mut derived_roots = Vec::new();
    let mut nested_conflicted = false;
    let mut nested_expanded = 0;
    let mut nested_reused = 0;
    let mut nested_work = Work::default();
    loop {
        let tops = [cursors[0].top(), cursors[1].top(), cursors[2].top()];
        if tops.iter().all(Option::is_none) {
            break;
        }
        if let [
            Some(Part::Node(a)),
            Some(Part::Node(b)),
            Some(Part::Node(c)),
        ] = tops
        {
            let aligned = a.first_key() == b.first_key()
                && b.first_key() == c.first_key()
                && a.last_key() == b.last_key()
                && b.last_key() == c.last_key()
                && a.level() == b.level()
                && b.level() == c.level();
            let keep_ours = b.identity() == c.identity() || a.identity() == c.identity();
            let incoming = if allow_splice && a.identity() == b.identity() {
                c.shared.map(Rc::clone)
            } else {
                None
            };
            if aligned && (keep_ours || incoming.is_some()) {
                if !keep_ours && let Some(target) = incoming {
                    patches.push(SubtreeReplacement {
                        old_identity: b.identity(),
                        target,
                    });
                }
                for cursor in &mut cursors {
                    cursor.parts.pop();
                }
                continue;
            }
        }

        let Some(key) = tops
            .iter()
            .flatten()
            .copied()
            .map(Part::first_key)
            .min()
            .map(<[u8]>::to_vec)
        else {
            break;
        };
        let mut expanded = false;
        for (cursor, top) in cursors.iter_mut().zip(tops) {
            if let Some(Part::Node(node)) = top
                && Part::Node(node).first_key() == key
            {
                cursor.expand();
                expanded = true;
            }
        }
        if expanded {
            continue;
        }

        let mut values = [None, None, None];
        for (value, cursor) in values.iter_mut().zip(&mut cursors) {
            if let Some(Part::Item(item)) = cursor.top()
                && item.key == key
            {
                *value = Some(&item.entry);
                cursor.parts.pop();
            }
        }
        let [base_value, our_value, their_value] = values;
        let mut result = None;
        if let [Some(a), Some(b), Some(c)] = values
            && graft_metadata_equal(a, b)
            && graft_metadata_equal(a, c)
            && let (
                EntryKind::Tree { root: ar, .. },
                EntryKind::Tree { root: br, .. },
                EntryKind::Tree { root: cr, .. },
            ) = (&a.kind, &b.kind, &c.kind)
            && ar != br
            && ar != cr
            && br != cr
        {
            let mut nested_prefix = prefix.to_vec();
            nested_prefix.extend_from_slice(&key);
            nested_prefix.push(b'/');
            let nested = merge_at(
                roots.resolve(ar).ok_or(Error::MissingRoot)?,
                roots.resolve(br).ok_or(Error::MissingRoot)?,
                roots.resolve(cr).ok_or(Error::MissingRoot)?,
                policies,
                trusted,
                roots,
                depth + 1,
                allow_splice,
                input_roots,
                &nested_prefix,
                domains,
            )?;
            nested_conflicted |= nested.conflicted;
            nested_expanded += nested.expanded_nodes;
            nested_reused += nested.reused_subtrees;
            add_work(&mut nested_work, nested.mutation_work);
            let mut entry = b.clone();
            if let EntryKind::Tree { root, .. } = &mut entry.kind {
                *root = nested.tree.root_identity();
            }
            derived_roots.extend(nested.derived_roots);
            derived_roots.push(nested.tree);
            result = Some(Some(entry));
        }
        let result = match result {
            Some(value) => value,
            None => {
                let mut path = prefix.to_vec();
                path.extend_from_slice(&key);
                resolve(
                    base_value,
                    our_value,
                    their_value,
                    policies,
                    trusted,
                    input_roots,
                    &path,
                )?
            }
        };
        if result.as_ref() != our_value {
            updates.push((key, result));
        }
    }

    let usage = if ours.usage() == crate::tree_format::TreeUse::OverlayLayer {
        crate::tree_format::TreeUse::OverlayLayer
    } else {
        crate::tree_format::TreeUse::Ordinary
    };
    let mut tree = ours.with_usage(usage)?;
    let mut mutation_work = nested_work;
    let blocked: Vec<_> = updates
        .iter()
        .filter(|(_, value)| {
            !value
                .as_ref()
                .is_some_and(|entry| entry.kind.permits_descendants())
        })
        .map(|(key, _)| key.clone())
        .collect();
    // Pruning a resolved nondirectory must also remove descendants shared by
    // unchanged cursors. All semantic edits are admitted in one transaction.
    let mut edits = BTreeMap::new();
    for blocked_path in &blocked {
        let mut start = blocked_path.clone();
        start.push(b'/');
        let mut end = blocked_path.clone();
        end.push(b'0');
        if patches.iter().any(|patch| {
            patch
                .target
                .first_key()
                .is_some_and(|first| first < end.as_slice())
                && patch
                    .target
                    .last_key()
                    .is_some_and(|last| last >= start.as_slice())
        }) {
            // Signed evaluators still require the enclosing full view path
            // when this root is retried without subtree splices.
            let mut result = merge_at(
                base,
                ours,
                theirs,
                policies,
                trusted,
                roots,
                depth,
                false,
                input_roots,
                prefix,
                domains,
            )?;
            result.expanded_nodes += nested_expanded
                + cursors
                    .iter()
                    .map(|cursor| cursor.expanded_nodes)
                    .sum::<usize>();
            add_work(&mut result.mutation_work, nested_work);
            return Ok(result);
        }
        for item in tree.cursor_from(&start).take_while(|item| item.key < end) {
            edits.insert(item.key.clone(), None);
        }
    }
    for (key, value) in updates {
        if !blocked
            .iter()
            .any(|prefix| key.starts_with(prefix) && key.get(prefix.len()) == Some(&b'/'))
        {
            edits.insert(key, value);
        }
    }
    let edits: Vec<_> = edits.into_iter().collect();
    match tree.edit_entries_with_subtrees(&edits, &patches)? {
        SpliceOutcome::Applied(mutation) => {
            add_work(&mut mutation_work, mutation.work);
            tree = mutation.tree;
        }
        SpliceOutcome::RechunkRequired(work) => {
            // Changed cuts require finer semantic frontiers; certification
            // remains measured even though the original tree is unchanged.
            let mut result = merge_at(
                base,
                ours,
                theirs,
                policies,
                trusted,
                roots,
                depth,
                false,
                input_roots,
                prefix,
                domains,
            )?;
            result.expanded_nodes += nested_expanded
                + cursors
                    .iter()
                    .map(|cursor| cursor.expanded_nodes)
                    .sum::<usize>();
            add_work(&mut result.mutation_work, nested_work);
            add_work(&mut result.mutation_work, work);
            return Ok(result);
        }
    }
    let mutation = tree.with_properties(properties)?;
    add_work(&mut mutation_work, mutation.work);
    tree = mutation.tree;
    let conflicted = nested_conflicted || has_conflicts(&tree);
    Ok(MergeResult {
        tree,
        recipe,
        conflicted,
        fast_forward: false,
        derived_roots,
        expanded_nodes: nested_expanded
            + cursors
                .iter()
                .map(|cursor| cursor.expanded_nodes)
                .sum::<usize>(),
        reused_subtrees: nested_reused + patches.len(),
        mutation_work,
        admission_work: super::GraphWork::default(),
    })
}

fn add_work(total: &mut Work, work: Work) {
    total.node_reads += work.node_reads;
    total.validation_reads += work.validation_reads;
    total.item_encodings += work.item_encodings;
    total.node_encodings += work.node_encodings;
}

fn has_conflicts(tree: &Tree<'_>) -> bool {
    tree.has_conflicts()
}

impl MergeResult<'_> {
    /// Binds the root, ordered parents, recipe, and conflict flag to a commit.
    ///
    /// Clears any stale signature because these fields change its preimage.
    pub fn bind_commit(
        &self,
        commit: &mut crate::refs::Commit,
        parents: [crate::identity::Digest; 2],
    ) {
        commit.tree = self.tree.root_identity();
        commit.parents = parents.to_vec();
        commit.profile_pair.recipe = Some(self.recipe.clone());
        commit.profile_pair.conflicted = Some(self.conflicted);
        commit.provenance.source = crate::refs::CommitSource::Merged;
        commit.signature = None;
    }
}
