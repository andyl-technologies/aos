//! Describes pure fork and fold outcomes before repository ref publication.

use alloc::vec::Vec;

use super::{Change, Error, MergePolicy, MergeResult, Roots, diff, merge};
use crate::identity::Digest;
use crate::tree_builder::Tree;
use crate::tree_format::Entry;

/// The constant-time commit binding needed to create a fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fork {
    /// Tree inherited verbatim from the observed parent commit.
    pub root: Digest,
    /// Parent commit observed at the chosen ref sequence.
    pub parent: Digest,
    /// Parent ref sequence the fork was based on.
    pub sequence: u64,
}

/// Records a fork without reading or writing any tree node.
pub const fn fork(root: Digest, parent: Digest, sequence: u64) -> Fork {
    Fork {
        root,
        parent,
        sequence,
    }
}

/// The child-ref action following a successfully published fold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retirement {
    /// Removes the child branch after parent ref publication succeeds.
    Delete,
    /// Preserves the child commit as an immutable tag.
    Tag,
}

/// A fold ready for commit construction and conditional ref publication.
#[derive(Clone, Debug)]
pub struct FoldResult<'a> {
    /// Materialized tree and conflict/fast-forward flags.
    pub merged: MergeResult<'a>,
    /// Commit parents in required destination-first order.
    pub parents: [Digest; 2],
    /// Incoming changed paths excluded by commit authorization.
    pub excluded: Vec<Vec<u8>>,
    /// Child retirement to perform only after successful parent publication.
    pub retirement: Retirement,
}

/// Folds authorized child changes into the current parent tree.
///
/// The authorization predicate receives each changed path and its incoming
/// value (absent for deletion). The repository derives this predicate from
/// root-scoped grants; exclusions are reported in deterministic path order.
///
/// # Errors
/// Returns errors from authorization-filtered tree updates or three-way merge.
/// An explicit `error` policy may reject conflicts; other policies preserve or
/// resolve them. No ref is advanced or retired by this pure operation.
#[allow(clippy::too_many_arguments)]
pub fn fold<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    parents: [Digest; 2],
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    authorized: impl Fn(&[u8], Option<&Entry<'a>>) -> bool,
    retirement: Retirement,
) -> Result<FoldResult<'a>, Error> {
    fold_inner(
        base, ours, theirs, parents, policies, trusted, roots, authorized, retirement, None,
    )
}

/// Folds authorized child changes while preserving resolved root ownership.
///
/// # Errors
/// Returns the errors of [`fold`] and missing or ambiguous source ownership.
#[allow(clippy::too_many_arguments)]
pub fn fold_with_domains<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    parents: [Digest; 2],
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    authorized: impl Fn(&[u8], Option<&Entry<'a>>) -> bool,
    retirement: Retirement,
    domains: &'a super::OperationDomains,
) -> Result<FoldResult<'a>, Error> {
    fold_inner(
        base,
        ours,
        theirs,
        parents,
        policies,
        trusted,
        roots,
        authorized,
        retirement,
        Some(domains),
    )
}

#[allow(clippy::too_many_arguments)]
fn fold_inner<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    parents: [Digest; 2],
    policies: &[MergePolicy],
    trusted: &super::TrustContext,
    roots: &impl Roots<'a>,
    authorized: impl Fn(&[u8], Option<&Entry<'a>>) -> bool,
    retirement: Retirement,
    domains: Option<&'a super::OperationDomains>,
) -> Result<FoldResult<'a>, Error> {
    let changes = diff(base, theirs);
    let mut excluded = Vec::new();
    let mut incoming = theirs.clone();
    let mut restore = Vec::new();

    for change in changes {
        let value = match &change {
            Change::Added(item) => Some(&item.entry),
            Change::Removed(_) => None,
            Change::Modified { new, .. } => Some(new),
        };
        if !authorized(change.path(), value) {
            let path = change.path().to_vec();
            excluded.push(path.clone());
            restore.push((path.clone(), base.get(&path).cloned()));
        }
    }

    if !restore.is_empty() {
        incoming =
            super::domain::preserve(theirs, incoming.edit_entries(&restore)?.tree, domains)?.tree;
    }

    let trusted = if incoming.root_identity() != theirs.root_identity() {
        trusted
            .clone()
            .with_fold_filter(base, theirs, &incoming, &excluded, domains)
            .map_err(Error::Trust)?
    } else {
        trusted.clone()
    };
    let mut merged = match domains {
        Some(domains) => {
            super::merge_with_domains(base, ours, &incoming, policies, &trusted, roots, domains)?
        }
        None => merge(base, ours, &incoming, policies, &trusted, roots)?,
    };
    if incoming.root_identity() != theirs.root_identity() {
        merged.derived_roots.push(incoming);
    }
    Ok(FoldResult {
        merged,
        parents,
        excluded,
        retirement,
    })
}

impl Fork {
    /// Binds a fork's inherited root and single parent to a new commit.
    ///
    /// The caller copies the parent's profile pair, including its conflict flag,
    /// before binding. Forks clear recipes and introduction receipts so unchanged
    /// entries inherit their origins from the sole parent.
    pub fn bind_commit(&self, commit: &mut crate::refs::Commit) {
        commit.tree = self.root;
        commit.parents = alloc::vec![self.parent];
        commit.profile_pair.recipe = None;
        // An unchanged fork inherits origins from its parent. Copied `current`
        // receipts would instead reintroduce entries under this new signer.
        commit.profile_pair.entry_receipts = None;
        commit.signature = None;
    }
}

impl FoldResult<'_> {
    /// Binds the authorized fold and destination-first parent order to a commit.
    pub fn bind_commit(&self, commit: &mut crate::refs::Commit) {
        self.merged.bind_commit(commit, self.parents);
    }
}
