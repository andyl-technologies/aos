//! Compares authorized scoped metadata using the canonical core Merkle algebra.

use terrane_core::{
    algebra::{self, DiffResult},
    identity::Digest,
    surface::View,
    tree_builder::Tree,
    tree_format::{self, LeafItem, TreeUse},
};

use crate::store::{Clock, LocalFs, Store};

use super::{Error, PreparedTree, Repository, read::ReadEntry};

/// Retains owned metadata for a deterministic difference between two views.
///
/// Changes reuse core algebra values borrowed from canonical owned encodings.
/// No plaintext, unexposed sibling paths, or raw history witnesses are retained.
pub struct Difference {
    before: PreparedTree,
    after: PreparedTree,
    before_commit: Digest,
    after_commit: Digest,
    policies_changed: bool,
}

impl Difference {
    /// Returns the exact immutable commit used for the old view.
    pub const fn before_commit(&self) -> Digest {
        self.before_commit
    }

    /// Returns the exact immutable commit used for the new view.
    pub const fn after_commit(&self) -> Digest {
        self.after_commit
    }

    /// Reports changes to inherited root or graft property declarations.
    pub const fn policies_changed(&self) -> bool {
        self.policies_changed
    }

    /// Returns canonical entry changes and observable Merkle comparison work.
    ///
    /// Policy declaration changes are reported separately by
    /// [`Self::policies_changed`]; the projected metadata has no invented root
    /// property values or permission to flatten stored policy boundaries.
    ///
    /// # Errors
    /// Returns a canonical tree error if retained metadata cannot be decoded.
    pub fn entries(&self) -> Result<DiffResult<'_>, tree_format::Error> {
        let before = self.before.tree()?;
        let after = self.after.tree()?;
        Ok(algebra::diff_with_work(&before, &after))
    }
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Compares two currently authorized views without fetching object content.
    ///
    /// # Errors
    /// Rejects denied or untrusted scope, unknown policies, invalid metadata,
    /// unsupported unresolved entries, and paths escaping either presentation.
    pub async fn diff(
        &self,
        before: &View,
        after: &View,
        token: &[u8],
        surface: &str,
    ) -> Result<Difference, Error> {
        let (old_snapshot, old_entries) = self.metadata(before, token, surface).await?;
        let (new_snapshot, new_entries) = self.metadata(after, token, surface).await?;
        let minimum = self.chunk_profile().minimum() as u64;
        let old_policy = policies(&old_snapshot, &before.subtree, minimum)?;
        let new_policy = policies(&new_snapshot, &after.subtree, minimum)?;
        Ok(Difference {
            before: prepared(&old_entries, minimum)?,
            after: prepared(&new_entries, minimum)?,
            before_commit: old_snapshot.commit.identity(),
            after_commit: new_snapshot.commit.identity(),
            policies_changed: old_policy != new_policy,
        })
    }
}

fn prepared(entries: &[ReadEntry], minimum: u64) -> Result<PreparedTree, Error> {
    let entries = entries
        .iter()
        .map(|item| {
            Ok(LeafItem {
                key: item.key.clone(),
                entry: tree_format::decode_entry_bytes(&item.encoded, minimum)?,
            })
        })
        .collect::<Result<Vec<_>, tree_format::Error>>()?;
    let tree = Tree::build(entries, None, minimum, TreeUse::Ordinary)?;
    Ok(PreparedTree::from_tree(&tree)?)
}

type PolicyDeclarations = Vec<(Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>)>;

fn policies(
    snapshot: &crate::guard::AuthorizedSnapshot,
    scope: &[u8],
    minimum: u64,
) -> Result<PolicyDeclarations, Error> {
    let mut path = b"/".to_vec();
    path.extend_from_slice(scope);
    Ok(snapshot
        .evidence
        .policy_path(&path, minimum)?
        .into_iter()
        .map(|(properties, overrides)| {
            let owned = |items: Vec<terrane_core::tree_format::Property<'_>>| {
                items
                    .into_iter()
                    .map(|item| (item.name.to_owned(), item.value.to_vec()))
                    .collect()
            };
            (owned(properties), owned(overrides))
        })
        .collect())
}
