//! Unions completed history evidence without replacing checked authority.
//!
//! Public unions accept completed contexts on both sides. Private disclosure
//! candidates may import completed dependencies while their own scope remains
//! provisional; that staging never exposes a completed candidate history.

use super::{Rejected, VerifiedHistory};

impl VerifiedHistory {
    /// Appends compatible authenticated evidence with completed view contexts.
    ///
    /// The union preserves checked disclosure boundaries, original root scopes,
    /// retained bootstrap policies and selected side records. A repeated commit
    /// must carry the same signed record and original authentication context.
    /// This operation creates no authority from provisional scopes and performs
    /// no current token, ACL or physical repository authorization.
    ///
    /// Missing tree or ancestry witnesses remain missing until supplied and
    /// checked separately. Rejection leaves the receiving history unchanged.
    ///
    /// # Errors
    /// Returns [`Rejected`] for unfinished or provisional contexts, different
    /// chunk-profile limits, graph cycles, or conflicting signed records,
    /// verification contexts, tree interpretations, side records, disclosure
    /// boundaries, original root scopes or retained bootstrap policies.
    pub fn append_verified(&mut self, other: &Self) -> Result<(), Rejected> {
        self.require_completed_history()?;
        self.append_evidence(other)
    }

    fn require_completed_history(&self) -> Result<(), Rejected> {
        if !self.provisional_scopes.is_empty() {
            return Err(Rejected);
        }
        for view in self.commits.keys() {
            self.require_verified_context(*view)?;
        }
        Ok(())
    }

    pub(in crate::provenance) fn append_evidence(&mut self, other: &Self) -> Result<(), Rejected> {
        other.require_completed_history()?;
        if self.min_chunk_size != other.min_chunk_size {
            return Err(Rejected);
        }
        let mut candidate = self.clone();
        for (identity, commit) in &other.commits {
            if candidate
                .commits
                .get(identity)
                .is_some_and(|previous| previous != commit)
            {
                return Err(Rejected);
            }
            candidate.insert_commit(commit.clone())?;
        }
        for (identity, bytes) in &other.nodes {
            if candidate
                .nodes
                .get(identity)
                .is_some_and(|previous| previous != bytes)
            {
                return Err(Rejected);
            }
            candidate.nodes.insert(*identity, bytes.clone());
        }
        for (root, children) in &other.roots {
            if candidate
                .roots
                .get(root)
                .is_some_and(|previous| previous != children)
                || candidate
                    .usage
                    .get(root)
                    .is_some_and(|usage| other.usage.get(root) != Some(usage))
            {
                return Err(Rejected);
            }
            candidate.roots.insert(*root, children.clone());
            candidate
                .usage
                .insert(*root, *other.usage.get(root).ok_or(Rejected)?);
        }
        for (key, bound) in &other.side_attributes {
            if candidate
                .side_attributes
                .get(key)
                .is_some_and(|previous| previous != bound)
            {
                return Err(Rejected);
            }
            candidate.side_attributes.insert(key.clone(), bound.clone());
        }
        for (location, boundary) in &other.disclosure_boundaries {
            if candidate
                .disclosure_boundaries
                .get(location)
                .is_some_and(|previous| previous != boundary)
            {
                return Err(Rejected);
            }
            candidate
                .disclosure_boundaries
                .insert(location.clone(), boundary.clone());
        }
        candidate
            .disclosure_parents
            .extend(other.disclosure_parents.iter().copied());
        candidate
            .disclosure_verified_views
            .extend(other.disclosure_verified_views.iter().copied());
        for (identity, scope) in &other.root_scopes {
            let scope = match candidate.root_scopes.get(identity) {
                Some(previous) => previous.merge_checked(scope)?,
                None => scope.clone(),
            };
            candidate.root_scopes.insert(*identity, scope);
        }
        for (key, baseline) in &other.bootstrap_policies {
            if candidate
                .bootstrap_policies
                .get(key)
                .is_some_and(|previous| previous != baseline)
            {
                return Err(Rejected);
            }
            candidate
                .bootstrap_policies
                .insert(key.clone(), baseline.clone());
        }
        *self = candidate;
        Ok(())
    }
}
