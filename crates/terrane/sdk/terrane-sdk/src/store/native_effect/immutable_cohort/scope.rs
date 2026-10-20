//! Defers only unrelated bodies classified by the closed Raw producer.
//!
//! Creation receipts are provenance, not authority. Complete cohort and preslot
//! boundaries still compare every body. A transient unrelated body mutation
//! restored before those boundaries may remain unobserved; refusal precedence
//! and harmless attempts before a persistent refusal can therefore change.

use super::super::{ExactRead, FencePolicy};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;

/// Fixes positive canonical candidates before installation erases input roles.
pub(in crate::store::native_effect) struct Candidates {
    root: PathBuf,
    owner: u32,
    bodies: Arc<BTreeMap<PathBuf, Vec<u8>>>,
}

impl Candidates {
    /// Reports fixed classification for producer tests without supplying authority.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(in crate::store::native_effect) fn contains(&self, path: &Path) -> bool {
        self.bodies.contains_key(path)
    }

    /// Receives only canonical expected-absent noncontainer immutable rows.
    pub(in crate::store::native_effect) fn new(
        root: &Path,
        owner: u32,
        bodies: BTreeMap<PathBuf, Vec<u8>>,
    ) -> Self {
        Self {
            root: root.to_owned(),
            owner,
            bodies: Arc::new(bodies),
        }
    }

    /// Carries actual previously acknowledged creations into one bounded worker.
    pub(in crate::store::native_effect) fn cohort(&self, created: &BTreeSet<PathBuf>) -> Scope {
        Scope {
            root: self.root.clone(),
            owner: self.owner,
            bodies: Arc::clone(&self.bodies),
            promoted: created.clone(),
            active: None,
            unambiguous: BTreeSet::new(),
        }
    }
}

/// Limits body omission to positively classified, actually rebound creations.
pub(in crate::store::native_effect) struct Scope {
    root: PathBuf,
    owner: u32,
    bodies: Arc<BTreeMap<PathBuf, Vec<u8>>>,
    promoted: BTreeSet<PathBuf>,
    active: Option<(PathBuf, PathBuf)>,
    unambiguous: BTreeSet<PathBuf>,
}

impl Scope {
    /// Keeps both current primitive names outside unrelated-output deferral.
    pub(in crate::store::native_effect) fn activate(&mut self, temporary: &Path, target: &Path) {
        self.active = Some((temporary.to_owned(), target.to_owned()));
    }

    /// Promotes only after actual no-replace rename and whole nofollow rebind.
    pub(in crate::store::native_effect) fn promote(&mut self, target: &Path) {
        self.promoted.insert(target.to_owned());
    }

    /// Classifies fixed predicate variants; this performs no physical observation.
    pub(in crate::store::native_effect) fn prepare(&mut self, reads: &[ExactRead]) {
        let mut first = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        for read in reads {
            if let Some(previous) = first.insert(&read.path, read)
                && previous != read
            {
                conflicts.insert(&read.path);
            }
        }
        self.unambiguous = first
            .iter()
            .filter(|(path, read)| {
                !conflicts.contains(*path)
                    && read.expected.is_some()
                    && read.metadata.is_some()
                    && read.identity.is_some()
            })
            .map(|(path, _)| (*path).clone())
            .collect();
    }

    /// Refreshes all variants at the only path changed by a successful rebind.
    ///
    /// Every other retained row is unchanged in the operation-local cohort. This
    /// classification observes no filesystem state and does not certify a body.
    pub(super) fn refresh_path(&mut self, reads: &[ExactRead], path: &Path) {
        let mut variants = reads.iter().filter(|read| read.path == path);
        let unambiguous = match variants.next() {
            Some(first) => {
                let conflict = variants.any(|read| read != first);
                !conflict
                    && first.expected.is_some()
                    && first.metadata.is_some()
                    && first.identity.is_some()
            }
            None => false,
        };
        if unambiguous {
            self.unambiguous.insert(path.to_owned());
        } else {
            self.unambiguous.remove(path);
        }
    }

    /// Drops pure membership for a consumed staging path with no retained rows.
    pub(super) fn forget_path(&mut self, path: &Path) {
        self.unambiguous.remove(path);
    }

    /// Requires matching whole expected bytes and every identical retained variant.
    pub(in crate::store::native_effect) fn defers(&self, read: &ExactRead) -> bool {
        if !self.promoted.contains(&read.path)
            || !read.path.starts_with(&self.root)
            || self
                .active
                .as_ref()
                .is_some_and(|(temporary, target)| read.path == *temporary || read.path == *target)
            || read.owner != self.owner
            || read.policy != (FencePolicy::Payload { owner: self.owner })
            || read.metadata.is_none()
            || read.identity.is_none()
            || read.expected.is_none()
            || !self.bodies.contains_key(&read.path)
            || self.bodies.get(&read.path).map(Vec::as_slice) != read.expected.as_deref()
        {
            return false;
        }
        // A conflicting protected, absent or differently bound variant stays full.
        self.unambiguous.contains(&read.path)
    }
}
