//! Tracks exact sorted marks and retention-sensitive commit expansion.
//!
//! The bounded membership hint is subordinate to the exact sorted digest set.
//! A hint may produce false positives; it must never hide an exact mark.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use super::{ParentCutoff, ProofContext};
use crate::identity::Digest;

/// Width in bytes of each checkpoint's deterministic membership hint.
pub const MARK_FILTER_BYTES: usize = 2048;

/// An exact content mark set with a bounded, rebuildable membership hint.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MarkSet {
    hashes: BTreeSet<Digest>,
}

impl MarkSet {
    /// Creates an empty collection mark set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks a digest and reports whether this is its first encounter.
    pub fn insert(&mut self, hash: Digest) -> bool {
        self.hashes.insert(hash)
    }

    /// Tests the exact mark set rather than accepting a filter positive.
    pub fn contains(&self, hash: &Digest) -> bool {
        self.hashes.contains(hash)
    }

    /// Borrows the exact digest set in strict lexicographic order.
    pub fn hashes(&self) -> impl Iterator<Item = &Digest> {
        self.hashes.iter()
    }

    /// Returns one index-shaped shard's strictly sorted digests.
    pub fn shard(&self, shard: u8) -> Vec<Digest> {
        self.hashes
            .iter()
            .filter(|hash| hash[0] == shard)
            .copied()
            .collect()
    }

    /// Computes the bounded three-position membership hint for sorted digests.
    pub fn filter(hashes: &[Digest]) -> Vec<u8> {
        let mut filter = alloc::vec![0; MARK_FILTER_BYTES];
        for hash in hashes {
            for bit in positions(hash) {
                filter[bit / 8] |= 1 << (bit % 8);
            }
        }
        filter
    }

    /// Reports possible membership without claiming an exact positive.
    ///
    /// An incorrectly sized filter is treated as possibly containing every
    /// digest; malformed hints must never authorize deletion.
    pub fn filter_may_contain(filter: &[u8], hash: &Digest) -> bool {
        filter.len() != MARK_FILTER_BYTES
            || positions(hash)
                .into_iter()
                .all(|bit| filter[bit / 8] & (1 << (bit % 8)) != 0)
    }
}

fn positions(hash: &Digest) -> [usize; 3] {
    [1, 11, 21].map(|offset| {
        usize::from(u16::from_be_bytes([hash[offset], hash[offset + 1]])) % (MARK_FILTER_BYTES * 8)
    })
}

/// Records the least restrictive parent cutoff expanded for each signed commit.
///
/// Tree and content marking is shared, but parent traversal cannot be skipped
/// merely because another ref already visited the commit with shorter retention.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitVisits {
    cutoffs: BTreeMap<(Digest, Option<ProofContext>), ParentCutoff>,
}

impl CommitVisits {
    /// Creates empty commit expansion state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits an initial visit or a less restrictive parent-retention context.
    ///
    /// Roots-only is narrowest; lower timestamps and then unbounded are broader.
    pub fn expand(&mut self, hash: Digest, cutoff: ParentCutoff) -> bool {
        self.expand_in_context(hash, cutoff, None)
    }

    /// Reports whether a commit's parent context still requires expansion.
    ///
    /// This observation does not change state; callers stage fallible metadata
    /// work before recording the completed context with `expand`.
    pub fn needs_expansion(&self, hash: &Digest, cutoff: ParentCutoff) -> bool {
        self.needs_expansion_in_context(hash, cutoff, None)
    }

    /// Admits a visit without merging distinct proof contexts.
    pub fn expand_in_context(
        &mut self,
        hash: Digest,
        cutoff: ParentCutoff,
        context: Option<&ProofContext>,
    ) -> bool {
        if !self.needs_expansion_in_context(&hash, cutoff, context) {
            return false;
        }
        self.cutoffs.insert((hash, context.cloned()), cutoff);
        true
    }

    /// Tests cutoff dominance only within the exact supplied proof context.
    pub fn needs_expansion_in_context(
        &self,
        hash: &Digest,
        cutoff: ParentCutoff,
        context: Option<&ProofContext>,
    ) -> bool {
        match self.cutoffs.get(&(*hash, context.cloned())) {
            None => true,
            Some(previous) => !previous.covers(cutoff),
        }
    }

    /// Borrows completed visits in commit and optional proof-context order.
    pub fn contexts(
        &self,
    ) -> impl Iterator<Item = (&Digest, Option<&ProofContext>, &ParentCutoff)> {
        self.cutoffs
            .iter()
            .map(|((hash, context), cutoff)| (hash, context.as_ref(), cutoff))
    }
}

#[cfg(test)]
mod tests {
    //! Checks pure mark policy invariants.

    use super::*;

    #[test]
    fn gc_mark_reachability_revisits_shared_commits_under_broader_retention() {
        let mut visits = CommitVisits::new();
        assert!(visits.expand([1; 32], ParentCutoff::RootsOnly));
        assert!(!visits.expand([1; 32], ParentCutoff::RootsOnly));
        assert!(visits.expand([1; 32], ParentCutoff::Since(100)));
        assert!(!visits.expand([1; 32], ParentCutoff::Since(110)));
        assert!(visits.expand([1; 32], ParentCutoff::Since(90)));
        assert!(visits.expand([1; 32], ParentCutoff::Unbounded));
        assert!(!visits.expand([1; 32], ParentCutoff::Since(0)));
        assert!(!visits.expand([1; 32], ParentCutoff::RootsOnly));
    }

    #[test]
    fn gc_mark_checkpoint_filter_never_hides_exact_sorted_hashes() {
        let mut marks = MarkSet::new();
        for value in (0..=255).rev() {
            assert!(marks.insert([value; 32]));
        }
        assert!(!marks.insert([1; 32]));
        let hashes = marks.hashes().copied().collect::<Vec<_>>();
        assert!(hashes.windows(2).all(|pair| pair[0] < pair[1]));
        let filter = MarkSet::filter(&hashes);
        assert!(
            hashes
                .iter()
                .all(|hash| MarkSet::filter_may_contain(&filter, hash))
        );
        assert_eq!(marks.shard(42), alloc::vec![[42; 32]]);
        assert!(MarkSet::filter_may_contain(&[], &[42; 32]));
    }
}
