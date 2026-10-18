//! An append-only ordered set whose clones share their storage.
//!
//! [`Schedule`](super::Schedule) keeps the choice opportunities its selection
//! decisions chose, so a per-quantum stop check can ask whether a discovered
//! opportunity is already selected without decoding the recorded history.
//! Schedules are cloned and extended once per quantum, so an owned set would
//! be copied on every append that follows a clone.
//!
//! [`PersistentSet`] is instead a binary-counter stack of sorted, immutable,
//! pairwise-disjoint runs behind reference counts:
//!
//! ```text
//! runs: [2^k values] [2^j values] ... [1 value]     k > j > ... > 0
//! ```
//!
//! Inserting a new value pushes a one-element run and merges trailing runs of
//! equal length, exactly like incrementing a binary counter. Each value is
//! therefore copied O(log n) times over the life of the set, a clone copies
//! one reference count, and a lookup binary-searches at most log2(n) + 1
//! runs. Clones that diverge share every run created before they diverged.

use std::sync::Arc;

/// A persistent set of ordered values that supports insertion and lookup.
///
/// Membership is a pure function of the values inserted; insertion order and
/// sharing between clones never affect it.
pub(super) struct PersistentSet<T> {
    // Strictly decreasing power-of-two lengths, sorted within each run, and
    // no value in more than one run.
    runs: Arc<Vec<Arc<[T]>>>,
}

impl<T> Default for PersistentSet<T> {
    fn default() -> Self {
        Self {
            runs: Arc::default(),
        }
    }
}

impl<T> Clone for PersistentSet<T> {
    fn clone(&self) -> Self {
        Self {
            runs: Arc::clone(&self.runs),
        }
    }
}

impl<T: Ord + Clone> PersistentSet<T> {
    /// Returns whether `value` has been inserted.
    pub(super) fn contains(&self, value: &T) -> bool {
        self.runs.iter().any(|run| run.binary_search(value).is_ok())
    }

    /// Inserts `value`, leaving other clones unchanged.
    ///
    /// Re-inserting a present value is a no-op, which keeps runs disjoint and
    /// their lengths exact powers of two.
    pub(super) fn insert(&mut self, value: T) {
        if self.contains(&value) {
            return;
        }

        let runs = Arc::make_mut(&mut self.runs);
        let mut carry: Arc<[T]> = Arc::from([value]);
        while let Some(last) = runs.pop_if(|last| last.len() == carry.len()) {
            carry = merge_disjoint_runs(&last, &carry);
        }
        runs.push(carry);
    }
}

/// Merges two sorted runs that share no value into one sorted run.
fn merge_disjoint_runs<T: Ord + Clone>(left: &[T], right: &[T]) -> Arc<[T]> {
    let mut merged = Vec::with_capacity(left.len() + right.len());
    let (mut left, mut right) = (left.iter().peekable(), right.iter().peekable());
    while let (Some(next_left), Some(next_right)) = (left.peek(), right.peek()) {
        if next_left < next_right {
            merged.extend(left.next().cloned());
        } else {
            merged.extend(right.next().cloned());
        }
    }
    merged.extend(left.cloned());
    merged.extend(right.cloned());
    Arc::from(merged)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn assert_matches_reference(set: &PersistentSet<u64>, reference: &BTreeSet<u64>) {
        for value in 0..128 {
            assert_eq!(
                set.contains(&value),
                reference.contains(&value),
                "membership of {value}"
            );
        }

        let lengths = set.runs.iter().map(|run| run.len()).collect::<Vec<_>>();
        assert!(lengths.windows(2).all(|pair| pair[0] > pair[1]));
        assert!(lengths.iter().all(|length| length.is_power_of_two()));
        assert_eq!(lengths.iter().sum::<usize>(), reference.len());
        assert!(set.runs.iter().all(|run| run.is_sorted()));
    }

    #[test]
    fn membership_matches_an_owned_set_across_duplicate_inserts() {
        let mut set = PersistentSet::default();
        let mut reference = BTreeSet::new();

        // A fixed stride revisits earlier values, exercising duplicate inserts.
        for step in 0..200_u64 {
            let value = (step * 37) % 100;
            set.insert(value);
            reference.insert(value);
            assert_matches_reference(&set, &reference);
        }
    }

    #[test]
    fn diverging_clones_keep_independent_membership() {
        let mut base = PersistentSet::default();
        let mut base_reference = BTreeSet::new();
        for value in 0..21 {
            base.insert(value);
            base_reference.insert(value);
        }

        let mut left = base.clone();
        let mut right = base.clone();
        let mut left_reference = base_reference.clone();
        let mut right_reference = base_reference.clone();
        for value in 21..40 {
            left.insert(value);
            left_reference.insert(value);
            right.insert(value + 40);
            right_reference.insert(value + 40);
        }

        assert_matches_reference(&base, &base_reference);
        assert_matches_reference(&left, &left_reference);
        assert_matches_reference(&right, &right_reference);
    }
}
