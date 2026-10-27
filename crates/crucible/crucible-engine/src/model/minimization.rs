//! Deterministic finding-minimization candidate enumeration.
//!
//! Minimization replays shorter subsequences of a finding's recorded schedule.
//! Every candidate the enumerator admits has one of two shapes: an unremovable
//! prefix `[0, prefix_end)` followed by a few strictly increasing extra
//! indexes, or a bare prefix ending at a campaign branch. This module stores
//! each candidate in exactly that form, so a candidate costs memory
//! proportional to its extra indexes rather than to the schedule:
//!
//! ```text
//! original:  d0 d1 d2 d3 d4 d5 d6 d7
//! kept:      [0, 3) + {5, 7}          -> d0 d1 d2 d5 d7
//! removed:   [3, 5) + [6, 7)          -> d3 d4 d6
//! ```
//!
//! The candidate's schedule identity and seeded order key are streamed from
//! the original schedule when the candidate is admitted. Only the sort key
//! fields are retained, and a candidate's [`Schedule`] is materialized only
//! when it is replayed, one candidate at a time.

use std::ops::Range;

use super::*;
use crate::History;

/// Sorted, disjoint, nonadjacent half-open ranges of schedule decision indexes.
///
/// Minimization records which original decisions a candidate removed. A
/// removal set is a few runs of consecutive indexes, so it is stored as those
/// runs rather than as one entry per index.
///
/// # Examples
///
/// ```rust
/// use crucible_engine::ScheduleIndexRanges;
///
/// let removed = [3, 4, 6].into_iter().collect::<ScheduleIndexRanges>();
///
/// assert_eq!(removed.len(), 3);
/// assert_eq!(removed.ranges(), &[3..5, 6..7]);
/// assert_eq!(removed.iter().collect::<Vec<_>>(), vec![3, 4, 6]);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ScheduleIndexRanges {
    // Invariant: every range is nonempty, and each range starts strictly after
    // the previous range ends, so equal index sets have equal range lists.
    ranges: Vec<Range<usize>>,
}

impl ScheduleIndexRanges {
    /// Builds an empty index set.
    #[must_use]
    pub const fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Returns the number of indexes in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ranges.iter().map(ExactSizeIterator::len).sum()
    }

    /// Returns `true` when the set holds no indexes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the maximal runs of consecutive indexes in ascending order.
    #[must_use]
    pub fn ranges(&self) -> &[Range<usize>] {
        &self.ranges
    }

    /// Returns an iterator over the indexes in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.ranges.iter().flat_map(Clone::clone)
    }

    /// Returns `true` when the set holds `index`.
    #[must_use]
    pub fn contains(&self, index: usize) -> bool {
        let position = self.ranges.partition_point(|range| range.end <= index);
        self.ranges
            .get(position)
            .is_some_and(|range| range.contains(&index))
    }

    /// Appends `range`, which must start at or after every retained index.
    ///
    /// Empty ranges are ignored and a range touching the last run extends it.
    /// Returns `false`, leaving the set unchanged, when `range` would overlap
    /// or precede retained indexes.
    fn push_range(&mut self, range: Range<usize>) -> bool {
        if range.is_empty() {
            return true;
        }
        match self.ranges.last_mut() {
            Some(last) if range.start < last.end => false,
            Some(last) if range.start == last.end => {
                last.end = range.end;
                true
            }
            _ => {
                self.ranges.push(range);
                true
            }
        }
    }
}

impl FromIterator<usize> for ScheduleIndexRanges {
    /// Collects indexes in any order; duplicates collapse to one index.
    fn from_iter<I: IntoIterator<Item = usize>>(indexes: I) -> Self {
        let mut ranges = Self::new();
        for index in indexes.into_iter().collect::<BTreeSet<_>>() {
            // Ascending, distinct indexes always extend or follow the last run.
            ranges.push_range(index..index.saturating_add(1));
        }
        ranges
    }
}

/// Kept original indexes of one candidate: a prefix plus increasing extras.
///
/// The form is canonical: the first extra never equals `prefix_end`, because
/// such an extra is folded into the prefix. Equal kept sets therefore compare
/// equal, which the enumerator relies on for de-duplication.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct KeptIndexes {
    prefix_end: usize,
    extras: Vec<usize>,
}

impl KeptIndexes {
    fn new(mut prefix_end: usize, extras: &[usize]) -> Self {
        let folded = extras
            .iter()
            .zip(prefix_end..)
            .take_while(|(extra, next)| **extra == *next)
            .count();
        prefix_end += folded;
        Self {
            prefix_end,
            extras: extras[folded..].to_vec(),
        }
    }

    fn len(&self) -> usize {
        self.prefix_end + self.extras.len()
    }

    /// Returns the kept decisions of `original` in order.
    fn decisions<'a>(
        &'a self,
        original: &'a History<Decision>,
    ) -> impl Iterator<Item = &'a Decision> + 'a {
        original.iter().take(self.prefix_end).chain(
            self.extras
                .iter()
                .filter_map(move |index| original.get(*index)),
        )
    }

    /// Returns the complement of the kept indexes within `[0, original_len)`.
    fn removed(&self, original_len: usize) -> ScheduleIndexRanges {
        let mut removed = ScheduleIndexRanges::new();
        let mut cursor = self.prefix_end;
        for extra in &self.extras {
            // Extras strictly increase from the prefix, so each gap starts at
            // or after the previous one ends.
            removed.push_range(cursor..*extra);
            cursor = extra.saturating_add(1);
        }
        removed.push_range(cursor..original_len.max(cursor));
        removed
    }
}

/// One admitted candidate, held as its sort key and kept-index descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct MinimizationCandidate {
    kept: KeptIndexes,
    schedule_hash: ContentHash,
    order_key: ContentHash,
}

impl MinimizationCandidate {
    /// Returns the candidate schedule's canonical content address.
    pub(super) fn schedule_hash(&self) -> ContentHash {
        self.schedule_hash
    }

    /// Returns the original decision indexes this candidate removes.
    pub(super) fn removed_indices(&self, original: &Schedule) -> ScheduleIndexRanges {
        self.kept.removed(original.len())
    }

    /// Builds the candidate schedule from the original it was enumerated from.
    pub(super) fn schedule(&self, original: &Schedule) -> Schedule {
        Schedule::from_decisions(self.kept.decisions(original.decision_history()).cloned())
    }
}

/// Enumerates the bounded, deterministically ordered minimization candidates.
///
/// Candidates are ordered by kept length, then by seeded content-address
/// order key, then by their removed index sequence.
pub(super) fn minimization_candidates(
    config: MinimizationConfig,
    artifact: ContentHash,
    schedule: &Schedule,
) -> Result<Vec<MinimizationCandidate>, EngineError> {
    if !config.validates_schedule(schedule) {
        return Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "finding minimization",
            reason: "automatic interesting window does not match the original schedule",
        });
    }

    let decisions = schedule.decision_history();
    let removable_start = config
        .interesting_window()
        .map_or(0, InterestingScheduleWindow::start);
    let mut collector = MinimizationCandidateCollector {
        seed: config.seed,
        artifact,
        decisions,
        removable_start,
        candidates: Vec::new(),
        remaining_work: MAX_MINIMIZATION_CANDIDATES,
        admitted: BTreeSet::new(),
    };
    collector.collect_campaign_branch_suffix_reductions()?;
    let mut extras = Vec::new();
    for kept_len in 0..decisions.len().saturating_sub(removable_start) {
        if collector.is_finished() {
            break;
        }
        collector.collect_for_len(removable_start + kept_len, removable_start, &mut extras)?;
    }

    let mut candidates = collector.candidates;
    let original_len = decisions.len();
    candidates.sort_by(|left, right| {
        left.kept
            .len()
            .cmp(&right.kept.len())
            .then_with(|| left.order_key.cmp(&right.order_key))
            .then_with(|| {
                // Distinct candidates of equal length differ in their order
                // keys unless the hash collides, so this rarely runs.
                left.kept
                    .removed(original_len)
                    .iter()
                    .cmp(right.kept.removed(original_len).iter())
            })
    });
    Ok(candidates)
}

struct MinimizationCandidateCollector<'a> {
    seed: Seed,
    artifact: ContentHash,
    decisions: &'a History<Decision>,
    removable_start: usize,
    candidates: Vec<MinimizationCandidate>,
    remaining_work: usize,
    admitted: BTreeSet<KeptIndexes>,
}

impl MinimizationCandidateCollector<'_> {
    fn is_finished(&self) -> bool {
        self.candidates.len() >= MAX_MINIMIZATION_CANDIDATES || self.remaining_work == 0
    }

    fn is_campaign_branch_at(&self, index: usize) -> bool {
        self.decisions
            .get(index)
            .is_some_and(is_campaign_branch_selection)
    }

    fn collect_campaign_branch_suffix_reductions(&mut self) -> Result<(), EngineError> {
        if !self
            .decisions
            .iter_from(self.removable_start)
            .any(is_campaign_branch_selection)
        {
            return Ok(());
        }

        // Always retain the empty candidate, then reserve the remaining bounded
        // window for exact branch prefixes that can remove a trailing suffix.
        self.admit_candidate(KeptIndexes::new(self.removable_start, &[]))?;
        for index in self.removable_start..self.decisions.len().saturating_sub(1) {
            if self.is_finished() {
                break;
            }
            if self.is_campaign_branch_at(index) {
                self.admit_candidate(KeptIndexes::new(index + 1, &[]))?;
            }
        }
        Ok(())
    }

    fn admit_candidate(&mut self, kept: KeptIndexes) -> Result<(), EngineError> {
        if !self.spend_work() || self.admitted.contains(&kept) {
            return Ok(());
        }
        let candidate =
            candidate_from_kept(self.seed, self.artifact, self.decisions, kept.clone())?;
        self.admitted.insert(kept);
        self.candidates.push(candidate);
        Ok(())
    }

    fn spend_work(&mut self) -> bool {
        let Some(remaining) = self.remaining_work.checked_sub(1) else {
            return false;
        };
        self.remaining_work = remaining;
        true
    }

    /// Admits every kept set of `kept_len` decisions that extends the
    /// removable-start prefix by `extras` plus indexes from `start` onward.
    fn collect_for_len(
        &mut self,
        kept_len: usize,
        start: usize,
        extras: &mut Vec<usize>,
    ) -> Result<(), EngineError> {
        if self.is_finished() {
            return Ok(());
        }
        let kept_so_far = self.removable_start + extras.len();
        if kept_so_far == kept_len {
            return self.admit_candidate(KeptIndexes::new(self.removable_start, extras));
        }

        let remaining = kept_len - kept_so_far;
        let max_start = self.decisions.len().saturating_sub(remaining);
        for index in start..=max_start {
            if self.is_finished() {
                break;
            }
            if self.is_campaign_branch_at(index) && kept_so_far != index {
                // A campaign branch selection authenticates the complete
                // schedule prefix at its original index. Reject the branch as
                // soon as that prefix can no longer be complete.
                self.spend_work();
                continue;
            }
            extras.push(index);
            let collected = self.collect_for_len(kept_len, index + 1, extras);
            extras.pop();
            collected?;
        }
        Ok(())
    }
}

fn is_campaign_branch_selection(decision: &Decision) -> bool {
    matches!(decision, Decision::Selection(selection) if selection.is_campaign_branch())
}

/// Streams the schedule identity and order key of one kept-index descriptor.
fn candidate_from_kept(
    seed: Seed,
    artifact: ContentHash,
    decisions: &History<Decision>,
    kept: KeptIndexes,
) -> Result<MinimizationCandidate, EngineError> {
    let schedule_hash =
        canonical::schedule_hash_from_decisions(kept.len(), kept.decisions(decisions))
            .ok_or_else(|| candidate_descriptor_mismatch("kept indexes exceed the schedule"))?;
    let removed = kept.removed(decisions.len());
    let order_key = minimization_candidate_key(seed, artifact, schedule_hash, &removed)?;
    Ok(MinimizationCandidate {
        kept,
        schedule_hash,
        order_key,
    })
}

/// Computes the seeded order key of one candidate.
///
/// The key hashes the canonical material
///
/// ```text
/// seed=<hex>\nartifact=<hex>\nkept_schedule=<hex>\nremoved=<i>,<j>,...
/// ```
///
/// under the domain `crucible.minimization.candidate.v1`. The removed list is
/// written incrementally because it is as long as the schedule when manual
/// minimization keeps only a few decisions.
fn minimization_candidate_key(
    seed: Seed,
    artifact: ContentHash,
    kept_schedule: ContentHash,
    removed: &ScheduleIndexRanges,
) -> Result<ContentHash, EngineError> {
    let header = format!(
        "seed={}\nartifact={}\nkept_schedule={}\nremoved=",
        seed.to_hex(),
        content_hash_hex(artifact),
        content_hash_hex(kept_schedule)
    );
    let removed_count = removed.len();
    let list_len = removed
        .iter()
        .map(decimal_len)
        .fold(removed_count.saturating_sub(1), usize::saturating_add);
    let material_len = (header.len() as u64).saturating_add(list_len as u64);

    let mut stream =
        canonical::CanonicalMaterialStream::new("crucible.minimization.candidate.v1", material_len);
    stream.write(header.as_bytes());
    let mut digits = [0_u8; 20];
    for (position, index) in removed.iter().enumerate() {
        if position != 0 {
            stream.write(b",");
        }
        stream.write(decimal_digits(index, &mut digits));
    }
    stream
        .finish()
        .ok_or_else(|| candidate_descriptor_mismatch("order-key material length"))
}

fn decimal_len(value: usize) -> usize {
    value
        .checked_ilog10()
        .map_or(1, |digits| digits as usize + 1)
}

/// Writes `value` in decimal into the tail of `buffer` and returns the digits.
fn decimal_digits(mut value: usize, buffer: &mut [u8; 20]) -> &[u8] {
    let mut start = buffer.len();
    loop {
        start -= 1;
        // `value % 10` is a single decimal digit.
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &buffer[start..];
        }
    }
}

fn candidate_descriptor_mismatch(reason: &'static str) -> EngineError {
    EngineError::UnifiedOperationEvidenceMismatch {
        operation: "finding minimization candidate",
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(value: u64) -> Decision {
        Decision::RngDraw(RngDecision::ordinal(
            RngStreamId::from_name("minimization-descriptor-test"),
            0,
            value,
        ))
    }

    /// Order key built the way the previous materializing enumerator did.
    fn legacy_order_key(
        seed: Seed,
        artifact: ContentHash,
        kept: &Schedule,
        removed: &[usize],
    ) -> ContentHash {
        let removed = removed
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        ContentHash::from_canonical_material(
            "crucible.minimization.candidate.v1",
            &format!(
                "seed={}\nartifact={}\nkept_schedule={}\nremoved={removed}",
                seed.to_hex(),
                content_hash_hex(artifact),
                content_hash_hex(kept.content_hash())
            ),
        )
    }

    #[test]
    fn index_ranges_merge_adjacent_runs_and_reject_overlap() {
        let mut ranges = ScheduleIndexRanges::new();

        assert!(ranges.push_range(2..4));
        assert!(ranges.push_range(4..4));
        assert!(ranges.push_range(4..6));
        assert!(ranges.push_range(9..10));
        assert!(!ranges.push_range(5..12));

        assert_eq!(ranges.ranges(), &[2..6, 9..10]);
        assert_eq!(ranges.len(), 5);
        assert!(ranges.contains(5) && ranges.contains(9));
        assert!(!ranges.contains(6) && !ranges.contains(1) && !ranges.contains(10));
        assert_eq!(
            [9, 3, 2, 5, 4, 3]
                .into_iter()
                .collect::<ScheduleIndexRanges>()
                .ranges(),
            &[2..6, 9..10]
        );
    }

    #[test]
    fn kept_indexes_fold_contiguous_extras_into_the_prefix() {
        assert_eq!(KeptIndexes::new(3, &[3, 4, 7]), KeptIndexes::new(5, &[7]));
        assert_eq!(KeptIndexes::new(3, &[3, 4]), KeptIndexes::new(5, &[]));
        assert_eq!(KeptIndexes::new(3, &[3, 4, 7]).len(), 6);
        assert_eq!(
            KeptIndexes::new(2, &[4, 6]).removed(8).ranges(),
            &[2..4, 5..6, 7..8]
        );
        assert!(KeptIndexes::new(8, &[]).removed(8).is_empty());
    }

    #[test]
    fn streamed_descriptor_matches_materialized_schedule_and_legacy_key() -> Result<(), EngineError>
    {
        let original = Schedule::from_decisions((0..12).map(rng));
        let seed = Seed::from_u64(0x6d69_6e69);
        let artifact = ContentHash::from_canonical_material("test", "artifact");

        for (prefix_end, extras) in [
            (0, vec![]),
            (0, vec![11]),
            (0, vec![1, 5, 10]),
            (4, vec![]),
            (4, vec![6, 9]),
            (4, vec![4, 5, 11]),
            (12, vec![]),
        ] {
            let kept = KeptIndexes::new(prefix_end, &extras);
            let candidate =
                candidate_from_kept(seed, artifact, original.decision_history(), kept.clone())?;

            let kept_indices = (0..prefix_end)
                .chain(extras.iter().copied())
                .collect::<Vec<_>>();
            let expected_schedule = Schedule::from_decisions(
                kept_indices
                    .iter()
                    .map(|index| original.decision_history()[*index].clone()),
            );
            let expected_removed = (0..original.len())
                .filter(|index| !kept_indices.contains(index))
                .collect::<Vec<_>>();

            assert_eq!(candidate.schedule(&original), expected_schedule);
            assert_eq!(candidate.schedule_hash(), expected_schedule.content_hash());
            assert_eq!(
                candidate
                    .removed_indices(&original)
                    .iter()
                    .collect::<Vec<_>>(),
                expected_removed
            );
            assert_eq!(
                candidate.order_key,
                legacy_order_key(seed, artifact, &expected_schedule, &expected_removed),
                "order key for prefix {prefix_end} extras {extras:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn long_manual_schedules_enumerate_the_full_candidate_bound() -> Result<(), EngineError> {
        // The former candidate-copy byte bound admitted only a few hundred
        // candidates for a schedule this long; the fixed count bound alone
        // now applies.
        let original = Schedule::from_decisions((0..5_000).map(rng));
        let artifact = ContentHash::from_canonical_material("test", "long-artifact");

        let candidates = minimization_candidates(
            MinimizationConfig::new(Seed::from_u64(7)),
            artifact,
            &original,
        )?;

        assert_eq!(candidates.len(), MAX_MINIMIZATION_CANDIDATES);
        assert_eq!(candidates[0].kept.len(), 0);
        assert!(
            candidates
                .windows(2)
                .all(|pair| pair[0].kept.len() <= pair[1].kept.len())
        );
        assert!(candidates.iter().all(|candidate| candidate.kept.len() <= 1));
        Ok(())
    }
}
