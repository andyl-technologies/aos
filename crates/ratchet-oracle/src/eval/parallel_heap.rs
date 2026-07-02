//! Per-worker heap partitioning and hash-cons merge precursors.
//!
//! This module owns the Phase 3.5 planning boundary for heap state that will
//! later be attached to the parallel evaluator. It models two constraints from
//! RFC-0007 before the allocator and table internals become concurrent:
//!
//! ```text
//! top-level task -> initial worker -> worker-local bump nursery
//! worker-local hash-cons candidates -> deterministic equality-confirmed merge
//! ```
//!
//! The implementation is deliberately a deterministic planning layer. It does
//! not allocate evaluator objects, move nursery records, publish to the live
//! hash-cons tables, or replace the current single-threaded tree-walk heap.

use std::{collections::BTreeMap, fmt, num::NonZeroUsize};

use thiserror::Error;

/// Builds the deterministic initial per-worker nursery plan for top-level work.
///
/// Every worker receives a distinct nursery id equal to the worker id, and
/// tasks are assigned to initial worker-local nurseries round-robin so the
/// placement matches the safe top-level scheduler precursor. Future scheduler
/// integration must decide how stolen tasks switch allocation ownership.
pub fn parallel_worker_nursery_plan(
    task_count: usize,
    worker_count: NonZeroUsize,
) -> ParallelWorkerNurseryPlan {
    let worker_count = worker_count.get();
    let nurseries = (0..worker_count)
        .map(|worker_id| ParallelWorkerNursery {
            worker_id,
            nursery_id: worker_id,
        })
        .collect();
    let assignments = (0..task_count)
        .map(|task_index| {
            let worker_id = task_index % worker_count;
            ParallelWorkerNurseryAssignment {
                task_index,
                worker_id,
                nursery_id: worker_id,
            }
        })
        .collect();

    ParallelWorkerNurseryPlan {
        worker_count,
        task_count,
        nurseries,
        assignments,
    }
}

/// Merges worker-local hash-cons candidates into a deterministic canonical set.
///
/// Candidate order is normalized by `(worker_id, local_index)` before any
/// equality checks run. The hash key is only a bucket accelerator: values with
/// the same hash are reused only when `V: Eq` confirms equality, while hash
/// collisions with distinct values both become canonical entries.
///
/// Callers must compute `hash` from the same structural identity represented by
/// `value`. Equal values with different hash keys live in different buckets and
/// are admitted independently.
///
/// # Errors
///
/// Returns [`ParallelHashConsMergeError::DuplicateCandidateSlot`] when one
/// worker reports more than one candidate for the same local index.
pub fn merge_parallel_hash_cons_candidates<I, K, V>(
    candidates: I,
) -> Result<ParallelHashConsMerge<K, V>, ParallelHashConsMergeError>
where
    I: IntoIterator<Item = ParallelHashConsCandidate<K, V>>,
    K: Clone + Ord,
    V: Clone + Eq,
{
    let mut ordered_candidates = candidates.into_iter().collect::<Vec<_>>();
    ordered_candidates.sort_by_key(|candidate| (candidate.worker_id, candidate.local_index));

    for pair in ordered_candidates.windows(2) {
        let first = &pair[0];
        let second = &pair[1];
        if first.worker_id == second.worker_id && first.local_index == second.local_index {
            return Err(ParallelHashConsMergeError::DuplicateCandidateSlot {
                worker_id: first.worker_id,
                local_index: first.local_index,
            });
        }
    }

    let mut buckets = BTreeMap::<K, Vec<usize>>::new();
    let mut canonical_entries = Vec::<ParallelHashConsCandidate<K, V>>::new();
    let mut decisions = Vec::with_capacity(ordered_candidates.len());

    for candidate in ordered_candidates {
        let bucket = buckets.entry(candidate.hash.clone()).or_default();
        if let Some(canonical_index) = bucket
            .iter()
            .copied()
            .find(|canonical_index| canonical_entries[*canonical_index].value == candidate.value)
        {
            decisions.push(ParallelHashConsMergeDecision {
                candidate,
                canonical_index,
                outcome: ParallelHashConsMergeOutcome::Reused,
            });
            continue;
        }

        let canonical_index = canonical_entries.len();
        canonical_entries.push(candidate.clone());
        bucket.push(canonical_index);
        decisions.push(ParallelHashConsMergeDecision {
            candidate,
            canonical_index,
            outcome: ParallelHashConsMergeOutcome::Admitted,
        });
    }

    Ok(ParallelHashConsMerge {
        canonical_entries,
        decisions,
    })
}

/// A deterministic task-to-worker nursery partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelWorkerNurseryPlan {
    worker_count: usize,
    task_count: usize,
    nurseries: Vec<ParallelWorkerNursery>,
    assignments: Vec<ParallelWorkerNurseryAssignment>,
}

impl ParallelWorkerNurseryPlan {
    /// Returns the number of worker-local nurseries in the plan.
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns the number of top-level tasks covered by the plan.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns all worker-local nursery partitions in worker-id order.
    pub fn nurseries(&self) -> &[ParallelWorkerNursery] {
        &self.nurseries
    }

    /// Returns task-to-nursery assignments in stable task-index order.
    pub fn assignments(&self) -> &[ParallelWorkerNurseryAssignment] {
        &self.assignments
    }
}

/// A bump nursery owned by one worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelWorkerNursery {
    worker_id: usize,
    nursery_id: usize,
}

impl ParallelWorkerNursery {
    /// Returns the worker that owns this nursery.
    pub const fn worker_id(self) -> usize {
        self.worker_id
    }

    /// Returns the stable nursery identifier.
    pub const fn nursery_id(self) -> usize {
        self.nursery_id
    }
}

/// The nursery selected for one top-level task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelWorkerNurseryAssignment {
    task_index: usize,
    worker_id: usize,
    nursery_id: usize,
}

impl ParallelWorkerNurseryAssignment {
    /// Returns the stable top-level task index.
    pub const fn task_index(self) -> usize {
        self.task_index
    }

    /// Returns the worker assigned to own the task initially.
    pub const fn worker_id(self) -> usize {
        self.worker_id
    }

    /// Returns the worker-local nursery selected for the task's seed placement.
    pub const fn nursery_id(self) -> usize {
        self.nursery_id
    }
}

/// One worker-local hash-cons admission candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelHashConsCandidate<K, V> {
    worker_id: usize,
    local_index: usize,
    hash: K,
    value: V,
}

impl<K, V> ParallelHashConsCandidate<K, V> {
    /// Builds a candidate emitted by one worker-local table.
    pub const fn new(worker_id: usize, local_index: usize, hash: K, value: V) -> Self {
        Self {
            worker_id,
            local_index,
            hash,
            value,
        }
    }

    /// Returns the worker that produced the candidate.
    pub const fn worker_id(&self) -> usize {
        self.worker_id
    }

    /// Returns the candidate's stable index in the worker-local table.
    pub const fn local_index(&self) -> usize {
        self.local_index
    }

    /// Returns the structural hash bucket key.
    pub const fn hash(&self) -> &K {
        &self.hash
    }

    /// Returns the candidate payload used for equality confirmation.
    pub const fn value(&self) -> &V {
        &self.value
    }
}

/// A deterministic merge of worker-local hash-cons candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelHashConsMerge<K, V> {
    canonical_entries: Vec<ParallelHashConsCandidate<K, V>>,
    decisions: Vec<ParallelHashConsMergeDecision<K, V>>,
}

impl<K, V> ParallelHashConsMerge<K, V> {
    /// Returns canonical entries in deterministic admission order.
    pub fn canonical_entries(&self) -> &[ParallelHashConsCandidate<K, V>] {
        &self.canonical_entries
    }

    /// Returns per-candidate decisions in deterministic candidate order.
    pub fn decisions(&self) -> &[ParallelHashConsMergeDecision<K, V>] {
        &self.decisions
    }

    /// Returns the number of candidates considered by the merge.
    pub fn candidate_count(&self) -> usize {
        self.decisions.len()
    }

    /// Returns the number of candidates admitted as canonical entries.
    pub fn admitted_count(&self) -> usize {
        self.canonical_entries.len()
    }

    /// Returns the number of candidates that reused an earlier canonical entry.
    pub fn reused_count(&self) -> usize {
        self.decisions
            .len()
            .saturating_sub(self.canonical_entries.len())
    }
}

/// The merge outcome for one worker-local hash-cons candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelHashConsMergeDecision<K, V> {
    candidate: ParallelHashConsCandidate<K, V>,
    canonical_index: usize,
    outcome: ParallelHashConsMergeOutcome,
}

impl<K, V> ParallelHashConsMergeDecision<K, V> {
    /// Returns the candidate covered by this decision.
    pub const fn candidate(&self) -> &ParallelHashConsCandidate<K, V> {
        &self.candidate
    }

    /// Returns the canonical entry index selected for the candidate.
    pub const fn canonical_index(&self) -> usize {
        self.canonical_index
    }

    /// Returns whether the candidate was admitted or reused.
    pub const fn outcome(&self) -> ParallelHashConsMergeOutcome {
        self.outcome
    }
}

/// Whether a hash-cons candidate became canonical or reused an existing value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelHashConsMergeOutcome {
    /// The candidate became a new canonical entry.
    Admitted,
    /// The candidate reused an equality-confirmed earlier canonical entry.
    Reused,
}

/// A failure while merging worker-local hash-cons candidates.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelHashConsMergeError {
    /// One worker reported two candidates for the same local slot.
    #[error(
        "parallel hash-cons worker {worker_id} reported duplicate local candidate {local_index}"
    )]
    DuplicateCandidateSlot {
        /// The worker that reported the duplicate local index.
        worker_id: usize,
        /// The duplicated local candidate index.
        local_index: usize,
    },
}

impl fmt::Display for ParallelWorkerNurseryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} top-level task(s) partitioned across {} worker-local nursery(s)",
            self.task_count, self.worker_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workers(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("test worker count is nonzero")
    }

    fn candidate(
        worker_id: usize,
        local_index: usize,
        hash: u64,
        value: &'static str,
    ) -> ParallelHashConsCandidate<u64, &'static str> {
        ParallelHashConsCandidate::new(worker_id, local_index, hash, value)
    }

    #[test]
    fn nursery_plan_assigns_each_task_to_worker_local_nursery() {
        let plan = parallel_worker_nursery_plan(8, workers(3));

        assert_eq!(plan.worker_count(), 3);
        assert_eq!(plan.task_count(), 8);
        assert_eq!(
            plan.nurseries()
                .iter()
                .copied()
                .map(|nursery| (nursery.worker_id(), nursery.nursery_id()))
                .collect::<Vec<_>>(),
            vec![(0, 0), (1, 1), (2, 2)]
        );
        assert_eq!(
            plan.assignments()
                .iter()
                .copied()
                .map(|assignment| {
                    (
                        assignment.task_index(),
                        assignment.worker_id(),
                        assignment.nursery_id(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (0, 0, 0),
                (1, 1, 1),
                (2, 2, 2),
                (3, 0, 0),
                (4, 1, 1),
                (5, 2, 2),
                (6, 0, 0),
                (7, 1, 1)
            ]
        );
        assert_eq!(
            plan.to_string(),
            "8 top-level task(s) partitioned across 3 worker-local nursery(s)"
        );
    }

    #[test]
    fn nursery_plan_keeps_idle_worker_nurseries() {
        let plan = parallel_worker_nursery_plan(1, workers(4));

        assert_eq!(plan.worker_count(), 4);
        assert_eq!(plan.nurseries().len(), 4);
        assert_eq!(plan.assignments().len(), 1);
        assert_eq!(plan.assignments()[0].worker_id(), 0);
    }

    #[test]
    fn hash_cons_merge_is_independent_of_completion_order() {
        let first = merge_parallel_hash_cons_candidates([
            candidate(2, 0, 11, "third"),
            candidate(0, 1, 7, "shared"),
            candidate(1, 0, 7, "shared"),
            candidate(0, 0, 3, "first"),
        ])
        .expect("first merge succeeds");
        let second = merge_parallel_hash_cons_candidates([
            candidate(0, 0, 3, "first"),
            candidate(1, 0, 7, "shared"),
            candidate(2, 0, 11, "third"),
            candidate(0, 1, 7, "shared"),
        ])
        .expect("second merge succeeds");

        assert_eq!(first, second);
        assert_eq!(first.candidate_count(), 4);
        assert_eq!(first.admitted_count(), 3);
        assert_eq!(first.reused_count(), 1);
    }

    #[test]
    fn duplicate_candidates_converge_to_earliest_worker_local_entry() {
        let merge = merge_parallel_hash_cons_candidates([
            candidate(2, 0, 7, "shared"),
            candidate(0, 5, 7, "shared"),
            candidate(1, 0, 7, "other"),
        ])
        .expect("merge succeeds");

        assert_eq!(merge.admitted_count(), 2);
        assert_eq!(merge.reused_count(), 1);
        assert_eq!(merge.canonical_entries()[0], candidate(0, 5, 7, "shared"));
        assert_eq!(merge.canonical_entries()[1], candidate(1, 0, 7, "other"));
        assert_eq!(
            merge
                .decisions()
                .iter()
                .map(|decision| (
                    decision.candidate().worker_id(),
                    decision.candidate().local_index(),
                    decision.canonical_index(),
                    decision.outcome(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (0, 5, 0, ParallelHashConsMergeOutcome::Admitted),
                (1, 0, 1, ParallelHashConsMergeOutcome::Admitted),
                (2, 0, 0, ParallelHashConsMergeOutcome::Reused)
            ]
        );
    }

    #[test]
    fn hash_collisions_keep_distinct_values() {
        let merge = merge_parallel_hash_cons_candidates([
            candidate(0, 0, 7, "left"),
            candidate(1, 0, 7, "right"),
        ])
        .expect("merge succeeds");

        assert_eq!(merge.candidate_count(), 2);
        assert_eq!(merge.admitted_count(), 2);
        assert_eq!(merge.reused_count(), 0);
        assert!(merge.decisions().iter().all(|decision| {
            decision.outcome() == ParallelHashConsMergeOutcome::Admitted
                && decision.canonical_index() < merge.canonical_entries().len()
        }));
    }

    #[test]
    fn equal_values_with_different_hashes_are_admitted_separately() {
        let merge = merge_parallel_hash_cons_candidates([
            candidate(0, 0, 7, "shared"),
            candidate(1, 0, 11, "shared"),
        ])
        .expect("merge succeeds");

        assert_eq!(merge.candidate_count(), 2);
        assert_eq!(merge.admitted_count(), 2);
        assert_eq!(merge.reused_count(), 0);
        assert_eq!(
            merge
                .decisions()
                .iter()
                .map(ParallelHashConsMergeDecision::outcome)
                .collect::<Vec<_>>(),
            vec![
                ParallelHashConsMergeOutcome::Admitted,
                ParallelHashConsMergeOutcome::Admitted
            ]
        );
    }

    #[test]
    fn duplicate_worker_local_slot_is_rejected() {
        let error = merge_parallel_hash_cons_candidates([
            candidate(1, 0, 7, "left"),
            candidate(1, 0, 11, "right"),
        ])
        .expect_err("duplicate worker-local slots reject");

        assert_eq!(
            error,
            ParallelHashConsMergeError::DuplicateCandidateSlot {
                worker_id: 1,
                local_index: 0
            }
        );
    }

    #[test]
    fn empty_hash_cons_merge_has_no_entries() {
        let merge =
            merge_parallel_hash_cons_candidates(Vec::<ParallelHashConsCandidate<u64, u64>>::new())
                .expect("empty merge succeeds");

        assert_eq!(merge.candidate_count(), 0);
        assert_eq!(merge.admitted_count(), 0);
        assert_eq!(merge.reused_count(), 0);
        assert!(merge.canonical_entries().is_empty());
        assert!(merge.decisions().is_empty());
    }
}
