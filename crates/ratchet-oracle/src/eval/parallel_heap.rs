//! Per-worker heap partitioning and hash-cons merge precursors.
//!
//! This module owns the Phase 3.5 planning boundary for heap state that will
//! later be attached to the parallel evaluator. It models two constraints from
//! RFC-0007 before the allocator and table internals become concurrent:
//!
//! ```text
//! top-level task -> initial worker -> worker-local bump nursery
//! stolen top-level task -> executing worker -> executing worker-local nursery
//! worker-local hash-cons candidates -> deterministic equality-confirmed merge
//! ```
//!
//! The implementation is deliberately a deterministic planning layer. It does
//! not allocate evaluator objects, move nursery records, publish to the live
//! hash-cons tables, or replace the current single-threaded tree-walk heap.

use std::{collections::BTreeMap, fmt, num::NonZeroUsize};

use thiserror::Error;

use super::{
    parallel::ParallelTopLevelExecutionReport, parallel_failure::ParallelFallibleTopLevelReport,
};

/// Builds the deterministic initial per-worker nursery plan for top-level work.
///
/// Every worker receives a distinct nursery id equal to the worker id, and
/// tasks are assigned to initial worker-local nurseries round-robin so the
/// placement matches the safe top-level scheduler precursor.
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

/// Builds the deterministic allocation-ownership plan for completed tasks.
///
/// The seed nursery is retained for diagnostics, but the allocation nursery is
/// selected from the worker that actually executed the task. This gives stolen
/// tasks an explicit ownership rule before live `EvalHeap` instances become
/// worker-local: once worker `B` steals a task seeded to worker `A`, new
/// allocations for that task must flow through worker `B`'s nursery.
///
/// Completion records are normalized by stable task index so the returned plan
/// does not depend on scheduler completion order.
///
/// # Errors
///
/// Returns [`ParallelNurseryOwnershipError`] if a task completion references an
/// unknown task, references an unknown executing worker, or reports the same
/// task more than once.
pub fn parallel_task_nursery_ownership_plan<I>(
    nursery_plan: &ParallelWorkerNurseryPlan,
    executions: I,
) -> Result<ParallelTaskNurseryOwnershipPlan, ParallelNurseryOwnershipError>
where
    I: IntoIterator<Item = ParallelTaskNurseryExecution>,
{
    let mut executions = executions.into_iter().collect::<Vec<_>>();
    executions.sort_by_key(|execution| execution.task_index);

    for pair in executions.windows(2) {
        let first = pair[0];
        let second = pair[1];
        if first.task_index == second.task_index {
            return Err(ParallelNurseryOwnershipError::DuplicateTaskExecution {
                task_index: first.task_index,
            });
        }
    }

    let mut records = Vec::with_capacity(executions.len());
    for execution in executions {
        let assignment = nursery_plan.assignments.get(execution.task_index).ok_or(
            ParallelNurseryOwnershipError::UnknownTask {
                task_index: execution.task_index,
                task_count: nursery_plan.task_count,
            },
        )?;
        let execution_nursery = nursery_plan
            .nurseries
            .get(execution.executing_worker)
            .ok_or(ParallelNurseryOwnershipError::UnknownWorker {
                worker_id: execution.executing_worker,
                worker_count: nursery_plan.worker_count,
            })?;
        let mode = if assignment.worker_id == execution.executing_worker {
            ParallelNurseryOwnershipMode::Local
        } else {
            ParallelNurseryOwnershipMode::Stolen
        };

        records.push(ParallelTaskNurseryOwnership {
            task_index: execution.task_index,
            initial_worker: assignment.worker_id,
            initial_nursery_id: assignment.nursery_id,
            executing_worker: execution.executing_worker,
            allocation_nursery_id: execution_nursery.nursery_id,
            mode,
        });
    }

    Ok(ParallelTaskNurseryOwnershipPlan { records })
}

/// Builds allocation ownership from a safe top-level scheduler report.
///
/// This is the stricter integration path for [`super::parallel`]: it requires
/// the nursery plan and scheduler report to agree on task and worker counts,
/// verifies that the report's initial worker matches the seed nursery
/// assignment, and then assigns allocations to the worker that actually
/// completed each task.
///
/// # Errors
///
/// Returns [`ParallelNurseryOwnershipError`] if the report does not match the
/// seed nursery plan or if any reported task execution is invalid for that plan.
pub fn parallel_task_nursery_ownership_from_top_level_report<R>(
    nursery_plan: &ParallelWorkerNurseryPlan,
    report: &ParallelTopLevelExecutionReport<R>,
) -> Result<ParallelTaskNurseryOwnershipPlan, ParallelNurseryOwnershipError> {
    if nursery_plan.worker_count != report.worker_count() {
        return Err(ParallelNurseryOwnershipError::WorkerCountMismatch {
            planned_worker_count: nursery_plan.worker_count,
            reported_worker_count: report.worker_count(),
        });
    }
    if nursery_plan.task_count != report.task_count() {
        return Err(ParallelNurseryOwnershipError::TaskCountMismatch {
            planned_task_count: nursery_plan.task_count,
            reported_task_count: report.task_count(),
        });
    }
    if report.results().len() != report.task_count() {
        return Err(ParallelNurseryOwnershipError::IncompleteTaskReport {
            task_count: report.task_count(),
            completed_task_count: report.results().len(),
        });
    }

    let executions = report
        .results()
        .iter()
        .map(|execution| {
            let assignment = nursery_plan.assignments.get(execution.task_index()).ok_or(
                ParallelNurseryOwnershipError::UnknownTask {
                    task_index: execution.task_index(),
                    task_count: nursery_plan.task_count,
                },
            )?;
            if assignment.worker_id != execution.initial_worker() {
                return Err(ParallelNurseryOwnershipError::InitialWorkerMismatch {
                    task_index: execution.task_index(),
                    planned_worker: assignment.worker_id,
                    reported_worker: execution.initial_worker(),
                });
            }
            Ok(ParallelTaskNurseryExecution::new(
                execution.task_index(),
                execution.worker_id(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    parallel_task_nursery_ownership_plan(nursery_plan, executions)
}

/// Builds allocation ownership from a fallible top-level scheduler report.
///
/// The fallible report may be partial when fail-fast cancellation skips queued
/// roots before they start. This bridge therefore assigns ownership only for
/// completed outcomes while validating that the report and nursery seed plan
/// agree on the submitted task and worker counts.
///
/// # Errors
///
/// Returns [`ParallelNurseryOwnershipError`] if the report does not match the
/// seed nursery plan, if completed outcome accounting is inconsistent, or if any
/// reported task outcome is invalid for that plan.
pub fn parallel_task_nursery_ownership_from_fallible_top_level_report<R, E>(
    nursery_plan: &ParallelWorkerNurseryPlan,
    report: &ParallelFallibleTopLevelReport<R, E>,
) -> Result<ParallelTaskNurseryOwnershipPlan, ParallelNurseryOwnershipError> {
    if nursery_plan.worker_count != report.worker_count() {
        return Err(ParallelNurseryOwnershipError::WorkerCountMismatch {
            planned_worker_count: nursery_plan.worker_count,
            reported_worker_count: report.worker_count(),
        });
    }
    if nursery_plan.task_count != report.task_count() {
        return Err(ParallelNurseryOwnershipError::TaskCountMismatch {
            planned_task_count: nursery_plan.task_count,
            reported_task_count: report.task_count(),
        });
    }
    if report.outcomes().len() != report.completed_task_count() {
        return Err(
            ParallelNurseryOwnershipError::CompletedOutcomeCountMismatch {
                completed_task_count: report.completed_task_count(),
                outcome_count: report.outcomes().len(),
            },
        );
    }
    if report.completed_task_count() + report.cancelled_before_start_count() != report.task_count()
    {
        return Err(
            ParallelNurseryOwnershipError::FallibleTaskAccountingMismatch {
                task_count: report.task_count(),
                completed_task_count: report.completed_task_count(),
                cancelled_before_start_count: report.cancelled_before_start_count(),
            },
        );
    }
    if !report.cancelled() && report.cancelled_before_start_count() > 0 {
        return Err(
            ParallelNurseryOwnershipError::SkippedTasksWithoutCancellation {
                cancelled_before_start_count: report.cancelled_before_start_count(),
            },
        );
    }

    let executions = report
        .outcomes()
        .iter()
        .map(|outcome| {
            let assignment = nursery_plan.assignments.get(outcome.task_index()).ok_or(
                ParallelNurseryOwnershipError::UnknownTask {
                    task_index: outcome.task_index(),
                    task_count: nursery_plan.task_count,
                },
            )?;
            if assignment.worker_id != outcome.initial_worker() {
                return Err(ParallelNurseryOwnershipError::InitialWorkerMismatch {
                    task_index: outcome.task_index(),
                    planned_worker: assignment.worker_id,
                    reported_worker: outcome.initial_worker(),
                });
            }
            Ok(ParallelTaskNurseryExecution::new(
                outcome.task_index(),
                outcome.worker_id(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    parallel_task_nursery_ownership_plan(nursery_plan, executions)
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

/// One observed top-level task completion for nursery ownership planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelTaskNurseryExecution {
    task_index: usize,
    executing_worker: usize,
}

impl ParallelTaskNurseryExecution {
    /// Builds a task completion record from the stable task and worker ids.
    pub const fn new(task_index: usize, executing_worker: usize) -> Self {
        Self {
            task_index,
            executing_worker,
        }
    }

    /// Returns the stable top-level task index.
    pub const fn task_index(self) -> usize {
        self.task_index
    }

    /// Returns the worker that executed the task body.
    pub const fn executing_worker(self) -> usize {
        self.executing_worker
    }
}

/// Deterministic allocation ownership for completed top-level tasks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelTaskNurseryOwnershipPlan {
    records: Vec<ParallelTaskNurseryOwnership>,
}

impl ParallelTaskNurseryOwnershipPlan {
    /// Returns ownership records in stable task-index order.
    pub fn records(&self) -> &[ParallelTaskNurseryOwnership] {
        &self.records
    }

    /// Returns the number of completed tasks covered by the plan.
    pub fn completed_task_count(&self) -> usize {
        self.records.len()
    }

    /// Returns the number of tasks that executed on their seed worker.
    pub fn local_task_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.mode == ParallelNurseryOwnershipMode::Local)
            .count()
    }

    /// Returns the number of tasks that executed on a stealing worker.
    pub fn stolen_task_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.mode == ParallelNurseryOwnershipMode::Stolen)
            .count()
    }
}

/// The worker-local nursery selected for one completed task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelTaskNurseryOwnership {
    task_index: usize,
    initial_worker: usize,
    initial_nursery_id: usize,
    executing_worker: usize,
    allocation_nursery_id: usize,
    mode: ParallelNurseryOwnershipMode,
}

impl ParallelTaskNurseryOwnership {
    /// Returns the stable top-level task index.
    pub const fn task_index(self) -> usize {
        self.task_index
    }

    /// Returns the worker that initially owned the task queue entry.
    pub const fn initial_worker(self) -> usize {
        self.initial_worker
    }

    /// Returns the nursery selected by the deterministic seed placement.
    pub const fn initial_nursery_id(self) -> usize {
        self.initial_nursery_id
    }

    /// Returns the worker that executed the task body.
    pub const fn executing_worker(self) -> usize {
        self.executing_worker
    }

    /// Returns the nursery that owns allocations made by the task body.
    pub const fn allocation_nursery_id(self) -> usize {
        self.allocation_nursery_id
    }

    /// Returns whether allocation stayed local or moved with a stolen task.
    pub const fn mode(self) -> ParallelNurseryOwnershipMode {
        self.mode
    }
}

/// How task execution selected its allocation nursery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelNurseryOwnershipMode {
    /// The task executed on its initial worker and kept the seed nursery.
    Local,
    /// The task was stolen and allocations move to the executing worker nursery.
    Stolen,
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

/// A failure while assigning completed tasks to worker-local nurseries.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelNurseryOwnershipError {
    /// The scheduler report used a different worker count than the nursery plan.
    #[error(
        "parallel nursery ownership planned {planned_worker_count} worker(s) but report used {reported_worker_count}"
    )]
    WorkerCountMismatch {
        /// The number of worker-local nurseries in the seed plan.
        planned_worker_count: usize,
        /// The number of workers in the scheduler report.
        reported_worker_count: usize,
    },
    /// The scheduler report used a different task count than the nursery plan.
    #[error(
        "parallel nursery ownership planned {planned_task_count} task(s) but report used {reported_task_count}"
    )]
    TaskCountMismatch {
        /// The number of tasks in the seed nursery plan.
        planned_task_count: usize,
        /// The number of tasks in the scheduler report.
        reported_task_count: usize,
    },
    /// A scheduler report did not contain one result per submitted task.
    #[error(
        "parallel nursery ownership report has {completed_task_count} completed task(s) for {task_count} submitted task(s)"
    )]
    IncompleteTaskReport {
        /// The number of submitted tasks in the scheduler report.
        task_count: usize,
        /// The number of completed task results in the scheduler report.
        completed_task_count: usize,
    },
    /// A fallible report's outcome vector did not match its completed count.
    #[error(
        "parallel nursery ownership fallible report has {outcome_count} outcome(s) for {completed_task_count} completed task(s)"
    )]
    CompletedOutcomeCountMismatch {
        /// The completed task count reported by the fallible scheduler.
        completed_task_count: usize,
        /// The number of stored outcomes in the fallible scheduler report.
        outcome_count: usize,
    },
    /// A fallible report did not account for every submitted root exactly once.
    #[error(
        "parallel nursery ownership fallible report accounted for {completed_task_count} completed and {cancelled_before_start_count} skipped task(s) out of {task_count}"
    )]
    FallibleTaskAccountingMismatch {
        /// The number of submitted tasks in the fallible scheduler report.
        task_count: usize,
        /// The number of completed tasks in the fallible scheduler report.
        completed_task_count: usize,
        /// The number of queued tasks skipped before start.
        cancelled_before_start_count: usize,
    },
    /// A fallible report skipped queued roots without reporting cancellation.
    #[error(
        "parallel nursery ownership fallible report skipped {cancelled_before_start_count} task(s) without cancellation"
    )]
    SkippedTasksWithoutCancellation {
        /// The number of queued tasks skipped before start.
        cancelled_before_start_count: usize,
    },
    /// A completion record referenced a task outside the seed plan.
    #[error(
        "parallel nursery ownership referenced task {task_index} with only {task_count} task(s) planned"
    )]
    UnknownTask {
        /// The referenced stable task index.
        task_index: usize,
        /// The number of tasks in the seed nursery plan.
        task_count: usize,
    },
    /// A completion record referenced a worker outside the seed plan.
    #[error(
        "parallel nursery ownership referenced worker {worker_id} with only {worker_count} worker(s) planned"
    )]
    UnknownWorker {
        /// The referenced executing worker.
        worker_id: usize,
        /// The number of worker-local nurseries in the seed plan.
        worker_count: usize,
    },
    /// A scheduler report disagreed with the seed plan's initial owner.
    #[error(
        "parallel nursery ownership expected task {task_index} to start on worker {planned_worker} but report used worker {reported_worker}"
    )]
    InitialWorkerMismatch {
        /// The task whose seed worker disagreed with the plan.
        task_index: usize,
        /// The worker selected by the nursery seed plan.
        planned_worker: usize,
        /// The worker recorded by the scheduler report.
        reported_worker: usize,
    },
    /// More than one completion record was provided for the same task.
    #[error("parallel nursery ownership received duplicate completion for task {task_index}")]
    DuplicateTaskExecution {
        /// The duplicated stable task index.
        task_index: usize,
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
mod tests;
