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
mod tests {
    use super::super::{
        parallel::execute_parallel_top_level,
        parallel_failure::{
            ParallelFailurePolicy, ParallelFallibleTopLevelReport, ParallelTaskOutcome,
            execute_parallel_top_level_fallible,
        },
    };
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

    const fn execution(task_index: usize, executing_worker: usize) -> ParallelTaskNurseryExecution {
        ParallelTaskNurseryExecution::new(task_index, executing_worker)
    }

    fn outcome(
        task_index: usize,
        initial_worker: usize,
        worker_id: usize,
    ) -> ParallelTaskOutcome<usize, &'static str> {
        ParallelTaskOutcome::for_test(task_index, initial_worker, worker_id, Ok(task_index))
    }

    fn fallible_report(
        worker_count: usize,
        task_count: usize,
        completed_task_count: usize,
        cancelled_before_start_count: usize,
        cancelled: bool,
        outcomes: Vec<ParallelTaskOutcome<usize, &'static str>>,
    ) -> ParallelFallibleTopLevelReport<usize, &'static str> {
        ParallelFallibleTopLevelReport::for_test(
            worker_count,
            task_count,
            completed_task_count,
            cancelled_before_start_count,
            cancelled,
            outcomes,
        )
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
    fn nursery_ownership_uses_executing_worker_for_stolen_tasks() {
        let plan = parallel_worker_nursery_plan(5, workers(3));
        let ownership = parallel_task_nursery_ownership_plan(
            &plan,
            [
                execution(4, 1),
                execution(0, 0),
                execution(2, 0),
                execution(1, 2),
                execution(3, 0),
            ],
        )
        .expect("ownership plan succeeds");

        assert_eq!(ownership.completed_task_count(), 5);
        assert_eq!(ownership.local_task_count(), 3);
        assert_eq!(ownership.stolen_task_count(), 2);
        assert_eq!(
            ownership
                .records()
                .iter()
                .copied()
                .map(|record| {
                    (
                        record.task_index(),
                        record.initial_worker(),
                        record.initial_nursery_id(),
                        record.executing_worker(),
                        record.allocation_nursery_id(),
                        record.mode(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (0, 0, 0, 0, 0, ParallelNurseryOwnershipMode::Local),
                (1, 1, 1, 2, 2, ParallelNurseryOwnershipMode::Stolen),
                (2, 2, 2, 0, 0, ParallelNurseryOwnershipMode::Stolen),
                (3, 0, 0, 0, 0, ParallelNurseryOwnershipMode::Local),
                (4, 1, 1, 1, 1, ParallelNurseryOwnershipMode::Local)
            ]
        );
    }

    #[test]
    fn nursery_ownership_is_independent_of_completion_order() {
        let plan = parallel_worker_nursery_plan(4, workers(2));
        let first = parallel_task_nursery_ownership_plan(
            &plan,
            [
                execution(3, 0),
                execution(0, 0),
                execution(2, 1),
                execution(1, 1),
            ],
        )
        .expect("first ownership plan succeeds");
        let second = parallel_task_nursery_ownership_plan(
            &plan,
            [
                execution(0, 0),
                execution(1, 1),
                execution(2, 1),
                execution(3, 0),
            ],
        )
        .expect("second ownership plan succeeds");

        assert_eq!(first, second);
    }

    #[test]
    fn nursery_ownership_accepts_empty_completed_task_set() {
        let plan = parallel_worker_nursery_plan(4, workers(2));
        let ownership =
            parallel_task_nursery_ownership_plan(&plan, Vec::<ParallelTaskNurseryExecution>::new())
                .expect("empty ownership plan succeeds");

        assert!(ownership.records().is_empty());
        assert_eq!(ownership.completed_task_count(), 0);
        assert_eq!(ownership.local_task_count(), 0);
        assert_eq!(ownership.stolen_task_count(), 0);
    }

    #[test]
    fn nursery_ownership_rejects_unknown_task() {
        let plan = parallel_worker_nursery_plan(2, workers(2));
        let error = parallel_task_nursery_ownership_plan(&plan, [execution(2, 0)])
            .expect_err("unknown task rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::UnknownTask {
                task_index: 2,
                task_count: 2
            }
        );
    }

    #[test]
    fn nursery_ownership_rejects_unknown_worker() {
        let plan = parallel_worker_nursery_plan(2, workers(2));
        let error = parallel_task_nursery_ownership_plan(&plan, [execution(1, 2)])
            .expect_err("unknown worker rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::UnknownWorker {
                worker_id: 2,
                worker_count: 2
            }
        );
    }

    #[test]
    fn nursery_ownership_rejects_duplicate_task_execution() {
        let plan = parallel_worker_nursery_plan(2, workers(2));
        let error = parallel_task_nursery_ownership_plan(
            &plan,
            [execution(1, 0), execution(0, 0), execution(1, 1)],
        )
        .expect_err("duplicate task rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::DuplicateTaskExecution { task_index: 1 }
        );
    }

    #[test]
    fn nursery_ownership_derives_from_top_level_scheduler_report() {
        let worker_count = workers(3);
        let report = execute_parallel_top_level(0..9, worker_count, |value| value * 2)
            .expect("parallel execution succeeds");
        let plan = parallel_worker_nursery_plan(report.task_count(), worker_count);

        let ownership = parallel_task_nursery_ownership_from_top_level_report(&plan, &report)
            .expect("scheduler report ownership succeeds");

        assert_eq!(ownership.completed_task_count(), report.results().len());
        assert_eq!(
            ownership.local_task_count() + ownership.stolen_task_count(),
            report.results().len()
        );
        assert_eq!(
            ownership
                .records()
                .iter()
                .map(|record| (
                    record.task_index(),
                    record.initial_worker(),
                    record.initial_nursery_id(),
                    record.executing_worker(),
                    record.allocation_nursery_id(),
                ))
                .collect::<Vec<_>>(),
            report
                .results()
                .iter()
                .map(|execution| (
                    execution.task_index(),
                    execution.initial_worker(),
                    execution.initial_worker(),
                    execution.worker_id(),
                    execution.worker_id(),
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn nursery_ownership_from_report_rejects_worker_count_mismatch() {
        let report = execute_parallel_top_level(0..3, workers(3), |value| value)
            .expect("parallel execution succeeds");
        let plan = parallel_worker_nursery_plan(report.task_count(), workers(2));

        let error = parallel_task_nursery_ownership_from_top_level_report(&plan, &report)
            .expect_err("worker count mismatch rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::WorkerCountMismatch {
                planned_worker_count: 2,
                reported_worker_count: 3
            }
        );
    }

    #[test]
    fn nursery_ownership_from_report_rejects_task_count_mismatch() {
        let worker_count = workers(2);
        let report = execute_parallel_top_level(0..3, worker_count, |value| value)
            .expect("parallel execution succeeds");
        let plan = parallel_worker_nursery_plan(2, worker_count);

        let error = parallel_task_nursery_ownership_from_top_level_report(&plan, &report)
            .expect_err("task count mismatch rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::TaskCountMismatch {
                planned_task_count: 2,
                reported_task_count: 3
            }
        );
    }

    #[test]
    fn nursery_ownership_derives_from_complete_fallible_scheduler_report() {
        let worker_count = workers(3);
        let report = execute_parallel_top_level_fallible(
            0..6,
            worker_count,
            ParallelFailurePolicy::CollectAll,
            |value| {
                if value == 4 {
                    Err(value)
                } else {
                    Ok(value * 2)
                }
            },
        )
        .expect("fallible execution succeeds");
        let plan = parallel_worker_nursery_plan(report.task_count(), worker_count);

        let ownership =
            parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
                .expect("fallible scheduler ownership succeeds");

        assert_eq!(
            ownership.completed_task_count(),
            report.completed_task_count()
        );
        assert_eq!(ownership.completed_task_count(), report.outcomes().len());
        assert_eq!(
            ownership
                .records()
                .iter()
                .map(|record| (
                    record.task_index(),
                    record.initial_worker(),
                    record.executing_worker(),
                    record.allocation_nursery_id(),
                ))
                .collect::<Vec<_>>(),
            report
                .outcomes()
                .iter()
                .map(|outcome| (
                    outcome.task_index(),
                    outcome.initial_worker(),
                    outcome.worker_id(),
                    outcome.worker_id(),
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn nursery_ownership_derives_from_cancelled_fallible_scheduler_report() {
        let worker_count = workers(1);
        let report = execute_parallel_top_level_fallible(
            0..5,
            worker_count,
            ParallelFailurePolicy::CancelQueuedAfterFirstError,
            |value| {
                if value == 4 { Err(value) } else { Ok(value) }
            },
        )
        .expect("fallible execution succeeds");
        let plan = parallel_worker_nursery_plan(report.task_count(), worker_count);

        let ownership =
            parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
                .expect("cancelled fallible scheduler ownership succeeds");

        assert!(report.cancelled());
        assert_eq!(report.completed_task_count(), 1);
        assert_eq!(report.cancelled_before_start_count(), 4);
        assert_eq!(ownership.completed_task_count(), 1);
        assert_eq!(
            ownership.records()[0].task_index(),
            report.outcomes()[0].task_index()
        );
        assert_eq!(ownership.records()[0].allocation_nursery_id(), 0);
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_worker_count_mismatch() {
        let report = execute_parallel_top_level_fallible(
            0..3,
            workers(3),
            ParallelFailurePolicy::CollectAll,
            |value| Ok::<_, &'static str>(value),
        )
        .expect("fallible execution succeeds");
        let plan = parallel_worker_nursery_plan(report.task_count(), workers(2));

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("worker count mismatch rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::WorkerCountMismatch {
                planned_worker_count: 2,
                reported_worker_count: 3
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_task_count_mismatch() {
        let worker_count = workers(2);
        let report = execute_parallel_top_level_fallible(
            0..3,
            worker_count,
            ParallelFailurePolicy::CollectAll,
            |value| Ok::<_, &'static str>(value),
        )
        .expect("fallible execution succeeds");
        let plan = parallel_worker_nursery_plan(2, worker_count);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("task count mismatch rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::TaskCountMismatch {
                planned_task_count: 2,
                reported_task_count: 3
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_completed_outcome_count_mismatch() {
        let plan = parallel_worker_nursery_plan(2, workers(1));
        let report = fallible_report(1, 2, 1, 1, true, vec![outcome(0, 0, 0), outcome(1, 0, 0)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("completed outcome count mismatch rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::CompletedOutcomeCountMismatch {
                completed_task_count: 1,
                outcome_count: 2
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_under_accounted_report() {
        let plan = parallel_worker_nursery_plan(2, workers(1));
        let report = fallible_report(1, 2, 1, 0, false, vec![outcome(0, 0, 0)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("under-accounted report rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::FallibleTaskAccountingMismatch {
                task_count: 2,
                completed_task_count: 1,
                cancelled_before_start_count: 0
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_over_accounted_report() {
        let plan = parallel_worker_nursery_plan(2, workers(1));
        let report = fallible_report(1, 2, 2, 1, true, vec![outcome(0, 0, 0), outcome(1, 0, 0)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("over-accounted report rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::FallibleTaskAccountingMismatch {
                task_count: 2,
                completed_task_count: 2,
                cancelled_before_start_count: 1
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_skipped_without_cancellation() {
        let plan = parallel_worker_nursery_plan(2, workers(1));
        let report = fallible_report(1, 2, 1, 1, false, vec![outcome(0, 0, 0)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("skipped without cancellation rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::SkippedTasksWithoutCancellation {
                cancelled_before_start_count: 1
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_initial_worker_mismatch() {
        let plan = parallel_worker_nursery_plan(1, workers(2));
        let report = fallible_report(2, 1, 1, 0, false, vec![outcome(0, 1, 1)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("initial worker mismatch rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::InitialWorkerMismatch {
                task_index: 0,
                planned_worker: 0,
                reported_worker: 1
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_unknown_task() {
        let plan = parallel_worker_nursery_plan(1, workers(1));
        let report = fallible_report(1, 1, 1, 0, false, vec![outcome(1, 0, 0)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("unknown task rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::UnknownTask {
                task_index: 1,
                task_count: 1
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_unknown_worker() {
        let plan = parallel_worker_nursery_plan(1, workers(1));
        let report = fallible_report(1, 1, 1, 0, false, vec![outcome(0, 0, 1)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("unknown worker rejects");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::UnknownWorker {
                worker_id: 1,
                worker_count: 1
            }
        );
    }

    #[test]
    fn nursery_ownership_from_fallible_report_rejects_duplicate_task_outcomes() {
        let plan = parallel_worker_nursery_plan(2, workers(1));
        let report = fallible_report(1, 2, 2, 0, false, vec![outcome(0, 0, 0), outcome(0, 0, 0)]);

        let error = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
            .expect_err("duplicate task outcomes reject");

        assert_eq!(
            error,
            ParallelNurseryOwnershipError::DuplicateTaskExecution { task_index: 0 }
        );
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
