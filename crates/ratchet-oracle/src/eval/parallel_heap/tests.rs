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

    let ownership = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
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

    let ownership = parallel_task_nursery_ownership_from_fallible_top_level_report(&plan, &report)
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
