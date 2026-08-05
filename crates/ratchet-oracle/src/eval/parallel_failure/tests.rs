use super::*;

fn workers(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).expect("test worker count is nonzero")
}

#[test]
fn collect_all_reports_every_root_and_selects_canonical_error() {
    let report = execute_parallel_top_level_fallible(
        0..6,
        workers(3),
        ParallelFailurePolicy::CollectAll,
        |value| {
            if value == 4 || value == 1 {
                Err(format!("root {value} failed"))
            } else {
                Ok(value * 10)
            }
        },
    )
    .expect("fallible execution succeeds");

    assert_eq!(report.worker_count(), 3);
    assert_eq!(report.task_count(), 6);
    assert_eq!(report.completed_task_count(), 6);
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert_eq!(
        report
            .outcomes()
            .iter()
            .map(ParallelTaskOutcome::task_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5]
    );
    assert_eq!(
        report
            .outcomes()
            .iter()
            .filter(|outcome| outcome.is_err())
            .map(ParallelTaskOutcome::task_index)
            .collect::<Vec<_>>(),
        vec![1, 4]
    );
    assert_eq!(
        report
            .canonical_error()
            .expect("canonical error exists")
            .task_index(),
        1
    );
}

#[test]
fn successful_outcomes_are_returned_in_stable_task_order() {
    let report = execute_parallel_top_level_fallible(
        [3, 1, 4, 1, 5, 9],
        workers(3),
        ParallelFailurePolicy::CollectAll,
        |value| Ok::<_, &'static str>(value * value),
    )
    .expect("fallible execution succeeds");

    assert_eq!(report.canonical_error(), None);
    assert_eq!(
        report
            .outcomes()
            .iter()
            .map(|outcome| *outcome.outcome().as_ref().expect("root succeeded"))
            .collect::<Vec<_>>(),
        vec![9, 1, 16, 1, 25, 81]
    );
    assert!(
        report
            .outcomes()
            .iter()
            .enumerate()
            .all(
                |(expected_index, outcome)| outcome.task_index() == expected_index
                    && outcome.initial_worker() == expected_index % 3
                    && outcome.worker_id() < 3
            )
    );
}

#[test]
fn chase_lev_collect_all_reports_every_root_and_selects_canonical_error() {
    let report = execute_parallel_top_level_fallible_chase_lev(
        0..6,
        workers(3),
        ParallelFailurePolicy::CollectAll,
        |value| {
            if value == 4 || value == 1 {
                Err(format!("root {value} failed"))
            } else {
                Ok(value * 10)
            }
        },
    )
    .expect("Chase-Lev fallible execution succeeds");

    assert_eq!(report.worker_count(), 3);
    assert_eq!(report.task_count(), 6);
    assert_eq!(report.completed_task_count(), 6);
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert_eq!(
        report
            .outcomes()
            .iter()
            .map(ParallelTaskOutcome::task_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5]
    );
    assert_eq!(
        report
            .outcomes()
            .iter()
            .filter(|outcome| outcome.is_err())
            .map(ParallelTaskOutcome::task_index)
            .collect::<Vec<_>>(),
        vec![1, 4]
    );
    assert_eq!(
        report
            .canonical_error()
            .expect("canonical error exists")
            .task_index(),
        1
    );
}

#[test]
fn chase_lev_successful_outcomes_are_returned_in_stable_task_order() {
    let report = execute_parallel_top_level_fallible_chase_lev(
        [3, 1, 4, 1, 5, 9],
        workers(3),
        ParallelFailurePolicy::CollectAll,
        |value| Ok::<_, &'static str>(value * value),
    )
    .expect("Chase-Lev fallible execution succeeds");

    assert_eq!(report.canonical_error(), None);
    assert_eq!(
        report
            .outcomes()
            .iter()
            .map(|outcome| *outcome.outcome().as_ref().expect("root succeeded"))
            .collect::<Vec<_>>(),
        vec![9, 1, 16, 1, 25, 81]
    );
    assert!(
        report
            .outcomes()
            .iter()
            .enumerate()
            .all(
                |(expected_index, outcome)| outcome.task_index() == expected_index
                    && outcome.initial_worker() == expected_index % 3
                    && outcome.worker_id() < 3
            )
    );
}

#[test]
fn worker_aware_executor_reports_task_context() {
    let report = execute_parallel_top_level_fallible_with_worker(
        0..9,
        workers(3),
        ParallelFailurePolicy::CollectAll,
        |context, value| {
            Ok::<_, &'static str>((
                value,
                context.task_index(),
                context.initial_worker(),
                context.worker_id(),
                context.worker_count(),
            ))
        },
    )
    .expect("worker-aware fallible execution succeeds");

    assert_eq!(report.worker_count(), 3);
    assert!(
        report
            .outcomes()
            .iter()
            .enumerate()
            .all(|(expected_index, outcome)| {
                let (value, task_index, initial_worker, context_worker, worker_count) =
                    outcome.outcome().as_ref().expect("root succeeded");
                *value == expected_index
                    && *task_index == expected_index
                    && *initial_worker == expected_index % 3
                    && *context_worker == outcome.worker_id()
                    && outcome.worker_id() < 3
                    && *worker_count == 3
            })
    );
}

#[test]
fn chase_lev_worker_aware_executor_reports_task_context() {
    let report = execute_parallel_top_level_fallible_chase_lev_with_worker(
        0..9,
        workers(3),
        ParallelFailurePolicy::CollectAll,
        |context, value| {
            Ok::<_, &'static str>((
                value,
                context.task_index(),
                context.initial_worker(),
                context.worker_id(),
                context.worker_count(),
            ))
        },
    )
    .expect("worker-aware Chase-Lev fallible execution succeeds");

    assert_eq!(report.worker_count(), 3);
    assert!(
        report
            .outcomes()
            .iter()
            .enumerate()
            .all(|(expected_index, outcome)| {
                let (value, task_index, initial_worker, context_worker, worker_count) =
                    outcome.outcome().as_ref().expect("root succeeded");
                *value == expected_index
                    && *task_index == expected_index
                    && *initial_worker == expected_index % 3
                    && *context_worker == outcome.worker_id()
                    && outcome.worker_id() < 3
                    && *worker_count == 3
            })
    );
}

#[test]
fn fail_fast_cancellation_stops_only_before_new_task_boundaries() {
    let report = execute_parallel_top_level_fallible(
        0..5,
        workers(1),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        |value| {
            if value == 4 {
                Err("requested root failed")
            } else {
                Ok(value)
            }
        },
    )
    .expect("fallible execution succeeds");

    assert!(report.cancelled());
    assert_eq!(report.completed_task_count(), 1);
    assert_eq!(report.cancelled_before_start_count(), 4);
    assert_eq!(
        report
            .canonical_error()
            .expect("canonical observed error exists")
            .task_index(),
        4
    );
    assert_eq!(
        report
            .worker_reports()
            .iter()
            .map(|worker| worker.task_boundary_cancellations())
            .sum::<usize>(),
        1
    );
}

#[test]
fn chase_lev_fail_fast_cancellation_stops_only_before_new_task_boundaries() {
    let report = execute_parallel_top_level_fallible_chase_lev(
        0..5,
        workers(1),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        |value| {
            if value == 4 {
                Err("requested root failed")
            } else {
                Ok(value)
            }
        },
    )
    .expect("Chase-Lev fallible execution succeeds");

    assert!(report.cancelled());
    assert_eq!(report.completed_task_count(), 1);
    assert_eq!(report.cancelled_before_start_count(), 4);
    assert_eq!(
        report
            .canonical_error()
            .expect("canonical observed error exists")
            .task_index(),
        4
    );
    assert_eq!(
        report
            .worker_reports()
            .iter()
            .map(|worker| worker.task_boundary_cancellations())
            .sum::<usize>(),
        1
    );
}

#[test]
fn fail_fast_canonical_error_is_over_observed_failures() {
    use std::sync::{Arc, Barrier};

    let concurrent_failures = Arc::new(Barrier::new(2));
    let report = execute_parallel_top_level_fallible(
        0..5,
        workers(2),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        {
            let concurrent_failures = Arc::clone(&concurrent_failures);
            move |value| {
                if value == 3 || value == 4 {
                    concurrent_failures.wait();
                    Err(value)
                } else {
                    Ok(value)
                }
            }
        },
    )
    .expect("fallible execution succeeds");

    let observed_errors = report
        .outcomes()
        .iter()
        .filter(|outcome| outcome.is_err())
        .map(ParallelTaskOutcome::task_index)
        .collect::<Vec<_>>();

    assert!(report.cancelled());
    assert!(observed_errors.contains(&3));
    assert!(observed_errors.contains(&4));
    assert_eq!(
        report
            .canonical_error()
            .expect("canonical observed error exists")
            .task_index(),
        3
    );
    assert_eq!(
        report.completed_task_count() + report.cancelled_before_start_count(),
        report.task_count()
    );
    assert!(
        report.cancelled_before_start_count() > 0,
        "queued roots should remain after the observed failures request cancellation"
    );
}

#[test]
fn collect_all_does_not_cancel_after_errors() {
    let report = execute_parallel_top_level_fallible(
        0..4,
        workers(1),
        ParallelFailurePolicy::CollectAll,
        |value| {
            if value == 3 {
                Err("root failed")
            } else {
                Ok(value)
            }
        },
    )
    .expect("fallible execution succeeds");

    assert!(!report.cancelled());
    assert_eq!(report.completed_task_count(), 4);
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert_eq!(report.worker_reports()[0].task_boundary_cancellations(), 0);
}

#[test]
fn worker_reports_account_for_completed_tasks_and_errors() {
    let report = execute_parallel_top_level_fallible(
        0..16,
        workers(4),
        ParallelFailurePolicy::CollectAll,
        |value| {
            if value % 5 == 0 {
                Err(value)
            } else {
                Ok(value)
            }
        },
    )
    .expect("fallible execution succeeds");

    let completed = report
        .worker_reports()
        .iter()
        .map(|worker| worker.tasks_completed())
        .sum::<usize>();
    let local_and_stolen = report
        .worker_reports()
        .iter()
        .map(|worker| worker.local_pops() + worker.steals())
        .sum::<usize>();
    let task_errors = report
        .worker_reports()
        .iter()
        .map(|worker| worker.task_errors())
        .sum::<usize>();

    assert_eq!(completed, 16);
    assert_eq!(local_and_stolen, 16);
    assert_eq!(task_errors, 4);
    assert_eq!(report.outcomes().len(), 16);
}

#[test]
fn chase_lev_worker_reports_account_for_completed_tasks_and_errors() {
    let report = execute_parallel_top_level_fallible_chase_lev(
        0..16,
        workers(4),
        ParallelFailurePolicy::CollectAll,
        |value| {
            if value % 5 == 0 {
                Err(value)
            } else {
                Ok(value)
            }
        },
    )
    .expect("Chase-Lev fallible execution succeeds");

    let completed = report
        .worker_reports()
        .iter()
        .map(|worker| worker.tasks_completed())
        .sum::<usize>();
    let local_and_stolen = report
        .worker_reports()
        .iter()
        .map(|worker| worker.local_pops() + worker.steals())
        .sum::<usize>();
    let task_errors = report
        .worker_reports()
        .iter()
        .map(|worker| worker.task_errors())
        .sum::<usize>();

    assert_eq!(completed, 16);
    assert_eq!(local_and_stolen, 16);
    assert_eq!(task_errors, 4);
    assert_eq!(report.outcomes().len(), 16);
}

#[test]
fn fallible_executor_handles_empty_task_sets() {
    let report = execute_parallel_top_level_fallible(
        std::iter::empty::<usize>(),
        workers(2),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        Ok::<_, &'static str>,
    )
    .expect("empty execution succeeds");

    assert_eq!(report.worker_count(), 2);
    assert_eq!(report.task_count(), 0);
    assert_eq!(report.completed_task_count(), 0);
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert!(report.outcomes().is_empty());
    assert_eq!(report.worker_reports().len(), 2);
}

#[test]
fn chase_lev_fallible_executor_handles_empty_task_sets() {
    let report = execute_parallel_top_level_fallible_chase_lev(
        std::iter::empty::<usize>(),
        workers(2),
        ParallelFailurePolicy::CancelQueuedAfterFirstError,
        Ok::<_, &'static str>,
    )
    .expect("empty Chase-Lev fallible execution succeeds");

    assert_eq!(report.worker_count(), 2);
    assert_eq!(report.task_count(), 0);
    assert_eq!(report.completed_task_count(), 0);
    assert_eq!(report.cancelled_before_start_count(), 0);
    assert!(!report.cancelled());
    assert!(report.outcomes().is_empty());
    assert_eq!(report.worker_reports().len(), 2);
}

#[test]
fn fallible_executor_reports_worker_panic() {
    let error = execute_parallel_top_level_fallible(
        0..4,
        workers(2),
        ParallelFailurePolicy::CollectAll,
        |value| {
            assert_ne!(value, 2, "task panic is reported as worker failure");
            Ok::<_, &'static str>(value)
        },
    )
    .expect_err("panicking task fails execution");

    assert!(matches!(
        error,
        ParallelFallibleTopLevelError::WorkerPanicked { worker_id } if worker_id < 2
    ));
}

#[test]
fn chase_lev_fallible_executor_reports_worker_panic() {
    let error = execute_parallel_top_level_fallible_chase_lev(
        0..4,
        workers(2),
        ParallelFailurePolicy::CollectAll,
        |value| {
            assert_ne!(value, 2, "task panic is reported as worker failure");
            Ok::<_, &'static str>(value)
        },
    )
    .expect_err("panicking task fails Chase-Lev fallible execution");

    assert!(matches!(
        error,
        ParallelFallibleTopLevelError::WorkerPanicked { worker_id } if worker_id < 2
    ));
}

#[test]
fn chase_lev_fallible_executor_drains_join_handles_after_multiple_worker_panics() {
    let outcome = std::panic::catch_unwind(|| {
        execute_parallel_top_level_fallible_chase_lev(
            0..8,
            workers(4),
            ParallelFailurePolicy::CollectAll,
            |value| -> Result<usize, &'static str> {
                panic!("task {value} panics");
            },
        )
    });

    assert!(
        outcome.is_ok(),
        "Chase-Lev fallible executor returns an error instead of unwinding"
    );
    let error = outcome
        .expect("executor call did not unwind")
        .expect_err("panicking tasks fail Chase-Lev fallible execution");
    assert!(matches!(
        error,
        ParallelFallibleTopLevelError::WorkerPanicked { worker_id } if worker_id < 4
    ));
}

#[test]
fn failure_policy_display_is_stable() {
    assert_eq!(
        ParallelFailurePolicy::CollectAll.to_string(),
        "collect all root-local outcomes"
    );
    assert_eq!(
        ParallelFailurePolicy::CancelQueuedAfterFirstError.to_string(),
        "cancel queued roots after the first observed error"
    );
}
