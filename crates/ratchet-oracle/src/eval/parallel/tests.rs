//! Unit tests for the parallel top-level executor and ready-work queues.

mod part_1;

use std::{
    sync::{
        Arc,
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use super::super::thunk_cas::{ParallelThunkTerminalState, ParallelThunkWorkerId};
use super::super::thunk_wait::{ParallelThunkWait, ParallelThunkWaitCell};
use super::*;

fn workers(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).expect("test worker count is nonzero")
}

fn worker(raw: u64) -> ParallelThunkWorkerId {
    ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
}

fn wait_until_registered(cell: &ParallelThunkWaitCell, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cell
            .stats()
            .expect("stats are readable")
            .wait_registrations()
            >= expected
        {
            return;
        }
        thread::yield_now();
    }
    panic!("timed out waiting for {expected} waiter registration(s)");
}

#[test]
fn seed_plan_distributes_tasks_round_robin() {
    let plan = parallel_top_level_seed_plan(8, workers(3));

    assert_eq!(plan.worker_count(), 3);
    assert_eq!(plan.task_count(), 8);
    assert_eq!(
        plan.placements()
            .iter()
            .copied()
            .map(|placement| (placement.task_index(), placement.initial_worker()))
            .collect::<Vec<_>>(),
        vec![
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 0),
            (4, 1),
            (5, 2),
            (6, 0),
            (7, 1)
        ]
    );
    assert_eq!(
        plan.to_string(),
        "8 top-level task(s) seeded across 3 worker(s)"
    );
}

#[test]
fn top_level_executor_returns_results_in_stable_task_order() {
    let report = execute_parallel_top_level([3, 1, 4, 1, 5, 9], workers(3), |value| value * value)
        .expect("parallel execution succeeds");

    assert_eq!(report.worker_count(), 3);
    assert_eq!(report.task_count(), 6);
    assert_eq!(
        report.into_results_in_task_order(),
        vec![9, 1, 16, 1, 25, 81]
    );
}

#[test]
fn top_level_executor_reports_every_task_once() {
    let report = execute_parallel_top_level(0..64, workers(4), |value| value + 10)
        .expect("parallel execution succeeds");
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

    assert_eq!(completed, 64);
    assert_eq!(local_and_stolen, 64);
    assert_eq!(report.results().len(), 64);
    assert!(
        report
            .results()
            .iter()
            .enumerate()
            .all(|(expected_index, execution)| {
                execution.task_index() == expected_index
                    && execution.initial_worker() == expected_index % 4
                    && execution.worker_id() < 4
                    && *execution.result() == expected_index + 10
            })
    );
}

#[test]
fn top_level_executor_handles_empty_task_sets() {
    let report = execute_parallel_top_level(std::iter::empty::<usize>(), workers(2), |value| value)
        .expect("empty execution succeeds");

    assert_eq!(report.worker_count(), 2);
    assert_eq!(report.task_count(), 0);
    assert!(report.results().is_empty());
    assert_eq!(report.worker_reports().len(), 2);
    assert!(report.worker_reports().iter().all(|worker| {
        worker.local_pops() == 0 && worker.steals() == 0 && worker.tasks_completed() == 0
    }));
}

#[test]
fn chase_lev_executor_returns_results_in_stable_task_order() {
    let report =
        execute_parallel_top_level_chase_lev([3, 1, 4, 1, 5, 9], workers(3), |value| value * value)
            .expect("Chase-Lev execution succeeds");

    assert_eq!(report.worker_count(), 3);
    assert_eq!(report.task_count(), 6);
    assert_eq!(
        report.into_results_in_task_order(),
        vec![9, 1, 16, 1, 25, 81]
    );
}

#[test]
fn chase_lev_executor_reports_every_task_once() {
    let report = execute_parallel_top_level_chase_lev(0..96, workers(4), |value| value + 10)
        .expect("Chase-Lev execution succeeds");
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

    assert_eq!(completed, 96);
    assert_eq!(local_and_stolen, 96);
    assert_eq!(report.results().len(), 96);
    assert!(
        report
            .results()
            .iter()
            .enumerate()
            .all(|(expected_index, execution)| {
                execution.task_index() == expected_index
                    && execution.initial_worker() == expected_index % 4
                    && execution.worker_id() < 4
                    && *execution.result() == expected_index + 10
            })
    );
}

#[test]
fn chase_lev_executor_handles_empty_task_sets() {
    let report =
        execute_parallel_top_level_chase_lev(std::iter::empty::<usize>(), workers(2), |value| {
            value
        })
        .expect("empty Chase-Lev execution succeeds");

    assert_eq!(report.worker_count(), 2);
    assert_eq!(report.task_count(), 0);
    assert!(report.results().is_empty());
    assert_eq!(report.worker_reports().len(), 2);
    assert!(report.worker_reports().iter().all(|worker| {
        worker.local_pops() == 0 && worker.steals() == 0 && worker.tasks_completed() == 0
    }));
}

#[test]
fn chase_lev_ready_work_queues_preserve_worker_and_task_counts() {
    let queues = parallel_chase_lev_ready_work_queues([10, 20, 30, 40, 50], workers(3));

    assert_eq!(queues.worker_count(), 3);
    assert_eq!(queues.task_count(), 5);

    let worker_queues = queues.into_worker_queues();
    assert_eq!(worker_queues.len(), 3);
    assert!(worker_queues.iter().enumerate().all(|(worker_id, queue)| {
        queue.worker_id() == worker_id && queue.worker_count() == 3 && queue.task_count() == 5
    }));
}

#[test]
fn ready_work_queues_run_local_before_stealing() {
    let queues = parallel_ready_work_queues([10, 20, 30, 40], workers(2));

    let first = queues
        .run_next(0, |value| value + 1)
        .expect("first ready work runs");
    assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
    let ParallelReadyWorkStep::RanLocal(execution) = first else {
        panic!("first task should be local");
    };
    assert_eq!(execution.task_index(), 2);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 31);

    let second = queues
        .run_next(0, |value| value + 1)
        .expect("second ready work runs");
    assert_eq!(second.ready_work(), ParallelThunkReadyWork::RanLocal);
    let ParallelReadyWorkStep::RanLocal(execution) = second else {
        panic!("second task should be local");
    };
    assert_eq!(execution.task_index(), 0);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 11);

    let third = queues
        .run_next(0, |value| value + 1)
        .expect("third ready work runs");
    assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkStep::StolePeer(execution) = third else {
        panic!("third task should be stolen");
    };
    assert_eq!(execution.task_index(), 1);
    assert_eq!(execution.initial_worker(), 1);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 21);

    let fourth = queues
        .run_next(0, |value| value + 1)
        .expect("fourth ready work runs");
    assert_eq!(fourth.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkStep::StolePeer(execution) = fourth else {
        panic!("fourth task should be stolen");
    };
    assert_eq!(execution.task_index(), 3);
    assert_eq!(execution.initial_worker(), 1);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 41);

    let fifth = queues
        .run_next(0, |value| value + 1)
        .expect("idle ready work succeeds");
    assert_eq!(fifth.ready_work(), ParallelThunkReadyWork::Idle);
    assert!(fifth.execution().is_none());
}

#[test]
fn chase_lev_ready_work_queue_runs_local_before_stealing() {
    let queues = parallel_chase_lev_ready_work_queues([10, 20, 30, 40], workers(2));
    let worker_queues = queues.into_worker_queues();
    let worker = &worker_queues[0];

    let first = worker.run_next(|value| value + 1);
    assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
    let ParallelReadyWorkStep::RanLocal(execution) = first else {
        panic!("first task should be local");
    };
    assert_eq!(execution.task_index(), 2);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 31);

    let second = worker.run_next(|value| value + 1);
    assert_eq!(second.ready_work(), ParallelThunkReadyWork::RanLocal);
    let ParallelReadyWorkStep::RanLocal(execution) = second else {
        panic!("second task should be local");
    };
    assert_eq!(execution.task_index(), 0);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 11);

    let third = worker.run_next(|value| value + 1);
    assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkStep::StolePeer(execution) = third else {
        panic!("third task should be stolen");
    };
    assert_eq!(execution.task_index(), 1);
    assert_eq!(execution.initial_worker(), 1);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 21);

    let fourth = worker.run_next(|value| value + 1);
    assert_eq!(fourth.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkStep::StolePeer(execution) = fourth else {
        panic!("fourth task should be stolen");
    };
    assert_eq!(execution.task_index(), 3);
    assert_eq!(execution.initial_worker(), 1);
    assert_eq!(execution.worker_id(), 0);
    assert_eq!(*execution.result(), 41);

    let fifth = worker.run_next(|value| value + 1);
    assert_eq!(fifth.ready_work(), ParallelThunkReadyWork::Idle);
    assert!(fifth.execution().is_none());
}

#[test]
fn ready_work_park_preflight_snapshot_reports_seeded_depths() {
    let queues = parallel_ready_work_queues([10, 20, 30, 40, 50], workers(3));

    let snapshot = queues
        .park_preflight_snapshot(1)
        .expect("preflight snapshot succeeds");

    assert_eq!(snapshot.observing_worker(), 1);
    assert_eq!(snapshot.worker_count(), 3);
    assert_eq!(snapshot.task_count(), 5);
    assert_eq!(snapshot.ready_task_count(), 5);
    assert!(!snapshot.is_idle());
    assert_eq!(snapshot.queue_lengths(), &[2, 2, 1]);
    assert_eq!(snapshot.queue_length(0), Some(2));
    assert_eq!(snapshot.queue_length(1), Some(2));
    assert_eq!(snapshot.queue_length(2), Some(1));
    assert_eq!(snapshot.queue_length(3), None);
}

#[test]
fn chase_lev_ready_work_park_preflight_snapshot_reports_seeded_depths() {
    let queues = parallel_chase_lev_ready_work_queues([10, 20, 30, 40, 50], workers(3));
    let worker_queues = queues.into_worker_queues();
    let snapshot = worker_queues[1].park_preflight_snapshot();

    assert_eq!(snapshot.observing_worker(), 1);
    assert_eq!(snapshot.worker_count(), 3);
    assert_eq!(snapshot.task_count(), 5);
    assert_eq!(snapshot.ready_task_count(), 5);
    assert!(!snapshot.is_idle());
    assert_eq!(snapshot.queue_lengths(), &[2, 2, 1]);
    assert_eq!(snapshot.queue_length(0), Some(2));
    assert_eq!(snapshot.queue_length(1), Some(2));
    assert_eq!(snapshot.queue_length(2), Some(1));
    assert_eq!(snapshot.queue_length(3), None);
}

#[test]
fn ready_work_park_preflight_snapshot_reports_idle_after_drain() {
    let queues = parallel_ready_work_queues([10, 20, 30], workers(2));
    let mut ran = Vec::new();

    while queues
        .run_next(0, |value| ran.push(value))
        .expect("ready work run succeeds")
        .ready_work()
        != ParallelThunkReadyWork::Idle
    {}

    let snapshot = queues
        .park_preflight_snapshot(0)
        .expect("preflight snapshot succeeds");

    assert_eq!(ran, vec![30, 10, 20]);
    assert_eq!(snapshot.ready_task_count(), 0);
    assert_eq!(snapshot.queue_lengths(), &[0, 0]);
    assert!(snapshot.is_idle());
}

#[test]
fn chase_lev_ready_work_park_preflight_snapshot_reports_idle_after_drain() {
    let queues = parallel_chase_lev_ready_work_queues([10, 20, 30], workers(2));
    let worker_queues = queues.into_worker_queues();
    let worker = &worker_queues[0];
    let mut ran = Vec::new();

    while worker.run_next(|value| ran.push(value)).ready_work() != ParallelThunkReadyWork::Idle {}

    let snapshot = worker.park_preflight_snapshot();

    assert_eq!(ran, vec![30, 10, 20]);
    assert_eq!(snapshot.ready_task_count(), 0);
    assert_eq!(snapshot.queue_lengths(), &[0, 0]);
    assert!(snapshot.is_idle());
}

#[test]
fn ready_work_park_readiness_accepts_idle_snapshot() {
    let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

    let snapshot = queues
        .park_preflight_snapshot(1)
        .expect("preflight snapshot succeeds");
    let readiness = snapshot
        .validate_idle_for_worker(1)
        .expect("idle snapshot validates");

    assert_eq!(readiness.preflight(), &snapshot);
    assert_eq!(readiness.observing_worker(), 1);
    assert_eq!(readiness.worker_count(), 2);
    assert_eq!(readiness.task_count(), 0);
    assert_eq!(readiness.ready_task_count(), 0);
    assert_eq!(readiness.queue_lengths(), &[0, 0]);
}

#[test]
fn chase_lev_ready_work_park_readiness_accepts_idle_snapshot() {
    let queues = parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2));
    let worker_queues = queues.into_worker_queues();

    let snapshot = worker_queues[1].park_preflight_snapshot();
    let readiness = snapshot
        .validate_idle_for_worker(1)
        .expect("idle snapshot validates");

    assert_eq!(readiness.preflight(), &snapshot);
    assert_eq!(readiness.observing_worker(), 1);
    assert_eq!(readiness.worker_count(), 2);
    assert_eq!(readiness.task_count(), 0);
    assert_eq!(readiness.ready_task_count(), 0);
    assert_eq!(readiness.queue_lengths(), &[0, 0]);
}

#[test]
fn ready_work_park_readiness_rejects_non_idle_snapshot() {
    let queues = parallel_ready_work_queues([10], workers(2));

    let snapshot = queues
        .park_preflight_snapshot(1)
        .expect("preflight snapshot succeeds");
    let error = snapshot
        .validate_idle_for_worker(1)
        .expect_err("non-idle snapshot is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
            ready_task_count: 1
        }
    );
}

#[test]
fn chase_lev_ready_work_park_readiness_rejects_non_idle_snapshot() {
    let queues = parallel_chase_lev_ready_work_queues([10], workers(2));
    let worker_queues = queues.into_worker_queues();

    let snapshot = worker_queues[1].park_preflight_snapshot();
    let error = snapshot
        .validate_idle_for_worker(1)
        .expect_err("non-idle snapshot is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
            ready_task_count: 1
        }
    );
}

#[test]
fn ready_work_park_readiness_rejects_observing_worker_mismatch() {
    let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

    let snapshot = queues
        .park_preflight_snapshot(1)
        .expect("preflight snapshot succeeds");
    let error = snapshot
        .validate_idle_for_worker(0)
        .expect_err("worker mismatch is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
            expected_worker: 0,
            observed_worker: 1
        }
    );
}

#[test]
fn chase_lev_ready_work_park_readiness_rejects_observing_worker_mismatch() {
    let queues = parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2));
    let worker_queues = queues.into_worker_queues();

    let snapshot = worker_queues[1].park_preflight_snapshot();
    let error = snapshot
        .validate_idle_for_worker(0)
        .expect_err("worker mismatch is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
            expected_worker: 0,
            observed_worker: 1
        }
    );
}

#[test]
fn ready_work_park_preflight_snapshot_feeds_wait_or_steal_idle_path() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };
    let mut owner_guard = Some(owner_guard);
    let queues = parallel_ready_work_queues([10, 20], workers(2));
    let mut ran = Vec::new();
    let mut preflight = None;

    let outcome = cell
        .claim_or_run_ready_then_wait(worker(2), || {
            let step = queues
                .run_next(1, |value| ran.push(value))
                .expect("ready queue run succeeds");
            if step.ready_work() == ParallelThunkReadyWork::Idle {
                preflight = Some(
                    queues
                        .park_preflight_snapshot(1)
                        .expect("preflight snapshot succeeds"),
                );
                owner_guard
                    .take()
                    .expect("owner guard remains available")
                    .publish_forced()
                    .expect("owner publishes after idle preflight");
            }
            step.ready_work()
        })
        .expect("wait-or-steal hook completes");

    let (result, report) = outcome.into_parts();
    let snapshot = preflight.expect("idle preflight snapshot is captured");
    assert!(matches!(
        result,
        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
    ));
    assert_eq!(ran, vec![20, 10]);
    assert_eq!(snapshot.observing_worker(), 1);
    assert_eq!(snapshot.ready_task_count(), 0);
    assert!(snapshot.is_idle());
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
}
