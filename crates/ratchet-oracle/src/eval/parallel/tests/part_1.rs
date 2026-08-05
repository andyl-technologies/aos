//! Parallel executor and ready-work tests, continued.

use super::*;

#[test]
fn chase_lev_ready_work_poll_feeds_wait_or_steal_hook_with_preflight() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };
    let mut owner_guard = Some(owner_guard);
    let queues = parallel_chase_lev_ready_work_queues([10, 20], workers(2));
    let worker_queues = queues.into_worker_queues();
    let ready_worker = &worker_queues[1];
    let mut ran = Vec::new();
    let mut preflight = None;

    let outcome = cell
        .claim_or_run_ready_then_wait(worker(2), || {
            let poll = ready_worker.run_next_or_park_preflight(|value| ran.push(value));
            if let Some(snapshot) = poll.park_preflight() {
                preflight = Some(snapshot.clone());
                owner_guard
                    .take()
                    .expect("owner guard remains available")
                    .publish_forced()
                    .expect("owner publishes after idle preflight");
            }
            poll.ready_work()
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

#[test]
fn ready_work_poll_runs_one_task_or_returns_idle_preflight() {
    let queues = parallel_ready_work_queues([10, 20, 30], workers(2));

    let first = queues
        .run_next_or_park_preflight(1, |value| value + 1)
        .expect("first ready work runs");
    assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
    assert!(first.park_preflight().is_none());
    let ParallelReadyWorkPoll::RanLocal(execution) = first else {
        panic!("first poll should run local work");
    };
    assert_eq!(execution.task_index(), 1);
    assert_eq!(execution.initial_worker(), 1);
    assert_eq!(execution.worker_id(), 1);
    assert_eq!(*execution.result(), 21);

    let second = queues
        .run_next_or_park_preflight(1, |value| value + 1)
        .expect("second ready work runs");
    assert_eq!(second.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkPoll::StolePeer(execution) = second else {
        panic!("second poll should steal peer work");
    };
    assert_eq!(execution.task_index(), 0);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 1);
    assert_eq!(*execution.result(), 11);

    let third = queues
        .run_next_or_park_preflight(1, |value| value + 1)
        .expect("third ready work runs");
    assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkPoll::StolePeer(execution) = third else {
        panic!("third poll should steal peer work");
    };
    assert_eq!(execution.task_index(), 2);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 1);
    assert_eq!(*execution.result(), 31);

    let fourth = queues
        .run_next_or_park_preflight(1, |value| value + 1)
        .expect("idle preflight succeeds");
    assert_eq!(fourth.ready_work(), ParallelThunkReadyWork::Idle);
    assert!(fourth.execution().is_none());
    let ParallelReadyWorkPoll::Idle(preflight) = fourth else {
        panic!("fourth poll should report idle preflight");
    };
    assert_eq!(preflight.observing_worker(), 1);
    assert_eq!(preflight.ready_task_count(), 0);
    assert_eq!(preflight.queue_lengths(), &[0, 0]);
    assert!(preflight.is_idle());
}

#[test]
fn chase_lev_ready_work_poll_runs_one_task_or_returns_idle_preflight() {
    let queues = parallel_chase_lev_ready_work_queues([10, 20, 30], workers(2));
    let worker_queues = queues.into_worker_queues();
    let worker = &worker_queues[1];

    let first = worker.run_next_or_park_preflight(|value| value + 1);
    assert_eq!(first.ready_work(), ParallelThunkReadyWork::RanLocal);
    assert!(first.park_preflight().is_none());
    let ParallelReadyWorkPoll::RanLocal(execution) = first else {
        panic!("first poll should run local work");
    };
    assert_eq!(execution.task_index(), 1);
    assert_eq!(execution.initial_worker(), 1);
    assert_eq!(execution.worker_id(), 1);
    assert_eq!(*execution.result(), 21);

    let second = worker.run_next_or_park_preflight(|value| value + 1);
    assert_eq!(second.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkPoll::StolePeer(execution) = second else {
        panic!("second poll should steal peer work");
    };
    assert_eq!(execution.task_index(), 0);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 1);
    assert_eq!(*execution.result(), 11);

    let third = worker.run_next_or_park_preflight(|value| value + 1);
    assert_eq!(third.ready_work(), ParallelThunkReadyWork::StolePeer);
    let ParallelReadyWorkPoll::StolePeer(execution) = third else {
        panic!("third poll should steal peer work");
    };
    assert_eq!(execution.task_index(), 2);
    assert_eq!(execution.initial_worker(), 0);
    assert_eq!(execution.worker_id(), 1);
    assert_eq!(*execution.result(), 31);

    let fourth = worker.run_next_or_park_preflight(|value| value + 1);
    assert_eq!(fourth.ready_work(), ParallelThunkReadyWork::Idle);
    assert!(fourth.execution().is_none());
    let ParallelReadyWorkPoll::Idle(preflight) = fourth else {
        panic!("fourth poll should report idle preflight");
    };
    assert_eq!(preflight.observing_worker(), 1);
    assert_eq!(preflight.ready_task_count(), 0);
    assert_eq!(preflight.queue_lengths(), &[0, 0]);
    assert!(preflight.is_idle());
}

#[test]
fn ready_work_poll_idle_preflight_does_not_call_runner() {
    let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
    let runner_called = std::cell::Cell::new(false);

    let poll = queues
        .run_next_or_park_preflight(0, |value| {
            runner_called.set(true);
            value
        })
        .expect("idle preflight succeeds");

    assert!(!runner_called.get());
    let preflight = poll
        .park_preflight()
        .expect("idle poll carries preflight snapshot");
    assert_eq!(poll.ready_work(), ParallelThunkReadyWork::Idle);
    assert_eq!(preflight.observing_worker(), 0);
    assert!(preflight.is_idle());
}

#[test]
fn chase_lev_ready_work_poll_idle_preflight_does_not_call_runner() {
    let queues = parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2));
    let worker_queues = queues.into_worker_queues();
    let runner_called = std::cell::Cell::new(false);

    let poll = worker_queues[0].run_next_or_park_preflight(|value| {
        runner_called.set(true);
        value
    });

    assert!(!runner_called.get());
    let preflight = poll
        .park_preflight()
        .expect("idle poll carries preflight snapshot");
    assert_eq!(poll.ready_work(), ParallelThunkReadyWork::Idle);
    assert_eq!(preflight.observing_worker(), 0);
    assert!(preflight.is_idle());
}

#[test]
fn ready_work_poll_rejects_unknown_worker() {
    let queues = parallel_ready_work_queues([1, 2], workers(2));

    let error = queues
        .run_next_or_park_preflight(2, |value| value)
        .expect_err("unknown worker is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkError::WorkerQueueMissing { worker_id: 2 }
    );
}

#[test]
fn ready_work_poll_reports_poisoned_queue() {
    let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(1));
    let poison = std::panic::catch_unwind(|| {
        let _guard = queues.queues[0].lock().expect("queue lock succeeds");
        panic!("poison ready-work queue");
    });
    assert!(poison.is_err());

    let error = queues
        .run_next_or_park_preflight(0, |value| value)
        .expect_err("poisoned queue is reported");

    assert_eq!(
        error,
        ParallelReadyWorkError::WorkerQueuePoisoned { worker_id: 0 }
    );
}

#[test]
fn ready_work_poll_feeds_wait_or_steal_hook_with_preflight() {
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
            let poll = queues
                .run_next_or_park_preflight(1, |value| ran.push(value))
                .expect("ready queue poll succeeds");
            if let Some(snapshot) = poll.park_preflight() {
                preflight = Some(snapshot.clone());
                owner_guard
                    .take()
                    .expect("owner guard remains available")
                    .publish_forced()
                    .expect("owner publishes after idle preflight");
            }
            poll.ready_work()
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

#[test]
fn ready_work_wait_bridge_records_park_readiness_when_waiter_registers() {
    let cell = Arc::new(ParallelThunkWaitCell::new());
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };
    let waiter_cell = Arc::clone(&cell);
    let (result_tx, result_rx) = mpsc::channel();

    let waiter_thread = thread::spawn(move || {
        let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
        let outcome = claim_or_poll_ready_then_wait(&waiter_cell, worker(2), 1, || {
            queues.run_next_or_park_preflight(1, |value| value)
        })
        .expect("ready-work wait bridge succeeds");
        let terminal_state = match outcome.result() {
            ParallelThunkWait::Terminal(terminal_state) => *terminal_state,
            _ => panic!("waiter should observe a terminal state"),
        };
        result_tx
            .send((
                terminal_state,
                outcome.contention_report(),
                outcome.park_readiness().cloned(),
            ))
            .expect("result send succeeds");
    });

    wait_until_registered(&cell, 1);
    assert!(matches!(
        result_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    owner_guard
        .publish_forced()
        .expect("owner publishes forced");
    let (terminal_state, report, park_readiness) = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");
    let park_readiness = park_readiness.expect("registered waiter carries park readiness");

    assert_eq!(terminal_state, ParallelThunkTerminalState::Forced);
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(report.wait_registered());
    assert_eq!(park_readiness.observing_worker(), 1);
    assert_eq!(park_readiness.worker_count(), 2);
    assert_eq!(park_readiness.task_count(), 0);
    assert_eq!(park_readiness.ready_task_count(), 0);
    assert_eq!(park_readiness.queue_lengths(), &[0, 0]);
    waiter_thread.join().expect("waiter joins");
}

#[test]
fn ready_work_wait_bridge_rejects_mismatched_park_preflight_before_wait_registration() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };
    let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

    let error = claim_or_poll_ready_then_wait(&cell, worker(2), 0, || {
        queues.run_next_or_park_preflight(1, |value| value)
    })
    .expect_err("wrong-worker idle preflight is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkWaitError::ParkReadiness(
            ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
                expected_worker: 0,
                observed_worker: 1,
            },
        )
    );
    assert_eq!(
        cell.stats()
            .expect("stats are readable")
            .wait_registrations(),
        0
    );

    owner_guard
        .publish_forced()
        .expect("owner remains publishable after preflight rejection");
}

#[test]
fn ready_work_wait_bridge_rejects_non_idle_preflight_before_wait_registration() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };

    let error = claim_or_poll_ready_then_wait(&cell, worker(2), 1, || {
        Ok::<_, ParallelReadyWorkError>(ParallelReadyWorkPoll::<()>::Idle(
            ParallelReadyWorkParkPreflight {
                observing_worker: 1,
                worker_count: 2,
                task_count: 1,
                queue_lengths: vec![1, 0],
                ready_task_count: 1,
            },
        ))
    })
    .expect_err("non-idle preflight is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkWaitError::ParkReadiness(
            ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
                ready_task_count: 1,
            },
        )
    );
    assert_eq!(
        cell.stats()
            .expect("stats are readable")
            .wait_registrations(),
        0
    );

    owner_guard
        .publish_forced()
        .expect("owner remains publishable after preflight rejection");
}

#[test]
fn ready_work_wait_bridge_ready_work_error_returns_before_wait_registration() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };

    let error = claim_or_poll_ready_then_wait::<(), _>(&cell, worker(2), 1, || Err("queue failed"))
        .expect_err("ready-work errors are propagated");

    assert_eq!(error, ParallelReadyWorkWaitError::ReadyWork("queue failed"));
    assert_eq!(
        cell.stats()
            .expect("stats are readable")
            .wait_registrations(),
        0
    );

    owner_guard
        .publish_forced()
        .expect("owner remains publishable after ready-work error");
}

#[test]
fn ready_work_wait_bridge_drops_park_readiness_when_terminal_wins_race() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };
    let mut owner_guard = Some(owner_guard);
    let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));

    let outcome = claim_or_poll_ready_then_wait(&cell, worker(2), 1, || {
        let poll = queues
            .run_next_or_park_preflight(1, |value| value)
            .expect("idle preflight succeeds");
        owner_guard
            .take()
            .expect("owner guard remains available")
            .publish_forced()
            .expect("owner publishes before wait registration");
        Ok::<_, ParallelReadyWorkError>(poll)
    })
    .expect("ready-work wait bridge observes terminal");

    assert!(matches!(
        outcome.result(),
        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
    ));
    assert!(!outcome.contention_report().wait_registered());
    assert!(outcome.park_readiness().is_none());
    assert_eq!(
        cell.stats()
            .expect("stats are readable")
            .wait_registrations(),
        0
    );
}

#[test]
fn ready_work_queues_reject_unknown_worker() {
    let queues = parallel_ready_work_queues([1, 2], workers(2));

    let error = queues
        .run_next(2, |value| value)
        .expect_err("unknown worker is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkError::WorkerQueueMissing { worker_id: 2 }
    );
}

#[test]
fn ready_work_park_preflight_snapshot_rejects_unknown_worker() {
    let queues = parallel_ready_work_queues([1, 2], workers(2));

    let error = queues
        .park_preflight_snapshot(2)
        .expect_err("unknown worker is rejected");

    assert_eq!(
        error,
        ParallelReadyWorkError::WorkerQueueMissing { worker_id: 2 }
    );
}

#[test]
fn ready_work_queues_report_poisoned_queue() {
    let queues = parallel_ready_work_queues([1], workers(1));
    let poison = std::panic::catch_unwind(|| {
        let _guard = queues.queues[0].lock().expect("queue lock succeeds");
        panic!("poison ready-work queue");
    });
    assert!(poison.is_err());

    let error = queues
        .run_next(0, |value| value)
        .expect_err("poisoned queue is reported");

    assert_eq!(
        error,
        ParallelReadyWorkError::WorkerQueuePoisoned { worker_id: 0 }
    );
}

#[test]
fn ready_work_park_preflight_snapshot_reports_poisoned_queue() {
    let queues = parallel_ready_work_queues([1], workers(1));
    let poison = std::panic::catch_unwind(|| {
        let _guard = queues.queues[0].lock().expect("queue lock succeeds");
        panic!("poison ready-work queue");
    });
    assert!(poison.is_err());

    let error = queues
        .park_preflight_snapshot(0)
        .expect_err("poisoned queue is reported");

    assert_eq!(
        error,
        ParallelReadyWorkError::WorkerQueuePoisoned { worker_id: 0 }
    );
}

#[test]
fn ready_work_queues_drop_popped_task_if_runner_panics() {
    let queues = parallel_ready_work_queues([1], workers(1));

    let panic = std::panic::catch_unwind(|| {
        let _ = queues.run_next(0, |_value| {
            panic!("ready-work runner panics after dequeue");
        });
    });
    assert!(panic.is_err());

    let next = queues
        .run_next(0, |value| value)
        .expect("queue remains usable after runner panic");
    assert_eq!(next.ready_work(), ParallelThunkReadyWork::Idle);
}

#[test]
fn ready_work_queues_feed_thunk_wait_or_steal_hook() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims thunk")
    else {
        panic!("owner should claim suspended wait cell");
    };
    let mut owner_guard = Some(owner_guard);
    let queues = parallel_ready_work_queues([10, 20, 30], workers(2));
    let mut ran = Vec::new();
    let mut runs = 0usize;

    let outcome = cell
        .claim_or_run_ready_then_wait(worker(2), || {
            runs = runs.saturating_add(1);
            let step = queues
                .run_next(1, |value| ran.push(value))
                .expect("ready queue run succeeds");
            if runs == 2 {
                owner_guard
                    .take()
                    .expect("owner guard remains available")
                    .publish_forced()
                    .expect("owner publishes during ready work");
            }
            step.ready_work()
        })
        .expect("wait-or-steal hook completes");

    let (result, report) = outcome.into_parts();
    assert!(matches!(
        result,
        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
    ));
    assert_eq!(ran, vec![20, 10]);
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
}

#[test]
fn nursery_ownership_bridge_rejects_incomplete_scheduler_report() {
    let report = ParallelTopLevelExecutionReport {
        worker_count: 2,
        task_count: 2,
        results: vec![ParallelTaskExecution {
            task_index: 0,
            initial_worker: 0,
            worker_id: 0,
            result: 10,
        }],
        worker_reports: vec![
            ParallelWorkerExecutionReport::new(0),
            ParallelWorkerExecutionReport::new(1),
        ],
    };
    let plan = crate::eval::parallel_heap::parallel_worker_nursery_plan(2, workers(2));

    let error = crate::eval::parallel_heap::parallel_task_nursery_ownership_from_top_level_report(
        &plan, &report,
    )
    .expect_err("incomplete scheduler report rejects");

    assert_eq!(
        error,
        crate::eval::parallel_heap::ParallelNurseryOwnershipError::IncompleteTaskReport {
            task_count: 2,
            completed_task_count: 1
        }
    );
}

#[test]
fn top_level_executor_reports_worker_panic() {
    let error = execute_parallel_top_level(0..4, workers(2), |value| {
        assert_ne!(value, 2, "task panic is reported as worker failure");
        value
    })
    .expect_err("panicking task fails execution");

    assert!(matches!(
        error,
        ParallelTopLevelError::WorkerPanicked { worker_id } if worker_id < 2
    ));
}

#[test]
fn chase_lev_executor_reports_worker_panic() {
    let error = execute_parallel_top_level_chase_lev(0..4, workers(2), |value| {
        assert_ne!(value, 2, "task panic is reported as worker failure");
        value
    })
    .expect_err("panicking task fails Chase-Lev execution");

    assert!(matches!(
        error,
        ParallelTopLevelError::WorkerPanicked { worker_id } if worker_id < 2
    ));
}

#[test]
fn top_level_executor_drains_join_handles_after_multiple_worker_panics() {
    let outcome = std::panic::catch_unwind(|| {
        execute_parallel_top_level(0..8, workers(4), |value| {
            panic!("task {value} panics");
        })
    });

    assert!(
        outcome.is_ok(),
        "executor returns an error instead of unwinding"
    );
    let error = outcome
        .expect("executor call did not unwind")
        .expect_err("panicking tasks fail execution");
    assert!(matches!(
        error,
        ParallelTopLevelError::WorkerPanicked { worker_id } if worker_id < 4
    ));
}

#[test]
fn chase_lev_executor_drains_join_handles_after_multiple_worker_panics() {
    let outcome = std::panic::catch_unwind(|| {
        execute_parallel_top_level_chase_lev(0..8, workers(4), |value| {
            panic!("task {value} panics");
        })
    });

    assert!(
        outcome.is_ok(),
        "Chase-Lev executor returns an error instead of unwinding"
    );
    let error = outcome
        .expect("executor call did not unwind")
        .expect_err("panicking tasks fail Chase-Lev execution");
    assert!(matches!(
        error,
        ParallelTopLevelError::WorkerPanicked { worker_id } if worker_id < 4
    ));
}
