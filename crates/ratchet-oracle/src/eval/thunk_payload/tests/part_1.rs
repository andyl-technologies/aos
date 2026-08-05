//! Parallel thunk payload-cell tests, continued.

use super::*;

#[test]
fn tree_walk_parallel_thunk_chase_lev_ready_path_rejects_mismatch_before_claiming_suspended() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let worker_queues =
        parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
    let before = worker_queues[0].park_preflight_snapshot();
    let mut ready_work_ran = false;
    let mut body_ran = false;

    let error = cell
        .force_or_chase_lev_ready_then_wait_with(
            worker(2),
            &worker_queues[0],
            |value| {
                ready_work_ran = true;
                value
            },
            || {
                body_ran = true;
                Ok(Value::int(377))
            },
        )
        .expect_err("worker/queue mismatch is rejected before claim");

    assert_eq!(
        error,
        ParallelThunkPayloadError::ReadyWorkQueueWorkerMismatch {
            worker: worker(2),
            expected_queue_worker: 1,
            queue_worker: 0
        }
    );
    assert!(!ready_work_ran);
    assert!(!body_ran);
    let after = worker_queues[0].park_preflight_snapshot();
    assert_eq!(after.queue_lengths(), before.queue_lengths());
    assert_eq!(after.ready_task_count(), before.ready_task_count());
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 0);
    assert_eq!(stats.notifications(), 0);
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Suspended));
}

#[test]
fn tree_walk_parallel_thunk_force_poll_path_captures_preflight_before_blocking_wait() {
    let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (waiter_tx, waiter_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let guard = claimed_guard(
                cell.claim_or_wait_for_result(worker(1))
                    .expect("owner claims tree-walk thunk"),
            );
            owner_ready.wait();
            publish_ready.wait();
            guard
                .publish_value(Value::int(4181))
                .expect("owner publishes tree-walk value");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
            owner_ready.wait();
            let outcome = cell
                .force_or_poll_ready_then_wait_with(
                    worker(2),
                    || {
                        queues
                            .run_next_or_park_preflight(1, |value| value)
                            .expect("idle preflight poll succeeds")
                    },
                    || {
                        panic!("waiting worker must not evaluate the claimed thunk body");
                    },
                )
                .expect("waiter observes owner result");
            let readiness = outcome
                .registered_park_readiness_for_worker(1)
                .expect("registered park preflight validates")
                .expect("waiter registration has a park readiness");
            let (result, report, preflight) = outcome.into_parts();
            waiter_tx
                .send((ready_force_outcome(result), report, preflight, readiness))
                .expect("waiter result send succeeds");
        })
    };

    owner_ready.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cell
            .stats()
            .expect("stats are readable")
            .wait_registrations()
            >= 1
        {
            break;
        }
        thread::yield_now();
    }
    assert_eq!(
        cell.stats()
            .expect("stats are readable")
            .wait_registrations(),
        1
    );
    assert!(matches!(
        waiter_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    publish_ready.wait();
    let (result, report, preflight, readiness) = waiter_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");
    let value = result.expect("waiter result is Ok");
    let preflight = preflight.expect("idle preflight is captured before blocking");
    assert_eq!(value.as_int(), Ok(4181));
    assert_eq!(readiness.preflight(), &preflight);
    assert_eq!(readiness.observing_worker(), 1);
    assert_eq!(readiness.ready_task_count(), 0);
    assert_eq!(preflight.observing_worker(), 1);
    assert_eq!(preflight.ready_task_count(), 0);
    assert!(preflight.is_idle());
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(report.wait_registered());
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
}

#[test]
fn tree_walk_parallel_thunk_force_poll_path_replays_body_error() {
    let expected = tree_walk_error(43);
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

    let owner = cell
        .force_or_poll_ready_then_wait_with::<()>(
            worker(1),
            || {
                panic!("claim owner should not poll ready work");
            },
            || Err(expected.clone()),
        )
        .expect("owner publishes body error");
    assert_eq!(
        ready_force_outcome(owner.outcome().clone()).expect_err("owner sees body error"),
        expected
    );
    assert_eq!(owner.report().local_work_runs(), 0);
    assert_eq!(owner.report().stolen_work_runs(), 0);
    assert!(!owner.report().wait_registered());
    assert!(owner.park_preflight().is_none());

    let later = cell
        .force_or_poll_ready_then_wait_with::<()>(
            worker(2),
            || {
                panic!("terminal replay should not poll ready work");
            },
            || {
                panic!("terminal replay should not run body");
            },
        )
        .expect("later worker replays body error");
    assert_eq!(
        ready_force_outcome(later.outcome().clone()).expect_err("later sees body error"),
        expected
    );
    assert_eq!(later.report().local_work_runs(), 0);
    assert_eq!(later.report().stolen_work_runs(), 0);
    assert!(!later.report().wait_registered());
    assert!(later.park_preflight().is_none());
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
}

#[test]
fn tree_walk_parallel_thunk_force_poll_path_rejects_non_idle_preflight_before_wait() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let queues = parallel_ready_work_queues([10], workers(2));
    let snapshot = queues
        .park_preflight_snapshot(1)
        .expect("non-idle preflight snapshot succeeds");

    let error = cell
        .force_or_poll_ready_then_wait_with(
            worker(2),
            || ParallelReadyWorkPoll::<()>::Idle(snapshot.clone()),
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect_err("non-idle preflight is rejected");

    assert_eq!(
        error,
        ParallelThunkPayloadError::ParkReadiness(
            ParallelReadyWorkParkReadinessError::ReadyWorkRemaining {
                ready_task_count: 1
            }
        )
    );
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 0);
    assert_eq!(stats.notifications(), 0);

    owner_guard
        .publish_value(Value::int(6765))
        .expect("owner can publish after rejected preflight");
    assert_eq!(
        ready_result(
            cell.claim_or_wait_for_result(worker(3))
                .expect("later worker reads terminal value")
        )
        .expect("later value replays as Ok")
        .as_int(),
        Ok(6765)
    );
}

#[test]
fn tree_walk_parallel_thunk_try_poll_path_rejects_wrong_worker_preflight_before_wait() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let queues = parallel_ready_work_queues(std::iter::empty::<usize>(), workers(2));
    let snapshot = queues
        .park_preflight_snapshot(0)
        .expect("idle preflight snapshot succeeds");

    let error = cell
        .force_or_try_poll_ready_then_wait_with(
            worker(2),
            || {
                Ok::<_, crate::eval::parallel::ParallelReadyWorkError>(
                    ParallelReadyWorkPoll::<()>::Idle(snapshot.clone()),
                )
            },
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect_err("wrong-worker preflight is rejected");

    assert_eq!(
        error,
        ParallelThunkPayloadReadyWorkError::Payload(ParallelThunkPayloadError::ParkReadiness(
            ParallelReadyWorkParkReadinessError::ObservingWorkerMismatch {
                expected_worker: 1,
                observed_worker: 0
            }
        ))
    );
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 0);
    assert_eq!(stats.notifications(), 0);

    owner_guard
        .publish_value(Value::int(10946))
        .expect("owner can publish after rejected preflight");
    assert_eq!(
        ready_result(
            cell.claim_or_wait_for_result(worker(3))
                .expect("later worker reads terminal value")
        )
        .expect("later value replays as Ok")
        .as_int(),
        Ok(10946)
    );
}

#[test]
fn tree_walk_parallel_thunk_try_ready_work_error_returns_before_wait_registration() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let mut step = 0usize;

    let error = cell
        .claim_or_try_run_ready_then_wait_for_result(worker(2), || {
            step = step.saturating_add(1);
            match step {
                1 => Ok(ParallelThunkReadyWork::RanLocal),
                _ => Err("scheduler failed"),
            }
        })
        .expect_err("ready-work error is returned");

    assert_eq!(
        error,
        ParallelThunkPayloadReadyWorkError::ReadyWork("scheduler failed")
    );
    assert_eq!(step, 2);
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 0);
    assert_eq!(stats.notifications(), 0);

    owner_guard
        .publish_value(Value::int(610))
        .expect("owner can publish after ready-work error");
    assert_eq!(
        ready_result(
            cell.claim_or_wait_for_result(worker(3))
                .expect("later worker reads terminal value")
        )
        .expect("later value replays as Ok")
        .as_int(),
        Ok(610)
    );
}

#[test]
fn tree_walk_parallel_thunk_try_poll_path_propagates_scheduler_queue_error() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let queues = parallel_ready_work_queues([10], workers(1));

    let error = cell
        .force_or_try_poll_ready_then_wait_with(
            worker(2),
            || queues.run_next_or_park_preflight(1, |value| value),
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect_err("scheduler queue error is propagated");

    assert_eq!(
        error,
        ParallelThunkPayloadReadyWorkError::ReadyWork(
            crate::eval::parallel::ParallelReadyWorkError::WorkerQueueMissing { worker_id: 1 }
        )
    );
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 0);
    assert_eq!(stats.notifications(), 0);

    owner_guard
        .publish_value(Value::int(987))
        .expect("owner can publish after scheduler queue error");
    assert_eq!(
        ready_result(
            cell.claim_or_wait_for_result(worker(3))
                .expect("later worker reads terminal value")
        )
        .expect("later value replays as Ok")
        .as_int(),
        Ok(987)
    );
}

#[test]
fn tree_walk_parallel_thunk_try_poll_path_captures_preflight_before_replay() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let mut owner_guard = Some(owner_guard);
    let queues = parallel_ready_work_queues([10, 20], workers(2));
    let mut ran = Vec::new();

    let outcome = cell
        .force_or_try_poll_ready_then_wait_with(
            worker(2),
            || {
                let poll = queues.run_next_or_park_preflight(1, |value| ran.push(value))?;
                if poll.ready_work() == ParallelThunkReadyWork::Idle {
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_value(Value::int(2584))
                        .expect("owner publishes after idle preflight");
                }
                Ok::<_, crate::eval::parallel::ParallelReadyWorkError>(poll)
            },
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect("fallible poll force path completes");

    let (result, report, preflight) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("replayed result is Ok")
            .as_int(),
        Ok(2584)
    );
    let preflight = preflight.expect("idle preflight is captured");
    assert_eq!(ran, vec![20, 10]);
    assert_eq!(preflight.observing_worker(), 1);
    assert_eq!(preflight.ready_task_count(), 0);
    assert!(preflight.is_idle());
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
}

#[test]
fn tree_walk_parallel_thunk_force_ready_path_reports_blocking_waiter_registration() {
    let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (waiter_tx, waiter_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let guard = claimed_guard(
                cell.claim_or_wait_for_result(worker(1))
                    .expect("owner claims tree-walk thunk"),
            );
            owner_ready.wait();
            publish_ready.wait();
            guard
                .publish_value(Value::int(377))
                .expect("owner publishes tree-walk value");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let outcome = cell
                .force_or_run_ready_then_wait_with(
                    worker(2),
                    || ParallelThunkReadyWork::Idle,
                    || {
                        panic!("waiting worker must not evaluate the claimed thunk body");
                    },
                )
                .expect("waiter observes owner result");
            let (result, report) = outcome.into_parts();
            waiter_tx
                .send((ready_force_outcome(result), report))
                .expect("waiter result send succeeds");
        })
    };

    owner_ready.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cell
            .stats()
            .expect("stats are readable")
            .wait_registrations()
            >= 1
        {
            break;
        }
        thread::yield_now();
    }
    assert_eq!(
        cell.stats()
            .expect("stats are readable")
            .wait_registrations(),
        1
    );
    assert!(matches!(
        waiter_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    publish_ready.wait();
    let (result, report) = waiter_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");
    let value = result.expect("waiter result is Ok");
    assert_eq!(value.as_int(), Ok(377));
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(report.wait_registered());
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
}

#[test]
fn tree_walk_parallel_thunk_force_ready_path_replays_body_error() {
    let expected = tree_walk_error(41);
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

    let owner = cell
        .force_or_run_ready_then_wait_with(
            worker(1),
            || {
                panic!("claim owner should not run ready work");
            },
            || Err(expected.clone()),
        )
        .expect("owner publishes body error");
    assert_eq!(
        ready_force_outcome(owner.outcome().clone()).expect_err("owner sees body error"),
        expected
    );
    assert_eq!(owner.report().local_work_runs(), 0);

    let later = cell
        .force_or_run_ready_then_wait_with(
            worker(2),
            || {
                panic!("terminal replay should not run ready work");
            },
            || {
                panic!("terminal replay should not run body");
            },
        )
        .expect("later worker replays body error");
    assert_eq!(
        ready_force_outcome(later.outcome().clone()).expect_err("later sees body error"),
        expected
    );
    assert_eq!(later.report().local_work_runs(), 0);
    assert_eq!(later.report().stolen_work_runs(), 0);
    assert!(!later.report().wait_registered());
}

#[test]
fn tree_walk_parallel_thunk_force_ready_path_preserves_self_cycle() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let _guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );

    let outcome = cell
        .force_or_run_ready_then_wait_with(
            worker(1),
            || {
                panic!("self-cycle should not run ready work");
            },
            || {
                panic!("self-cycle should not run body");
            },
        )
        .expect("self-cycle is classified");

    let (result, report) = outcome.into_parts();
    assert_eq!(force_self_cycle_owner(result), worker(1));
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(!report.wait_registered());
}

#[test]
fn tree_walk_parallel_thunk_force_poll_path_preserves_self_cycle_without_polling() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let _guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );

    let outcome = cell
        .force_or_poll_ready_then_wait_with::<()>(
            worker(1),
            || {
                panic!("self-cycle should not poll ready work");
            },
            || {
                panic!("self-cycle should not run body");
            },
        )
        .expect("self-cycle is classified");

    let (result, report, preflight) = outcome.into_parts();
    assert_eq!(force_self_cycle_owner(result), worker(1));
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(!report.wait_registered());
    assert!(preflight.is_none());
}

#[test]
fn tree_walk_parallel_thunk_forced_value_wakes_blocked_waiter() {
    let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let guard = claimed_guard(
                cell.claim_or_wait_for_result(worker(1))
                    .expect("owner claims tree-walk thunk"),
            );
            owner_ready.wait();
            publish_ready.wait();
            guard
                .publish_value(Value::int(123))
                .expect("owner publishes tree-walk value");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let result = ready_result(
                cell.claim_or_wait_for_result(worker(2))
                    .expect("waiter observes tree-walk value"),
            );
            result_tx.send(result).expect("result send succeeds");
        })
    };

    owner_ready.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cell
            .stats()
            .expect("stats are readable")
            .wait_registrations()
            >= 1
        {
            break;
        }
        thread::yield_now();
    }
    assert_eq!(
        cell.stats()
            .expect("stats are readable")
            .wait_registrations(),
        1
    );
    assert!(matches!(
        result_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    publish_ready.wait();
    let result = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes")
        .expect("forced value replays as Ok");

    assert_eq!(result.as_int(), Ok(123));
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 1);
    assert_eq!(stats.notifications(), 1);
}

#[test]
fn tree_walk_parallel_thunk_replays_failures_as_err_results() {
    let expected = tree_walk_error(7);
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );

    guard
        .publish_error(expected.clone())
        .expect("owner publishes error");

    let later = ready_result(
        cell.claim_or_wait_for_result(worker(2))
            .expect("later worker reads terminal error"),
    )
    .expect_err("failed thunk replays as Err");

    assert_eq!(later, expected);
    assert_eq!(
        cell.terminal_result()
            .expect("terminal result is stored")
            .expect_err("stored result is Err"),
        expected
    );
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
}

#[test]
fn tree_walk_parallel_thunk_publish_result_routes_ok_and_err() {
    let ok_cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    claimed_guard(
        ok_cell
            .claim_or_wait_for_result(worker(1))
            .expect("owner claims ok tree-walk thunk"),
    )
    .publish_result(Ok(Value::int(64)))
    .expect("owner publishes ok result");
    assert_eq!(
        ready_result(
            ok_cell
                .claim_or_wait_for_result(worker(2))
                .expect("later worker reads ok result")
        )
        .expect("stored result is ok")
        .as_int(),
        Ok(64)
    );

    let err_cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let expected = tree_walk_error(21);
    claimed_guard(
        err_cell
            .claim_or_wait_for_result(worker(1))
            .expect("owner claims err tree-walk thunk"),
    )
    .publish_result(Err(expected.clone()))
    .expect("owner publishes err result");
    assert_eq!(
        ready_result(
            err_cell
                .claim_or_wait_for_result(worker(2))
                .expect("later worker reads err result")
        )
        .expect_err("stored result is err"),
        expected
    );
}

#[test]
fn tree_walk_parallel_thunk_preserves_self_cycle_classification() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let _guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );

    assert_eq!(
        self_cycle_owner(
            cell.claim_or_wait_for_result(worker(1))
                .expect("same worker sees self-cycle")
        ),
        worker(1)
    );
    assert!(cell.terminal_result().is_none());
}

#[test]
fn tree_walk_parallel_thunk_drop_publishes_configured_error() {
    let dropped = tree_walk_error(13);
    let cell = TreeWalkParallelThunkCell::new(dropped.clone());

    {
        let _guard = claimed_guard(
            cell.claim_or_wait_for_result(worker(1))
                .expect("owner claims tree-walk thunk"),
        );
    }

    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
    assert_eq!(
        cell.terminal_result()
            .expect("terminal result is stored")
            .expect_err("drop failure replays as Err"),
        dropped
    );
}

#[test]
fn tree_walk_parallel_thunk_ready_work_preserves_contention_report() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let mut owner_guard = Some(owner_guard);
    let mut step = 0usize;

    let outcome = cell
        .claim_or_run_ready_then_wait_for_result(worker(2), || {
            step = step.saturating_add(1);
            match step {
                1 => ParallelThunkReadyWork::RanLocal,
                2 => {
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_value(Value::int(77))
                        .expect("owner publishes during ready work");
                    ParallelThunkReadyWork::StolePeer
                }
                _ => ParallelThunkReadyWork::Idle,
            }
        })
        .expect("wait-or-steal tree-walk path completes");

    let (result, report) = outcome.into_parts();
    assert_eq!(
        ready_result(result)
            .expect("forced value replays as Ok")
            .as_int(),
        Ok(77)
    );
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
}
