//! Unit tests for the parallel thunk payload cell and its tree-walk bridge.

mod part_1;

use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{compile::ir::IrId, syntax::Span, value::Value};

use super::super::parallel::{parallel_chase_lev_ready_work_queues, parallel_ready_work_queues};
use super::super::tree_walk::{TreeWalkError, TreeWalkErrorKind};
use super::*;

fn worker(raw: u64) -> ParallelThunkWorkerId {
    ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
}

fn workers(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).expect("test worker count is nonzero")
}

fn wait_until_registered<T: Clone, E: Clone>(
    cell: &ParallelThunkPayloadCell<T, E>,
    expected: usize,
) {
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

fn terminal_payload<T: Clone, E: Clone>(
    wait: ParallelThunkPayloadWait<'_, T, E>,
) -> ParallelThunkTerminalPayload<T, E> {
    match wait {
        ParallelThunkPayloadWait::Terminal(payload) => payload,
        ParallelThunkPayloadWait::Claimed(_) => {
            panic!("expected terminal payload, found claim guard");
        }
        ParallelThunkPayloadWait::SelfCycle { owner } => {
            panic!("expected terminal payload, found self-cycle owned by {owner:?}");
        }
    }
}

fn tree_walk_error(raw: u32) -> TreeWalkError {
    TreeWalkError::new(
        TreeWalkErrorKind::DivisionByZero { id: IrId::new(raw) },
        Span::new(raw, raw.saturating_add(1)),
    )
}

fn ready_result(wait: TreeWalkParallelThunkWait<'_>) -> Result<Value, TreeWalkError> {
    match wait {
        TreeWalkParallelThunkWait::Ready(result) => result,
        TreeWalkParallelThunkWait::Claimed(_) => {
            panic!("expected ready tree-walk result, found claim guard");
        }
        TreeWalkParallelThunkWait::SelfCycle { owner } => {
            panic!("expected ready tree-walk result, found self-cycle owned by {owner:?}");
        }
    }
}

fn ready_force_outcome(outcome: TreeWalkParallelThunkForceOutcome) -> Result<Value, TreeWalkError> {
    match outcome {
        TreeWalkParallelThunkForceOutcome::Ready(result) => result,
        TreeWalkParallelThunkForceOutcome::SelfCycle { owner } => {
            panic!("expected ready tree-walk force result, found self-cycle owned by {owner:?}");
        }
    }
}

fn force_self_cycle_owner(outcome: TreeWalkParallelThunkForceOutcome) -> ParallelThunkWorkerId {
    match outcome {
        TreeWalkParallelThunkForceOutcome::SelfCycle { owner } => owner,
        TreeWalkParallelThunkForceOutcome::Ready(_) => {
            panic!("expected tree-walk force self-cycle, found ready result");
        }
    }
}

fn self_cycle_owner(wait: TreeWalkParallelThunkWait<'_>) -> ParallelThunkWorkerId {
    match wait {
        TreeWalkParallelThunkWait::SelfCycle { owner } => owner,
        TreeWalkParallelThunkWait::Ready(_) => {
            panic!("expected tree-walk self-cycle, found ready result");
        }
        TreeWalkParallelThunkWait::Claimed(_) => {
            panic!("expected tree-walk self-cycle, found claim guard");
        }
    }
}

fn claimed_guard(wait: TreeWalkParallelThunkWait<'_>) -> TreeWalkParallelThunkGuard<'_> {
    match wait {
        TreeWalkParallelThunkWait::Claimed(guard) => guard,
        TreeWalkParallelThunkWait::Ready(_) => {
            panic!("expected claimed tree-walk thunk, found ready result");
        }
        TreeWalkParallelThunkWait::SelfCycle { owner } => {
            panic!("expected claimed tree-walk thunk, found self-cycle owned by {owner:?}");
        }
    }
}

#[test]
fn forced_payload_wakes_waiter_and_replays_to_later_claims() {
    let cell = Arc::new(ParallelThunkPayloadCell::<u32, &str>::new("dropped"));
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let ParallelThunkPayloadWait::Claimed(guard) = cell
                .claim_or_wait_for_payload(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended payload cell");
            };
            owner_ready.wait();
            publish_ready.wait();
            guard.publish_forced(55).expect("owner publishes forced");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let result = cell
                .claim_or_wait_for_payload(worker(2))
                .expect("waiter observes payload");
            let ParallelThunkPayloadWait::Terminal(payload) = result else {
                panic!("waiter should observe a terminal payload");
            };
            result_tx.send(payload).expect("payload send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    assert!(matches!(
        result_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    publish_ready.wait();
    let payload = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");

    assert_eq!(payload, ParallelThunkTerminalPayload::Forced(55));
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Forced));
    assert_eq!(
        terminal_payload(
            cell.claim_or_wait_for_payload(worker(3))
                .expect("later claimant reads payload")
        ),
        ParallelThunkTerminalPayload::Forced(55)
    );
}

#[test]
fn failed_payload_wakes_waiter_and_replays_to_later_claims() {
    let cell = Arc::new(ParallelThunkPayloadCell::<u32, &str>::new("dropped"));
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let ParallelThunkPayloadWait::Claimed(guard) = cell
                .claim_or_wait_for_payload(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended payload cell");
            };
            owner_ready.wait();
            publish_ready.wait();
            guard
                .publish_failed("boom")
                .expect("owner publishes failure");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let result = cell
                .claim_or_wait_for_payload(worker(2))
                .expect("waiter observes payload");
            let ParallelThunkPayloadWait::Terminal(payload) = result else {
                panic!("waiter should observe a terminal payload");
            };
            result_tx.send(payload).expect("payload send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    publish_ready.wait();
    let payload = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");

    assert_eq!(payload, ParallelThunkTerminalPayload::Failed("boom"));
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
    assert_eq!(
        terminal_payload(
            cell.claim_or_wait_for_payload(worker(3))
                .expect("later claimant reads payload")
        ),
        ParallelThunkTerminalPayload::Failed("boom")
    );
}

#[test]
fn dropped_claim_publishes_configured_failure_payload() {
    let cell = ParallelThunkPayloadCell::<u32, &str>::new("dropped");

    {
        let ParallelThunkPayloadWait::Claimed(_guard) = cell
            .claim_or_wait_for_payload(worker(1))
            .expect("owner claims")
        else {
            panic!("owner should claim suspended payload cell");
        };
    }

    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
    assert_eq!(
        cell.terminal_payload(),
        Some(ParallelThunkTerminalPayload::Failed("dropped"))
    );
    assert_eq!(
        terminal_payload(
            cell.claim_or_wait_for_payload(worker(2))
                .expect("later claimant reads drop failure")
        ),
        ParallelThunkTerminalPayload::Failed("dropped")
    );
}

#[test]
fn dropped_claim_wakes_registered_waiter_with_configured_failure_payload() {
    let cell = Arc::new(ParallelThunkPayloadCell::<u32, &str>::new("dropped"));
    let owner_ready = Arc::new(Barrier::new(3));
    let drop_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let drop_ready = Arc::clone(&drop_ready);
        thread::spawn(move || {
            let ParallelThunkPayloadWait::Claimed(guard) = cell
                .claim_or_wait_for_payload(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended payload cell");
            };
            owner_ready.wait();
            drop_ready.wait();
            drop(guard);
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let payload = terminal_payload(
                cell.claim_or_wait_for_payload(worker(2))
                    .expect("waiter observes drop failure"),
            );
            result_tx.send(payload).expect("payload send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    assert!(matches!(
        result_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    drop_ready.wait();
    let payload = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");

    assert_eq!(payload, ParallelThunkTerminalPayload::Failed("dropped"));
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));

    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 1);
    assert_eq!(stats.notifications(), 1);
}

#[test]
fn ready_work_path_returns_payload_and_contention_report() {
    let cell = ParallelThunkPayloadCell::new("dropped");
    let ParallelThunkPayloadWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_payload(worker(1))
        .expect("owner claims")
    else {
        panic!("owner should claim suspended payload cell");
    };
    let mut owner_guard = Some(owner_guard);
    let mut step = 0usize;

    let outcome = cell
        .claim_or_run_ready_then_wait_for_payload(worker(2), || {
            step = step.saturating_add(1);
            match step {
                1 => ParallelThunkReadyWork::RanLocal,
                2 => {
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_forced(99)
                        .expect("owner publishes during ready work");
                    ParallelThunkReadyWork::StolePeer
                }
                _ => ParallelThunkReadyWork::Idle,
            }
        })
        .expect("wait-or-steal payload path completes");

    let (result, report) = outcome.into_parts();
    assert_eq!(
        terminal_payload(result),
        ParallelThunkTerminalPayload::Forced(99)
    );
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 0);
    assert_eq!(stats.notifications(), 0);
}

#[test]
fn payload_fallible_ready_work_error_returns_before_wait_registration() {
    let cell = ParallelThunkPayloadCell::new("dropped");
    let ParallelThunkPayloadWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_payload(worker(1))
        .expect("owner claims")
    else {
        panic!("owner should claim suspended payload cell");
    };
    let mut step = 0usize;

    let error = cell
        .claim_or_try_run_ready_then_wait_for_payload(worker(2), || {
            step = step.saturating_add(1);
            match step {
                1 => Ok(ParallelThunkReadyWork::RanLocal),
                _ => Err("queue failed"),
            }
        })
        .expect_err("ready-work error is returned");

    assert_eq!(
        error,
        ParallelThunkPayloadReadyWorkError::ReadyWork("queue failed")
    );
    assert_eq!(step, 2);
    let stats = cell.stats().expect("stats are readable");
    assert_eq!(stats.wait_registrations(), 0);
    assert_eq!(stats.notifications(), 0);

    owner_guard
        .publish_forced(123)
        .expect("owner can publish after ready-work error");
    assert_eq!(
        terminal_payload(
            cell.claim_or_wait_for_payload(worker(3))
                .expect("later claimant reads payload")
        ),
        ParallelThunkTerminalPayload::Forced(123)
    );
}

#[test]
fn tree_walk_parallel_thunk_replays_forced_values_as_ok_results() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );

    guard
        .publish_value(Value::int(42))
        .expect("owner publishes value");

    let later = ready_result(
        cell.claim_or_wait_for_result(worker(2))
            .expect("later worker reads terminal value"),
    )
    .expect("forced value replays as Ok");

    assert_eq!(later.as_int(), Ok(42));
    assert_eq!(
        cell.terminal_result()
            .expect("terminal result is stored")
            .expect("stored result is Ok")
            .as_int(),
        Ok(42)
    );
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Forced));
}

#[test]
fn tree_walk_parallel_thunk_force_body_runs_once_and_wakes_waiter() {
    let cell = Arc::new(TreeWalkParallelThunkCell::new(tree_walk_error(99)));
    let body_runs = Arc::new(AtomicUsize::new(0));
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (owner_tx, owner_rx) = mpsc::channel();
    let (waiter_tx, waiter_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let body_runs = Arc::clone(&body_runs);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let outcome = cell
                .force_or_wait_with(worker(1), || {
                    body_runs.fetch_add(1, AtomicOrdering::SeqCst);
                    owner_ready.wait();
                    publish_ready.wait();
                    Ok(Value::int(144))
                })
                .expect("owner forces tree-walk thunk body");
            owner_tx
                .send(ready_force_outcome(outcome))
                .expect("owner result send succeeds");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let outcome = cell
                .force_or_wait_with(worker(2), || {
                    panic!("waiter must not evaluate the claimed thunk body");
                })
                .expect("waiter observes owner result");
            waiter_tx
                .send(ready_force_outcome(outcome))
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
    let owner_result = owner_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("owner returns")
        .expect("owner result is Ok");
    let waiter_result = waiter_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes")
        .expect("waiter result is Ok");

    assert_eq!(owner_result.as_int(), Ok(144));
    assert_eq!(waiter_result.as_int(), Ok(144));
    assert_eq!(body_runs.load(AtomicOrdering::SeqCst), 1);
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
}

#[test]
fn tree_walk_parallel_thunk_force_body_publishes_error_result() {
    let expected = tree_walk_error(31);
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

    let owner_result = ready_force_outcome(
        cell.force_or_wait_with(worker(1), || Err(expected.clone()))
            .expect("owner publishes body error"),
    )
    .expect_err("owner sees body error");
    assert_eq!(owner_result, expected);

    let later_result = ready_force_outcome(
        cell.force_or_wait_with(worker(2), || {
            panic!("later worker must not re-run failed body");
        })
        .expect("later worker replays body error"),
    )
    .expect_err("later worker sees body error");
    assert_eq!(later_result, expected);
    assert_eq!(cell.state(), Ok(ParallelThunkTerminalStatus::Failed));
}

#[test]
fn tree_walk_parallel_thunk_force_body_preserves_self_cycle() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let _guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );

    let outcome = cell
        .force_or_wait_with(worker(1), || {
            panic!("self-cycle must not evaluate the thunk body");
        })
        .expect("self-cycle is classified");

    assert_eq!(force_self_cycle_owner(outcome), worker(1));
    assert!(cell.terminal_result().is_none());
}

#[test]
fn tree_walk_parallel_thunk_force_ready_path_claim_owner_runs_body_without_ready_work() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

    let outcome = cell
        .force_or_run_ready_then_wait_with(
            worker(1),
            || {
                panic!("ready work should not run when this worker claims the thunk");
            },
            || Ok(Value::int(188)),
        )
        .expect("claim owner forces through ready path");

    let (result, report) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("claim owner result is Ok")
            .as_int(),
        Ok(188)
    );
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(!report.wait_registered());
}

#[test]
fn tree_walk_parallel_thunk_force_ready_path_runs_ready_work_before_replay() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let mut owner_guard = Some(owner_guard);
    let mut step = 0usize;

    let outcome = cell
        .force_or_run_ready_then_wait_with(
            worker(2),
            || {
                step = step.saturating_add(1);
                match step {
                    1 => ParallelThunkReadyWork::RanLocal,
                    2 => {
                        owner_guard
                            .take()
                            .expect("owner guard remains available")
                            .publish_value(Value::int(233))
                            .expect("owner publishes during ready work");
                        ParallelThunkReadyWork::StolePeer
                    }
                    _ => ParallelThunkReadyWork::Idle,
                }
            },
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect("ready-work force path completes");

    let (result, report) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("replayed result is Ok")
            .as_int(),
        Ok(233)
    );
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
}

#[test]
fn tree_walk_parallel_thunk_force_poll_path_claim_owner_runs_body_without_polling() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));

    let outcome = cell
        .force_or_poll_ready_then_wait_with::<()>(
            worker(1),
            || {
                panic!("ready-work poll should not run when this worker claims the thunk");
            },
            || Ok(Value::int(258)),
        )
        .expect("claim owner forces through poll path");

    let (result, report, preflight) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("claim owner result is Ok")
            .as_int(),
        Ok(258)
    );
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(!report.wait_registered());
    assert!(preflight.is_none());
}

#[test]
fn tree_walk_parallel_thunk_force_poll_path_captures_idle_preflight_before_replay() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let mut owner_guard = Some(owner_guard);
    let queues = parallel_ready_work_queues([10, 20], workers(2));
    let mut ran = Vec::new();

    let outcome = cell
        .force_or_poll_ready_then_wait_with(
            worker(2),
            || {
                let poll = queues
                    .run_next_or_park_preflight(1, |value| ran.push(value))
                    .expect("ready-work poll succeeds");
                if poll.ready_work() == ParallelThunkReadyWork::Idle {
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_value(Value::int(1597))
                        .expect("owner publishes after idle preflight");
                }
                poll
            },
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect("poll force path completes");

    assert!(
        outcome
            .registered_park_readiness_for_worker(1)
            .expect("captured replay preflight validates when checked")
            .is_none()
    );
    let (result, report, preflight) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("replayed result is Ok")
            .as_int(),
        Ok(1597)
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
fn tree_walk_parallel_thunk_chase_lev_ready_path_claim_owner_runs_body_without_polling() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let worker_queues =
        parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
    let mut ran = Vec::new();

    let outcome = cell
        .force_or_chase_lev_ready_then_wait_with(
            worker(2),
            &worker_queues[1],
            |value| ran.push(value),
            || Ok(Value::int(34)),
        )
        .expect("claim owner forces through Chase-Lev bridge");

    let (result, report, preflight) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("claim owner result is Ok")
            .as_int(),
        Ok(34)
    );
    assert!(ran.is_empty());
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(!report.wait_registered());
    assert!(preflight.is_none());
}

#[test]
fn tree_walk_parallel_thunk_chase_lev_ready_path_runs_local_and_stolen_before_replay() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let mut owner_guard = Some(owner_guard);
    let worker_queues =
        parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
    let mut ran = Vec::new();

    let outcome = cell
        .force_or_chase_lev_ready_then_wait_with(
            worker(2),
            &worker_queues[1],
            |value| {
                ran.push(value);
                if ran.len() == 2 {
                    owner_guard
                        .take()
                        .expect("owner guard remains available")
                        .publish_value(Value::int(55))
                        .expect("owner publishes during stolen ready work");
                }
            },
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect("Chase-Lev ready-work force path completes");
    let (result, report, preflight) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("replayed result is Ok")
            .as_int(),
        Ok(55)
    );
    assert_eq!(ran, vec![20, 10]);
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
    assert!(preflight.is_none());
}

#[test]
fn tree_walk_parallel_thunk_chase_lev_ready_path_rechecks_after_one_local_task() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
    let mut owner_guard = Some(owner_guard);
    let worker_queues =
        parallel_chase_lev_ready_work_queues([10, 20], workers(2)).into_worker_queues();
    let mut ran = Vec::new();

    let outcome = cell
        .force_or_chase_lev_ready_then_wait_with(
            worker(2),
            &worker_queues[1],
            |value| {
                ran.push(value);
                owner_guard
                    .take()
                    .expect("owner guard remains available")
                    .publish_value(Value::int(144))
                    .expect("owner publishes during local ready work");
            },
            || {
                panic!("waiting worker must not evaluate the claimed thunk body");
            },
        )
        .expect("Chase-Lev ready-work force path completes after one local task");
    let (result, report, preflight) = outcome.into_parts();
    assert_eq!(
        ready_force_outcome(result)
            .expect("replayed result is Ok")
            .as_int(),
        Ok(144)
    );
    assert_eq!(ran, vec![20]);
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(!report.wait_registered());
    assert!(preflight.is_none());
}

#[test]
fn tree_walk_parallel_thunk_chase_lev_ready_path_captures_preflight_before_blocking_wait() {
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
                .publish_value(Value::int(89))
                .expect("owner publishes tree-walk value");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            let worker_queues =
                parallel_chase_lev_ready_work_queues(std::iter::empty::<usize>(), workers(2))
                    .into_worker_queues();
            owner_ready.wait();
            let outcome = cell
                .force_or_chase_lev_ready_then_wait_with(
                    worker(2),
                    &worker_queues[1],
                    |value| value,
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
    assert_eq!(value.as_int(), Ok(89));
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
fn tree_walk_parallel_thunk_chase_lev_ready_path_rejects_queue_worker_mismatch() {
    let cell = TreeWalkParallelThunkCell::new(tree_walk_error(99));
    let owner_guard = claimed_guard(
        cell.claim_or_wait_for_result(worker(1))
            .expect("owner claims tree-walk thunk"),
    );
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
                Ok(Value::int(144))
            },
        )
        .expect_err("worker/queue mismatch is rejected");

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

    owner_guard
        .publish_value(Value::int(233))
        .expect("owner can publish after rejected mismatch");
}
