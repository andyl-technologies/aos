//! Unit tests for the parallel thunk wait cell and claim/park protocol.

use std::{
    sync::{
        Arc, Barrier,
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use super::*;

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
fn suspended_wait_cell_claims_and_publishes_forced() {
    let cell = ParallelThunkWaitCell::new();
    let owner = worker(1);

    let ParallelThunkWait::Claimed(guard) = cell
        .claim_or_wait_for_terminal(owner)
        .expect("claim checks state")
    else {
        panic!("suspended wait cell should be claimed");
    };

    let report = guard.publish_forced().expect("publish succeeds");

    assert_eq!(report.terminal_state(), ParallelThunkTerminalState::Forced);
    assert_eq!(cell.state(), Ok(ParallelThunkState::Forced));
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 0,
            notifications: 0,
        }
    );
}

#[test]
fn foreign_waiter_blocks_until_forced_publish_and_wakes() {
    let cell = Arc::new(ParallelThunkWaitCell::new());
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let ParallelThunkWait::Claimed(guard) = cell
                .claim_or_wait_for_terminal(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended cell");
            };
            owner_ready.wait();
            publish_ready.wait();
            guard.publish_forced().expect("owner publishes forced");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let result = cell
                .claim_or_wait_for_terminal(worker(2))
                .expect("waiter observes terminal");
            let ParallelThunkWait::Terminal(terminal_state) = result else {
                panic!("waiter should observe a terminal state");
            };
            result_tx
                .send(terminal_state)
                .expect("result send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    assert!(matches!(
        result_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    publish_ready.wait();
    let result = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");

    assert_eq!(result, ParallelThunkTerminalState::Forced);
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    assert_eq!(cell.state(), Ok(ParallelThunkState::Forced));
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 1,
            notifications: 1,
        }
    );
}

#[test]
fn ready_work_runs_before_parking_and_can_observe_terminal_publish() {
    let cell = ParallelThunkWaitCell::new();
    let owner = worker(1);

    let ParallelThunkWait::Claimed(guard) = cell
        .claim_or_wait_for_terminal(owner)
        .expect("owner claims")
    else {
        panic!("owner should claim suspended cell");
    };
    let mut owner_guard = Some(guard);
    let mut step = 0;

    let outcome = cell
        .claim_or_run_ready_then_wait(worker(2), || {
            step += 1;
            match step {
                1 => ParallelThunkReadyWork::RanLocal,
                2 => {
                    owner_guard
                        .take()
                        .expect("owner guard is present")
                        .publish_forced()
                        .expect("owner publishes while stolen work runs");
                    ParallelThunkReadyWork::StolePeer
                }
                _ => ParallelThunkReadyWork::Idle,
            }
        })
        .expect("wait-or-steal precursor completes");

    let (result, report) = outcome.into_parts();
    assert!(matches!(
        result,
        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
    ));
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 0,
            notifications: 0,
        }
    );
}

#[test]
fn fallible_ready_work_runs_before_parking_and_preserves_report() {
    let cell = ParallelThunkWaitCell::new();
    let owner = worker(1);

    let ParallelThunkWait::Claimed(guard) = cell
        .claim_or_wait_for_terminal(owner)
        .expect("owner claims")
    else {
        panic!("owner should claim suspended cell");
    };
    let mut owner_guard = Some(guard);
    let mut step = 0;

    let outcome = cell
        .claim_or_try_run_ready_then_wait(worker(2), || {
            step += 1;
            match step {
                1 => Ok::<_, &str>(ParallelThunkReadyWork::RanLocal),
                2 => {
                    owner_guard
                        .take()
                        .expect("owner guard is present")
                        .publish_forced()
                        .expect("owner publishes while stolen work runs");
                    Ok(ParallelThunkReadyWork::StolePeer)
                }
                _ => Ok(ParallelThunkReadyWork::Idle),
            }
        })
        .expect("fallible wait-or-steal precursor completes");

    let (result, report) = outcome.into_parts();
    assert!(matches!(
        result,
        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
    ));
    assert_eq!(report.local_work_runs(), 1);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(!report.wait_registered());
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 0,
            notifications: 0,
        }
    );
}

#[test]
fn fallible_ready_work_error_returns_before_wait_registration() {
    let cell = ParallelThunkWaitCell::new();
    let ParallelThunkWait::Claimed(owner_guard) = cell
        .claim_or_wait_for_terminal(worker(1))
        .expect("owner claims")
    else {
        panic!("owner should claim suspended cell");
    };
    let mut step = 0usize;

    let error = cell
        .claim_or_try_run_ready_then_wait(worker(2), || {
            step = step.saturating_add(1);
            match step {
                1 => Ok(ParallelThunkReadyWork::RanLocal),
                _ => Err("queue failed"),
            }
        })
        .expect_err("ready-work error is returned");

    assert_eq!(
        error,
        ParallelThunkReadyWorkWaitError::ReadyWork("queue failed")
    );
    assert_eq!(step, 2);
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 0,
            notifications: 0,
        }
    );

    owner_guard
        .publish_forced()
        .expect("owner can still publish after ready-work error");
    let later = cell
        .claim_or_wait_for_terminal(worker(3))
        .expect("later worker observes terminal");
    assert!(matches!(
        later,
        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
    ));
}

#[test]
fn idle_after_terminal_publish_returns_without_wait_registration() {
    let cell = ParallelThunkWaitCell::new();
    let owner = worker(1);

    let ParallelThunkWait::Claimed(guard) = cell
        .claim_or_wait_for_terminal(owner)
        .expect("owner claims")
    else {
        panic!("owner should claim suspended cell");
    };
    let mut owner_guard = Some(guard);

    let outcome = cell
        .claim_or_run_ready_then_wait(worker(2), || {
            owner_guard
                .take()
                .expect("owner guard is present")
                .publish_forced()
                .expect("owner publishes before idle wait");
            ParallelThunkReadyWork::Idle
        })
        .expect("wait-or-steal precursor completes");

    let (result, report) = outcome.into_parts();
    assert!(matches!(
        result,
        ParallelThunkWait::Terminal(ParallelThunkTerminalState::Forced)
    ));
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(!report.wait_registered());
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 0,
            notifications: 0,
        }
    );
}

#[test]
fn idle_ready_work_parks_until_terminal_publish() {
    let cell = Arc::new(ParallelThunkWaitCell::new());
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let ParallelThunkWait::Claimed(guard) = cell
                .claim_or_wait_for_terminal(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended cell");
            };
            owner_ready.wait();
            publish_ready.wait();
            guard.publish_forced().expect("owner publishes forced");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let outcome = cell
                .claim_or_run_ready_then_wait(worker(2), || ParallelThunkReadyWork::Idle)
                .expect("waiter observes terminal");
            let (result, report) = outcome.into_parts();
            let ParallelThunkWait::Terminal(terminal_state) = result else {
                panic!("waiter should observe a terminal state");
            };
            result_tx
                .send((terminal_state, report))
                .expect("result send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    assert!(matches!(
        result_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));

    publish_ready.wait();
    let (terminal_state, report) = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");

    assert_eq!(terminal_state, ParallelThunkTerminalState::Forced);
    assert_eq!(report.local_work_runs(), 0);
    assert_eq!(report.stolen_work_runs(), 0);
    assert!(report.wait_registered());
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 1,
            notifications: 1,
        }
    );
}

#[test]
fn ready_work_repeats_until_idle_before_wait_registration() {
    let cell = Arc::new(ParallelThunkWaitCell::new());
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let ParallelThunkWait::Claimed(guard) = cell
                .claim_or_wait_for_terminal(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended cell");
            };
            owner_ready.wait();
            publish_ready.wait();
            guard.publish_forced().expect("owner publishes forced");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let mut step = 0;
            let outcome = cell
                .claim_or_run_ready_then_wait(worker(2), || {
                    step += 1;
                    match step {
                        1 | 3 => ParallelThunkReadyWork::RanLocal,
                        2 => ParallelThunkReadyWork::StolePeer,
                        _ => ParallelThunkReadyWork::Idle,
                    }
                })
                .expect("waiter observes terminal");
            let (result, report) = outcome.into_parts();
            let ParallelThunkWait::Terminal(terminal_state) = result else {
                panic!("waiter should observe a terminal state");
            };
            result_tx
                .send((terminal_state, report))
                .expect("result send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    publish_ready.wait();
    let (terminal_state, report) = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");

    assert_eq!(terminal_state, ParallelThunkTerminalState::Forced);
    assert_eq!(report.local_work_runs(), 2);
    assert_eq!(report.stolen_work_runs(), 1);
    assert!(report.wait_registered());
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
}

#[test]
fn dropped_owner_guard_wakes_waiter_with_failed_terminal() {
    let cell = Arc::new(ParallelThunkWaitCell::new());
    let owner_ready = Arc::new(Barrier::new(3));
    let drop_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let drop_ready = Arc::clone(&drop_ready);
        thread::spawn(move || {
            let ParallelThunkWait::Claimed(_guard) = cell
                .claim_or_wait_for_terminal(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended cell");
            };
            owner_ready.wait();
            drop_ready.wait();
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let result = cell
                .claim_or_wait_for_terminal(worker(2))
                .expect("waiter observes terminal");
            let ParallelThunkWait::Terminal(terminal_state) = result else {
                panic!("waiter should observe a terminal state");
            };
            result_tx
                .send(terminal_state)
                .expect("result send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    drop_ready.wait();
    let result = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes");

    assert_eq!(result, ParallelThunkTerminalState::Failed);
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    assert_eq!(cell.state(), Ok(ParallelThunkState::Failed));
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 1,
            notifications: 1,
        }
    );
}

#[test]
fn owner_reentry_reports_self_cycle_without_waiting() {
    let cell = ParallelThunkWaitCell::new();
    let owner = worker(1);

    let ParallelThunkWait::Claimed(guard) = cell
        .claim_or_wait_for_terminal(owner)
        .expect("owner claims")
    else {
        panic!("owner should claim suspended cell");
    };

    assert!(matches!(
        cell.claim_or_wait_for_terminal(owner),
        Ok(ParallelThunkWait::SelfCycle { owner: actual }) if actual == owner
    ));

    guard.publish_failed().expect("cleanup publishes failure");
}

#[test]
fn already_terminal_wait_cell_returns_without_registering_waiter() {
    let cell = ParallelThunkWaitCell::new();
    let owner = worker(1);

    let ParallelThunkWait::Claimed(guard) = cell
        .claim_or_wait_for_terminal(owner)
        .expect("owner claims")
    else {
        panic!("owner should claim suspended cell");
    };
    guard.publish_failed().expect("owner publishes failure");

    assert!(matches!(
        cell.claim_or_wait_for_terminal(worker(2)),
        Ok(ParallelThunkWait::Terminal(
            ParallelThunkTerminalState::Failed
        ))
    ));
    assert_eq!(
        cell.stats().expect("stats are readable"),
        ParallelThunkWaitStats {
            wait_registrations: 0,
            notifications: 0,
        }
    );
}

#[test]
fn publish_still_notifies_after_waiter_lock_poison() {
    let cell = Arc::new(ParallelThunkWaitCell::new());
    let owner_ready = Arc::new(Barrier::new(3));
    let publish_ready = Arc::new(Barrier::new(2));
    let (result_tx, result_rx) = mpsc::channel();

    let owner_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        let publish_ready = Arc::clone(&publish_ready);
        thread::spawn(move || {
            let ParallelThunkWait::Claimed(guard) = cell
                .claim_or_wait_for_terminal(worker(1))
                .expect("owner claims")
            else {
                panic!("owner should claim suspended cell");
            };
            owner_ready.wait();
            publish_ready.wait();
            guard.publish_forced().expect("publish still succeeds");
        })
    };

    let waiter_thread = {
        let cell = Arc::clone(&cell);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            owner_ready.wait();
            let result = cell
                .claim_or_wait_for_terminal(worker(2))
                .expect("waiter observes terminal");
            let ParallelThunkWait::Terminal(terminal_state) = result else {
                panic!("waiter should observe a terminal state");
            };
            result_tx
                .send(terminal_state)
                .expect("result send succeeds");
        })
    };

    owner_ready.wait();
    wait_until_registered(&cell, 1);
    let poison_cell = Arc::clone(&cell);
    let poison_thread = thread::spawn(move || {
        let _poisoned = poison_cell
            .waiters
            .lock()
            .expect("waiter lock is available");
        panic!("poison waiter lock");
    });
    assert!(poison_thread.join().is_err());

    publish_ready.wait();
    let result = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter wakes despite poison");

    assert_eq!(result, ParallelThunkTerminalState::Forced);
    owner_thread.join().expect("owner joins");
    waiter_thread.join().expect("waiter joins");
    assert_eq!(cell.state(), Ok(ParallelThunkState::Forced));
}
