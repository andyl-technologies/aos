//! Unit tests for the parallel thunk CAS state word and claim protocol.

use std::{
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    },
    thread,
};

use super::*;

fn worker(raw: u64) -> ParallelThunkWorkerId {
    ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
}

#[test]
fn memory_ordering_audit_pins_state_word_orderings() {
    let audit = validate_parallel_thunk_memory_ordering().expect("memory ordering audit succeeds");

    assert_eq!(audit.requirement_count(), 7);
    assert_eq!(
        audit.ordering_for(ParallelThunkMemoryOrderingRole::StateLoad),
        Some(Ordering::Acquire)
    );
    assert_eq!(
        audit.ordering_for(ParallelThunkMemoryOrderingRole::ClaimSuccess),
        Some(Ordering::AcqRel)
    );
    assert_eq!(
        audit.ordering_for(ParallelThunkMemoryOrderingRole::ClaimFailure),
        Some(Ordering::Acquire)
    );
    assert_eq!(
        audit.ordering_for(ParallelThunkMemoryOrderingRole::AwaitMarkSuccess),
        Some(Ordering::AcqRel)
    );
    assert_eq!(
        audit.ordering_for(ParallelThunkMemoryOrderingRole::AwaitMarkFailure),
        Some(Ordering::Acquire)
    );
    assert_eq!(
        audit.ordering_for(ParallelThunkMemoryOrderingRole::TerminalPublishSuccess),
        Some(Ordering::Release)
    );
    assert_eq!(
        audit.ordering_for(ParallelThunkMemoryOrderingRole::TerminalPublishFailure),
        Some(Ordering::Acquire)
    );
    assert!(
        audit
            .requirements()
            .iter()
            .all(
                |requirement| requirement.expected_ordering() == requirement.actual_ordering()
                    && !requirement.rationale().is_empty()
            )
    );
}

#[test]
fn worker_ids_reject_zero_and_reserved_overflow() {
    assert_eq!(ParallelThunkWorkerId::FIRST.get(), 1);
    assert_eq!(
        ParallelThunkWorkerId::new(1),
        Some(ParallelThunkWorkerId::FIRST)
    );
    assert_eq!(ParallelThunkWorkerId::new(0), None);
    assert_eq!(
        ParallelThunkWorkerId::new(PARALLEL_THUNK_MAX_WORKER_ID).map(ParallelThunkWorkerId::get),
        Some(PARALLEL_THUNK_MAX_WORKER_ID)
    );
    assert_eq!(
        ParallelThunkWorkerId::new(PARALLEL_THUNK_MAX_WORKER_ID + 1),
        None
    );
}

#[test]
fn states_roundtrip_raw_words() {
    let owner = worker(7);
    let states = [
        ParallelThunkState::Suspended,
        ParallelThunkState::Pending { owner },
        ParallelThunkState::Awaited { owner },
        ParallelThunkState::Forced,
        ParallelThunkState::Failed,
    ];

    for state in states {
        assert_eq!(ParallelThunkState::from_raw(state.as_raw()), Ok(state));
    }

    assert_eq!(
        ParallelThunkState::from_raw(PENDING_TAG),
        Err(ParallelThunkStateError::InvalidStateWord { raw: PENDING_TAG })
    );
    assert_eq!(
        ParallelThunkState::from_raw(7),
        Err(ParallelThunkStateError::InvalidStateWord { raw: 7 })
    );
    assert_eq!(ParallelThunkState::Pending { owner }.owner(), Some(owner));
    assert_eq!(ParallelThunkState::Forced.owner(), None);
}

#[test]
fn suspended_thunk_claims_and_publishes_forced() {
    let state = ParallelThunkStateWord::new();
    let owner = worker(1);

    let ParallelThunkClaim::Claimed(guard) = state.try_claim(owner).expect("claim checks state")
    else {
        panic!("suspended thunk should be claimed");
    };

    assert_eq!(
        state.state(),
        Ok(ParallelThunkState::Pending {
            owner: guard.owner()
        })
    );

    let publish = guard.publish_forced().expect("publish succeeds");

    assert_eq!(publish.owner(), owner);
    assert_eq!(publish.terminal_state(), ParallelThunkTerminalState::Forced);
    assert!(!publish.had_waiters());
    assert_eq!(state.state(), Ok(ParallelThunkState::Forced));
    assert!(matches!(
        state.try_claim(worker(2)),
        Ok(ParallelThunkClaim::AlreadyForced)
    ));
}

#[test]
fn concurrent_claim_has_single_winner() {
    const WORKERS: usize = 8;

    let state = Arc::new(ParallelThunkStateWord::new());
    let start = Arc::new(Barrier::new(WORKERS));
    let finish = Arc::new(Barrier::new(WORKERS));
    let outcomes = Arc::new(Mutex::new(Vec::with_capacity(WORKERS)));
    let mut handles = Vec::with_capacity(WORKERS);

    for raw_worker in 1..=WORKERS as u64 {
        let state = Arc::clone(&state);
        let start = Arc::clone(&start);
        let finish = Arc::clone(&finish);
        let outcomes = Arc::clone(&outcomes);
        handles.push(thread::spawn(move || {
            let worker = worker(raw_worker);
            start.wait();

            match state.try_claim(worker).expect("claim checks state") {
                ParallelThunkClaim::Claimed(guard) => {
                    outcomes.lock().expect("outcomes lock").push("claimed");
                    finish.wait();
                    guard.publish_forced().expect("winner publishes");
                }
                ParallelThunkClaim::ForeignPending { .. } => {
                    outcomes.lock().expect("outcomes lock").push("foreign");
                    finish.wait();
                }
                other => {
                    panic!("unexpected claim result in contention test: {other:?}");
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("worker joins");
    }

    let outcomes = outcomes.lock().expect("outcomes lock");
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == "claimed")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == "foreign")
            .count(),
        WORKERS - 1
    );
    assert_eq!(state.state(), Ok(ParallelThunkState::Forced));
}

#[test]
fn awaited_marks_foreign_pending_and_reports_waiters_on_publish() {
    let state = ParallelThunkStateWord::new();
    let owner = worker(1);
    let waiter = worker(2);
    let second_waiter = worker(3);

    let ParallelThunkClaim::Claimed(guard) = state.try_claim(owner).expect("claim checks state")
    else {
        panic!("suspended thunk should be claimed");
    };

    assert_eq!(
        state.mark_awaited(owner),
        Ok(ParallelThunkAwait::SelfCycle { owner })
    );
    assert_eq!(
        state.mark_awaited(waiter),
        Ok(ParallelThunkAwait::Awaited {
            owner,
            newly_marked: true,
        })
    );
    assert_eq!(state.state(), Ok(ParallelThunkState::Awaited { owner }));
    assert_eq!(
        state.mark_awaited(second_waiter),
        Ok(ParallelThunkAwait::Awaited {
            owner,
            newly_marked: false,
        })
    );

    let publish = guard.publish_forced().expect("publish succeeds");

    assert!(publish.had_waiters());
    assert_eq!(state.state(), Ok(ParallelThunkState::Forced));
}

#[test]
fn failed_state_is_terminal_for_claim_and_await() {
    let state = ParallelThunkStateWord::new();
    let owner = worker(1);

    let ParallelThunkClaim::Claimed(guard) = state.try_claim(owner).expect("claim checks state")
    else {
        panic!("suspended thunk should be claimed");
    };

    let publish = guard.publish_failed().expect("publish succeeds");

    assert_eq!(publish.terminal_state(), ParallelThunkTerminalState::Failed);
    assert_eq!(state.state(), Ok(ParallelThunkState::Failed));
    assert!(matches!(
        state.try_claim(worker(2)),
        Ok(ParallelThunkClaim::AlreadyFailed)
    ));
    assert_eq!(
        state.mark_awaited(worker(2)),
        Ok(ParallelThunkAwait::AlreadyFailed)
    );
}

#[test]
fn dropped_claim_publishes_failed_to_avoid_stuck_pending() {
    let state = ParallelThunkStateWord::new();
    let owner = worker(1);

    {
        let ParallelThunkClaim::Claimed(_guard) =
            state.try_claim(owner).expect("claim checks state")
        else {
            panic!("suspended thunk should be claimed");
        };
        assert_eq!(state.state(), Ok(ParallelThunkState::Pending { owner }));
    }

    assert_eq!(state.state(), Ok(ParallelThunkState::Failed));
}

#[test]
fn dropped_claim_publishes_failed_from_awaited_state() {
    let state = ParallelThunkStateWord::new();
    let owner = worker(1);
    let waiter = worker(2);

    {
        let ParallelThunkClaim::Claimed(_guard) =
            state.try_claim(owner).expect("claim checks state")
        else {
            panic!("suspended thunk should be claimed");
        };
        assert_eq!(
            state.mark_awaited(waiter),
            Ok(ParallelThunkAwait::Awaited {
                owner,
                newly_marked: true,
            })
        );
        assert_eq!(state.state(), Ok(ParallelThunkState::Awaited { owner }));
    }

    assert_eq!(state.state(), Ok(ParallelThunkState::Failed));
}

#[test]
fn acquire_load_observes_payload_written_before_release_publish() {
    let state = Arc::new(ParallelThunkStateWord::new());
    let payload = Arc::new(AtomicUsize::new(0));
    let owner_ready = Arc::new(Barrier::new(2));
    let owner = worker(1);

    let owner_thread = {
        let state = Arc::clone(&state);
        let payload = Arc::clone(&payload);
        let owner_ready = Arc::clone(&owner_ready);
        thread::spawn(move || {
            let ParallelThunkClaim::Claimed(guard) =
                state.try_claim(owner).expect("claim checks state")
            else {
                panic!("suspended thunk should be claimed");
            };

            owner_ready.wait();
            payload.store(55, AtomicOrdering::Relaxed);
            guard.publish_forced().expect("publish succeeds");
        })
    };

    owner_ready.wait();
    let observed = loop {
        if state.state().expect("state decodes") == ParallelThunkState::Forced {
            break payload.load(AtomicOrdering::Relaxed);
        }
        thread::yield_now();
    };

    owner_thread.join().expect("owner joins");
    assert_eq!(observed, 55);
}

#[test]
fn publish_from_wrong_owner_fails_without_changing_state() {
    let state = ParallelThunkStateWord::new();
    let owner = worker(1);
    let wrong_owner = worker(2);

    let ParallelThunkClaim::Claimed(guard) = state.try_claim(owner).expect("claim checks state")
    else {
        panic!("suspended thunk should be claimed");
    };

    assert_eq!(
        state.publish_forced(wrong_owner),
        Err(ParallelThunkStateError::UnexpectedState {
            expected_owner: wrong_owner,
            actual: ParallelThunkState::Pending { owner },
        })
    );
    assert_eq!(state.state(), Ok(ParallelThunkState::Pending { owner }));

    guard.publish_forced().expect("real owner publishes");
}
