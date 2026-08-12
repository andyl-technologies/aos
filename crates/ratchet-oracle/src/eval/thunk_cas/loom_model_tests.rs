//! Loom model checks for the parallel thunk claim/await/publish protocol.

use std::sync::{
    Arc as StdArc,
    atomic::{AtomicBool, Ordering as StdOrdering},
};

use loom::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering as LoomOrdering},
    },
    thread,
};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoomClaim {
    Claimed,
    AlreadyForced,
    AlreadyFailed,
    SelfCycle,
    Foreign,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoomAwait {
    AlreadyForced,
    AlreadyFailed,
    SelfCycle,
    Awaited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoomForceError {
    Failed(u64),
    SelfCycle,
}

#[derive(Debug, Default)]
struct LoomWaiters {
    wait_registrations: usize,
    notifications: usize,
}

/// A minimal loom-only model of the RFC-0007 L2 thunk protocol.
///
/// The model deliberately mirrors the production state-word encoding and
/// ordering constants while keeping the terminal payloads as relaxed side
/// slots. Any reader that observes `Forced` or `Failed` must rely on the
/// state acquire load to see the relaxed payload write that happened before
/// the owner's release publish.
struct LoomThunk {
    state: AtomicU64,
    waiters: Mutex<LoomWaiters>,
    terminal_ready: Condvar,
    forced_payload: AtomicU64,
    failed_payload: AtomicU64,
    body_runs: AtomicUsize,
}

impl LoomThunk {
    fn new() -> Self {
        Self {
            state: AtomicU64::new(SUSPENDED_TAG),
            waiters: Mutex::new(LoomWaiters::default()),
            terminal_ready: Condvar::new(),
            forced_payload: AtomicU64::new(0),
            failed_payload: AtomicU64::new(0),
            body_runs: AtomicUsize::new(0),
        }
    }

    fn state(&self) -> ParallelThunkState {
        ParallelThunkState::from_raw(self.state.load(PARALLEL_THUNK_STATE_LOAD_ORDERING))
            .expect("loom model never observes torn or invalid state words")
    }

    fn try_claim(&self, worker: ParallelThunkWorkerId) -> LoomClaim {
        loop {
            match self.state() {
                ParallelThunkState::Suspended => {
                    let pending = ParallelThunkState::Pending { owner: worker }.as_raw();
                    if self
                        .state
                        .compare_exchange(
                            SUSPENDED_TAG,
                            pending,
                            PARALLEL_THUNK_CLAIM_SUCCESS_ORDERING,
                            PARALLEL_THUNK_CLAIM_FAILURE_ORDERING,
                        )
                        .is_ok()
                    {
                        return LoomClaim::Claimed;
                    }
                }
                ParallelThunkState::Pending { owner } | ParallelThunkState::Awaited { owner }
                    if owner == worker =>
                {
                    return LoomClaim::SelfCycle;
                }
                ParallelThunkState::Pending { .. } | ParallelThunkState::Awaited { .. } => {
                    return LoomClaim::Foreign;
                }
                ParallelThunkState::Forced => return LoomClaim::AlreadyForced,
                ParallelThunkState::Failed => return LoomClaim::AlreadyFailed,
            }
        }
    }

    fn mark_awaited(&self, waiter: ParallelThunkWorkerId) -> LoomAwait {
        loop {
            match self.state() {
                ParallelThunkState::Suspended => {
                    panic!("foreign waiter saw an unclaimed thunk")
                }
                ParallelThunkState::Pending { owner } if owner == waiter => {
                    return LoomAwait::SelfCycle;
                }
                ParallelThunkState::Pending { owner } => {
                    let pending = ParallelThunkState::Pending { owner }.as_raw();
                    let awaited = ParallelThunkState::Awaited { owner }.as_raw();
                    if self
                        .state
                        .compare_exchange(
                            pending,
                            awaited,
                            PARALLEL_THUNK_AWAIT_MARK_SUCCESS_ORDERING,
                            PARALLEL_THUNK_AWAIT_MARK_FAILURE_ORDERING,
                        )
                        .is_ok()
                    {
                        return LoomAwait::Awaited;
                    }
                }
                ParallelThunkState::Awaited { owner } if owner == waiter => {
                    return LoomAwait::SelfCycle;
                }
                ParallelThunkState::Awaited { .. } => return LoomAwait::Awaited,
                ParallelThunkState::Forced => return LoomAwait::AlreadyForced,
                ParallelThunkState::Failed => return LoomAwait::AlreadyFailed,
            }
        }
    }

    fn force_success(
        &self,
        worker: ParallelThunkWorkerId,
        value: u64,
    ) -> Result<u64, LoomForceError> {
        match self.try_claim(worker) {
            LoomClaim::Claimed => {
                self.run_body_once();
                self.write_forced_payload(value);
                self.publish_terminal(worker, ParallelThunkTerminalState::Forced);
                Ok(value)
            }
            LoomClaim::AlreadyForced => Ok(self.read_forced_payload()),
            LoomClaim::AlreadyFailed => Err(LoomForceError::Failed(self.read_failed_payload())),
            LoomClaim::SelfCycle => Err(LoomForceError::SelfCycle),
            LoomClaim::Foreign => self.wait_for_terminal(worker),
        }
    }

    fn force_failure(
        &self,
        worker: ParallelThunkWorkerId,
        error: u64,
    ) -> Result<u64, LoomForceError> {
        match self.try_claim(worker) {
            LoomClaim::Claimed => {
                self.run_body_once();
                self.write_failed_payload(error);
                self.publish_terminal(worker, ParallelThunkTerminalState::Failed);
                Err(LoomForceError::Failed(error))
            }
            LoomClaim::AlreadyForced => Ok(self.read_forced_payload()),
            LoomClaim::AlreadyFailed => Err(LoomForceError::Failed(self.read_failed_payload())),
            LoomClaim::SelfCycle => Err(LoomForceError::SelfCycle),
            LoomClaim::Foreign => self.wait_for_terminal(worker),
        }
    }

    fn wait_for_terminal(&self, worker: ParallelThunkWorkerId) -> Result<u64, LoomForceError> {
        let mut waiters = self.waiters.lock().expect("waiter mutex is not poisoned");
        match self.mark_awaited(worker) {
            LoomAwait::AlreadyForced => Ok(self.read_forced_payload()),
            LoomAwait::AlreadyFailed => Err(LoomForceError::Failed(self.read_failed_payload())),
            LoomAwait::SelfCycle => Err(LoomForceError::SelfCycle),
            LoomAwait::Awaited => {
                waiters.wait_registrations = waiters.wait_registrations.saturating_add(1);
                loop {
                    match self.state() {
                        ParallelThunkState::Forced => return Ok(self.read_forced_payload()),
                        ParallelThunkState::Failed => {
                            return Err(LoomForceError::Failed(self.read_failed_payload()));
                        }
                        ParallelThunkState::Pending { owner }
                        | ParallelThunkState::Awaited { owner }
                            if owner == worker =>
                        {
                            return Err(LoomForceError::SelfCycle);
                        }
                        ParallelThunkState::Pending { .. } | ParallelThunkState::Awaited { .. } => {
                            waiters = self
                                .terminal_ready
                                .wait(waiters)
                                .expect("waiter mutex is not poisoned");
                        }
                        ParallelThunkState::Suspended => {
                            panic!("waiter observed suspended after marking awaited")
                        }
                    }
                }
            }
        }
    }

    fn publish_success(&self, owner: ParallelThunkWorkerId, value: u64) {
        self.write_forced_payload(value);
        self.publish_terminal(owner, ParallelThunkTerminalState::Forced);
    }

    fn publish_failure(&self, owner: ParallelThunkWorkerId, error: u64) {
        self.write_failed_payload(error);
        self.publish_terminal(owner, ParallelThunkTerminalState::Failed);
    }

    fn publish_terminal(
        &self,
        owner: ParallelThunkWorkerId,
        terminal_state: ParallelThunkTerminalState,
    ) {
        loop {
            let actual = self.state();
            let had_waiters = match actual {
                ParallelThunkState::Pending {
                    owner: actual_owner,
                } if actual_owner == owner => false,
                ParallelThunkState::Awaited {
                    owner: actual_owner,
                } if actual_owner == owner => true,
                _ => panic!("owner attempted to publish from unexpected state: {actual:?}"),
            };

            if self
                .state
                .compare_exchange(
                    actual.as_raw(),
                    terminal_state.as_state().as_raw(),
                    PARALLEL_THUNK_TERMINAL_PUBLISH_SUCCESS_ORDERING,
                    PARALLEL_THUNK_TERMINAL_PUBLISH_FAILURE_ORDERING,
                )
                .is_ok()
            {
                if had_waiters {
                    let mut waiters = self.waiters.lock().expect("waiter mutex is not poisoned");
                    waiters.notifications = waiters.notifications.saturating_add(1);
                    self.terminal_ready.notify_all();
                }
                return;
            }
        }
    }

    fn run_body_once(&self) {
        let previous = self.body_runs.fetch_add(1, LoomOrdering::SeqCst);
        assert_eq!(previous, 0, "loom model ran the thunk body more than once");
    }

    fn body_runs(&self) -> usize {
        self.body_runs.load(LoomOrdering::SeqCst)
    }

    fn waiter_stats(&self) -> (usize, usize) {
        let waiters = self.waiters.lock().expect("waiter mutex is not poisoned");
        (waiters.wait_registrations, waiters.notifications)
    }

    fn write_forced_payload(&self, value: u64) {
        assert_ne!(value, 0, "zero is the uninitialized payload sentinel");
        self.forced_payload.store(value, LoomOrdering::Relaxed);
    }

    fn read_forced_payload(&self) -> u64 {
        let value = self.forced_payload.load(LoomOrdering::Relaxed);
        assert_ne!(value, 0, "forced state exposed an uninitialized payload");
        value
    }

    fn write_failed_payload(&self, error: u64) {
        assert_ne!(error, 0, "zero is the uninitialized error sentinel");
        self.failed_payload.store(error, LoomOrdering::Relaxed);
    }

    fn read_failed_payload(&self) -> u64 {
        let error = self.failed_payload.load(LoomOrdering::Relaxed);
        assert_ne!(error, 0, "failed state exposed an uninitialized payload");
        error
    }
}

fn worker(raw: u64) -> ParallelThunkWorkerId {
    ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
}

fn bounded_three_worker_claimant_model() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.max_permutations = Some(2048);
    builder.checkpoint_interval = 1;
    builder
}

fn exhaustive_three_worker_waiter_model() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.preemption_bound = None;
    builder.checkpoint_file = None;
    builder
}

fn assert_waiters_were_not_stranded(thunk: &LoomThunk) {
    let (registrations, notifications) = thunk.waiter_stats();
    if registrations > 0 {
        assert!(
            notifications > 0,
            "waiter registered but no terminal wakeup notification was observed"
        );
    }
}

fn record_waiter_coverage(thunk: &LoomThunk, observed_waiter: &AtomicBool) {
    if thunk.waiter_stats().0 > 0 {
        observed_waiter.store(true, StdOrdering::Relaxed);
    }
}

fn assert_combined_model_exercised_waiter_path(observed_waiter: &AtomicBool) {
    assert!(
        observed_waiter.load(StdOrdering::Relaxed),
        "bounded three-worker force model did not exercise a waiter/replay path"
    );
}

fn wait_until_waiter_registered(thunk: &LoomThunk) {
    while thunk.waiter_stats().0 == 0 {
        thread::yield_now();
    }
}

#[test]
fn loom_two_racing_workers_force_once_and_replay_published_value() {
    loom::model(|| {
        let thunk = Arc::new(LoomThunk::new());
        let first = {
            let thunk = Arc::clone(&thunk);
            thread::spawn(move || thunk.force_success(worker(1), 11))
        };
        let second = {
            let thunk = Arc::clone(&thunk);
            thread::spawn(move || thunk.force_success(worker(2), 22))
        };

        let first = first.join().expect("first worker joins");
        let second = second.join().expect("second worker joins");

        assert!(first.is_ok());
        assert_eq!(first, second);
        assert!(matches!(first, Ok(11 | 22)));
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Forced);
        assert_waiters_were_not_stranded(&thunk);
    });
}

/// Models the Chunk C single-entry CAS bypass (S7).
///
/// A single-entry thunk carries a plain cell: no blackhole CAS, no
/// update write-back, no parallel payload cell. Its safety argument is
/// that every cross-thread path to it flows through an enclosing update
/// thunk's claim protocol — the enclosing CAS cell's release publish
/// happens-after the single force's relaxed reads and writes, so exactly
/// one worker ever enters the plain cell and every other worker replays
/// the enclosing published value without touching it.
#[test]
fn loom_single_entry_plain_cell_behind_enclosing_claim_runs_once() {
    loom::model(|| {
        let enclosing = Arc::new(LoomThunk::new());
        // The single-entry thunk: a captured payload and an entry
        // counter with no ordering of their own (Relaxed everywhere).
        let captured = Arc::new(AtomicU64::new(77));
        let entries = Arc::new(AtomicUsize::new(0));

        let spawn_worker = |id: u64| {
            let enclosing = Arc::clone(&enclosing);
            let captured = Arc::clone(&captured);
            let entries = Arc::clone(&entries);
            thread::spawn(move || {
                // Forcing the enclosing thunk runs its body at most once;
                // the body is the only reader of the single-entry cell.
                let winner_value = captured.load(LoomOrdering::Relaxed);
                match enclosing.try_claim(worker(id)) {
                    LoomClaim::Claimed => {
                        // Single-entry force: plain relaxed entry, no CAS.
                        entries.fetch_add(1, LoomOrdering::Relaxed);
                        enclosing.write_forced_payload(winner_value);
                        enclosing.publish_terminal(worker(id), ParallelThunkTerminalState::Forced);
                        Ok(winner_value)
                    }
                    LoomClaim::AlreadyForced => Ok(enclosing.read_forced_payload()),
                    LoomClaim::Foreign => enclosing.wait_for_terminal(worker(id)),
                    other => panic!("unexpected claim outcome {other:?}"),
                }
            })
        };

        let first = spawn_worker(1);
        let second = spawn_worker(2);
        let first = first.join().expect("first worker joins");
        let second = second.join().expect("second worker joins");

        assert_eq!(first, Ok(77));
        assert_eq!(second, Ok(77));
        assert_eq!(
            entries.load(LoomOrdering::Relaxed),
            1,
            "the plain single-entry cell must be entered exactly once"
        );
        assert_eq!(enclosing.state(), ParallelThunkState::Forced);
        assert_waiters_were_not_stranded(&enclosing);
    });
}

#[test]
fn loom_bounded_three_racing_claimants_have_one_body_owner() {
    let builder = bounded_three_worker_claimant_model();
    builder.check(|| {
        let thunk = Arc::new(LoomThunk::new());
        let mut handles = Vec::new();

        for raw_worker in 1..=3 {
            let thunk = Arc::clone(&thunk);
            handles.push(thread::spawn(move || {
                match thunk.try_claim(worker(raw_worker)) {
                    LoomClaim::Claimed => {
                        thunk.run_body_once();
                        thunk.publish_success(worker(raw_worker), raw_worker * 10);
                        true
                    }
                    LoomClaim::AlreadyForced | LoomClaim::Foreign => false,
                    unexpected => panic!("unexpected 3-worker claim outcome: {unexpected:?}"),
                }
            }));
        }

        let mut claimed = 0;
        for handle in handles {
            if handle.join().expect("worker joins") {
                claimed += 1;
            }
        }

        assert_eq!(claimed, 1);
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Forced);
        assert!(matches!(thunk.read_forced_payload(), 10 | 20 | 30));
    });
}

#[test]
fn loom_bounded_three_racing_workers_force_once_and_replay_published_value() {
    let builder = bounded_three_worker_claimant_model();
    let observed_waiter = StdArc::new(AtomicBool::new(false));
    let observed_waiter_for_model = StdArc::clone(&observed_waiter);
    builder.check(move || {
        let thunk = Arc::new(LoomThunk::new());
        let mut handles = Vec::new();

        for raw_worker in 1..=3 {
            let thunk = Arc::clone(&thunk);
            handles.push(thread::spawn(move || {
                thunk.force_success(worker(raw_worker), raw_worker * 10)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().expect("worker joins"));
        }

        let winner = results[0];
        assert!(results.iter().all(|result| *result == winner));
        assert!(matches!(winner, Ok(10 | 20 | 30)));
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Forced);
        assert_waiters_were_not_stranded(&thunk);
        record_waiter_coverage(&thunk, &observed_waiter_for_model);
    });
    assert_combined_model_exercised_waiter_path(&observed_waiter);
}

#[test]
fn loom_bounded_three_racing_workers_replay_one_failed_payload() {
    let builder = bounded_three_worker_claimant_model();
    let observed_waiter = StdArc::new(AtomicBool::new(false));
    let observed_waiter_for_model = StdArc::clone(&observed_waiter);
    builder.check(move || {
        let thunk = Arc::new(LoomThunk::new());
        let mut handles = Vec::new();

        for raw_worker in 1..=3 {
            let thunk = Arc::clone(&thunk);
            handles.push(thread::spawn(move || {
                thunk.force_failure(worker(raw_worker), raw_worker * 100)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().expect("worker joins"));
        }

        let winner = results[0];
        assert!(results.iter().all(|result| *result == winner));
        assert!(matches!(
            winner,
            Err(LoomForceError::Failed(100 | 200 | 300))
        ));
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Failed);
        assert_waiters_were_not_stranded(&thunk);
        record_waiter_coverage(&thunk, &observed_waiter_for_model);
    });
    assert_combined_model_exercised_waiter_path(&observed_waiter);
}

#[test]
fn loom_three_workers_replay_one_published_value_after_waiter_registration() {
    let builder = exhaustive_three_worker_waiter_model();
    builder.check(|| {
        let thunk = Arc::new(LoomThunk::new());
        assert_eq!(thunk.try_claim(worker(1)), LoomClaim::Claimed);
        thunk.run_body_once();

        let mut handles = Vec::new();
        for raw_worker in 2..=3 {
            let thunk = Arc::clone(&thunk);
            handles.push(thread::spawn(move || {
                thunk.force_success(worker(raw_worker), raw_worker * 10)
            }));
        }
        wait_until_waiter_registered(&thunk);
        thunk.publish_success(worker(1), 10);

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().expect("worker joins"));
        }

        assert!(results.iter().all(Result::is_ok));
        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(results[0], Ok(10));
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Forced);
        assert!(thunk.waiter_stats().0 > 0);
        assert_waiters_were_not_stranded(&thunk);
    });
}

#[test]
fn loom_three_workers_replay_one_failed_payload_after_waiter_registration() {
    let builder = exhaustive_three_worker_waiter_model();
    builder.check(|| {
        let thunk = Arc::new(LoomThunk::new());
        assert_eq!(thunk.try_claim(worker(1)), LoomClaim::Claimed);
        thunk.run_body_once();

        let mut handles = Vec::new();
        for raw_worker in 2..=3 {
            let thunk = Arc::clone(&thunk);
            handles.push(thread::spawn(move || {
                thunk.force_failure(worker(raw_worker), raw_worker * 100)
            }));
        }
        wait_until_waiter_registered(&thunk);
        thunk.publish_failure(worker(1), 100);

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().expect("worker joins"));
        }

        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(results[0], Err(LoomForceError::Failed(100)));
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Failed);
        assert!(thunk.waiter_stats().0 > 0);
        assert_waiters_were_not_stranded(&thunk);
    });
}

#[test]
fn loom_same_worker_reentry_reports_cycle_without_body_run() {
    loom::model(|| {
        let thunk = LoomThunk::new();
        assert_eq!(thunk.try_claim(worker(1)), LoomClaim::Claimed);

        let recursive = thunk.force_success(worker(1), 99);

        assert_eq!(recursive, Err(LoomForceError::SelfCycle));
        assert_eq!(thunk.body_runs(), 0);
        thunk.publish_success(worker(1), 7);
        assert_eq!(thunk.force_success(worker(2), 22), Ok(7));
        assert_eq!(thunk.body_runs(), 0);
        assert_eq!(thunk.state(), ParallelThunkState::Forced);
    });
}

#[test]
fn loom_failed_terminal_state_wakes_and_replays_to_waiters() {
    loom::model(|| {
        let thunk = Arc::new(LoomThunk::new());
        let first = {
            let thunk = Arc::clone(&thunk);
            thread::spawn(move || thunk.force_failure(worker(1), 101))
        };
        let second = {
            let thunk = Arc::clone(&thunk);
            thread::spawn(move || thunk.force_failure(worker(2), 202))
        };

        let first = first.join().expect("first worker joins");
        let second = second.join().expect("second worker joins");

        assert!(matches!(first, Err(LoomForceError::Failed(101 | 202))));
        assert_eq!(first, second);
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Failed);
        assert_waiters_were_not_stranded(&thunk);
    });
}

#[test]
fn loom_already_failed_replays_same_captured_payload() {
    loom::model(|| {
        let thunk = LoomThunk::new();

        assert_eq!(
            thunk.force_failure(worker(1), 303),
            Err(LoomForceError::Failed(303))
        );
        assert_eq!(
            thunk.force_failure(worker(2), 404),
            Err(LoomForceError::Failed(303))
        );
        assert_eq!(
            thunk.force_success(worker(3), 505),
            Err(LoomForceError::Failed(303))
        );
        assert_eq!(thunk.body_runs(), 1);
        assert_eq!(thunk.state(), ParallelThunkState::Failed);
    });
}
