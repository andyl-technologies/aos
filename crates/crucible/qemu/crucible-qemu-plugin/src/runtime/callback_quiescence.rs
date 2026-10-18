//! Process-wide admission control for live QEMU callbacks.
//!
//! Every production callback takes a short in-flight token before touching
//! callback-owned or shared-memory state. Teardown closes admission permanently;
//! the hot-fork coordinator can independently hold and release a reversible
//! admission barrier. Sequentially consistent operations make either close
//! versus enter race explicit and keep the proof independent of host time.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const TEARDOWN_CLOSED: u64 = 1_u64 << 63;
const HOT_FORK_HELD: u64 = 1_u64 << 62;
const PARENT_PARK_OWNED: u64 = 1_u64 << 61;
const CLOSED_MASK: u64 = TEARDOWN_CLOSED | HOT_FORK_HELD | PARENT_PARK_OWNED;
const IN_FLIGHT_MASK: u64 = !CLOSED_MASK;

/// One instantaneous view of callback admission and in-flight work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiveCallbackQuiescenceSnapshot {
    pub(crate) hot_fork_held: bool,
    pub(crate) teardown_closed: bool,
    pub(crate) in_flight: u64,
}

impl LiveCallbackQuiescenceSnapshot {
    #[cfg(test)]
    pub(crate) const fn hot_fork_quiescent(self) -> bool {
        self.hot_fork_held && !self.teardown_closed && self.in_flight == 0
    }
}

/// Shared callback admission and in-flight accounting state.
#[derive(Debug, Default)]
pub(crate) struct LiveCallbackQuiescence {
    state: AtomicU64,
}

impl LiveCallbackQuiescence {
    /// Creates an open callback admission gate.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    /// Admits one callback unless teardown or a reversible hot-fork hold closed the gate.
    pub(crate) fn enter(&self) -> Option<LiveCallbackInFlight<'_>> {
        self.enter_with_rejection(|_| {})
    }

    /// Reports the exact rejecting admission observation to an observational hook.
    pub(crate) fn enter_with_rejection(
        &self,
        rejected: impl FnOnce(LiveCallbackQuiescenceSnapshot),
    ) -> Option<LiveCallbackInFlight<'_>> {
        self.enter_with_hooks(|| {}, rejected)
    }

    /// Prevents every later callback from beginning work.
    pub(crate) fn close(&self) {
        self.state.fetch_or(TEARDOWN_CLOSED, Ordering::SeqCst);
    }

    /// Holds the reversible hot-fork callback-admission barrier.
    pub(crate) fn hold_hot_fork(&self) -> LiveCallbackQuiescenceSnapshot {
        self.state.fetch_or(HOT_FORK_HELD, Ordering::SeqCst);
        self.snapshot()
    }

    /// Releases only the reversible hot-fork admission barrier.
    pub(crate) fn release_hot_fork(&self) -> LiveCallbackQuiescenceSnapshot {
        let mut observed = self.state.load(Ordering::SeqCst);
        while observed & PARENT_PARK_OWNED == 0 {
            match self.state.compare_exchange(
                observed,
                observed & !HOT_FORK_HELD,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => observed = actual,
            }
        }
        self.snapshot()
    }

    /// Reserves an exclusive callback hold for the retained parent owner.
    ///
    /// The token has no release-on-drop behavior. Losing it preserves the closed
    /// admission gate; only the same owner can explicitly relinquish it.
    pub(super) fn reserve_parent_hold(self: &Arc<Self>) -> Option<ParentCallbackHold> {
        self.reserve_parent_hold_after_snapshot(|| {})
    }

    fn reserve_parent_hold_after_snapshot(
        self: &Arc<Self>,
        after_snapshot: impl FnOnce(),
    ) -> Option<ParentCallbackHold> {
        let observed = self.state.load(Ordering::SeqCst);
        after_snapshot();
        if observed & (PARENT_PARK_OWNED | TEARDOWN_CLOSED) != 0 {
            return None;
        }
        self.state
            .compare_exchange(
                observed,
                observed | PARENT_PARK_OWNED | HOT_FORK_HELD,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .ok()?;
        Some(ParentCallbackHold {
            gate: Arc::clone(self),
        })
    }

    pub(super) fn parent_hold_owned(&self) -> bool {
        self.state.load(Ordering::SeqCst) & PARENT_PARK_OWNED != 0
    }

    /// Returns one instantaneous callback-admission view.
    pub(crate) fn snapshot(&self) -> LiveCallbackQuiescenceSnapshot {
        let state = self.state.load(Ordering::SeqCst);
        LiveCallbackQuiescenceSnapshot {
            hot_fork_held: state & HOT_FORK_HELD != 0,
            teardown_closed: state & TEARDOWN_CLOSED != 0,
            in_flight: state & IN_FLIGHT_MASK,
        }
    }

    /// Waits causally until every callback admitted before close has returned.
    pub(crate) fn wait_until_drained(&self) {
        while self.state.load(Ordering::SeqCst) & IN_FLIGHT_MASK != 0 {
            std::thread::yield_now();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_closed(&self) -> bool {
        self.state.load(Ordering::SeqCst) & CLOSED_MASK != 0
    }

    #[cfg(test)]
    fn enter_with_hook(
        &self,
        after_initial_load: impl FnOnce(),
    ) -> Option<LiveCallbackInFlight<'_>> {
        self.enter_with_hooks(after_initial_load, |_| {})
    }

    fn enter_with_hooks(
        &self,
        after_initial_load: impl FnOnce(),
        rejected: impl FnOnce(LiveCallbackQuiescenceSnapshot),
    ) -> Option<LiveCallbackInFlight<'_>> {
        let mut observed = self.state.load(Ordering::SeqCst);
        after_initial_load();
        loop {
            if observed & CLOSED_MASK != 0 {
                rejected(LiveCallbackQuiescenceSnapshot {
                    hot_fork_held: observed & HOT_FORK_HELD != 0,
                    teardown_closed: observed & TEARDOWN_CLOSED != 0,
                    in_flight: observed & IN_FLIGHT_MASK,
                });
                return None;
            }
            let count = observed & IN_FLIGHT_MASK;
            let Some(next_count) = count.checked_add(1) else {
                std::process::abort();
            };
            if next_count > IN_FLIGHT_MASK {
                std::process::abort();
            }
            match self.state.compare_exchange(
                observed,
                next_count,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_previous) => {
                    return Some(LiveCallbackInFlight { quiescence: self });
                }
                Err(actual) => observed = actual,
            }
        }
    }
}

/// Noncopying exclusive admission hold retained by the parent park owner.
pub(super) struct ParentCallbackHold {
    gate: Arc<LiveCallbackQuiescence>,
}

impl ParentCallbackHold {
    pub(super) fn snapshot(&self) -> LiveCallbackQuiescenceSnapshot {
        self.gate.snapshot()
    }

    /// Relinquishes this hold after the owning runtime has closed its drain scope.
    pub(super) fn relinquish(self) {
        self.gate
            .state
            .fetch_and(!(PARENT_PARK_OWNED | HOT_FORK_HELD), Ordering::SeqCst);
    }
}

/// RAII proof that one callback is included in teardown's drain count.
///
/// The callback's existing owner keeps the gate alive until this borrow ends.
/// Admission therefore needs no reference-count operations on the hot path.
pub(crate) struct LiveCallbackInFlight<'a> {
    quiescence: &'a LiveCallbackQuiescence,
}

impl Drop for LiveCallbackInFlight<'_> {
    fn drop(&mut self) {
        let previous = self.quiescence.state.fetch_sub(1, Ordering::SeqCst);
        if previous & IN_FLIGHT_MASK == 0 {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn parent_hold_single_attempt_refuses_actual_callback_admission_race() {
        let gate = Arc::new(LiveCallbackQuiescence::new());
        let mut callback = None;
        let held = gate.reserve_parent_hold_after_snapshot(|| {
            callback = gate.enter();
        });
        assert!(held.is_none());
        assert!(!gate.parent_hold_owned());
        assert!(!gate.snapshot().hot_fork_held);
        assert_eq!(gate.snapshot().in_flight, 1);
        drop(callback);
        assert_eq!(gate.snapshot().in_flight, 0);
    }

    #[test]
    fn parent_hold_blocks_legacy_release_and_second_owner() {
        let gate = Arc::new(LiveCallbackQuiescence::new());
        let hold = gate
            .reserve_parent_hold()
            .unwrap_or_else(|| panic!("exclusive hold"));

        assert!(gate.release_hot_fork().hot_fork_held);
        assert!(gate.enter().is_none());
        assert!(gate.reserve_parent_hold().is_none());
        assert_eq!(hold.snapshot().in_flight, 0);

        hold.relinquish();
        assert!(!gate.parent_hold_owned());
        assert!(gate.enter().is_some());
    }

    #[test]
    fn lost_parent_hold_keeps_gate_closed_and_prior_callback_counted() {
        let gate = Arc::new(LiveCallbackQuiescence::new());
        let callback = gate.enter().unwrap_or_else(|| panic!("open callback"));
        let hold = gate
            .reserve_parent_hold()
            .unwrap_or_else(|| panic!("exclusive hold"));
        assert_eq!(hold.snapshot().in_flight, 1);

        drop(hold);
        drop(callback);

        assert_eq!(gate.snapshot().in_flight, 0);
        assert!(gate.release_hot_fork().hot_fork_held);
        assert!(gate.enter().is_none());
    }

    #[test]
    fn close_rejects_new_callbacks_and_drain_waits_for_prior_guard() {
        let quiescence = Arc::new(LiveCallbackQuiescence::new());
        let guard = quiescence
            .enter()
            .unwrap_or_else(|| panic!("open gate should admit callback"));
        quiescence.close();
        assert!(quiescence.is_closed());
        assert!(quiescence.enter().is_none());

        let waiter = Arc::clone(&quiescence);
        let joined = std::thread::spawn(move || waiter.wait_until_drained());
        assert!(!joined.is_finished());
        drop(guard);
        joined
            .join()
            .unwrap_or_else(|_panic| panic!("drain waiter should finish"));
    }

    #[test]
    fn close_between_admission_load_and_cas_rejects_the_late_entry() {
        let quiescence = Arc::new(LiveCallbackQuiescence::new());
        let loaded = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let callback_quiescence = Arc::clone(&quiescence);
        let callback_loaded = Arc::clone(&loaded);
        let callback_resume = Arc::clone(&resume);
        let callback = std::thread::spawn(move || {
            callback_quiescence
                .enter_with_hook(|| {
                    callback_loaded.wait();
                    callback_resume.wait();
                })
                .is_none()
        });

        loaded.wait();
        quiescence.close();
        quiescence.wait_until_drained();
        resume.wait();

        let rejected = callback
            .join()
            .unwrap_or_else(|_panic| panic!("callback admission thread should finish"));
        assert!(rejected);
        assert!(quiescence.is_closed());
    }

    #[test]
    fn hot_fork_hold_between_admission_load_and_cas_rejects_the_late_entry() {
        let quiescence = Arc::new(LiveCallbackQuiescence::new());
        let loaded = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let callback_quiescence = Arc::clone(&quiescence);
        let callback_loaded = Arc::clone(&loaded);
        let callback_resume = Arc::clone(&resume);
        let callback = std::thread::spawn(move || {
            callback_quiescence
                .enter_with_hook(|| {
                    callback_loaded.wait();
                    callback_resume.wait();
                })
                .is_none()
        });

        loaded.wait();
        let held = quiescence.hold_hot_fork();
        assert!(held.hot_fork_held);
        assert_eq!(held.in_flight, 0);
        resume.wait();

        let rejected = callback
            .join()
            .unwrap_or_else(|_panic| panic!("callback admission thread should finish"));
        assert!(rejected);
        assert_eq!(quiescence.release_hot_fork().in_flight, 0);
        assert!(quiescence.enter().is_some());
    }

    #[test]
    fn hot_fork_hold_drains_and_release_reopens_admission() {
        let quiescence = Arc::new(LiveCallbackQuiescence::new());
        let guard = quiescence
            .enter()
            .unwrap_or_else(|| panic!("open gate should admit callback"));

        let held = quiescence.hold_hot_fork();
        assert!(held.hot_fork_held);
        assert!(!held.teardown_closed);
        assert_eq!(held.in_flight, 1);
        assert!(!held.hot_fork_quiescent());
        assert!(quiescence.enter().is_none());

        drop(guard);
        let drained = quiescence.snapshot();
        assert!(drained.hot_fork_quiescent());

        let released = quiescence.release_hot_fork();
        assert!(!released.hot_fork_held);
        assert!(!released.teardown_closed);
        assert_eq!(released.in_flight, 0);
        assert!(quiescence.enter().is_some());
    }

    #[test]
    fn hot_fork_release_cannot_reopen_teardown_closed_admission() {
        let quiescence = Arc::new(LiveCallbackQuiescence::new());
        quiescence.hold_hot_fork();
        quiescence.close();

        let released = quiescence.release_hot_fork();
        assert!(!released.hot_fork_held);
        assert!(released.teardown_closed);
        assert!(!released.hot_fork_quiescent());
        assert!(quiescence.enter().is_none());
    }
}
