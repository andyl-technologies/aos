//! Private operational clocks for process supervision and fork-rate admission.
//!
//! These clocks never define guest time, an execution horizon, campaign fuel,
//! or a persisted execution result. Process deadlines only stop host waiting;
//! the fork clock feeds the process-wide launch-rate limiter, not planner
//! selection. Neither clock exposes its host timestamp to callers.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::ExecutionCancellation;

/// Measures elapsed host time solely for operational fork-rate admission.
pub(super) struct ForkRateClock {
    origin: Instant,
}

impl ForkRateClock {
    pub(super) fn new() -> Self {
        Self { origin: now() }
    }

    pub(super) fn elapsed_nanos(&self) -> u64 {
        let elapsed = now().saturating_duration_since(self.origin);
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Bounds one host process operation without exposing an absolute timestamp.
#[derive(Clone, Copy)]
pub(super) struct ProcessDeadline {
    deadline: Instant,
}

impl ProcessDeadline {
    /// Wraps an existing host deadline without exposing clock reads to callers.
    pub(super) const fn at(deadline: Instant) -> Self {
        Self { deadline }
    }

    /// Returns no deadline if the requested host duration cannot be represented.
    pub(super) fn after(timeout: Duration) -> Option<Self> {
        now().checked_add(timeout).map(|deadline| Self { deadline })
    }

    /// Returns the remaining operational wait allowance.
    pub(super) fn remaining(self) -> Duration {
        self.deadline.saturating_duration_since(now())
    }

    pub(super) fn expired(self) -> bool {
        now() >= self.deadline
    }

    /// Caps a process-poll pause at the remaining operational wait allowance.
    pub(super) fn pause(self, maximum: Duration) {
        std::thread::sleep(maximum.min(self.remaining()));
    }
}

/// Monotonic, clone-shared operational deadline for one accepted assignment.
#[derive(Clone, Debug)]
pub(super) struct AssignmentHostWatchdog {
    started_at: Instant,
    allowance: Duration,
    expired: Arc<AtomicBool>,
}

impl AssignmentHostWatchdog {
    /// Returns the operational allowance left before process cancellation.
    // crucible-lint: allow clippy-disallowed-method -- elapsed host time controls only cancellation.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn remaining(&self) -> Duration {
        self.allowance.saturating_sub(self.started_at.elapsed())
    }

    /// Reports whether the assignment budget elapsed or its watcher fired.
    pub(super) fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire) || self.remaining().is_zero()
    }
}

/// Cancels a live QEMU child when the whole assignment exceeds its host budget.
pub(super) struct AssignmentHostWatchdogGuard {
    completion: mpsc::Sender<()>,
    watcher: Option<JoinHandle<()>>,
    pub(super) state: AssignmentHostWatchdog,
}

impl AssignmentHostWatchdogGuard {
    /// Starts operational supervision for one accepted assignment.
    // crucible-lint: allow clippy-disallowed-method -- host time never enters campaign semantic state.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn start(
        milliseconds: u64,
        cancellation: ExecutionCancellation,
    ) -> std::io::Result<Self> {
        let state = AssignmentHostWatchdog {
            started_at: Instant::now(),
            allowance: Duration::from_millis(milliseconds),
            expired: Arc::new(AtomicBool::new(false)),
        };
        let (completion, receiver) = mpsc::channel();
        let watcher_state = state.clone();
        let watcher = thread::Builder::new()
            .name(String::from("campaign-host-watchdog"))
            .spawn(move || {
                loop {
                    // Keep each wait representable even when policy admits a
                    // duration far beyond the platform's Instant range.
                    let slice = watcher_state.remaining().min(Duration::from_secs(3600));
                    match receiver.recv_timeout(slice) {
                        Err(mpsc::RecvTimeoutError::Timeout) if watcher_state.expired() => {
                            watcher_state.expired.store(true, Ordering::Release);
                            cancellation.cancel();
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) | Ok(()) => break,
                    }
                }
            })?;
        Ok(Self {
            completion,
            watcher: Some(watcher),
            state,
        })
    }

    /// Stops supervision and reports whether the host allowance expired.
    pub(super) fn stop(&mut self) -> bool {
        // A completed candidate cannot win a race against the assignment deadline
        // merely because the watchdog thread has not been scheduled yet.
        if self.state.remaining().is_zero() {
            self.state.expired.store(true, Ordering::Release);
        }
        let _ = self.completion.send(());
        let joined = self
            .watcher
            .take()
            .is_none_or(|watcher| watcher.join().is_ok());
        !joined || self.state.expired()
    }
}

impl Drop for AssignmentHostWatchdogGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

// Host time controls operational waiting and admission only. Keeping the read
// here prevents public lifecycle APIs from exporting a raw host-clock basis.
// crucible-lint: allow clippy-disallowed-method -- monotonic host time bounds only process supervision and operational fork admission.
#[allow(clippy::disallowed_methods)]
fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_process_allowance_is_already_expired() {
        assert!(ProcessDeadline::after(Duration::ZERO).is_some_and(ProcessDeadline::expired));
    }

    #[test]
    fn overflowing_process_allowance_is_rejected() {
        assert!(ProcessDeadline::after(Duration::MAX).is_none());
    }

    #[test]
    fn fork_rate_clock_never_moves_backwards() {
        let clock = ForkRateClock::new();
        let first = clock.elapsed_nanos();
        assert!(clock.elapsed_nanos() >= first);
    }
}
