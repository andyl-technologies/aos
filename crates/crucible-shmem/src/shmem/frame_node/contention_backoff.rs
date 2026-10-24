//! Bounded waiting for a peer's in-progress shared-memory publication.
//!
//! A reader that finds a seqlock word odd, or a publication claim held, must
//! retry. The peer that owns that state is another process: if it stalls or
//! dies mid-publication, an unbounded spin would peg the reader's core for as
//! long as the state stays held. The backoff spins briefly, because ordinary
//! publications finish within a few stores, and then sleeps with a doubling
//! delay capped at one millisecond.
//!
//! ```text
//! attempt   0 ..  63   spin hint
//! attempt  64 ..       sleep 1 us, 2 us, 4 us, ... capped at 1 ms
//! ```

use std::time::Duration;

/// Retries that only hint the CPU before the reader starts sleeping.
const SPIN_ATTEMPTS: u32 = 64;

/// The longest sleep between two retries.
const MAX_SLEEP: Duration = Duration::from_millis(1);

/// One reader's retry schedule for a contended publication.
#[derive(Debug, Default)]
pub(super) struct ContentionBackoff {
    attempts: u32,
}

impl ContentionBackoff {
    /// Starts a schedule whose first retries spin.
    pub(super) const fn new() -> Self {
        Self { attempts: 0 }
    }

    /// Waits before the next retry.
    pub(super) fn wait(&mut self) {
        match self.sleep() {
            None => core::hint::spin_loop(),
            Some(delay) => std::thread::sleep(delay),
        }
        self.attempts = self.attempts.saturating_add(1);
    }

    /// Returns how many retries this schedule has waited for.
    #[cfg(test)]
    pub(super) const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Returns the sleep before the next retry, or `None` while still spinning.
    fn sleep(&self) -> Option<Duration> {
        let sleeping = self.attempts.checked_sub(SPIN_ATTEMPTS)?;
        let micros = 1_u64.checked_shl(sleeping).unwrap_or(u64::MAX);
        Some(Duration::from_micros(micros).min(MAX_SLEEP))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::super::{AdvanceStopCondition, KIND_VM, NodeSlot};
    use super::*;

    /// How long each test holds the contended state.
    const HOLD: Duration = Duration::from_millis(30);

    /// Far above the schedule's retries over [`HOLD`], far below a spin's.
    const MAX_ATTEMPTS_WHILE_HELD: u32 = 1_000;

    #[test]
    fn spins_first_and_then_sleeps_with_a_capped_doubling_delay() {
        let mut backoff = ContentionBackoff::new();
        for _ in 0..SPIN_ATTEMPTS {
            assert_eq!(backoff.sleep(), None);
            backoff.attempts += 1;
        }

        assert_eq!(backoff.sleep(), Some(Duration::from_micros(1)));
        backoff.attempts += 1;
        assert_eq!(backoff.sleep(), Some(Duration::from_micros(2)));

        backoff.attempts = SPIN_ATTEMPTS + 10;
        assert_eq!(backoff.sleep(), Some(MAX_SLEEP));
        backoff.attempts = u32::MAX;
        assert_eq!(backoff.sleep(), Some(MAX_SLEEP));
    }

    #[test]
    fn a_held_host_claim_parks_a_snapshot_reader_until_released() {
        let slot = NodeSlot::new(KIND_VM);
        let lease = slot
            .try_claim_control_boundary_publication()
            .unwrap_or_else(|error| panic!("claim should be free: {error}"))
            .unwrap_or_else(|| panic!("claim should not be native-owned"));
        assert!(slot.try_snapshot().is_none());

        let mut backoff = ContentionBackoff::new();
        let started = Instant::now();
        let snapshot = std::thread::scope(|scope| {
            let reader = scope.spawn(|| slot.snapshot_with(&mut backoff));
            std::thread::sleep(HOLD);
            drop(lease);
            reader
                .join()
                .unwrap_or_else(|_| panic!("reader should not panic"))
        });

        assert!(started.elapsed() >= HOLD);
        assert_eq!(snapshot.publish_gen, slot.snapshot().publish_gen);
        assert!(backoff.attempts() > SPIN_ATTEMPTS);
        assert!(backoff.attempts() < MAX_ATTEMPTS_WHILE_HELD);
    }

    #[test]
    fn an_odd_advance_sequence_parks_a_scheduler_reader_until_published() {
        let slot = NodeSlot::new(KIND_VM);
        let mut backoff = ContentionBackoff::new();

        let observed = std::thread::scope(|scope| {
            let mut reader = None;
            slot.publish_scheduler_advance_fields_with_effect(
                400,
                AdvanceStopCondition::Ceiling,
                |_| {
                    // The host's sequence stays odd until this effect returns.
                    reader =
                        Some(scope.spawn(|| slot.load_scheduler_advance_raw_with(&mut backoff)));
                    std::thread::sleep(HOLD);
                },
            );
            reader
                .unwrap_or_else(|| panic!("effect should spawn the reader"))
                .join()
                .unwrap_or_else(|_| panic!("reader should not panic"))
        });

        assert_eq!(observed.0, 400);
        assert_eq!(observed.1, AdvanceStopCondition::Ceiling.encode());
        assert!(backoff.attempts() > SPIN_ATTEMPTS);
        assert!(backoff.attempts() < MAX_ATTEMPTS_WHILE_HELD);
    }
}
