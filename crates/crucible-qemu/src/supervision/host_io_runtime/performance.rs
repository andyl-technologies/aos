//! Bounded, opt-in host timing excluded from guest state and checkpoints.

use std::io::Write;
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_SAMPLES: u16 = 256;

/// Reads host time for diagnostic sampling only.
// crucible-lint: allow clippy-disallowed-method -- this private clock measures stderr diagnostics, never guest deadlines or results.
#[allow(clippy::disallowed_methods)]
fn diagnostic_clock() -> Instant {
    Instant::now()
}

#[derive(Default)]
struct Phase {
    pending_sleeps: u64,
    wake_writes: u64,
    pin_calls: u64,
}

/// Retains process-local measurements for at most one sampled advance.
pub(super) struct PerformanceDiagnostics {
    remaining: u16,
    next_sample: Option<Instant>,
    active: Option<Instant>,
    acknowledging: bool,
    region_inode: Option<u64>,
    phase: Phase,
}

impl PerformanceDiagnostics {
    pub(super) fn from_environment(fd: BorrowedFd<'_>) -> Self {
        let maximum = std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_default();
        let mut diagnostics = Self::with_budget(maximum);
        // Disabled diagnostics perform neither metadata reads nor clock reads.
        if diagnostics.remaining != 0 {
            diagnostics.region_inode = rustix::fs::fstat(fd).ok().map(|stat| stat.st_ino);
        }
        diagnostics
    }

    fn with_budget(maximum: u16) -> Self {
        Self {
            remaining: (maximum / 2).min(MAX_SAMPLES),
            next_sample: None,
            active: None,
            acknowledging: false,
            region_inode: None,
            phase: Phase::default(),
        }
    }

    /// Starts just after the actual scheduler ceiling has been published.
    pub(super) fn arm(&mut self) {
        self.arm_with_clock(diagnostic_clock);
    }

    fn arm_with_clock(&mut self, clock: impl FnOnce() -> Instant) {
        self.active = None;
        if self.remaining == 0 {
            return;
        }
        let now = clock();
        if self.next_sample.is_some_and(|next| now < next) {
            return;
        }
        self.remaining -= 1;
        self.next_sample = now.checked_add(SAMPLE_INTERVAL);
        self.active = Some(now);
        self.acknowledging = false;
        self.phase = Phase::default();
    }

    pub(super) fn pending_sleep(&mut self) {
        if self.active.is_some() {
            self.phase.pending_sleeps = self.phase.pending_sleeps.saturating_add(1);
        }
    }

    pub(super) fn wake_write(&mut self) {
        if self.active.is_some() {
            self.phase.wake_writes = self.phase.wake_writes.saturating_add(1);
        }
    }

    pub(super) fn pin_call(&mut self) {
        if self.active.is_some() {
            self.phase.pin_calls = self.phase.pin_calls.saturating_add(1);
        }
    }

    /// Splits boundary discovery from the separate exact control ACK wait.
    pub(super) fn boundary(&mut self, slot: u32) {
        if self.active.is_none() || self.acknowledging {
            return;
        }
        let now = diagnostic_clock();
        self.report(slot, "post-publication-arm-to-boundary", "observed", now);
        self.active = Some(now);
        self.acknowledging = true;
        self.phase = Phase::default();
    }

    pub(super) fn finish(&mut self, slot: u32, status: &str) {
        if self.active.is_none() {
            return;
        }
        let now = diagnostic_clock();
        self.report(slot, "boundary-to-ack", status, now);
        self.active = None;
    }

    fn report(&self, slot: u32, phase: &str, status: &str, now: Instant) {
        let Some(started) = self.active else {
            return;
        };
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "CRUCIBLE-HOST-QUANTUM-PERF-V1 slot={slot} region_inode={:?} phase={phase:?} status={status:?} host_elapsed_us={} pending_sleeps={} wake_write_attempts={} block_pin_calls={} pin_elapsed=unavailable",
            self.region_inode,
            now.saturating_duration_since(started).as_micros(),
            self.phase.pending_sleeps,
            self.phase.wake_writes,
            self.phase.pin_calls,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_and_exhausted_samples_never_read_the_clock() {
        let mut disabled = PerformanceDiagnostics::with_budget(0);
        disabled.arm_with_clock(|| panic!("disabled diagnostic read the clock"));
        disabled.pending_sleep();
        disabled.wake_write();
        disabled.pin_call();
        disabled.boundary(0);
        disabled.finish(0, "unused");
        assert!(disabled.active.is_none());
        assert_eq!(disabled.phase.pending_sleeps, 0);

        let mut exhausted = PerformanceDiagnostics::with_budget(2);
        exhausted.arm_with_clock(diagnostic_clock);
        exhausted.arm_with_clock(|| panic!("exhausted diagnostic read the clock"));
        assert!(exhausted.active.is_none());
    }

    #[test]
    fn sampling_cadence_and_total_budget_are_bounded() {
        let now = diagnostic_clock();
        let mut diagnostics = PerformanceDiagnostics::with_budget(u16::MAX);
        assert_eq!(diagnostics.remaining, MAX_SAMPLES);
        diagnostics.arm_with_clock(|| now);
        diagnostics.arm_with_clock(|| now + Duration::from_secs(4));
        assert!(diagnostics.active.is_none());
        assert_eq!(diagnostics.remaining, MAX_SAMPLES - 1);
        diagnostics.arm_with_clock(|| now + SAMPLE_INTERVAL);
        assert!(diagnostics.active.is_some());
        assert_eq!(diagnostics.remaining, MAX_SAMPLES - 2);
    }
}
