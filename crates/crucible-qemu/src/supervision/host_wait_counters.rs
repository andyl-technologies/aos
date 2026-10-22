//! Process-wide counters for host waits on plugin publications.
//!
//! Every host-liveness wait in the live host-I/O runtime reports here: plain
//! sleeps and futex waits on a node's host publication signal. The
//! attempt-progress row reads the totals as deltas, so an operator can tell
//! whether wall time per quantum goes to guest execution or to host waits.
//!
//! The counters are diagnostics only. They are relaxed atomics, never read by
//! scheduling code, and never enter guest-visible or canonical state. They are
//! process-wide, so a process that runs several attempts at once reports the
//! sum of their waits.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SLEEPS: AtomicU64 = AtomicU64::new(0);
static SLEEP_NANOS: AtomicU64 = AtomicU64::new(0);
// Futex waits arrive with the host publication signal.
static FUTEX_WAITS: AtomicU64 = AtomicU64::new(0);
static FUTEX_WAIT_NANOS: AtomicU64 = AtomicU64::new(0);
static FUTEX_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// Totals of host waits since process start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HostWaitTotals {
    /// Plain sleeps taken while polling for a publication.
    pub(crate) sleeps: u64,
    /// Requested sleep time, in nanoseconds.
    pub(crate) sleep_nanos: u64,
    /// Futex waits on a host publication signal.
    pub(crate) futex_waits: u64,
    /// Wall time spent inside those futex waits, in nanoseconds.
    pub(crate) futex_wait_nanos: u64,
    /// Futex waits that ended at their liveness timeout without a publication.
    pub(crate) futex_timeouts: u64,
}

impl HostWaitTotals {
    /// Returns the waits recorded since `earlier`.
    pub(crate) fn since(self, earlier: Self) -> Self {
        Self {
            sleeps: self.sleeps.saturating_sub(earlier.sleeps),
            sleep_nanos: self.sleep_nanos.saturating_sub(earlier.sleep_nanos),
            futex_waits: self.futex_waits.saturating_sub(earlier.futex_waits),
            futex_wait_nanos: self
                .futex_wait_nanos
                .saturating_sub(earlier.futex_wait_nanos),
            futex_timeouts: self.futex_timeouts.saturating_sub(earlier.futex_timeouts),
        }
    }
}

fn saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Records one plain sleep of `requested` length.
pub(crate) fn record_sleep(requested: Duration) {
    SLEEPS.fetch_add(1, Ordering::Relaxed);
    SLEEP_NANOS.fetch_add(saturating_nanos(requested), Ordering::Relaxed);
}

/// Reads the current totals.
pub(crate) fn totals() -> HostWaitTotals {
    HostWaitTotals {
        sleeps: SLEEPS.load(Ordering::Relaxed),
        sleep_nanos: SLEEP_NANOS.load(Ordering::Relaxed),
        futex_waits: FUTEX_WAITS.load(Ordering::Relaxed),
        futex_wait_nanos: FUTEX_WAIT_NANOS.load(Ordering::Relaxed),
        futex_timeouts: FUTEX_TIMEOUTS.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deltas_subtract_each_counter_and_saturate() {
        let earlier = HostWaitTotals {
            sleeps: 2,
            sleep_nanos: 40,
            futex_waits: 1,
            futex_wait_nanos: 7,
            futex_timeouts: 0,
        };
        let later = HostWaitTotals {
            sleeps: 5,
            sleep_nanos: 100,
            futex_waits: 4,
            futex_wait_nanos: 9,
            futex_timeouts: 1,
        };

        let delta = later.since(earlier);

        assert_eq!(
            delta,
            HostWaitTotals {
                sleeps: 3,
                sleep_nanos: 60,
                futex_waits: 3,
                futex_wait_nanos: 2,
                futex_timeouts: 1,
            }
        );
        assert_eq!(earlier.since(later), HostWaitTotals::default());
    }

    #[test]
    fn recorded_waits_reach_the_totals() {
        let before = totals();

        record_sleep(Duration::from_micros(3));

        // Other tests may record concurrently, so only lower bounds hold.
        let delta = totals().since(before);
        assert!(delta.sleeps >= 1);
        assert!(delta.sleep_nanos >= 3_000);
    }
}
