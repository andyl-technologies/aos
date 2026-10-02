//! Opt-in, bounded diagnostics around production scheduler operations.
//!
//! Host time controls only stderr sampling. These notices never select a
//! deadline, mutate a queue, or replace the operation's actual result.

use std::io::Write;
// crucible-lint: allow host-nondeterminism-state -- host time limits diagnostic output only; scheduler state and results remain authoritative.
use std::time::{Duration, Instant};

use super::super::ProductionVmLifecycleLoop;

const REPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_REPORTS: u16 = 256;
const MAX_REPORTED_NODES: usize = 32;

/// Reads host time solely to limit stderr notices, never scheduler decisions.
#[allow(clippy::disallowed_methods)]
fn diagnostic_clock() -> Instant {
    Instant::now()
}

/// Process-local sampling state excluded from every checkpoint and wire format.
#[derive(Debug, Default)]
pub(in crate::vm_lifecycle) struct RuntimeProgress {
    remaining: u16,
    next_report: Option<Instant>,
}

impl RuntimeProgress {
    pub(in crate::vm_lifecycle) fn from_environment() -> Self {
        let maximum = std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_default()
            .min(MAX_REPORTS);
        Self {
            remaining: maximum,
            next_report: None,
        }
    }

    pub(in crate::vm_lifecycle) fn begin(&mut self) -> bool {
        if self.remaining < 2 {
            return false;
        }
        self.begin_at(diagnostic_clock())
    }

    fn begin_at(&mut self, now: Instant) -> bool {
        if self.remaining < 2 || self.next_report.is_some_and(|next| now < next) {
            return false;
        }
        // Reserve both notices before effects. A blocked operation leaves its
        // before notice visible without inventing a completed quantum.
        self.remaining -= 2;
        self.next_report = now.checked_add(REPORT_INTERVAL);
        true
    }
}

impl ProductionVmLifecycleLoop {
    pub(in crate::vm_lifecycle) fn report_runtime_progress(&self, stage: &str) {
        let scheduler = self.inner.loop_impl();
        let nodes = self.source.world().vm_nodes();
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "CRUCIBLE-RUNTIME-PROGRESS-V1 stage={stage} quanta={} frontier_ps={} pending_network_outputs={} node_count={} omitted_nodes={} published_slot_status=unavailable tx_rx_counters=unavailable",
            scheduler.quanta(),
            scheduler.frontier().ticks,
            self.inner.pending_network_output_count(),
            nodes.len(),
            nodes.len().saturating_sub(MAX_REPORTED_NODES),
        );
        for node in nodes.iter().take(MAX_REPORTED_NODES) {
            // These are retained, authenticated boundary coordinates. The
            // backend clock is not a fresh shared-slot sample during a RUN.
            let scheduler_time = scheduler
                .scheduler_time_for_node(&node.id)
                .map(|time| time.ticks);
            let backend_time =
                crucible::SimulationBackend::node_now(self.inner.backend(), &node.id)
                    .map(|time| time.ticks);
            let state = self.production_node_fault_evidence(&node.id);
            let _ = writeln!(
                stderr,
                "CRUCIBLE-RUNTIME-PROGRESS-V1 stage={stage} node={:?} scheduler_time_ps={scheduler_time:?} backend_last_observed_tick_ps={backend_time:?} lifecycle_state={state:?}",
                node.id.name,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_reserve_pairs_at_bounded_cadence_without_sleeping() {
        let now = diagnostic_clock();
        let mut progress = RuntimeProgress {
            remaining: 4,
            next_report: None,
        };

        assert!(progress.begin_at(now));
        assert!(!progress.begin_at(now + Duration::from_secs(4)));
        assert!(progress.begin_at(now + REPORT_INTERVAL));
        assert!(!progress.begin_at(now + REPORT_INTERVAL * 2));
        assert_eq!(progress.remaining, 0);
    }

    #[test]
    fn disabled_and_exhausted_reporters_do_not_sample() {
        let mut disabled = RuntimeProgress::default();
        assert!(!disabled.begin());
        let mut exhausted = RuntimeProgress {
            remaining: 1,
            next_report: None,
        };
        assert!(!exhausted.begin());
        assert_eq!(exhausted.remaining, 1);
    }
}
