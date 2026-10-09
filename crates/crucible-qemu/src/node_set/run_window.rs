//! Sampled wall-time accounting for host RUN dispatch.
//!
//! Multi-node campaigns spend wall time in three places: guest execution
//! inside backend RUNs, host-parallel overlap between those RUNs, and
//! scheduler work between them. The node set sees every RUN it dispatches,
//! so it can split a fixed wall-clock window into those parts without
//! touching scheduling decisions.
//!
//! The accounting is enabled only by the existing
//! `CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS` diagnostic budget. When
//! disabled it performs no clock reads. Each closed window emits one bounded
//! stderr record:
//!
//! ```text
//! CRUCIBLE-HOST-RUN-WINDOW-V1 window_ms=5000 serial_runs=12 concurrent_sets=40 concurrent_runs=180 realized_sum=150 max_realized=5 backend_ms=4700
//! ```
//!
//! `backend_ms` counts wall time inside RUN dispatch calls; the remainder of
//! `window_ms` is scheduler and driver work. `realized_sum / concurrent_sets`
//! is the mean peak overlap of concurrent RUN sets.

use std::io::Write;
use std::time::{Duration, Instant};

/// Wall-clock length of one emitted accounting window.
const WINDOW: Duration = Duration::from_secs(5);

/// Upper bound on emitted records, so a long run cannot flood stderr.
const MAX_RECORDS: u32 = 512;

/// Totals for the currently open window.
#[derive(Debug)]
struct OpenWindow {
    started: Instant,
    serial_runs: u64,
    concurrent_sets: u64,
    concurrent_runs: u64,
    realized_sum: u64,
    max_realized: usize,
    backend: Duration,
}

impl OpenWindow {
    fn new(started: Instant) -> Self {
        Self {
            started,
            serial_runs: 0,
            concurrent_sets: 0,
            concurrent_runs: 0,
            realized_sum: 0,
            max_realized: 0,
            backend: Duration::ZERO,
        }
    }
}

/// Lazily enabled RUN-dispatch accounting owned by one node set.
#[derive(Debug)]
pub(super) struct RunWindow {
    enabled: Option<bool>,
    emitted: u32,
    open: Option<OpenWindow>,
}

impl RunWindow {
    pub(super) const fn new() -> Self {
        Self {
            enabled: None,
            emitted: 0,
            open: None,
        }
    }

    /// Builds accounting that never samples, for per-RUN worker sets.
    pub(super) const fn disabled() -> Self {
        Self {
            enabled: Some(false),
            emitted: 0,
            open: None,
        }
    }

    /// Returns a start instant when accounting is enabled.
    pub(super) fn begin(&mut self) -> Option<Instant> {
        let enabled = *self.enabled.get_or_insert_with(|| {
            std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .is_some_and(|budget| budget != 0)
        });
        (enabled && self.emitted < MAX_RECORDS).then(Instant::now)
    }

    /// Records one RUN dispatched through the single-node path.
    pub(super) fn finish_serial(&mut self, started: Option<Instant>) {
        let Some(started) = started else {
            return;
        };
        let window = self.open.get_or_insert_with(|| OpenWindow::new(started));
        window.serial_runs = window.serial_runs.saturating_add(1);
        window.backend = window.backend.saturating_add(started.elapsed());
        self.close_if_due();
    }

    /// Records one host-concurrent RUN set and its peak overlap.
    pub(super) fn finish_concurrent(
        &mut self,
        started: Option<Instant>,
        requested: usize,
        realized: usize,
    ) {
        let Some(started) = started else {
            return;
        };
        let window = self.open.get_or_insert_with(|| OpenWindow::new(started));
        window.concurrent_sets = window.concurrent_sets.saturating_add(1);
        window.concurrent_runs = window
            .concurrent_runs
            .saturating_add(u64::try_from(requested).unwrap_or(u64::MAX));
        window.realized_sum = window
            .realized_sum
            .saturating_add(u64::try_from(realized).unwrap_or(u64::MAX));
        window.max_realized = window.max_realized.max(realized);
        window.backend = window.backend.saturating_add(started.elapsed());
        self.close_if_due();
    }

    fn close_if_due(&mut self) {
        let Some(window) = &self.open else {
            return;
        };
        let elapsed = window.started.elapsed();
        if elapsed < WINDOW {
            return;
        }
        let _ = writeln!(
            std::io::stderr().lock(),
            "CRUCIBLE-HOST-RUN-WINDOW-V1 window_ms={} serial_runs={} concurrent_sets={} concurrent_runs={} realized_sum={} max_realized={} backend_ms={}",
            elapsed.as_millis(),
            window.serial_runs,
            window.concurrent_sets,
            window.concurrent_runs,
            window.realized_sum,
            window.max_realized,
            window.backend.as_millis(),
        );
        self.emitted = self.emitted.saturating_add(1);
        self.open = None;
    }
}
