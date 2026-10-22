//! Always-on wall-time progress rows for the RUNs of one node set.
//!
//! A long multi-node attempt can run for hours. Operators need to see, while
//! it runs, how fast virtual time advances, how many nodes run together, and
//! where host wall time goes. The node set sees every RUN it dispatches, so it
//! accumulates those figures here and prints one bounded stderr row about
//! every [`PROGRESS_INTERVAL`] of wall time:
//!
//! ```text
//! CRUCIBLE-ATTEMPT-PROGRESS-V1 window_ms=30004 quanta=812 quanta_per_s=27.06 frontier_ps=4100000000 virtual_per_wall=0.013700 mean_runs_per_quantum=4.62 max_runs=5 realized_parallelism=4.40 max_realized=5 batches=1:20,5:792 run_wall_ms=28800 host_overhead_ms=1204 sleeps=3 sleep_ms=0 futex_waits=4010 futex_wait_ms=27000 futex_timeouts=0 nodes=router-a:812/27900/900/4150000000/4149999950,...
//! ```
//!
//! - `quanta` counts dispatched RUN sets: serial RUNs and host-concurrent
//!   sets alike. Control-only scheduler quanta dispatch nothing.
//! - `frontier_ps` is the minimum clock over every node that has run, and
//!   `virtual_per_wall` divides its advance in this window by the window's
//!   wall time.
//! - `realized_parallelism` is RFC-0010 [PERF-3]'s realized parallelism P:
//!   the mean, over RUN sets, of the peak number of RUNs that executed at once.
//! - `batches` maps a RUN-set size to the number of sets of that size.
//! - `run_wall_ms` is wall time inside RUN dispatch; `host_overhead_ms` is the
//!   rest of the window, spent in scheduler and driver work.
//! - The wait fields are process-wide deltas from
//!   [`crate::supervision::host_wait_counters`].
//! - Each node reports `runs/run_ms/wait_ms/horizon_ps/clock_ps`: its RUN
//!   count, wall time inside its own RUNs, wall time it sat finished while
//!   other RUNs of its set still ran, its latest RUN ceiling, and its clock.
//!
//! Host time read here is diagnostic only. It never reaches a scheduling
//! decision, a guest-visible value, or canonical evidence.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{Duration, Instant};

use crucible::NodeId;

use crate::supervision::host_wait_counters::{self, HostWaitTotals};

/// Wall-clock length of one progress window.
pub(crate) const PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

/// Upper bound on rows from one node set, about four days at the interval.
const MAX_ROWS: u32 = 12_000;

/// Reads wall time exclusively for noncanonical progress attribution.
// crucible-lint: allow clippy-disallowed-method -- private host-cost observations do not drive guest clocks, deadlines, or results.
#[allow(clippy::disallowed_methods)]
pub(crate) fn progress_clock() -> Instant {
    Instant::now()
}

/// One node's completed RUN within a dispatched set.
#[derive(Clone, Debug)]
pub(crate) struct NodeRunSample {
    /// Node that ran.
    pub(crate) node: NodeId,
    /// Scheduler ceiling the RUN was bounded by.
    pub(crate) horizon_ticks: u64,
    /// Node clock when the RUN returned, when it completed.
    pub(crate) reached_ticks: Option<u64>,
    /// Wall time inside this node's RUN.
    pub(crate) wall: Duration,
}

#[derive(Debug, Default)]
struct NodeWindow {
    runs: u64,
    run: Duration,
    wait: Duration,
}

#[derive(Debug)]
struct Window {
    started: Instant,
    start_frontier: Option<u64>,
    start_waits: HostWaitTotals,
    sets: u64,
    runs: u64,
    max_runs: usize,
    realized_sum: u64,
    max_realized: usize,
    batches: BTreeMap<usize, u64>,
    run_wall: Duration,
    nodes: BTreeMap<NodeId, NodeWindow>,
}

/// Accumulates and prints progress rows for one node set.
#[derive(Debug)]
pub(crate) struct AttemptProgress {
    enabled: bool,
    emitted: u32,
    window: Option<Window>,
    horizons: BTreeMap<NodeId, u64>,
    clocks: BTreeMap<NodeId, u64>,
}

impl AttemptProgress {
    /// Builds accounting that prints rows.
    pub(crate) const fn new() -> Self {
        Self {
            enabled: true,
            emitted: 0,
            window: None,
            horizons: BTreeMap::new(),
            clocks: BTreeMap::new(),
        }
    }

    /// Builds accounting that records nothing, for per-RUN worker sets.
    pub(crate) const fn disabled() -> Self {
        Self {
            enabled: false,
            emitted: 0,
            window: None,
            horizons: BTreeMap::new(),
            clocks: BTreeMap::new(),
        }
    }

    /// Returns a start instant when the set should be measured.
    pub(crate) fn begin(&self) -> Option<Instant> {
        (self.enabled && self.emitted < MAX_ROWS).then(progress_clock)
    }

    /// Records one dispatched RUN set and prints a row when the window is due.
    ///
    /// `realized` is the peak number of RUNs of the set that executed at once.
    pub(crate) fn finish(
        &mut self,
        started: Option<Instant>,
        samples: &[NodeRunSample],
        realized: usize,
    ) {
        let Some(started) = started else {
            return;
        };
        let now = progress_clock();
        self.record(
            started,
            now,
            samples,
            realized,
            host_wait_counters::totals(),
        );
        if let Some(row) = self.close_if_due(now, host_wait_counters::totals()) {
            let _ = writeln!(std::io::stderr().lock(), "{row}");
        }
    }

    /// Records one RUN dispatched through the single-node path.
    pub(crate) fn finish_serial(
        &mut self,
        started: Option<Instant>,
        node: &NodeId,
        horizon_ticks: u64,
        reached_ticks: Option<u64>,
    ) {
        let Some(run_started) = started else {
            return;
        };
        let sample = NodeRunSample {
            node: node.clone(),
            horizon_ticks,
            reached_ticks,
            wall: progress_clock().saturating_duration_since(run_started),
        };
        self.finish(started, std::slice::from_ref(&sample), 1);
    }

    fn frontier(&self) -> Option<u64> {
        self.clocks.values().copied().min()
    }

    fn record(
        &mut self,
        started: Instant,
        now: Instant,
        samples: &[NodeRunSample],
        realized: usize,
        waits: HostWaitTotals,
    ) {
        let start_frontier = self.frontier();
        let window = self.window.get_or_insert_with(|| Window {
            started,
            start_frontier,
            start_waits: waits,
            sets: 0,
            runs: 0,
            max_runs: 0,
            realized_sum: 0,
            max_realized: 0,
            batches: BTreeMap::new(),
            run_wall: Duration::ZERO,
            nodes: BTreeMap::new(),
        });
        let set_wall = now.saturating_duration_since(started);
        window.sets = window.sets.saturating_add(1);
        window.runs = window
            .runs
            .saturating_add(u64::try_from(samples.len()).unwrap_or(u64::MAX));
        window.max_runs = window.max_runs.max(samples.len());
        window.realized_sum = window
            .realized_sum
            .saturating_add(u64::try_from(realized).unwrap_or(u64::MAX));
        window.max_realized = window.max_realized.max(realized);
        *window.batches.entry(samples.len()).or_default() += 1;
        window.run_wall = window.run_wall.saturating_add(set_wall);

        for sample in samples {
            let node = window.nodes.entry(sample.node.clone()).or_default();
            node.runs = node.runs.saturating_add(1);
            node.run = node.run.saturating_add(sample.wall);
            node.wait = node
                .wait
                .saturating_add(set_wall.saturating_sub(sample.wall));
            self.horizons
                .insert(sample.node.clone(), sample.horizon_ticks);
            if let Some(reached) = sample.reached_ticks {
                self.clocks.insert(sample.node.clone(), reached);
            }
        }

        // The first set of an attempt has no earlier frontier to measure from.
        if window.start_frontier.is_none() {
            window.start_frontier = self.clocks.values().copied().min();
        }
    }

    fn close_if_due(&mut self, now: Instant, waits: HostWaitTotals) -> Option<String> {
        let window = self.window.as_ref()?;
        let elapsed = now.saturating_duration_since(window.started);
        if elapsed < PROGRESS_INTERVAL {
            return None;
        }
        let row = self.format_row(window, elapsed, waits.since(window.start_waits));
        self.window = None;
        self.emitted = self.emitted.saturating_add(1);
        Some(row)
    }

    fn format_row(&self, window: &Window, elapsed: Duration, waits: HostWaitTotals) -> String {
        let frontier = self.frontier();
        let advanced = match (frontier, window.start_frontier) {
            (Some(end), Some(start)) => end.saturating_sub(start),
            _ => 0,
        };
        // Virtual ticks and wall time are both picoseconds, so the ratio is unitless.
        let elapsed_ps = elapsed.as_nanos().saturating_mul(1_000);
        let virtual_per_wall = decimal_ratio(u128::from(advanced), elapsed_ps, 6);
        let quanta_per_s = decimal_ratio(
            u128::from(window.sets).saturating_mul(1_000_000_000),
            elapsed.as_nanos(),
            2,
        );
        let mean_runs = decimal_ratio(u128::from(window.runs), u128::from(window.sets), 2);
        let realized = decimal_ratio(u128::from(window.realized_sum), u128::from(window.sets), 2);

        let mut row = format!(
            "CRUCIBLE-ATTEMPT-PROGRESS-V1 window_ms={} quanta={} quanta_per_s={quanta_per_s} frontier_ps={} virtual_per_wall={virtual_per_wall} mean_runs_per_quantum={mean_runs} max_runs={} realized_parallelism={realized} max_realized={} batches=",
            elapsed.as_millis(),
            window.sets,
            frontier.map_or_else(|| String::from("none"), |ticks| ticks.to_string()),
            window.max_runs,
            window.max_realized,
        );
        let batches = window
            .batches
            .iter()
            .map(|(size, count)| format!("{size}:{count}"))
            .collect::<Vec<_>>()
            .join(",");
        row.push_str(&batches);
        let _ = write!(
            row,
            " run_wall_ms={} host_overhead_ms={} sleeps={} sleep_ms={} futex_waits={} futex_wait_ms={} futex_timeouts={} nodes=",
            window.run_wall.as_millis(),
            elapsed.saturating_sub(window.run_wall).as_millis(),
            waits.sleeps,
            waits.sleep_nanos / 1_000_000,
            waits.futex_waits,
            waits.futex_wait_nanos / 1_000_000,
            waits.futex_timeouts,
        );
        let nodes = window
            .nodes
            .iter()
            .map(|(node, progress)| {
                format!(
                    "{}:{}/{}/{}/{}/{}",
                    node.name,
                    progress.runs,
                    progress.run.as_millis(),
                    progress.wait.as_millis(),
                    self.horizons.get(node).copied().unwrap_or_default(),
                    self.clocks.get(node).copied().unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        row.push_str(&nodes);
        row
    }
}

/// Formats `numerator / denominator` with `places` truncated decimal places.
///
/// Diagnostics stay in integer arithmetic; a zero denominator reads as zero.
fn decimal_ratio(numerator: u128, denominator: u128, places: u32) -> String {
    let scale = 10_u128.pow(places);
    let scaled = numerator
        .saturating_mul(scale)
        .checked_div(denominator)
        .unwrap_or(0);
    if places == 0 {
        return scaled.to_string();
    }
    format!(
        "{}.{:0width$}",
        scaled / scale,
        scaled % scale,
        width = places as usize
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, horizon: u64, reached: u64, wall_ms: u64) -> NodeRunSample {
        NodeRunSample {
            node: NodeId {
                name: String::from(name),
            },
            horizon_ticks: horizon,
            reached_ticks: Some(reached),
            wall: Duration::from_millis(wall_ms),
        }
    }

    #[test]
    fn row_reports_batches_frontier_and_per_node_waits() {
        let mut progress = AttemptProgress::new();
        let start = progress_clock();
        let waits = HostWaitTotals::default();

        // The first set of the attempt establishes the starting frontier.
        progress.record(
            start,
            start + Duration::from_millis(10),
            &[sample("a", 100, 100, 10), sample("b", 150, 120, 4)],
            2,
            waits,
        );
        progress.record(
            start + Duration::from_secs(10),
            start + Duration::from_secs(20),
            &[sample("a", 300, 290, 10_000)],
            1,
            waits,
        );
        assert!(
            progress
                .close_if_due(start + Duration::from_secs(29), waits)
                .is_none()
        );

        let later = HostWaitTotals {
            futex_waits: 7,
            futex_timeouts: 1,
            ..waits
        };
        let Some(row) = progress.close_if_due(start + Duration::from_secs(30), later) else {
            panic!("a 30 s window must be due");
        };

        assert!(row.starts_with("CRUCIBLE-ATTEMPT-PROGRESS-V1 window_ms=30000 quanta=2 "));
        assert!(row.contains(" frontier_ps=120 virtual_per_wall=0.000000 "));
        assert!(row.contains(" mean_runs_per_quantum=1.50 max_runs=2 realized_parallelism=1.50 max_realized=2 batches=1:1,2:1 "));
        assert!(row.contains(" run_wall_ms=10010 host_overhead_ms=19990 "));
        assert!(row.contains(" futex_waits=7 futex_wait_ms=0 futex_timeouts=1 "));
        assert!(row.ends_with(" nodes=a:2/10010/0/300/290,b:1/4/6/150/120"));
        assert!(progress.window.is_none());
    }

    #[test]
    fn decimal_ratios_truncate_without_floating_point() {
        assert_eq!(decimal_ratio(3, 2, 2), "1.50");
        assert_eq!(decimal_ratio(1, 3, 6), "0.333333");
        assert_eq!(decimal_ratio(5, 0, 2), "0.00");
        assert_eq!(decimal_ratio(2_700, 100, 0), "27");
    }

    #[test]
    fn disabled_accounting_never_reads_the_clock_or_records() {
        let mut progress = AttemptProgress::disabled();

        assert!(progress.begin().is_none());
        progress.finish(None, &[sample("a", 1, 1, 1)], 1);

        assert!(progress.window.is_none());
        assert!(progress.clocks.is_empty());
    }
}
