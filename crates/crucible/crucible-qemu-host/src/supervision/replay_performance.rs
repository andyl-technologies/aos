//! Bounded host-cost attribution for one exact/thin replay comparison.
//!
//! These process-local observations are advisory stderr data. They never enter
//! replay coordinates, certificates, checkpoints, or operational error results.
//!
//! Worker CPU excludes QEMU process CPU. Session wall time includes caller and
//! guard gaps and any teardown before reporting; phase totals do not. A dropped
//! summary describes lifetime termination, not the cause of a timeout. The
//! existing diagnostic opt-in admits at most 16 rows per executor independently
//! of other diagnostic producers' budgets.

use std::io::Write;
use std::time::{Duration, Instant};

use crate::QemuNode;

const PHASE_COUNT: usize = 8;
const MAX_REPORT_ROWS: u16 = 16;

/// Distinguishes the original exact probe from its independently launched replay.
#[derive(Clone, Copy)]
pub(super) enum ReplayLeg {
    Exact,
    Thin,
}

impl ReplayLeg {
    const fn index(self) -> usize {
        self as usize
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Thin => "thin",
        }
    }
}

/// Classifies existing executor operations without retaining their per-step history.
#[derive(Clone, Copy)]
pub(super) enum ReplayPhase {
    ExactLoad,
    ThinLoad,
    Advance,
    ChoiceDrain,
    ChoiceReply,
    Input,
    ModelDecision,
    Comparison,
}

impl ReplayPhase {
    const ALL: [Self; PHASE_COUNT] = [
        Self::ExactLoad,
        Self::ThinLoad,
        Self::Advance,
        Self::ChoiceDrain,
        Self::ChoiceReply,
        Self::Input,
        Self::ModelDecision,
        Self::Comparison,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::ExactLoad => "exact-load",
            Self::ThinLoad => "thin-load",
            Self::Advance => "physical-advance",
            Self::ChoiceDrain => "choice-drain",
            Self::ChoiceReply => "choice-reply",
            Self::Input => "input",
            Self::ModelDecision => "model-decision",
            Self::Comparison => "final-comparison",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Totals {
    calls: u64,
    errors: u64,
    wall: Duration,
    worker_cpu: Duration,
    cpu_unavailable: bool,
}

#[derive(Clone, Copy, Default)]
struct LegContext {
    pid: Option<u32>,
    start_ticks: Option<u64>,
    first_ps: Option<u64>,
    last_ps: Option<u64>,
    observation_generation: u64,
}

/// Opaque start sample consumed only by the supervising phase accumulator.
pub(super) struct Measurement {
    phase: ReplayPhase,
    leg: ReplayLeg,
    wall: Instant,
    worker_cpu: Option<Duration>,
}

/// Reads wall time exclusively for noncanonical diagnostic attribution.
// crucible-lint: allow clippy-disallowed-method -- private host-cost observations do not drive guest clocks, deadlines, or results.
#[allow(clippy::disallowed_methods)]
fn diagnostic_clock() -> Instant {
    Instant::now()
}

fn worker_cpu_clock() -> Option<Duration> {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    Some(Duration::new(
        u64::try_from(time.tv_sec).ok()?,
        u32::try_from(time.tv_nsec)
            .ok()
            .filter(|nanos| *nanos < 1_000_000_000)?,
    ))
}

/// Aggregates fixed phase counters without retaining individual replay steps.
pub(super) struct ReplayPerformance {
    remaining_rows: u16,
    reported: bool,
    active_leg: ReplayLeg,
    totals: [[Totals; PHASE_COUNT]; 2],
    contexts: [LegContext; 2],
    started: Option<Instant>,
}

impl ReplayPerformance {
    pub(super) fn from_environment() -> Self {
        let maximum = std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|maximum| (1..=256).contains(maximum))
            .unwrap_or_default();
        Self::with_budget(maximum)
    }

    fn with_budget(maximum: u16) -> Self {
        Self {
            remaining_rows: maximum.min(MAX_REPORT_ROWS),
            reported: false,
            active_leg: ReplayLeg::Exact,
            totals: [[Totals::default(); PHASE_COUNT]; 2],
            contexts: [LegContext::default(); 2],
            started: None,
        }
    }

    fn enabled(&self) -> bool {
        self.remaining_rows != 0 && !self.reported
    }

    pub(super) fn bind_node(&mut self, leg: ReplayLeg, node: &QemuNode) {
        if !self.enabled() {
            return;
        }
        self.active_leg = leg;
        let owned_pid = node.process_id();
        self.contexts[leg.index()].pid = Some(owned_pid);
        // The direct-child PID is original ownership; proc start ticks merely
        // disambiguate reuse. Metadata failure leaves that attribution absent.
        self.contexts[leg.index()].start_ticks = node
            .process_identity()
            .ok()
            .filter(|identity| identity.process_id == owned_pid)
            .map(|identity| identity.start_time_ticks);
    }

    // These are the existing authenticated replay node's calibrated logical
    // picoseconds, not QEMU's raw retired-instruction counter.
    pub(super) fn observe_physical(&mut self, logical_ps: u64) {
        if !self.enabled() {
            return;
        }
        let context = &mut self.contexts[self.active_leg.index()];
        context.first_ps.get_or_insert(logical_ps);
        context.last_ps = Some(logical_ps);
    }

    pub(super) fn begin(&mut self, phase: ReplayPhase) -> Option<Measurement> {
        self.begin_with_clocks(phase, diagnostic_clock, worker_cpu_clock)
    }

    pub(super) fn finish(&mut self, measurement: Measurement, generation: u64, failed: bool) {
        self.finish_at(
            measurement,
            diagnostic_clock(),
            worker_cpu_clock(),
            generation,
            failed,
        );
    }

    fn begin_with_clocks(
        &mut self,
        phase: ReplayPhase,
        wall_clock: impl FnOnce() -> Instant,
        cpu_clock: impl FnOnce() -> Option<Duration>,
    ) -> Option<Measurement> {
        if !self.enabled() {
            return None;
        }
        let wall = wall_clock();
        self.started.get_or_insert(wall);
        let leg = match phase {
            ReplayPhase::ExactLoad => ReplayLeg::Exact,
            ReplayPhase::ThinLoad => ReplayLeg::Thin,
            _ => self.active_leg,
        };
        Some(Measurement {
            phase,
            leg,
            wall,
            worker_cpu: cpu_clock(),
        })
    }

    fn finish_at(
        &mut self,
        measurement: Measurement,
        wall: Instant,
        worker_cpu: Option<Duration>,
        generation: u64,
        failed: bool,
    ) {
        let totals = &mut self.totals[measurement.leg.index()][measurement.phase as usize];
        totals.calls = totals.calls.saturating_add(1);
        totals.errors = totals.errors.saturating_add(u64::from(failed));
        totals.wall = totals
            .wall
            .saturating_add(wall.saturating_duration_since(measurement.wall));
        match measurement
            .worker_cpu
            .zip(worker_cpu)
            .and_then(|(before, after)| after.checked_sub(before))
        {
            Some(elapsed) => totals.worker_cpu = totals.worker_cpu.saturating_add(elapsed),
            None => totals.cpu_unavailable = true,
        }
        self.contexts[measurement.leg.index()].observation_generation = generation;
    }

    fn report_to(&mut self, output: &mut impl Write, status: &'static str, now: Instant) {
        if !self.enabled() {
            return;
        }
        self.reported = true;
        let session_us = self
            .started
            .map_or(0, |start| now.saturating_duration_since(start).as_micros());
        for leg in [ReplayLeg::Exact, ReplayLeg::Thin] {
            let context = self.contexts[leg.index()];
            for phase in ReplayPhase::ALL {
                let totals = self.totals[leg.index()][phase as usize];
                if totals.calls == 0 || self.remaining_rows == 0 {
                    continue;
                }
                self.remaining_rows -= 1;
                let cpu = if totals.cpu_unavailable {
                    String::from("unavailable")
                } else {
                    totals.worker_cpu.as_micros().to_string()
                };
                // Only fixed labels and bounded integers are formatted. The
                // maximum row is below 512 bytes, including its newline.
                let _ = writeln!(
                    output,
                    "CRUCIBLE-REPLAY-PERF-V1 leg={} phase={} status={status} pid={:?} start_ticks={:?} leg_last_observation_generation={} first_ps={:?} last_ps={:?} calls={} errors={} wall_us={} worker_cpu_us={cpu} session_wall_us={session_us}",
                    leg.name(),
                    phase.name(),
                    context.pid,
                    context.start_ticks,
                    context.observation_generation,
                    context.first_ps,
                    context.last_ps,
                    totals.calls,
                    totals.errors,
                    totals.wall.as_micros(),
                );
            }
        }
    }

    pub(super) fn report(&mut self, status: &'static str) {
        if self.enabled() {
            self.report_to(&mut std::io::stderr().lock(), status, diagnostic_clock());
        }
    }
}

impl Drop for ReplayPerformance {
    fn drop(&mut self) {
        self.report("dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_measurements_do_not_read_either_clock() {
        let mut diagnostics = ReplayPerformance::with_budget(0);
        assert!(
            diagnostics
                .begin_with_clocks(
                    ReplayPhase::Advance,
                    || panic!("disabled wall clock"),
                    || panic!("disabled CPU clock")
                )
                .is_none()
        );
        diagnostics.observe_physical(99);
        assert_eq!(diagnostics.contexts[0].last_ps, None);
    }

    #[test]
    fn fixed_phase_totals_separate_waiting_from_worker_cost_and_report_once() {
        let mut diagnostics = ReplayPerformance::with_budget(16);
        let start = diagnostic_clock();
        let measurement = diagnostics
            .begin_with_clocks(
                ReplayPhase::ThinLoad,
                || start,
                || Some(Duration::from_millis(2)),
            )
            .unwrap_or_else(|| panic!("enabled measurement absent"));
        diagnostics.finish_at(
            measurement,
            start + Duration::from_millis(100),
            Some(Duration::from_millis(5)),
            1,
            false,
        );
        diagnostics.active_leg = ReplayLeg::Thin;
        diagnostics.contexts[1].pid = Some(123);
        diagnostics.contexts[1].start_ticks = Some(456);
        diagnostics.observe_physical(10);
        for failed in [false, true] {
            let measurement = diagnostics
                .begin_with_clocks(
                    ReplayPhase::Advance,
                    || start,
                    || Some(Duration::from_millis(5)),
                )
                .unwrap_or_else(|| panic!("enabled measurement absent"));
            diagnostics.finish_at(
                measurement,
                start + Duration::from_millis(20),
                Some(Duration::from_millis(6)),
                3,
                failed,
            );
        }
        diagnostics.observe_physical(30);
        let mut bytes = Vec::new();
        diagnostics.report_to(&mut bytes, "error", start + Duration::from_secs(1));
        let text = String::from_utf8(bytes.clone())
            .unwrap_or_else(|error| panic!("invalid diagnostic UTF-8: {error}"));
        assert!(text.contains("phase=thin-load status=error pid=Some(123)"));
        assert!(text.contains("calls=2 errors=1 wall_us=40000 worker_cpu_us=2000"));
        assert!(text.contains("first_ps=Some(10) last_ps=Some(30)"));
        assert_eq!(text.lines().count(), 2);
        diagnostics.report_to(&mut bytes, "dropped", start);
        assert_eq!(bytes, text.as_bytes());
        assert!(
            diagnostics
                .begin_with_clocks(
                    ReplayPhase::Advance,
                    || panic!("reported wall clock"),
                    || panic!("reported CPU clock")
                )
                .is_none()
        );
    }

    #[test]
    fn row_budget_failed_cpu_observation_and_sink_errors_are_advisory() {
        let mut diagnostics = ReplayPerformance::with_budget(1);
        let start = diagnostic_clock();
        for phase in [ReplayPhase::ExactLoad, ReplayPhase::ChoiceDrain] {
            let measurement = diagnostics
                .begin_with_clocks(phase, || start, || None)
                .unwrap_or_else(|| panic!("enabled measurement absent"));
            diagnostics.finish_at(measurement, start, None, 7, true);
        }
        let mut bytes = Vec::new();
        diagnostics.report_to(&mut bytes, "error", start);
        let text = String::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("invalid diagnostic UTF-8: {error}"));
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("worker_cpu_us=unavailable"));
        assert!(text.len() <= 512);
        assert_eq!(diagnostics.remaining_rows, 0);

        let mut diagnostics = ReplayPerformance::with_budget(16);
        let measurement = diagnostics
            .begin_with_clocks(ReplayPhase::Advance, || start, || None)
            .unwrap_or_else(|| panic!("enabled measurement absent"));
        diagnostics.finish_at(measurement, start, None, 0, true);
        struct FailedSink;
        impl Write for FailedSink {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        diagnostics.report_to(&mut FailedSink, "error", start);
        assert!(diagnostics.reported);

        let mut diagnostics = ReplayPerformance::with_budget(u16::MAX);
        diagnostics.contexts.fill(LegContext {
            pid: Some(u32::MAX),
            start_ticks: Some(u64::MAX),
            first_ps: Some(u64::MAX),
            last_ps: Some(u64::MAX),
            observation_generation: u64::MAX,
        });
        for leg in &mut diagnostics.totals {
            leg.fill(Totals {
                calls: u64::MAX,
                errors: u64::MAX,
                wall: Duration::MAX,
                worker_cpu: Duration::MAX,
                cpu_unavailable: false,
            });
        }
        let mut bytes = Vec::new();
        diagnostics.report_to(&mut bytes, "completed", start);
        let text = String::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("invalid diagnostic UTF-8: {error}"));
        assert_eq!(text.lines().count(), usize::from(MAX_REPORT_ROWS));
        // Reserve the full Duration::MAX decimal width for session wall time,
        // whose value is zero here because no synthetic Instant was advanced.
        assert!(text.lines().all(|line| line.len() + 1 + 26 <= 512));
    }
}
