//! The SS25.7.1 metric report, the regression baseline, and the gate error type.
//!
//! This module owns the data the perf-bench gate *records* and *compares*: the
//! [`PerfBenchReport`] aggregating every SS25.7.1 metric term, the stored
//! [`PerfBaseline`] the regression gate compares against ([PERF-19], [PERF-21]),
//! the [`PerfBenchInput`] pairing a corpus with its baseline, and the
//! [`PerfBenchError`] enumerating every cost-model property the gate can find
//! violated. The assertion logic that produces a report or an error lives in
//! [`super::gate`].

use std::error::Error;
use std::fmt;

use super::admission::HostParallelismAdmission;
use super::model::{
    BenchScenario, COVERAGE_ON_MIN_PCT, SYNC_OVERHEAD_FAIL_PCT, THROUGHPUT_REGRESSION_MAX_PCT,
};
use super::sweeps::{AdvanceSyscallCount, HostProfile, SnapshotLatencyPoint};

/// The SS25.7.1 metric set, one aggregate over the benchmark corpus.
///
/// Every field is *recorded* for humans and trend tracking; the gate asserts the
/// structural/relative properties described in [`super::gate::run_perf_bench_gate`].
/// Ratios and counts are host-independent ([PERF-20]); the wall-clock fields
/// (`restore_latency_units`) are recorded, never hard-asserted against an
/// absolute threshold on a shared builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerfBenchReport {
    /// `tcg_ips`: modeled retired guest instructions per host second.
    pub tcg_ips: u64,
    /// `idle_compression`: wall-clock across an idle sweep; MUST be flat.
    pub idle_compression: Vec<u64>,
    /// `parallelism_P`: realized concurrent-node factor.
    pub parallelism_p: u64,
    /// `sync_overhead_pct`: non-execution wall-clock / busy wall-clock.
    pub sync_overhead_pct: u64,
    /// `per_tb_ns`: plugin per-TB overhead, in modeled atomic operations.
    pub per_tb_atomics: u64,
    /// `boot_amortization`: cold boots per M-scenario campaign.
    pub cold_boots_per_campaign: u64,
    /// `restore_latency`: loadvm/replay to-runnable latency (recorded units).
    pub restore_latency_units: u64,
    /// `fuzz_throughput`: scenarios per core per hour.
    pub fuzz_throughput: u64,
    /// `coverage_on_off`: guest IPS coverage-on / coverage-off ratio (percent).
    pub coverage_on_off_pct: u64,
    /// `fork_cost`: modeled fork cost (bytes) as a function of delta size.
    pub fork_cost_bytes: Vec<u64>,
    /// `replay_cost`: modeled replay time as a function of suffix length.
    pub replay_cost_by_suffix: Vec<u64>,
    /// Peak host RSS over a representative search ([PERF-23]).
    pub peak_rss_units: u64,
    /// Arithmetic advance-path kernel-entry accounting ([PERF-8]).
    pub advance_syscalls: AdvanceSyscallCount,
    /// The snapshot capture/restore latency series ([PERF-12], [PERF-17]).
    pub snapshot_latency: Vec<SnapshotLatencyPoint>,
    /// The pinned host profile the gate ran against ([PERF-20]).
    pub host_profile: HostProfile,
    /// The content-addressed corpus+baseline digest ([PERF-21]).
    pub corpus_digest: u64,
}

/// A `gate:perf-bench` failure: a violated cost-model property or a regression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerfBenchError {
    /// The corpus is empty; the gate requires at least one benchmark scenario.
    EmptyCorpus,
    /// Wall-clock scaled with idle virtual duration rather than staying flat
    /// ([PERF-2]).
    IdleNotCompressed {
        /// The observed wall-clock series across the idle sweep.
        observed: Vec<u64>,
    },
    /// Realized parallelism did not increase with the lookahead budget ([PERF-4]).
    ParallelismNotLookaheadBounded {
        /// The latency/parallelism sweep that violated monotonicity.
        smaller_latency: u64,
        /// The realized parallelism that failed to rise.
        larger_latency: u64,
    },
    /// Adding cores did not reduce wall-clock ([PERF-3]).
    SpeedupNotMonotone {
        /// Core count whose wall-clock rose.
        cores: u64,
    },
    /// A serial (`P=1`) and parallel run produced different result fingerprints
    /// ([PERF-5]).
    SerialParallelDivergence {
        /// The serial fingerprint.
        serial: u64,
        /// The parallel fingerprint.
        parallel: u64,
    },
    /// A low-latency scenario failed determinism instead of merely losing
    /// parallelism ([PERF-6]).
    LowLatencyDeterminismLoss {
        /// The baseline fingerprint.
        baseline: u64,
        /// The low-latency fingerprint.
        low_latency: u64,
    },
    /// Sync overhead exceeded the hard-fail threshold ([PERF-7]).
    SyncOverheadExceeded {
        /// The observed sync overhead percentage.
        observed_pct: u64,
    },
    /// Per-TB plugin overhead scaled with node count ([PERF-9]).
    PerTbScalesWithNodes {
        /// The small-scenario per-TB atomics.
        small: u64,
        /// The large-scenario per-TB atomics.
        large: u64,
    },
    /// A rendezvous-frequency sweep changed the result fingerprint ([PERF-10]).
    RendezvousChangedResult {
        /// The rendezvous frequency that changed the result.
        rendezvous_frequency: u64,
    },
    /// Cold boots scaled with campaign size instead of staying at one per VM
    /// per `World` ([PERF-11]).
    BootNotAmortized {
        /// The observed cold-boot count.
        observed: u64,
        /// The campaign scenario count.
        campaign_size: u64,
    },
    /// The coverage-on guest IPS fell below the configured ratio ([PERF-14]).
    CoverageOnBelowBudget {
        /// The observed coverage-on/off ratio percentage.
        observed_pct: u64,
    },
    /// Coverage extraction changed the result fingerprint ([PERF-15]).
    CoveragePerturbedResult {
        /// The coverage-off fingerprint.
        coverage_off: u64,
        /// The coverage-on fingerprint.
        coverage_on: u64,
    },
    /// Fork cost scaled with absolute state size rather than delta ([PERF-16]).
    ForkCostNotDeltaBounded {
        /// The fork cost that failed to track delta size.
        delta: u64,
    },
    /// Replay cost was not bounded by the schedule suffix length ([PERF-18]).
    ReplayCostNotSuffixBounded {
        /// The suffix length whose replay cost fell out of order.
        suffix: u64,
    },
    /// Fuzzing throughput regressed beyond the tolerated fraction of baseline
    /// ([PERF-13]).
    ThroughputRegressed {
        /// The recorded baseline throughput.
        baseline: u64,
        /// The observed throughput.
        observed: u64,
    },
    /// Fleet throughput did not scale near-linearly to saturation ([PERF-27]).
    FleetThroughputNotLinear {
        /// The host count whose aggregate throughput fell out of order.
        hosts: u64,
    },
    /// Cumulative campaign coverage decreased across CI runs ([PERF-28]).
    CoverageRegressed {
        /// The prior cumulative coverage.
        prior: u64,
        /// The next cumulative coverage.
        next: u64,
    },
    /// Peak host RSS scaled with fork count rather than with guest RAM + active
    /// rings + sum deltas ([PERF-23]).
    RssScalesWithForkCount {
        /// The fork count whose RSS rose out of proportion.
        forks: u64,
    },
    /// The advance path modeled a per-quantum socket/control round trip ([PERF-8]).
    PerQuantumIpcRoundTrip {
        /// The number of modeled socket/QMP/plugin-control round trips.
        round_trips: u64,
    },
    /// Advance-path kernel-entry bookkeeping differed from the expected model.
    AdvanceKernelEntryAccounting {
        /// The kernel-entry category whose arithmetic differed.
        entry: &'static str,
        /// The count required by the current cost model.
        expected: u64,
        /// The count produced by the arithmetic bookkeeping.
        actual: u64,
    },
    /// Snapshot capture cost scaled with total state rather than changed state
    /// ([PERF-17]).
    CaptureNotChangedStateBounded {
        /// The changed-page count whose capture cost fell out of order.
        changed_pages: u64,
    },
    /// A required host-parallel mechanism has no admission record ([PERF-34]).
    MissingHostParallelismAdmission {
        /// Stable identifier of the missing mechanism.
        mechanism: String,
    },
    /// A host-parallel admission is duplicate, empty, or lacks proof ([PERF-34]).
    InvalidHostParallelismAdmission {
        /// Stable identifier of the invalid mechanism.
        mechanism: String,
    },
}

impl fmt::Display for PerfBenchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCorpus => write!(formatter, "perf-bench requires a non-empty corpus"),
            Self::IdleNotCompressed { observed } => write!(
                formatter,
                "idle virtual duration must not add wall-clock; observed series {observed:?}"
            ),
            Self::ParallelismNotLookaheadBounded {
                smaller_latency,
                larger_latency,
            } => write!(
                formatter,
                "realized parallelism must not fall as link latency rises from {smaller_latency} to {larger_latency}"
            ),
            Self::SpeedupNotMonotone { cores } => write!(
                formatter,
                "adding cores must not raise wall-clock; regressed at {cores} cores"
            ),
            Self::SerialParallelDivergence { serial, parallel } => write!(
                formatter,
                "serial and parallel runs must be bit-identical: serial {serial:#018x} parallel {parallel:#018x}"
            ),
            Self::LowLatencyDeterminismLoss {
                baseline,
                low_latency,
            } => write!(
                formatter,
                "a low-latency scenario must stay deterministic: baseline {baseline:#018x} low-latency {low_latency:#018x}"
            ),
            Self::SyncOverheadExceeded { observed_pct } => write!(
                formatter,
                "sync overhead {observed_pct}% exceeds the {SYNC_OVERHEAD_FAIL_PCT}% hard-fail threshold"
            ),
            Self::PerTbScalesWithNodes { small, large } => write!(
                formatter,
                "per-TB plugin overhead must be node-count-independent: {small} vs {large} atomics"
            ),
            Self::RendezvousChangedResult {
                rendezvous_frequency,
            } => write!(
                formatter,
                "rendezvous frequency {rendezvous_frequency} changed the result fingerprint"
            ),
            Self::BootNotAmortized {
                observed,
                campaign_size,
            } => write!(
                formatter,
                "cold boots ({observed}) must be independent of the {campaign_size}-scenario campaign size"
            ),
            Self::CoverageOnBelowBudget { observed_pct } => write!(
                formatter,
                "coverage-on guest IPS ({observed_pct}%) is below the {COVERAGE_ON_MIN_PCT}% budget"
            ),
            Self::CoveragePerturbedResult {
                coverage_off,
                coverage_on,
            } => write!(
                formatter,
                "coverage extraction must be observation-only: off {coverage_off:#018x} on {coverage_on:#018x}"
            ),
            Self::ForkCostNotDeltaBounded { delta } => write!(
                formatter,
                "fork cost must scale with delta {delta}, not absolute state size"
            ),
            Self::ReplayCostNotSuffixBounded { suffix } => write!(
                formatter,
                "replay cost must be bounded by suffix length; regressed at suffix {suffix}"
            ),
            Self::ThroughputRegressed { baseline, observed } => write!(
                formatter,
                "fuzz throughput regressed beyond {THROUGHPUT_REGRESSION_MAX_PCT}%: baseline {baseline} observed {observed}"
            ),
            Self::FleetThroughputNotLinear { hosts } => write!(
                formatter,
                "fleet throughput must scale near-linearly to saturation; regressed at {hosts} hosts"
            ),
            Self::CoverageRegressed { prior, next } => write!(
                formatter,
                "cumulative campaign coverage must be monotone non-decreasing: {prior} then {next}"
            ),
            Self::RssScalesWithForkCount { forks } => write!(
                formatter,
                "peak RSS must not scale with fork count; regressed at {forks} forks"
            ),
            Self::PerQuantumIpcRoundTrip { round_trips } => write!(
                formatter,
                "the advance path must model no per-quantum socket/control round trip; found {round_trips}"
            ),
            Self::AdvanceKernelEntryAccounting {
                entry,
                expected,
                actual,
            } => write!(
                formatter,
                "advance-path {entry} bookkeeping expected {expected}, found {actual}"
            ),
            Self::CaptureNotChangedStateBounded { changed_pages } => write!(
                formatter,
                "snapshot capture must scale with changed state; regressed at {changed_pages} pages"
            ),
            Self::MissingHostParallelismAdmission { mechanism } => write!(
                formatter,
                "host-parallel mechanism {mechanism} has no admission record"
            ),
            Self::InvalidHostParallelismAdmission { mechanism } => write!(
                formatter,
                "host-parallel mechanism {mechanism} has no unique class argument and proving gate"
            ),
        }
    }
}

impl Error for PerfBenchError {}

/// A stored baseline for the regression-gate comparison ([PERF-19], [PERF-21]).
///
/// The gate compares the run's throughput and coverage ratio against these
/// stored values and fails on a regression beyond the configured threshold; a
/// baseline update is an explicit, reviewed change recorded in the decision
/// register, never a silent laundering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfBaseline {
    /// The recorded fuzzing-throughput baseline (scenarios / core / hour).
    pub fuzz_throughput: u64,
    /// The recorded coverage-on/off ratio baseline (percent).
    pub coverage_on_off_pct: u64,
    /// The prior cumulative campaign coverage (basic blocks).
    pub cumulative_coverage: u64,
}

/// The full input to the perf-bench gate: a corpus plus its stored baseline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerfBenchInput {
    /// The benchmark corpus: a small set of hermetic scenarios ([PERF-21]).
    pub corpus: Vec<BenchScenario>,
    /// The stored baseline for the regression comparison.
    pub baseline: PerfBaseline,
    /// This run's measured fuzzing throughput (scenarios / core / hour).
    pub observed_fuzz_throughput: u64,
    /// This run's cumulative campaign coverage ([PERF-28]).
    pub cumulative_coverage: u64,
    /// Admission records for every enabled or experimentally gated host-parallel mechanism.
    pub host_parallelism_admissions: Vec<HostParallelismAdmission>,
}
