//! The `gate:perf-bench` cost-model substrate.
//!
//! This module owns the performance-benchmark gate of RFC-0010 file 25
//! ([`25-performance-targets.md`]). It is the *measurement and assertion*
//! substrate: it models the SS25.1 cost model
//!
//! ```text
//!   wall_clock  ~=  (sum busy_i) / (IPS_tcg x P)  +  T_amortized_boot  +  T_sync_overhead
//! ```
//!
//! attributes wall-clock to each term separately ([PERF-1]), and exposes the
//! SS25.7.1 metric set as a [`PerfBenchReport`] so the gate can assert the
//! *structural and relative* properties the RFC requires while *recording* the
//! raw numbers for humans and trend tracking.
//!
//! # The regression-gate discipline
//!
//! Unlike every determinism gate, `gate:perf-bench` is a *regression* gate
//! ([PERF-19]): it compares metrics against a stored baseline and fails on a
//! per-metric regression beyond a configured threshold, rather than asserting
//! byte-identity. Because it runs on a shared, noisy builder, the gate asserts
//! *host-independent* properties wherever possible ([PERF-20])  --  ratios,
//! monotonicity, syscall counts, and flatness  --  and tolerance-bands the few
//! unavoidable wall-clock numbers (restore latency, throughput). Absolute
//! wall-clock thresholds are never hard-asserted here; they are recorded.
//!
//! # What the substrate models
//!
//! The gate must run hermetically with no QEMU, so this module carries a
//! deterministic *cost-model simulator*: a closed-form evaluation of the SS25.1
//! equation for a described [`BenchScenario`]. Given a scenario's busy
//! instruction counts, idle spans, link latencies, core budget, and fault/plugin
//! configuration, [`evaluate_cost_model`] computes the modeled wall-clock and its
//! term breakdown deterministically. This lets the gate assert the *relations*
//! the RFC pins ("idle contributes zero", "parallelism scales with lookahead",
//! "serial and parallel are bit-identical") without a live VM, exactly the way
//! the mock e2e artifact lets `gate:e2e-determinism` run without a VM. Real
//! wall-clock timing of the host lives in the gate *test target*, not here, so
//! the workspace determinism lints do not fire on this reduction-path crate.
//!
//! # Module map
//!
//! - [`admission`]  --  the Class A/Class B host-parallelism register and its
//!   fail-closed validator ([PERF-34]).
//! - [`model`]  --  the [`BenchScenario`] inputs, the [`CostModelBreakdown`], and
//!   [`evaluate_cost_model`]/[`realized_parallelism`] (the SS25.1 evaluator).
//! - [`sweeps`]  --  the SS25 parameter sweeps ([`latency_parallelism_sweep`],
//!   [`core_count_speedup_sweep`], [`rendezvous_frequency_sweep`],
//!   [`fleet_host_sweep`]) and the derived host-independent metrics
//!   ([`advance_syscall_count`], [`snapshot_latency_series`],
//!   [`canonical_host_profile`], [`perf_corpus_digest`],
//!   [`scenario_result_fingerprint`]).
//! - [`report`]  --  the [`PerfBenchReport`] metric set, the [`PerfBaseline`], the
//!   [`PerfBenchInput`], and the [`PerfBenchError`] failure taxonomy.
//! - [`gate`]  --  [`run_perf_bench_gate`], the assertion pass, plus the modeled
//!   [`fork_cost_bytes`]/[`replay_cost_units`]/[`peak_rss_units`] helpers.
//! - [`corpus`]  --  the canonical hermetic corpus, baseline, and gate input.
//!
//! [`25-performance-targets.md`]: ../../../docs/rfcs/0010-crucible/25-performance-targets.md

pub mod admission;
pub mod corpus;
pub mod gate;
pub mod model;
pub mod report;
pub mod sweeps;

pub use admission::{
    DEVICE_WORK_OVERLAP, FINGERPRINT_DIGEST_OFFLOAD, HOST_WORKER_POOL, HostParallelismAdmission,
    HostParallelismClass, SEGMENT_PARALLEL_REPLAY, TRANSLATION_PREFETCH,
    canonical_host_parallelism_admissions, validate_host_parallelism_admissions,
};
pub use corpus::{canonical_bench_corpus, canonical_perf_baseline, canonical_perf_bench_input};
pub use gate::{fork_cost_bytes, peak_rss_units, replay_cost_units, run_perf_bench_gate};
pub use model::{
    BenchLink, BenchNode, BenchScenario, COVERAGE_ON_MIN_PCT, CostModelBreakdown, CoverageMode,
    RealizationConfig, SYNC_OVERHEAD_FAIL_PCT, SYNC_OVERHEAD_WARN_PCT, TCG_FLOOR_MAX,
    TCG_FLOOR_MIN, THROUGHPUT_REGRESSION_MAX_PCT, evaluate_cost_model, realized_parallelism,
};
pub use report::{PerfBaseline, PerfBenchError, PerfBenchInput, PerfBenchReport};
pub use sweeps::{
    AdvanceSyscallCount, CoreCountPoint, FleetHostPoint, HostProfile, LatencyParallelismPoint,
    RendezvousPoint, SnapshotLatencyPoint, advance_syscall_count, canonical_host_profile,
    core_count_speedup_sweep, fleet_host_sweep, latency_parallelism_sweep, perf_corpus_digest,
    rendezvous_frequency_sweep, scenario_result_fingerprint, snapshot_latency_series,
};
