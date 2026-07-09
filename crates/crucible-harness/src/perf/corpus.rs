//! The canonical hermetic perf-bench corpus, baseline, and gate input.
//!
//! This module owns the content-addressable reference benchmark corpus and its
//! stored baseline ([PERF-21], [PERF-19]): a small, deterministic fan-out
//! scenario and the [`PerfBaseline`] the regression gate compares against. Their
//! identities travel together  --  [`canonical_perf_bench_input`] pairs them.

use super::model::{BenchLink, BenchNode, BenchScenario, CoverageMode};
use super::report::{PerfBaseline, PerfBenchInput};

/// Returns the canonical hermetic benchmark corpus for the reference guest.
///
/// The corpus is small, deterministic, and content-addressable ([PERF-21]): a
/// representative fan-out scenario with realistic busy/idle mix, links at the
/// recommended operating point, and the coverage hook enabled. Its identity and
/// baseline travel together.
///
/// The topology is a coordinator feeding four *independent* workers (the workers
/// do not depend on each other), so the critical path  --  the coordinator plus one
/// worker  --  is well below total busy work. This makes the parallelism sweeps
/// non-trivial: realized `P` rises with cores and with the lookahead budget,
/// bounded by the coordinator->worker critical path (SS25.2.2), rather than
/// collapsing to `P = 1` the way a pure causal chain would.
#[must_use]
pub fn canonical_bench_corpus() -> Vec<BenchScenario> {
    let mut nodes = vec![BenchNode {
        name: String::from("coordinator"),
        busy_instructions: 2_000_000,
        idle_ticks: 60_000,
    }];
    let mut links = Vec::new();
    for index in 0..4u64 {
        let worker = format!("worker-{index}");
        nodes.push(BenchNode {
            name: worker.clone(),
            busy_instructions: 4_000_000,
            idle_ticks: 45_000 + index * 5_000,
        });
        links.push(BenchLink {
            from: String::from("coordinator"),
            to: worker,
            // Links at the recommended operating point (well above the floor).
            latency_ticks: 8,
        });
    }
    vec![BenchScenario {
        name: String::from("perf-reference-fanout"),
        nodes,
        links,
        // Native / TCG-floor: a modeled TCG rate consistent with the 10-20x floor.
        tcg_ips: 200_000_000,
        cores: 4,
        per_tb_atomics: 3,
        coverage: CoverageMode::On,
    }]
}

/// Returns the canonical stored baseline for the reference corpus ([PERF-19]).
#[must_use]
pub fn canonical_perf_baseline() -> PerfBaseline {
    PerfBaseline {
        fuzz_throughput: 50_000,
        coverage_on_off_pct: 82,
        cumulative_coverage: 12_800,
    }
}

/// Returns the canonical perf-bench gate input: the reference corpus and its
/// stored baseline, with a clean (non-regressing) cumulative coverage.
#[must_use]
pub fn canonical_perf_bench_input() -> PerfBenchInput {
    let baseline = canonical_perf_baseline();
    PerfBenchInput {
        corpus: canonical_bench_corpus(),
        cumulative_coverage: baseline.cumulative_coverage,
        baseline,
    }
}
