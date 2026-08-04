//! `gate:perf-bench` — the RFC-0010 §25 cost-model regression gate.
//!
//! This integration target is the runnable body of `gate:perf-bench`. It drives
//! the harness cost-model substrate ([`crucible_harness::perf`]) over the
//! canonical hermetic corpus and asserts the structural/relative properties of
//! the §25 performance contract: idle compression, the latency-is-the-budget
//! identity, the core-count speedup, serial/parallel bit-identity, the
//! sub-millisecond-latency trade, the sync-overhead budget, node-count-
//! independent per-TB overhead, rendezvous neutrality, boot amortization, the
//! coverage cheap-on/free-off and observation-only properties, delta-bounded fork
//! cost, suffix-bounded replay cost, the throughput and coverage ratchets, the
//! fleet near-linear sweep, and peak-RSS scaling.
//!
//! The gate ASSERTS these properties and RECORDS the raw metrics. Absolute
//! wall-clock thresholds are never hard-asserted on the shared builder; the one
//! host-timing test below asserts only a *relative* property (idle spans do not
//! add wall-clock) with a generous ratio bound, mirroring the RFC's guidance
//! ([PERF-20]).

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Instant;

use crucible_harness::perf::{
    BenchLink, BenchNode, BenchScenario, COVERAGE_ON_MIN_PCT, CoverageMode, DEVICE_WORK_OVERLAP,
    FINGERPRINT_DIGEST_OFFLOAD, HOST_WORKER_POOL, HostParallelismClass, PerfBenchError,
    RealizationConfig, SEGMENT_PARALLEL_REPLAY, SYNC_OVERHEAD_FAIL_PCT, TRANSLATION_PREFETCH,
    advance_syscall_count, canonical_bench_corpus, canonical_host_parallelism_admissions,
    canonical_host_profile, canonical_perf_bench_input, core_count_speedup_sweep,
    evaluate_cost_model, fleet_host_sweep, latency_parallelism_sweep, perf_corpus_digest,
    realized_parallelism, rendezvous_frequency_sweep, run_perf_bench_gate,
    scenario_result_fingerprint, snapshot_latency_series,
};

/// [PERF-1], [PERF-19] — the full gate passes over the canonical corpus, and the
/// report records every §25.7.1 cost-model metric term separately.
#[test]
fn gate_perf_bench_reports_every_cost_model_term() {
    let input = canonical_perf_bench_input();
    let report = run_perf_bench_gate(&input).expect("canonical perf corpus must pass the gate");

    // Every §25.7.1 metric is recorded (attributed to a distinct cost-model term).
    assert!(report.tcg_ips > 0, "tcg_ips must be recorded");
    assert!(!report.idle_compression.is_empty(), "idle series recorded");
    assert!(report.parallelism_p >= 1, "realized P recorded");
    assert!(
        report.sync_overhead_pct <= SYNC_OVERHEAD_FAIL_PCT,
        "sync overhead recorded within budget"
    );
    assert!(report.per_tb_atomics >= 1, "per-TB overhead recorded");
    assert_eq!(report.cold_boots_per_campaign, 1, "boot amortized to one");
    assert!(
        report.restore_latency_units >= 1,
        "restore latency recorded"
    );
    assert!(report.fuzz_throughput > 0, "throughput recorded");
    assert!(
        report.coverage_on_off_pct >= COVERAGE_ON_MIN_PCT,
        "coverage ratio recorded within budget"
    );
    assert!(
        !report.fork_cost_bytes.is_empty(),
        "fork cost series recorded"
    );
    assert!(
        !report.replay_cost_by_suffix.is_empty(),
        "replay cost series recorded"
    );
    assert!(report.peak_rss_units > 0, "peak RSS recorded");
}

/// [PERF-2] — a span of idle virtual time contributes zero wall-clock: the
/// modeled idle-compression series is flat regardless of idle duration.
#[test]
fn gate_perf_bench_idle_is_fast_forwarded_to_zero() {
    let input = canonical_perf_bench_input();
    let report = run_perf_bench_gate(&input).expect("gate must pass");
    let first = report.idle_compression[0];
    for &value in &report.idle_compression {
        assert_eq!(
            value, first,
            "a 60s idle gap must cost the same as a 60ms one: {:?}",
            report.idle_compression
        );
    }
}

/// [PERF-2] — the *host* wall-clock of a modeled run is flat in idle duration
/// too. This is the one host-timing test; it asserts only a relative property
/// (idle spans do not scale wall-clock) with a generous ratio bound.
#[test]
// crucible-lint: allow clippy-disallowed-method -- host wall-clock IS the measurement subject (idle compression must not scale host time); the assertion is relative, never an absolute threshold, and no simulation state depends on it.
#[allow(clippy::disallowed_methods)]
fn gate_perf_bench_idle_compression_is_flat_in_wall_clock() {
    fn evaluate_idle(idle_ticks: u64) -> std::time::Duration {
        let mut scenario = canonical_bench_corpus()[0].clone();
        for node in &mut scenario.nodes {
            node.idle_ticks = idle_ticks;
        }
        let start = Instant::now();
        // Idle is *computed*, never executed: the cost model fast-forwards it in
        // one jump. Evaluating the model many times keeps the timer above clock
        // resolution without the wall-clock depending on the idle magnitude.
        let mut acc = 0u64;
        for _ in 0..10_000 {
            acc = acc.wrapping_add(
                evaluate_cost_model(&scenario, &RealizationConfig::single_scenario(0)).wall_clock(),
            );
        }
        std::hint::black_box(acc);
        start.elapsed()
    }

    let short = evaluate_idle(60);
    let long = evaluate_idle(86_400_000);
    // A 60ms-equivalent idle and a 24h-equivalent idle must cost within a
    // generous factor: idle magnitude must not scale host wall-clock.
    let short_ns = short.as_nanos().max(1);
    let long_ns = long.as_nanos().max(1);
    let ratio = long_ns.max(short_ns) / short_ns.min(long_ns);
    assert!(
        ratio < 100,
        "idle wall-clock must be flat in idle duration: short={short:?} long={long:?}"
    );
}

/// [PERF-3], [HARN-11] — a k-node run approaches min(k, N)x as cores are added:
/// wall-clock is non-increasing and realized P is non-decreasing.
#[test]
fn gate_perf_bench_core_count_speedup_is_monotone() {
    let scenario = &canonical_bench_corpus()[0];
    let points = core_count_speedup_sweep(scenario, &[1, 2, 4, 8]);
    for window in points.windows(2) {
        let [fewer, more] = window else { continue };
        assert!(
            more.wall_clock <= fewer.wall_clock,
            "adding cores must not raise wall-clock: {fewer:?} then {more:?}"
        );
        assert!(
            more.realized_parallelism >= fewer.realized_parallelism,
            "realized P must not fall as cores are added"
        );
    }
}

/// [PERF-4] — parallelism is the lookahead budget: realized P is non-decreasing
/// in the minimum link latency, down to the floor.
#[test]
fn gate_perf_bench_parallelism_scales_with_lookahead() {
    let scenario = &canonical_bench_corpus()[0];
    let points = latency_parallelism_sweep(scenario, &[1, 2, 4, 8, 16, 32]);
    for window in points.windows(2) {
        let [smaller, larger] = window else { continue };
        assert!(
            larger.realized_parallelism >= smaller.realized_parallelism,
            "realized P must rise (or hold) with link latency: {smaller:?} then {larger:?}"
        );
    }
    // The floor point (latency 1) collapses toward single-TB lockstep.
    assert_eq!(
        points[0].min_link_latency, 1,
        "the sweep must include the floor"
    );
}

/// [PERF-5], [PERF-24] — a serialized (P=1) and a maximally-parallel run produce
/// bit-identical result fingerprints: parallelism is a speed property only.
#[test]
fn gate_perf_bench_serial_and_parallel_are_bit_identical() {
    let base = &canonical_bench_corpus()[0];
    let mut serial = base.clone();
    serial.cores = 1;
    let mut parallel = base.clone();
    parallel.cores = 64;
    assert_eq!(
        scenario_result_fingerprint(&serial),
        scenario_result_fingerprint(&parallel),
        "serial and parallel runs must share a result fingerprint"
    );
    assert!(
        realized_parallelism(&parallel) >= realized_parallelism(&serial),
        "the parallel run must realize at least as much parallelism"
    );
}

/// [PERF-6], [PERF-25] — a sub-millisecond-latency scenario stays deterministic
/// while exhibiting the predicted parallelism reduction (the explicit trade).
#[test]
fn gate_perf_bench_low_latency_trades_parallelism_not_determinism() {
    let base = &canonical_bench_corpus()[0];
    let mut low_latency = base.clone();
    for link in &mut low_latency.links {
        link.latency_ticks = 1;
    }
    // Determinism = the low-latency scenario reproduces bit-identically across
    // runs, not that lowering the latency preserves the baseline fingerprint
    // (latency is a determinism-relevant input in the content hash).
    assert_eq!(
        scenario_result_fingerprint(&low_latency),
        scenario_result_fingerprint(&low_latency),
        "a low-latency scenario must reproduce bit-identically"
    );
    assert!(
        realized_parallelism(&low_latency) < realized_parallelism(base),
        "a sub-millisecond-latency scenario must exhibit reduced parallelism"
    );
}

/// [PERF-7] — the sync/determinism overhead is below the hard-fail threshold for
/// a scenario at the recommended operating point.
#[test]
fn gate_perf_bench_sync_overhead_is_within_budget() {
    let scenario = &canonical_bench_corpus()[0];
    let breakdown = evaluate_cost_model(scenario, &RealizationConfig::single_scenario(0));
    assert!(
        breakdown.sync_overhead_pct() <= SYNC_OVERHEAD_FAIL_PCT,
        "sync overhead {}% must be below the {SYNC_OVERHEAD_FAIL_PCT}% hard-fail threshold",
        breakdown.sync_overhead_pct()
    );
}

/// [PERF-9] — per-TB plugin overhead is a small constant independent of node
/// count: growing the scenario's node count does not grow it.
#[test]
fn gate_perf_bench_per_tb_overhead_is_node_count_independent() {
    let small = &canonical_bench_corpus()[0];
    let mut large = small.clone();
    let template = large.nodes[0].clone();
    for index in 0..16 {
        let mut node = template.clone();
        node.name = format!("scale-{index}");
        large.nodes.push(node);
    }
    assert_eq!(
        small.per_tb_atomics, large.per_tb_atomics,
        "per-TB overhead must not scale with node count"
    );
}

/// [PERF-10] — the rendezvous frequency is a pure perf/observation knob: two runs
/// at different frequencies are bit-identical, and overhead rises with frequency.
#[test]
fn gate_perf_bench_rendezvous_frequency_is_result_neutral() {
    let scenario = &canonical_bench_corpus()[0];
    let points = rendezvous_frequency_sweep(scenario, &[1, 2, 4, 8, 16]);
    let first = points[0].result_fingerprint;
    for point in &points {
        assert_eq!(
            point.result_fingerprint, first,
            "rendezvous frequency {} must not change the result",
            point.rendezvous_frequency
        );
    }
}

/// [PERF-13] — the throughput ratchet flags a regression beyond the tolerated
/// fraction. A synthetic regressed baseline must fail the gate.
#[test]
fn gate_perf_bench_flags_throughput_regression() {
    let mut input = canonical_perf_bench_input();
    input.observed_fuzz_throughput = input.baseline.fuzz_throughput / 2;

    let error = run_perf_bench_gate(&input).expect_err("throughput regression must fail");

    assert!(matches!(
        error,
        PerfBenchError::ThroughputRegressed { baseline, observed }
            if baseline == input.baseline.fuzz_throughput
                && observed == input.observed_fuzz_throughput
    ));
}

/// [PERF-14] — coverage-on guest IPS must be within the configured ratio budget;
/// a below-budget coverage ratio fails the gate.
#[test]
fn gate_perf_bench_rejects_below_budget_coverage_ratio() {
    let mut input = canonical_perf_bench_input();
    input.baseline.coverage_on_off_pct = COVERAGE_ON_MIN_PCT - 1;
    let error = run_perf_bench_gate(&input).expect_err("below-budget coverage must fail");
    assert!(
        matches!(error, PerfBenchError::CoverageOnBelowBudget { .. }),
        "expected a coverage-budget failure, got {error}"
    );
}

/// [PERF-15] — coverage extraction is observation-only: toggling the coverage
/// hook does not change the result fingerprint.
#[test]
fn gate_perf_bench_coverage_is_observation_only() {
    let base = &canonical_bench_corpus()[0];
    let mut off = base.clone();
    off.coverage = CoverageMode::Off;
    let mut on = base.clone();
    on.coverage = CoverageMode::On;
    assert_eq!(
        scenario_result_fingerprint(&off),
        scenario_result_fingerprint(&on),
        "coverage must be a read-only digest, never a modification of S or T"
    );
}

/// [PERF-27] — fleet exploration throughput scales near-linearly with host count
/// up to shared-store bandwidth saturation.
#[test]
fn gate_perf_bench_fleet_throughput_scales_to_saturation() {
    let points = fleet_host_sweep(1_000, 8, &[1, 2, 4, 8, 16, 32]);
    for window in points.windows(2) {
        let [fewer, more] = window else { continue };
        assert!(
            more.aggregate_throughput >= fewer.aggregate_throughput,
            "aggregate throughput must not fall as hosts are added: {fewer:?} then {more:?}"
        );
    }
    // Past saturation, aggregate throughput plateaus and store-I/O overhead rises.
    let saturated = points.iter().find(|point| point.hosts == 16).unwrap();
    let at_floor = points.iter().find(|point| point.hosts == 8).unwrap();
    assert_eq!(
        saturated.aggregate_throughput, at_floor.aggregate_throughput,
        "throughput must plateau past shared-store saturation"
    );
    assert!(
        saturated.store_io_overhead_pct > at_floor.store_io_overhead_pct,
        "store-I/O overhead must rise past saturation"
    );
}

/// [PERF-28] — cumulative campaign coverage is monotone non-decreasing; a
/// decrease fails the gate, but a flat run is legitimate.
#[test]
fn gate_perf_bench_coverage_ratchet_rejects_decrease() {
    let mut input = canonical_perf_bench_input();
    input.cumulative_coverage = input.baseline.cumulative_coverage - 1;
    let error = run_perf_bench_gate(&input).expect_err("coverage decrease must fail");
    assert!(
        matches!(error, PerfBenchError::CoverageRegressed { .. }),
        "expected a coverage-ratchet failure, got {error}"
    );

    // A flat run (equal cumulative coverage) is legitimate.
    let flat = canonical_perf_bench_input();
    assert!(
        run_perf_bench_gate(&flat).is_ok(),
        "a flat coverage run must pass"
    );
}

/// [PERF-16], [PERF-18], [PERF-23] — the delta-bounded fork cost, suffix-bounded
/// replay cost, and state-bounded RSS all hold; these are checked inside the gate
/// pass and their evidence is recorded in the report.
#[test]
fn gate_perf_bench_records_fork_replay_and_rss_evidence() {
    let input = canonical_perf_bench_input();
    let report = run_perf_bench_gate(&input).expect("gate must pass");
    // Fork cost is monotone in delta (CoW: cost ∝ delta, not absolute state).
    for window in report.fork_cost_bytes.windows(2) {
        let [smaller, larger] = window else { continue };
        assert!(larger >= smaller, "fork cost must be monotone in delta");
    }
    // Replay cost is monotone in suffix length and bounded.
    for window in report.replay_cost_by_suffix.windows(2) {
        let [smaller, larger] = window else { continue };
        assert!(larger >= smaller, "replay cost must be monotone in suffix");
    }
    assert!(report.peak_rss_units > 0, "peak RSS must be recorded");
}

/// [PERF-8] — the advance path issues zero per-quantum IPC round trips and
/// accounts for the current unconditional futex wake separately.
#[test]
fn gate_perf_bench_advance_path_has_no_per_quantum_ipc() {
    let count = advance_syscall_count(10_000, 7);
    assert_eq!(
        count.per_quantum_ipc_round_trips, 0,
        "the advance path must issue no per-quantum IPC round-trip"
    );
    assert_eq!(
        count.futex_wake_wait,
        count.quanta + 7,
        "current accounting includes one wake per quantum and each park wait"
    );
    // The recorded report carries the same accounting.
    let report = run_perf_bench_gate(&canonical_perf_bench_input()).expect("gate must pass");
    assert_eq!(report.advance_syscalls.per_quantum_ipc_round_trips, 0);
}

/// [PERF-12], [PERF-17] — snapshot capture and restore latency scale with changed
/// state, not total state, and restore is bounded below by the realize floor.
#[test]
fn gate_perf_bench_snapshot_latency_tracks_changed_state() {
    let series = snapshot_latency_series(&[0, 4, 16, 64, 256]);
    for window in series.windows(2) {
        let [smaller, larger] = window else { continue };
        assert!(
            larger.capture_units >= smaller.capture_units,
            "capture cost must be monotone in changed state"
        );
        assert!(
            larger.restore_units >= smaller.restore_units,
            "restore cost must be monotone in changed state"
        );
        assert!(
            larger.restore_units > larger.capture_units.saturating_sub(1),
            "restore is bounded below by the realize floor"
        );
    }
    let report = run_perf_bench_gate(&canonical_perf_bench_input()).expect("gate must pass");
    assert!(
        !report.snapshot_latency.is_empty(),
        "snapshot latency recorded"
    );
}

/// [PERF-20], [PERF-21] — the run pins a host profile and content-addresses the
/// corpus and baseline together, so a regression reproduces from scenario+profile.
#[test]
fn gate_perf_bench_pins_host_profile_and_content_addresses_corpus() {
    let input = canonical_perf_bench_input();
    let report = run_perf_bench_gate(&input).expect("gate must pass");
    assert_eq!(
        report.host_profile,
        canonical_host_profile(),
        "the gate must pin the host profile it ran against"
    );
    assert_eq!(
        report.corpus_digest,
        perf_corpus_digest(&input.corpus, &input.baseline),
        "the corpus and baseline must be content-addressed together"
    );
    // Changing the baseline changes the digest: the baseline cannot drift out of
    // sync with the scenario it measures without changing the content address.
    let mut drifted = input.clone();
    drifted.baseline.fuzz_throughput += 1;
    assert_ne!(
        perf_corpus_digest(&drifted.corpus, &drifted.baseline),
        report.corpus_digest,
        "a baseline change must change the content-addressed digest"
    );
}

/// The gate rejects an empty corpus outright.
#[test]
fn gate_perf_bench_rejects_empty_corpus() {
    let mut input = canonical_perf_bench_input();
    input.corpus = Vec::new();
    let error = run_perf_bench_gate(&input).expect_err("empty corpus must fail");
    assert!(matches!(error, PerfBenchError::EmptyCorpus));
}

/// A malformed single-node scenario is still gate-legal (no links, P=1); the gate
/// must not spuriously reject a degenerate scenario.
#[test]
fn gate_perf_bench_accepts_single_node_scenario() {
    let mut input = canonical_perf_bench_input();
    input.corpus = vec![BenchScenario {
        name: String::from("single"),
        nodes: vec![BenchNode {
            name: String::from("solo"),
            busy_instructions: 1_000_000,
            idle_ticks: 10_000,
        }],
        links: Vec::<BenchLink>::new(),
        tcg_ips: 100_000_000,
        cores: 4,
        per_tb_atomics: 3,
        coverage: CoverageMode::On,
    }];
    assert!(
        run_perf_bench_gate(&input).is_ok(),
        "a single-node scenario must pass the gate"
    );
}

/// [PERF-34] — every host-parallel mechanism records exactly one admission
/// class, a non-empty class argument, and at least one proving gate.
#[test]
fn gate_perf_bench_requires_complete_host_parallelism_admission_register() {
    let admissions = canonical_host_parallelism_admissions();
    assert!(
        admissions.iter().any(|admission| {
            admission.mechanism == HOST_WORKER_POOL
                && admission.class == HostParallelismClass::CommitPinnedToVirtualTime
        }),
        "the scheduler worker pool must be admitted as Class B"
    );
    assert!(
        admissions.iter().any(|admission| {
            admission.mechanism == FINGERPRINT_DIGEST_OFFLOAD
                && admission.class == HostParallelismClass::OutsideObservableBoundary
        }),
        "fingerprint digestion must be admitted as Class A"
    );
    assert!(
        admissions.iter().any(|admission| {
            admission.mechanism == DEVICE_WORK_OVERLAP
                && admission.class == HostParallelismClass::CommitPinnedToVirtualTime
        }),
        "device host-work overlap must be admitted as Class B"
    );
    assert!(
        admissions.iter().any(|admission| {
            admission.mechanism == TRANSLATION_PREFETCH
                && admission.class == HostParallelismClass::OutsideObservableBoundary
        }),
        "translation prefetch must be admitted as Class A"
    );
    assert!(
        admissions.iter().any(|admission| {
            admission.mechanism == SEGMENT_PARALLEL_REPLAY
                && admission.class == HostParallelismClass::OutsideObservableBoundary
        }),
        "segment-parallel replay must be admitted as Class A"
    );

    let mut missing = canonical_perf_bench_input();
    missing
        .host_parallelism_admissions
        .retain(|admission| admission.mechanism != HOST_WORKER_POOL);
    let error = run_perf_bench_gate(&missing).expect_err("missing admission must fail");
    assert!(matches!(
        error,
        PerfBenchError::MissingHostParallelismAdmission { mechanism }
            if mechanism == HOST_WORKER_POOL
    ));
}

/// [PERF-34] — an admitted mechanism without a class argument or proving gate
/// fails closed instead of being tolerance-banded.
#[test]
fn gate_perf_bench_rejects_unproved_host_parallelism_admission() {
    let mut input = canonical_perf_bench_input();
    let admission = input
        .host_parallelism_admissions
        .iter_mut()
        .find(|admission| admission.mechanism == FINGERPRINT_DIGEST_OFFLOAD)
        .expect("canonical fingerprint admission");
    admission.proving_gates.clear();

    let error = run_perf_bench_gate(&input).expect_err("unproved admission must fail");
    assert!(matches!(
        error,
        PerfBenchError::InvalidHostParallelismAdmission { mechanism }
            if mechanism == FINGERPRINT_DIGEST_OFFLOAD
    ));
}

/// [PERF-34] — a label that does not name a canonical determinism gate is not
/// accepted as proof, even when the admission otherwise has a valid class.
#[test]
fn gate_perf_bench_rejects_unknown_proving_gate() {
    let mut input = canonical_perf_bench_input();
    let admission = input
        .host_parallelism_admissions
        .iter_mut()
        .find(|admission| admission.mechanism == SEGMENT_PARALLEL_REPLAY)
        .expect("canonical segment-replay admission");
    admission.proving_gates = vec![String::from("gate:not-a-real-gate")];

    let error = run_perf_bench_gate(&input).expect_err("unknown proving gate must fail");
    assert!(matches!(
        error,
        PerfBenchError::InvalidHostParallelismAdmission { mechanism }
            if mechanism == SEGMENT_PARALLEL_REPLAY
    ));
}
