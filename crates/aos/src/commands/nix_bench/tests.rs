use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_core::nix::{DrvClosure, NixEval};

use super::analysis::*;
use super::corpus;
use super::record::*;
use super::*;

fn sample(elapsed_seconds: f64, cpu_time: f64, thunks: u64) -> BenchmarkSample {
    BenchmarkSample {
        elapsed_seconds,
        elapsed_nanos: duration_nanos(Duration::from_secs_f64(elapsed_seconds)),
        drv_path: "/nix/store/example.drv".to_string(),
        stats: serde_json::json!({
            "cpuTime": cpu_time,
            "nrThunks": thunks,
        }),
        child_peak_rss_bytes: None,
        exact_child_peak_rss: ExactOracleChildPeakRss::NotRecorded,
    }
}

fn sample_without_stats(elapsed_seconds: f64) -> BenchmarkSample {
    BenchmarkSample {
        elapsed_seconds,
        elapsed_nanos: duration_nanos(Duration::from_secs_f64(elapsed_seconds)),
        drv_path: "/nix/store/example.drv".to_string(),
        stats: serde_json::json!({}),
        child_peak_rss_bytes: None,
        exact_child_peak_rss: ExactOracleChildPeakRss::NotRecorded,
    }
}

fn record(name: &str, samples: Vec<BenchmarkSample>) -> BenchmarkRecord {
    record_with_context(
        name,
        samples,
        context("/repo/default.nix", Some("x86_64-linux")),
    )
}

fn outcome(
    category: &str,
    previous: BenchmarkRecord,
    mut current: BenchmarkRecord,
    threshold: f64,
) -> BenchmarkOutcome {
    current.category = category.to_string();
    let comparison = compare_benchmarks(
        &current,
        PreviousBenchmark {
            commit: "previous",
            record: &previous,
        },
        threshold,
        default_memory_regression_threshold(),
    );
    BenchmarkOutcome {
        record: current,
        comparison: Some(comparison),
    }
}

fn record_with_context(
    name: &str,
    samples: Vec<BenchmarkSample>,
    context: BenchmarkContext,
) -> BenchmarkRecord {
    let attr = name.rsplit(':').next().unwrap_or(name).to_string();
    // Mirror each oracle sample's wall time into a native sample so timing-based
    // assertions exercise the native-gated comparison path.
    let native_samples: Vec<NativeBenchmarkSample> = samples
        .iter()
        .map(|sample| NativeBenchmarkSample {
            elapsed_seconds: sample.elapsed_seconds,
            elapsed_nanos: sample.elapsed_nanos,
            drv_path: sample.drv_path.clone(),
            memory: None,
        })
        .collect();
    BenchmarkRecord {
        name: name.to_string(),
        file: context.file.clone(),
        attr,
        category: "test".to_string(),
        temperature: "cold".to_string(),
        temperature_semantics: PAIRED_COLD_SEMANTICS.to_string(),
        context,
        parity: matched_parity("aos-nix"),
        summary: summarize_samples(&samples),
        samples,
        native_summary: summarize_native_samples(&native_samples),
        native_samples,
    }
}

fn matched_parity(candidate: &str) -> BenchmarkParity {
    BenchmarkParity {
        mode: "byte".to_string(),
        candidate: candidate.to_string(),
        matched: true,
        oracle_root: Some("/nix/store/example.drv".to_string()),
        candidate_root: Some("/nix/store/example.drv".to_string()),
        divergence_count: 0,
        root_divergence_count: 0,
        contaminated_divergence_count: 0,
    }
}

fn context(file: &str, current_system: Option<&str>) -> BenchmarkContext {
    BenchmarkContext {
        file: file.to_string(),
        eval_mode: "ambient".to_string(),
        current_system: current_system.map(str::to_string),
        trace_verbose: false,
        allowed_paths: Vec::new(),
        allowed_uris: Vec::new(),
        nix_path: None,
        store_dir: None,
        state_dir: None,
        log_dir: None,
        working_dir: None,
        home_dir: None,
        eval_env_sha256: eval_env_fingerprint(std::iter::empty()),
        eval_env_count: 0,
    }
}

fn context_with_env(
    file: &str,
    current_system: Option<&str>,
    name: &[u8],
    value: &[u8],
) -> BenchmarkContext {
    let mut context = context(file, current_system);
    context.eval_env_sha256 = eval_env_fingerprint(std::iter::once((name, value)));
    context.eval_env_count = 1;
    context
}

struct FakeEval {
    name: &'static str,
    root: PathBuf,
    closure: DrvClosure,
}

impl FakeEval {
    fn new(name: &'static str, root: PathBuf, bytes: Vec<u8>) -> Self {
        let mut drvs = BTreeMap::new();
        drvs.insert(root.clone(), bytes);
        Self {
            name,
            root: root.clone(),
            closure: DrvClosure::new(root, drvs),
        }
    }
}

impl NixEval for FakeEval {
    fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
        Ok(self.root.clone())
    }

    fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
        Ok(self.root.clone())
    }

    fn instantiate_closure(&self, _file: &Path, _attr: &str) -> Result<Option<DrvClosure>> {
        Ok(Some(self.closure.clone()))
    }

    fn eval_expr(&self, _expr: &str) -> Result<String> {
        Ok("null".to_string())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

fn drv_bytes(name: &str) -> Vec<u8> {
    let output = format!("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-{name}-out");
    let builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
    format!(
        r#"Derive([("out","{output}","","")],[],[],"x86_64-linux","{builder}",[],[("builder","{builder}"),("name","{name}"),("out","{output}"),("system","x86_64-linux")])"#
    )
    .into_bytes()
}

fn parity_spec() -> corpus::BenchmarkSpec {
    corpus::explicit_benchmark_specs(Path::new("/repo/default.nix"), &["pkgs.zlib".into()])
        .into_iter()
        .next()
        .expect("explicit benchmark spec is present")
}

#[test]
fn summary_captures_elapsed_and_stats_means() {
    let summary = summarize_samples(&[sample(1.0, 0.5, 10), sample(1.2, 0.7, 14)]);

    assert_eq!(summary.samples, 2);
    assert!((summary.mean_seconds - 1.1).abs() < 0.000_001);
    assert_eq!(summary.stats_mean.get("nrThunks"), Some(&12.0));
    assert_eq!(summary.stats_mean.get("cpuTime"), Some(&0.6));
}

#[test]
fn comparison_flags_significant_regression_with_stats_delta() {
    let previous = record(
        "eval:pkgs.zlib",
        vec![
            sample(1.00, 0.50, 10),
            sample(1.01, 0.51, 10),
            sample(0.99, 0.49, 10),
        ],
    );
    let current = record(
        "eval:pkgs.zlib",
        vec![
            sample(1.30, 0.70, 15),
            sample(1.31, 0.71, 15),
            sample(1.29, 0.69, 15),
        ],
    );

    let comparison = compare_benchmarks(
        &current,
        PreviousBenchmark {
            commit: "previous",
            record: &previous,
        },
        0.10,
        0.10,
    );

    assert!(comparison.significant);
    assert!(comparison.regression);
    assert!(!comparison.improvement);
    assert!(
        comparison
            .z_score
            .is_some_and(|score| score >= SIGNIFICANCE_Z)
    );
    assert_eq!(
        comparison
            .stats_delta
            .get("nrThunks")
            .map(|delta| delta.delta),
        Some(5.0)
    );
}

#[test]
fn comparison_flags_significant_improvement_with_stats_delta() {
    let previous = record(
        "leaf:cold:pkgs.zlib",
        vec![
            sample(1.00, 0.50, 10),
            sample(1.01, 0.51, 10),
            sample(0.99, 0.49, 10),
        ],
    );
    let current = record(
        "leaf:cold:pkgs.zlib",
        vec![
            sample(0.80, 0.40, 8),
            sample(0.81, 0.41, 8),
            sample(0.79, 0.39, 8),
        ],
    );

    let comparison = compare_benchmarks(
        &current,
        PreviousBenchmark {
            commit: "previous",
            record: &previous,
        },
        0.10,
        0.10,
    );

    assert!(comparison.significant);
    assert!(!comparison.regression);
    assert!(comparison.improvement);
    assert_eq!(
        comparison
            .stats_delta
            .get("nrThunks")
            .map(|delta| delta.delta),
        Some(-2.0)
    );
}

#[test]
fn admissibility_accepts_real_workload_improvement_with_stats_delta() {
    let previous = record(
        "leaf:cold:pkgs.zlib",
        vec![
            sample(1.00, 0.50, 10),
            sample(1.01, 0.51, 10),
            sample(0.99, 0.49, 10),
        ],
    );
    let current = record(
        "leaf:cold:pkgs.zlib",
        vec![
            sample(0.80, 0.40, 8),
            sample(0.81, 0.41, 8),
            sample(0.79, 0.39, 8),
        ],
    );
    let outcomes = vec![outcome("leaf", previous, current, 0.10)];

    let admissibility = BenchmarkAdmissibility::evaluate(&outcomes, true, 0);

    assert!(admissibility.admitted);
    assert!(admissibility.parity_green);
    assert!(admissibility.regression_free);
    assert!(admissibility.real_workload_improvement);
    assert!(admissibility.counter_breakdown);
    assert!(admissibility.failure_reasons.is_empty());
}

#[test]
fn admissibility_rejects_diagnostic_only_improvement() {
    let previous = record(
        "diagnostic:cold:diagnostic.attrset_access",
        vec![
            sample(1.00, 0.50, 10),
            sample(1.01, 0.51, 10),
            sample(0.99, 0.49, 10),
        ],
    );
    let current = record(
        "diagnostic:cold:diagnostic.attrset_access",
        vec![
            sample(0.80, 0.40, 8),
            sample(0.81, 0.41, 8),
            sample(0.79, 0.39, 8),
        ],
    );
    let outcomes = vec![outcome("diagnostic", previous, current, 0.10)];

    let admissibility = BenchmarkAdmissibility::evaluate(&outcomes, true, 0);

    assert!(!admissibility.admitted);
    assert!(!admissibility.real_workload_improvement);
    assert!(
        admissibility
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("no non-diagnostic workload"))
    );
}

#[test]
fn admissibility_rejects_improvement_without_stats_delta() {
    let previous = record(
        "leaf:cold:pkgs.zlib",
        vec![
            sample_without_stats(1.00),
            sample_without_stats(1.01),
            sample_without_stats(0.99),
        ],
    );
    let current = record(
        "leaf:cold:pkgs.zlib",
        vec![
            sample_without_stats(0.80),
            sample_without_stats(0.81),
            sample_without_stats(0.79),
        ],
    );
    let outcomes = vec![outcome("leaf", previous, current, 0.10)];

    let admissibility = BenchmarkAdmissibility::evaluate(&outcomes, true, 0);

    assert!(!admissibility.admitted);
    assert!(admissibility.real_workload_improvement);
    assert!(!admissibility.counter_breakdown);
    assert!(
        admissibility
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("stats delta"))
    );
}

#[test]
fn previous_benchmark_skips_current_commit_records() {
    let current = record("eval:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);
    let previous = record("eval:pkgs.zlib", vec![sample(0.9, 0.4, 9)]);
    let history = vec![
        BenchmarkRunRecord {
            version: BENCH_HISTORY_VERSION,
            commit: "older".to_string(),
            timestamp_unix_ms: 1,
            file: "default.nix".to_string(),
            benchmarks: vec![previous],
        },
        BenchmarkRunRecord {
            version: BENCH_HISTORY_VERSION,
            commit: "current".to_string(),
            timestamp_unix_ms: 2,
            file: "default.nix".to_string(),
            benchmarks: vec![current],
        },
    ];
    let current = record("eval:pkgs.zlib", vec![sample(1.1, 0.5, 10)]);

    let found = previous_benchmark(&history, &current, "current").expect("older benchmark exists");

    assert_eq!(found.commit, "older");
}

#[test]
fn previous_benchmark_requires_matching_file_context() {
    let previous = record_with_context(
        "eval:pkgs.zlib",
        vec![sample(0.9, 0.4, 9)],
        context("/repo/other.nix", Some("x86_64-linux")),
    );
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/other.nix".to_string(),
        benchmarks: vec![previous],
    }];
    let current = record_with_context(
        "eval:pkgs.zlib",
        vec![sample(1.0, 0.5, 10)],
        context("/repo/default.nix", Some("x86_64-linux")),
    );

    let found = previous_benchmark(&history, &current, "current");

    assert!(found.is_none());
}

#[test]
fn previous_benchmark_requires_matching_eval_system_context() {
    let previous = record_with_context(
        "eval:pkgs.zlib",
        vec![sample(0.9, 0.4, 9)],
        context("/repo/default.nix", Some("aarch64-linux")),
    );
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/default.nix".to_string(),
        benchmarks: vec![previous],
    }];
    let current = record_with_context(
        "eval:pkgs.zlib",
        vec![sample(1.0, 0.5, 10)],
        context("/repo/default.nix", Some("x86_64-linux")),
    );

    let found = previous_benchmark(&history, &current, "current");

    assert!(found.is_none());
}

#[test]
fn previous_benchmark_requires_matching_eval_environment_context() {
    let previous = record_with_context(
        "eval:pkgs.zlib",
        vec![sample(0.9, 0.4, 9)],
        context_with_env(
            "/repo/default.nix",
            Some("x86_64-linux"),
            b"TEST_VAR",
            b"foo",
        ),
    );
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/default.nix".to_string(),
        benchmarks: vec![previous],
    }];
    let current = record_with_context(
        "eval:pkgs.zlib",
        vec![sample(1.0, 0.5, 10)],
        context_with_env(
            "/repo/default.nix",
            Some("x86_64-linux"),
            b"TEST_VAR",
            b"bar",
        ),
    );

    let found = previous_benchmark(&history, &current, "current");

    assert!(found.is_none());
}

#[test]
fn previous_benchmark_requires_matching_parity_context() {
    let mut previous = record("eval:pkgs.zlib", vec![sample(0.9, 0.4, 9)]);
    previous.parity = BenchmarkParity::legacy_missing();
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/default.nix".to_string(),
        benchmarks: vec![previous],
    }];
    let current = record("eval:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);

    let found = previous_benchmark(&history, &current, "current");

    assert!(found.is_none());
}

#[test]
fn previous_benchmark_requires_matching_temperature() {
    let mut previous = record("leaf:pkgs.zlib", vec![sample(0.9, 0.4, 9)]);
    previous.temperature = "cold".to_string();
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/default.nix".to_string(),
        benchmarks: vec![previous],
    }];
    let mut current = record("leaf:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);
    current.temperature = "warm".to_string();

    let found = previous_benchmark(&history, &current, "current");

    assert!(found.is_none());
}

#[test]
fn parity_gate_records_matching_byte_diff() {
    let root = PathBuf::from("/nix/store/cccccccccccccccccccccccccccccccc-root.drv");
    let oracle = FakeEval::new("oracle", root.clone(), drv_bytes("same"));
    let candidate = FakeEval::new("native-test", root.clone(), drv_bytes("same"));
    let spec = parity_spec();

    let parity = run_parity_gate(&oracle, &candidate, candidate.name(), &spec)
        .expect("matching closures pass parity gate");

    assert!(parity.matched);
    assert_eq!(parity.mode, "byte");
    assert_eq!(parity.candidate, "native-test");
    assert_eq!(
        parity.oracle_root.as_deref(),
        Some("/nix/store/cccccccccccccccccccccccccccccccc-root.drv")
    );
    assert_eq!(parity.divergence_count, 0);
}

#[test]
fn parity_gate_blocks_divergent_byte_diff() {
    let root = PathBuf::from("/nix/store/cccccccccccccccccccccccccccccccc-root.drv");
    let oracle = FakeEval::new("oracle", root.clone(), drv_bytes("oracle"));
    let candidate = FakeEval::new("native-test", root, drv_bytes("candidate"));
    let spec = parity_spec();

    let error = run_parity_gate(&oracle, &candidate, candidate.name(), &spec)
        .expect_err("divergent closures fail parity gate");

    assert!(
        error
            .to_string()
            .contains("nix benchmark parity gate failed for explicit:pkgs.zlib")
    );
}

/// Fake evaluator whose instantiation advances through a script of closures,
/// mimicking a source tree edited between parity-gate attempts.
struct ScriptedEval {
    name: &'static str,
    script: Vec<DrvClosure>,
    calls: std::sync::atomic::AtomicUsize,
}

impl ScriptedEval {
    fn new(name: &'static str, script: Vec<(PathBuf, Vec<u8>)>) -> Self {
        let script = script
            .into_iter()
            .map(|(root, bytes)| {
                let mut drvs = BTreeMap::new();
                drvs.insert(root.clone(), bytes);
                DrvClosure::new(root, drvs)
            })
            .collect();
        Self {
            name,
            script,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn current(&self) -> DrvClosure {
        let calls = self.calls.load(std::sync::atomic::Ordering::Relaxed);
        let index = calls.min(self.script.len() - 1);
        self.script[index].clone()
    }
}

impl NixEval for ScriptedEval {
    fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
        Ok(self.current().root().to_path_buf())
    }

    fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
        Ok(self.current().root().to_path_buf())
    }

    fn instantiate_closure(&self, _file: &Path, _attr: &str) -> Result<Option<DrvClosure>> {
        let closure = self.current();
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Some(closure))
    }

    fn eval_expr(&self, _expr: &str) -> Result<String> {
        Ok("null".to_string())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

#[test]
fn parity_gate_retries_when_oracle_root_drifts_then_stabilizes() {
    let stale = PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-stale.drv");
    let fresh = PathBuf::from("/nix/store/cccccccccccccccccccccccccccccccc-root.drv");
    // The oracle first sees the pre-edit sources, then converges with the
    // candidate once the tree stops moving.
    let oracle = ScriptedEval::new(
        "oracle",
        vec![
            (stale, drv_bytes("stale")),
            (fresh.clone(), drv_bytes("same")),
        ],
    );
    let candidate = FakeEval::new("native-test", fresh, drv_bytes("same"));
    let spec = parity_spec();

    let parity = run_parity_gate(&oracle, &candidate, candidate.name(), &spec)
        .expect("gate retries through input drift and matches");

    assert!(parity.matched);
    assert_eq!(
        parity.oracle_root.as_deref(),
        Some("/nix/store/cccccccccccccccccccccccccccccccc-root.drv")
    );
}

#[test]
fn parity_gate_reports_unstable_comparison_under_perpetual_drift() {
    let candidate_root = PathBuf::from("/nix/store/cccccccccccccccccccccccccccccccc-root.drv");
    // The oracle root moves on every attempt: the gate can never pin a
    // stable pair of inputs and must say so rather than report divergences.
    let oracle = ScriptedEval::new(
        "oracle",
        vec![
            (
                PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-one.drv"),
                drv_bytes("one"),
            ),
            (
                PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-two.drv"),
                drv_bytes("two"),
            ),
            (
                PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-three.drv"),
                drv_bytes("three"),
            ),
        ],
    );
    let candidate = FakeEval::new("native-test", candidate_root, drv_bytes("same"));
    let spec = parity_spec();

    let error = run_parity_gate(&oracle, &candidate, candidate.name(), &spec)
        .expect_err("perpetual drift cannot produce a parity verdict");

    assert!(
        error
            .to_string()
            .contains("could not obtain a stable comparison"),
        "{error}"
    );
}

#[test]
fn classify_divergent_attempt_requires_a_repeat_root_to_trust_divergence() {
    let root_a = Some(PathBuf::from("/nix/store/aaaa-a.drv"));
    let root_b = Some(PathBuf::from("/nix/store/bbbb-b.drv"));
    let mut previous = None;

    // First divergent attempt never fails the gate outright.
    assert_eq!(
        classify_divergent_attempt(&mut previous, &root_a),
        ParityAttemptVerdict::InputsDrifted
    );
    // A different oracle root means the inputs moved: retry again.
    assert_eq!(
        classify_divergent_attempt(&mut previous, &root_b),
        ParityAttemptVerdict::InputsDrifted
    );
    // Reproducing the divergence from the same oracle root makes it real.
    assert_eq!(
        classify_divergent_attempt(&mut previous, &root_b),
        ParityAttemptVerdict::RealDivergence
    );
}

#[test]
fn read_history_accepts_legacy_run_context_records() {
    let temp = tempfile::tempdir().expect("temporary directory is created");
    let path = temp.path().join("nix-eval.jsonl");
    let samples = vec![sample(1.0, 0.5, 10)];
    let legacy = serde_json::json!({
        "version": BENCH_HISTORY_VERSION,
        "commit": "older",
        "timestamp_unix_ms": 1,
        "file": "/repo/default.nix",
        "context": context("/repo/default.nix", Some("x86_64-linux")),
        "benchmarks": [
            {
                "name": "eval:pkgs.zlib",
                "attr": "pkgs.zlib",
                "samples": samples,
                "summary": summarize_samples(&[sample(1.0, 0.5, 10)]),
            }
        ],
    });
    fs::write(&path, format!("{legacy}\n")).expect("legacy history is written");

    let records = read_history(&path).expect("legacy history parses");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].benchmarks[0].category, "legacy");
    assert_eq!(records[0].benchmarks[0].temperature, "cold");
    assert_eq!(records[0].benchmarks[0].context.file, "/repo/default.nix");
    assert_eq!(records[0].benchmarks[0].parity.mode, "legacy-missing");
}

#[test]
fn explicit_benchmark_specs_are_temperature_neutral() {
    let specs =
        corpus::explicit_benchmark_specs(Path::new("/repo/default.nix"), &["pkgs.zlib".into()]);

    // One spec per attr; the paired-cycle driver derives both temperatures.
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, "explicit:pkgs.zlib");
    assert_eq!(specs[0].category, "explicit");
}

#[test]
fn toolchain_attr_expr_includes_bootstrap_roots_and_gcc_tiers() {
    let expr = corpus::toolchain_attr_expr(Path::new("/repo/default.nix"))
        .expect("toolchain expression renders");

    assert!(expr.contains("attr = \"stdenv.bootstrap.gcc\";"));
    assert!(expr.contains("attr = \"pkgs.rust-1_74\";"));
    assert!(expr.contains("attr = \"pkgs.openjdk-8\";"));
    assert!(expr.contains("attr = \"pkgs.bazel-bootstrap\";"));
    assert!(expr.contains("attr = \"pkgs.llvm-17\";"));
    assert!(expr.contains("root.stdenv.toolchainTiers"));
    assert!(expr.contains("stdenv.toolchainTiers.${tierName}.${componentName}"));
    assert!(expr.contains("\"gccStage2\""));
    assert!(expr.contains("\"linuxHeaders\""));
}

fn native_sample_with_memory(peak_rss_delta: u64) -> NativeBenchmarkSample {
    NativeBenchmarkSample {
        elapsed_seconds: 1.0,
        elapsed_nanos: 1_000_000_000,
        drv_path: "/nix/store/example.drv".to_string(),
        memory: Some(NativeSampleMemory {
            rss_before_bytes: Some(100),
            rss_after_bytes: Some(200 + peak_rss_delta),
            peak_rss_before_bytes: Some(1_000),
            peak_rss_after_bytes: Some(1_000 + peak_rss_delta),
            peak_rss_delta_bytes: Some(peak_rss_delta),
            arena: Some(NativeSampleArena {
                live_mapped_bytes_before: 0,
                live_mapped_bytes_after: 0,
                peak_live_mapped_bytes: 64 + peak_rss_delta,
                live_chunks_after: 0,
                chunks_mapped: 6,
                bytes_mapped: 64 + peak_rss_delta,
            }),
        }),
    }
}

fn record_with_memory(name: &str, peak_rss_delta: u64) -> BenchmarkRecord {
    let mut record = record(name, vec![sample(1.0, 0.5, 10)]);
    record.native_samples = vec![
        native_sample_with_memory(peak_rss_delta),
        native_sample_with_memory(peak_rss_delta / 2),
    ];
    record.native_summary = summarize_native_samples(&record.native_samples);
    record
}

#[test]
fn native_memory_summary_takes_maxima_and_final_arena_state() {
    let record = record_with_memory("leaf:cold:pkgs.zlib", 1_000);
    let memory = record.native_summary.memory.expect("memory summary");

    assert_eq!(memory.peak_rss_delta_bytes_max, Some(1_000));
    assert_eq!(memory.rss_after_bytes_max, Some(1_200));
    assert_eq!(memory.arena_peak_live_mapped_bytes_max, Some(1_064));
    assert_eq!(memory.arena_live_mapped_bytes_after_last, Some(0));
}

#[test]
fn native_memory_summary_is_absent_without_memory_probes() {
    let record = record("leaf:cold:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);

    assert!(record.native_summary.memory.is_none());
}

#[test]
fn exact_oracle_child_peak_never_falls_back_to_children_watermark() {
    let mut unavailable = sample(1.0, 0.5, 10);
    unavailable.child_peak_rss_bytes = Some(900);
    unavailable.exact_child_peak_rss =
        ExactOracleChildPeakRss::UnavailableSafePerChildWaitApi;

    let summary = summarize_samples(&[unavailable]);

    assert_eq!(summary.child_peak_rss_bytes_max, Some(900));
    assert_eq!(
        summary.exact_child_peak_rss,
        ExactOracleChildPeakRss::UnavailableSafePerChildWaitApi
    );
}

#[test]
fn exact_oracle_child_peak_summary_uses_maximum_measured_sample() {
    let mut smaller = sample(1.0, 0.5, 10);
    smaller.exact_child_peak_rss = ExactOracleChildPeakRss::Measured { bytes: 700 };
    let mut larger = sample(1.0, 0.5, 10);
    larger.exact_child_peak_rss = ExactOracleChildPeakRss::Measured { bytes: 1_200 };

    let summary = summarize_samples(&[smaller, larger]);

    assert_eq!(
        summary.exact_child_peak_rss,
        ExactOracleChildPeakRss::Measured { bytes: 1_200 }
    );
}

#[test]
fn exact_oracle_child_peak_summary_refuses_partial_measurement() {
    let mut measured = sample(1.0, 0.5, 10);
    measured.exact_child_peak_rss = ExactOracleChildPeakRss::Measured { bytes: 1_200 };
    let mut unavailable = sample(1.0, 0.5, 10);
    unavailable.exact_child_peak_rss =
        ExactOracleChildPeakRss::UnavailableSafePerChildWaitApi;

    let summary = summarize_samples(&[measured, unavailable]);

    assert_eq!(
        summary.exact_child_peak_rss,
        ExactOracleChildPeakRss::UnavailableSafePerChildWaitApi
    );
}

#[test]
fn memory_report_names_exact_unavailability_and_watermark_separately() {
    let mut benchmark = record("leaf:cold:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);
    benchmark.samples[0].child_peak_rss_bytes = Some(1024 * 1024);
    benchmark.samples[0].exact_child_peak_rss =
        ExactOracleChildPeakRss::UnavailableSafePerChildWaitApi;
    benchmark.summary = summarize_samples(&benchmark.samples);
    let outcome = BenchmarkOutcome {
        record: benchmark,
        comparison: None,
    };

    let line = render_memory_line(&outcome).expect("oracle state renders");

    assert!(line.contains("oracle_exact_child_peak_rss=unavailable:safe-per-child-wait-api"));
    assert!(line.contains("oracle_child_peak_rss_watermark=1.0MiB"));
    assert!(!line.contains(" oracle_child_peak_rss=1.0MiB"));
}

#[test]
fn memory_regression_is_flagged_past_the_memory_threshold() {
    let previous = record_with_memory("leaf:cold:pkgs.zlib", 1_000);
    let current = record_with_memory("leaf:cold:pkgs.zlib", 1_500);

    let comparison = compare_benchmarks(
        &current,
        PreviousBenchmark {
            commit: "previous",
            record: &previous,
        },
        0.10,
        0.10,
    );

    let memory = comparison.memory.expect("memory movement");
    assert_eq!(memory.previous_peak_rss_delta_bytes, 1_000);
    assert_eq!(memory.current_peak_rss_delta_bytes, 1_500);
    assert_eq!(memory.delta_bytes, 500);
    assert!(memory.regression);
    assert!(!memory.improvement);
}

#[test]
fn memory_improvement_is_flagged_and_small_movement_is_neither() {
    let previous = record_with_memory("leaf:cold:pkgs.zlib", 1_000);

    let improved = record_with_memory("leaf:cold:pkgs.zlib", 500);
    let comparison = compare_benchmarks(
        &improved,
        PreviousBenchmark {
            commit: "previous",
            record: &previous,
        },
        0.10,
        0.10,
    );
    let memory = comparison.memory.expect("memory movement");
    assert!(memory.improvement);
    assert!(!memory.regression);

    let steady = record_with_memory("leaf:cold:pkgs.zlib", 1_050);
    let comparison = compare_benchmarks(
        &steady,
        PreviousBenchmark {
            commit: "previous",
            record: &previous,
        },
        0.10,
        0.10,
    );
    let memory = comparison.memory.expect("memory movement");
    assert!(!memory.improvement);
    assert!(!memory.regression);
}

#[test]
fn memory_movement_requires_probes_on_both_sides() {
    let previous = record("leaf:cold:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);
    let current = record_with_memory("leaf:cold:pkgs.zlib", 1_000);

    let comparison = compare_benchmarks(
        &current,
        PreviousBenchmark {
            commit: "previous",
            record: &previous,
        },
        0.10,
        0.10,
    );

    assert!(comparison.memory.is_none());
}

#[test]
fn skipped_parity_records_never_match_as_baselines() {
    let mut previous = record("leaf:cold:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);
    previous.parity = BenchmarkParity::skipped("aos-nix");
    let current = record("leaf:cold:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "previous".to_string(),
        timestamp_unix_ms: 1,
        file: current.file.clone(),
        benchmarks: vec![previous],
    }];

    assert!(previous_benchmark(&history, &current, "current").is_none());
}

#[test]
fn v2_history_records_without_memory_fields_still_parse() {
    let line = serde_json::json!({
        "version": 2,
        "commit": "previouscommit",
        "timestamp_unix_ms": 1,
        "file": "/repo/default.nix",
        "benchmarks": [{
            "name": "leaf:cold:pkgs.zlib",
            "attr": "pkgs.zlib",
            "samples": [{
                "elapsed_seconds": 1.0,
                "elapsed_nanos": 1000000000u64,
                "drv_path": "/nix/store/example.drv",
                "stats": {}
            }],
            "summary": {
                "samples": 1,
                "mean_seconds": 1.0,
                "stddev_seconds": 0.0,
                "min_seconds": 1.0,
                "max_seconds": 1.0,
                "stats_mean": {}
            }
        }]
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("history.jsonl");
    fs::write(&path, format!("{line}\n")).expect("write history");

    let history = read_history(&path).expect("v2 history parses");
    let benchmark = &history[0].benchmarks[0];
    assert!(benchmark.summary.child_peak_rss_bytes_max.is_none());
    assert_eq!(
        benchmark.summary.exact_child_peak_rss,
        ExactOracleChildPeakRss::NotRecorded
    );
    assert!(benchmark.native_summary.memory.is_none());
    assert!(benchmark.samples[0].child_peak_rss_bytes.is_none());
    assert_eq!(
        benchmark.samples[0].exact_child_peak_rss,
        ExactOracleChildPeakRss::NotRecorded
    );
}
