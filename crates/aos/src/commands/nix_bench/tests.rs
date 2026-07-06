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
    }
}

fn sample_without_stats(elapsed_seconds: f64) -> BenchmarkSample {
    BenchmarkSample {
        elapsed_seconds,
        elapsed_nanos: duration_nanos(Duration::from_secs_f64(elapsed_seconds)),
        drv_path: "/nix/store/example.drv".to_string(),
        stats: serde_json::json!({}),
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
        })
        .collect();
    BenchmarkRecord {
        name: name.to_string(),
        file: context.file.clone(),
        attr,
        category: "test".to_string(),
        temperature: "cold".to_string(),
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

fn spec_with_temperature(temperature: &str) -> corpus::BenchmarkSpec {
    corpus::BenchmarkSpec {
        name: format!("leaf:{temperature}:pkgs.zlib"),
        file: PathBuf::from("/repo/default.nix"),
        attr: "pkgs.zlib".to_string(),
        category: "leaf".to_string(),
        temperature: temperature.to_string(),
    }
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
            .contains("nix benchmark parity gate failed for explicit:cold:pkgs.zlib")
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
fn explicit_benchmark_specs_use_cold_explicit_category() {
    let specs =
        corpus::explicit_benchmark_specs(Path::new("/repo/default.nix"), &["pkgs.zlib".into()]);

    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, "explicit:cold:pkgs.zlib");
    assert_eq!(specs[0].category, "explicit");
    assert_eq!(specs[0].temperature, "cold");
}

#[test]
fn cold_benchmark_samples_do_not_prime_before_recording() {
    let spec = spec_with_temperature("cold");
    let mut calls = 0;

    let samples = capture_benchmark_samples(&spec, 2, || {
        calls += 1;
        Ok(sample(calls as f64, 0.0, calls))
    })
    .expect("cold samples capture");

    assert_eq!(calls, 2);
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].elapsed_seconds, 1.0);
    assert_eq!(samples[1].elapsed_seconds, 2.0);
}

#[test]
fn warm_benchmark_samples_prime_once_before_recording() {
    let spec = spec_with_temperature("warm");
    let mut calls = 0;

    let samples = capture_benchmark_samples(&spec, 2, || {
        calls += 1;
        Ok(sample(calls as f64, 0.0, calls))
    })
    .expect("warm samples capture");

    assert_eq!(calls, 3);
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].elapsed_seconds, 2.0);
    assert_eq!(samples[1].elapsed_seconds, 3.0);
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
