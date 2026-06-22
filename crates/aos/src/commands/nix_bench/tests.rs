use std::time::Duration;

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

fn record(name: &str, samples: Vec<BenchmarkSample>) -> BenchmarkRecord {
    BenchmarkRecord {
        name: name.to_string(),
        attr: name.trim_start_matches("eval:").to_string(),
        summary: summarize_samples(&samples),
        samples,
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
fn previous_benchmark_skips_current_commit_records() {
    let current = record("eval:pkgs.zlib", vec![sample(1.0, 0.5, 10)]);
    let previous = record("eval:pkgs.zlib", vec![sample(0.9, 0.4, 9)]);
    let bench_context = context("/repo/default.nix", Some("x86_64-linux"));
    let history = vec![
        BenchmarkRunRecord {
            version: BENCH_HISTORY_VERSION,
            commit: "older".to_string(),
            timestamp_unix_ms: 1,
            file: "default.nix".to_string(),
            context: bench_context.clone(),
            benchmarks: vec![previous],
        },
        BenchmarkRunRecord {
            version: BENCH_HISTORY_VERSION,
            commit: "current".to_string(),
            timestamp_unix_ms: 2,
            file: "default.nix".to_string(),
            context: bench_context.clone(),
            benchmarks: vec![current],
        },
    ];

    let found = previous_benchmark(&history, &bench_context, "eval:pkgs.zlib", "current")
        .expect("older benchmark exists");

    assert_eq!(found.commit, "older");
}

#[test]
fn previous_benchmark_requires_matching_file_context() {
    let previous = record("eval:pkgs.zlib", vec![sample(0.9, 0.4, 9)]);
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/other.nix".to_string(),
        context: context("/repo/other.nix", Some("x86_64-linux")),
        benchmarks: vec![previous],
    }];

    let found = previous_benchmark(
        &history,
        &context("/repo/default.nix", Some("x86_64-linux")),
        "eval:pkgs.zlib",
        "current",
    );

    assert!(found.is_none());
}

#[test]
fn previous_benchmark_requires_matching_eval_system_context() {
    let previous = record("eval:pkgs.zlib", vec![sample(0.9, 0.4, 9)]);
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/default.nix".to_string(),
        context: context("/repo/default.nix", Some("aarch64-linux")),
        benchmarks: vec![previous],
    }];

    let found = previous_benchmark(
        &history,
        &context("/repo/default.nix", Some("x86_64-linux")),
        "eval:pkgs.zlib",
        "current",
    );

    assert!(found.is_none());
}

#[test]
fn previous_benchmark_requires_matching_eval_environment_context() {
    let previous = record("eval:pkgs.zlib", vec![sample(0.9, 0.4, 9)]);
    let history = vec![BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit: "older".to_string(),
        timestamp_unix_ms: 1,
        file: "/repo/default.nix".to_string(),
        context: context_with_env(
            "/repo/default.nix",
            Some("x86_64-linux"),
            b"TEST_VAR",
            b"foo",
        ),
        benchmarks: vec![previous],
    }];

    let found = previous_benchmark(
        &history,
        &context_with_env(
            "/repo/default.nix",
            Some("x86_64-linux"),
            b"TEST_VAR",
            b"bar",
        ),
        "eval:pkgs.zlib",
        "current",
    );

    assert!(found.is_none());
}

#[test]
fn selected_attrs_defaults_to_fixed_scaffold_corpus() {
    assert_eq!(selected_attrs(&[]), vec!["pkgs.zlib".to_string()]);
}
