//! `aos nix-bench` -- record per-commit Nix evaluation benchmarks.

pub(crate) mod corpus;

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use aos_core::error::AosError;
use aos_core::nix::{
    NixCli, NixEval, NixEvalConfig, NixEvalMode, NixRunner,
    select_native_diff_candidate_with_config,
};
use aos_core::output::{OutputMode, Printer};
use aos_nix_harness::diff::{DiffMode, DrvDiffReport, diff_closure};

use corpus::{BenchmarkSpec, benchmark_specs};

const BENCH_HISTORY_VERSION: u32 = 1;
const DEFAULT_SAMPLES: usize = 3;
const DEFAULT_REGRESSION_THRESHOLD: f64 = 0.10;
const SIGNIFICANCE_Z: f64 = 2.0;
const STATS_DELTA_KEYS: &[&str] = &[
    "cpuTime",
    "nrThunks",
    "nrExprs",
    "nrValues",
    "nrOpUpdates",
    "nrOpUpdateValuesCopied",
    "nrListElems",
    "nrAttrsets",
    "nrAttrs",
];

/// Error returned after `aos nix-bench` has rendered a regression report.
#[derive(Debug, Clone)]
pub struct NixBenchRegressionFailure {
    message: String,
}

impl NixBenchRegressionFailure {
    fn new(count: usize) -> Self {
        let plural = if count == 1 { "" } else { "s" };
        Self {
            message: format!("nix benchmark found {count} significant regression{plural}"),
        }
    }
}

impl std::fmt::Display for NixBenchRegressionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NixBenchRegressionFailure {}

/// Error returned when a benchmark run is not admissible as a perf win.
#[derive(Debug, Clone)]
pub struct NixBenchAdmissibilityFailure {
    message: String,
}

impl NixBenchAdmissibilityFailure {
    fn new(reasons: &[String]) -> Self {
        let detail = if reasons.is_empty() {
            "no admission reason was recorded".to_string()
        } else {
            reasons.join("; ")
        };
        Self {
            message: format!("nix benchmark is not admissible as a perf win: {detail}"),
        }
    }
}

impl std::fmt::Display for NixBenchAdmissibilityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NixBenchAdmissibilityFailure {}

/// Error returned when the benchmark parity gate finds a `.drv` divergence.
#[derive(Debug, Clone)]
pub struct NixBenchParityFailure {
    message: String,
}

impl NixBenchParityFailure {
    fn new(spec: &BenchmarkSpec, candidate_name: &str, report: &DrvDiffReport) -> Self {
        let plural = if report.divergences.len() == 1 {
            ""
        } else {
            "s"
        };
        Self {
            message: format!(
                "nix benchmark parity gate failed for {} against {candidate_name}: {} divergence{plural}",
                spec.name,
                report.divergences.len()
            ),
        }
    }
}

impl std::fmt::Display for NixBenchParityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NixBenchParityFailure {}

/// Runs the per-commit Nix evaluation benchmark scaffold.
///
/// # Errors
///
/// Returns an error if the benchmark arguments are invalid, Git cannot provide
/// the current commit SHA, the native `.drv` parity candidate cannot be
/// initialized, a selected benchmark diverges at the parity gate, Nix cannot
/// instantiate a selected attribute with `NIX_SHOW_STATS`, history cannot be
/// read or written, or `fail_on_regression` is set and a significant
/// regression is detected. It also returns an error when `require_perf_win` is
/// set and the run is not admissible as a performance win.
pub fn run(
    printer: &Printer,
    verbose: u8,
    mut eval_config: NixEvalConfig,
    file: Option<&Path>,
    attrs: &[String],
    samples: usize,
    history: Option<&Path>,
    no_record: bool,
    fail_on_regression: bool,
    require_perf_win: bool,
    regression_threshold: f64,
) -> Result<()> {
    validate_args(samples, regression_threshold)?;
    NixRunner::ensure_nix_instantiate_available()?;
    if eval_config.eval_mode() == NixEvalMode::Ambient {
        eval_config.set_eval_mode(NixEvalMode::Impure);
    }
    let candidate = select_native_diff_candidate_with_config(verbose, eval_config.clone())
        .context("initializing nix-bench .drv parity gate")?;
    let candidate_name = candidate.name().to_string();

    let root = NixRunner::find_root()?;
    let file = file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("default.nix"));
    let file = absolute_eval_file(&file)?;
    let history = history
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".aos-benchmarks").join("nix-eval.jsonl"));
    let commit = current_commit_sha()?;
    let previous_runs = read_history(&history)?;
    let oracle = NixCli::with_eval_config(verbose, eval_config.clone());
    let specs = benchmark_specs(&oracle, &root, &file, attrs)?;

    printer.info(&format!(
        "Running {} Nix eval benchmark(s) with {samples} sample(s)...",
        specs.len()
    ));

    let mut outcomes = Vec::with_capacity(specs.len());
    for spec in specs {
        let record = run_one_benchmark(
            &oracle,
            candidate.as_ref(),
            &candidate_name,
            &spec,
            &eval_config,
            samples,
        )?;
        let comparison = previous_benchmark(&previous_runs, &record, &commit)
            .map(|previous| compare_benchmarks(&record, previous, regression_threshold));
        outcomes.push(BenchmarkOutcome { record, comparison });
    }

    let run = BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit,
        timestamp_unix_ms: unix_timestamp_millis()?,
        file: file.to_string_lossy().into_owned(),
        benchmarks: outcomes
            .iter()
            .map(|outcome| outcome.record.clone())
            .collect(),
    };

    if !no_record {
        append_history(&history, &run)?;
    }

    let regression_count = outcomes
        .iter()
        .filter(|outcome| {
            outcome
                .comparison
                .as_ref()
                .is_some_and(|comparison| comparison.regression)
        })
        .count();
    let failure = (regression_count > 0).then(|| NixBenchRegressionFailure::new(regression_count));
    let admissibility =
        BenchmarkAdmissibility::evaluate(&outcomes, require_perf_win, regression_count);
    let admissibility_failure = (require_perf_win && !admissibility.admitted)
        .then(|| NixBenchAdmissibilityFailure::new(&admissibility.failure_reasons));
    let blocked = (fail_on_regression && failure.is_some()) || admissibility_failure.is_some();

    if printer.json_if_active(&run_json(
        &run,
        &outcomes,
        &admissibility,
        &history,
        !no_record,
        blocked,
        failure.as_ref(),
        admissibility_failure.as_ref(),
    )) {
        return finish_benchmark_run(blocked, failure, admissibility_failure);
    }

    render_human_report(
        printer,
        &run,
        &outcomes,
        &admissibility,
        &history,
        !no_record,
        failure.as_ref(),
        admissibility_failure.as_ref(),
    );

    finish_benchmark_run(blocked, failure, admissibility_failure)
}

/// Returns the default sample count used by the CLI.
pub const fn default_samples() -> usize {
    DEFAULT_SAMPLES
}

/// Returns the default regression threshold used by the CLI.
pub const fn default_regression_threshold() -> f64 {
    DEFAULT_REGRESSION_THRESHOLD
}

fn validate_args(samples: usize, regression_threshold: f64) -> Result<()> {
    if samples == 0 {
        return Err(AosError::InvalidArgument {
            message: "nix-bench requires at least one sample".to_string(),
        }
        .into());
    }
    if !regression_threshold.is_finite() || regression_threshold < 0.0 {
        return Err(AosError::InvalidArgument {
            message: "nix-bench --regression-threshold must be a finite non-negative number"
                .to_string(),
        }
        .into());
    }
    Ok(())
}

fn absolute_eval_file(path: &Path) -> Result<std::path::PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolving current directory for nix-bench file")?
        .join(path))
}

#[derive(Debug, Clone)]
struct BenchmarkOutcome {
    record: BenchmarkRecord,
    comparison: Option<BenchmarkComparison>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkRunRecord {
    version: u32,
    commit: String,
    timestamp_unix_ms: u64,
    file: String,
    benchmarks: Vec<BenchmarkRecord>,
}

#[derive(Debug, Deserialize)]
struct HistoryRunRecord {
    version: u32,
    commit: String,
    timestamp_unix_ms: u64,
    file: String,
    #[serde(default)]
    context: Option<BenchmarkContext>,
    benchmarks: Vec<HistoryBenchmarkRecord>,
}

impl HistoryRunRecord {
    fn into_record(self) -> BenchmarkRunRecord {
        let benchmarks = self
            .benchmarks
            .into_iter()
            .map(|record| record.into_record(self.context.as_ref(), &self.file))
            .collect();
        BenchmarkRunRecord {
            version: self.version,
            commit: self.commit,
            timestamp_unix_ms: self.timestamp_unix_ms,
            file: self.file,
            benchmarks,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BenchmarkContext {
    file: String,
    eval_mode: String,
    current_system: Option<String>,
    trace_verbose: bool,
    allowed_paths: Vec<String>,
    allowed_uris: Vec<String>,
    nix_path: Option<String>,
    store_dir: Option<String>,
    state_dir: Option<String>,
    log_dir: Option<String>,
    working_dir: Option<String>,
    home_dir: Option<String>,
    eval_env_sha256: String,
    eval_env_count: usize,
}

impl BenchmarkContext {
    fn from_eval_config(file: &Path, eval_config: &NixEvalConfig) -> Self {
        Self {
            file: file.to_string_lossy().into_owned(),
            eval_mode: eval_mode_name(eval_config.eval_mode()).to_string(),
            current_system: eval_config.current_system().map(str::to_string),
            trace_verbose: eval_config.trace_verbose(),
            allowed_paths: eval_config.allowed_paths().to_vec(),
            allowed_uris: eval_config.allowed_uris().to_vec(),
            nix_path: eval_config.nix_path_env().map(str::to_string),
            store_dir: eval_config.store_dir().map(str::to_string),
            state_dir: eval_config.state_dir().map(str::to_string),
            log_dir: eval_config.log_dir().map(str::to_string),
            working_dir: eval_config
                .working_dir()
                .map(|path| path.to_string_lossy().into_owned()),
            home_dir: eval_config
                .home_dir()
                .map(|path| path.to_string_lossy().into_owned()),
            eval_env_count: eval_config.eval_env_vars().count(),
            eval_env_sha256: eval_env_fingerprint(eval_config.eval_env_vars()),
        }
    }

    fn legacy_missing(file: &str) -> Self {
        Self {
            file: file.to_string(),
            eval_mode: "legacy-missing".to_string(),
            current_system: None,
            trace_verbose: false,
            allowed_paths: Vec::new(),
            allowed_uris: Vec::new(),
            nix_path: None,
            store_dir: None,
            state_dir: None,
            log_dir: None,
            working_dir: None,
            home_dir: None,
            eval_env_sha256: "legacy-missing".to_string(),
            eval_env_count: 0,
        }
    }
}

fn eval_mode_name(mode: NixEvalMode) -> &'static str {
    match mode {
        NixEvalMode::Ambient => "ambient",
        NixEvalMode::Impure => "impure",
        NixEvalMode::Restricted => "restricted",
        NixEvalMode::Pure => "pure",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn eval_env_fingerprint<'a>(vars: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> String {
    let mut hasher = Sha256::new();
    for (name, value) in vars {
        hasher.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(name);
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value);
    }
    hex_bytes(&hasher.finalize())
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkRecord {
    name: String,
    file: String,
    attr: String,
    category: String,
    temperature: String,
    context: BenchmarkContext,
    parity: BenchmarkParity,
    samples: Vec<BenchmarkSample>,
    summary: BenchmarkSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkParity {
    mode: String,
    candidate: String,
    matched: bool,
    oracle_root: Option<String>,
    candidate_root: Option<String>,
    divergence_count: usize,
    root_divergence_count: usize,
    contaminated_divergence_count: usize,
}

impl BenchmarkParity {
    fn matched(candidate_name: &str, report: &DrvDiffReport) -> Self {
        Self {
            mode: "byte".to_string(),
            candidate: candidate_name.to_string(),
            matched: true,
            oracle_root: report
                .oracle_root
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            candidate_root: report
                .candidate_root
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            divergence_count: report.divergences.len(),
            root_divergence_count: report.root_divergences.len(),
            contaminated_divergence_count: report.contaminated_divergences.len(),
        }
    }

    fn legacy_missing() -> Self {
        Self {
            mode: "legacy-missing".to_string(),
            candidate: "legacy-missing".to_string(),
            matched: false,
            oracle_root: None,
            candidate_root: None,
            divergence_count: 0,
            root_divergence_count: 0,
            contaminated_divergence_count: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
struct HistoryBenchmarkRecord {
    name: String,
    attr: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    temperature: Option<String>,
    #[serde(default)]
    context: Option<BenchmarkContext>,
    #[serde(default)]
    parity: Option<BenchmarkParity>,
    samples: Vec<BenchmarkSample>,
    summary: BenchmarkSummary,
}

impl HistoryBenchmarkRecord {
    fn into_record(
        self,
        run_context: Option<&BenchmarkContext>,
        run_file: &str,
    ) -> BenchmarkRecord {
        let context = self
            .context
            .or_else(|| run_context.cloned())
            .unwrap_or_else(|| BenchmarkContext::legacy_missing(run_file));
        let file = self.file.unwrap_or_else(|| {
            run_context.map_or_else(|| run_file.to_string(), |ctx| ctx.file.clone())
        });
        BenchmarkRecord {
            name: self.name,
            file,
            attr: self.attr,
            category: self.category.unwrap_or_else(|| "legacy".to_string()),
            temperature: self.temperature.unwrap_or_else(|| "cold".to_string()),
            context,
            parity: self.parity.unwrap_or_else(BenchmarkParity::legacy_missing),
            samples: self.samples,
            summary: self.summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkSample {
    elapsed_seconds: f64,
    elapsed_nanos: u64,
    drv_path: String,
    stats: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkSummary {
    samples: usize,
    mean_seconds: f64,
    stddev_seconds: f64,
    min_seconds: f64,
    max_seconds: f64,
    stats_mean: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkComparison {
    previous_commit: String,
    previous_mean_seconds: f64,
    current_mean_seconds: f64,
    delta_seconds: f64,
    delta_percent: f64,
    threshold_percent: f64,
    z_score: Option<f64>,
    significant: bool,
    regression: bool,
    improvement: bool,
    stats_delta: BTreeMap<String, StatsDelta>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkAdmissibility {
    required: bool,
    admitted: bool,
    parity_green: bool,
    regression_free: bool,
    real_workload_improvement: bool,
    counter_breakdown: bool,
    compared_real_workloads: usize,
    improving_real_workloads: usize,
    failure_reasons: Vec<String>,
}

impl BenchmarkAdmissibility {
    fn evaluate(outcomes: &[BenchmarkOutcome], required: bool, regression_count: usize) -> Self {
        let parity_green = outcomes.iter().all(|outcome| {
            let parity = &outcome.record.parity;
            parity.matched
                && parity.mode == "byte"
                && parity.divergence_count == 0
                && parity.root_divergence_count == 0
                && parity.contaminated_divergence_count == 0
        });
        let regression_free = regression_count == 0;
        let real_comparisons = outcomes
            .iter()
            .filter(|outcome| is_real_workload(&outcome.record))
            .filter_map(|outcome| outcome.comparison.as_ref())
            .collect::<Vec<_>>();
        let compared_real_workloads = real_comparisons.len();
        let improving_real = real_comparisons
            .iter()
            .copied()
            .filter(|comparison| comparison.improvement)
            .collect::<Vec<_>>();
        let improving_real_workloads = improving_real.len();
        let real_workload_improvement = improving_real_workloads > 0;
        let counter_breakdown = improving_real
            .iter()
            .any(|comparison| !comparison.stats_delta.is_empty());

        let mut failure_reasons = Vec::new();
        if !parity_green {
            failure_reasons.push("the .drv parity gate did not prove byte parity".to_string());
        }
        if !regression_free {
            let plural = if regression_count == 1 { "" } else { "s" };
            failure_reasons.push(format!(
                "{regression_count} benchmark regression{plural} found"
            ));
        }
        if compared_real_workloads == 0 {
            failure_reasons
                .push("no non-diagnostic workload had a comparable baseline".to_string());
        } else if !real_workload_improvement {
            failure_reasons.push(
                "no non-diagnostic workload improved past the configured threshold".to_string(),
            );
        }
        if real_workload_improvement && !counter_breakdown {
            failure_reasons.push(
                "improving non-diagnostic workloads had no stats delta breakdown".to_string(),
            );
        }

        let admitted =
            parity_green && regression_free && real_workload_improvement && counter_breakdown;
        Self {
            required,
            admitted,
            parity_green,
            regression_free,
            real_workload_improvement,
            counter_breakdown,
            compared_real_workloads,
            improving_real_workloads,
            failure_reasons,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct StatsDelta {
    previous: f64,
    current: f64,
    delta: f64,
    delta_percent: Option<f64>,
}

fn run_one_benchmark(
    oracle: &NixCli,
    candidate: &dyn NixEval,
    candidate_name: &str,
    spec: &BenchmarkSpec,
    eval_config: &NixEvalConfig,
    samples: usize,
) -> Result<BenchmarkRecord> {
    let parity = run_parity_gate(oracle, candidate, candidate_name, spec)?;
    let mut records = Vec::with_capacity(samples);
    for _ in 0..samples {
        let stats = oracle
            .instantiate_with_stats(&spec.file, &spec.attr)
            .with_context(|| format!("capturing NIX_SHOW_STATS for {}", spec.name))?;
        records.push(BenchmarkSample {
            elapsed_seconds: stats.elapsed.as_secs_f64(),
            elapsed_nanos: duration_nanos(stats.elapsed),
            drv_path: stats.drv_path.to_string_lossy().into_owned(),
            stats: stats.stats,
        });
    }

    Ok(BenchmarkRecord {
        name: spec.name.clone(),
        file: spec.file.to_string_lossy().into_owned(),
        attr: spec.attr.clone(),
        category: spec.category.clone(),
        temperature: spec.temperature.clone(),
        context: BenchmarkContext::from_eval_config(&spec.file, eval_config),
        parity,
        summary: summarize_samples(&records),
        samples: records,
    })
}

fn run_parity_gate(
    oracle: &dyn NixEval,
    candidate: &dyn NixEval,
    candidate_name: &str,
    spec: &BenchmarkSpec,
) -> Result<BenchmarkParity> {
    let report = diff_closure(oracle, candidate, &spec.file, &spec.attr, DiffMode::Byte)
        .with_context(|| format!("checking .drv parity for {}", spec.name))?;
    if !report.divergences.is_empty() {
        return Err(NixBenchParityFailure::new(spec, candidate_name, &report).into());
    }
    Ok(BenchmarkParity::matched(candidate_name, &report))
}

fn summarize_samples(samples: &[BenchmarkSample]) -> BenchmarkSummary {
    let count = samples.len();
    let mean_seconds = samples
        .iter()
        .map(|sample| sample.elapsed_seconds)
        .sum::<f64>()
        / count as f64;
    let stddev_seconds = if count > 1 {
        let variance = samples
            .iter()
            .map(|sample| {
                let delta = sample.elapsed_seconds - mean_seconds;
                delta * delta
            })
            .sum::<f64>()
            / (count - 1) as f64;
        variance.sqrt()
    } else {
        0.0
    };
    let min_seconds = samples
        .iter()
        .map(|sample| sample.elapsed_seconds)
        .fold(f64::INFINITY, f64::min);
    let max_seconds = samples
        .iter()
        .map(|sample| sample.elapsed_seconds)
        .fold(f64::NEG_INFINITY, f64::max);

    BenchmarkSummary {
        samples: count,
        mean_seconds,
        stddev_seconds,
        min_seconds,
        max_seconds,
        stats_mean: mean_numeric_stats(samples),
    }
}

fn mean_numeric_stats(samples: &[BenchmarkSample]) -> BTreeMap<String, f64> {
    let mut values = BTreeMap::new();
    for key in STATS_DELTA_KEYS {
        let mut total = 0.0;
        let mut count = 0_u64;
        for sample in samples {
            if let Some(value) = numeric_json_value(sample.stats.get(*key)) {
                total += value;
                count = count.saturating_add(1);
            }
        }
        if count > 0 {
            values.insert((*key).to_string(), total / count as f64);
        }
    }
    values
}

fn numeric_json_value(value: Option<&serde_json::Value>) -> Option<f64> {
    match value {
        Some(serde_json::Value::Number(number)) => number.as_f64(),
        _ => None,
    }
}

fn compare_benchmarks(
    current: &BenchmarkRecord,
    previous: PreviousBenchmark<'_>,
    threshold: f64,
) -> BenchmarkComparison {
    let current_mean = current.summary.mean_seconds;
    let previous_mean = previous.record.summary.mean_seconds;
    let delta_seconds = current_mean - previous_mean;
    let delta_percent = if previous_mean > 0.0 {
        delta_seconds / previous_mean
    } else {
        0.0
    };
    let (significant, z_score) = significant_movement(current, previous.record, delta_seconds);
    let regression = delta_percent > threshold && significant;
    let improvement = delta_percent < -threshold && significant;

    BenchmarkComparison {
        previous_commit: previous.commit.to_string(),
        previous_mean_seconds: previous_mean,
        current_mean_seconds: current_mean,
        delta_seconds,
        delta_percent,
        threshold_percent: threshold,
        z_score,
        significant,
        regression,
        improvement,
        stats_delta: stats_delta(&current.summary, &previous.record.summary),
    }
}

fn significant_movement(
    current: &BenchmarkRecord,
    previous: &BenchmarkRecord,
    delta_seconds: f64,
) -> (bool, Option<f64>) {
    if delta_seconds == 0.0 {
        return (false, None);
    }
    if current.summary.samples < 2 || previous.summary.samples < 2 {
        return (true, None);
    }

    let current_variance = current.summary.stddev_seconds * current.summary.stddev_seconds;
    let previous_variance = previous.summary.stddev_seconds * previous.summary.stddev_seconds;
    let standard_error = (current_variance / current.summary.samples as f64
        + previous_variance / previous.summary.samples as f64)
        .sqrt();
    if standard_error == 0.0 {
        return (true, None);
    }

    let z_score = delta_seconds.abs() / standard_error;
    (z_score >= SIGNIFICANCE_Z, Some(z_score))
}

fn is_real_workload(record: &BenchmarkRecord) -> bool {
    record.category != "diagnostic"
}

fn stats_delta(
    current: &BenchmarkSummary,
    previous: &BenchmarkSummary,
) -> BTreeMap<String, StatsDelta> {
    let mut deltas = BTreeMap::new();
    for key in STATS_DELTA_KEYS {
        let Some(current_value) = current.stats_mean.get(*key).copied() else {
            continue;
        };
        let Some(previous_value) = previous.stats_mean.get(*key).copied() else {
            continue;
        };
        let delta = current_value - previous_value;
        let delta_percent = (previous_value != 0.0).then_some(delta / previous_value);
        deltas.insert(
            (*key).to_string(),
            StatsDelta {
                previous: previous_value,
                current: current_value,
                delta,
                delta_percent,
            },
        );
    }
    deltas
}

#[derive(Clone, Copy)]
struct PreviousBenchmark<'a> {
    commit: &'a str,
    record: &'a BenchmarkRecord,
}

fn previous_benchmark<'a>(
    history: &'a [BenchmarkRunRecord],
    current: &BenchmarkRecord,
    current_commit: &str,
) -> Option<PreviousBenchmark<'a>> {
    history.iter().rev().find_map(|run| {
        if run.commit == current_commit {
            return None;
        }
        run.benchmarks
            .iter()
            .find(|record| {
                record.name == current.name
                    && record.context == current.context
                    && parity_context_matches(&record.parity, &current.parity)
            })
            .map(|record| PreviousBenchmark {
                commit: run.commit.as_str(),
                record,
            })
    })
}

fn parity_context_matches(previous: &BenchmarkParity, current: &BenchmarkParity) -> bool {
    previous.matched
        && current.matched
        && previous.mode == current.mode
        && previous.candidate == current.candidate
}

fn read_history(path: &Path) -> Result<Vec<BenchmarkRunRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record = serde_json::from_str::<HistoryRunRecord>(line).with_context(|| {
            format!(
                "parsing benchmark history {} line {}",
                path.display(),
                index + 1
            )
        })?;
        records.push(record.into_record());
    }
    Ok(records)
}

fn append_history(path: &Path, record: &BenchmarkRunRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening benchmark history {}", path.display()))?;
    serde_json::to_writer(&mut file, record)
        .with_context(|| format!("writing benchmark history {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("writing benchmark history {}", path.display()))?;
    Ok(())
}

fn run_json(
    run: &BenchmarkRunRecord,
    outcomes: &[BenchmarkOutcome],
    admissibility: &BenchmarkAdmissibility,
    history: &Path,
    recorded: bool,
    blocked: bool,
    failure: Option<&NixBenchRegressionFailure>,
    admissibility_failure: Option<&NixBenchAdmissibilityFailure>,
) -> serde_json::Value {
    let errors = benchmark_error_messages(failure, admissibility_failure);
    serde_json::json!({
        "version": run.version,
        "commit": run.commit,
        "timestamp_unix_ms": run.timestamp_unix_ms,
        "file": run.file,
        "history": history.to_string_lossy(),
        "recorded": recorded,
        "blocked": blocked,
        "regression_count": outcomes.iter().filter(|outcome| {
            outcome.comparison.as_ref().is_some_and(|comparison| comparison.regression)
        }).count(),
        "admissibility": admissibility,
        "error": errors.first(),
        "errors": errors,
        "benchmarks": outcomes.iter().map(outcome_json).collect::<Vec<_>>(),
    })
}

fn outcome_json(outcome: &BenchmarkOutcome) -> serde_json::Value {
    serde_json::json!({
        "name": &outcome.record.name,
        "file": &outcome.record.file,
        "attr": &outcome.record.attr,
        "category": &outcome.record.category,
        "temperature": &outcome.record.temperature,
        "context": &outcome.record.context,
        "parity": &outcome.record.parity,
        "samples": &outcome.record.samples,
        "summary": &outcome.record.summary,
        "comparison": &outcome.comparison,
    })
}

fn render_human_report(
    printer: &Printer,
    run: &BenchmarkRunRecord,
    outcomes: &[BenchmarkOutcome],
    admissibility: &BenchmarkAdmissibility,
    history: &Path,
    recorded: bool,
    failure: Option<&NixBenchRegressionFailure>,
    admissibility_failure: Option<&NixBenchAdmissibilityFailure>,
) {
    let errors = benchmark_error_messages(failure, admissibility_failure);
    if let Some(error) = errors.first() {
        if printer.mode() == OutputMode::Quiet {
            printer.error(error);
            return;
        }
        for error in errors {
            printer.warning(&error);
        }
    } else {
        printer.success(&format!(
            "nix benchmark completed for {} benchmark(s) at {}",
            outcomes.len(),
            short_commit(&run.commit)
        ));
    }

    if printer.mode() == OutputMode::Quiet {
        return;
    }

    for outcome in outcomes {
        render_outcome(printer, outcome);
    }
    printer.plain(&format!(
        "  admissibility: admitted={} required={} parity={} regressions={} real_improvements={} stats_breakdown={}",
        admissibility.admitted,
        admissibility.required,
        admissibility.parity_green,
        admissibility.regression_free,
        admissibility.improving_real_workloads,
        admissibility.counter_breakdown
    ));
    if recorded {
        printer.plain(&format!("  history: {}", history.display()));
    } else {
        printer.plain("  history: not recorded (--no-record)");
    }
}

fn render_outcome(printer: &Printer, outcome: &BenchmarkOutcome) {
    let summary = &outcome.record.summary;
    let mut line = format!(
        "  - {} mean={:.6}s stddev={:.6}s samples={} parity={}:{}",
        outcome.record.name,
        summary.mean_seconds,
        summary.stddev_seconds,
        summary.samples,
        outcome.record.parity.mode,
        outcome.record.parity.candidate
    );
    if let Some(comparison) = &outcome.comparison {
        line.push_str(&format!(
            " delta={:+.2}% threshold={:.2}%",
            comparison.delta_percent * 100.0,
            comparison.threshold_percent * 100.0
        ));
        if let Some(z_score) = comparison.z_score {
            line.push_str(&format!(" z={z_score:.2}"));
        } else {
            line.push_str(" z=n/a");
        }
        if comparison.regression {
            line.push_str(" REGRESSION");
        }
        if comparison.improvement {
            line.push_str(" IMPROVEMENT");
        }
        let stats = render_stats_delta(comparison);
        if !stats.is_empty() {
            line.push_str(&format!(" stats_delta=[{stats}]"));
        }
    } else {
        line.push_str(" baseline=none");
    }
    printer.plain(&line);
}

fn benchmark_error_messages(
    failure: Option<&NixBenchRegressionFailure>,
    admissibility_failure: Option<&NixBenchAdmissibilityFailure>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(failure) = failure {
        errors.push(failure.to_string());
    }
    if let Some(failure) = admissibility_failure {
        errors.push(failure.to_string());
    }
    errors
}

fn finish_benchmark_run(
    blocked: bool,
    failure: Option<NixBenchRegressionFailure>,
    admissibility_failure: Option<NixBenchAdmissibilityFailure>,
) -> Result<()> {
    if !blocked {
        return Ok(());
    }
    if let Some(failure) = admissibility_failure {
        return Err(failure.into());
    }
    if let Some(failure) = failure {
        return Err(failure.into());
    }
    Ok(())
}

fn render_stats_delta(comparison: &BenchmarkComparison) -> String {
    comparison
        .stats_delta
        .iter()
        .map(|(key, delta)| {
            if let Some(percent) = delta.delta_percent {
                format!("{key}={:+.2} ({:+.2}%)", delta.delta, percent * 100.0)
            } else {
                format!("{key}={:+.2}", delta.delta)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn current_commit_sha() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("running git rev-parse HEAD for benchmark commit key")?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let commit = String::from_utf8(output.stdout).context("git rev-parse HEAD output is UTF-8")?;
    let commit = commit.trim();
    if commit.is_empty() {
        anyhow::bail!("git rev-parse HEAD returned an empty commit");
    }
    Ok(commit.to_string())
}

fn unix_timestamp_millis() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    Ok(u64::try_from(millis).unwrap_or(u64::MAX))
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn short_commit(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

#[cfg(test)]
mod tests;
