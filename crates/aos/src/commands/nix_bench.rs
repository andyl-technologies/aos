//! `aos nix-bench` -- record per-commit Nix evaluation benchmarks.

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
use aos_core::nix::{NixCli, NixEvalConfig, NixEvalMode, NixRunner};
use aos_core::output::{OutputMode, Printer};

const BENCH_HISTORY_VERSION: u32 = 1;
const DEFAULT_SAMPLES: usize = 3;
const DEFAULT_REGRESSION_THRESHOLD: f64 = 0.10;
const SIGNIFICANCE_Z: f64 = 2.0;
const DEFAULT_BENCH_ATTRS: &[&str] = &["pkgs.zlib"];
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

/// Runs the per-commit Nix evaluation benchmark scaffold.
///
/// # Errors
///
/// Returns an error if the benchmark arguments are invalid, Git cannot provide
/// the current commit SHA, Nix cannot instantiate a selected attribute with
/// `NIX_SHOW_STATS`, history cannot be read or written, or `fail_on_regression`
/// is set and a significant regression is detected.
pub fn run(
    printer: &Printer,
    verbose: u8,
    eval_config: NixEvalConfig,
    file: Option<&Path>,
    attrs: &[String],
    samples: usize,
    history: Option<&Path>,
    no_record: bool,
    fail_on_regression: bool,
    regression_threshold: f64,
) -> Result<()> {
    validate_args(samples, regression_threshold)?;
    NixRunner::ensure_nix_instantiate_available()?;

    let root = NixRunner::find_root()?;
    let file = file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("default.nix"));
    let file = absolute_eval_file(&file)?;
    let history = history
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".aos-benchmarks").join("nix-eval.jsonl"));
    let commit = current_commit_sha()?;
    let attrs = selected_attrs(attrs);
    let previous_runs = read_history(&history)?;
    let context = BenchmarkContext::from_eval_config(&file, &eval_config);
    let oracle = NixCli::with_eval_config(verbose, eval_config);

    printer.info(&format!(
        "Running {} Nix eval benchmark(s) with {samples} sample(s)...",
        attrs.len()
    ));

    let mut outcomes = Vec::with_capacity(attrs.len());
    for attr in attrs {
        let record = run_one_benchmark(&oracle, &file, &attr, samples)?;
        let comparison = previous_benchmark(&previous_runs, &context, &record.name, &commit)
            .map(|previous| compare_benchmarks(&record, previous, regression_threshold));
        outcomes.push(BenchmarkOutcome { record, comparison });
    }

    let run = BenchmarkRunRecord {
        version: BENCH_HISTORY_VERSION,
        commit,
        timestamp_unix_ms: unix_timestamp_millis()?,
        file: file.to_string_lossy().into_owned(),
        context,
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
    let blocked = fail_on_regression && failure.is_some();

    if printer.json_if_active(&run_json(
        &run,
        &outcomes,
        &history,
        !no_record,
        blocked,
        failure.as_ref(),
    )) {
        if blocked {
            if let Some(failure) = failure.clone() {
                return Err(failure.into());
            }
        }
        return Ok(());
    }

    render_human_report(
        printer,
        &run,
        &outcomes,
        &history,
        !no_record,
        failure.as_ref(),
    );

    if blocked {
        if let Some(failure) = failure {
            return Err(failure.into());
        }
    }
    Ok(())
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

fn selected_attrs(attrs: &[String]) -> Vec<String> {
    if attrs.is_empty() {
        return DEFAULT_BENCH_ATTRS
            .iter()
            .map(|attr| (*attr).to_string())
            .collect();
    }
    attrs.to_vec()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkRunRecord {
    version: u32,
    commit: String,
    timestamp_unix_ms: u64,
    file: String,
    context: BenchmarkContext,
    benchmarks: Vec<BenchmarkRecord>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkRecord {
    name: String,
    attr: String,
    samples: Vec<BenchmarkSample>,
    summary: BenchmarkSummary,
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
    stats_delta: BTreeMap<String, StatsDelta>,
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
    file: &Path,
    attr: &str,
    samples: usize,
) -> Result<BenchmarkRecord> {
    let mut records = Vec::with_capacity(samples);
    for _ in 0..samples {
        let stats = oracle
            .instantiate_with_stats(file, attr)
            .with_context(|| format!("capturing NIX_SHOW_STATS for {attr}"))?;
        records.push(BenchmarkSample {
            elapsed_seconds: stats.elapsed.as_secs_f64(),
            elapsed_nanos: duration_nanos(stats.elapsed),
            drv_path: stats.drv_path.to_string_lossy().into_owned(),
            stats: stats.stats,
        });
    }

    Ok(BenchmarkRecord {
        name: format!("eval:{attr}"),
        attr: attr.to_string(),
        summary: summarize_samples(&records),
        samples: records,
    })
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
    let (significant, z_score) = significance(current, previous.record, delta_seconds);
    let regression = delta_percent > threshold && significant;

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
        stats_delta: stats_delta(&current.summary, &previous.record.summary),
    }
}

fn significance(
    current: &BenchmarkRecord,
    previous: &BenchmarkRecord,
    delta_seconds: f64,
) -> (bool, Option<f64>) {
    if delta_seconds <= 0.0 {
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

    let z_score = delta_seconds / standard_error;
    (z_score >= SIGNIFICANCE_Z, Some(z_score))
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
    context: &BenchmarkContext,
    name: &str,
    current_commit: &str,
) -> Option<PreviousBenchmark<'a>> {
    history.iter().rev().find_map(|run| {
        if run.commit == current_commit || run.context != *context {
            return None;
        }
        run.benchmarks
            .iter()
            .find(|record| record.name == name)
            .map(|record| PreviousBenchmark {
                commit: run.commit.as_str(),
                record,
            })
    })
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
        let record = serde_json::from_str::<BenchmarkRunRecord>(line).with_context(|| {
            format!(
                "parsing benchmark history {} line {}",
                path.display(),
                index + 1
            )
        })?;
        records.push(record);
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
    history: &Path,
    recorded: bool,
    blocked: bool,
    failure: Option<&NixBenchRegressionFailure>,
) -> serde_json::Value {
    serde_json::json!({
        "version": run.version,
        "commit": run.commit,
        "timestamp_unix_ms": run.timestamp_unix_ms,
        "file": run.file,
        "context": &run.context,
        "history": history.to_string_lossy(),
        "recorded": recorded,
        "blocked": blocked,
        "regression_count": outcomes.iter().filter(|outcome| {
            outcome.comparison.as_ref().is_some_and(|comparison| comparison.regression)
        }).count(),
        "error": failure.map(ToString::to_string),
        "benchmarks": outcomes.iter().map(outcome_json).collect::<Vec<_>>(),
    })
}

fn outcome_json(outcome: &BenchmarkOutcome) -> serde_json::Value {
    serde_json::json!({
        "name": &outcome.record.name,
        "attr": &outcome.record.attr,
        "samples": &outcome.record.samples,
        "summary": &outcome.record.summary,
        "comparison": &outcome.comparison,
    })
}

fn render_human_report(
    printer: &Printer,
    run: &BenchmarkRunRecord,
    outcomes: &[BenchmarkOutcome],
    history: &Path,
    recorded: bool,
    failure: Option<&NixBenchRegressionFailure>,
) {
    if let Some(failure) = failure {
        if printer.mode() == OutputMode::Quiet {
            printer.error(&failure.to_string());
            return;
        }
        printer.warning(&failure.to_string());
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
    if recorded {
        printer.plain(&format!("  history: {}", history.display()));
    } else {
        printer.plain("  history: not recorded (--no-record)");
    }
}

fn render_outcome(printer: &Printer, outcome: &BenchmarkOutcome) {
    let summary = &outcome.record.summary;
    let mut line = format!(
        "  - {} mean={:.6}s stddev={:.6}s samples={}",
        outcome.record.name, summary.mean_seconds, summary.stddev_seconds, summary.samples
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
        let stats = render_stats_delta(comparison);
        if !stats.is_empty() {
            line.push_str(&format!(" stats_delta=[{stats}]"));
        }
    } else {
        line.push_str(" baseline=none");
    }
    printer.plain(&line);
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
