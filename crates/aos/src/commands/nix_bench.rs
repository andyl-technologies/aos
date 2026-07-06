//! `aos nix-bench` -- record per-commit Nix evaluation benchmarks.
//!
//! A run evaluates a corpus of attributes twice per sample: once through the
//! C++ Nix **oracle** (capturing `NIX_SHOW_STATS`) and once through the
//! **native** evaluator candidate. The native timings are the subject under
//! test, so history, regression gating (`--fail-on-regression`), and perf-win
//! admission (`--require-perf-win`) are all driven by them, with the oracle
//! timings reported alongside for context and the `native / oracle` ratio as the
//! headline metric.
//!
//! The module is split by concern: `record` owns the on-disk JSONL schema,
//! `analysis` owns regression and admissibility analysis, `corpus` builds the
//! benchmark specs, and this file drives sampling and rendering.

mod analysis;
pub(crate) mod corpus;
mod record;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use aos_core::error::AosError;
use aos_core::nix::{
    NixCli, NixEval, NixEvalConfig, NixEvalMode, NixRunner,
    select_native_diff_candidate_with_config,
};
use aos_core::output::{OutputMode, Printer};
use aos_nix_harness::diff::{DiffMode, DrvDiffReport, diff_closure};

use analysis::*;
use corpus::{BenchmarkSpec, benchmark_specs};
use record::*;

const DEFAULT_SAMPLES: usize = 3;
const DEFAULT_REGRESSION_THRESHOLD: f64 = 0.10;

/// Error returned after `aos nix-bench` has rendered a regression report.
#[derive(Debug, Clone)]
pub struct NixBenchRegressionFailure {
    message: String,
}

impl NixBenchRegressionFailure {
    fn new(count: usize) -> Self {
        let plural = if count == 1 { "" } else { "s" };
        Self {
            message: format!("nix benchmark found {count} significant native regression{plural}"),
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
/// instantiate a selected attribute with `NIX_SHOW_STATS`, the native evaluator
/// cannot instantiate a selected attribute, history cannot be read or written,
/// or `fail_on_regression` is set and a significant native regression is
/// detected. It also returns an error when `require_perf_win` is set and the run
/// is not admissible as a performance win.
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

/// Runs the parity gate and captures paired oracle and native timing samples.
///
/// The oracle samples carry `NIX_SHOW_STATS` counters; the native samples time a
/// plain [`NixEval::instantiate`] of the same file and attribute, without the
/// byte-diff cost the parity gate already paid.
fn run_one_benchmark(
    oracle: &NixCli,
    candidate: &dyn NixEval,
    candidate_name: &str,
    spec: &BenchmarkSpec,
    eval_config: &NixEvalConfig,
    samples: usize,
) -> Result<BenchmarkRecord> {
    let parity = run_parity_gate(oracle, candidate, candidate_name, spec)?;
    let oracle_samples = capture_benchmark_samples(spec, samples, || {
        let stats = oracle
            .instantiate_with_stats(&spec.file, &spec.attr)
            .with_context(|| format!("running nix-instantiate for {}", spec.name))?;
        Ok(BenchmarkSample {
            elapsed_seconds: stats.elapsed.as_secs_f64(),
            elapsed_nanos: duration_nanos(stats.elapsed),
            drv_path: stats.drv_path.to_string_lossy().into_owned(),
            stats: stats.stats,
        })
    })?;
    let native_samples = capture_benchmark_samples(spec, samples, || {
        let started = Instant::now();
        let drv_path = candidate
            .instantiate(&spec.file, &spec.attr)
            .with_context(|| format!("running native instantiate for {}", spec.name))?;
        let elapsed = started.elapsed();
        Ok(NativeBenchmarkSample {
            elapsed_seconds: elapsed.as_secs_f64(),
            elapsed_nanos: duration_nanos(elapsed),
            drv_path: drv_path.to_string_lossy().into_owned(),
        })
    })?;

    Ok(BenchmarkRecord {
        name: spec.name.clone(),
        file: spec.file.to_string_lossy().into_owned(),
        attr: spec.attr.clone(),
        category: spec.category.clone(),
        temperature: spec.temperature.clone(),
        context: BenchmarkContext::from_eval_config(&spec.file, eval_config),
        parity,
        summary: summarize_samples(&oracle_samples),
        samples: oracle_samples,
        native_summary: summarize_native_samples(&native_samples),
        native_samples,
    })
}

/// Captures `samples` timing samples, priming once for warm-temperature specs.
///
/// The same warm-up semantics apply to whichever evaluator `capture` exercises,
/// so the native and oracle sides both honor the corpus temperature.
///
/// # Errors
///
/// Returns the first error produced by `capture`, whether during the warm-up
/// call or a recorded sample.
fn capture_benchmark_samples<T>(
    spec: &BenchmarkSpec,
    samples: usize,
    mut capture: impl FnMut() -> Result<T>,
) -> Result<Vec<T>> {
    if temperature_requires_warmup(&spec.temperature) {
        let _ = capture().with_context(|| format!("warming eval cache for {}", spec.name))?;
    }

    let mut records = Vec::with_capacity(samples);
    for _ in 0..samples {
        records.push(
            capture().with_context(|| format!("capturing benchmark sample for {}", spec.name))?,
        );
    }
    Ok(records)
}

fn temperature_requires_warmup(temperature: &str) -> bool {
    temperature == "warm"
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
        "native_samples": &outcome.record.native_samples,
        "native_summary": &outcome.record.native_summary,
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
    let record = &outcome.record;
    let native = &record.native_summary;
    let oracle = &record.summary;
    let mut line = format!(
        "  - {} native_mean={:.6}s oracle_mean={:.6}s native/oracle={} samples={} parity={}:{}",
        record.name,
        native.mean_seconds,
        oracle.mean_seconds,
        ratio_display(native.mean_seconds, oracle.mean_seconds),
        native.samples,
        record.parity.mode,
        record.parity.candidate
    );
    if let Some(comparison) = &outcome.comparison {
        line.push_str(&format!(
            " native_delta={:+.2}% z={} oracle_delta={:+.2}% threshold={:.2}%",
            comparison.delta_percent * 100.0,
            z_display(comparison.z_score),
            comparison.oracle.delta_percent * 100.0,
            comparison.threshold_percent * 100.0
        ));
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

/// Formats the `native / oracle` mean ratio, or `n/a` when the oracle mean is
/// not positive.
fn ratio_display(native_mean: f64, oracle_mean: f64) -> String {
    if oracle_mean > 0.0 {
        format!("{:.3}x", native_mean / oracle_mean)
    } else {
        "n/a".to_string()
    }
}

/// Formats a z-score, or `n/a` when the movement had no defined z-score.
fn z_display(z_score: Option<f64>) -> String {
    match z_score {
        Some(z_score) => format!("{z_score:.2}"),
        None => "n/a".to_string(),
    }
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
