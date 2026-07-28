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
//! benchmark specs, `memory` owns the per-sample memory probes (RSS, peak-RSS
//! watermarks, arena gauges), and this file drives sampling and rendering.

mod analysis;
#[cfg(feature = "native-eval")]
mod changed_tree;
mod cold_only;
pub(crate) mod corpus;
mod memory;
mod record;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tempfile::TempDir;

use aos_core::error::AosError;
use aos_core::nix::{
    NixCli, NixEval, NixEvalConfig, NixEvalMode, NixRunner,
    select_native_diff_candidate_with_config,
};
use aos_core::output::{OutputMode, Printer};
use aos_nix_harness::diff::{DiffMode, DrvDiffReport, diff_closure};

use analysis::*;
use corpus::{BenchmarkSpec, benchmark_specs};
use memory::{NativeMemoryBefore, OracleChildPeakBefore, mib, trace_phase};
use record::*;

const DEFAULT_SAMPLES: usize = 3;
const DEFAULT_REGRESSION_THRESHOLD: f64 = 0.10;
const DEFAULT_MEMORY_REGRESSION_THRESHOLD: f64 = 0.10;

/// Error returned after `aos nix-bench` has rendered a regression report.
#[derive(Debug, Clone)]
pub struct NixBenchRegressionFailure {
    message: String,
}

impl NixBenchRegressionFailure {
    fn new(count: usize, memory_count: usize) -> Self {
        let plural = if count == 1 { "" } else { "s" };
        let memory = if memory_count > 0 {
            let plural = if memory_count == 1 { "" } else { "s" };
            format!(" (including {memory_count} peak-memory regression{plural})")
        } else {
            String::new()
        };
        Self {
            message: format!(
                "nix benchmark found {count} significant native regression{plural}{memory}"
            ),
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
/// or `fail_on_regression` is set and a significant native time or peak-memory
/// regression is detected. It also returns an error when `require_perf_win` is
/// set and the run is not admissible as a performance win.
#[allow(clippy::too_many_arguments)]
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
    memory_regression_threshold: f64,
    changed_tree: bool,
) -> Result<()> {
    validate_args(samples, regression_threshold, memory_regression_threshold)?;
    if eval_config.eval_mode() == NixEvalMode::Ambient {
        eval_config.set_eval_mode(NixEvalMode::Impure);
    }
    // Instruction-attribution diagnostics path (RFC-0007 instruction-bloat
    // campaign): a single, isolated, native-only cold eval with no C++ oracle,
    // no warm re-instantiate, no parity gate, and no history — so `perf stat`
    // wrapping this process counts exactly one cold eval's retired
    // instructions, and a paired `AOS_NIX_EVAL_STATS=1` run reports that same
    // eval's op counters and force-shape census for the per-op budget. See the
    // instruction-bloat design note.
    if cold_only::enabled() {
        return cold_only::run(printer, verbose, &eval_config, file, attrs);
    }
    NixRunner::ensure_nix_instantiate_available()?;
    if changed_tree {
        #[cfg(feature = "native-eval")]
        return changed_tree::run(printer, verbose, samples);
        #[cfg(not(feature = "native-eval"))]
        anyhow::bail!("nix-bench --changed-tree requires the native-eval feature");
    }
    let candidate = select_native_diff_candidate_with_config(verbose, eval_config.clone())
        .context("initializing nix-bench .drv parity gate")?;
    let candidate_name = candidate.name().to_string();
    trace_phase("candidate-initialized");

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

    // Each attribute yields two records (cold + warm) from one paired-cycle run.
    let mut outcomes = Vec::with_capacity(specs.len().saturating_mul(2));
    for spec in specs {
        let records = run_one_benchmark(
            &oracle,
            candidate.as_ref(),
            &candidate_name,
            &spec,
            &eval_config,
            verbose,
            samples,
        )?;
        for record in records {
            let comparison = previous_benchmark(&previous_runs, &record, &commit).map(|previous| {
                compare_benchmarks(
                    &record,
                    previous,
                    regression_threshold,
                    memory_regression_threshold,
                )
            });
            outcomes.push(BenchmarkOutcome { record, comparison });
        }
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

    let time_regression_count = outcomes
        .iter()
        .filter(|outcome| {
            outcome
                .comparison
                .as_ref()
                .is_some_and(|comparison| comparison.regression)
        })
        .count();
    let memory_regression_count = outcomes
        .iter()
        .filter(|outcome| {
            outcome.comparison.as_ref().is_some_and(|comparison| {
                comparison
                    .memory
                    .as_ref()
                    .is_some_and(|memory| memory.regression)
            })
        })
        .count();
    let regression_count = time_regression_count + memory_regression_count;
    let failure = (regression_count > 0)
        .then(|| NixBenchRegressionFailure::new(regression_count, memory_regression_count));
    // Perf-win admissibility stays driven by the timing movements; a memory
    // regression blocks `--fail-on-regression` but does not veto admission.
    let admissibility =
        BenchmarkAdmissibility::evaluate(&outcomes, require_perf_win, time_regression_count);
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

/// Returns the default peak-memory regression threshold used by the CLI.
pub const fn default_memory_regression_threshold() -> f64 {
    DEFAULT_MEMORY_REGRESSION_THRESHOLD
}

fn validate_args(
    samples: usize,
    regression_threshold: f64,
    memory_regression_threshold: f64,
) -> Result<()> {
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
    if !memory_regression_threshold.is_finite() || memory_regression_threshold < 0.0 {
        return Err(AosError::InvalidArgument {
            message: "nix-bench --memory-regression-threshold must be a finite non-negative number"
                .to_string(),
        }
        .into());
    }
    Ok(())
}

pub(super) fn absolute_eval_file(path: &Path) -> Result<std::path::PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolving current directory for nix-bench file")?
        .join(path))
}

/// Temperature label for the first (cold) run of each paired cycle.
const COLD_TEMPERATURE: &str = "cold";
/// Temperature label for the second (warm) run of each paired cycle.
const WARM_TEMPERATURE: &str = "warm";

/// Runs the parity gate, samples the oracle, and produces the paired cold and
/// warm records for one attribute.
///
/// Each of the `samples` native cycles builds a FRESH evaluator instance whose
/// durable caches point at a fresh temp dir, times its first `instantiate()`
/// (the cold sample), then times a second `instantiate()` on the now-warm
/// instance (the warm sample), and drops the instance and its temp caches. The
/// oracle has no in-process warm state (a fresh `nix-instantiate` subprocess per
/// call), so it is sampled `samples` times once and its summary is shared as the
/// denominator for both records — the warm ratio is thus `warm_native /
/// cold_oracle`.
///
/// The parity gate runs on the long-lived `parity_candidate`, never on a cycle
/// instance, so it cannot pre-warm the first cycle's cold sample.
///
/// # Errors
///
/// Returns an error if the parity gate fails, or if any oracle or native
/// instantiation fails, or if a fresh cold evaluator cannot be built.
fn run_one_benchmark(
    oracle: &NixCli,
    parity_candidate: &dyn NixEval,
    candidate_name: &str,
    spec: &BenchmarkSpec,
    eval_config: &NixEvalConfig,
    verbose: u8,
    samples: usize,
) -> Result<[BenchmarkRecord; 2]> {
    trace_phase("parity-gate-start");
    let parity = run_parity_gate(oracle, parity_candidate, candidate_name, spec)?;
    trace_phase("parity-gate-done");

    let oracle_samples = capture_oracle_samples(oracle, spec, samples)?;
    trace_phase("oracle-samples-done");

    let mut cold_samples = Vec::with_capacity(samples);
    let mut warm_samples = Vec::with_capacity(samples);
    for _ in 0..samples {
        // Fresh instance + fresh durable caches: the first run is a true cold
        // eval, the second run reuses the now-warm instance. Both drop at the
        // end of the iteration, so no state carries into the next cycle.
        let (candidate, _cache_dir) = fresh_isolated_candidate(verbose, eval_config, spec)?;
        cold_samples.push(capture_native_sample(candidate.as_ref(), spec)?);
        warm_samples.push(capture_native_sample(candidate.as_ref(), spec)?);
    }
    trace_phase("native-cycles-done");

    let context = BenchmarkContext::from_eval_config(&spec.file, eval_config);
    let oracle_summary = summarize_samples(&oracle_samples);
    Ok([
        build_paired_record(
            spec,
            COLD_TEMPERATURE,
            PAIRED_COLD_SEMANTICS,
            &context,
            &parity,
            &oracle_samples,
            &oracle_summary,
            cold_samples,
        ),
        build_paired_record(
            spec,
            WARM_TEMPERATURE,
            PAIRED_WARM_SEMANTICS,
            &context,
            &parity,
            &oracle_samples,
            &oracle_summary,
            warm_samples,
        ),
    ])
}

/// Assembles one temperature's [`BenchmarkRecord`] from shared oracle data and
/// this temperature's native samples.
#[allow(clippy::too_many_arguments)]
fn build_paired_record(
    spec: &BenchmarkSpec,
    temperature: &str,
    temperature_semantics: &str,
    context: &BenchmarkContext,
    parity: &BenchmarkParity,
    oracle_samples: &[BenchmarkSample],
    oracle_summary: &BenchmarkSummary,
    native_samples: Vec<NativeBenchmarkSample>,
) -> BenchmarkRecord {
    let native_summary = summarize_native_samples(&native_samples);
    BenchmarkRecord {
        name: format!("{}:{temperature}:{}", spec.category, spec.attr),
        file: spec.file.to_string_lossy().into_owned(),
        attr: spec.attr.clone(),
        category: spec.category.clone(),
        temperature: temperature.to_string(),
        temperature_semantics: temperature_semantics.to_string(),
        context: context.clone(),
        parity: parity.clone(),
        summary: oracle_summary.clone(),
        samples: oracle_samples.to_vec(),
        native_summary,
        native_samples,
    }
}

/// Samples the C++ Nix oracle `samples` times. Every call is a fresh subprocess,
/// so all samples are cold; the summary is shared by both temperature records.
///
/// # Errors
///
/// Returns the first `nix-instantiate` failure.
fn capture_oracle_samples(
    oracle: &NixCli,
    spec: &BenchmarkSpec,
    samples: usize,
) -> Result<Vec<BenchmarkSample>> {
    let mut records = Vec::with_capacity(samples);
    for _ in 0..samples {
        let child_peak = OracleChildPeakBefore::capture();
        let stats = oracle
            .instantiate_with_stats(&spec.file, &spec.attr)
            .with_context(|| format!("running nix-instantiate for {}", spec.name))?;
        let child_peak = child_peak.finish();
        records.push(BenchmarkSample {
            elapsed_seconds: stats.elapsed.as_secs_f64(),
            elapsed_nanos: duration_nanos(stats.elapsed),
            drv_path: stats.drv_path.to_string_lossy().into_owned(),
            stats: stats.stats,
            child_peak_rss_bytes: child_peak.watermark_bytes,
            exact_child_peak_rss: child_peak.exact,
        });
    }
    Ok(records)
}

/// Times one native `instantiate()` with its bracketing memory probes.
///
/// # Errors
///
/// Returns the native instantiation failure, if any.
fn capture_native_sample(
    candidate: &dyn NixEval,
    spec: &BenchmarkSpec,
) -> Result<NativeBenchmarkSample> {
    let memory_before = NativeMemoryBefore::capture();
    let started = Instant::now();
    let drv_path = native_instantiate(candidate, spec)
        .with_context(|| format!("running native instantiate for {}", spec.name))?;
    let elapsed = started.elapsed();
    let memory = memory_before.finish();
    trace_phase("native-sample-done");
    Ok(NativeBenchmarkSample {
        elapsed_seconds: elapsed.as_secs_f64(),
        elapsed_nanos: duration_nanos(elapsed),
        drv_path: drv_path.to_string_lossy().into_owned(),
        memory,
    })
}

/// Builds a fresh native candidate whose durable caches (parse cache, eval
/// persist cache, root-cutoff records) point at a fresh temp dir, so its first
/// eval is a true cold eval against empty caches.
///
/// The returned [`TempDir`] owns the cache directory and removes it on drop;
/// keep it alive for the candidate's lifetime.
///
/// # Errors
///
/// Returns an error if the temp dir cannot be created, the cache root cannot be
/// configured, or the evaluator cannot be built.
pub(super) fn fresh_isolated_candidate(
    verbose: u8,
    base_config: &NixEvalConfig,
    spec: &BenchmarkSpec,
) -> Result<(Box<dyn NixEval>, Option<TempDir>)> {
    let mut config = base_config.clone();
    // "Cold" excludes cache data from earlier runs; it does not disable caches
    // populated and reused within this run. Enable both in-process memo
    // stack, but detach persistent and additive disk/network locations. Durable
    // cache population is a separate benchmark axis: including it here measures
    // cross-run serialization and writeback rather than the evaluator's legal
    // same-run reuse.
    enable_isolated_intra_run_caches(&mut config);
    let candidate = select_native_diff_candidate_with_config(verbose, config)
        .with_context(|| format!("building cold evaluator for {}", spec.name))?;
    Ok((candidate, None))
}

/// Enables every cache tier that can be populated without importing prior data.
fn enable_isolated_intra_run_caches(config: &mut NixEvalConfig) {
    config.clear_native_cache_root();
    let mut memo = config.native_memo();
    memo.enabled = true;
    memo.l0_enabled = true;
    memo.l1_enabled = Some(true);
    memo.l2_enabled = false;
    config.set_native_memo(memo);
    config.set_native_memo_disk_spec(None);
    config.set_native_memo_net(None);
}

/// Maximum `diff_closure` attempts before the parity gate reports an
/// unstable comparison.
const PARITY_GATE_MAX_ATTEMPTS: usize = 3;

/// Verdict for a parity-gate attempt that reported divergences.
#[derive(Debug, Eq, PartialEq)]
enum ParityAttemptVerdict {
    /// Two consecutive divergent attempts produced the same oracle root, so
    /// the evaluated inputs were identical both times: the divergence is real.
    RealDivergence,
    /// The oracle root moved since the previous divergent attempt (or this
    /// was the first attempt), so the evaluated sources may have changed
    /// between the oracle and candidate instantiations: retry.
    InputsDrifted,
}

/// Classifies one divergent parity-gate attempt against the previous one.
///
/// The gate's oracle and candidate instantiations are seconds apart on wide
/// attributes (the oracle writes the whole `.drv` closure), and an evaluated
/// source tree edited inside that window — `pkgs.aos` sources the live
/// `crates/` directory, which sits in every `bench.wide` closure — yields two
/// evaluations of *different* inputs. A drifted hash also reorders the sorted
/// `inputDrvs` lists, so the order-paired closure walk cascades one moved
/// node into tens of thousands of reported divergences. A divergence is only
/// trusted as real when a repeat attempt reproduces it from the same oracle
/// root, which pins the oracle-visible inputs as identical across both
/// attempts.
fn classify_divergent_attempt(
    previous_divergent_root: &mut Option<Option<std::path::PathBuf>>,
    oracle_root: &Option<std::path::PathBuf>,
) -> ParityAttemptVerdict {
    if previous_divergent_root.as_ref() == Some(oracle_root) {
        return ParityAttemptVerdict::RealDivergence;
    }
    *previous_divergent_root = Some(oracle_root.clone());
    ParityAttemptVerdict::InputsDrifted
}

fn run_parity_gate(
    oracle: &dyn NixEval,
    candidate: &dyn NixEval,
    candidate_name: &str,
    spec: &BenchmarkSpec,
) -> Result<BenchmarkParity> {
    if skip_parity_gate_for_diagnostics() {
        return Ok(BenchmarkParity::skipped(candidate_name));
    }
    let mut previous_divergent_root = None;
    for _ in 0..PARITY_GATE_MAX_ATTEMPTS {
        let report = diff_closure(oracle, candidate, &spec.file, &spec.attr, DiffMode::Byte)
            .with_context(|| format!("checking .drv parity for {}", spec.name))?;
        if report.divergences.is_empty() {
            return Ok(BenchmarkParity::matched(candidate_name, &report));
        }
        match classify_divergent_attempt(&mut previous_divergent_root, &report.oracle_root) {
            ParityAttemptVerdict::RealDivergence => {
                return Err(NixBenchParityFailure::new(spec, candidate_name, &report).into());
            }
            ParityAttemptVerdict::InputsDrifted => trace_phase("parity-gate-drift-retry"),
        }
    }
    Err(anyhow::anyhow!(
        "nix benchmark parity gate for {} against {candidate_name} could not obtain a stable \
         comparison: the oracle .drv root changed on every attempt, so the evaluated sources \
         were being modified while the gate ran",
        spec.name
    ))
}

/// Runs one native instantiation for a timing/memory sample.
///
/// The normal path is [`NixEval::instantiate`], which includes `.drv` store
/// materialization exactly like the C++ oracle. Under the
/// `AOS_NIX_BENCH_SKIP_PARITY=1` diagnostics mode the sample instead uses the
/// in-memory [`NixEval::instantiate_closure`] when the candidate supports it:
/// a diagnostics run may be measuring an evaluator whose `.drv` bytes do not
/// yet match the store contents, and writing divergent `.drv`s is neither
/// possible (store permissions) nor desirable.
pub(super) fn native_instantiate(
    candidate: &dyn NixEval,
    spec: &BenchmarkSpec,
) -> Result<std::path::PathBuf> {
    if skip_parity_gate_for_diagnostics()
        && let Some(closure) = candidate.instantiate_closure(&spec.file, &spec.attr)?
    {
        return Ok(closure.into_parts().0);
    }
    candidate.instantiate(&spec.file, &spec.attr)
}

/// Returns whether `AOS_NIX_BENCH_SKIP_PARITY=1` disables the parity gate.
///
/// This is a memory/perf diagnostics escape hatch only: the recorded parity
/// mode becomes `"skipped"` with `matched == false`, so such a run can never
/// pass perf-win admissibility and is never selected as a comparison baseline
/// (baseline matching requires matched parity on both sides).
fn skip_parity_gate_for_diagnostics() -> bool {
    std::env::var("AOS_NIX_BENCH_SKIP_PARITY").is_ok_and(|value| value == "1")
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
        "memory_regression_count": outcomes.iter().filter(|outcome| {
            outcome.comparison.as_ref().is_some_and(|comparison| {
                comparison.memory.as_ref().is_some_and(|memory| memory.regression)
            })
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
    if let Some(memory_line) = render_memory_line(outcome) {
        printer.plain(&memory_line);
    }
}

/// Renders the optional per-benchmark memory line for the human report.
///
/// Returns `None` when the run captured no native memory probes and no
/// attributed oracle-child peak, so builds without probes render unchanged.
fn render_memory_line(outcome: &BenchmarkOutcome) -> Option<String> {
    let record = &outcome.record;
    let memory = record.native_summary.memory;
    let oracle_child_watermark = record.summary.child_peak_rss_bytes_max;
    let oracle_child_exact = record.summary.exact_child_peak_rss;
    if memory.is_none()
        && oracle_child_watermark.is_none()
        && oracle_child_exact == ExactOracleChildPeakRss::NotRecorded
    {
        return None;
    }
    let mut line = "    memory:".to_string();
    if let Some(memory) = memory {
        if let Some(peak) = memory.peak_rss_delta_bytes_max {
            line.push_str(&format!(" native_peak_rss_delta_max={}", mib(peak)));
        }
        if let Some(rss) = memory.rss_after_bytes_max {
            line.push_str(&format!(" native_rss_after_max={}", mib(rss)));
        }
        if let Some(arena_peak) = memory.arena_peak_live_mapped_bytes_max {
            line.push_str(&format!(" arena_peak={}", mib(arena_peak)));
        }
        if let Some(arena_after) = memory.arena_live_mapped_bytes_after_last {
            line.push_str(&format!(" arena_after={}", mib(arena_after)));
        }
    }
    match oracle_child_exact {
        ExactOracleChildPeakRss::NotRecorded => {}
        ExactOracleChildPeakRss::UnavailableSafePerChildWaitApi => {
            line.push_str(
                " oracle_exact_child_peak_rss=unavailable:safe-per-child-wait-api",
            );
        }
        ExactOracleChildPeakRss::Measured { bytes } => {
            line.push_str(&format!(" oracle_exact_child_peak_rss={}", mib(bytes)));
        }
    }
    if let Some(oracle_child) = oracle_child_watermark {
        line.push_str(&format!(
            " oracle_child_peak_rss_watermark={}",
            mib(oracle_child)
        ));
    }
    if let Some(movement) = outcome
        .comparison
        .as_ref()
        .and_then(|comparison| comparison.memory.as_ref())
    {
        line.push_str(&format!(
            " mem_delta={:+.2}% threshold={:.2}%",
            movement.delta_percent * 100.0,
            movement.threshold_percent * 100.0
        ));
        if movement.regression {
            line.push_str(" MEM-REGRESSION");
        }
        if movement.improvement {
            line.push_str(" MEM-IMPROVEMENT");
        }
    }
    Some(line)
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
