//! `aos nix-measure` -- run the RFC 0007 opening measurement gate.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use aos_core::error::AosError;
use aos_core::nix::{NixCli, NixEvalConfig, NixRunner};
use aos_core::output::{OutputMode, Printer};

use super::nix_bench::corpus::{BenchmarkSpec, benchmark_specs};

const MEASURE_HISTORY_VERSION: u32 = 1;
const DEFAULT_MIN_EVAL_FRACTION: f64 = 0.50;

/// Error returned after `aos nix-measure` renders a stop decision.
#[derive(Debug, Clone)]
pub struct NixMeasureStopFailure {
    message: String,
}

impl NixMeasureStopFailure {
    fn new(fraction: f64, threshold: f64) -> Self {
        Self {
            message: format!(
                "nix measurement gate stopped: mean eval/build fraction {fraction:.3} is below threshold {threshold:.3}"
            ),
        }
    }
}

impl std::fmt::Display for NixMeasureStopFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NixMeasureStopFailure {}

/// Runs the opening measurement gate.
///
/// # Errors
///
/// Returns an error if arguments are invalid, Nix cannot evaluate or build a
/// selected workload, the measurement history cannot be written, or
/// `fail_on_stop` is set and the aggregate gate decision is `stop`.
pub fn run(
    printer: &Printer,
    verbose: u8,
    eval_config: NixEvalConfig,
    file: Option<&Path>,
    attrs: &[String],
    history: Option<&Path>,
    no_record: bool,
    min_eval_fraction: f64,
    fail_on_stop: bool,
) -> Result<()> {
    validate_args(min_eval_fraction)?;
    NixRunner::ensure_nix_instantiate_available()?;
    NixRunner::ensure_nix_build_available()?;

    let root = NixRunner::find_root()?;
    let file = file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("default.nix"));
    let file = absolute_eval_file(&file)?;
    let history = history
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".aos-benchmarks").join("nix-measure.jsonl"));
    let oracle = NixCli::with_eval_config(verbose, eval_config);
    let specs = measurement_specs(&oracle, &root, &file, attrs)?;

    printer.info(&format!(
        "Running opening measurement gate for {} workload(s)...",
        specs.len()
    ));

    let mut measurements = Vec::with_capacity(specs.len());
    for spec in specs {
        measurements.push(measure_one(&oracle, &spec, min_eval_fraction)?);
    }
    let summary = summarize_measurements(&measurements, min_eval_fraction);
    let run = MeasurementRunRecord {
        version: MEASURE_HISTORY_VERSION,
        timestamp_unix_ms: unix_timestamp_millis()?,
        file: file.to_string_lossy().into_owned(),
        summary,
        measurements,
    };

    if !no_record {
        append_history(&history, &run)?;
    }

    let failure = (!run.summary.proceed)
        .then(|| NixMeasureStopFailure::new(run.summary.mean_eval_fraction, min_eval_fraction));
    let blocked = fail_on_stop && failure.is_some();

    if printer.json_if_active(&run_json(
        &run,
        &history,
        !no_record,
        blocked,
        failure.as_ref(),
    )) {
        if blocked {
            if let Some(failure) = failure {
                return Err(failure.into());
            }
        }
        return Ok(());
    }

    render_human_report(printer, &run, &history, !no_record, failure.as_ref());
    if blocked {
        if let Some(failure) = failure {
            return Err(failure.into());
        }
    }
    Ok(())
}

/// Returns the default minimum eval/build fraction for the gate.
pub const fn default_min_eval_fraction() -> f64 {
    DEFAULT_MIN_EVAL_FRACTION
}

fn validate_args(min_eval_fraction: f64) -> Result<()> {
    if !min_eval_fraction.is_finite() || !(0.0..=1.0).contains(&min_eval_fraction) {
        return Err(AosError::InvalidArgument {
            message: "nix-measure --min-eval-fraction must be a finite value between 0 and 1"
                .to_string(),
        }
        .into());
    }
    Ok(())
}

fn absolute_eval_file(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolving current directory for nix-measure file")?
        .join(path))
}

fn measurement_specs(
    oracle: &NixCli,
    root: &Path,
    file: &Path,
    attrs: &[String],
) -> Result<Vec<BenchmarkSpec>> {
    let specs = benchmark_specs(oracle, root, file, attrs)?
        .into_iter()
        .filter(is_buildable_measurement_spec)
        .collect::<Vec<_>>();
    if specs.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-measure found no buildable measurement workloads".to_string(),
        }
        .into());
    }
    Ok(specs)
}

fn is_buildable_measurement_spec(spec: &BenchmarkSpec) -> bool {
    // `benchmark_specs` now yields one temperature-neutral spec per attr, so
    // there is no cold/warm pair to dedup; only the non-buildable diagnostic
    // corpus is excluded.
    spec.category != "diagnostic"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasurementRunRecord {
    version: u32,
    timestamp_unix_ms: u64,
    file: String,
    summary: MeasurementSummary,
    measurements: Vec<MeasurementRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasurementSummary {
    workloads: usize,
    min_eval_fraction: f64,
    mean_eval_fraction: f64,
    proceed: bool,
    action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasurementRecord {
    name: String,
    file: String,
    attr: String,
    category: String,
    cold_eval: EvalMeasurement,
    warm_eval: EvalMeasurement,
    build: BuildMeasurement,
    eval_fraction_of_build: f64,
    warm_delta_seconds: f64,
    warm_delta_percent: f64,
    decision: MeasurementDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvalMeasurement {
    elapsed_seconds: f64,
    elapsed_nanos: u64,
    drv_path: String,
    stats: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildMeasurement {
    elapsed_seconds: f64,
    elapsed_nanos: u64,
    output_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasurementDecision {
    min_eval_fraction: f64,
    eval_dominant: bool,
    action: String,
}

fn measure_one(
    oracle: &NixCli,
    spec: &BenchmarkSpec,
    min_eval_fraction: f64,
) -> Result<MeasurementRecord> {
    let cold_eval = measure_eval(oracle, spec, "cold")?;
    let warm_eval = measure_eval(oracle, spec, "warm")?;
    let build = measure_build(oracle, spec)?;
    let eval_fraction_of_build = eval_fraction(cold_eval.elapsed_seconds, build.elapsed_seconds);
    let warm_delta_seconds = warm_eval.elapsed_seconds - cold_eval.elapsed_seconds;
    let warm_delta_percent = if cold_eval.elapsed_seconds > 0.0 {
        warm_delta_seconds / cold_eval.elapsed_seconds
    } else {
        0.0
    };
    let eval_dominant = eval_fraction_of_build >= min_eval_fraction;
    Ok(MeasurementRecord {
        name: spec.name.clone(),
        file: spec.file.to_string_lossy().into_owned(),
        attr: spec.attr.clone(),
        category: spec.category.clone(),
        cold_eval,
        warm_eval,
        build,
        eval_fraction_of_build,
        warm_delta_seconds,
        warm_delta_percent,
        decision: MeasurementDecision {
            min_eval_fraction,
            eval_dominant,
            action: gate_action(eval_dominant).to_string(),
        },
    })
}

fn measure_eval(oracle: &NixCli, spec: &BenchmarkSpec, label: &str) -> Result<EvalMeasurement> {
    let stats = oracle
        .instantiate_with_stats(&spec.file, &spec.attr)
        .with_context(|| format!("capturing {label} NIX_SHOW_STATS for {}", spec.name))?;
    Ok(EvalMeasurement {
        elapsed_seconds: stats.elapsed.as_secs_f64(),
        elapsed_nanos: duration_nanos(stats.elapsed),
        drv_path: stats.drv_path.to_string_lossy().into_owned(),
        stats: stats.stats,
    })
}

fn measure_build(oracle: &NixCli, spec: &BenchmarkSpec) -> Result<BuildMeasurement> {
    let started = Instant::now();
    let output = oracle
        .build(&spec.file, &spec.attr)
        .with_context(|| format!("timing nix-build for {}", spec.name))?;
    let elapsed = started.elapsed();
    Ok(BuildMeasurement {
        elapsed_seconds: elapsed.as_secs_f64(),
        elapsed_nanos: duration_nanos(elapsed),
        output_path: output.to_string_lossy().into_owned(),
    })
}

fn summarize_measurements(
    measurements: &[MeasurementRecord],
    min_eval_fraction: f64,
) -> MeasurementSummary {
    let mean_eval_fraction = if measurements.is_empty() {
        0.0
    } else {
        measurements
            .iter()
            .map(|measurement| measurement.eval_fraction_of_build)
            .sum::<f64>()
            / measurements.len() as f64
    };
    let proceed = mean_eval_fraction >= min_eval_fraction;
    MeasurementSummary {
        workloads: measurements.len(),
        min_eval_fraction,
        mean_eval_fraction,
        proceed,
        action: gate_action(proceed).to_string(),
    }
}

fn eval_fraction(eval_seconds: f64, build_seconds: f64) -> f64 {
    if build_seconds > 0.0 {
        (eval_seconds / build_seconds).min(1.0)
    } else {
        0.0
    }
}

fn gate_action(proceed: bool) -> &'static str {
    if proceed { "proceed" } else { "stop" }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn unix_timestamp_millis() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?;
    Ok(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

fn append_history(path: &Path, record: &MeasurementRunRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening measurement history {}", path.display()))?;
    serde_json::to_writer(&mut file, record)
        .with_context(|| format!("writing measurement history {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("writing measurement history {}", path.display()))?;
    Ok(())
}

fn run_json(
    run: &MeasurementRunRecord,
    history: &Path,
    recorded: bool,
    blocked: bool,
    failure: Option<&NixMeasureStopFailure>,
) -> serde_json::Value {
    serde_json::json!({
        "version": run.version,
        "timestamp_unix_ms": run.timestamp_unix_ms,
        "file": run.file,
        "history": history.to_string_lossy(),
        "recorded": recorded,
        "blocked": blocked,
        "error": failure.map(ToString::to_string),
        "summary": &run.summary,
        "measurements": &run.measurements,
    })
}

fn render_human_report(
    printer: &Printer,
    run: &MeasurementRunRecord,
    history: &Path,
    recorded: bool,
    failure: Option<&NixMeasureStopFailure>,
) {
    if let Some(failure) = failure {
        if printer.mode() == OutputMode::Quiet {
            printer.error(&failure.to_string());
            return;
        }
        printer.warning(&failure.to_string());
    } else {
        printer.success(&format!("nix measurement gate: {}", run.summary.action));
    }

    if printer.mode() == OutputMode::Quiet {
        return;
    }

    for measurement in &run.measurements {
        printer.plain(&format!(
            "  - {} eval/build={:.2}% cold={:.6}s warm={:.6}s build={:.6}s action={}",
            measurement.name,
            measurement.eval_fraction_of_build * 100.0,
            measurement.cold_eval.elapsed_seconds,
            measurement.warm_eval.elapsed_seconds,
            measurement.build.elapsed_seconds,
            measurement.decision.action
        ));
    }
    printer.plain(&format!(
        "  mean_eval_fraction={:.2}% threshold={:.2}% action={}",
        run.summary.mean_eval_fraction * 100.0,
        run.summary.min_eval_fraction * 100.0,
        run.summary.action
    ));
    if recorded {
        printer.plain(&format!("  history: {}", history.display()));
    } else {
        printer.plain("  history: not recorded (--no-record)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(eval_fraction: f64) -> MeasurementRecord {
        MeasurementRecord {
            name: "explicit:cold:pkgs.zlib".to_string(),
            file: "/repo/default.nix".to_string(),
            attr: "pkgs.zlib".to_string(),
            category: "explicit".to_string(),
            cold_eval: EvalMeasurement {
                elapsed_seconds: eval_fraction,
                elapsed_nanos: 1,
                drv_path: "/nix/store/example.drv".to_string(),
                stats: serde_json::json!({}),
            },
            warm_eval: EvalMeasurement {
                elapsed_seconds: eval_fraction,
                elapsed_nanos: 1,
                drv_path: "/nix/store/example.drv".to_string(),
                stats: serde_json::json!({}),
            },
            build: BuildMeasurement {
                elapsed_seconds: 1.0,
                elapsed_nanos: 1,
                output_path: "/nix/store/example".to_string(),
            },
            eval_fraction_of_build: eval_fraction,
            warm_delta_seconds: 0.0,
            warm_delta_percent: 0.0,
            decision: MeasurementDecision {
                min_eval_fraction: 0.5,
                eval_dominant: eval_fraction >= 0.5,
                action: gate_action(eval_fraction >= 0.5).to_string(),
            },
        }
    }

    #[test]
    fn eval_fraction_caps_at_one() {
        assert_eq!(eval_fraction(2.0, 1.0), 1.0);
        assert_eq!(eval_fraction(1.0, 0.0), 0.0);
    }

    #[test]
    fn summary_stops_below_threshold() {
        let summary = summarize_measurements(&[record(0.2), record(0.4)], 0.5);

        assert!(!summary.proceed);
        assert_eq!(summary.action, "stop");
    }

    #[test]
    fn summary_proceeds_at_threshold() {
        let summary = summarize_measurements(&[record(0.6), record(0.4)], 0.5);

        assert!(summary.proceed);
        assert_eq!(summary.action, "proceed");
    }

    #[test]
    fn validate_args_rejects_invalid_threshold() {
        let error = validate_args(1.2).expect_err("threshold above one is invalid");

        assert!(error.to_string().contains("--min-eval-fraction"));
    }

    #[test]
    fn diagnostic_specs_are_not_build_measurement_workloads() {
        let spec = BenchmarkSpec {
            name: "diagnostic:diagnostic.attrset_access".to_string(),
            file: PathBuf::from("/repo/.aos-benchmarks/corpus/diagnostics.nix"),
            attr: "diagnostic.attrset_access".to_string(),
            category: "diagnostic".to_string(),
        };

        assert!(!is_buildable_measurement_spec(&spec));
    }

    #[test]
    fn leaf_specs_are_build_measurement_workloads() {
        let spec = BenchmarkSpec {
            name: "leaf:pkgs.zlib".to_string(),
            file: PathBuf::from("/repo/default.nix"),
            attr: "pkgs.zlib".to_string(),
            category: "leaf".to_string(),
        };

        assert!(is_buildable_measurement_spec(&spec));
    }
}
