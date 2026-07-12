//! Regression and perf-win analysis over benchmark history.
//!
//! The native evaluator is the subject under test, so all gating — the
//! `--fail-on-regression` and `--require-perf-win` paths — is driven by the
//! **native** timings. The C++ Nix oracle timings are still compared and
//! reported, clearly labelled, so a reviewer can see whether a native movement
//! tracked a machine-wide effect or was specific to the native evaluator.
//!
//! A [`BenchmarkComparison`] therefore carries the native [`Movement`] at its
//! top level (the fields that decide `regression` / `improvement`) plus the
//! oracle [`Movement`] under [`BenchmarkComparison::oracle`] and the headline
//! `native / oracle` mean ratio under
//! [`BenchmarkComparison::native_over_oracle`].

use std::collections::BTreeMap;

use serde::Serialize;

use super::record::{
    BenchmarkRecord, BenchmarkRunRecord, BenchmarkSummary, NativeBenchmarkSummary,
    NativeMemorySummary, STATS_DELTA_KEYS,
};

/// Z-score threshold above which a mean movement is treated as significant.
pub(crate) const SIGNIFICANCE_Z: f64 = 2.0;

/// A benchmark's freshly captured record paired with its baseline comparison.
#[derive(Debug, Clone)]
pub(crate) struct BenchmarkOutcome {
    pub(crate) record: BenchmarkRecord,
    pub(crate) comparison: Option<BenchmarkComparison>,
}

/// A directional mean movement between a baseline and the current run.
///
/// Used for both the native (headline) movement and the oracle movement. A
/// movement over a side with no samples reports zeroed deltas and is never
/// flagged significant, so a missing native baseline cannot trip a regression.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Movement {
    pub(crate) previous_mean_seconds: f64,
    pub(crate) current_mean_seconds: f64,
    pub(crate) delta_seconds: f64,
    pub(crate) delta_percent: f64,
    pub(crate) z_score: Option<f64>,
    pub(crate) significant: bool,
    pub(crate) regression: bool,
    pub(crate) improvement: bool,
}

/// A per-benchmark comparison against the most recent differing-commit baseline.
///
/// The top-level movement fields mirror the native [`Movement`] and are what
/// gating consults. [`Self::oracle`] holds the C++ Nix movement for context and
/// [`Self::stats_delta`] the mean `NIX_SHOW_STATS` counter deltas.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchmarkComparison {
    pub(crate) previous_commit: String,
    pub(crate) previous_mean_seconds: f64,
    pub(crate) current_mean_seconds: f64,
    pub(crate) delta_seconds: f64,
    pub(crate) delta_percent: f64,
    pub(crate) threshold_percent: f64,
    pub(crate) z_score: Option<f64>,
    pub(crate) significant: bool,
    pub(crate) regression: bool,
    pub(crate) improvement: bool,
    /// Current-run mean ratio `native / oracle`; the project's headline metric.
    ///
    /// `None` when the oracle mean is not positive.
    pub(crate) native_over_oracle: Option<f64>,
    /// The C++ Nix oracle movement, reported for context only.
    pub(crate) oracle: Movement,
    pub(crate) stats_delta: BTreeMap<String, StatsDelta>,
    /// The native peak-memory movement, when both runs captured memory probes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) memory: Option<MemoryMovement>,
}

/// A native peak-memory movement between a baseline and the current run.
///
/// Compares the maximum per-sample `getrusage` peak-RSS watermark movement
/// ([`NativeMemorySummary::peak_rss_delta_bytes_max`]). The watermark is a
/// single deterministic high-water measurement per run, so significance uses a
/// plain relative threshold rather than a z-score.
#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct MemoryMovement {
    pub(crate) previous_peak_rss_delta_bytes: u64,
    pub(crate) current_peak_rss_delta_bytes: u64,
    pub(crate) delta_bytes: i64,
    pub(crate) delta_percent: f64,
    pub(crate) threshold_percent: f64,
    pub(crate) regression: bool,
    pub(crate) improvement: bool,
}

/// Compares native peak-memory summaries between baseline and current runs.
///
/// Returns `None` unless both sides captured a positive peak-RSS movement, so
/// legacy records and no-probe builds can never trip a memory regression.
fn memory_movement(
    current: &NativeBenchmarkSummary,
    previous: &NativeBenchmarkSummary,
    threshold: f64,
) -> Option<MemoryMovement> {
    let current_peak = peak_rss_delta(current.memory)?;
    let previous_peak = peak_rss_delta(previous.memory)?;
    let delta_bytes = i64::try_from(current_peak).unwrap_or(i64::MAX)
        - i64::try_from(previous_peak).unwrap_or(i64::MAX);
    let delta_percent = delta_bytes as f64 / previous_peak as f64;
    Some(MemoryMovement {
        previous_peak_rss_delta_bytes: previous_peak,
        current_peak_rss_delta_bytes: current_peak,
        delta_bytes,
        delta_percent,
        threshold_percent: threshold,
        regression: delta_percent > threshold,
        improvement: delta_percent < -threshold,
    })
}

/// Extracts a comparable (positive) peak-RSS movement from a memory summary.
fn peak_rss_delta(memory: Option<NativeMemorySummary>) -> Option<u64> {
    memory
        .and_then(|memory| memory.peak_rss_delta_bytes_max)
        .filter(|&peak| peak > 0)
}

/// A single `NIX_SHOW_STATS` counter's movement between baseline and current run.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StatsDelta {
    pub(crate) previous: f64,
    pub(crate) current: f64,
    pub(crate) delta: f64,
    pub(crate) delta_percent: Option<f64>,
}

/// The perf-win admissibility verdict aggregated over a run's outcomes.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchmarkAdmissibility {
    pub(crate) required: bool,
    pub(crate) admitted: bool,
    pub(crate) parity_green: bool,
    pub(crate) regression_free: bool,
    pub(crate) real_workload_improvement: bool,
    pub(crate) counter_breakdown: bool,
    pub(crate) compared_real_workloads: usize,
    pub(crate) improving_real_workloads: usize,
    pub(crate) failure_reasons: Vec<String>,
}

impl BenchmarkAdmissibility {
    /// Evaluates whether a run is admissible as a native perf win.
    ///
    /// Admission requires byte parity on every benchmark, zero native
    /// regressions, at least one non-diagnostic native improvement past the
    /// threshold, and a `NIX_SHOW_STATS` counter breakdown proving the work the
    /// improvement removed.
    pub(crate) fn evaluate(
        outcomes: &[BenchmarkOutcome],
        required: bool,
        regression_count: usize,
    ) -> Self {
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
                "{regression_count} native benchmark regression{plural} found"
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

/// A baseline benchmark record and the commit it was recorded at.
#[derive(Clone, Copy)]
pub(crate) struct PreviousBenchmark<'a> {
    pub(crate) commit: &'a str,
    pub(crate) record: &'a BenchmarkRecord,
}

/// Compares a fresh benchmark record against its baseline.
///
/// The returned comparison is gated on the native movement; the oracle movement
/// and `NIX_SHOW_STATS` deltas are computed for context.
pub(crate) fn compare_benchmarks(
    current: &BenchmarkRecord,
    previous: PreviousBenchmark<'_>,
    threshold: f64,
    memory_threshold: f64,
) -> BenchmarkComparison {
    let native = native_movement(
        &current.native_summary,
        &previous.record.native_summary,
        threshold,
    );
    let oracle = oracle_movement(&current.summary, &previous.record.summary, threshold);
    let native_over_oracle = ratio(native.current_mean_seconds, oracle.current_mean_seconds);

    BenchmarkComparison {
        previous_commit: previous.commit.to_string(),
        previous_mean_seconds: native.previous_mean_seconds,
        current_mean_seconds: native.current_mean_seconds,
        delta_seconds: native.delta_seconds,
        delta_percent: native.delta_percent,
        threshold_percent: threshold,
        z_score: native.z_score,
        significant: native.significant,
        regression: native.regression,
        improvement: native.improvement,
        native_over_oracle,
        oracle,
        stats_delta: stats_delta(&current.summary, &previous.record.summary),
        memory: memory_movement(
            &current.native_summary,
            &previous.record.native_summary,
            memory_threshold,
        ),
    }
}

fn native_movement(
    current: &NativeBenchmarkSummary,
    previous: &NativeBenchmarkSummary,
    threshold: f64,
) -> Movement {
    movement(
        previous.mean_seconds,
        previous.stddev_seconds,
        previous.samples,
        current.mean_seconds,
        current.stddev_seconds,
        current.samples,
        threshold,
    )
}

fn oracle_movement(
    current: &BenchmarkSummary,
    previous: &BenchmarkSummary,
    threshold: f64,
) -> Movement {
    movement(
        previous.mean_seconds,
        previous.stddev_seconds,
        previous.samples,
        current.mean_seconds,
        current.stddev_seconds,
        current.samples,
        threshold,
    )
}

/// Builds a [`Movement`] from paired baseline and current summary statistics.
///
/// A side with no samples yields a non-significant movement (zeroed deltas), so
/// a benchmark that lacks a native baseline is never flagged as a regression.
#[allow(clippy::too_many_arguments)]
fn movement(
    previous_mean: f64,
    previous_stddev: f64,
    previous_samples: usize,
    current_mean: f64,
    current_stddev: f64,
    current_samples: usize,
    threshold: f64,
) -> Movement {
    if current_samples == 0 || previous_samples == 0 {
        return Movement {
            previous_mean_seconds: previous_mean,
            current_mean_seconds: current_mean,
            delta_seconds: 0.0,
            delta_percent: 0.0,
            z_score: None,
            significant: false,
            regression: false,
            improvement: false,
        };
    }

    let delta_seconds = current_mean - previous_mean;
    let delta_percent = if previous_mean > 0.0 {
        delta_seconds / previous_mean
    } else {
        0.0
    };
    let (significant, z_score) = significance(
        delta_seconds,
        current_stddev,
        current_samples,
        previous_stddev,
        previous_samples,
    );
    let regression = delta_percent > threshold && significant;
    let improvement = delta_percent < -threshold && significant;

    Movement {
        previous_mean_seconds: previous_mean,
        current_mean_seconds: current_mean,
        delta_seconds,
        delta_percent,
        z_score,
        significant,
        regression,
        improvement,
    }
}

/// Returns whether a mean movement is statistically significant, with its z-score.
///
/// A zero delta is never significant. With fewer than two samples on either
/// side, or a zero pooled standard error, the movement is treated as
/// significant without a defined z-score.
fn significance(
    delta_seconds: f64,
    current_stddev: f64,
    current_samples: usize,
    previous_stddev: f64,
    previous_samples: usize,
) -> (bool, Option<f64>) {
    if delta_seconds == 0.0 {
        return (false, None);
    }
    if current_samples < 2 || previous_samples < 2 {
        return (true, None);
    }

    let current_variance = current_stddev * current_stddev;
    let previous_variance = previous_stddev * previous_stddev;
    let standard_error = (current_variance / current_samples as f64
        + previous_variance / previous_samples as f64)
        .sqrt();
    if standard_error == 0.0 {
        return (true, None);
    }

    let z_score = delta_seconds.abs() / standard_error;
    (z_score >= SIGNIFICANCE_Z, Some(z_score))
}

fn ratio(numerator: f64, denominator: f64) -> Option<f64> {
    (denominator > 0.0).then_some(numerator / denominator)
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

/// Finds the most recent baseline for `current` from a differing commit.
///
/// The baseline must share the benchmark name, temperature, temperature
/// semantics, evaluator context, and matched parity mode/candidate so
/// comparisons stay like-for-like. The `temperature_semantics` match is what
/// stops a pre-v4 fake-cold baseline from being compared against a v4 true-cold
/// record. Records from `current_commit` are skipped so a re-run does not
/// compare against itself.
pub(crate) fn previous_benchmark<'a>(
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
                    && record.temperature == current.temperature
                    && record.temperature_semantics == current.temperature_semantics
                    && record.context == current.context
                    && parity_context_matches(&record.parity, &current.parity)
            })
            .map(|record| PreviousBenchmark {
                commit: run.commit.as_str(),
                record,
            })
    })
}

fn parity_context_matches(
    previous: &super::record::BenchmarkParity,
    current: &super::record::BenchmarkParity,
) -> bool {
    previous.matched
        && current.matched
        && previous.mode == current.mode
        && previous.candidate == current.candidate
}
