//! Benchmark history schema: the on-disk JSONL record shapes for `aos nix-bench`.
//!
//! Each `aos nix-bench` run appends one JSON object per line to the history
//! file (default `.aos-benchmarks/nix-eval.jsonl`). A run bundles every
//! benchmark evaluated at one commit; each benchmark carries both the C++ Nix
//! **oracle** timings (with `NIX_SHOW_STATS` counters) and the native
//! evaluator timings that are the project's headline metric.
//!
//! ```text
//! {
//!   "version": 2,
//!   "commit": "<40-hex>",
//!   "timestamp_unix_ms": 1720000000000,
//!   "file": "/repo/default.nix",
//!   "benchmarks": [
//!     {
//!       "name": "leaf:cold:pkgs.zlib",
//!       "file": "/repo/default.nix",
//!       "attr": "pkgs.zlib",
//!       "category": "leaf",
//!       "temperature": "cold",
//!       "context": { ... },
//!       "parity": { "mode": "byte", "candidate": "aos-nix", "matched": true, ... },
//!       "samples":        [ { "elapsed_seconds": .., "drv_path": "..", "stats": {..} } ],
//!       "summary":        { "mean_seconds": .., "stats_mean": {..} },
//!       "native_samples": [ { "elapsed_seconds": .., "drv_path": ".." } ],
//!       "native_summary": { "mean_seconds": .., "min_seconds": .. }
//!     }
//!   ]
//! }
//! ```
//!
//! The `native_samples` / `native_summary` fields were added in schema
//! [`BENCH_HISTORY_VERSION`] `2`. Records written by version `1` omit them, so
//! both deserialize with serde defaults (an empty native sample set, a
//! zero-count [`NativeBenchmarkSummary`]) and are treated as lacking a native
//! baseline rather than as a regression.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use aos_core::nix::{NixEvalConfig, NixEvalMode};
use aos_nix_harness::diff::DrvDiffReport;

/// On-disk benchmark history schema version.
///
/// Version `2` added the native evaluator timings (`native_samples` and
/// `native_summary`); version `1` records omit them and deserialize with serde
/// defaults.
pub(crate) const BENCH_HISTORY_VERSION: u32 = 2;

/// C++ Nix `NIX_SHOW_STATS` counters tracked for the per-benchmark delta report.
pub(crate) const STATS_DELTA_KEYS: &[&str] = &[
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

/// One benchmark recorded at a commit: its identity, parity proof, and timings.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchmarkRecord {
    pub(crate) name: String,
    pub(crate) file: String,
    pub(crate) attr: String,
    pub(crate) category: String,
    pub(crate) temperature: String,
    pub(crate) context: BenchmarkContext,
    pub(crate) parity: BenchmarkParity,
    /// C++ Nix oracle samples, one per configured sample.
    pub(crate) samples: Vec<BenchmarkSample>,
    /// Aggregate of the oracle samples, including mean `NIX_SHOW_STATS` counters.
    pub(crate) summary: BenchmarkSummary,
    /// Native evaluator samples, one per configured sample.
    pub(crate) native_samples: Vec<NativeBenchmarkSample>,
    /// Aggregate of the native samples; the headline timing of the benchmark.
    pub(crate) native_summary: NativeBenchmarkSummary,
}

/// The full run record appended as a single JSONL line.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchmarkRunRecord {
    pub(crate) version: u32,
    pub(crate) commit: String,
    pub(crate) timestamp_unix_ms: u64,
    pub(crate) file: String,
    pub(crate) benchmarks: Vec<BenchmarkRecord>,
}

/// A single C++ Nix oracle evaluation timing plus its `NIX_SHOW_STATS` counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BenchmarkSample {
    pub(crate) elapsed_seconds: f64,
    pub(crate) elapsed_nanos: u64,
    pub(crate) drv_path: String,
    pub(crate) stats: serde_json::Value,
}

/// A single native evaluator instantiation timing.
///
/// The native evaluator does not emit `NIX_SHOW_STATS`, so a native sample
/// records only wall-clock time and the resulting `.drv` path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NativeBenchmarkSample {
    pub(crate) elapsed_seconds: f64,
    pub(crate) elapsed_nanos: u64,
    pub(crate) drv_path: String,
}

/// Aggregate statistics over a benchmark's C++ Nix oracle samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BenchmarkSummary {
    pub(crate) samples: usize,
    pub(crate) mean_seconds: f64,
    pub(crate) stddev_seconds: f64,
    pub(crate) min_seconds: f64,
    pub(crate) max_seconds: f64,
    pub(crate) stats_mean: BTreeMap<String, f64>,
}

/// Aggregate wall-clock statistics over a benchmark's native evaluator samples.
///
/// A [`Default`] value (all zeroes, `samples == 0`) marks a record that carries
/// no native timings, i.e. one written by schema version `1`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct NativeBenchmarkSummary {
    pub(crate) samples: usize,
    pub(crate) mean_seconds: f64,
    pub(crate) stddev_seconds: f64,
    pub(crate) min_seconds: f64,
    pub(crate) max_seconds: f64,
}

/// The `.drv` parity proof recorded alongside a benchmark's timings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BenchmarkParity {
    pub(crate) mode: String,
    pub(crate) candidate: String,
    pub(crate) matched: bool,
    pub(crate) oracle_root: Option<String>,
    pub(crate) candidate_root: Option<String>,
    pub(crate) divergence_count: usize,
    pub(crate) root_divergence_count: usize,
    pub(crate) contaminated_divergence_count: usize,
}

impl BenchmarkParity {
    /// Builds a matched parity record from a byte-diff report.
    pub(crate) fn matched(candidate_name: &str, report: &DrvDiffReport) -> Self {
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

    /// Builds the placeholder parity record used for legacy history entries.
    pub(crate) fn legacy_missing() -> Self {
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

/// The evaluator configuration fingerprint recorded to keep comparisons like-for-like.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BenchmarkContext {
    pub(crate) file: String,
    pub(crate) eval_mode: String,
    pub(crate) current_system: Option<String>,
    pub(crate) trace_verbose: bool,
    pub(crate) allowed_paths: Vec<String>,
    pub(crate) allowed_uris: Vec<String>,
    pub(crate) nix_path: Option<String>,
    pub(crate) store_dir: Option<String>,
    pub(crate) state_dir: Option<String>,
    pub(crate) log_dir: Option<String>,
    pub(crate) working_dir: Option<String>,
    pub(crate) home_dir: Option<String>,
    pub(crate) eval_env_sha256: String,
    pub(crate) eval_env_count: usize,
}

impl BenchmarkContext {
    /// Captures the evaluator configuration as a comparison fingerprint.
    pub(crate) fn from_eval_config(file: &Path, eval_config: &NixEvalConfig) -> Self {
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

/// Hashes evaluator environment bindings into a stable comparison fingerprint.
pub(crate) fn eval_env_fingerprint<'a>(vars: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> String {
    let mut hasher = Sha256::new();
    for (name, value) in vars {
        hasher.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(name);
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value);
    }
    hex_bytes(&hasher.finalize())
}

/// Summarizes the C++ Nix oracle samples of one benchmark.
pub(crate) fn summarize_samples(samples: &[BenchmarkSample]) -> BenchmarkSummary {
    let count = samples.len();
    let elapsed = samples.iter().map(|sample| sample.elapsed_seconds);
    let (mean_seconds, stddev_seconds, min_seconds, max_seconds) = aggregate(elapsed, count);

    BenchmarkSummary {
        samples: count,
        mean_seconds,
        stddev_seconds,
        min_seconds,
        max_seconds,
        stats_mean: mean_numeric_stats(samples),
    }
}

/// Summarizes the native evaluator samples of one benchmark.
///
/// Returns a [`Default`] summary (`samples == 0`) when no native samples were
/// captured, which downstream comparison treats as "no native baseline".
pub(crate) fn summarize_native_samples(
    samples: &[NativeBenchmarkSample],
) -> NativeBenchmarkSummary {
    let count = samples.len();
    if count == 0 {
        return NativeBenchmarkSummary::default();
    }
    let elapsed = samples.iter().map(|sample| sample.elapsed_seconds);
    let (mean_seconds, stddev_seconds, min_seconds, max_seconds) = aggregate(elapsed, count);

    NativeBenchmarkSummary {
        samples: count,
        mean_seconds,
        stddev_seconds,
        min_seconds,
        max_seconds,
    }
}

/// Returns `(mean, sample-stddev, min, max)` over `count` elapsed-second values.
///
/// The standard deviation uses Bessel's correction and is `0.0` for a single
/// sample. `min` and `max` are `0.0` when `count` is zero.
fn aggregate(elapsed: impl Iterator<Item = f64> + Clone, count: usize) -> (f64, f64, f64, f64) {
    if count == 0 {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let mean = elapsed.clone().sum::<f64>() / count as f64;
    let stddev = if count > 1 {
        let variance = elapsed
            .clone()
            .map(|value| {
                let delta = value - mean;
                delta * delta
            })
            .sum::<f64>()
            / (count - 1) as f64;
        variance.sqrt()
    } else {
        0.0
    };
    let min = elapsed.clone().fold(f64::INFINITY, f64::min);
    let max = elapsed.fold(f64::NEG_INFINITY, f64::max);
    (mean, stddev, min, max)
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

/// A history run record as parsed from disk, tolerant of legacy field shapes.
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

/// A benchmark record as parsed from disk, filling defaults for legacy fields.
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
    #[serde(default)]
    native_samples: Vec<NativeBenchmarkSample>,
    #[serde(default)]
    native_summary: NativeBenchmarkSummary,
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
            native_samples: self.native_samples,
            native_summary: self.native_summary,
        }
    }
}

/// Reads and parses a benchmark history JSONL file.
///
/// Returns an empty history when `path` does not exist. Legacy records that
/// predate the native timings or the per-run context are upgraded in place with
/// serde defaults.
///
/// # Errors
///
/// Returns an error if the file cannot be read or any non-empty line fails to
/// parse as a history run record.
pub(crate) fn read_history(path: &Path) -> Result<Vec<BenchmarkRunRecord>> {
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

/// Appends one run record as a JSONL line, creating parent directories.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created, the file cannot
/// be opened for appending, or the record cannot be serialized and written.
pub(crate) fn append_history(path: &Path, record: &BenchmarkRunRecord) -> Result<()> {
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
