//! Warm-cache benchmarks over controlled mutations to an imported Nix tree.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use aos_core::output::Printer;

const GROUPS: usize = 8;
const LEAVES_PER_GROUP: usize = 12;
const LEAF_WORK_ITEMS: usize = 2_048;
const PRIME_RUNS: usize = 2;
const REPORT_VERSION: u32 = 1;

const SCENARIOS: &[ChangedTreeScenario] = &[
    ChangedTreeScenario::new(
        "unchanged",
        "no source change (root-cache control)",
        Mutation::None,
        false,
    ),
    ChangedTreeScenario::new(
        "unused-file-comment",
        "comment in a file outside the import graph",
        Mutation::UnusedFileComment,
        false,
    ),
    ChangedTreeScenario::new(
        "forced-leaf-comment",
        "comment in one forced leaf",
        Mutation::ForcedLeafComment,
        false,
    ),
    ChangedTreeScenario::new(
        "root-comment",
        "comment in the root expression",
        Mutation::RootComment,
        false,
    ),
    ChangedTreeScenario::new(
        "import-edge",
        "one group imports an equivalent alternate leaf",
        Mutation::ImportEdge,
        false,
    ),
    ChangedTreeScenario::new(
        "one-leaf-value",
        "one forced leaf changes value",
        Mutation::OneLeafValue,
        true,
    ),
    ChangedTreeScenario::new(
        "scattered-leaf-values",
        "one forced leaf per group changes value",
        Mutation::ScatteredLeafValues,
        true,
    ),
    ChangedTreeScenario::new(
        "shared-comment",
        "comment in a dependency imported by every group",
        Mutation::SharedComment,
        false,
    ),
    ChangedTreeScenario::new(
        "shared-value",
        "value in a dependency imported by every group",
        Mutation::SharedValue,
        true,
    ),
];

#[derive(Clone, Copy)]
struct ChangedTreeScenario {
    name: &'static str,
    description: &'static str,
    mutation: Mutation,
    output_changes: bool,
}

impl ChangedTreeScenario {
    const fn new(
        name: &'static str,
        description: &'static str,
        mutation: Mutation,
        output_changes: bool,
    ) -> Self {
        Self {
            name,
            description,
            mutation,
            output_changes,
        }
    }
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    UnusedFileComment,
    ForcedLeafComment,
    RootComment,
    ImportEdge,
    OneLeafValue,
    ScatteredLeafValues,
    SharedComment,
    SharedValue,
}

#[derive(Debug, Serialize)]
struct ChangedTreeReport {
    version: u32,
    stock_cache_scope: &'static str,
    aos_cache_scope: &'static str,
    groups: usize,
    leaves_per_group: usize,
    leaf_work_items: usize,
    prime_runs: usize,
    samples: usize,
    scenarios: Vec<ScenarioReport>,
}

#[derive(Debug, Serialize)]
struct ScenarioReport {
    name: &'static str,
    description: &'static str,
    output_changed: bool,
    outputs_matched: bool,
    cpp_nix: TimingSummary,
    aos_nix: TimingSummary,
    aos_over_cpp: f64,
    aos_cache: CacheCounterSummary,
    cpp_samples: Vec<TimingSample>,
    aos_samples: Vec<AosTimingSample>,
    settled_cpp_nix: TimingSummary,
    settled_aos_nix: TimingSummary,
    settled_aos_over_cpp: f64,
    settled_aos_cache: CacheCounterSummary,
    settled_cpp_samples: Vec<TimingSample>,
    settled_aos_samples: Vec<AosTimingSample>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct TimingSample {
    elapsed_seconds: f64,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct AosTimingSample {
    elapsed_seconds: f64,
    cache: CacheCounters,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct TimingSummary {
    median_seconds: f64,
    mean_seconds: f64,
    min_seconds: f64,
    max_seconds: f64,
}

impl TimingSummary {
    fn from_samples(samples: &[f64]) -> Self {
        let mut ordered = samples.to_vec();
        ordered.sort_by(f64::total_cmp);
        let median_seconds = median_f64(&ordered);
        let sum = ordered.iter().sum::<f64>();
        let mean_seconds = if ordered.is_empty() {
            0.0
        } else {
            sum / ordered.len() as f64
        };
        Self {
            median_seconds,
            mean_seconds,
            min_seconds: ordered.first().copied().unwrap_or(0.0),
            max_seconds: ordered.last().copied().unwrap_or(0.0),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct CacheCounters {
    cache_hits: u64,
    cache_misses: u64,
    early_cutoffs: u64,
    root_cutoffs: u64,
    force_cache_hits: u64,
    force_cache_misses: u64,
    memoization_admits: u64,
    memoization_bypasses: u64,
    materialization_materializes: u64,
    materialization_keeps_in_memory: u64,
    thunks_forced: u64,
    thunks_allocated: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct CacheCounterSummary {
    median_cache_hits: u64,
    median_cache_misses: u64,
    median_early_cutoffs: u64,
    median_root_cutoffs: u64,
    median_force_cache_hits: u64,
    median_force_cache_misses: u64,
    median_memoization_admits: u64,
    median_memoization_bypasses: u64,
    median_materialization_materializes: u64,
    median_materialization_keeps_in_memory: u64,
    median_thunks_forced: u64,
    median_thunks_allocated: u64,
}

impl CacheCounterSummary {
    fn from_samples(samples: &[CacheCounters]) -> Self {
        Self {
            median_cache_hits: median_u64(samples.iter().map(|value| value.cache_hits)),
            median_cache_misses: median_u64(samples.iter().map(|value| value.cache_misses)),
            median_early_cutoffs: median_u64(samples.iter().map(|value| value.early_cutoffs)),
            median_root_cutoffs: median_u64(samples.iter().map(|value| value.root_cutoffs)),
            median_force_cache_hits: median_u64(samples.iter().map(|value| value.force_cache_hits)),
            median_force_cache_misses: median_u64(
                samples.iter().map(|value| value.force_cache_misses),
            ),
            median_memoization_admits: median_u64(
                samples.iter().map(|value| value.memoization_admits),
            ),
            median_memoization_bypasses: median_u64(
                samples.iter().map(|value| value.memoization_bypasses),
            ),
            median_materialization_materializes: median_u64(
                samples
                    .iter()
                    .map(|value| value.materialization_materializes),
            ),
            median_materialization_keeps_in_memory: median_u64(
                samples
                    .iter()
                    .map(|value| value.materialization_keeps_in_memory),
            ),
            median_thunks_forced: median_u64(samples.iter().map(|value| value.thunks_forced)),
            median_thunks_allocated: median_u64(samples.iter().map(|value| value.thunks_allocated)),
        }
    }
}

#[derive(Debug)]
struct MeasuredValue {
    value: serde_json::Value,
    elapsed_seconds: f64,
}

#[cfg(feature = "native-eval")]
#[derive(Debug)]
struct MeasuredAosValue {
    value: serde_json::Value,
    elapsed_seconds: f64,
    cache: CacheCounters,
}

/// Runs the controlled changed-tree warm-cache suite.
pub(super) fn run(printer: &Printer, verbose: u8, samples: usize) -> Result<()> {
    let report = run_native(verbose, samples)?;
    if printer.json_if_active(&serde_json::to_value(&report)?) {
        return Ok(());
    }
    render_human(printer, &report);
    Ok(())
}

#[cfg(feature = "native-eval")]
fn run_native(verbose: u8, samples: usize) -> Result<ChangedTreeReport> {
    let cpp_nix = cpp_nix_binary();
    let mut scenarios = Vec::with_capacity(SCENARIOS.len());
    for scenario in SCENARIOS {
        let mut cpp_samples = Vec::with_capacity(samples);
        let mut aos_samples = Vec::with_capacity(samples);
        let mut settled_cpp_samples = Vec::with_capacity(samples);
        let mut settled_aos_samples = Vec::with_capacity(samples);
        let mut output_changed = None;
        for sample_index in 0..samples {
            let scratch = ScratchTree::create()?;
            let fixture = NixTreeFixture::create(scratch.tree(), GROUPS, LEAVES_PER_GROUP)?;
            let expression = fixture.aos_expression()?;
            let baseline = prime_evaluators(
                &cpp_nix,
                &fixture,
                &expression,
                scratch.cpp_cache(),
                scratch.aos_cache(),
                scratch.home(),
                verbose,
            )?;
            fixture.apply(scenario.mutation)?;

            let (cpp, aos) = measure_pair(
                &cpp_nix,
                &fixture,
                &expression,
                &scratch,
                verbose,
                sample_index % 2 == 0,
            )?;
            let sample_output_changed = validate_pair(scenario, &baseline, &cpp, &aos, "first")?;
            let (settled_cpp, settled_aos) = measure_pair(
                &cpp_nix,
                &fixture,
                &expression,
                &scratch,
                verbose,
                sample_index % 2 != 0,
            )?;
            validate_pair(scenario, &baseline, &settled_cpp, &settled_aos, "settled")?;

            output_changed = Some(sample_output_changed);
            cpp_samples.push(TimingSample {
                elapsed_seconds: cpp.elapsed_seconds,
            });
            aos_samples.push(AosTimingSample {
                elapsed_seconds: aos.elapsed_seconds,
                cache: aos.cache,
            });
            settled_cpp_samples.push(TimingSample {
                elapsed_seconds: settled_cpp.elapsed_seconds,
            });
            settled_aos_samples.push(AosTimingSample {
                elapsed_seconds: settled_aos.elapsed_seconds,
                cache: settled_aos.cache,
            });
        }
        let cpp_times = cpp_samples
            .iter()
            .map(|sample| sample.elapsed_seconds)
            .collect::<Vec<_>>();
        let aos_times = aos_samples
            .iter()
            .map(|sample| sample.elapsed_seconds)
            .collect::<Vec<_>>();
        let cache_samples = aos_samples
            .iter()
            .map(|sample| sample.cache)
            .collect::<Vec<_>>();
        let settled_cpp_times = settled_cpp_samples
            .iter()
            .map(|sample| sample.elapsed_seconds)
            .collect::<Vec<_>>();
        let settled_aos_times = settled_aos_samples
            .iter()
            .map(|sample| sample.elapsed_seconds)
            .collect::<Vec<_>>();
        let settled_cache_samples = settled_aos_samples
            .iter()
            .map(|sample| sample.cache)
            .collect::<Vec<_>>();
        let cpp_summary = TimingSummary::from_samples(&cpp_times);
        let aos_summary = TimingSummary::from_samples(&aos_times);
        let aos_over_cpp = if cpp_summary.median_seconds == 0.0 {
            0.0
        } else {
            aos_summary.median_seconds / cpp_summary.median_seconds
        };
        let settled_cpp_summary = TimingSummary::from_samples(&settled_cpp_times);
        let settled_aos_summary = TimingSummary::from_samples(&settled_aos_times);
        let settled_aos_over_cpp = if settled_cpp_summary.median_seconds == 0.0 {
            0.0
        } else {
            settled_aos_summary.median_seconds / settled_cpp_summary.median_seconds
        };
        scenarios.push(ScenarioReport {
            name: scenario.name,
            description: scenario.description,
            output_changed: output_changed.unwrap_or(false),
            outputs_matched: true,
            cpp_nix: cpp_summary,
            aos_nix: aos_summary,
            aos_over_cpp,
            aos_cache: CacheCounterSummary::from_samples(&cache_samples),
            cpp_samples,
            aos_samples,
            settled_cpp_nix: settled_cpp_summary,
            settled_aos_nix: settled_aos_summary,
            settled_aos_over_cpp,
            settled_aos_cache: CacheCounterSummary::from_samples(&settled_cache_samples),
            settled_cpp_samples,
            settled_aos_samples,
        });
    }
    Ok(ChangedTreeReport {
        version: REPORT_VERSION,
        stock_cache_scope: "flake-output root; any source-tree fingerprint change invalidates it",
        aos_cache_scope: "persistent parse cache plus force-level expression memoization",
        groups: GROUPS,
        leaves_per_group: LEAVES_PER_GROUP,
        leaf_work_items: LEAF_WORK_ITEMS,
        prime_runs: PRIME_RUNS,
        samples,
        scenarios,
    })
}

#[cfg(feature = "native-eval")]
fn measure_pair(
    cpp_nix: &Path,
    fixture: &NixTreeFixture,
    expression: &str,
    scratch: &ScratchTree,
    verbose: u8,
    cpp_first: bool,
) -> Result<(MeasuredValue, MeasuredAosValue)> {
    if cpp_first {
        let cpp = measure_cpp(cpp_nix, fixture.root(), scratch.cpp_cache(), scratch.home())?;
        let aos = measure_aos(expression, scratch.aos_cache(), verbose)?;
        Ok((cpp, aos))
    } else {
        let aos = measure_aos(expression, scratch.aos_cache(), verbose)?;
        let cpp = measure_cpp(cpp_nix, fixture.root(), scratch.cpp_cache(), scratch.home())?;
        Ok((cpp, aos))
    }
}

#[cfg(feature = "native-eval")]
fn validate_pair(
    scenario: &ChangedTreeScenario,
    baseline: &serde_json::Value,
    cpp: &MeasuredValue,
    aos: &MeasuredAosValue,
    phase: &str,
) -> Result<bool> {
    if cpp.value != aos.value {
        anyhow::bail!(
            "changed-tree scenario {} {phase} run diverged: C++ Nix={} aos-nix={}",
            scenario.name,
            cpp.value,
            aos.value
        );
    }
    let output_changed = cpp.value != *baseline;
    if output_changed != scenario.output_changes {
        anyhow::bail!(
            "changed-tree scenario {} {phase} output-change contract failed: expected {}, got {}",
            scenario.name,
            scenario.output_changes,
            output_changed
        );
    }
    Ok(output_changed)
}

#[cfg(feature = "native-eval")]
#[allow(clippy::too_many_arguments)]
fn prime_evaluators(
    cpp_nix: &Path,
    fixture: &NixTreeFixture,
    expression: &str,
    cpp_cache: &Path,
    aos_cache: &Path,
    home: &Path,
    verbose: u8,
) -> Result<serde_json::Value> {
    let mut baseline = None;
    for _ in 0..PRIME_RUNS {
        let cpp = measure_cpp(cpp_nix, fixture.root(), cpp_cache, home)?;
        let aos = measure_aos(expression, aos_cache, verbose)?;
        if cpp.value != aos.value {
            anyhow::bail!(
                "changed-tree cache prime diverged: C++ Nix={} aos-nix={}",
                cpp.value,
                aos.value
            );
        }
        baseline = Some(cpp.value);
    }
    baseline.context("changed-tree benchmark configured no cache-prime runs")
}

fn measure_cpp(cpp_nix: &Path, tree: &Path, cache: &Path, home: &Path) -> Result<MeasuredValue> {
    fs::create_dir_all(cache)
        .with_context(|| format!("creating C++ Nix eval cache {}", cache.display()))?;
    fs::create_dir_all(home)
        .with_context(|| format!("creating changed-tree HOME {}", home.display()))?;
    let installable = format!("path:{}#result", tree.display());
    let started = Instant::now();
    let output = Command::new(cpp_nix)
        .arg("--extra-experimental-features")
        .arg("nix-command flakes")
        .arg("eval")
        .arg("--json")
        .arg("--no-write-lock-file")
        .arg(installable)
        .env("XDG_CACHE_HOME", cache)
        .env("HOME", home)
        .output()
        .with_context(|| {
            format!(
                "running C++ Nix changed-tree eval via {}",
                cpp_nix.display()
            )
        })?;
    let elapsed_seconds = started.elapsed().as_secs_f64();
    if !output.status.success() {
        anyhow::bail!(
            "C++ Nix changed-tree eval failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let value = serde_json::from_slice(&output.stdout)
        .context("parsing C++ Nix changed-tree JSON output")?;
    Ok(MeasuredValue {
        value,
        elapsed_seconds,
    })
}

#[cfg(feature = "native-eval")]
fn measure_aos(expression: &str, cache: &Path, verbose: u8) -> Result<MeasuredAosValue> {
    use aos_nix::NixNative;
    use aos_nix::eval::tree_walk::TreeWalkOptions;

    let mut options = TreeWalkOptions::default();
    options.set_parse_cache_root(cache.join("parse"));
    options.set_persist_cache_root(cache.join("persist"));
    options.set_eval_cache_enabled(true);
    let evaluator = NixNative::with_options(verbose, options)
        .context("creating aos-nix changed-tree evaluator")?;
    let started = Instant::now();
    let (json, stats) = evaluator
        .eval_expr_with_stats(expression)
        .context("running aos-nix changed-tree eval")?;
    let elapsed_seconds = started.elapsed().as_secs_f64();
    let value = serde_json::from_str(&json).context("parsing aos-nix changed-tree JSON output")?;
    Ok(MeasuredAosValue {
        value,
        elapsed_seconds,
        cache: CacheCounters {
            cache_hits: stats.cache_hits(),
            cache_misses: stats.cache_misses(),
            early_cutoffs: stats.early_cutoffs(),
            root_cutoffs: stats.root_cutoffs(),
            force_cache_hits: stats.force_cache_hits(),
            force_cache_misses: stats.force_cache_misses(),
            memoization_admits: stats.force_cache_memoization_admits(),
            memoization_bypasses: stats.force_cache_memoization_bypasses(),
            materialization_materializes: stats.force_cache_materialization_materializes(),
            materialization_keeps_in_memory: stats.force_cache_materialization_keeps_in_memory(),
            thunks_forced: stats.thunks_forced(),
            thunks_allocated: stats.thunks_allocated(),
        },
    })
}

fn cpp_nix_binary() -> PathBuf {
    if let Some(oracle) = std::env::var_os("AOS_NIX_ORACLE") {
        let oracle = PathBuf::from(oracle);
        if let Some(parent) = oracle.parent() {
            let sibling = parent.join("nix");
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from("nix")
}

fn render_human(printer: &Printer, report: &ChangedTreeReport) {
    printer.success(&format!(
        "changed-tree warm-cache benchmark matched {} scenario(s)",
        report.scenarios.len()
    ));
    printer.plain(&format!(
        "  fixture: {} groups x {} leaves; {} work items/leaf; {} prime runs; {} samples",
        report.groups,
        report.leaves_per_group,
        report.leaf_work_items,
        report.prime_runs,
        report.samples
    ));
    printer.plain("  first run after mutation");
    printer.plain(
        "  scenario                 changed  aos-ms  cpp-ms  aos/cpp  force-h  force-m  forced",
    );
    for scenario in &report.scenarios {
        printer.plain(&format!(
            "  {:<24} {:<7} {:>7.2} {:>7.2} {:>8.3} {:>8} {:>8} {:>7}",
            scenario.name,
            scenario.output_changed,
            scenario.aos_nix.median_seconds * 1_000.0,
            scenario.cpp_nix.median_seconds * 1_000.0,
            scenario.aos_over_cpp,
            scenario.aos_cache.median_force_cache_hits,
            scenario.aos_cache.median_force_cache_misses,
            scenario.aos_cache.median_thunks_forced,
        ));
    }
    printer.plain(
        "  settled warm rerun       changed  aos-ms  cpp-ms  aos/cpp  force-h  force-m  cutoffs",
    );
    for scenario in &report.scenarios {
        printer.plain(&format!(
            "  {:<24} {:<7} {:>7.2} {:>7.2} {:>8.3} {:>8} {:>8} {:>8}",
            scenario.name,
            scenario.output_changed,
            scenario.settled_aos_nix.median_seconds * 1_000.0,
            scenario.settled_cpp_nix.median_seconds * 1_000.0,
            scenario.settled_aos_over_cpp,
            scenario.settled_aos_cache.median_force_cache_hits,
            scenario.settled_aos_cache.median_force_cache_misses,
            scenario.settled_aos_cache.median_early_cutoffs,
        ));
    }
    printer.plain("  memo heuristic            admits  bypasses  durable  in-memory  cutoffs");
    for scenario in &report.scenarios {
        printer.plain(&format!(
            "  {:<24} {:>7} {:>9} {:>8} {:>10} {:>8}",
            scenario.name,
            scenario.aos_cache.median_memoization_admits,
            scenario.aos_cache.median_memoization_bypasses,
            scenario.aos_cache.median_materialization_materializes,
            scenario.aos_cache.median_materialization_keeps_in_memory,
            scenario.aos_cache.median_early_cutoffs,
        ));
    }
    printer.plain(&format!("  C++ cache: {}", report.stock_cache_scope));
    printer.plain(&format!("  aos cache: {}", report.aos_cache_scope));
}

struct ScratchTree {
    root: PathBuf,
    tree: PathBuf,
    cpp_cache: PathBuf,
    aos_cache: PathBuf,
    home: PathBuf,
}

impl ScratchTree {
    fn create() -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_nanos();
        for attempt in 0..100_u32 {
            let root = std::env::temp_dir().join(format!(
                "aos-nix-changed-tree-{}-{now}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let root = fs::canonicalize(&root).with_context(|| {
                        format!("canonicalizing changed-tree root {}", root.display())
                    })?;
                    let tree = root.join("tree");
                    fs::create_dir(&tree).with_context(|| {
                        format!("creating changed-tree source root {}", tree.display())
                    })?;
                    return Ok(Self {
                        cpp_cache: root.join("cpp-cache"),
                        aos_cache: root.join("aos-cache"),
                        home: root.join("home"),
                        root,
                        tree,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("creating changed-tree root {}", root.display()));
                }
            }
        }
        anyhow::bail!("unable to allocate a unique changed-tree benchmark root")
    }

    fn tree(&self) -> &Path {
        &self.tree
    }

    fn cpp_cache(&self) -> &Path {
        &self.cpp_cache
    }

    fn aos_cache(&self) -> &Path {
        &self.aos_cache
    }

    fn home(&self) -> &Path {
        &self.home
    }
}

impl Drop for ScratchTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct NixTreeFixture {
    root: PathBuf,
    groups: usize,
    leaves_per_group: usize,
}

impl NixTreeFixture {
    fn create(root: &Path, groups: usize, leaves_per_group: usize) -> Result<Self> {
        let fixture = Self {
            root: root.to_path_buf(),
            groups,
            leaves_per_group,
        };
        fs::create_dir_all(fixture.root.join("groups"))?;
        fs::create_dir_all(fixture.root.join("leaves"))?;
        fixture.write("flake.nix", &flake_source())?;
        fixture.write("root.nix", &fixture.root_source(0))?;
        fixture.write("shared.nix", &shared_source(7, 0))?;
        fixture.write("unused.nix", "{ marker = 1; } # revision 0\n")?;
        for group in 0..groups {
            fixture.write(
                &format!("groups/group-{group:02}.nix"),
                &fixture.group_source(group, false),
            )?;
            for leaf in 0..leaves_per_group {
                fixture.write_leaf(group, leaf, leaf_seed(group, leaf), 0)?;
            }
        }
        fixture.write("leaves/alternate.nix", &leaf_source(leaf_seed(0, 0), 0))?;
        Ok(fixture)
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn aos_expression(&self) -> Result<String> {
        let root = self.root.join("root.nix");
        let root = root
            .to_str()
            .with_context(|| format!("changed-tree path is not UTF-8: {}", root.display()))?;
        Ok(format!("import (builtins.toPath {})", nix_string(root)))
    }

    fn apply(&self, mutation: Mutation) -> Result<()> {
        match mutation {
            Mutation::None => Ok(()),
            Mutation::UnusedFileComment => {
                self.write("unused.nix", "{ marker = 1; } # revision 1\n")
            }
            Mutation::ForcedLeafComment => self.write_leaf(0, 0, leaf_seed(0, 0), 1),
            Mutation::RootComment => self.write("root.nix", &self.root_source(1)),
            Mutation::ImportEdge => self.write("groups/group-00.nix", &self.group_source(0, true)),
            Mutation::OneLeafValue => {
                self.write_leaf(0, 0, leaf_seed(0, 0).saturating_add(10_000), 0)
            }
            Mutation::ScatteredLeafValues => {
                for group in 0..self.groups {
                    self.write_leaf(group, 0, leaf_seed(group, 0).saturating_add(10_000), 0)?;
                }
                Ok(())
            }
            Mutation::SharedComment => self.write("shared.nix", &shared_source(7, 1)),
            Mutation::SharedValue => self.write("shared.nix", &shared_source(8, 0)),
        }
    }

    fn root_source(&self, revision: u32) -> String {
        let imports = (0..self.groups)
            .map(|group| format!("(import ./groups/group-{group:02}.nix)"))
            .collect::<Vec<_>>()
            .join("\n    ");
        format!(
            r#"let
  groups = [
    {imports}
  ];
in {{
  count = builtins.foldl' (sum: group: sum + group.count) 0 groups;
  total = builtins.foldl' (sum: group: sum + group.total) 0 groups;
  groupTotals = map (group: group.total) groups;
}}
# revision {revision}
"#
        )
    }

    fn group_source(&self, group: usize, alternate: bool) -> String {
        let imports = (0..self.leaves_per_group)
            .map(|leaf| {
                if alternate && leaf == 0 {
                    "(import ../leaves/alternate.nix)".to_string()
                } else {
                    format!("(import ../leaves/leaf-{group:02}-{leaf:02}.nix)")
                }
            })
            .collect::<Vec<_>>()
            .join("\n    ");
        format!(
            r#"let
  shared = import ../shared.nix;
  leaves = [
    {imports}
  ];
in {{
  count = builtins.length leaves;
  total = builtins.foldl' (sum: leaf: sum + leaf) 0 leaves
    + shared.bias * builtins.length leaves;
}}
"#
        )
    }

    fn write_leaf(&self, group: usize, leaf: usize, seed: usize, revision: u32) -> Result<()> {
        self.write(
            &format!("leaves/leaf-{group:02}-{leaf:02}.nix"),
            &leaf_source(seed, revision),
        )
    }

    fn write(&self, relative: &str, source: &str) -> Result<()> {
        let path = self.root.join(relative);
        fs::write(&path, source)
            .with_context(|| format!("writing changed-tree fixture {}", path.display()))
    }
}

fn leaf_seed(group: usize, leaf: usize) -> usize {
    group
        .saturating_mul(1_000)
        .saturating_add(leaf)
        .saturating_add(1)
}

fn leaf_source(seed: usize, revision: u32) -> String {
    format!(
        r#"let
  values = builtins.genList (i: (i + {seed}) * (i + 3)) {LEAF_WORK_ITEMS};
in {seed} + builtins.foldl' (sum: value: sum + value) 0 values
# revision {revision}
"#
    )
}

fn shared_source(bias: usize, revision: u32) -> String {
    format!("{{ bias = {bias}; }} # revision {revision}\n")
}

fn flake_source() -> String {
    "{ outputs = { self }: { result = import ./root.nix; }; }\n".to_string()
}

fn nix_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn median_f64(ordered: &[f64]) -> f64 {
    if ordered.is_empty() {
        return 0.0;
    }
    let middle = ordered.len() / 2;
    if ordered.len() % 2 == 0 {
        (ordered[middle - 1] + ordered[middle]) / 2.0
    } else {
        ordered[middle]
    }
}

fn median_u64(values: impl Iterator<Item = u64>) -> u64 {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    if values.is_empty() {
        return 0;
    }
    values[values.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_matrix_covers_change_locality_and_semantics() {
        assert_eq!(SCENARIOS.len(), 9);
        assert!(
            SCENARIOS
                .iter()
                .any(|scenario| scenario.name == "unchanged")
        );
        assert!(
            SCENARIOS
                .iter()
                .any(|scenario| scenario.name == "unused-file-comment")
        );
        assert!(
            SCENARIOS
                .iter()
                .any(|scenario| scenario.name == "shared-value" && scenario.output_changes)
        );
        assert!(
            SCENARIOS
                .iter()
                .any(|scenario| scenario.name == "import-edge" && !scenario.output_changes)
        );
    }

    #[test]
    fn fixture_mutations_touch_the_expected_scope() {
        let scratch = ScratchTree::create().expect("scratch tree builds");
        let fixture = NixTreeFixture::create(scratch.tree(), 2, 3).expect("fixture builds");
        let leaf = fixture.root.join("leaves/leaf-00-00.nix");
        let sibling = fixture.root.join("leaves/leaf-01-00.nix");
        let before_leaf = fs::read_to_string(&leaf).expect("leaf reads");
        let before_sibling = fs::read_to_string(&sibling).expect("sibling reads");

        fixture
            .apply(Mutation::ForcedLeafComment)
            .expect("leaf comment mutates");

        assert_ne!(fs::read_to_string(leaf).expect("leaf rereads"), before_leaf);
        assert_eq!(
            fs::read_to_string(sibling).expect("sibling rereads"),
            before_sibling
        );
    }

    #[test]
    fn timing_summary_reports_even_sample_median() {
        let summary = TimingSummary::from_samples(&[4.0, 1.0, 3.0, 2.0]);
        assert_eq!(summary.median_seconds, 2.5);
        assert_eq!(summary.mean_seconds, 2.5);
        assert_eq!(summary.min_seconds, 1.0);
        assert_eq!(summary.max_seconds, 4.0);
    }
}
