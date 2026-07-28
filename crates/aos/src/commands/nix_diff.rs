//! `aos nix-diff` -- compare evaluator `.drv` and strict JSON expression output.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use aos_core::error::AosError;
use aos_core::nix::{
    DrvClosure, NixCli, NixCompatProfile, NixEval, NixEvalConfig, NixEvalMode,
    NixEvalStrictJsonStats, NixInstantiateStats, NixRunner,
    select_native_diff_candidate_with_config,
};
use aos_core::output::{OutputMode, Printer};
use aos_nix_harness::diff::{
    DiffMode, DiffSide, DrvDiff, DrvDiffPair, DrvDiffReport, diff_closure,
    diff_drv_pair_with_bundles,
};

const SOURCE_SEED_PREFIX: &str = "# aos-nix-fuzz-source\n";
const SOURCE_SEED_CONFIG_PREFIX: &str = "# aos-nix-fuzz-config ";

const EXPLICIT_TOOLCHAIN_CORPUS_ATTRS: &[&str] = &[
    "stdenv.stdenv",
    "stdenv.cc",
    "stdenv.gcc",
    "stdenv.gccStage2",
    "stdenv.glibc",
    "stdenv.binutils",
    "stdenv.bash",
    "stdenv.coreutils",
    "stdenv.gnumake",
    "stdenv.sed",
    "stdenv.grep",
    "stdenv.findutils",
    "stdenv.gawk",
    "stdenv.diffutils",
    "stdenv.tar",
    "stdenv.gzip",
    "stdenv.patch",
    "stdenv.bootstrap.gcc",
    "stdenv.bootstrap.glibc",
    "stdenv.bootstrap.binutils",
    "stdenv.bootstrap.bash",
    "stdenv.bootstrap.gnumake",
    "stdenv.bootstrap.sed",
    "stdenv.bootstrap.grep",
    "stdenv.bootstrap.patch",
    "stdenv.bootstrap.coreutils",
    "stdenv.bootstrap.gawk",
    "stdenv.bootstrap.findutils",
    "stdenv.bootstrap.diffutils",
    "stdenv.bootstrap.tar",
    "stdenv.bootstrap.gzip",
    "pkgs.bootstrapTools",
    "pkgs.cc",
    "pkgs.gcc",
    "pkgs.gccUnwrapped",
    "pkgs.glibc",
    "pkgs.binutils",
    "pkgs.rust-1_74",
    "pkgs.rust-1_75",
    "pkgs.rust-1_76",
    "pkgs.rust-1_77",
    "pkgs.rust-1_78",
    "pkgs.rust-1_79",
    "pkgs.rust-1_80",
    "pkgs.rust-1_81",
    "pkgs.rust-1_82",
    "pkgs.rust-1_83",
    "pkgs.rust-1_84",
    "pkgs.rust-1_85",
    "pkgs.rust-1_86",
    "pkgs.rust-1_87",
    "pkgs.rust-1_88",
    "pkgs.rust-1_89",
    "pkgs.rust-1_90",
    "pkgs.rust-1_91",
    "pkgs.rust-1_92",
    "pkgs.rust",
    "pkgs.openjdk-7",
    "pkgs.openjdk-8",
    "pkgs.openjdk-9",
    "pkgs.openjdk-10",
    "pkgs.openjdk-11",
    "pkgs.openjdk-12",
    "pkgs.openjdk-13",
    "pkgs.openjdk-14",
    "pkgs.openjdk-15",
    "pkgs.openjdk-16",
    "pkgs.openjdk-17",
    "pkgs.openjdk-18",
    "pkgs.openjdk-19",
    "pkgs.openjdk-20",
    "pkgs.openjdk-21",
    "pkgs.openjdk-22",
    "pkgs.openjdk-23",
    "pkgs.openjdk-24",
    "pkgs.openjdk",
    "pkgs.bazel-bootstrap",
    "pkgs.bazel-7",
    "pkgs.bazel-8",
    "pkgs.bazel-9",
    "pkgs.bazel",
    "pkgs.llvm-17",
    "pkgs.llvm-18",
    "pkgs.llvm-19",
    "pkgs.llvm-20",
    "pkgs.llvm-21",
    "pkgs.llvm-22",
    "pkgs.llvm",
    "pkgs.go-1_4",
    "pkgs.go-1_17",
    "pkgs.go-1_20",
    "pkgs.go-1_22",
    "pkgs.go-1_24",
    "pkgs.go",
    "pkgs.python3-3_12",
    "pkgs.python3",
    "pkgs.cmake",
    "pkgs.meson",
    "pkgs.ninja",
];

const SMOKE_CORPUS_ATTRS: &[&str] = &["pkgs.zlib"];

const GCC_TOOLCHAIN_TIER_COMPONENTS: &[&str] = &[
    "gcc",
    "gccStage2",
    "glibc",
    "binutils",
    "linuxHeaders",
    "bash",
    "coreutils",
    "gnumake",
    "sed",
    "grep",
    "gawk",
    "findutils",
    "diffutils",
    "tar",
    "gzip",
    "patch",
    "m4",
    "flex",
    "bison",
    "perl",
    "autoconf",
    "automake",
    "texinfo",
    "help2man",
    "gperf",
    "python3",
    "xz",
    "bzip2",
    "patchelf",
];

const AOS_NIX_LANG_TESTS_ENV: &str = "AOS_NIX_LANG_TESTS";
const CONFORMANCE_CORPUS_ATTRSET: &str = "conformance";
const CONFORMANCE_CORPUS_BUILDER: &str =
    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-nix-conformance-builder";
const LANG_CASE_EXCLUSION_NAMES: &[&str] = &[];
const CONFORMANCE_WRAPPER_ONLY_EXCLUSION_NAMES: &[&str] = &[
    // `lang.sh` fixes HOME and TEST_VAR for these cases; `nix-diff` has no
    // per-attribute environment override, so the dedicated runner owns them.
    "eval-okay-getenv",
    "eval-okay-path-string-interpolation",
    // The case value is the non-existent source path `/foo`; the corpus
    // wrapper's `builtins.toJSON` must copy it to the store, and both
    // evaluators fail uncatchably outside `lang.sh`'s raw-output mode. The
    // dedicated runner compares the raw value without JSON serialization.
    "eval-okay-builtins",
    // `(builtins.tryEval <foobaz>).success` needs the configured `NIX_PATH`
    // angle-bracket lookup that `lang.sh` provides; the `nix-diff` seam does
    // not configure a search path, so the dedicated runner owns this case.
    "eval-okay-redefine-builtin",
];

/// Error returned after `aos nix-diff` has already rendered a failure report.
#[derive(Debug, Clone)]
pub struct NixDiffReportedFailure {
    message: String,
}

impl NixDiffReportedFailure {
    pub(crate) fn diverged(count: usize) -> Self {
        Self {
            message: format!("drv diff found {count} divergence(s)"),
        }
    }

    fn no_drv_output() -> Self {
        Self {
            message: "drv diff produced no derivation output to compare".to_string(),
        }
    }

    fn incomplete_drv_output() -> Self {
        Self {
            message: "drv diff produced incomplete derivation output to compare".to_string(),
        }
    }

    fn corpus_failed(failing_attrs: usize, divergence_count: usize) -> Self {
        let message = if divergence_count == 0 {
            format!("drv diff failed for {failing_attrs} attribute(s)")
        } else {
            format!(
                "drv diff failed for {failing_attrs} attribute(s) with {divergence_count} divergence(s)"
            )
        };
        Self { message }
    }

    fn eval_json_failed(failing_exprs: usize, divergence_count: usize) -> Self {
        let message = if divergence_count == 0 {
            format!("eval-json diff failed for {failing_exprs} expression(s)")
        } else {
            format!(
                "eval-json diff failed for {failing_exprs} expression(s) with {divergence_count} divergence(s)"
            )
        };
        Self { message }
    }

    fn attr_error(error: String) -> Self {
        Self { message: error }
    }
}

impl std::fmt::Display for NixDiffReportedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NixDiffReportedFailure {}

/// Runs the evaluator `.drv` diff harness.
///
/// # Errors
///
/// Returns an error if either evaluator cannot be initialized, the harness
/// cannot read the resulting `.drv` closure, or the evaluators diverge.
pub fn run(
    printer: &Printer,
    verbose: u8,
    mut eval_config: NixEvalConfig,
    file: &Path,
    attr: Option<&str>,
    smoke: bool,
    all: bool,
    systems: bool,
    eval_json: bool,
    exprs: &[String],
    eval_json_corpus: &[PathBuf],
    time_budget: Option<Duration>,
    mode: DiffMode,
    oracle_stats: bool,
    cache_validation: bool,
) -> Result<()> {
    if eval_config.eval_mode() == NixEvalMode::Ambient {
        eval_config.set_eval_mode(NixEvalMode::Impure);
    }
    validate_eval_json_selection(
        eval_json,
        attr,
        smoke,
        all,
        systems,
        mode,
        oracle_stats,
        cache_validation,
    )?;
    ensure_nix_instantiate_after_cache_validation_mode_check(
        cache_validation,
        mode,
        NixRunner::ensure_nix_instantiate_available,
    )?;

    if eval_json {
        return run_eval_json(
            printer,
            verbose,
            &eval_config,
            exprs,
            eval_json_corpus,
            time_budget,
        );
    }

    let oracle = NixCli::with_eval_config(verbose, eval_config.clone());

    if cache_validation {
        return run_cache_validation(
            printer,
            verbose,
            &oracle,
            &eval_config,
            file,
            attr,
            smoke,
            all,
            systems,
            mode,
        );
    }

    let candidate = select_native_diff_candidate_with_config(verbose, eval_config.clone())?;
    let candidate_name = candidate.name();

    if smoke || all || systems {
        return run_all(
            printer,
            &oracle,
            candidate.as_ref(),
            candidate_name,
            &eval_config,
            file,
            smoke,
            all,
            systems,
            mode,
            oracle_stats,
        );
    }

    let attr = attr.ok_or_else(|| AosError::InvalidArgument {
        message: "provide --attr <ATTR>, --smoke, --all, or --systems".to_string(),
    })?;

    let oracle_stats = if oracle_stats {
        Some(
            oracle
                .instantiate_with_stats(file, attr)
                .with_context(|| format!("capturing nix-cli stats for {attr}"))?,
        )
    } else {
        None
    };
    let report = diff_closure(&oracle, candidate.as_ref(), file, attr, mode)?;
    let failure = report_failure(&report);

    if printer.json_if_active(&report_json(
        &report,
        candidate_name,
        &eval_config,
        file,
        attr,
        failure.as_ref(),
        oracle_stats.as_ref(),
    )) {
        if let Some(failure) = failure {
            return Err(failure.into());
        } else {
            return Ok(());
        }
    }

    let Some(failure) = failure else {
        printer.success(&format!(
            "drv diff matched: nix-cli vs {candidate_name} ({mode:?})"
        ));
        render_single_oracle_stats(printer, oracle_stats.as_ref());
        return Ok(());
    };

    if printer.mode() == OutputMode::Quiet {
        printer.error(&failure.to_string());
    } else if report.divergences.is_empty() {
        printer.warning(&failure.to_string());
        render_single_oracle_stats(printer, oracle_stats.as_ref());
    } else {
        printer.warning(&format!(
            "drv diff found {} divergence(s): nix-cli vs {candidate_name}",
            report.divergences.len()
        ));
        for divergence in &report.divergences {
            printer.plain(&format!("  - {}", render_diff(divergence)));
        }
        render_reproduction_hint(printer, &eval_config, file, attr, mode, "  ");
        render_eval_divergence_classes(printer, &eval_config, file, attr, &report, "  ");
        render_single_oracle_stats(printer, oracle_stats.as_ref());
    }
    Err(failure.into())
}

fn run_cache_validation(
    printer: &Printer,
    verbose: u8,
    oracle: &NixCli,
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: Option<&str>,
    smoke: bool,
    all: bool,
    systems: bool,
    mode: DiffMode,
) -> Result<()> {
    validate_cache_validation_mode(mode)?;
    let cache_off_config = cache_validation_cache_off_config(eval_config);
    let cache_off = select_native_diff_candidate_with_config(verbose, cache_off_config)?;

    let entries = if smoke || all || systems {
        corpus_entries(oracle, file, smoke, all, systems)?.entries
    } else {
        let attr = attr.ok_or_else(|| AosError::InvalidArgument {
            message: "provide --attr <ATTR>, --smoke, --all, or --systems".to_string(),
        })?;
        vec![CorpusEntry {
            file: file.to_path_buf(),
            attr: attr.to_string(),
        }]
    };

    if entries.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-diff cache validation selection found no derivations".to_string(),
        }
        .into());
    }

    printer.info(&format!(
        "Cache-validating {} selected derivation(s)...",
        entries.len()
    ));

    let mut reports = Vec::with_capacity(entries.len());
    for entry in &entries {
        let cold_cache_root = create_cold_cache_validation_root()?;
        let cold_cache_config = cache_validation_cold_cache_config(eval_config, &cold_cache_root)?;
        let cold_cache = select_native_diff_candidate_with_config(verbose, cold_cache_config)?;
        reports.push(cache_validation_attr_report(
            oracle,
            cache_off.as_ref(),
            cold_cache.as_ref(),
            cold_cache_root,
            &entry.file,
            &entry.attr,
            mode,
        ));
    }

    let failure = cache_validation_failure(&reports);
    cleanup_successful_cache_validation_roots(&reports);

    if printer.json_if_active(&cache_validation_json(
        &reports,
        eval_config,
        file,
        mode,
        failure.as_ref(),
    )) {
        if let Some(failure) = failure {
            return Err(failure.into());
        }
        return Ok(());
    }

    let Some(failure) = failure else {
        printer.success(&format!(
            "cache validation matched {} selected derivation(s): nix-cli, native cache-off, native cold-cache ({mode:?})",
            reports.len()
        ));
        printer.info("successful cold cache roots were removed");
        return Ok(());
    };

    if printer.mode() == OutputMode::Quiet {
        printer.error(&failure.to_string());
    } else {
        let failed = reports.iter().filter(|report| report.has_failure()).count();
        printer.warning(&format!(
            "cache validation failed for {failed} of {} selected derivation(s)",
            reports.len()
        ));
        for attr_report in reports.iter().filter(|report| report.has_failure()) {
            printer.plain(&format!(
                "  - {} {}",
                attr_report.file.display(),
                attr_report.attr
            ));
            printer.plain(&format!(
                "      reproduce: {}",
                cache_validation_reproduction_command(
                    eval_config,
                    &attr_report.file,
                    &attr_report.attr,
                    mode,
                )
            ));
            printer.plain(&format!(
                "      cold cache root: {}",
                attr_report.cold_cache_root.display()
            ));
            for comparison in attr_report
                .comparisons()
                .iter()
                .filter(|comparison| comparison.failure.is_some())
            {
                let failure = comparison
                    .failure
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "drv diff failed".to_string());
                printer.plain(&format!("      {}: {failure}", comparison.name));
                if let Some(report) = &comparison.report {
                    for divergence in &report.divergences {
                        printer.plain(&format!("        - {}", render_diff(divergence)));
                    }
                }
            }
        }
    }

    Err(failure.into())
}

/// Runs the direct `.drv` pair comparison path.
///
/// # Errors
///
/// Returns an error if the harness cannot read the requested `.drv` pair or
/// the derivations diverge under the requested comparison mode.
pub fn run_pair(
    printer: &Printer,
    oracle_drv: &Path,
    candidate_drv: &Path,
    oracle_bundle: Option<&Path>,
    candidate_bundle: Option<&Path>,
    mode: DiffMode,
) -> Result<()> {
    let report = diff_drv_pair_with_bundles(
        oracle_drv,
        candidate_drv,
        oracle_bundle,
        candidate_bundle,
        mode,
    )?;
    let failure = report_failure(&report);

    if printer.json_if_active(&drv_pair_report_json(
        &report,
        oracle_drv,
        candidate_drv,
        oracle_bundle,
        candidate_bundle,
        failure.as_ref(),
    )) {
        if let Some(failure) = failure {
            return Err(failure.into());
        } else {
            return Ok(());
        }
    }

    let Some(failure) = failure else {
        printer.success(&format!(
            "drv pair matched: oracle={} candidate={} ({mode:?})",
            oracle_drv.display(),
            candidate_drv.display(),
        ));
        return Ok(());
    };

    if printer.mode() == OutputMode::Quiet {
        printer.error(&failure.to_string());
    } else if report.divergences.is_empty() {
        printer.warning(&failure.to_string());
    } else {
        printer.warning(&format!(
            "drv pair found {} divergence(s): oracle={} candidate={}",
            report.divergences.len(),
            oracle_drv.display(),
            candidate_drv.display(),
        ));
        for divergence in &report.divergences {
            printer.plain(&format!("  - {}", render_diff(divergence)));
        }
        render_node_reproduction_hint(
            printer,
            oracle_drv,
            candidate_drv,
            oracle_bundle,
            candidate_bundle,
            mode,
            "  ",
        );
        render_pair_divergence_classes(printer, &report, "  ");
    }
    Err(failure.into())
}

fn run_all(
    printer: &Printer,
    oracle: &NixCli,
    candidate: &dyn NixEval,
    candidate_name: &str,
    eval_config: &NixEvalConfig,
    file: &Path,
    include_smoke: bool,
    include_packages: bool,
    include_systems: bool,
    mode: DiffMode,
    oracle_stats: bool,
) -> Result<()> {
    let corpus = corpus_entries(
        oracle,
        file,
        include_smoke,
        include_packages,
        include_systems,
    )?;
    if corpus.entries.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-diff corpus selection found no derivations".to_string(),
        }
        .into());
    }

    printer.info(&format!(
        "Comparing {} selected derivation(s)...",
        corpus.entries.len()
    ));

    let mut reports = Vec::with_capacity(corpus.entries.len());
    for entry in &corpus.entries {
        let stats = if oracle_stats {
            match oracle
                .instantiate_with_stats(&entry.file, &entry.attr)
                .with_context(|| format!("capturing nix-cli stats for {}", entry.attr))
            {
                Ok(stats) => Some(stats),
                Err(error) => {
                    reports.push(AttrDiffReport {
                        file: entry.file.clone(),
                        attr: entry.attr.clone(),
                        report: None,
                        failure: Some(NixDiffReportedFailure::attr_error(format!("{error:#}"))),
                        oracle_stats: None,
                    });
                    continue;
                }
            }
        } else {
            None
        };
        match diff_closure(oracle, candidate, &entry.file, &entry.attr, mode)
            .with_context(|| format!("diffing {}", entry.attr))
        {
            Ok(report) => {
                let failure = report_failure(&report);
                reports.push(AttrDiffReport {
                    file: entry.file.clone(),
                    attr: entry.attr.clone(),
                    report: Some(report),
                    failure,
                    oracle_stats: stats,
                });
            }
            Err(error) => {
                reports.push(AttrDiffReport {
                    file: entry.file.clone(),
                    attr: entry.attr.clone(),
                    report: None,
                    failure: Some(NixDiffReportedFailure::attr_error(format!("{error:#}"))),
                    oracle_stats: stats,
                });
            }
        }
    }

    let failure = corpus_failure(&reports);

    if printer.json_if_active(&corpus_json(
        &reports,
        candidate_name,
        &eval_config,
        file,
        mode,
        failure.as_ref(),
    )) {
        if let Some(failure) = failure {
            return Err(failure.into());
        } else {
            return Ok(());
        }
    }

    let Some(failure) = failure else {
        printer.success(&format!(
            "drv diff matched {} selected derivation(s): nix-cli vs {candidate_name} ({mode:?})",
            reports.len()
        ));
        render_corpus_oracle_stats_summary(printer, &reports);
        return Ok(());
    };

    if printer.mode() == OutputMode::Quiet {
        printer.error(&failure.to_string());
    } else {
        let failed = reports
            .iter()
            .filter(|report| report.failure.is_some())
            .count();
        printer.warning(&format!(
            "drv diff failed for {failed} of {} selected derivation(s): nix-cli vs {candidate_name}",
            reports.len()
        ));
        for attr_report in reports.iter().filter(|report| report.failure.is_some()) {
            let failure = attr_report
                .failure
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "drv diff failed".to_string());
            printer.plain(&format!(
                "  - {} {}: {failure}",
                attr_report.file.display(),
                attr_report.attr
            ));
            render_reproduction_hint(
                printer,
                &eval_config,
                &attr_report.file,
                &attr_report.attr,
                mode,
                "      ",
            );
            if let Some(report) = &attr_report.report {
                for divergence in &report.divergences {
                    printer.plain(&format!("      - {}", render_diff(divergence)));
                }
                render_eval_divergence_classes(
                    printer,
                    eval_config,
                    &attr_report.file,
                    &attr_report.attr,
                    report,
                    "      ",
                );
            }
        }
        render_corpus_oracle_stats_summary(printer, &reports);
    }
    Err(failure.into())
}

fn run_eval_json(
    printer: &Printer,
    verbose: u8,
    eval_config: &NixEvalConfig,
    exprs: &[String],
    eval_json_corpus: &[PathBuf],
    time_budget: Option<Duration>,
) -> Result<()> {
    let entries = eval_json_entries(exprs, eval_json_corpus, eval_config)?;
    let oracle = NixCli::with_eval_config(verbose, eval_config.clone());
    let candidate = select_native_diff_candidate_with_config(verbose, eval_config.clone())?;
    let candidate_name = candidate.name();
    printer.info(&format!(
        "Comparing {} strict JSON expression(s)...",
        entries.len()
    ));

    let started = Instant::now();
    let mut reports = Vec::with_capacity(entries.len());
    for entry in &entries {
        // The budget is checked between entries so an in-flight comparison is
        // never aborted; at least one entry always runs so a zero budget still
        // performs real gate work.
        if let Some(budget) = time_budget
            && !reports.is_empty()
            && started.elapsed() >= budget
        {
            break;
        }
        let Some(entry_eval_config) = entry.eval_config.as_ref() else {
            reports.push(eval_json_report(
                &oracle,
                candidate.as_ref(),
                entry,
                eval_config,
            ));
            continue;
        };
        let entry_oracle = NixCli::with_eval_config(verbose, entry_eval_config.clone());
        let entry_candidate =
            select_native_diff_candidate_with_config(verbose, entry_eval_config.clone())?;
        reports.push(eval_json_report(
            &entry_oracle,
            entry_candidate.as_ref(),
            entry,
            entry_eval_config,
        ));
    }
    let skipped = entries.len() - reports.len();
    let failure = eval_json_failure(&reports);

    if printer.json_if_active(&eval_json_report_json(
        &reports,
        skipped,
        time_budget,
        candidate_name,
        failure.as_ref(),
    )) {
        if let Some(failure) = failure {
            return Err(failure.into());
        }
        return Ok(());
    }

    let Some(failure) = failure else {
        printer.success(&format!(
            "eval-json diff matched {} expression(s): nix-cli vs {candidate_name}",
            reports.len()
        ));
        if skipped > 0 {
            printer.warning(&eval_json_budget_note(skipped, entries.len(), time_budget));
        }
        return Ok(());
    };

    if printer.mode() == OutputMode::Quiet {
        printer.error(&failure.to_string());
    } else {
        let failed = reports
            .iter()
            .filter(|report| report.failure.is_some())
            .count();
        printer.warning(&format!(
            "eval-json diff failed for {failed} of {} expression(s): nix-cli vs {candidate_name}",
            reports.len()
        ));
        for report in reports.iter().filter(|report| report.failure.is_some()) {
            let failure = report
                .failure
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "eval-json diff failed".to_string());
            printer.plain(&format!("  - {}: {failure}", report.name));
            printer.plain(&format!(
                "      reproduce: {}",
                eval_json_reproduction_command(&report.eval_config, &report.expr)
            ));
            if let (EvalJsonResult::Value(oracle), EvalJsonResult::Value(candidate)) =
                (&report.oracle, &report.candidate)
            {
                printer.plain(&format!("      oracle: {oracle}"));
                printer.plain(&format!("      candidate: {candidate}"));
            }
        }
        if skipped > 0 {
            printer.warning(&eval_json_budget_note(skipped, entries.len(), time_budget));
        }
    }
    Err(failure.into())
}

/// Renders the human-readable note emitted when a `--time-budget` run stops
/// before comparing every corpus entry.
fn eval_json_budget_note(skipped: usize, total: usize, time_budget: Option<Duration>) -> String {
    let budget = time_budget
        .map(|budget| format!("{}s", budget.as_secs()))
        .unwrap_or_else(|| "unset".to_string());
    format!(
        "eval-json time budget ({budget}) exhausted: skipped {skipped} of {total} expression(s)"
    )
}

fn eval_json_entries(
    exprs: &[String],
    eval_json_corpus: &[PathBuf],
    eval_config: &NixEvalConfig,
) -> Result<Vec<EvalJsonEntry>> {
    if exprs.is_empty() && eval_json_corpus.is_empty() {
        return Ok(default_eval_json_entries());
    }

    let mut entries = exprs
        .iter()
        .enumerate()
        .map(|(index, expr)| EvalJsonEntry {
            name: format!("expr[{index}]"),
            expr: expr.clone(),
            eval_config: None,
        })
        .collect::<Vec<_>>();

    for path in eval_json_corpus {
        entries.extend(eval_json_corpus_entries(path, eval_config)?);
    }

    if entries.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-diff --eval-json found no source expressions".to_string(),
        }
        .into());
    }
    Ok(entries)
}

fn default_eval_json_entries() -> Vec<EvalJsonEntry> {
    [
        ("scalar", "1 + 1"),
        (
            "float-format",
            "[ 1.0 1.50 (-0.0) 0.000001 100000000000000000000.0 ]",
        ),
        ("attr-order", r#"{ b = 1; a = [ true null "x" ]; }"#),
        ("string-escape", r#""tab\tcr\rnl\nslash\\quote\"""#),
        (
            "attr-update",
            r#"({ a = "left"; } // { b = "right"; a = "right"; })"#,
        ),
        ("lazy-length", "builtins.length [ (1 / 0) ]"),
        (
            "string-context",
            r#"let
  x = builtins.appendContext "x" {
    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-seed" = { path = true; };
  };
in builtins.getContext "${x}""#,
        ),
    ]
    .into_iter()
    .map(|(name, expr)| EvalJsonEntry {
        name: name.to_string(),
        expr: expr.to_string(),
        eval_config: None,
    })
    .collect()
}

fn eval_json_corpus_entries(
    path: &Path,
    eval_config: &NixEvalConfig,
) -> Result<Vec<EvalJsonEntry>> {
    if path.is_file() {
        return eval_json_seed_entry(path, eval_config).map(|entry| vec![entry]);
    }
    if !path.exists() {
        return Err(AosError::InvalidArgument {
            message: format!("eval-json corpus path does not exist: {}", path.display()),
        }
        .into());
    }
    if !path.is_dir() {
        return Err(AosError::InvalidArgument {
            message: format!(
                "eval-json corpus path is neither a file nor directory: {}",
                path.display()
            ),
        }
        .into());
    }

    let mut seed_paths = fs::read_dir(path)
        .with_context(|| format!("reading eval-json corpus directory {}", path.display()))?
        .map(|entry| {
            let entry = entry
                .with_context(|| format!("reading entry in eval-json corpus {}", path.display()))?;
            Ok(entry.path())
        })
        .collect::<Result<Vec<_>>>()?;
    seed_paths.retain(|seed_path| {
        seed_path.is_file()
            && matches!(
                seed_path
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("seed")
            )
    });
    seed_paths.sort();

    if seed_paths.is_empty() {
        return Err(AosError::InvalidArgument {
            message: format!(
                "eval-json corpus directory contains no .seed files: {}",
                path.display()
            ),
        }
        .into());
    }

    seed_paths
        .iter()
        .map(|seed_path| eval_json_seed_entry(seed_path, eval_config))
        .collect()
}

fn eval_json_seed_entry(path: &Path, eval_config: &NixEvalConfig) -> Result<EvalJsonEntry> {
    let seed = fs::read_to_string(path)
        .with_context(|| format!("reading eval-json source seed {}", path.display()))?;
    let seed =
        eval_json_source_seed(&seed, eval_config).map_err(|error| AosError::InvalidArgument {
            message: format!("eval-json source seed {error}: {}", path.display()),
        })?;
    Ok(EvalJsonEntry {
        name: format!("seed:{}", path.display()),
        expr: seed.expr,
        eval_config: seed.eval_config,
    })
}

fn eval_json_source_seed(
    seed: &str,
    eval_config: &NixEvalConfig,
) -> std::result::Result<EvalJsonSourceSeed, EvalJsonSourceSeedError> {
    let seed = seed
        .strip_prefix(SOURCE_SEED_PREFIX)
        .ok_or(EvalJsonSourceSeedError::MissingPrefix)?;
    let mut metadata = EvalJsonSourceSeedMetadata::default();
    let mut source_lines = Vec::new();
    let mut reading_config = true;
    for line in seed.lines() {
        if reading_config {
            if let Some(raw_config) = line.strip_prefix(SOURCE_SEED_CONFIG_PREFIX) {
                metadata.apply_config_line(raw_config)?;
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            reading_config = false;
        }
        source_lines.push(line);
    }

    let expr = source_lines.join("\n").trim().to_string();
    if expr.is_empty() {
        return Err(EvalJsonSourceSeedError::EmptySource);
    }

    let eval_config = metadata.eval_config(eval_config)?;
    Ok(EvalJsonSourceSeed { expr, eval_config })
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct EvalJsonSourceSeed {
    expr: String,
    eval_config: Option<NixEvalConfig>,
}

#[derive(Debug, Default)]
struct EvalJsonSourceSeedMetadata {
    has_metadata: bool,
    eval_mode: Option<NixEvalMode>,
    current_system: Option<String>,
    allowed_paths: Vec<String>,
    allowed_uris: Vec<String>,
}

impl EvalJsonSourceSeedMetadata {
    fn apply_config_line(
        &mut self,
        line: &str,
    ) -> std::result::Result<(), EvalJsonSourceSeedError> {
        self.has_metadata = true;
        let (key, value) =
            line.split_once('=')
                .ok_or_else(|| EvalJsonSourceSeedError::InvalidConfig {
                    message: format!("metadata line {line:?} is missing '='"),
                })?;
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            return Err(EvalJsonSourceSeedError::InvalidConfig {
                message: format!("metadata key {key:?} has an empty value"),
            });
        }

        match key {
            "eval-mode" => {
                self.eval_mode = Some(match value {
                    "ambient" => {
                        return Err(EvalJsonSourceSeedError::InvalidConfig {
                            message: "eval-mode \"ambient\" is not supported by eval-json diff"
                                .to_string(),
                        });
                    }
                    "impure" => NixEvalMode::Impure,
                    "restricted" => NixEvalMode::Restricted,
                    "pure" => NixEvalMode::Pure,
                    _ => {
                        return Err(EvalJsonSourceSeedError::InvalidConfig {
                            message: format!("unknown eval-mode {value:?}"),
                        });
                    }
                });
            }
            "current-system" | "system" => self.current_system = Some(value.to_string()),
            "allowed-path" => self.allowed_paths.push(value.to_string()),
            "allowed-uri" => self.allowed_uris.push(value.to_string()),
            _ => {
                return Err(EvalJsonSourceSeedError::InvalidConfig {
                    message: format!("unknown metadata key {key:?}"),
                });
            }
        }
        Ok(())
    }

    fn eval_config(
        self,
        base: &NixEvalConfig,
    ) -> std::result::Result<Option<NixEvalConfig>, EvalJsonSourceSeedError> {
        if !self.has_metadata {
            return Ok(None);
        }

        let mut config = base.clone();
        if let Some(eval_mode) = self.eval_mode {
            config.set_eval_mode(eval_mode);
            config.clear_allowed_paths();
            config.clear_allowed_uris();
        }
        if !self.allowed_paths.is_empty() || !self.allowed_uris.is_empty() {
            config.clear_allowed_paths();
            config.clear_allowed_uris();
        }
        if let Some(current_system) = self.current_system {
            config
                .set_current_system(current_system)
                .map_err(EvalJsonSourceSeedError::invalid_config)?;
        }
        for path in self.allowed_paths {
            config
                .add_allowed_path(path)
                .map_err(EvalJsonSourceSeedError::invalid_config)?;
        }
        for uri in self.allowed_uris {
            config
                .add_allowed_uri(uri)
                .map_err(EvalJsonSourceSeedError::invalid_config)?;
        }
        Ok(Some(config))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum EvalJsonSourceSeedError {
    MissingPrefix,
    EmptySource,
    InvalidConfig { message: String },
}

impl EvalJsonSourceSeedError {
    fn invalid_config(error: anyhow::Error) -> Self {
        Self::InvalidConfig {
            message: error.to_string(),
        }
    }
}

impl std::fmt::Display for EvalJsonSourceSeedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPrefix => {
                formatter.write_str("must start with \"# aos-nix-fuzz-source\\n\"")
            }
            Self::EmptySource => {
                formatter.write_str("contains no source expression after metadata")
            }
            Self::InvalidConfig { message } => {
                write!(formatter, "has invalid metadata: {message}")
            }
        }
    }
}

fn eval_json_report(
    oracle: &dyn NixEval,
    candidate: &dyn NixEval,
    entry: &EvalJsonEntry,
    eval_config: &NixEvalConfig,
) -> EvalJsonReport {
    let oracle_result = eval_json_side(oracle, &entry.expr);
    let (candidate_result, candidate_stats) = eval_json_candidate_side(candidate, &entry.expr);
    let failure = eval_json_expression_failure(&oracle_result, &candidate_result);

    EvalJsonReport {
        name: entry.name.clone(),
        expr: entry.expr.clone(),
        eval_config: eval_config.clone(),
        oracle: oracle_result,
        candidate: candidate_result,
        candidate_stats,
        failure,
    }
}

fn eval_json_side(eval: &dyn NixEval, expr: &str) -> EvalJsonResult {
    match eval.eval_expr(expr) {
        Ok(value) => EvalJsonResult::Value(value),
        Err(error) => EvalJsonResult::Error(format!("{error:#}")),
    }
}

fn eval_json_candidate_side(
    eval: &dyn NixEval,
    expr: &str,
) -> (EvalJsonResult, Option<NixEvalStrictJsonStats>) {
    match eval.eval_expr_with_stats(expr) {
        Ok((value, stats)) => (EvalJsonResult::Value(value), stats),
        Err(error) => (EvalJsonResult::Error(format!("{error:#}")), None),
    }
}

fn eval_json_expression_failure(
    oracle: &EvalJsonResult,
    candidate: &EvalJsonResult,
) -> Option<NixDiffReportedFailure> {
    match (oracle, candidate) {
        (EvalJsonResult::Value(oracle), EvalJsonResult::Value(candidate))
            if oracle == candidate =>
        {
            None
        }
        (EvalJsonResult::Value(_), EvalJsonResult::Value(_)) => Some(
            NixDiffReportedFailure::attr_error("eval-json output diverged".to_string()),
        ),
        (EvalJsonResult::Error(error), EvalJsonResult::Value(_)) => Some(
            NixDiffReportedFailure::attr_error(format!("nix-cli eval-json failed: {error}")),
        ),
        (EvalJsonResult::Value(_), EvalJsonResult::Error(error)) => Some(
            NixDiffReportedFailure::attr_error(format!("candidate eval-json failed: {error}")),
        ),
        (EvalJsonResult::Error(oracle), EvalJsonResult::Error(candidate)) => {
            Some(NixDiffReportedFailure::attr_error(format!(
                "both evaluators failed: nix-cli={oracle}; candidate={candidate}"
            )))
        }
    }
}

fn eval_json_failure(reports: &[EvalJsonReport]) -> Option<NixDiffReportedFailure> {
    let failing_exprs = reports
        .iter()
        .filter(|report| report.failure.is_some())
        .count();
    if failing_exprs == 0 {
        return None;
    }

    let divergence_count = reports.iter().filter(|report| report.diverged()).count();
    Some(NixDiffReportedFailure::eval_json_failed(
        failing_exprs,
        divergence_count,
    ))
}

#[derive(Debug)]
struct AttrDiffReport {
    file: PathBuf,
    attr: String,
    report: Option<DrvDiffReport>,
    failure: Option<NixDiffReportedFailure>,
    oracle_stats: Option<NixInstantiateStats>,
}

#[derive(Debug, Clone)]
struct EvalJsonEntry {
    name: String,
    expr: String,
    eval_config: Option<NixEvalConfig>,
}

#[derive(Debug)]
struct EvalJsonReport {
    name: String,
    expr: String,
    eval_config: NixEvalConfig,
    oracle: EvalJsonResult,
    candidate: EvalJsonResult,
    candidate_stats: Option<NixEvalStrictJsonStats>,
    failure: Option<NixDiffReportedFailure>,
}

impl EvalJsonReport {
    fn diverged(&self) -> bool {
        matches!(
            (&self.oracle, &self.candidate),
            (EvalJsonResult::Value(oracle), EvalJsonResult::Value(candidate)) if oracle != candidate
        )
    }
}

#[derive(Debug)]
enum EvalJsonResult {
    Value(String),
    Error(String),
}

#[derive(Debug)]
struct CacheValidationAttrReport {
    file: PathBuf,
    attr: String,
    cold_cache_root: PathBuf,
    oracle_vs_cache_off: CacheValidationComparison,
    oracle_vs_cold_cache: CacheValidationComparison,
    cache_off_vs_cold_cache: CacheValidationComparison,
}

impl CacheValidationAttrReport {
    fn comparisons(&self) -> [&CacheValidationComparison; 3] {
        [
            &self.oracle_vs_cache_off,
            &self.oracle_vs_cold_cache,
            &self.cache_off_vs_cold_cache,
        ]
    }

    fn failure_count(&self) -> usize {
        self.comparisons()
            .iter()
            .filter(|comparison| comparison.failure.is_some())
            .count()
    }

    fn has_failure(&self) -> bool {
        self.failure_count() > 0
    }
}

#[derive(Debug)]
struct CacheValidationComparison {
    name: &'static str,
    oracle: &'static str,
    candidate: &'static str,
    report: Option<DrvDiffReport>,
    failure: Option<NixDiffReportedFailure>,
}

#[derive(Debug, Clone)]
enum CacheValidationInstantiation {
    Closure(DrvClosure),
    Path(PathBuf),
    Error(String),
}

struct CacheValidationFixedEval<'a> {
    name: &'static str,
    result: &'a CacheValidationInstantiation,
}

impl NixEval for CacheValidationFixedEval<'_> {
    fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
        match self.result {
            CacheValidationInstantiation::Closure(closure) => Ok(closure.root().to_path_buf()),
            CacheValidationInstantiation::Path(path) => Ok(path.clone()),
            CacheValidationInstantiation::Error(error) => Err(anyhow::anyhow!(error.clone())),
        }
    }

    fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
        self.instantiate(Path::new("expr"), "")
    }

    fn instantiate_closure(&self, _file: &Path, _attr: &str) -> Result<Option<DrvClosure>> {
        match self.result {
            CacheValidationInstantiation::Closure(closure) => Ok(Some(closure.clone())),
            CacheValidationInstantiation::Path(_) => Ok(None),
            CacheValidationInstantiation::Error(error) => Err(anyhow::anyhow!(error.clone())),
        }
    }

    fn eval_expr(&self, _expr: &str) -> Result<String> {
        Err(anyhow::anyhow!(
            "cache-validation fixed evaluator only supports derivation instantiation"
        ))
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

#[derive(Debug)]
struct CorpusSelection {
    entries: Vec<CorpusEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CorpusEntry {
    file: PathBuf,
    attr: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum FuzzSourceFileKind {
    Direct,
    GeneratedConformance,
}

/// Source seed rendered from a `nix-diff` corpus attribute.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct FuzzSourceSeed {
    /// Human-readable seed name, usually the attribute path.
    pub(crate) name: String,
    /// Literal Nix source for a `# aos-nix-fuzz-source` corpus file.
    pub(crate) source: String,
    pub(crate) source_file: PathBuf,
    pub(crate) source_file_kind: FuzzSourceFileKind,
    pub(crate) root_args: String,
}

impl FuzzSourceSeed {
    pub(crate) fn with_source_file(&self, source_file: PathBuf) -> Result<Self> {
        Ok(Self {
            name: self.name.clone(),
            source: render_fuzz_source_expr(&source_file, &self.name, &self.root_args)?,
            source_file,
            source_file_kind: self.source_file_kind,
            root_args: self.root_args.clone(),
        })
    }
}

/// Renders source seeds from the same corpus used by `aos nix-diff`.
///
/// The generated source imports `file` and selects each corpus attribute by
/// string path, so attributes containing dashes remain valid seeds.
///
/// # Errors
///
/// Returns an error if the corpus cannot be enumerated through the C++ Nix
/// oracle, a generated conformance corpus cannot be written, or the selected
/// Nix file path is not valid UTF-8.
pub(crate) fn fuzz_source_seeds(
    oracle: &NixCli,
    file: &Path,
    include_packages: bool,
    include_systems: bool,
    eval_config: &NixEvalConfig,
) -> Result<Vec<FuzzSourceSeed>> {
    corpus_entries(oracle, file, false, include_packages, include_systems)?
        .entries
        .iter()
        .map(|entry| render_fuzz_source_seed(entry, eval_config))
        .collect()
}

/// Renders source seeds for explicit attribute paths.
///
/// # Errors
///
/// Returns an error if an attribute path is empty, contains an empty segment, or
/// the selected Nix file path is not valid UTF-8.
pub(crate) fn fuzz_source_seeds_for_attrs(
    file: &Path,
    attrs: &[String],
    eval_config: &NixEvalConfig,
) -> Result<Vec<FuzzSourceSeed>> {
    attrs
        .iter()
        .map(|attr| {
            validate_fuzz_source_attr(attr)?;
            render_fuzz_source_seed_with_kind(
                &CorpusEntry {
                    file: file.to_path_buf(),
                    attr: attr.clone(),
                },
                eval_config,
                FuzzSourceFileKind::Direct,
            )
        })
        .collect()
}

fn validate_fuzz_source_attr(attr: &str) -> Result<()> {
    if attr.is_empty() || attr.split('.').any(str::is_empty) {
        return Err(AosError::InvalidArgument {
            message: format!("nix-fuzz-corpus attribute path must not be empty: {attr:?}"),
        }
        .into());
    }
    Ok(())
}

fn render_fuzz_source_seed(
    entry: &CorpusEntry,
    eval_config: &NixEvalConfig,
) -> Result<FuzzSourceSeed> {
    render_fuzz_source_seed_with_kind(entry, eval_config, fuzz_source_file_kind(entry))
}

fn render_fuzz_source_seed_with_kind(
    entry: &CorpusEntry,
    eval_config: &NixEvalConfig,
    source_file_kind: FuzzSourceFileKind,
) -> Result<FuzzSourceSeed> {
    let root_args = render_fuzz_root_args(eval_config);
    let source = render_fuzz_source_expr(&entry.file, &entry.attr, &root_args)?;
    Ok(FuzzSourceSeed {
        name: entry.attr.clone(),
        source,
        source_file: absolute_path_for_nix(&entry.file)?,
        source_file_kind,
        root_args,
    })
}

fn render_fuzz_source_expr(file: &Path, attr: &str, root_args: &str) -> Result<String> {
    let file = absolute_path_for_nix(file)?;
    let file = file
        .to_str()
        .with_context(|| format!("nix file path is not valid UTF-8: {}", file.display()))?;
    let attr_path = attr
        .split('.')
        .map(nix_string_literal)
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!(
        r#"let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {} else loaded;
  path = [ {} ];
in
  builtins.foldl' (value: name: builtins.getAttr name value) root path
"#,
        nix_string_literal(file),
        root_args,
        attr_path
    ))
}

fn render_fuzz_root_args(eval_config: &NixEvalConfig) -> String {
    let Some(current_system) = eval_config.current_system() else {
        return "{}".to_string();
    };
    format!("{{ system = {}; }}", nix_string_literal(current_system))
}

fn fuzz_source_file_kind(entry: &CorpusEntry) -> FuzzSourceFileKind {
    if entry
        .attr
        .starts_with(&format!("{CONFORMANCE_CORPUS_ATTRSET}."))
    {
        FuzzSourceFileKind::GeneratedConformance
    } else {
        FuzzSourceFileKind::Direct
    }
}

fn corpus_entries(
    oracle: &NixCli,
    file: &Path,
    include_smoke: bool,
    include_packages: bool,
    include_systems: bool,
) -> Result<CorpusSelection> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();

    if include_smoke {
        extend_unique_attrs(&mut entries, &mut seen, file, smoke_attrs());
    }
    if include_packages {
        extend_unique_attrs(&mut entries, &mut seen, file, package_attrs(oracle, file)?);
        extend_unique_attrs(
            &mut entries,
            &mut seen,
            file,
            toolchain_attrs(oracle, file)?,
        );
        if let Some(generated) = generated_conformance_corpus_from_env()? {
            extend_unique_entries(&mut entries, &mut seen, generated.entries);
        }
    }
    if include_systems {
        extend_unique_attrs(&mut entries, &mut seen, file, system_attrs(oracle, file)?);
    }

    Ok(CorpusSelection { entries })
}

fn smoke_attrs() -> Vec<String> {
    SMOKE_CORPUS_ATTRS
        .iter()
        .map(|attr| (*attr).to_owned())
        .collect()
}

fn extend_unique_attrs(
    entries: &mut Vec<CorpusEntry>,
    seen: &mut BTreeSet<(PathBuf, String)>,
    file: &Path,
    new_attrs: Vec<String>,
) {
    let new_entries = new_attrs
        .into_iter()
        .map(|attr| CorpusEntry {
            file: file.to_path_buf(),
            attr,
        })
        .collect();
    extend_unique_entries(entries, seen, new_entries);
}

fn extend_unique_entries(
    entries: &mut Vec<CorpusEntry>,
    seen: &mut BTreeSet<(PathBuf, String)>,
    new_entries: Vec<CorpusEntry>,
) {
    for entry in new_entries {
        if seen.insert((entry.file.clone(), entry.attr.clone())) {
            entries.push(entry);
        }
    }
}

#[derive(Debug)]
struct GeneratedConformanceCorpus {
    entries: Vec<CorpusEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct LangCase {
    name: String,
    source: PathBuf,
    expected: Option<PathBuf>,
    expected_xml: Option<PathBuf>,
    flags: Vec<String>,
    disabled: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum LangAutoArg {
    Expr { name: String, expr: String },
    Str { name: String, value: String },
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct LangCaseConfig {
    auto_args: Vec<LangAutoArg>,
    attr_path: Vec<String>,
}

fn generated_conformance_corpus_from_env() -> Result<Option<GeneratedConformanceCorpus>> {
    let Some(lang_dir) = env::var_os(AOS_NIX_LANG_TESTS_ENV) else {
        return Ok(None);
    };
    let lang_dir = PathBuf::from(lang_dir);
    generated_conformance_corpus(&lang_dir).map(Some)
}

fn generated_conformance_corpus(lang_dir: &Path) -> Result<GeneratedConformanceCorpus> {
    let cases = discover_eval_okay_lang_cases(lang_dir)?;
    let rendered_cases = cases
        .iter()
        .map(|case| render_conformance_case(case, lang_dir))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    if rendered_cases.is_empty() {
        return Err(AosError::InvalidArgument {
            message: format!(
                "{AOS_NIX_LANG_TESTS_ENV}={} did not contain any supported eval-okay conformance cases",
                lang_dir.display()
            ),
        }
        .into());
    }

    let dir = create_persistent_conformance_corpus_dir()?;
    let file = dir.join("corpus.nix");
    fs::write(&file, render_conformance_file(&rendered_cases))
        .with_context(|| format!("writing generated conformance corpus {}", file.display()))?;
    let entries = rendered_cases
        .into_iter()
        .map(|case| CorpusEntry {
            file: file.clone(),
            attr: format!("{CONFORMANCE_CORPUS_ATTRSET}.{}", case.attr),
        })
        .collect();

    Ok(GeneratedConformanceCorpus { entries })
}

fn create_persistent_conformance_corpus_dir() -> Result<PathBuf> {
    let tmp = env::temp_dir();
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    for attempt in 0..100_u32 {
        let dir = tmp.join(format!("aos-nix-diff-conformance-{pid}-{nanos}-{attempt}"));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", dir.display()));
            }
        }
    }
    Err(AosError::InvalidArgument {
        message: "failed to allocate a temporary nix-diff conformance corpus directory".to_string(),
    }
    .into())
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RenderedConformanceCase {
    attr: String,
    name: String,
    value_expr: String,
}

fn render_conformance_file(cases: &[RenderedConformanceCase]) -> String {
    let mut file = String::from(
        r#"{ system ? builtins.currentSystem }:
let
  mkCase = name: value:
    let
      json = builtins.tryEval (builtins.toJSON value);
      rendered =
        if json.success
        then json.value
        else builtins.seq value "__aos_nix_non_json__";
    in
      derivationStrict {
        inherit name system;
        builder = "#,
    );
    file.push_str(&nix_string_literal(CONFORMANCE_CORPUS_BUILDER));
    file.push_str(
        r#";
        args = [];
        evaluated = rendered;
      };
in
{
  conformance = {
"#,
    );
    for case in cases {
        file.push_str("    ");
        file.push_str(&case.attr);
        file.push_str(" = mkCase ");
        file.push_str(&nix_string_literal(&format!("aos-nix-lang-{}", case.name)));
        file.push_str(" (\n");
        push_indented(&mut file, &case.value_expr, "      ");
        file.push_str("\n    );\n");
    }
    file.push_str("  };\n}\n");
    file
}

fn push_indented(out: &mut String, text: &str, indent: &str) {
    for (index, line) in text.lines().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(indent);
        out.push_str(line);
    }
}

fn discover_eval_okay_lang_cases(lang_dir: &Path) -> Result<Vec<LangCase>> {
    let mut cases = Vec::new();
    for entry in fs::read_dir(lang_dir)
        .with_context(|| format!("reading lang corpus directory {}", lang_dir.display()))?
    {
        let entry = entry
            .with_context(|| format!("reading lang corpus entry in {}", lang_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("nix") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let stem = stem.to_owned();
        if !stem.starts_with("eval-okay-") {
            continue;
        }
        cases.push(LangCase {
            name: stem.clone(),
            source: path,
            expected: Some(lang_dir.join(format!("{stem}.exp"))),
            expected_xml: lang_dir
                .join(format!("{stem}.exp.xml"))
                .exists()
                .then(|| lang_dir.join(format!("{stem}.exp.xml"))),
            flags: read_lang_case_flags(lang_dir, &stem)?,
            disabled: lang_dir.join(format!("{stem}.exp-disabled")).exists(),
        });
    }
    cases.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(cases)
}

fn read_lang_case_flags(lang_dir: &Path, stem: &str) -> Result<Vec<String>> {
    let path = lang_dir.join(format!("{stem}.flags"));
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect())
}

fn render_conformance_case(
    case: &LangCase,
    lang_dir: &Path,
) -> Result<Option<RenderedConformanceCase>> {
    if !is_supported_conformance_case(case)? {
        return Ok(None);
    }
    let attr = conformance_case_attr(&case.name)?;
    let config = match parse_eval_okay_flags(&case.flags, lang_dir) {
        Ok(config) => config,
        Err(()) => return Ok(None),
    };
    let mut value_expr = render_case_import(&case.source)?;
    if !config.auto_args.is_empty() {
        value_expr = render_auto_arg_application(&value_expr, &config.auto_args)?;
    }
    if !config.attr_path.is_empty() {
        value_expr = format!("({value_expr})");
        for segment in &config.attr_path {
            value_expr.push('.');
            value_expr.push_str(segment);
        }
    }
    if case.expected_xml.is_some() {
        value_expr = format!("builtins.toXML ({value_expr})");
    }
    Ok(Some(RenderedConformanceCase {
        attr,
        name: case.name.clone(),
        value_expr,
    }))
}

fn is_supported_conformance_case(case: &LangCase) -> Result<bool> {
    if case.disabled
        || LANG_CASE_EXCLUSION_NAMES.contains(&case.name.as_str())
        || CONFORMANCE_WRAPPER_ONLY_EXCLUSION_NAMES.contains(&case.name.as_str())
    {
        return Ok(false);
    }
    if case_expected_mentions_repeated_value(case)? {
        return Ok(false);
    }
    Ok(true)
}

fn case_expected_mentions_repeated_value(case: &LangCase) -> Result<bool> {
    let Some(path) = case.expected.as_ref() else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(bytes
        .windows("repeated".len())
        .any(|window| window == b"repeated"))
}

fn conformance_case_attr(name: &str) -> Result<String> {
    if !name
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
    {
        return Err(AosError::InvalidArgument {
            message: format!("unsupported conformance case name for attr path: {name}"),
        }
        .into());
    }
    Ok(name.to_owned())
}

fn parse_eval_okay_flags(
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<LangCaseConfig, ()> {
    let mut auto_args = Vec::new();
    let mut attr_path = Vec::new();
    let mut index = 0;
    while let Some(flag) = flags.get(index) {
        match flag.as_str() {
            "--eval" | "--strict" => {}
            "--arg" => {
                index += 1;
                let Some(name) = flags.get(index) else {
                    return Err(());
                };
                index += 1;
                let Some(expr) = flags.get(index) else {
                    return Err(());
                };
                validate_lang_identifier(name)?;
                auto_args.push(LangAutoArg::Expr {
                    name: name.clone(),
                    expr: render_auto_arg_expr(expr, lang_dir)?,
                });
            }
            "--argstr" => {
                index += 1;
                let Some(name) = flags.get(index) else {
                    return Err(());
                };
                index += 1;
                let Some(value) = flags.get(index) else {
                    return Err(());
                };
                validate_lang_identifier(name)?;
                auto_args.push(LangAutoArg::Str {
                    name: name.clone(),
                    value: value.clone(),
                });
            }
            "-A" => {
                if !attr_path.is_empty() {
                    return Err(());
                }
                index += 1;
                let Some(attr) = flags.get(index) else {
                    return Err(());
                };
                attr_path = parse_lang_attr_path(attr)?;
            }
            _ => return Err(()),
        }
        index += 1;
    }
    Ok(LangCaseConfig {
        auto_args,
        attr_path,
    })
}

fn render_auto_arg_application(source_expr: &str, auto_args: &[LangAutoArg]) -> Result<String> {
    let mut rendered = String::new();
    rendered.push_str("((");
    rendered.push_str(source_expr);
    rendered.push_str(") { ");
    for auto_arg in auto_args {
        match auto_arg {
            LangAutoArg::Expr { name, expr } => {
                rendered.push_str(name);
                rendered.push_str(" = ");
                rendered.push_str(expr);
                rendered.push_str("; ");
            }
            LangAutoArg::Str { name, value } => {
                rendered.push_str(name);
                rendered.push_str(" = ");
                rendered.push_str(&nix_string_literal(value));
                rendered.push_str("; ");
            }
        }
    }
    rendered.push_str("})");
    Ok(rendered)
}

fn render_auto_arg_expr(expr: &str, lang_dir: &Path) -> std::result::Result<String, ()> {
    let Some(path) = expr
        .strip_prefix("import(")
        .and_then(|expr| expr.strip_suffix(')'))
    else {
        return Err(());
    };
    if path.contains("${") {
        return Err(());
    }
    let path = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        lang_dir.parent().ok_or(())?.join(path)
    };
    render_case_import(&path).map_err(|_| ())
}

fn render_case_import(path: &Path) -> Result<String> {
    let path = absolute_path_for_nix(path)?;
    let path = path
        .to_str()
        .with_context(|| format!("nix file path is not valid UTF-8: {}", path.display()))?;
    Ok(format!(
        "import (builtins.toPath {})",
        nix_string_literal(path)
    ))
}

fn parse_lang_attr_path(attr: &str) -> std::result::Result<Vec<String>, ()> {
    attr.split('.')
        .map(|segment| {
            validate_lang_identifier(segment)?;
            Ok(segment.to_owned())
        })
        .collect()
}

fn validate_lang_identifier(value: &str) -> std::result::Result<(), ()> {
    let Some((first, rest)) = value.as_bytes().split_first() else {
        return Err(());
    };
    if !matches!(first, b'_' | b'a'..=b'z' | b'A'..=b'Z')
        || !rest
            .iter()
            .all(|byte| matches!(byte, b'_' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'))
    {
        return Err(());
    }
    Ok(())
}

fn package_attrs(oracle: &NixCli, file: &Path) -> Result<Vec<String>> {
    let expr = package_attr_expr(file)?;
    let raw = oracle.eval_expr(&expr)?;
    let names: Vec<String> =
        serde_json::from_str(&raw).context("parsing nix-diff package attribute list")?;

    Ok(names
        .into_iter()
        .map(|name| format!("pkgs.{name}"))
        .collect())
}

fn toolchain_attrs(oracle: &NixCli, file: &Path) -> Result<Vec<String>> {
    let expr = toolchain_attr_expr(file)?;
    let raw = oracle.eval_expr(&expr)?;
    serde_json::from_str(&raw).context("parsing nix-diff explicit toolchain attribute list")
}

fn system_attrs(oracle: &NixCli, file: &Path) -> Result<Vec<String>> {
    let expr = system_attr_expr(file)?;
    let raw = oracle.eval_expr(&expr)?;
    serde_json::from_str(&raw).context("parsing nix-diff system attribute list")
}

fn package_attr_expr(file: &Path) -> Result<String> {
    let file = absolute_path_for_nix(file)?;
    let file = file
        .to_str()
        .with_context(|| format!("nix file path is not valid UTF-8: {}", file.display()))?;
    Ok(format!(
        r#"
let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {{}} else loaded;
  pkgs =
    if builtins.isAttrs root && (root ? pkgs)
    then root.pkgs
    else throw "nix-diff --all requires the imported file to expose pkgs";
  isDerivation = value:
    builtins.isAttrs value && (value ? type) && value.type == "derivation";
  shouldCheck = name:
    let probe = builtins.tryEval (isDerivation (builtins.getAttr name pkgs));
    in if probe.success then probe.value else true;
in
  builtins.filter shouldCheck (builtins.attrNames pkgs)
"#,
        nix_string_literal(file)
    ))
}

fn toolchain_attr_expr(file: &Path) -> Result<String> {
    let file = absolute_path_for_nix(file)?;
    let file = file
        .to_str()
        .with_context(|| format!("nix file path is not valid UTF-8: {}", file.display()))?;
    let wanted = EXPLICIT_TOOLCHAIN_CORPUS_ATTRS
        .iter()
        .map(|attr| {
            let path = attr
                .split('.')
                .map(nix_string_literal)
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "{{ attr = {}; path = [ {path} ]; }}",
                nix_string_literal(attr)
            )
        })
        .collect::<Vec<_>>()
        .join("\n    ");
    let tier_components = GCC_TOOLCHAIN_TIER_COMPONENTS
        .iter()
        .map(|component| nix_string_literal(component))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(format!(
        r#"
let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {{}} else loaded;
  missing = {{ __aosNixDiffMissing = true; }};
  explicit = [
    {}
  ];
  gccTierComponentNames = [ {} ];
  gccTierItems =
    if builtins.isAttrs root
      && builtins.hasAttr "stdenv" root
      && builtins.isAttrs root.stdenv
      && builtins.hasAttr "toolchainTiers" root.stdenv
    then
      let
        tiers = root.stdenv.toolchainTiers;
        tierNames = builtins.attrNames tiers;
        tierItems = tierName:
          builtins.map (
            componentName: {{
              attr = "stdenv.toolchainTiers.${{tierName}}.${{componentName}}";
              path = [ "stdenv" "toolchainTiers" tierName componentName ];
            }}
          ) gccTierComponentNames;
      in
        builtins.concatLists (builtins.map tierItems tierNames)
    else [];
  wanted = explicit ++ gccTierItems;
  isDerivation = value:
    builtins.isAttrs value && (value ? type) && value.type == "derivation";
  getPath = path:
    builtins.foldl' (
      value: name:
        if builtins.isAttrs value && builtins.hasAttr name value
        then builtins.getAttr name value
        else missing
    ) root path;
  shouldCheck = item:
    let probe = builtins.tryEval (isDerivation (getPath item.path));
    in if probe.success then probe.value else false;
in
  builtins.map (item: item.attr) (builtins.filter shouldCheck wanted)
"#,
        nix_string_literal(file),
        wanted,
        tier_components
    ))
}

fn system_attr_expr(file: &Path) -> Result<String> {
    let file = absolute_path_for_nix(file)?;
    let file = file
        .to_str()
        .with_context(|| format!("nix file path is not valid UTF-8: {}", file.display()))?;
    Ok(format!(
        r#"
let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {{}} else loaded;
  systems =
    if builtins.isAttrs root && (root ? systems)
    then root.systems
    else throw "nix-diff --systems requires the imported file to expose systems";
in
  builtins.map (name: "systems.${{name}}.build.toplevel") (builtins.attrNames systems)
"#,
        nix_string_literal(file)
    ))
}

fn absolute_path_for_nix(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()
        .context("resolving current directory for nix-diff --all")?
        .join(path))
}

fn nix_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if chars.peek() == Some(&'{') => out.push_str("\\$"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn corpus_failure(reports: &[AttrDiffReport]) -> Option<NixDiffReportedFailure> {
    let failing_attrs = reports
        .iter()
        .filter(|report| report.failure.is_some())
        .count();
    if failing_attrs == 0 {
        return None;
    }

    let divergence_count = reports
        .iter()
        .filter_map(|report| report.report.as_ref())
        .map(|report| report.divergences.len())
        .sum();
    Some(NixDiffReportedFailure::corpus_failed(
        failing_attrs,
        divergence_count,
    ))
}

fn cache_validation_cache_off_config(eval_config: &NixEvalConfig) -> NixEvalConfig {
    let mut config = eval_config.clone();
    config.clear_native_cache_root();
    config
}

fn cache_validation_cold_cache_config(
    eval_config: &NixEvalConfig,
    cold_cache_root: &Path,
) -> Result<NixEvalConfig> {
    let mut config = eval_config.clone();
    config.set_native_cache_root(cold_cache_root)?;
    Ok(config)
}

fn validate_cache_validation_mode(mode: DiffMode) -> Result<()> {
    if mode == DiffMode::Path {
        return Err(AosError::InvalidArgument {
            message: "nix-diff --cache-validation requires --mode=byte or --mode=structural"
                .to_string(),
        }
        .into());
    }
    Ok(())
}

fn validate_eval_json_selection(
    eval_json: bool,
    attr: Option<&str>,
    smoke: bool,
    all: bool,
    systems: bool,
    mode: DiffMode,
    oracle_stats: bool,
    cache_validation: bool,
) -> Result<()> {
    if !eval_json {
        return Ok(());
    }

    if attr.is_some() || smoke || all || systems || oracle_stats || cache_validation {
        return Err(AosError::InvalidArgument {
            message: "nix-diff --eval-json cannot be combined with derivation diff selection"
                .to_string(),
        }
        .into());
    }

    if mode != DiffMode::Byte {
        return Err(AosError::InvalidArgument {
            message: "nix-diff --eval-json does not accept --mode".to_string(),
        }
        .into());
    }

    Ok(())
}

fn ensure_nix_instantiate_after_cache_validation_mode_check<F>(
    cache_validation: bool,
    mode: DiffMode,
    ensure: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if cache_validation {
        validate_cache_validation_mode(mode)?;
    }
    ensure()
}

fn cache_validation_attr_report(
    oracle: &dyn NixEval,
    cache_off: &dyn NixEval,
    cold_cache: &dyn NixEval,
    cold_cache_root: PathBuf,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> CacheValidationAttrReport {
    let oracle_result = instantiate_cache_validation_side(oracle, file, attr, mode);
    let cache_off_result = instantiate_cache_validation_side(cache_off, file, attr, mode);
    let cold_cache_result = instantiate_cache_validation_side(cold_cache, file, attr, mode);

    CacheValidationAttrReport {
        file: file.to_path_buf(),
        attr: attr.to_string(),
        cold_cache_root,
        oracle_vs_cache_off: cache_validation_comparison(
            "oracle_vs_cache_off",
            "nix-cli",
            "aos-nix-cache-off",
            &oracle_result,
            &cache_off_result,
            file,
            attr,
            mode,
        ),
        oracle_vs_cold_cache: cache_validation_comparison(
            "oracle_vs_cold_cache",
            "nix-cli",
            "aos-nix-cold-cache",
            &oracle_result,
            &cold_cache_result,
            file,
            attr,
            mode,
        ),
        cache_off_vs_cold_cache: cache_validation_comparison(
            "cache_off_vs_cold_cache",
            "aos-nix-cache-off",
            "aos-nix-cold-cache",
            &cache_off_result,
            &cold_cache_result,
            file,
            attr,
            mode,
        ),
    }
}

fn instantiate_cache_validation_side(
    eval: &dyn NixEval,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> CacheValidationInstantiation {
    match mode {
        DiffMode::Path => match eval.instantiate(file, attr) {
            Ok(path) => CacheValidationInstantiation::Path(path),
            Err(error) => CacheValidationInstantiation::Error(format!("{error:#}")),
        },
        DiffMode::Byte | DiffMode::Structural => match eval.instantiate_closure(file, attr) {
            Ok(Some(closure)) => CacheValidationInstantiation::Closure(closure),
            Ok(None) => CacheValidationInstantiation::Error(format!(
                "{} did not provide full .drv closure output for {} cache validation",
                eval.name(),
                mode_name(mode)
            )),
            Err(error) => CacheValidationInstantiation::Error(format!("{error:#}")),
        },
    }
}

fn cache_validation_comparison(
    name: &'static str,
    oracle_label: &'static str,
    candidate_label: &'static str,
    oracle_result: &CacheValidationInstantiation,
    candidate_result: &CacheValidationInstantiation,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> CacheValidationComparison {
    let oracle = CacheValidationFixedEval {
        name: oracle_label,
        result: oracle_result,
    };
    let candidate = CacheValidationFixedEval {
        name: candidate_label,
        result: candidate_result,
    };
    match diff_closure(&oracle, &candidate, file, attr, mode)
        .with_context(|| format!("cache-validating {name} for {attr}"))
    {
        Ok(report) => {
            let failure = report_failure(&report);
            CacheValidationComparison {
                name,
                oracle: oracle_label,
                candidate: candidate_label,
                report: Some(report),
                failure,
            }
        }
        Err(error) => CacheValidationComparison {
            name,
            oracle: oracle_label,
            candidate: candidate_label,
            report: None,
            failure: Some(NixDiffReportedFailure::attr_error(format!("{error:#}"))),
        },
    }
}

fn cache_validation_failure(
    reports: &[CacheValidationAttrReport],
) -> Option<NixDiffReportedFailure> {
    let failing_attrs = reports.iter().filter(|report| report.has_failure()).count();
    if failing_attrs == 0 {
        return None;
    }

    let divergence_count = reports
        .iter()
        .flat_map(CacheValidationAttrReport::comparisons)
        .filter_map(|comparison| comparison.report.as_ref())
        .map(|report| report.divergences.len())
        .sum();
    Some(NixDiffReportedFailure::corpus_failed(
        failing_attrs,
        divergence_count,
    ))
}

fn create_cold_cache_validation_root() -> Result<PathBuf> {
    let tmp = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..100_u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time is before UNIX_EPOCH")?
            .as_nanos();
        let root = tmp.join(format!("aos-nix-diff-cold-cache-{pid}-{nanos}-{attempt}"));
        match fs::create_dir(&root) {
            Ok(()) => return Ok(root),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating cold cache root {}", root.display()));
            }
        }
    }
    anyhow::bail!("creating unique cold cache root in {}", tmp.display())
}

fn cleanup_successful_cache_validation_roots(reports: &[CacheValidationAttrReport]) {
    for report in reports.iter().filter(|report| !report.has_failure()) {
        let _ = fs::remove_dir_all(&report.cold_cache_root);
    }
}

fn report_failure(report: &DrvDiffReport) -> Option<NixDiffReportedFailure> {
    if !report.divergences.is_empty() {
        return Some(NixDiffReportedFailure::diverged(report.divergences.len()));
    }

    if report.oracle_root.is_some() && report.candidate_root.is_some() {
        return None;
    }

    if report.oracle_root.is_none() && report.candidate_root.is_none() {
        return Some(NixDiffReportedFailure::no_drv_output());
    }

    Some(NixDiffReportedFailure::incomplete_drv_output())
}

fn report_json(
    report: &DrvDiffReport,
    candidate_name: &str,
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    failure: Option<&NixDiffReportedFailure>,
    oracle_stats: Option<&NixInstantiateStats>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "mode": mode_name(report.mode),
        "oracle": "nix-cli",
        "candidate": candidate_name,
        "file": file.to_string_lossy(),
        "attr": attr,
        "reproduce": reproduction_command(eval_config, file, attr, report.mode),
        "matched": failure.is_none(),
        "error": failure.map(ToString::to_string),
        "oracle_root": report.oracle_root.as_ref().map(|path| path.to_string_lossy().to_string()),
        "candidate_root": report.candidate_root.as_ref().map(|path| path.to_string_lossy().to_string()),
        "root_divergences": report.root_divergences.iter().map(pair_json).collect::<Vec<_>>(),
        "contaminated_divergences": report.contaminated_divergences.iter().map(pair_json).collect::<Vec<_>>(),
        "root_reports": root_reports_json(report, eval_config, file, attr),
        "divergences": report.divergences.iter().map(diff_json).collect::<Vec<_>>(),
    });
    insert_oracle_stats(&mut value, oracle_stats);
    value
}

fn drv_pair_report_json(
    report: &DrvDiffReport,
    oracle_drv: &Path,
    candidate_drv: &Path,
    oracle_bundle: Option<&Path>,
    candidate_bundle: Option<&Path>,
    failure: Option<&NixDiffReportedFailure>,
) -> serde_json::Value {
    serde_json::json!({
        "mode": mode_name(report.mode),
        "oracle": "oracle-drv",
        "candidate": "candidate-drv",
        "oracle_drv": oracle_drv.to_string_lossy(),
        "candidate_drv": candidate_drv.to_string_lossy(),
        "oracle_drv_bundle": oracle_bundle.map(|path| path.to_string_lossy().to_string()),
        "candidate_drv_bundle": candidate_bundle.map(|path| path.to_string_lossy().to_string()),
        "reproduce": node_reproduction_command(
            oracle_drv,
            candidate_drv,
            oracle_bundle,
            candidate_bundle,
            report.mode
        ),
        "matched": failure.is_none(),
        "error": failure.map(ToString::to_string),
        "oracle_root": report.oracle_root.as_ref().map(|path| path.to_string_lossy().to_string()),
        "candidate_root": report.candidate_root.as_ref().map(|path| path.to_string_lossy().to_string()),
        "root_divergences": report.root_divergences.iter().map(pair_json).collect::<Vec<_>>(),
        "contaminated_divergences": report.contaminated_divergences.iter().map(pair_json).collect::<Vec<_>>(),
        "root_reports": root_pair_reports_json(report),
        "divergences": report.divergences.iter().map(diff_json).collect::<Vec<_>>(),
    })
}

fn corpus_json(
    reports: &[AttrDiffReport],
    candidate_name: &str,
    eval_config: &NixEvalConfig,
    file: &Path,
    mode: DiffMode,
    failure: Option<&NixDiffReportedFailure>,
) -> serde_json::Value {
    let failed_attrs = reports
        .iter()
        .filter(|report| report.failure.is_some())
        .count();
    let divergence_count: usize = reports
        .iter()
        .filter_map(|report| report.report.as_ref())
        .map(|report| report.divergences.len())
        .sum();

    let mut value = serde_json::json!({
        "mode": mode_name(mode),
        "oracle": "nix-cli",
        "candidate": candidate_name,
        "file": file.to_string_lossy(),
        "matched": failure.is_none(),
        "error": failure.map(ToString::to_string),
        "attrs_checked": reports.len(),
        "attrs_failed": failed_attrs,
        "divergence_count": divergence_count,
        "reports": reports.iter().map(|report| attr_report_json(report, candidate_name, eval_config, mode)).collect::<Vec<_>>(),
    });
    if let (serde_json::Value::Object(object), Some(summary)) =
        (&mut value, corpus_oracle_stats_aggregate(reports))
    {
        object.insert("oracle_stats_summary".to_string(), summary.json());
    }
    value
}

fn eval_json_report_json(
    reports: &[EvalJsonReport],
    skipped: usize,
    time_budget: Option<Duration>,
    candidate_name: &str,
    failure: Option<&NixDiffReportedFailure>,
) -> serde_json::Value {
    let failed_exprs = reports
        .iter()
        .filter(|report| report.failure.is_some())
        .count();
    let divergence_count = reports.iter().filter(|report| report.diverged()).count();

    serde_json::json!({
        "eval_json": true,
        "oracle": "nix-cli",
        "candidate": candidate_name,
        "matched": failure.is_none(),
        "error": failure.map(ToString::to_string),
        "expressions_checked": reports.len(),
        "expressions_skipped": skipped,
        "time_budget_seconds": time_budget.map(|budget| budget.as_secs()),
        "expressions_failed": failed_exprs,
        "divergence_count": divergence_count,
        "reports": reports.iter()
            .map(|report| eval_json_entry_json(report, candidate_name))
            .collect::<Vec<_>>(),
    })
}

fn eval_json_entry_json(report: &EvalJsonReport, candidate_name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": report.name,
        "expr": report.expr,
        "reproduce": eval_json_reproduction_command(&report.eval_config, &report.expr),
        "oracle": "nix-cli",
        "candidate": candidate_name,
        "matched": report.failure.is_none(),
        "error": report.failure.as_ref().map(ToString::to_string),
        "oracle_value": eval_json_value(&report.oracle),
        "candidate_value": eval_json_value(&report.candidate),
        "oracle_error": eval_json_error(&report.oracle),
        "candidate_error": eval_json_error(&report.candidate),
        "candidate_stats": report.candidate_stats.as_ref().map(eval_json_stats_json),
    })
}

fn eval_json_stats_json(stats: &NixEvalStrictJsonStats) -> serde_json::Value {
    serde_json::json!({
        "thunks_forced": stats.thunks_forced(),
        "thunks_allocated": stats.thunks_allocated(),
        "gc_bytes": stats.gc_bytes(),
        "gc_pause_us": stats.gc_pause_us(),
        "tier_promotions": stats.tier_promotions(),
        "deopts": stats.deopts(),
        "heap_chunks": stats.heap_chunks(),
        "heap_reserved_bytes": stats.heap_reserved_bytes(),
        "heap_mapped_bytes": stats.heap_mapped_bytes(),
        "heap_used_bytes": stats.heap_used_bytes(),
        "permanent_heap_chunks": stats.permanent_heap_chunks(),
        "permanent_heap_reserved_bytes": stats.permanent_heap_reserved_bytes(),
        "permanent_heap_mapped_bytes": stats.permanent_heap_mapped_bytes(),
        "permanent_heap_used_bytes": stats.permanent_heap_used_bytes(),
        "heap_tier_b_admission_worker_records": stats.heap_tier_b_admission_worker_records(),
        "heap_tier_b_admission_permanent_shared_records": stats
            .heap_tier_b_admission_permanent_shared_records(),
        "heap_tier_b_admission_generation_rewrites": stats
            .heap_tier_b_admission_generation_rewrites(),
    })
}

fn eval_json_value(result: &EvalJsonResult) -> Option<&str> {
    match result {
        EvalJsonResult::Value(value) => Some(value),
        EvalJsonResult::Error(_) => None,
    }
}

fn eval_json_error(result: &EvalJsonResult) -> Option<&str> {
    match result {
        EvalJsonResult::Value(_) => None,
        EvalJsonResult::Error(error) => Some(error),
    }
}

fn attr_report_json(
    report: &AttrDiffReport,
    candidate_name: &str,
    eval_config: &NixEvalConfig,
    mode: DiffMode,
) -> serde_json::Value {
    let Some(diff_report) = &report.report else {
        let mut value = serde_json::json!({
            "attr": report.attr,
            "mode": mode_name(mode),
            "oracle": "nix-cli",
            "candidate": candidate_name,
            "file": report.file.to_string_lossy(),
            "reproduce": reproduction_command(eval_config, &report.file, &report.attr, mode),
            "matched": false,
            "error": report.failure.as_ref().map(ToString::to_string),
            "oracle_root": null,
            "candidate_root": null,
            "root_divergences": [],
            "contaminated_divergences": [],
            "root_reports": [],
            "divergences": [],
        });
        insert_oracle_stats(&mut value, report.oracle_stats.as_ref());
        return value;
    };

    let mut value = report_json(
        diff_report,
        candidate_name,
        eval_config,
        &report.file,
        &report.attr,
        report.failure.as_ref(),
        report.oracle_stats.as_ref(),
    );
    if let serde_json::Value::Object(object) = &mut value {
        object.insert(
            "attr".to_string(),
            serde_json::Value::String(report.attr.clone()),
        );
        object.insert(
            "reproduce".to_string(),
            serde_json::Value::String(reproduction_command(
                eval_config,
                &report.file,
                &report.attr,
                mode,
            )),
        );
    }
    value
}

fn cache_validation_json(
    reports: &[CacheValidationAttrReport],
    eval_config: &NixEvalConfig,
    file: &Path,
    mode: DiffMode,
    failure: Option<&NixDiffReportedFailure>,
) -> serde_json::Value {
    let failed_attrs = reports.iter().filter(|report| report.has_failure()).count();
    let comparison_failures: usize = reports
        .iter()
        .map(CacheValidationAttrReport::failure_count)
        .sum();
    let divergence_count: usize = reports
        .iter()
        .flat_map(CacheValidationAttrReport::comparisons)
        .filter_map(|comparison| comparison.report.as_ref())
        .map(|report| report.divergences.len())
        .sum();

    serde_json::json!({
        "mode": mode_name(mode),
        "cache_validation": true,
        "file": file.to_string_lossy(),
        "matched": failure.is_none(),
        "error": failure.map(ToString::to_string),
        "attrs_checked": reports.len(),
        "attrs_failed": failed_attrs,
        "comparison_failures": comparison_failures,
        "divergence_count": divergence_count,
        "reports": reports.iter()
            .map(|report| cache_validation_attr_json(report, eval_config, mode))
            .collect::<Vec<_>>(),
    })
}

fn cache_validation_attr_json(
    report: &CacheValidationAttrReport,
    eval_config: &NixEvalConfig,
    mode: DiffMode,
) -> serde_json::Value {
    serde_json::json!({
        "attr": report.attr,
        "file": report.file.to_string_lossy(),
        "cold_cache_root": report.cold_cache_root.to_string_lossy(),
        "cold_cache_root_retained": report.has_failure(),
        "matched": !report.has_failure(),
        "comparison_failures": report.failure_count(),
        "reproduce": cache_validation_reproduction_command(
            eval_config,
            &report.file,
            &report.attr,
            mode,
        ),
        "comparisons": report.comparisons()
            .iter()
            .map(|comparison| cache_validation_comparison_json(comparison))
            .collect::<Vec<_>>(),
    })
}

fn cache_validation_comparison_json(comparison: &CacheValidationComparison) -> serde_json::Value {
    serde_json::json!({
        "name": comparison.name,
        "oracle": comparison.oracle,
        "candidate": comparison.candidate,
        "matched": comparison.failure.is_none(),
        "error": comparison.failure.as_ref().map(ToString::to_string),
        "oracle_root": comparison.report.as_ref()
            .and_then(|report| report.oracle_root.as_ref())
            .map(|path| path.to_string_lossy().to_string()),
        "candidate_root": comparison.report.as_ref()
            .and_then(|report| report.candidate_root.as_ref())
            .map(|path| path.to_string_lossy().to_string()),
        "divergences": comparison.report.as_ref()
            .map(|report| report.divergences.iter().map(diff_json).collect::<Vec<_>>())
            .unwrap_or_default(),
    })
}

fn insert_oracle_stats(value: &mut serde_json::Value, stats: Option<&NixInstantiateStats>) {
    let Some(stats) = stats else {
        return;
    };
    if let serde_json::Value::Object(object) = value {
        object.insert("oracle_stats".to_string(), oracle_stats_json(stats));
    }
}

fn oracle_stats_json(stats: &NixInstantiateStats) -> serde_json::Value {
    serde_json::json!({
        "drv_path": stats.drv_path.to_string_lossy(),
        "elapsed": {
            "seconds": stats.elapsed.as_secs_f64(),
            "nanos": duration_nanos(stats.elapsed),
        },
        "raw": stats.stats,
    })
}

fn duration_nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn duration_nanos_div(duration: std::time::Duration, divisor: usize) -> u64 {
    let nanos = duration.as_nanos() / divisor as u128;
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn pair_json(pair: &DrvDiffPair) -> serde_json::Value {
    serde_json::json!({
        "oracle": pair.oracle.to_string_lossy(),
        "candidate": pair.candidate.to_string_lossy(),
    })
}

fn root_reports_json(
    report: &DrvDiffReport,
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
) -> Vec<serde_json::Value> {
    report
        .root_divergences
        .iter()
        .map(|pair| root_report_json(report, eval_config, file, attr, pair))
        .collect()
}

fn root_pair_reports_json(report: &DrvDiffReport) -> Vec<serde_json::Value> {
    report
        .root_divergences
        .iter()
        .map(|pair| root_pair_report_json(report, pair))
        .collect()
}

fn root_report_json(
    report: &DrvDiffReport,
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    pair: &DrvDiffPair,
) -> serde_json::Value {
    let mut value = root_pair_report_json(report, pair);
    if let serde_json::Value::Object(object) = &mut value {
        object.insert(
            "file".to_string(),
            file.to_string_lossy().into_owned().into(),
        );
        object.insert("attr".to_string(), attr.to_string().into());
        object.insert(
            "reproduce".to_string(),
            reproduction_command(eval_config, file, attr, report.mode).into(),
        );
    }
    value
}

fn root_pair_report_json(report: &DrvDiffReport, pair: &DrvDiffPair) -> serde_json::Value {
    let mut value = serde_json::json!({
        "mode": mode_name(report.mode),
        "oracle": pair.oracle.to_string_lossy(),
        "candidate": pair.candidate.to_string_lossy(),
        "divergences": pair_divergences(report, pair).map(diff_json).collect::<Vec<_>>(),
    });
    if let (serde_json::Value::Object(object), Some(command)) =
        (&mut value, node_reproduction_for_pair(report, pair))
    {
        object.insert("node_reproduce".to_string(), command.into());
    }
    value
}

fn pair_divergences<'a>(
    report: &'a DrvDiffReport,
    pair: &'a DrvDiffPair,
) -> impl Iterator<Item = &'a DrvDiff> {
    report
        .divergences
        .iter()
        .filter(move |diff| diff_matches_pair(diff, pair))
}

fn diff_matches_pair(diff: &DrvDiff, pair: &DrvDiffPair) -> bool {
    match diff {
        DrvDiff::RootPath { oracle, candidate }
        | DrvDiff::Bytes { oracle, candidate }
        | DrvDiff::Structural {
            oracle, candidate, ..
        }
        | DrvDiff::InputCount {
            oracle, candidate, ..
        } => oracle == &pair.oracle && candidate == &pair.candidate,
        DrvDiff::InputOutputs {
            parent_oracle,
            parent_candidate,
            ..
        } => parent_oracle == &pair.oracle && parent_candidate == &pair.candidate,
        DrvDiff::StructuralParse { path, .. } => path == &pair.oracle || path == &pair.candidate,
        DrvDiff::Evaluation { .. } | DrvDiff::EvaluationMismatch { .. } => false,
    }
}

fn diff_json(diff: &DrvDiff) -> serde_json::Value {
    match diff {
        DrvDiff::RootPath { oracle, candidate } => serde_json::json!({
            "kind": "root_path",
            "oracle": oracle.to_string_lossy(),
            "candidate": candidate.to_string_lossy(),
        }),
        DrvDiff::Evaluation { side, error } => serde_json::json!({
            "kind": "evaluation",
            "side": side_name(*side),
            "error": error,
        }),
        DrvDiff::EvaluationMismatch {
            oracle_error,
            candidate_error,
        } => serde_json::json!({
            "kind": "evaluation_mismatch",
            "oracle_error": oracle_error,
            "candidate_error": candidate_error,
        }),
        DrvDiff::Bytes { oracle, candidate } => serde_json::json!({
            "kind": "bytes",
            "oracle": oracle.to_string_lossy(),
            "candidate": candidate.to_string_lossy(),
        }),
        DrvDiff::Structural {
            oracle,
            candidate,
            field,
        } => serde_json::json!({
            "kind": "structural",
            "oracle": oracle.to_string_lossy(),
            "candidate": candidate.to_string_lossy(),
            "field": field,
        }),
        DrvDiff::StructuralParse { side, path, error } => serde_json::json!({
            "kind": "structural_parse",
            "side": side_name(*side),
            "path": path.to_string_lossy(),
            "error": error,
        }),
        DrvDiff::InputCount {
            oracle,
            candidate,
            oracle_count,
            candidate_count,
        } => serde_json::json!({
            "kind": "input_count",
            "oracle": oracle.to_string_lossy(),
            "candidate": candidate.to_string_lossy(),
            "oracle_count": oracle_count,
            "candidate_count": candidate_count,
        }),
        DrvDiff::InputOutputs {
            parent_oracle,
            parent_candidate,
            oracle,
            candidate,
            oracle_outputs,
            candidate_outputs,
        } => serde_json::json!({
            "kind": "input_outputs",
            "parent_oracle": parent_oracle.to_string_lossy(),
            "parent_candidate": parent_candidate.to_string_lossy(),
            "oracle": oracle.to_string_lossy(),
            "candidate": candidate.to_string_lossy(),
            "oracle_outputs": oracle_outputs,
            "candidate_outputs": candidate_outputs,
        }),
    }
}

fn render_eval_divergence_classes(
    printer: &Printer,
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    report: &DrvDiffReport,
    indent: &str,
) {
    let reproduction = reproduction_command(eval_config, file, attr, report.mode);
    render_divergence_classes(printer, report, indent, Some(&reproduction));
}

fn render_pair_divergence_classes(printer: &Printer, report: &DrvDiffReport, indent: &str) {
    render_divergence_classes(printer, report, indent, None);
}

fn render_divergence_classes(
    printer: &Printer,
    report: &DrvDiffReport,
    indent: &str,
    eval_reproduction: Option<&str>,
) {
    if !report.root_divergences.is_empty() {
        printer.plain(&format!("{indent}root divergence reports:"));
        for pair in &report.root_divergences {
            printer.plain(&format!(
                "{indent}  - oracle={} candidate={}",
                pair.oracle.display(),
                pair.candidate.display()
            ));
            if let Some(command) = eval_reproduction {
                printer.plain(&format!("{indent}    reproduce: {command}"));
            }
            if let Some(command) = node_reproduction_for_pair(report, pair) {
                printer.plain(&format!("{indent}    node reproduce: {command}"));
            }
            let mut rendered = false;
            for divergence in pair_divergences(report, pair) {
                rendered = true;
                printer.plain(&format!("{indent}    - {}", render_diff(divergence)));
            }
            if !rendered {
                printer.plain(&format!(
                    "{indent}    - no pair-local byte or structural detail recorded"
                ));
            }
        }
    }
    if !report.contaminated_divergences.is_empty() {
        printer.plain(&format!("{indent}contaminated divergence nodes:"));
        for pair in &report.contaminated_divergences {
            printer.plain(&format!(
                "{indent}  - oracle={} candidate={}",
                pair.oracle.display(),
                pair.candidate.display()
            ));
        }
    }
}

fn render_reproduction_hint(
    printer: &Printer,
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    mode: DiffMode,
    indent: &str,
) {
    printer.plain(&format!(
        "{indent}reproduce: {}",
        reproduction_command(eval_config, file, attr, mode)
    ));
}

fn render_node_reproduction_hint(
    printer: &Printer,
    oracle_drv: &Path,
    candidate_drv: &Path,
    oracle_bundle: Option<&Path>,
    candidate_bundle: Option<&Path>,
    mode: DiffMode,
    indent: &str,
) {
    printer.plain(&format!(
        "{indent}node reproduce: {}",
        node_reproduction_command(
            oracle_drv,
            candidate_drv,
            oracle_bundle,
            candidate_bundle,
            mode
        )
    ));
}

fn reproduction_command(
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> String {
    reproduction_args(eval_config, file, attr, mode)
        .iter()
        .map(|arg| shell_word(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn eval_json_reproduction_command(eval_config: &NixEvalConfig, expr: &str) -> String {
    eval_json_reproduction_args(eval_config, expr)
        .iter()
        .map(|arg| shell_word(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn eval_json_reproduction_args(eval_config: &NixEvalConfig, expr: &str) -> Vec<String> {
    let mut args = vec!["aos".to_string()];
    if eval_config.nix_compat_profile() != NixCompatProfile::default() {
        args.push(format!("--nix-compat={}", eval_config.nix_compat_profile()));
    }
    if eval_config.trace_verbose() {
        args.push("--trace-verbose".to_string());
    }
    if let Some(current_system) = eval_config.current_system() {
        args.push(format!("--eval-system={current_system}"));
    }
    match eval_config.eval_mode() {
        NixEvalMode::Ambient => {}
        NixEvalMode::Impure => args.push("--impure-eval".to_string()),
        NixEvalMode::Pure => args.push("--pure-eval".to_string()),
        NixEvalMode::Restricted => {
            args.push("--restrict-eval".to_string());
            for path in eval_config.allowed_paths() {
                args.push(format!("--eval-allow-path={path}"));
            }
            for uri in eval_config.allowed_uris() {
                args.push(format!("--eval-allow-uri={uri}"));
            }
        }
    }
    args.extend([
        "nix-diff".to_string(),
        "--eval-json".to_string(),
        format!("--expr={expr}"),
    ]);
    args
}

fn reproduction_args(
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> Vec<String> {
    let mut args = vec!["aos".to_string()];
    if eval_config.nix_compat_profile() != NixCompatProfile::default() {
        args.push(format!("--nix-compat={}", eval_config.nix_compat_profile()));
    }
    if eval_config.trace_verbose() {
        args.push("--trace-verbose".to_string());
    }
    if let Some(current_system) = eval_config.current_system() {
        args.push(format!("--eval-system={current_system}"));
    }
    match eval_config.eval_mode() {
        NixEvalMode::Ambient => {}
        NixEvalMode::Impure => args.push("--impure-eval".to_string()),
        NixEvalMode::Pure => args.push("--pure-eval".to_string()),
        NixEvalMode::Restricted => {
            args.push("--restrict-eval".to_string());
            for path in eval_config.allowed_paths() {
                args.push(format!("--eval-allow-path={path}"));
            }
            for uri in eval_config.allowed_uris() {
                args.push(format!("--eval-allow-uri={uri}"));
            }
        }
    }
    args.extend([
        "nix-diff".to_string(),
        format!("--attr={attr}"),
        format!("--mode={}", mode_name(mode)),
        "--".to_string(),
        file.to_string_lossy().into_owned(),
    ]);
    args
}

fn cache_validation_reproduction_command(
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> String {
    cache_validation_reproduction_args(eval_config, file, attr, mode)
        .iter()
        .map(|arg| shell_word(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn cache_validation_reproduction_args(
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> Vec<String> {
    let mut args = reproduction_args(eval_config, file, attr, mode);
    let insert_at = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    args.insert(insert_at, "--cache-validation".to_string());
    args
}

fn node_reproduction_command(
    oracle_drv: &Path,
    candidate_drv: &Path,
    oracle_bundle: Option<&Path>,
    candidate_bundle: Option<&Path>,
    mode: DiffMode,
) -> String {
    node_reproduction_args(
        oracle_drv,
        candidate_drv,
        oracle_bundle,
        candidate_bundle,
        mode,
    )
    .iter()
    .map(|arg| shell_word(arg))
    .collect::<Vec<_>>()
    .join(" ")
}

fn node_reproduction_for_pair(report: &DrvDiffReport, pair: &DrvDiffPair) -> Option<String> {
    if report
        .file_backed_pairs
        .iter()
        .any(|file_backed_pair| file_backed_pair == pair)
    {
        return Some(node_reproduction_command(
            &pair.oracle,
            &pair.candidate,
            None,
            None,
            report.mode,
        ));
    }

    report
        .node_artifacts
        .iter()
        .find(|artifact| artifact.pair == *pair)
        .map(|artifact| {
            node_reproduction_command(
                &pair.oracle,
                &pair.candidate,
                artifact.oracle_bundle.as_deref(),
                artifact.candidate_bundle.as_deref(),
                report.mode,
            )
        })
}

fn node_reproduction_args(
    oracle_drv: &Path,
    candidate_drv: &Path,
    oracle_bundle: Option<&Path>,
    candidate_bundle: Option<&Path>,
    mode: DiffMode,
) -> Vec<String> {
    let mut args = vec![
        "aos".to_string(),
        "nix-diff".to_string(),
        format!("--oracle-drv={}", oracle_drv.to_string_lossy()),
        format!("--candidate-drv={}", candidate_drv.to_string_lossy()),
    ];
    if let Some(bundle) = oracle_bundle {
        args.push(format!("--oracle-drv-bundle={}", bundle.to_string_lossy()));
    }
    if let Some(bundle) = candidate_bundle {
        args.push(format!(
            "--candidate-drv-bundle={}",
            bundle.to_string_lossy()
        ));
    }
    args.push(format!("--mode={}", mode_name(mode)));
    args
}

fn shell_word(value: &str) -> String {
    if is_shell_bare_word(value) {
        return value.to_string();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn is_shell_bare_word(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'_'
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b','
                    | b'='
                    | b'+'
                    | b'@'
                    | b'%'
            )
        })
}

fn render_single_oracle_stats(printer: &Printer, stats: Option<&NixInstantiateStats>) {
    let Some(stats) = stats else {
        return;
    };
    if printer.mode() == OutputMode::Quiet {
        return;
    }
    printer.plain(&format!(
        "  nix-cli stats: drv={}{}",
        stats.drv_path.display(),
        stats_summary_suffix(stats)
    ));
}

fn render_corpus_oracle_stats_summary(printer: &Printer, reports: &[AttrDiffReport]) {
    if printer.mode() == OutputMode::Quiet {
        return;
    }
    if let Some(summary) = corpus_oracle_stats_summary(reports) {
        printer.plain(&summary);
    }
}

fn corpus_oracle_stats_summary(reports: &[AttrDiffReport]) -> Option<String> {
    let summary = corpus_oracle_stats_aggregate(reports)?;

    Some(format!(
        "  captured nix-cli stats for {} selected derivation(s) \
         (elapsed_total={:.6}s, elapsed_avg={:.6}s); use --json for raw NIX_SHOW_STATS",
        summary.captured,
        summary.elapsed_total.as_secs_f64(),
        summary.elapsed_avg_secs(),
    ))
}

fn corpus_oracle_stats_aggregate(reports: &[AttrDiffReport]) -> Option<CorpusOracleStatsAggregate> {
    let mut captured = 0;
    let mut elapsed_total = std::time::Duration::ZERO;
    for stats in reports
        .iter()
        .filter_map(|report| report.oracle_stats.as_ref())
    {
        captured += 1;
        elapsed_total = elapsed_total
            .checked_add(stats.elapsed)
            .unwrap_or(std::time::Duration::MAX);
    }

    (captured > 0).then_some(CorpusOracleStatsAggregate {
        captured,
        elapsed_total,
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct CorpusOracleStatsAggregate {
    captured: usize,
    elapsed_total: std::time::Duration,
}

impl CorpusOracleStatsAggregate {
    fn elapsed_avg_secs(self) -> f64 {
        self.elapsed_total.as_secs_f64() / self.captured as f64
    }

    fn json(self) -> serde_json::Value {
        serde_json::json!({
            "captured": self.captured,
            "elapsed": {
                "total_seconds": self.elapsed_total.as_secs_f64(),
                "total_nanos": duration_nanos(self.elapsed_total),
                "average_seconds": self.elapsed_avg_secs(),
                "average_nanos": duration_nanos_div(self.elapsed_total, self.captured),
            },
        })
    }
}

fn stats_summary_suffix(stats: &NixInstantiateStats) -> String {
    let mut fields = vec![format!("elapsed={:.6}s", stats.elapsed.as_secs_f64())];
    if let Some(cpu_time) = stats
        .stats
        .get("cpuTime")
        .and_then(serde_json::Value::as_f64)
    {
        fields.push(format!("cpuTime={cpu_time:.6}s"));
    }
    if let Some(thunks) = stats
        .stats
        .get("nrThunks")
        .and_then(serde_json::Value::as_u64)
    {
        fields.push(format!("nrThunks={thunks}"));
    }
    if let Some(exprs) = stats
        .stats
        .get("nrExprs")
        .and_then(serde_json::Value::as_u64)
    {
        fields.push(format!("nrExprs={exprs}"));
    }
    format!(" ({})", fields.join(", "))
}

fn render_diff(diff: &DrvDiff) -> String {
    match diff {
        DrvDiff::RootPath { oracle, candidate } => format!(
            "root path: oracle={} candidate={}",
            oracle.display(),
            candidate.display()
        ),
        DrvDiff::Evaluation { side, error } => {
            format!("{} evaluation failed: {error}", side_name(*side))
        }
        DrvDiff::EvaluationMismatch {
            oracle_error,
            candidate_error,
        } => format!(
            "evaluation mismatch: oracle error={oracle_error}; candidate error={candidate_error}"
        ),
        DrvDiff::Bytes { oracle, candidate } => format!(
            "bytes: oracle={} candidate={}",
            oracle.display(),
            candidate.display()
        ),
        DrvDiff::Structural {
            oracle,
            candidate,
            field,
        } => format!(
            "structural: oracle={} candidate={} field={field}",
            oracle.display(),
            candidate.display()
        ),
        DrvDiff::StructuralParse { side, path, error } => format!(
            "structural parse: {} path={} error={error}",
            side_name(*side),
            path.display()
        ),
        DrvDiff::InputCount {
            oracle,
            candidate,
            oracle_count,
            candidate_count,
        } => format!(
            "input count: oracle={} ({oracle_count}) candidate={} ({candidate_count})",
            oracle.display(),
            candidate.display()
        ),
        DrvDiff::InputOutputs {
            parent_oracle,
            parent_candidate,
            oracle,
            candidate,
            oracle_outputs,
            candidate_outputs,
        } => format!(
            "input outputs: parent_oracle={} parent_candidate={} oracle={} {:?} candidate={} {:?}",
            parent_oracle.display(),
            parent_candidate.display(),
            oracle.display(),
            oracle_outputs,
            candidate.display(),
            candidate_outputs
        ),
    }
}

const fn mode_name(mode: DiffMode) -> &'static str {
    match mode {
        DiffMode::Path => "path",
        DiffMode::Byte => "byte",
        DiffMode::Structural => "structural",
    }
}

const fn side_name(side: DiffSide) -> &'static str {
    match side {
        DiffSide::Oracle => "oracle",
        DiffSide::Candidate => "candidate",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FixedEval {
        name: &'static str,
        path: PathBuf,
        instantiate_calls: AtomicUsize,
    }

    impl FixedEval {
        fn new(name: &'static str, path: &str) -> Self {
            Self {
                name,
                path: PathBuf::from(path),
                instantiate_calls: AtomicUsize::new(0),
            }
        }

        fn instantiate_calls(&self) -> usize {
            self.instantiate_calls.load(Ordering::SeqCst)
        }
    }

    impl NixEval for FixedEval {
        fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
            self.instantiate_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.path.clone())
        }

        fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
            Ok(self.path.clone())
        }

        fn eval_expr(&self, _expr: &str) -> Result<String> {
            Ok("null".to_string())
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    struct FixedClosureEval {
        name: &'static str,
        closure: DrvClosure,
        instantiate_calls: AtomicUsize,
        instantiate_closure_calls: AtomicUsize,
    }

    impl FixedClosureEval {
        fn new(name: &'static str, root: &str, marker: &str) -> Self {
            Self {
                name,
                closure: single_drv_closure(root, marker),
                instantiate_calls: AtomicUsize::new(0),
                instantiate_closure_calls: AtomicUsize::new(0),
            }
        }

        fn instantiate_calls(&self) -> usize {
            self.instantiate_calls.load(Ordering::SeqCst)
        }

        fn instantiate_closure_calls(&self) -> usize {
            self.instantiate_closure_calls.load(Ordering::SeqCst)
        }
    }

    impl NixEval for FixedClosureEval {
        fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
            self.instantiate_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.closure.root().to_path_buf())
        }

        fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
            Ok(self.closure.root().to_path_buf())
        }

        fn instantiate_closure(&self, _file: &Path, _attr: &str) -> Result<Option<DrvClosure>> {
            self.instantiate_closure_calls
                .fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.closure.clone()))
        }

        fn eval_expr(&self, _expr: &str) -> Result<String> {
            Ok("null".to_string())
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    struct ErrorClosureEval {
        name: &'static str,
        message: &'static str,
        instantiate_closure_calls: AtomicUsize,
    }

    impl ErrorClosureEval {
        fn new(name: &'static str, message: &'static str) -> Self {
            Self {
                name,
                message,
                instantiate_closure_calls: AtomicUsize::new(0),
            }
        }

        fn instantiate_closure_calls(&self) -> usize {
            self.instantiate_closure_calls.load(Ordering::SeqCst)
        }
    }

    impl NixEval for ErrorClosureEval {
        fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
            Err(anyhow::anyhow!(self.message))
        }

        fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
            Err(anyhow::anyhow!(self.message))
        }

        fn instantiate_closure(&self, _file: &Path, _attr: &str) -> Result<Option<DrvClosure>> {
            self.instantiate_closure_calls
                .fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!(self.message))
        }

        fn eval_expr(&self, _expr: &str) -> Result<String> {
            Err(anyhow::anyhow!(self.message))
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    struct FixedJsonEval {
        name: &'static str,
        result: std::result::Result<&'static str, &'static str>,
        stats: Option<NixEvalStrictJsonStats>,
        eval_expr_calls: AtomicUsize,
    }

    impl FixedJsonEval {
        fn value(name: &'static str, value: &'static str) -> Self {
            Self {
                name,
                result: Ok(value),
                stats: None,
                eval_expr_calls: AtomicUsize::new(0),
            }
        }

        fn value_with_stats(
            name: &'static str,
            value: &'static str,
            stats: NixEvalStrictJsonStats,
        ) -> Self {
            Self {
                name,
                result: Ok(value),
                stats: Some(stats),
                eval_expr_calls: AtomicUsize::new(0),
            }
        }

        fn error(name: &'static str, message: &'static str) -> Self {
            Self {
                name,
                result: Err(message),
                stats: None,
                eval_expr_calls: AtomicUsize::new(0),
            }
        }

        fn eval_expr_calls(&self) -> usize {
            self.eval_expr_calls.load(Ordering::SeqCst)
        }
    }

    impl NixEval for FixedJsonEval {
        fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
            Err(anyhow::anyhow!(
                "fixed JSON evaluator only supports eval_expr"
            ))
        }

        fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
            Err(anyhow::anyhow!(
                "fixed JSON evaluator only supports eval_expr"
            ))
        }

        fn eval_expr(&self, _expr: &str) -> Result<String> {
            self.eval_expr_calls.fetch_add(1, Ordering::SeqCst);
            match self.result {
                Ok(value) => Ok(value.to_string()),
                Err(message) => Err(anyhow::anyhow!(message)),
            }
        }

        fn eval_expr_with_stats(
            &self,
            expr: &str,
        ) -> Result<(String, Option<NixEvalStrictJsonStats>)> {
            self.eval_expr(expr).map(|value| (value, self.stats))
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn repro_config() -> NixEvalConfig {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.clear_current_system();
        config.clear_allowed_paths();
        config.clear_allowed_uris();
        config.set_trace_verbose(false);
        config
    }

    fn single_drv_closure(root: &str, marker: &str) -> DrvClosure {
        let root = PathBuf::from(root);
        let mut drvs = BTreeMap::new();
        drvs.insert(root.clone(), single_drv_bytes(marker));
        DrvClosure::new(root, drvs)
    }

    fn single_drv_bytes(marker: &str) -> Vec<u8> {
        format!(
            r#"Derive([("out","/nix/store/cccccccccccccccccccccccccccccccc-{marker}-out","","")],[],[],"x86_64-linux","/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash",[],[("builder","/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash"),("name","{marker}"),("out","/nix/store/cccccccccccccccccccccccccccccccc-{marker}-out"),("system","x86_64-linux")])"#
        )
        .into_bytes()
    }

    #[test]
    fn cache_validation_rejects_path_mode() {
        let error = validate_cache_validation_mode(DiffMode::Path)
            .expect_err("path mode is not full-closure cache validation");
        assert_eq!(
            error.to_string(),
            "nix-diff --cache-validation requires --mode=byte or --mode=structural"
        );
        validate_cache_validation_mode(DiffMode::Byte).expect("byte mode is accepted");
        validate_cache_validation_mode(DiffMode::Structural).expect("structural mode is accepted");
    }

    #[test]
    fn cache_validation_path_mode_rejects_before_nix_probe() {
        let error =
            ensure_nix_instantiate_after_cache_validation_mode_check(true, DiffMode::Path, || {
                panic!("path-mode cache validation should reject before probing Nix")
            })
            .expect_err("cache validation path mode rejects before probing Nix");

        assert_eq!(
            error.to_string(),
            "nix-diff --cache-validation requires --mode=byte or --mode=structural"
        );

        let mut probe_called = false;
        ensure_nix_instantiate_after_cache_validation_mode_check(false, DiffMode::Path, || {
            probe_called = true;
            Ok(())
        })
        .expect("ordinary path-mode diff still probes Nix");
        assert!(probe_called);
    }

    #[test]
    fn eval_json_selection_rejects_drv_options_and_modes() {
        let error = validate_eval_json_selection(
            true,
            Some("pkgs.hello"),
            false,
            false,
            false,
            DiffMode::Byte,
            false,
            false,
        )
        .expect_err("attr selection should be rejected");
        assert!(
            error
                .to_string()
                .contains("cannot be combined with derivation diff selection"),
            "{error}"
        );

        let error = validate_eval_json_selection(
            true,
            None,
            false,
            false,
            false,
            DiffMode::Structural,
            false,
            false,
        )
        .expect_err("structural mode should be rejected");
        assert!(
            error.to_string().contains("does not accept --mode"),
            "{error}"
        );

        validate_eval_json_selection(
            true,
            None,
            false,
            false,
            false,
            DiffMode::Byte,
            false,
            false,
        )
        .expect("plain eval-json selection is accepted");

        validate_eval_json_selection(
            false,
            Some("pkgs.hello"),
            true,
            true,
            true,
            DiffMode::Structural,
            true,
            true,
        )
        .expect("derivation options are accepted outside eval-json mode");
    }

    #[test]
    fn eval_json_entries_loads_source_seed_directory() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let dir = temp.path();
        fs::write(
            dir.join("b.seed"),
            "# aos-nix-fuzz-source\n\
             # aos-nix-fuzz-config eval-mode=impure\n\
             \n\
             { b = 2; }\n",
        )?;
        fs::write(dir.join("a.seed"), "# aos-nix-fuzz-source\n{ a = 1; }\n")?;
        fs::write(dir.join("ignored.txt"), "# aos-nix-fuzz-source\n0\n")?;

        let entries = eval_json_entries(&[], &[dir.to_path_buf()], &repro_config())?;

        assert_eq!(entries.len(), 2);
        assert!(entries[0].name.ends_with("a.seed"));
        assert_eq!(entries[0].expr, "{ a = 1; }");
        assert!(entries[1].name.ends_with("b.seed"));
        assert_eq!(entries[1].expr, "{ b = 2; }");
        Ok(())
    }

    #[test]
    fn eval_json_entries_combines_expressions_and_source_seed_file() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("case.seed");
        fs::write(
            &seed,
            "# aos-nix-fuzz-source\nbuiltins.length [ (1 / 0) ]\n",
        )?;

        let entries = eval_json_entries(&["1 + 1".to_string()], &[seed], &repro_config())?;

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "expr[0]");
        assert_eq!(entries[0].expr, "1 + 1");
        assert!(entries[1].name.ends_with("case.seed"));
        assert_eq!(entries[1].expr, "builtins.length [ (1 / 0) ]");
        Ok(())
    }

    #[test]
    fn eval_json_entries_applies_source_seed_eval_config_metadata() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("restricted.seed");
        let allowed_path = temp.path().join("allowed");
        fs::create_dir(&allowed_path)?;
        fs::write(
            &seed,
            format!(
                "# aos-nix-fuzz-source\n\
                 # aos-nix-fuzz-config eval-mode=restricted\n\
                 # aos-nix-fuzz-config current-system=aos-seed-target\n\
                 # aos-nix-fuzz-config allowed-path={}\n\
                 # aos-nix-fuzz-config allowed-uri=https://cache.example/\n\
                 builtins.currentSystem\n",
                allowed_path.display()
            ),
        )?;
        let mut base = repro_config();
        base.set_eval_mode(NixEvalMode::Pure);
        base.set_current_system("aos-global-target")?;
        base.add_allowed_path(temp.path().to_string_lossy().into_owned())?;

        let entries = eval_json_entries(&[], &[seed], &base)?;

        let seed_config = entries[0]
            .eval_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metadata should produce a seed-local config"))?;
        assert_eq!(entries[0].expr, "builtins.currentSystem");
        assert_eq!(seed_config.eval_mode(), NixEvalMode::Restricted);
        assert_eq!(seed_config.current_system(), Some("aos-seed-target"));
        assert_eq!(
            seed_config.allowed_paths(),
            [allowed_path.to_string_lossy().into_owned()]
        );
        assert_eq!(seed_config.allowed_uris(), ["https://cache.example/"]);
        Ok(())
    }

    #[test]
    fn eval_json_entries_source_seed_allowlists_override_without_eval_mode() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("allowlist-only.seed");
        let global_path = temp.path().join("global");
        let seed_path = temp.path().join("seed");
        fs::create_dir(&global_path)?;
        fs::create_dir(&seed_path)?;
        fs::write(
            &seed,
            format!(
                "# aos-nix-fuzz-source\n\
                 # aos-nix-fuzz-config allowed-path={}\n\
                 # aos-nix-fuzz-config allowed-uri=https://seed.example/\n\
                 1\n",
                seed_path.display()
            ),
        )?;
        let mut base = repro_config();
        base.set_eval_mode(NixEvalMode::Restricted);
        base.add_allowed_path(global_path.to_string_lossy().into_owned())?;
        base.add_allowed_uri("https://global.example/")?;

        let entries = eval_json_entries(&[], &[seed], &base)?;

        let seed_config = entries[0]
            .eval_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metadata should produce a seed-local config"))?;
        assert_eq!(seed_config.eval_mode(), NixEvalMode::Restricted);
        assert_eq!(
            seed_config.allowed_paths(),
            [seed_path.to_string_lossy().into_owned()]
        );
        assert_eq!(seed_config.allowed_uris(), ["https://seed.example/"]);
        Ok(())
    }

    #[test]
    fn eval_json_entries_accepts_source_seed_system_alias() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("system-alias.seed");
        fs::write(
            &seed,
            "# aos-nix-fuzz-source\n\
             # aos-nix-fuzz-config system=aos-system-alias\n\
             builtins.currentSystem\n",
        )?;

        let entries = eval_json_entries(&[], &[seed], &repro_config())?;

        let seed_config = entries[0]
            .eval_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metadata should produce a seed-local config"))?;
        assert_eq!(seed_config.current_system(), Some("aos-system-alias"));
        Ok(())
    }

    #[test]
    fn eval_json_entries_rejects_non_source_seed_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("opaque.seed");
        fs::write(&seed, "not a source seed")?;

        let error = eval_json_entries(&[], &[seed], &repro_config())
            .expect_err("opaque fuzz bytes are not replayable as eval-json source seeds");

        assert!(
            error
                .to_string()
                .contains("source seed must start with \"# aos-nix-fuzz-source"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn eval_json_entries_rejects_invalid_source_seed_metadata() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("bad-config.seed");
        fs::write(
            &seed,
            "# aos-nix-fuzz-source\n\
             # aos-nix-fuzz-config allowed-path=relative\n\
             1\n",
        )?;

        let error = eval_json_entries(&[], &[seed], &repro_config())
            .expect_err("relative allowed paths should be rejected");

        assert!(
            error
                .to_string()
                .contains("has invalid metadata: allowed evaluation path must be absolute"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn eval_json_entries_rejects_unknown_source_seed_metadata() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("unknown-config.seed");
        fs::write(
            &seed,
            "# aos-nix-fuzz-source\n\
             # aos-nix-fuzz-config allowed-urii=https://cache.example/\n\
             1\n",
        )?;

        let error = eval_json_entries(&[], &[seed], &repro_config())
            .expect_err("unknown metadata keys should be rejected");

        assert!(
            error
                .to_string()
                .contains("has invalid metadata: unknown metadata key \"allowed-urii\""),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn eval_json_entries_rejects_empty_source_seed_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("empty.seed");
        fs::write(
            &seed,
            "# aos-nix-fuzz-source\n\
             # aos-nix-fuzz-config eval-mode=impure\n",
        )?;

        let error = eval_json_entries(&[], &[seed], &repro_config())
            .expect_err("empty source seeds should be rejected");

        assert!(
            error
                .to_string()
                .contains("contains no source expression after metadata"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn cache_validation_side_configs_only_change_native_cache_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work_dir = temp.path().join("work");
        let home_dir = temp.path().join("home");
        fs::create_dir(&work_dir)?;
        fs::create_dir(&home_dir)?;
        let configured_root = temp.path().join("configured-cache");
        let cold_root = temp.path().join("cold-cache");

        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Restricted);
        config.set_allowed_paths([temp.path().to_string_lossy().into_owned()])?;
        config.set_allowed_uris(["https://cache.example/".to_string()])?;
        config.set_current_system("aos-test-target")?;
        config.set_store_dirs("/nix/store", "/nix/var/nix", "/nix/var/log/nix")?;
        config.set_nix_path_env(format!("pkgs={}", temp.path().display()));
        config.set_working_dir(work_dir)?;
        config.set_home_dir(home_dir)?;
        config.set_native_cache_root(&configured_root)?;
        config.set_trace_verbose(true);
        let original = config.clone();

        let cache_off = cache_validation_cache_off_config(&config);
        let mut expected_cache_off = original.clone();
        expected_cache_off.clear_native_cache_root();
        assert_eq!(cache_off, expected_cache_off);
        assert_eq!(config, original);

        let cold_cache = cache_validation_cold_cache_config(&config, &cold_root)?;
        let mut expected_cold_cache = original.clone();
        expected_cold_cache.set_native_cache_root(&cold_root)?;
        assert_eq!(cold_cache, expected_cold_cache);
        assert_eq!(config, original);
        assert_eq!(cold_cache.native_cache_root(), Some(cold_root.as_path()));
        assert!(
            cold_cache
                .native_cache_root()
                .expect("cold cache root is configured")
                .is_absolute()
        );

        Ok(())
    }

    #[test]
    fn cache_validation_attr_report_compares_oracle_cache_off_and_cold_cache() {
        let oracle = FixedEval::new("oracle", "/nix/store/same.drv");
        let cache_off = FixedEval::new("cache-off", "/nix/store/same.drv");
        let cold_cache = FixedEval::new("cold-cache", "/nix/store/same.drv");

        let report = cache_validation_attr_report(
            &oracle,
            &cache_off,
            &cold_cache,
            PathBuf::from("/tmp/cold-cache"),
            Path::new("default.nix"),
            "pkgs.hello",
            DiffMode::Path,
        );

        assert!(!report.has_failure());
        assert_eq!(
            report
                .comparisons()
                .iter()
                .map(|comparison| comparison.name)
                .collect::<Vec<_>>(),
            [
                "oracle_vs_cache_off",
                "oracle_vs_cold_cache",
                "cache_off_vs_cold_cache"
            ]
        );
        assert_eq!(oracle.instantiate_calls(), 1);
        assert_eq!(cache_off.instantiate_calls(), 1);
        assert_eq!(cold_cache.instantiate_calls(), 1);
    }

    #[test]
    fn cache_validation_byte_mode_uses_in_memory_closures_without_path_fallback() {
        let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same.drv";
        let oracle = FixedClosureEval::new("oracle", root, "same");
        let cache_off = FixedClosureEval::new("cache-off", root, "same");
        let cold_cache = FixedClosureEval::new("cold-cache", root, "same");

        let report = cache_validation_attr_report(
            &oracle,
            &cache_off,
            &cold_cache,
            PathBuf::from("/tmp/cold-cache"),
            Path::new("default.nix"),
            "pkgs.hello",
            DiffMode::Byte,
        );

        assert!(!report.has_failure());
        assert_eq!(oracle.instantiate_calls(), 0);
        assert_eq!(cache_off.instantiate_calls(), 0);
        assert_eq!(cold_cache.instantiate_calls(), 0);
        assert_eq!(oracle.instantiate_closure_calls(), 1);
        assert_eq!(cache_off.instantiate_closure_calls(), 1);
        assert_eq!(cold_cache.instantiate_closure_calls(), 1);
        assert!(report.comparisons().iter().all(|comparison| {
            comparison
                .report
                .as_ref()
                .is_some_and(|report| report.mode == DiffMode::Byte)
        }));
    }

    #[test]
    fn cache_validation_byte_mode_detects_cold_closure_byte_drift() {
        let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same.drv";
        let oracle = FixedClosureEval::new("oracle", root, "same");
        let cache_off = FixedClosureEval::new("cache-off", root, "same");
        let cold_cache = FixedClosureEval::new("cold-cache", root, "cold");

        let report = cache_validation_attr_report(
            &oracle,
            &cache_off,
            &cold_cache,
            PathBuf::from("/tmp/cold-cache"),
            Path::new("default.nix"),
            "pkgs.hello",
            DiffMode::Byte,
        );

        assert!(report.has_failure());
        assert!(report.oracle_vs_cache_off.failure.is_none());
        assert!(report.oracle_vs_cold_cache.failure.is_some());
        assert!(report.cache_off_vs_cold_cache.failure.is_some());
        assert_eq!(oracle.instantiate_calls(), 0);
        assert_eq!(cache_off.instantiate_calls(), 0);
        assert_eq!(cold_cache.instantiate_calls(), 0);
        assert_eq!(oracle.instantiate_closure_calls(), 1);
        assert_eq!(cache_off.instantiate_closure_calls(), 1);
        assert_eq!(cold_cache.instantiate_closure_calls(), 1);

        let reports = vec![report];
        let failure = cache_validation_failure(&reports).expect("byte drift fails validation");
        assert_eq!(
            failure.to_string(),
            "drv diff failed for 1 attribute(s) with 2 divergence(s)"
        );
        let comparison_kinds = reports[0]
            .comparisons()
            .iter()
            .map(|comparison| {
                comparison
                    .report
                    .as_ref()
                    .map(|report| {
                        report
                            .divergences
                            .iter()
                            .map(diff_json)
                            .map(|value| value["kind"].clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        assert_eq!(comparison_kinds[0], Vec::<serde_json::Value>::new());
        assert_eq!(
            comparison_kinds[1],
            [serde_json::Value::String("bytes".to_string())]
        );
        assert_eq!(
            comparison_kinds[2],
            [serde_json::Value::String("bytes".to_string())]
        );
    }

    #[test]
    fn cache_validation_structural_mode_uses_in_memory_closures_without_path_fallback() {
        let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same.drv";
        let oracle = FixedClosureEval::new("oracle", root, "same");
        let cache_off = FixedClosureEval::new("cache-off", root, "same");
        let cold_cache = FixedClosureEval::new("cold-cache", root, "same");

        let report = cache_validation_attr_report(
            &oracle,
            &cache_off,
            &cold_cache,
            PathBuf::from("/tmp/cold-cache"),
            Path::new("default.nix"),
            "pkgs.hello",
            DiffMode::Structural,
        );

        assert!(!report.has_failure());
        assert_eq!(oracle.instantiate_calls(), 0);
        assert_eq!(cache_off.instantiate_calls(), 0);
        assert_eq!(cold_cache.instantiate_calls(), 0);
        assert_eq!(oracle.instantiate_closure_calls(), 1);
        assert_eq!(cache_off.instantiate_closure_calls(), 1);
        assert_eq!(cold_cache.instantiate_closure_calls(), 1);
        assert!(report.comparisons().iter().all(|comparison| {
            comparison
                .report
                .as_ref()
                .is_some_and(|report| report.mode == DiffMode::Structural)
        }));
    }

    #[test]
    fn cache_validation_structural_mode_detects_cold_closure_structural_drift() {
        let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same.drv";
        let oracle = FixedClosureEval::new("oracle", root, "same");
        let cache_off = FixedClosureEval::new("cache-off", root, "same");
        let cold_cache = FixedClosureEval::new("cold-cache", root, "cold");

        let report = cache_validation_attr_report(
            &oracle,
            &cache_off,
            &cold_cache,
            PathBuf::from("/tmp/cold-cache"),
            Path::new("default.nix"),
            "pkgs.hello",
            DiffMode::Structural,
        );

        assert!(report.has_failure());
        assert!(report.oracle_vs_cache_off.failure.is_none());
        assert!(report.oracle_vs_cold_cache.failure.is_some());
        assert!(report.cache_off_vs_cold_cache.failure.is_some());
        assert_eq!(oracle.instantiate_calls(), 0);
        assert_eq!(cache_off.instantiate_calls(), 0);
        assert_eq!(cold_cache.instantiate_calls(), 0);
        assert_eq!(oracle.instantiate_closure_calls(), 1);
        assert_eq!(cache_off.instantiate_closure_calls(), 1);
        assert_eq!(cold_cache.instantiate_closure_calls(), 1);

        let reports = vec![report];
        let failure =
            cache_validation_failure(&reports).expect("structural drift fails validation");
        assert_eq!(
            failure.to_string(),
            "drv diff failed for 1 attribute(s) with 4 divergence(s)"
        );
        let comparison_kinds = reports[0]
            .comparisons()
            .iter()
            .map(|comparison| {
                comparison
                    .report
                    .as_ref()
                    .map(|report| {
                        report
                            .divergences
                            .iter()
                            .map(diff_json)
                            .map(|value| value["kind"].clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        assert_eq!(comparison_kinds[0], Vec::<serde_json::Value>::new());
        assert_eq!(
            comparison_kinds[1],
            [
                serde_json::Value::String("bytes".to_string()),
                serde_json::Value::String("structural".to_string())
            ]
        );
        assert_eq!(
            comparison_kinds[2],
            [
                serde_json::Value::String("bytes".to_string()),
                serde_json::Value::String("structural".to_string())
            ]
        );
    }

    #[test]
    fn cache_validation_full_closure_modes_reject_path_only_evaluators() {
        for mode in [DiffMode::Byte, DiffMode::Structural] {
            let oracle = FixedEval::new("oracle", "/nix/store/oracle.drv");
            let cache_off = FixedEval::new("cache-off", "/nix/store/cache-off.drv");
            let cold_cache = FixedEval::new("cold-cache", "/nix/store/cold-cache.drv");

            let report = cache_validation_attr_report(
                &oracle,
                &cache_off,
                &cold_cache,
                PathBuf::from("/tmp/cold-cache"),
                Path::new("default.nix"),
                "pkgs.hello",
                mode,
            );

            assert!(
                report.has_failure(),
                "{mode:?} cache validation should reject path-only evaluators"
            );
            assert_eq!(
                oracle.instantiate_calls(),
                0,
                "{mode:?} cache validation must not fall back to oracle path instantiation"
            );
            assert_eq!(
                cache_off.instantiate_calls(),
                0,
                "{mode:?} cache validation must not fall back to cache-off path instantiation"
            );
            assert_eq!(
                cold_cache.instantiate_calls(),
                0,
                "{mode:?} cache validation must not fall back to cold-cache path instantiation"
            );
            assert!(report.comparisons().iter().all(|comparison| {
                comparison.failure.is_some()
                    && comparison.report.as_ref().is_some_and(|report| {
                        report
                            .divergences
                            .iter()
                            .any(|diff| matches!(diff, DrvDiff::EvaluationMismatch { .. }))
                    })
            }));
        }
    }

    #[test]
    fn cache_validation_json_renders_full_closure_matrix_failures() {
        let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same.drv";
        let oracle = FixedClosureEval::new("oracle", root, "same");
        let cache_off = FixedClosureEval::new("cache-off", root, "same");
        let cold_cache = FixedClosureEval::new("cold-cache", root, "cold");
        let report = cache_validation_attr_report(
            &oracle,
            &cache_off,
            &cold_cache,
            PathBuf::from("/tmp/aos-cold-cache"),
            Path::new("default.nix"),
            "pkgs.hello",
            DiffMode::Byte,
        );
        let reports = vec![report];
        let failure = cache_validation_failure(&reports);

        let value = cache_validation_json(
            &reports,
            &repro_config(),
            Path::new("default.nix"),
            DiffMode::Byte,
            failure.as_ref(),
        );

        assert_eq!(value["cache_validation"], true);
        assert_eq!(value["mode"], "byte");
        assert_eq!(value["matched"], false);
        assert_eq!(value["attrs_checked"], 1);
        assert_eq!(value["attrs_failed"], 1);
        assert_eq!(value["comparison_failures"], 2);
        assert_eq!(value["divergence_count"], 2);
        assert_eq!(value["reports"][0]["attr"], "pkgs.hello");
        assert_eq!(value["reports"][0]["comparison_failures"], 2);
        assert_eq!(
            value["reports"][0]["cold_cache_root"],
            "/tmp/aos-cold-cache"
        );
        assert_eq!(value["reports"][0]["cold_cache_root_retained"], true);
        assert_eq!(
            value["reports"][0]["reproduce"],
            "aos --impure-eval nix-diff --attr=pkgs.hello --mode=byte --cache-validation -- default.nix"
        );
        assert_eq!(
            value["reports"][0]["comparisons"][0]["name"],
            "oracle_vs_cache_off"
        );
        assert_eq!(value["reports"][0]["comparisons"][0]["matched"], true);
        assert_eq!(
            value["reports"][0]["comparisons"][1]["name"],
            "oracle_vs_cold_cache"
        );
        assert_eq!(value["reports"][0]["comparisons"][1]["matched"], false);
        assert_eq!(
            value["reports"][0]["comparisons"][1]["divergences"][0]["kind"],
            "bytes"
        );
        assert_eq!(
            value["reports"][0]["comparisons"][2]["name"],
            "cache_off_vs_cold_cache"
        );
        assert_eq!(
            value["reports"][0]["comparisons"][2]["divergences"][0]["kind"],
            "bytes"
        );
    }

    #[test]
    fn cache_validation_json_counts_failed_comparisons_without_divergences() {
        let oracle = ErrorClosureEval::new("oracle", "same hard failure");
        let cache_off = ErrorClosureEval::new("cache-off", "same hard failure");
        let cold_cache = ErrorClosureEval::new("cold-cache", "same hard failure");
        let report = cache_validation_attr_report(
            &oracle,
            &cache_off,
            &cold_cache,
            PathBuf::from("/tmp/aos-cold-cache-error"),
            Path::new("default.nix"),
            "pkgs.hello",
            DiffMode::Byte,
        );
        let reports = vec![report];
        let failure = cache_validation_failure(&reports);

        let value = cache_validation_json(
            &reports,
            &repro_config(),
            Path::new("default.nix"),
            DiffMode::Byte,
            failure.as_ref(),
        );

        assert_eq!(oracle.instantiate_closure_calls(), 1);
        assert_eq!(cache_off.instantiate_closure_calls(), 1);
        assert_eq!(cold_cache.instantiate_closure_calls(), 1);
        assert_eq!(value["matched"], false);
        assert_eq!(value["attrs_failed"], 1);
        assert_eq!(value["comparison_failures"], 3);
        assert_eq!(value["divergence_count"], 0);
        assert_eq!(value["reports"][0]["comparison_failures"], 3);
        assert_eq!(value["reports"][0]["cold_cache_root_retained"], true);
        assert!(
            value["reports"][0]["comparisons"]
                .as_array()
                .is_some_and(|comparisons| comparisons.iter().all(|comparison| {
                    comparison["matched"] == false
                        && comparison["error"]
                            == "drv diff produced no derivation output to compare"
                        && comparison["divergences"]
                            .as_array()
                            .is_some_and(Vec::is_empty)
                }))
        );
    }

    #[test]
    fn cache_validation_full_closure_cleanup_removes_only_successful_cold_roots() -> Result<()> {
        let matching_root = tempfile::tempdir()?;
        let failing_root = tempfile::tempdir()?;
        let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same.drv";
        let oracle = FixedClosureEval::new("oracle", root, "same");
        let matching_cache_off = FixedClosureEval::new("matching-cache-off", root, "same");
        let matching_cold = FixedClosureEval::new("matching-cold", root, "same");
        let failing_cache_off = FixedClosureEval::new("failing-cache-off", root, "same");
        let failing_cold = FixedClosureEval::new("failing-cold", root, "cold");
        let matching_path = matching_root.keep();
        let failing_path = failing_root.keep();
        let matching = cache_validation_attr_report(
            &oracle,
            &matching_cache_off,
            &matching_cold,
            matching_path.clone(),
            Path::new("default.nix"),
            "pkgs.matching",
            DiffMode::Byte,
        );
        let failing = cache_validation_attr_report(
            &oracle,
            &failing_cache_off,
            &failing_cold,
            failing_path.clone(),
            Path::new("default.nix"),
            "pkgs.failing",
            DiffMode::Byte,
        );

        cleanup_successful_cache_validation_roots(&[matching, failing]);

        assert!(
            !matching_path.exists(),
            "successful cold cache roots should be removed"
        );
        assert!(
            failing_path.exists(),
            "failing cold cache roots should remain for debugging"
        );
        fs::remove_dir_all(&failing_path)?;
        Ok(())
    }

    #[test]
    fn eval_json_report_json_renders_matching_expression() {
        let oracle = FixedJsonEval::value("oracle", r#"{"a":1}"#);
        let candidate = FixedJsonEval::value("candidate", r#"{"a":1}"#);
        let config = repro_config();
        let entry = EvalJsonEntry {
            name: "sample".to_string(),
            expr: "1".to_string(),
            eval_config: None,
        };
        let report = eval_json_report(&oracle, &candidate, &entry, &config);
        let reports = vec![report];
        let failure = eval_json_failure(&reports);

        let value = eval_json_report_json(&reports, 0, None, "aos-nix", failure.as_ref());

        assert_eq!(oracle.eval_expr_calls(), 1);
        assert_eq!(candidate.eval_expr_calls(), 1);
        assert!(failure.is_none());
        assert_eq!(value["eval_json"], true);
        assert_eq!(value["matched"], true);
        assert_eq!(value["expressions_checked"], 1);
        assert_eq!(value["expressions_failed"], 0);
        assert_eq!(value["divergence_count"], 0);
        assert_eq!(value["reports"][0]["name"], "sample");
        assert_eq!(value["reports"][0]["expr"], "1");
        assert_eq!(
            value["reports"][0]["reproduce"],
            "aos --impure-eval nix-diff --eval-json --expr=1"
        );
        assert_eq!(value["reports"][0]["oracle_value"], r#"{"a":1}"#);
        assert_eq!(value["reports"][0]["candidate_value"], r#"{"a":1}"#);
        assert!(value["reports"][0]["oracle_error"].is_null());
        assert!(value["reports"][0]["candidate_error"].is_null());
        assert!(value["reports"][0]["candidate_stats"].is_null());
        assert_eq!(value["expressions_skipped"], 0);
        assert!(value["time_budget_seconds"].is_null());
    }

    #[test]
    fn eval_json_report_json_renders_time_budget_and_skips() {
        let oracle = FixedJsonEval::value("oracle", "1");
        let candidate = FixedJsonEval::value("candidate", "1");
        let config = repro_config();
        let entry = EvalJsonEntry {
            name: "sample".to_string(),
            expr: "1".to_string(),
            eval_config: None,
        };
        let report = eval_json_report(&oracle, &candidate, &entry, &config);
        let reports = vec![report];
        let failure = eval_json_failure(&reports);

        let value = eval_json_report_json(
            &reports,
            3,
            Some(Duration::from_secs(120)),
            "aos-nix",
            failure.as_ref(),
        );

        assert_eq!(value["matched"], true);
        assert_eq!(value["expressions_checked"], 1);
        assert_eq!(value["expressions_skipped"], 3);
        assert_eq!(value["time_budget_seconds"], 120);
    }

    #[test]
    fn eval_json_budget_note_names_budget_and_skip_counts() {
        assert_eq!(
            eval_json_budget_note(7, 10, Some(Duration::from_secs(90))),
            "eval-json time budget (90s) exhausted: skipped 7 of 10 expression(s)"
        );
        assert_eq!(
            eval_json_budget_note(1, 2, None),
            "eval-json time budget (unset) exhausted: skipped 1 of 2 expression(s)"
        );
    }

    #[test]
    fn eval_json_report_json_renders_candidate_stats() {
        let oracle = FixedJsonEval::value("oracle", "1");
        let candidate = FixedJsonEval::value_with_stats(
            "candidate",
            "1",
            NixEvalStrictJsonStats::new(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17),
        );
        let config = repro_config();
        let entry = EvalJsonEntry {
            name: "stats".to_string(),
            expr: "1".to_string(),
            eval_config: None,
        };
        let report = eval_json_report(&oracle, &candidate, &entry, &config);
        let reports = vec![report];
        let failure = eval_json_failure(&reports);

        let value = eval_json_report_json(&reports, 0, None, "aos-nix", failure.as_ref());

        assert_eq!(oracle.eval_expr_calls(), 1);
        assert_eq!(candidate.eval_expr_calls(), 1);
        assert!(failure.is_none());
        let stats = &value["reports"][0]["candidate_stats"];
        assert_eq!(stats["thunks_forced"], 1);
        assert_eq!(stats["thunks_allocated"], 2);
        assert_eq!(stats["gc_bytes"], 3);
        assert_eq!(stats["gc_pause_us"], 4);
        assert_eq!(stats["tier_promotions"], 5);
        assert_eq!(stats["deopts"], 6);
        assert_eq!(stats["heap_chunks"], 7);
        assert_eq!(stats["heap_reserved_bytes"], 8);
        assert_eq!(stats["heap_mapped_bytes"], 9);
        assert_eq!(stats["heap_used_bytes"], 10);
        assert_eq!(stats["permanent_heap_chunks"], 11);
        assert_eq!(stats["permanent_heap_reserved_bytes"], 12);
        assert_eq!(stats["permanent_heap_mapped_bytes"], 13);
        assert_eq!(stats["permanent_heap_used_bytes"], 14);
        assert_eq!(stats["heap_tier_b_admission_worker_records"], 15);
        assert_eq!(stats["heap_tier_b_admission_permanent_shared_records"], 16);
        assert_eq!(stats["heap_tier_b_admission_generation_rewrites"], 17);
    }

    #[test]
    fn eval_json_report_json_renders_value_divergence() {
        let oracle = FixedJsonEval::value("oracle", "1");
        let candidate = FixedJsonEval::value("candidate", "2");
        let config = repro_config();
        let entry = EvalJsonEntry {
            name: "seed:/tmp/parity_json/number.seed".to_string(),
            expr: "1 + 1".to_string(),
            eval_config: None,
        };
        let report = eval_json_report(&oracle, &candidate, &entry, &config);
        let reports = vec![report];
        let failure = eval_json_failure(&reports);

        let value = eval_json_report_json(&reports, 0, None, "aos-nix", failure.as_ref());

        assert_eq!(
            failure.as_ref().map(ToString::to_string).as_deref(),
            Some("eval-json diff failed for 1 expression(s) with 1 divergence(s)")
        );
        assert_eq!(value["matched"], false);
        assert_eq!(value["expressions_failed"], 1);
        assert_eq!(value["divergence_count"], 1);
        assert_eq!(value["reports"][0]["matched"], false);
        assert_eq!(
            value["reports"][0]["name"],
            "seed:/tmp/parity_json/number.seed"
        );
        assert_eq!(value["reports"][0]["error"], "eval-json output diverged");
        assert_eq!(value["reports"][0]["oracle_value"], "1");
        assert_eq!(value["reports"][0]["candidate_value"], "2");
    }

    #[test]
    fn eval_json_report_json_renders_seed_effective_config() -> Result<()> {
        let oracle = FixedJsonEval::value("oracle", "1");
        let candidate = FixedJsonEval::value("candidate", "1");
        let mut config = repro_config();
        config.set_eval_mode(NixEvalMode::Restricted);
        config.set_current_system("aos-seed-target")?;
        config.add_allowed_path("/aos/seed")?;
        config.add_allowed_uri("https://seed.example/")?;
        let entry = EvalJsonEntry {
            name: "seed:/tmp/parity_json/config.seed".to_string(),
            expr: "builtins.currentSystem".to_string(),
            eval_config: Some(config.clone()),
        };
        let report = eval_json_report(&oracle, &candidate, &entry, &config);
        let reports = vec![report];
        let failure = eval_json_failure(&reports);

        let value = eval_json_report_json(&reports, 0, None, "aos-nix", failure.as_ref());

        assert_eq!(
            value["reports"][0]["reproduce"],
            "aos --eval-system=aos-seed-target --restrict-eval \
             --eval-allow-path=/aos/seed --eval-allow-uri=https://seed.example/ \
             nix-diff --eval-json --expr=builtins.currentSystem"
        );
        Ok(())
    }

    #[test]
    fn eval_json_report_json_renders_candidate_error() {
        let oracle = FixedJsonEval::value("oracle", "1");
        let candidate = FixedJsonEval::error("candidate", "unsupported builtin");
        let config = repro_config();
        let entry = EvalJsonEntry {
            name: "unsupported".to_string(),
            expr: "builtins.currentTime".to_string(),
            eval_config: None,
        };
        let report = eval_json_report(&oracle, &candidate, &entry, &config);
        let reports = vec![report];
        let failure = eval_json_failure(&reports);

        let value = eval_json_report_json(&reports, 0, None, "aos-nix", failure.as_ref());

        assert_eq!(
            failure.as_ref().map(ToString::to_string).as_deref(),
            Some("eval-json diff failed for 1 expression(s)")
        );
        assert_eq!(value["matched"], false);
        assert_eq!(value["expressions_failed"], 1);
        assert_eq!(value["divergence_count"], 0);
        assert_eq!(
            value["reports"][0]["error"],
            "candidate eval-json failed: unsupported builtin"
        );
        assert_eq!(value["reports"][0]["oracle_value"], "1");
        assert!(value["reports"][0]["candidate_value"].is_null());
        assert_eq!(
            value["reports"][0]["candidate_error"],
            "unsupported builtin"
        );
    }

    #[test]
    fn report_json_renders_divergence_details() {
        let report = DrvDiffReport {
            mode: DiffMode::Byte,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: Some(PathBuf::from("/nix/store/candidate.drv")),
            divergences: vec![
                DrvDiff::RootPath {
                    oracle: PathBuf::from("/nix/store/oracle.drv"),
                    candidate: PathBuf::from("/nix/store/candidate.drv"),
                },
                DrvDiff::Bytes {
                    oracle: PathBuf::from("/nix/store/oracle.drv"),
                    candidate: PathBuf::from("/nix/store/candidate.drv"),
                },
            ],
            root_divergences: vec![DrvDiffPair {
                oracle: PathBuf::from("/nix/store/oracle.drv"),
                candidate: PathBuf::from("/nix/store/candidate.drv"),
            }],
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let failure = report_failure(&report);
        let value = report_json(
            &report,
            "aos-nix",
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            failure.as_ref(),
            None,
        );

        assert_eq!(value["mode"], "byte");
        assert_eq!(value["oracle"], "nix-cli");
        assert_eq!(value["candidate"], "aos-nix");
        assert_eq!(value["file"], "default.nix");
        assert_eq!(value["attr"], "pkgs.hello");
        assert_eq!(
            value["reproduce"],
            "aos --impure-eval nix-diff --attr=pkgs.hello --mode=byte -- default.nix"
        );
        assert_eq!(value["matched"], false);
        assert_eq!(value["error"], "drv diff found 2 divergence(s)");
        assert!(value.get("oracle_stats").is_none());
        assert_eq!(value["divergences"][0]["kind"], "root_path");
        assert_eq!(value["divergences"][1]["kind"], "bytes");
        assert_eq!(
            value["root_divergences"][0]["oracle"],
            "/nix/store/oracle.drv"
        );
        assert_eq!(value["root_reports"][0]["file"], "default.nix");
        assert_eq!(value["root_reports"][0]["attr"], "pkgs.hello");
        assert_eq!(value["root_reports"][0]["mode"], "byte");
        assert_eq!(
            value["root_reports"][0]["reproduce"],
            "aos --impure-eval nix-diff --attr=pkgs.hello --mode=byte -- default.nix"
        );
        assert!(value["root_reports"][0].get("node_reproduce").is_none());
        assert_eq!(value["root_reports"][0]["oracle"], "/nix/store/oracle.drv");
        assert_eq!(
            value["root_reports"][0]["candidate"],
            "/nix/store/candidate.drv"
        );
        assert_eq!(
            value["root_reports"][0]["divergences"][0]["kind"],
            "root_path"
        );
        assert_eq!(value["root_reports"][0]["divergences"][1]["kind"], "bytes");
        assert!(
            value["contaminated_divergences"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn drv_pair_report_json_renders_direct_node_reproduction() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle_drv = temp.path().join("oracle.drv");
        let candidate_drv = temp.path().join("candidate.drv");
        fs::write(&oracle_drv, b"oracle drv")?;
        fs::write(&candidate_drv, b"candidate drv")?;
        let pair = DrvDiffPair {
            oracle: oracle_drv.clone(),
            candidate: candidate_drv.clone(),
        };
        let report = DrvDiffReport {
            mode: DiffMode::Structural,
            oracle_root: Some(oracle_drv.clone()),
            candidate_root: Some(candidate_drv.clone()),
            divergences: vec![DrvDiff::Structural {
                oracle: oracle_drv.clone(),
                candidate: candidate_drv.clone(),
                field: "environment".to_string(),
            }],
            root_divergences: vec![pair.clone()],
            contaminated_divergences: Vec::new(),
            file_backed_pairs: vec![pair],
            node_artifacts: Vec::new(),
        };
        let failure = report_failure(&report);

        let value = drv_pair_report_json(
            &report,
            &oracle_drv,
            &candidate_drv,
            None,
            None,
            failure.as_ref(),
        );

        assert_eq!(value["mode"], "structural");
        assert_eq!(value["oracle"], "oracle-drv");
        assert_eq!(value["candidate"], "candidate-drv");
        assert_eq!(
            value["oracle_drv"],
            oracle_drv.to_string_lossy().to_string()
        );
        assert_eq!(
            value["candidate_drv"],
            candidate_drv.to_string_lossy().to_string()
        );
        assert_eq!(
            value["reproduce"],
            node_reproduction_command(
                &oracle_drv,
                &candidate_drv,
                None,
                None,
                DiffMode::Structural
            )
        );
        assert_eq!(value["matched"], false);
        assert_eq!(value["error"], "drv diff found 1 divergence(s)");
        assert_eq!(
            value["root_reports"][0]["node_reproduce"],
            node_reproduction_command(
                &oracle_drv,
                &candidate_drv,
                None,
                None,
                DiffMode::Structural
            )
        );
        assert_eq!(
            value["root_reports"][0]["divergences"][0]["kind"],
            "structural"
        );
        Ok(())
    }

    #[test]
    fn root_report_json_renders_bundle_backed_node_reproduction() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle_drv = temp.path().join("oracle.drv");
        let candidate_drv = temp.path().join("candidate.drv");
        let oracle_bundle = temp.path().join("oracle-bundle.json");
        let candidate_bundle = temp.path().join("candidate-bundle.json");
        fs::write(&oracle_drv, b"stale oracle drv")?;
        fs::write(&candidate_drv, b"stale candidate drv")?;
        fs::write(&oracle_bundle, b"{}")?;
        fs::write(&candidate_bundle, b"{}")?;
        let pair = DrvDiffPair {
            oracle: oracle_drv.clone(),
            candidate: candidate_drv.clone(),
        };
        let report = DrvDiffReport {
            mode: DiffMode::Byte,
            oracle_root: Some(oracle_drv.clone()),
            candidate_root: Some(candidate_drv.clone()),
            divergences: vec![DrvDiff::Bytes {
                oracle: oracle_drv.clone(),
                candidate: candidate_drv.clone(),
            }],
            root_divergences: vec![pair.clone()],
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: vec![aos_nix_harness::diff::DrvDiffNodeArtifact {
                pair,
                oracle_bundle: Some(oracle_bundle.clone()),
                candidate_bundle: Some(candidate_bundle.clone()),
            }],
        };
        let value = report_json(
            &report,
            "aos-nix",
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            report_failure(&report).as_ref(),
            None,
        );

        assert_eq!(
            value["root_reports"][0]["node_reproduce"],
            node_reproduction_command(
                &oracle_drv,
                &candidate_drv,
                Some(&oracle_bundle),
                Some(&candidate_bundle),
                DiffMode::Byte,
            )
        );
        Ok(())
    }

    #[test]
    fn report_json_renders_oracle_stats() {
        let report = DrvDiffReport {
            mode: DiffMode::Byte,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: Some(PathBuf::from("/nix/store/candidate.drv")),
            divergences: Vec::new(),
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };
        let stats = NixInstantiateStats {
            drv_path: PathBuf::from("/nix/store/stats.drv"),
            stats: serde_json::json!({
                "cpuTime": 0.125,
                "nrThunks": 7,
                "nrExprs": 55,
            }),
            elapsed: std::time::Duration::from_millis(1500),
        };

        let value = report_json(
            &report,
            "aos-nix",
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            None,
            Some(&stats),
        );

        assert_eq!(value["oracle_stats"]["drv_path"], "/nix/store/stats.drv");
        assert_eq!(value["oracle_stats"]["elapsed"]["seconds"], 1.5);
        assert_eq!(value["oracle_stats"]["elapsed"]["nanos"], 1_500_000_000);
        assert_eq!(value["oracle_stats"]["raw"]["nrThunks"], 7);
        assert_eq!(
            stats_summary_suffix(&stats),
            " (elapsed=1.500000s, cpuTime=0.125000s, nrThunks=7, nrExprs=55)"
        );
    }

    #[test]
    fn corpus_oracle_stats_summary_renders_elapsed_aggregate() {
        let reports = vec![
            AttrDiffReport {
                file: PathBuf::from("default.nix"),
                attr: "pkgs.fast".to_string(),
                report: None,
                failure: None,
                oracle_stats: Some(NixInstantiateStats {
                    drv_path: PathBuf::from("/nix/store/fast.drv"),
                    stats: serde_json::json!({}),
                    elapsed: std::time::Duration::from_millis(500),
                }),
            },
            AttrDiffReport {
                file: PathBuf::from("default.nix"),
                attr: "pkgs.slow".to_string(),
                report: None,
                failure: None,
                oracle_stats: Some(NixInstantiateStats {
                    drv_path: PathBuf::from("/nix/store/slow.drv"),
                    stats: serde_json::json!({}),
                    elapsed: std::time::Duration::from_millis(1500),
                }),
            },
            AttrDiffReport {
                file: PathBuf::from("default.nix"),
                attr: "pkgs.skipped".to_string(),
                report: None,
                failure: None,
                oracle_stats: None,
            },
        ];

        assert_eq!(
            corpus_oracle_stats_summary(&reports).as_deref(),
            Some(
                "  captured nix-cli stats for 2 selected derivation(s) \
                 (elapsed_total=2.000000s, elapsed_avg=1.000000s); use --json for raw NIX_SHOW_STATS"
            )
        );
        assert_eq!(corpus_oracle_stats_summary(&[]), None);
    }

    #[test]
    fn corpus_json_renders_oracle_stats_summary() {
        let reports = vec![
            AttrDiffReport {
                file: PathBuf::from("default.nix"),
                attr: "pkgs.fast".to_string(),
                report: None,
                failure: None,
                oracle_stats: Some(NixInstantiateStats {
                    drv_path: PathBuf::from("/nix/store/fast.drv"),
                    stats: serde_json::json!({}),
                    elapsed: std::time::Duration::from_millis(500),
                }),
            },
            AttrDiffReport {
                file: PathBuf::from("default.nix"),
                attr: "pkgs.slow".to_string(),
                report: None,
                failure: None,
                oracle_stats: Some(NixInstantiateStats {
                    drv_path: PathBuf::from("/nix/store/slow.drv"),
                    stats: serde_json::json!({}),
                    elapsed: std::time::Duration::from_millis(1500),
                }),
            },
        ];

        let value = corpus_json(
            &reports,
            "native-test",
            &repro_config(),
            Path::new("default.nix"),
            DiffMode::Byte,
            None,
        );

        assert_eq!(value["file"], "default.nix");
        assert_eq!(value["oracle_stats_summary"]["captured"], 2);
        assert_eq!(
            value["oracle_stats_summary"]["elapsed"]["total_seconds"],
            2.0
        );
        assert_eq!(
            value["oracle_stats_summary"]["elapsed"]["total_nanos"],
            2_000_000_000
        );
        assert_eq!(
            value["oracle_stats_summary"]["elapsed"]["average_seconds"],
            1.0
        );
        assert_eq!(
            value["oracle_stats_summary"]["elapsed"]["average_nanos"],
            1_000_000_000
        );
    }

    #[test]
    fn divergence_error_renders_count() {
        let error = NixDiffReportedFailure::diverged(3);

        assert_eq!(error.to_string(), "drv diff found 3 divergence(s)");
    }

    #[test]
    fn reproduction_command_preserves_eval_config_and_quotes_shell_words() -> Result<()> {
        let mut config = repro_config();
        config.set_eval_mode(NixEvalMode::Restricted);
        config.set_current_system("aos-test-target")?;
        config.add_allowed_path("/aos/src")?;
        config.add_allowed_uri("https://cache.example/")?;
        config.set_trace_verbose(true);
        config.set_nix_compat_profile(NixCompatProfile::Nix2_34_8);
        config.reset_reported_nix_version();

        let args = reproduction_args(
            &config,
            Path::new("path with spaces/default.nix"),
            "pkgs.o'clock",
            DiffMode::Structural,
        );
        let args_as_str = args.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            args_as_str,
            [
                "aos",
                "--nix-compat=2.34.8",
                "--trace-verbose",
                "--eval-system=aos-test-target",
                "--restrict-eval",
                "--eval-allow-path=/aos/src",
                "--eval-allow-uri=https://cache.example/",
                "nix-diff",
                "--attr=pkgs.o'clock",
                "--mode=structural",
                "--",
                "path with spaces/default.nix",
            ]
        );

        assert_eq!(
            reproduction_command(
                &config,
                Path::new("path with spaces/default.nix"),
                "pkgs.o'clock",
                DiffMode::Structural,
            ),
            "aos --nix-compat=2.34.8 --trace-verbose --eval-system=aos-test-target --restrict-eval --eval-allow-path=/aos/src --eval-allow-uri=https://cache.example/ nix-diff '--attr=pkgs.o'\\''clock' --mode=structural -- 'path with spaces/default.nix'"
        );

        let node_args = node_reproduction_args(
            Path::new("/tmp/oracle root.drv"),
            Path::new("/tmp/candidate root.drv"),
            Some(Path::new("/tmp/oracle bundle.json")),
            Some(Path::new("/tmp/candidate bundle.json")),
            DiffMode::Structural,
        );
        let node_args_as_str = node_args.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            node_args_as_str,
            [
                "aos",
                "nix-diff",
                "--oracle-drv=/tmp/oracle root.drv",
                "--candidate-drv=/tmp/candidate root.drv",
                "--oracle-drv-bundle=/tmp/oracle bundle.json",
                "--candidate-drv-bundle=/tmp/candidate bundle.json",
                "--mode=structural",
            ]
        );
        assert_eq!(
            node_reproduction_command(
                Path::new("/tmp/oracle root.drv"),
                Path::new("/tmp/candidate root.drv"),
                Some(Path::new("/tmp/oracle bundle.json")),
                Some(Path::new("/tmp/candidate bundle.json")),
                DiffMode::Structural,
            ),
            "aos nix-diff '--oracle-drv=/tmp/oracle root.drv' '--candidate-drv=/tmp/candidate root.drv' '--oracle-drv-bundle=/tmp/oracle bundle.json' '--candidate-drv-bundle=/tmp/candidate bundle.json' --mode=structural"
        );
        Ok(())
    }

    #[test]
    fn cache_validation_reproduction_args_insert_flag_before_file_separator() {
        let config = repro_config();

        let args = cache_validation_reproduction_args(
            &config,
            Path::new("path with spaces/default.nix"),
            "pkgs.zlib",
            DiffMode::Byte,
        );
        let args_as_str = args.iter().map(String::as_str).collect::<Vec<_>>();

        assert_eq!(
            args_as_str,
            [
                "aos",
                "--impure-eval",
                "nix-diff",
                "--attr=pkgs.zlib",
                "--mode=byte",
                "--cache-validation",
                "--",
                "path with spaces/default.nix",
            ]
        );
        assert_eq!(
            cache_validation_reproduction_command(
                &config,
                Path::new("path with spaces/default.nix"),
                "pkgs.zlib",
                DiffMode::Byte,
            ),
            "aos --impure-eval nix-diff --attr=pkgs.zlib --mode=byte --cache-validation -- 'path with spaces/default.nix'"
        );
    }

    #[test]
    fn report_json_renders_structural_divergence_details() {
        let report = DrvDiffReport {
            mode: DiffMode::Structural,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: Some(PathBuf::from("/nix/store/candidate.drv")),
            divergences: vec![DrvDiff::Structural {
                oracle: PathBuf::from("/nix/store/oracle.drv"),
                candidate: PathBuf::from("/nix/store/candidate.drv"),
                field: "environment".to_string(),
            }],
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let failure = report_failure(&report);
        let value = report_json(
            &report,
            "aos-nix",
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            failure.as_ref(),
            None,
        );

        assert_eq!(value["mode"], "structural");
        assert_eq!(value["divergences"][0]["kind"], "structural");
        assert_eq!(value["divergences"][0]["field"], "environment");
    }

    #[test]
    fn report_json_renders_structural_parse_divergence_details() {
        let report = DrvDiffReport {
            mode: DiffMode::Structural,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: Some(PathBuf::from("/nix/store/candidate.drv")),
            divergences: vec![DrvDiff::StructuralParse {
                side: DiffSide::Candidate,
                path: PathBuf::from("/nix/store/candidate.drv"),
                error: "parse failed".to_string(),
            }],
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let failure = report_failure(&report);
        let value = report_json(
            &report,
            "aos-nix",
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            failure.as_ref(),
            None,
        );

        assert_eq!(value["divergences"][0]["kind"], "structural_parse");
        assert_eq!(value["divergences"][0]["side"], "candidate");
        assert_eq!(value["divergences"][0]["error"], "parse failed");
    }

    #[test]
    fn pair_divergences_match_pair_local_context() {
        let pair = DrvDiffPair {
            oracle: PathBuf::from("/nix/store/oracle.drv"),
            candidate: PathBuf::from("/nix/store/candidate.drv"),
        };
        let report = DrvDiffReport {
            mode: DiffMode::Structural,
            oracle_root: Some(pair.oracle.clone()),
            candidate_root: Some(pair.candidate.clone()),
            divergences: vec![
                DrvDiff::Structural {
                    oracle: pair.oracle.clone(),
                    candidate: pair.candidate.clone(),
                    field: "environment".to_string(),
                },
                DrvDiff::StructuralParse {
                    side: DiffSide::Candidate,
                    path: pair.candidate.clone(),
                    error: "parse failed".to_string(),
                },
                DrvDiff::InputOutputs {
                    parent_oracle: pair.oracle.clone(),
                    parent_candidate: pair.candidate.clone(),
                    oracle: PathBuf::from("/nix/store/input-oracle.drv"),
                    candidate: PathBuf::from("/nix/store/input-candidate.drv"),
                    oracle_outputs: vec!["out".to_string()],
                    candidate_outputs: vec!["dev".to_string()],
                },
                DrvDiff::Bytes {
                    oracle: PathBuf::from("/nix/store/other-oracle.drv"),
                    candidate: PathBuf::from("/nix/store/other-candidate.drv"),
                },
                DrvDiff::Evaluation {
                    side: DiffSide::Candidate,
                    error: "unsupported".to_string(),
                },
            ],
            root_divergences: vec![pair.clone()],
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let kinds = pair_divergences(&report, &pair)
            .map(diff_json)
            .map(|value| value["kind"].clone())
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            [
                serde_json::Value::String("structural".to_string()),
                serde_json::Value::String("structural_parse".to_string()),
                serde_json::Value::String("input_outputs".to_string()),
            ]
        );

        let root_report = root_report_json(
            &report,
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            &pair,
        );
        assert_eq!(
            root_report["divergences"][2]["parent_oracle"],
            "/nix/store/oracle.drv"
        );
        assert_eq!(
            root_report["divergences"][2]["parent_candidate"],
            "/nix/store/candidate.drv"
        );
        assert_eq!(
            root_report["divergences"][2]["oracle"],
            "/nix/store/input-oracle.drv"
        );
        assert_eq!(
            root_report["divergences"][2]["candidate"],
            "/nix/store/input-candidate.drv"
        );
    }

    #[test]
    fn pair_divergences_keep_parent_edge_context_off_child_roots() {
        let parent = DrvDiffPair {
            oracle: PathBuf::from("/nix/store/parent-oracle.drv"),
            candidate: PathBuf::from("/nix/store/parent-candidate.drv"),
        };
        let child = DrvDiffPair {
            oracle: PathBuf::from("/nix/store/child-oracle.drv"),
            candidate: PathBuf::from("/nix/store/child-candidate.drv"),
        };
        let report = DrvDiffReport {
            mode: DiffMode::Structural,
            oracle_root: Some(parent.oracle.clone()),
            candidate_root: Some(parent.candidate.clone()),
            divergences: vec![
                DrvDiff::InputOutputs {
                    parent_oracle: parent.oracle.clone(),
                    parent_candidate: parent.candidate.clone(),
                    oracle: child.oracle.clone(),
                    candidate: child.candidate.clone(),
                    oracle_outputs: vec!["out".to_string()],
                    candidate_outputs: vec!["dev".to_string()],
                },
                DrvDiff::Structural {
                    oracle: child.oracle.clone(),
                    candidate: child.candidate.clone(),
                    field: "environment".to_string(),
                },
            ],
            root_divergences: vec![child.clone()],
            contaminated_divergences: vec![parent],
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let kinds = pair_divergences(&report, &child)
            .map(diff_json)
            .map(|value| value["kind"].clone())
            .collect::<Vec<_>>();

        assert_eq!(kinds, [serde_json::Value::String("structural".to_string())]);
    }

    #[test]
    fn report_json_renders_evaluation_mismatch_details() {
        let report = DrvDiffReport {
            mode: DiffMode::Path,
            oracle_root: None,
            candidate_root: None,
            divergences: vec![DrvDiff::EvaluationMismatch {
                oracle_error: "type error".to_string(),
                candidate_error: "unsupported feature".to_string(),
            }],
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let failure = report_failure(&report);
        let value = report_json(
            &report,
            "aos-nix",
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            failure.as_ref(),
            None,
        );

        assert_eq!(value["matched"], false);
        assert_eq!(value["error"], "drv diff found 1 divergence(s)");
        assert_eq!(value["divergences"][0]["kind"], "evaluation_mismatch");
        assert_eq!(value["divergences"][0]["oracle_error"], "type error");
        assert_eq!(
            value["divergences"][0]["candidate_error"],
            "unsupported feature"
        );
    }

    #[test]
    fn report_failure_rejects_empty_comparison() {
        let report = DrvDiffReport {
            mode: DiffMode::Path,
            oracle_root: None,
            candidate_root: None,
            divergences: Vec::new(),
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let failure = report_failure(&report).expect("empty comparison should fail");
        let value = report_json(
            &report,
            "aos-nix",
            &repro_config(),
            Path::new("default.nix"),
            "pkgs.hello",
            Some(&failure),
            None,
        );

        assert_eq!(
            failure.to_string(),
            "drv diff produced no derivation output to compare"
        );
        assert_eq!(value["matched"], false);
        assert_eq!(
            value["error"],
            "drv diff produced no derivation output to compare"
        );
    }

    #[test]
    fn report_failure_rejects_incomplete_comparison() {
        let report = DrvDiffReport {
            mode: DiffMode::Path,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: None,
            divergences: Vec::new(),
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };

        let failure = report_failure(&report).expect("incomplete comparison should fail");

        assert_eq!(
            failure.to_string(),
            "drv diff produced incomplete derivation output to compare"
        );
    }

    #[test]
    fn corpus_json_renders_aggregate_and_attr_reports() {
        let report = DrvDiffReport {
            mode: DiffMode::Byte,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: Some(PathBuf::from("/nix/store/candidate.drv")),
            divergences: vec![DrvDiff::Bytes {
                oracle: PathBuf::from("/nix/store/oracle.drv"),
                candidate: PathBuf::from("/nix/store/candidate.drv"),
            }],
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };
        let attr_report = AttrDiffReport {
            file: PathBuf::from("default.nix"),
            attr: "pkgs.hello".to_string(),
            failure: report_failure(&report),
            report: Some(report),
            oracle_stats: None,
        };
        let reports = vec![attr_report];
        let failure = corpus_failure(&reports);

        let value = corpus_json(
            &reports,
            "native-test",
            &repro_config(),
            Path::new("default.nix"),
            DiffMode::Byte,
            failure.as_ref(),
        );

        assert_eq!(value["matched"], false);
        assert_eq!(value["attrs_checked"], 1);
        assert_eq!(value["attrs_failed"], 1);
        assert_eq!(value["divergence_count"], 1);
        assert_eq!(value["file"], "default.nix");
        assert_eq!(
            value["error"],
            "drv diff failed for 1 attribute(s) with 1 divergence(s)"
        );
        assert_eq!(value["reports"][0]["attr"], "pkgs.hello");
        assert_eq!(value["reports"][0]["file"], "default.nix");
        assert_eq!(value["reports"][0]["candidate"], "native-test");
        assert_eq!(
            value["reports"][0]["reproduce"],
            "aos --impure-eval nix-diff --attr=pkgs.hello --mode=byte -- default.nix"
        );
        assert_eq!(value["reports"][0]["divergences"][0]["kind"], "bytes");
        assert!(value.get("oracle_stats_summary").is_none());
    }

    #[test]
    fn smoke_attrs_start_with_zlib_witness() {
        assert_eq!(smoke_attrs(), ["pkgs.zlib"]);
    }

    #[test]
    fn smoke_corpus_selects_zlib_witness() -> Result<()> {
        let selection = corpus_entries(
            &NixCli::new(0),
            Path::new("default.nix"),
            true,
            false,
            false,
        )?;

        assert_eq!(selection.entries.len(), 1);
        assert_eq!(selection.entries[0].file, PathBuf::from("default.nix"));
        assert_eq!(selection.entries[0].attr, "pkgs.zlib");
        Ok(())
    }

    #[test]
    fn corpus_failure_rejects_one_divergent_attr_among_matches() {
        let matched = AttrDiffReport {
            file: PathBuf::from("default.nix"),
            attr: "pkgs.good".to_string(),
            failure: None,
            report: Some(DrvDiffReport {
                mode: DiffMode::Byte,
                oracle_root: Some(PathBuf::from("/nix/store/good.drv")),
                candidate_root: Some(PathBuf::from("/nix/store/good.drv")),
                divergences: Vec::new(),
                root_divergences: Vec::new(),
                contaminated_divergences: Vec::new(),
                file_backed_pairs: Vec::new(),
                node_artifacts: Vec::new(),
            }),
            oracle_stats: None,
        };
        let divergent_report = DrvDiffReport {
            mode: DiffMode::Byte,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: Some(PathBuf::from("/nix/store/candidate.drv")),
            divergences: vec![DrvDiff::Bytes {
                oracle: PathBuf::from("/nix/store/oracle.drv"),
                candidate: PathBuf::from("/nix/store/candidate.drv"),
            }],
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };
        let divergent = AttrDiffReport {
            file: PathBuf::from("default.nix"),
            attr: "pkgs.bad".to_string(),
            failure: report_failure(&divergent_report),
            report: Some(divergent_report),
            oracle_stats: None,
        };
        let reports = vec![matched, divergent];

        let failure = corpus_failure(&reports).expect("one divergent attr should fail the corpus");

        assert_eq!(
            failure.to_string(),
            "drv diff failed for 1 attribute(s) with 1 divergence(s)"
        );

        let value = corpus_json(
            &reports,
            "native-test",
            &repro_config(),
            Path::new("default.nix"),
            DiffMode::Byte,
            Some(&failure),
        );

        assert_eq!(value["matched"], false);
        assert_eq!(value["attrs_checked"], 2);
        assert_eq!(value["attrs_failed"], 1);
        assert_eq!(value["divergence_count"], 1);
    }

    #[test]
    fn corpus_failure_counts_attrs_without_divergences() {
        let report = DrvDiffReport {
            mode: DiffMode::Path,
            oracle_root: None,
            candidate_root: None,
            divergences: Vec::new(),
            root_divergences: Vec::new(),
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
            node_artifacts: Vec::new(),
        };
        let attr_report = AttrDiffReport {
            file: PathBuf::from("default.nix"),
            attr: "pkgs.empty".to_string(),
            failure: report_failure(&report),
            report: Some(report),
            oracle_stats: None,
        };

        let failure = corpus_failure(&[attr_report]).expect("empty comparison should fail");

        assert_eq!(failure.to_string(), "drv diff failed for 1 attribute(s)");
    }

    #[test]
    fn corpus_json_renders_hard_attr_errors() {
        let attr_report = AttrDiffReport {
            file: PathBuf::from("default.nix"),
            attr: "pkgs.bad".to_string(),
            report: None,
            failure: Some(NixDiffReportedFailure::attr_error(
                "diffing pkgs.bad: missing in-memory drv bytes".to_string(),
            )),
            oracle_stats: None,
        };
        let reports = vec![attr_report];
        let failure = corpus_failure(&reports);

        let value = corpus_json(
            &reports,
            "native-test",
            &repro_config(),
            Path::new("default.nix"),
            DiffMode::Structural,
            failure.as_ref(),
        );

        assert_eq!(value["matched"], false);
        assert_eq!(value["attrs_checked"], 1);
        assert_eq!(value["attrs_failed"], 1);
        assert_eq!(value["divergence_count"], 0);
        assert_eq!(value["error"], "drv diff failed for 1 attribute(s)");
        assert_eq!(value["reports"][0]["attr"], "pkgs.bad");
        assert_eq!(value["reports"][0]["file"], "default.nix");
        assert_eq!(value["reports"][0]["mode"], "structural");
        assert_eq!(
            value["reports"][0]["reproduce"],
            "aos --impure-eval nix-diff --attr=pkgs.bad --mode=structural -- default.nix"
        );
        assert!(value["reports"][0].get("oracle_stats").is_none());
        assert_eq!(
            value["reports"][0]["error"],
            "diffing pkgs.bad: missing in-memory drv bytes"
        );
        assert!(
            value["reports"][0]["divergences"]
                .as_array()
                .expect("divergences should be an array")
                .is_empty()
        );
    }

    #[test]
    fn package_attr_expr_absolutizes_relative_file_and_guards_attr_probes() -> Result<()> {
        let expr = package_attr_expr(Path::new("default.nix"))?;

        assert!(expr.contains("builtins.tryEval"));
        assert!(expr.contains("if probe.success then probe.value else true"));
        assert!(!expr.contains("builtins.toPath \"default.nix\""));

        Ok(())
    }

    #[test]
    fn system_attr_expr_absolutizes_relative_file_and_selects_toplevels() -> Result<()> {
        let expr = system_attr_expr(Path::new("default.nix"))?;

        assert!(expr.contains("root ? systems"));
        assert!(expr.contains("systems.${name}.build.toplevel"));
        assert!(!expr.contains("builtins.toPath \"default.nix\""));

        Ok(())
    }

    #[test]
    fn explicit_toolchain_corpus_names_foundational_roots() {
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"stdenv.bootstrap.gcc"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"stdenv.gccStage2"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.rust-1_74"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.rust"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.openjdk-8"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.openjdk"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.bazel-bootstrap"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.bazel"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.llvm-17"));
        assert!(EXPLICIT_TOOLCHAIN_CORPUS_ATTRS.contains(&"pkgs.llvm"));
    }

    #[test]
    fn gcc_toolchain_tier_components_name_derivation_roots() {
        assert!(GCC_TOOLCHAIN_TIER_COMPONENTS.contains(&"gcc"));
        assert!(GCC_TOOLCHAIN_TIER_COMPONENTS.contains(&"gccStage2"));
        assert!(GCC_TOOLCHAIN_TIER_COMPONENTS.contains(&"glibc"));
        assert!(GCC_TOOLCHAIN_TIER_COMPONENTS.contains(&"binutils"));
        assert!(GCC_TOOLCHAIN_TIER_COMPONENTS.contains(&"linuxHeaders"));
        assert!(GCC_TOOLCHAIN_TIER_COMPONENTS.contains(&"bash"));
    }

    #[test]
    fn toolchain_attr_expr_absolutizes_and_filters_existing_derivations() -> Result<()> {
        let expr = toolchain_attr_expr(Path::new("default.nix"))?;

        assert!(expr.contains("builtins.hasAttr name value"));
        assert!(expr.contains("builtins.tryEval"));
        assert!(expr.contains("if probe.success then probe.value else false"));
        assert!(expr.contains("root.stdenv.toolchainTiers"));
        assert!(expr.contains("builtins.attrNames tiers"));
        assert!(expr.contains("stdenv.toolchainTiers.${tierName}.${componentName}"));
        assert!(expr.contains("\"gccStage2\""));
        assert!(expr.contains(
            "attr = \"stdenv.bootstrap.gcc\"; path = [ \"stdenv\" \"bootstrap\" \"gcc\" ];"
        ));
        assert!(expr.contains("attr = \"pkgs.rust-1_74\"; path = [ \"pkgs\" \"rust-1_74\" ];"));
        assert!(!expr.contains("builtins.toPath \"default.nix\""));

        Ok(())
    }

    #[test]
    fn fuzz_source_seed_uses_string_attr_path_segments() -> Result<()> {
        let entry = CorpusEntry {
            file: PathBuf::from("/repo/default.nix"),
            attr: "pkgs.rust-1_74".to_string(),
        };
        let config = NixEvalConfig::with_current_system("x86_64-linux")?;

        let seed = render_fuzz_source_seed(&entry, &config)?;

        assert_eq!(seed.name, "pkgs.rust-1_74");
        assert!(
            seed.source
                .contains("builtins.toPath \"/repo/default.nix\"")
        );
        assert!(
            seed.source
                .contains("loaded { system = \"x86_64-linux\"; }")
        );
        assert!(seed.source.contains("path = [ \"pkgs\" \"rust-1_74\" ];"));
        assert!(
            seed.source
                .contains("builtins.foldl' (value: name: builtins.getAttr name value) root path")
        );
        Ok(())
    }

    #[test]
    fn explicit_fuzz_source_seeds_render_requested_attrs() -> Result<()> {
        let config = NixEvalConfig::with_current_system("x86_64-linux")?;
        let attrs = vec![
            "pkgs.generated-json-smoke".to_string(),
            "conformance.eval-okay-number".to_string(),
        ];

        let seeds = fuzz_source_seeds_for_attrs(Path::new("/repo/default.nix"), &attrs, &config)?;

        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].name, "pkgs.generated-json-smoke");
        assert_eq!(seeds[0].source_file_kind, FuzzSourceFileKind::Direct);
        assert!(
            seeds[0]
                .source
                .contains("path = [ \"pkgs\" \"generated-json-smoke\" ];")
        );
        assert_eq!(seeds[1].name, "conformance.eval-okay-number");
        assert_eq!(seeds[1].source_file_kind, FuzzSourceFileKind::Direct);
        assert!(
            seeds[1]
                .source
                .contains("path = [ \"conformance\" \"eval-okay-number\" ];")
        );
        Ok(())
    }

    #[test]
    fn explicit_fuzz_source_seeds_reject_empty_attr_segments() {
        for attrs in [
            vec!["".to_string()],
            vec!["pkgs.".to_string()],
            vec!["pkgs..zlib".to_string()],
        ] {
            let error = fuzz_source_seeds_for_attrs(
                Path::new("/repo/default.nix"),
                &attrs,
                &repro_config(),
            )
            .expect_err("empty attr segments should be rejected");
            assert!(
                error
                    .to_string()
                    .contains("attribute path must not be empty"),
                "{error}"
            );
        }
    }

    fn fixture_lang_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("aos-nix")
            .join("tests")
            .join("fixtures")
            .join("lang")
    }

    #[test]
    fn conformance_corpus_generates_eval_okay_derivation_attrs() -> Result<()> {
        let generated = generated_conformance_corpus(&fixture_lang_dir())?;
        let attrs = generated
            .entries
            .iter()
            .map(|entry| entry.attr.as_str())
            .collect::<Vec<_>>();

        assert!(attrs.contains(&"conformance.eval-okay-number"));
        assert!(attrs.contains(&"conformance.eval-okay-autoargs"));
        assert!(attrs.contains(&"conformance.eval-okay-string"));
        assert!(!attrs.contains(&"conformance.eval-okay-disabled"));
        assert!(!attrs.contains(&"conformance.eval-okay-search-path"));
        assert!(!attrs.contains(&"conformance.eval-okay-recursive"));
        assert!(
            generated
                .entries
                .iter()
                .all(|entry| entry.file.ends_with("corpus.nix"))
        );

        let generated_file = generated
            .entries
            .first()
            .map(|entry| entry.file.clone())
            .ok_or_else(|| anyhow::anyhow!("generated fixture corpus should have entries"))?;
        let generated_text = fs::read_to_string(&generated_file)?;
        assert!(generated_text.starts_with("{ system ? builtins.currentSystem }:\nlet\n"));
        assert!(generated_text.contains("conformance = {"));
        assert!(generated_text.contains("eval-okay-number = mkCase"));
        assert!(generated_text.contains("builtins.tryEval (builtins.toJSON value)"));
        assert!(generated_text.contains("((import (builtins.toPath"));
        assert!(generated_text.contains("xyzzy = \"xyzzy!\";"));
        assert!(generated_text.contains(".result"));
        assert!(!generated_text.contains("eval-okay-disabled = mkCase"));
        assert!(!generated_text.contains("eval-okay-recursive = mkCase"));

        if let Some(dir) = generated_file.parent() {
            fs::remove_dir_all(dir)?;
        }

        Ok(())
    }

    #[test]
    fn conformance_flag_parser_handles_autoargs_and_attr_selection() -> Result<()> {
        let flags = vec![
            "--arg".to_string(),
            "lib".to_string(),
            "import(lang/lib.nix)".to_string(),
            "--argstr".to_string(),
            "xyzzy".to_string(),
            "xyzzy!".to_string(),
            "-A".to_string(),
            "result".to_string(),
        ];

        let config = parse_eval_okay_flags(&flags, &fixture_lang_dir()).map_err(|()| {
            anyhow::anyhow!("fixture flags should be supported by conformance wrapper")
        })?;

        assert_eq!(
            config.auto_args,
            vec![
                LangAutoArg::Expr {
                    name: "lib".to_string(),
                    expr: render_case_import(&fixture_lang_dir().join("lib.nix"))?,
                },
                LangAutoArg::Str {
                    name: "xyzzy".to_string(),
                    value: "xyzzy!".to_string(),
                },
            ]
        );
        assert_eq!(config.attr_path, vec!["result".to_string()]);
        Ok(())
    }

    #[test]
    fn conformance_flag_parser_rejects_command_line_only_flags() {
        let flags = vec![
            "--extra-experimental-features".to_string(),
            "parse-toml-timestamps".to_string(),
        ];

        assert!(parse_eval_okay_flags(&flags, &fixture_lang_dir()).is_err());
    }

    #[test]
    fn conformance_corpus_skips_lang_sh_environment_sensitive_cases() -> Result<()> {
        for name in ["eval-okay-getenv", "eval-okay-path-string-interpolation"] {
            let case = LangCase {
                name: name.to_string(),
                source: fixture_lang_dir().join(format!("{name}.nix")),
                expected: None,
                expected_xml: None,
                flags: Vec::new(),
                disabled: false,
            };

            assert!(!is_supported_conformance_case(&case)?, "{name}");
        }
        Ok(())
    }

    #[test]
    fn extend_unique_preserves_first_seen_order() {
        let root = PathBuf::from("default.nix");
        let generated = PathBuf::from("/tmp/generated/corpus.nix");
        let mut entries = vec![CorpusEntry {
            file: root.clone(),
            attr: "pkgs.hello".to_string(),
        }];
        let mut seen = entries
            .iter()
            .map(|entry| (entry.file.clone(), entry.attr.clone()))
            .collect::<BTreeSet<_>>();

        extend_unique_entries(
            &mut entries,
            &mut seen,
            vec![
                CorpusEntry {
                    file: root.clone(),
                    attr: "pkgs.hello".to_string(),
                },
                CorpusEntry {
                    file: root,
                    attr: "systems.server.build.toplevel".to_string(),
                },
                CorpusEntry {
                    file: generated,
                    attr: "conformance.eval-okay-number".to_string(),
                },
            ],
        );

        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.attr.as_str())
                .collect::<Vec<_>>(),
            vec![
                "pkgs.hello",
                "systems.server.build.toplevel",
                "conformance.eval-okay-number"
            ]
        );
    }

    #[test]
    fn nix_string_literal_escapes_interpolation_and_control_chars() {
        assert_eq!(
            nix_string_literal("a\"b\\c\n${x}"),
            "\"a\\\"b\\\\c\\n\\${x}\""
        );
    }
}
