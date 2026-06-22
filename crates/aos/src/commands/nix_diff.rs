//! `aos nix-diff` -- compare evaluator `.drv` output.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use aos_core::error::AosError;
use aos_core::nix::diff::{
    DiffMode, DiffSide, DrvDiff, DrvDiffPair, DrvDiffReport, diff_closure, diff_drv_pair,
};
use aos_core::nix::{
    NixCli, NixEval, NixEvalConfig, NixEvalMode, NixInstantiateStats, NixRunner,
    select_native_diff_candidate_with_config,
};
use aos_core::output::{OutputMode, Printer};

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
    all: bool,
    systems: bool,
    mode: DiffMode,
    oracle_stats: bool,
) -> Result<()> {
    if eval_config.eval_mode() == NixEvalMode::Ambient {
        eval_config.set_eval_mode(NixEvalMode::Impure);
    }
    let candidate = select_native_diff_candidate_with_config(verbose, eval_config.clone())?;
    NixRunner::ensure_nix_instantiate_available()?;
    let oracle = NixCli::with_eval_config(verbose, eval_config.clone());
    let candidate_name = candidate.name();

    if all || systems {
        return run_all(
            printer,
            &oracle,
            candidate.as_ref(),
            candidate_name,
            &eval_config,
            file,
            all,
            systems,
            mode,
            oracle_stats,
        );
    }

    let attr = attr.ok_or_else(|| AosError::InvalidArgument {
        message: "provide --attr <ATTR>, --all, or --systems".to_string(),
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
    mode: DiffMode,
) -> Result<()> {
    let report = diff_drv_pair(oracle_drv, candidate_drv, mode)?;
    let failure = report_failure(&report);

    if printer.json_if_active(&drv_pair_report_json(
        &report,
        oracle_drv,
        candidate_drv,
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
        render_node_reproduction_hint(printer, oracle_drv, candidate_drv, mode, "  ");
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
    include_packages: bool,
    include_systems: bool,
    mode: DiffMode,
    oracle_stats: bool,
) -> Result<()> {
    let attrs = corpus_attrs(oracle, file, include_packages, include_systems)?;
    if attrs.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-diff corpus selection found no derivations".to_string(),
        }
        .into());
    }

    printer.info(&format!(
        "Comparing {} selected derivation(s)...",
        attrs.len()
    ));

    let mut reports = Vec::with_capacity(attrs.len());
    for attr in attrs {
        let stats = if oracle_stats {
            match oracle
                .instantiate_with_stats(file, &attr)
                .with_context(|| format!("capturing nix-cli stats for {attr}"))
            {
                Ok(stats) => Some(stats),
                Err(error) => {
                    reports.push(AttrDiffReport {
                        attr,
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
        match diff_closure(oracle, candidate, file, &attr, mode)
            .with_context(|| format!("diffing {attr}"))
        {
            Ok(report) => {
                let failure = report_failure(&report);
                reports.push(AttrDiffReport {
                    attr,
                    report: Some(report),
                    failure,
                    oracle_stats: stats,
                });
            }
            Err(error) => {
                reports.push(AttrDiffReport {
                    attr,
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
            printer.plain(&format!("  - {}: {failure}", attr_report.attr));
            render_reproduction_hint(
                printer,
                &eval_config,
                file,
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
                    file,
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

#[derive(Debug)]
struct AttrDiffReport {
    attr: String,
    report: Option<DrvDiffReport>,
    failure: Option<NixDiffReportedFailure>,
    oracle_stats: Option<NixInstantiateStats>,
}

fn corpus_attrs(
    oracle: &NixCli,
    file: &Path,
    include_packages: bool,
    include_systems: bool,
) -> Result<Vec<String>> {
    let mut attrs = Vec::new();
    let mut seen = BTreeSet::new();

    if include_packages {
        extend_unique(&mut attrs, &mut seen, package_attrs(oracle, file)?);
        extend_unique(&mut attrs, &mut seen, toolchain_attrs(oracle, file)?);
    }
    if include_systems {
        extend_unique(&mut attrs, &mut seen, system_attrs(oracle, file)?);
    }

    Ok(attrs)
}

fn extend_unique(attrs: &mut Vec<String>, seen: &mut BTreeSet<String>, new_attrs: Vec<String>) {
    for attr in new_attrs {
        if seen.insert(attr.clone()) {
            attrs.push(attr);
        }
    }
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

    Ok(format!(
        r#"
let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {{}} else loaded;
  missing = {{ __aosNixDiffMissing = true; }};
  wanted = [
    {}
  ];
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
        wanted
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
    failure: Option<&NixDiffReportedFailure>,
) -> serde_json::Value {
    serde_json::json!({
        "mode": mode_name(report.mode),
        "oracle": "oracle-drv",
        "candidate": "candidate-drv",
        "oracle_drv": oracle_drv.to_string_lossy(),
        "candidate_drv": candidate_drv.to_string_lossy(),
        "reproduce": node_reproduction_command(oracle_drv, candidate_drv, report.mode),
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
        "reports": reports.iter().map(|report| attr_report_json(report, candidate_name, eval_config, file, mode)).collect::<Vec<_>>(),
    });
    if let (serde_json::Value::Object(object), Some(summary)) =
        (&mut value, corpus_oracle_stats_aggregate(reports))
    {
        object.insert("oracle_stats_summary".to_string(), summary.json());
    }
    value
}

fn attr_report_json(
    report: &AttrDiffReport,
    candidate_name: &str,
    eval_config: &NixEvalConfig,
    file: &Path,
    mode: DiffMode,
) -> serde_json::Value {
    let Some(diff_report) = &report.report else {
        let mut value = serde_json::json!({
            "attr": report.attr,
            "mode": mode_name(mode),
            "oracle": "nix-cli",
            "candidate": candidate_name,
            "file": file.to_string_lossy(),
            "reproduce": reproduction_command(eval_config, file, &report.attr, mode),
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
        file,
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
            serde_json::Value::String(reproduction_command(eval_config, file, &report.attr, mode)),
        );
    }
    value
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
    mode: DiffMode,
    indent: &str,
) {
    printer.plain(&format!(
        "{indent}node reproduce: {}",
        node_reproduction_command(oracle_drv, candidate_drv, mode)
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

fn reproduction_args(
    eval_config: &NixEvalConfig,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> Vec<String> {
    let mut args = vec!["aos".to_string()];
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

fn node_reproduction_command(oracle_drv: &Path, candidate_drv: &Path, mode: DiffMode) -> String {
    node_reproduction_args(oracle_drv, candidate_drv, mode)
        .iter()
        .map(|arg| shell_word(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn node_reproduction_for_pair(report: &DrvDiffReport, pair: &DrvDiffPair) -> Option<String> {
    report
        .file_backed_pairs
        .iter()
        .any(|file_backed_pair| file_backed_pair == pair)
        .then(|| node_reproduction_command(&pair.oracle, &pair.candidate, report.mode))
}

fn node_reproduction_args(oracle_drv: &Path, candidate_drv: &Path, mode: DiffMode) -> Vec<String> {
    vec![
        "aos".to_string(),
        "nix-diff".to_string(),
        format!("--oracle-drv={}", oracle_drv.to_string_lossy()),
        format!("--candidate-drv={}", candidate_drv.to_string_lossy()),
        format!("--mode={}", mode_name(mode)),
    ]
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
    use std::fs;
    use std::path::{Path, PathBuf};

    fn repro_config() -> NixEvalConfig {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.clear_current_system();
        config.clear_allowed_paths();
        config.clear_allowed_uris();
        config.set_trace_verbose(false);
        config
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
        };
        let failure = report_failure(&report);

        let value = drv_pair_report_json(&report, &oracle_drv, &candidate_drv, failure.as_ref());

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
            node_reproduction_command(&oracle_drv, &candidate_drv, DiffMode::Structural)
        );
        assert_eq!(value["matched"], false);
        assert_eq!(value["error"], "drv diff found 1 divergence(s)");
        assert_eq!(
            value["root_reports"][0]["node_reproduce"],
            node_reproduction_command(&oracle_drv, &candidate_drv, DiffMode::Structural)
        );
        assert_eq!(
            value["root_reports"][0]["divergences"][0]["kind"],
            "structural"
        );
        Ok(())
    }

    #[test]
    fn root_report_json_omits_node_reproduction_without_file_backed_provenance() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle_drv = temp.path().join("oracle.drv");
        let candidate_drv = temp.path().join("candidate.drv");
        fs::write(&oracle_drv, b"stale oracle drv")?;
        fs::write(&candidate_drv, b"stale candidate drv")?;
        let report = DrvDiffReport {
            mode: DiffMode::Byte,
            oracle_root: Some(oracle_drv.clone()),
            candidate_root: Some(candidate_drv.clone()),
            divergences: vec![DrvDiff::Bytes {
                oracle: oracle_drv.clone(),
                candidate: candidate_drv.clone(),
            }],
            root_divergences: vec![DrvDiffPair {
                oracle: oracle_drv,
                candidate: candidate_drv,
            }],
            contaminated_divergences: Vec::new(),
            file_backed_pairs: Vec::new(),
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

        assert!(value["root_reports"][0].get("node_reproduce").is_none());
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
            "aos --trace-verbose --eval-system=aos-test-target --restrict-eval --eval-allow-path=/aos/src --eval-allow-uri=https://cache.example/ nix-diff '--attr=pkgs.o'\\''clock' --mode=structural -- 'path with spaces/default.nix'"
        );

        let node_args = node_reproduction_args(
            Path::new("/tmp/oracle root.drv"),
            Path::new("/tmp/candidate root.drv"),
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
                "--mode=structural",
            ]
        );
        assert_eq!(
            node_reproduction_command(
                Path::new("/tmp/oracle root.drv"),
                Path::new("/tmp/candidate root.drv"),
                DiffMode::Structural,
            ),
            "aos nix-diff '--oracle-drv=/tmp/oracle root.drv' '--candidate-drv=/tmp/candidate root.drv' --mode=structural"
        );
        Ok(())
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
        };
        let attr_report = AttrDiffReport {
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
    fn corpus_failure_rejects_one_divergent_attr_among_matches() {
        let matched = AttrDiffReport {
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
        };
        let divergent = AttrDiffReport {
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
        };
        let attr_report = AttrDiffReport {
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
    fn toolchain_attr_expr_absolutizes_and_filters_existing_derivations() -> Result<()> {
        let expr = toolchain_attr_expr(Path::new("default.nix"))?;

        assert!(expr.contains("builtins.hasAttr name value"));
        assert!(expr.contains("builtins.tryEval"));
        assert!(expr.contains("if probe.success then probe.value else false"));
        assert!(expr.contains(
            "attr = \"stdenv.bootstrap.gcc\"; path = [ \"stdenv\" \"bootstrap\" \"gcc\" ];"
        ));
        assert!(expr.contains("attr = \"pkgs.rust-1_74\"; path = [ \"pkgs\" \"rust-1_74\" ];"));
        assert!(!expr.contains("builtins.toPath \"default.nix\""));

        Ok(())
    }

    #[test]
    fn extend_unique_preserves_first_seen_order() {
        let mut attrs = vec!["pkgs.hello".to_string()];
        let mut seen = attrs.iter().cloned().collect::<BTreeSet<_>>();

        extend_unique(
            &mut attrs,
            &mut seen,
            vec![
                "pkgs.hello".to_string(),
                "systems.server.build.toplevel".to_string(),
            ],
        );

        assert_eq!(
            attrs,
            vec![
                "pkgs.hello".to_string(),
                "systems.server.build.toplevel".to_string()
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
