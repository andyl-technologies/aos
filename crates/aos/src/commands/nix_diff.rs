//! `aos nix-diff` -- compare evaluator `.drv` output.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use aos_core::error::AosError;
use aos_core::nix::diff::{DiffMode, DiffSide, DrvDiff, DrvDiffPair, DrvDiffReport, diff_closure};
use aos_core::nix::{
    NixCli, NixEval, NixEvalConfig, NixRunner, select_native_diff_candidate_with_config,
};
use aos_core::output::{OutputMode, Printer};

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
    eval_config: NixEvalConfig,
    file: &Path,
    attr: Option<&str>,
    all: bool,
    mode: DiffMode,
) -> Result<()> {
    let candidate = select_native_diff_candidate_with_config(verbose, eval_config.clone())?;
    NixRunner::ensure_nix_instantiate_available()?;
    let oracle = NixCli::with_eval_config(verbose, eval_config);
    let candidate_name = candidate.name();

    if all {
        return run_all(
            printer,
            &oracle,
            candidate.as_ref(),
            candidate_name,
            file,
            mode,
        );
    }

    let attr = attr.ok_or_else(|| AosError::InvalidArgument {
        message: "provide --attr <ATTR> or --all".to_string(),
    })?;

    let report = diff_closure(&oracle, candidate.as_ref(), file, attr, mode)?;
    let failure = report_failure(&report);

    if printer.json_if_active(&report_json(&report, candidate_name, failure.as_ref())) {
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
        return Ok(());
    };

    if printer.mode() == OutputMode::Quiet {
        printer.error(&failure.to_string());
    } else if report.divergences.is_empty() {
        printer.warning(&failure.to_string());
    } else {
        printer.warning(&format!(
            "drv diff found {} divergence(s): nix-cli vs {candidate_name}",
            report.divergences.len()
        ));
        for divergence in &report.divergences {
            printer.plain(&format!("  - {}", render_diff(divergence)));
        }
        render_divergence_classes(printer, &report, "  ");
    }
    Err(failure.into())
}

fn run_all(
    printer: &Printer,
    oracle: &NixCli,
    candidate: &dyn NixEval,
    candidate_name: &str,
    file: &Path,
    mode: DiffMode,
) -> Result<()> {
    let attrs = package_attrs(oracle, file)?;
    if attrs.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-diff --all found no derivations under pkgs".to_string(),
        }
        .into());
    }

    printer.info(&format!(
        "Comparing {} package derivation(s)...",
        attrs.len()
    ));

    let mut reports = Vec::with_capacity(attrs.len());
    for attr in attrs {
        match diff_closure(oracle, candidate, file, &attr, mode)
            .with_context(|| format!("diffing {attr}"))
        {
            Ok(report) => {
                let failure = report_failure(&report);
                reports.push(AttrDiffReport {
                    attr,
                    report: Some(report),
                    failure,
                });
            }
            Err(error) => {
                reports.push(AttrDiffReport {
                    attr,
                    report: None,
                    failure: Some(NixDiffReportedFailure::attr_error(format!("{error:#}"))),
                });
            }
        }
    }

    let failure = corpus_failure(&reports);

    if printer.json_if_active(&corpus_json(
        &reports,
        candidate_name,
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
            "drv diff matched {} package derivation(s): nix-cli vs {candidate_name} ({mode:?})",
            reports.len()
        ));
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
            "drv diff failed for {failed} of {} package derivation(s): nix-cli vs {candidate_name}",
            reports.len()
        ));
        for attr_report in reports.iter().filter(|report| report.failure.is_some()) {
            let failure = attr_report
                .failure
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "drv diff failed".to_string());
            printer.plain(&format!("  - {}: {failure}", attr_report.attr));
            if let Some(report) = &attr_report.report {
                for divergence in &report.divergences {
                    printer.plain(&format!("      - {}", render_diff(divergence)));
                }
                render_divergence_classes(printer, report, "      ");
            }
        }
    }
    Err(failure.into())
}

#[derive(Debug)]
struct AttrDiffReport {
    attr: String,
    report: Option<DrvDiffReport>,
    failure: Option<NixDiffReportedFailure>,
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
    failure: Option<&NixDiffReportedFailure>,
) -> serde_json::Value {
    serde_json::json!({
        "mode": mode_name(report.mode),
        "oracle": "nix-cli",
        "candidate": candidate_name,
        "matched": failure.is_none(),
        "error": failure.map(ToString::to_string),
        "oracle_root": report.oracle_root.as_ref().map(|path| path.to_string_lossy().to_string()),
        "candidate_root": report.candidate_root.as_ref().map(|path| path.to_string_lossy().to_string()),
        "root_divergences": report.root_divergences.iter().map(pair_json).collect::<Vec<_>>(),
        "contaminated_divergences": report.contaminated_divergences.iter().map(pair_json).collect::<Vec<_>>(),
        "divergences": report.divergences.iter().map(diff_json).collect::<Vec<_>>(),
    })
}

fn corpus_json(
    reports: &[AttrDiffReport],
    candidate_name: &str,
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

    serde_json::json!({
        "mode": mode_name(mode),
        "oracle": "nix-cli",
        "candidate": candidate_name,
        "matched": failure.is_none(),
        "error": failure.map(ToString::to_string),
        "attrs_checked": reports.len(),
        "attrs_failed": failed_attrs,
        "divergence_count": divergence_count,
        "reports": reports.iter().map(|report| attr_report_json(report, candidate_name, mode)).collect::<Vec<_>>(),
    })
}

fn attr_report_json(
    report: &AttrDiffReport,
    candidate_name: &str,
    mode: DiffMode,
) -> serde_json::Value {
    let Some(diff_report) = &report.report else {
        return serde_json::json!({
            "attr": report.attr,
            "mode": mode_name(mode),
            "oracle": "nix-cli",
            "candidate": candidate_name,
            "matched": false,
            "error": report.failure.as_ref().map(ToString::to_string),
            "oracle_root": null,
            "candidate_root": null,
            "root_divergences": [],
            "contaminated_divergences": [],
            "divergences": [],
        });
    };

    let mut value = report_json(diff_report, candidate_name, report.failure.as_ref());
    if let serde_json::Value::Object(object) = &mut value {
        object.insert(
            "attr".to_string(),
            serde_json::Value::String(report.attr.clone()),
        );
    }
    value
}

fn pair_json(pair: &DrvDiffPair) -> serde_json::Value {
    serde_json::json!({
        "oracle": pair.oracle.to_string_lossy(),
        "candidate": pair.candidate.to_string_lossy(),
    })
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
            oracle,
            candidate,
            oracle_outputs,
            candidate_outputs,
        } => serde_json::json!({
            "kind": "input_outputs",
            "oracle": oracle.to_string_lossy(),
            "candidate": candidate.to_string_lossy(),
            "oracle_outputs": oracle_outputs,
            "candidate_outputs": candidate_outputs,
        }),
    }
}

fn render_divergence_classes(printer: &Printer, report: &DrvDiffReport, indent: &str) {
    if !report.root_divergences.is_empty() {
        printer.plain(&format!("{indent}root divergence nodes:"));
        for pair in &report.root_divergences {
            printer.plain(&format!(
                "{indent}  - oracle={} candidate={}",
                pair.oracle.display(),
                pair.candidate.display()
            ));
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
            oracle,
            candidate,
            oracle_outputs,
            candidate_outputs,
        } => format!(
            "input outputs: oracle={} {:?} candidate={} {:?}",
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
    use std::path::PathBuf;

    #[test]
    fn report_json_renders_divergence_details() {
        let report = DrvDiffReport {
            mode: DiffMode::Byte,
            oracle_root: Some(PathBuf::from("/nix/store/oracle.drv")),
            candidate_root: Some(PathBuf::from("/nix/store/candidate.drv")),
            divergences: vec![DrvDiff::RootPath {
                oracle: PathBuf::from("/nix/store/oracle.drv"),
                candidate: PathBuf::from("/nix/store/candidate.drv"),
            }],
            root_divergences: vec![DrvDiffPair {
                oracle: PathBuf::from("/nix/store/oracle.drv"),
                candidate: PathBuf::from("/nix/store/candidate.drv"),
            }],
            contaminated_divergences: Vec::new(),
        };

        let failure = report_failure(&report);
        let value = report_json(&report, "aos-nix", failure.as_ref());

        assert_eq!(value["mode"], "byte");
        assert_eq!(value["oracle"], "nix-cli");
        assert_eq!(value["candidate"], "aos-nix");
        assert_eq!(value["matched"], false);
        assert_eq!(value["error"], "drv diff found 1 divergence(s)");
        assert_eq!(value["divergences"][0]["kind"], "root_path");
        assert_eq!(
            value["root_divergences"][0]["oracle"],
            "/nix/store/oracle.drv"
        );
        assert!(
            value["contaminated_divergences"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn divergence_error_renders_count() {
        let error = NixDiffReportedFailure::diverged(3);

        assert_eq!(error.to_string(), "drv diff found 3 divergence(s)");
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
        };

        let failure = report_failure(&report);
        let value = report_json(&report, "aos-nix", failure.as_ref());

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
        };

        let failure = report_failure(&report);
        let value = report_json(&report, "aos-nix", failure.as_ref());

        assert_eq!(value["divergences"][0]["kind"], "structural_parse");
        assert_eq!(value["divergences"][0]["side"], "candidate");
        assert_eq!(value["divergences"][0]["error"], "parse failed");
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
        };

        let failure = report_failure(&report);
        let value = report_json(&report, "aos-nix", failure.as_ref());

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
        };

        let failure = report_failure(&report).expect("empty comparison should fail");
        let value = report_json(&report, "aos-nix", Some(&failure));

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
        };
        let attr_report = AttrDiffReport {
            attr: "pkgs.hello".to_string(),
            failure: report_failure(&report),
            report: Some(report),
        };
        let reports = vec![attr_report];
        let failure = corpus_failure(&reports);

        let value = corpus_json(&reports, "native-test", DiffMode::Byte, failure.as_ref());

        assert_eq!(value["matched"], false);
        assert_eq!(value["attrs_checked"], 1);
        assert_eq!(value["attrs_failed"], 1);
        assert_eq!(value["divergence_count"], 1);
        assert_eq!(
            value["error"],
            "drv diff failed for 1 attribute(s) with 1 divergence(s)"
        );
        assert_eq!(value["reports"][0]["attr"], "pkgs.hello");
        assert_eq!(value["reports"][0]["candidate"], "native-test");
        assert_eq!(value["reports"][0]["divergences"][0]["kind"], "bytes");
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
        };
        let attr_report = AttrDiffReport {
            attr: "pkgs.empty".to_string(),
            failure: report_failure(&report),
            report: Some(report),
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
        };
        let reports = vec![attr_report];
        let failure = corpus_failure(&reports);

        let value = corpus_json(
            &reports,
            "native-test",
            DiffMode::Structural,
            failure.as_ref(),
        );

        assert_eq!(value["matched"], false);
        assert_eq!(value["attrs_checked"], 1);
        assert_eq!(value["attrs_failed"], 1);
        assert_eq!(value["divergence_count"], 0);
        assert_eq!(value["error"], "drv diff failed for 1 attribute(s)");
        assert_eq!(value["reports"][0]["attr"], "pkgs.bad");
        assert_eq!(value["reports"][0]["mode"], "structural");
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
    fn nix_string_literal_escapes_interpolation_and_control_chars() {
        assert_eq!(
            nix_string_literal("a\"b\\c\n${x}"),
            "\"a\\\"b\\\\c\\n\\${x}\""
        );
    }
}
