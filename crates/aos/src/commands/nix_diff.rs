//! `aos nix-diff` -- compare evaluator `.drv` output.

use std::path::Path;

use anyhow::Result;

use aos_core::nix::diff::{DiffMode, DiffSide, DrvDiff, DrvDiffReport, diff_closure};
use aos_core::nix::{NixCli, NixEvalConfig, NixRunner, select_native_diff_candidate_with_config};
use aos_core::output::{OutputMode, Printer};

/// Error returned after `aos nix-diff` has already rendered a failure report.
#[derive(Debug)]
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
    attr: &str,
    mode: DiffMode,
) -> Result<()> {
    let candidate = select_native_diff_candidate_with_config(verbose, eval_config.clone())?;
    NixRunner::ensure_nix_instantiate_available()?;
    let oracle = NixCli::with_eval_config(verbose, eval_config);
    let candidate_name = candidate.name();
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
    }
    Err(failure.into())
}

fn report_failure(report: &DrvDiffReport) -> Option<NixDiffReportedFailure> {
    if report.is_match() && report.oracle_root.is_some() && report.candidate_root.is_some() {
        return None;
    }

    if report.oracle_root.is_none() && report.candidate_root.is_none() {
        return Some(NixDiffReportedFailure::no_drv_output());
    }

    Some(NixDiffReportedFailure::diverged(report.divergences.len()))
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
        "divergences": report.divergences.iter().map(diff_json).collect::<Vec<_>>(),
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
        };

        let failure = report_failure(&report);
        let value = report_json(&report, "aos-nix", failure.as_ref());

        assert_eq!(value["mode"], "byte");
        assert_eq!(value["oracle"], "nix-cli");
        assert_eq!(value["candidate"], "aos-nix");
        assert_eq!(value["matched"], false);
        assert_eq!(value["error"], "drv diff found 1 divergence(s)");
        assert_eq!(value["divergences"][0]["kind"], "root_path");
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
        };

        let failure = report_failure(&report);
        let value = report_json(&report, "aos-nix", failure.as_ref());

        assert_eq!(value["divergences"][0]["kind"], "structural_parse");
        assert_eq!(value["divergences"][0]["side"], "candidate");
        assert_eq!(value["divergences"][0]["error"], "parse failed");
    }

    #[test]
    fn report_failure_rejects_empty_comparison() {
        let report = DrvDiffReport {
            mode: DiffMode::Path,
            oracle_root: None,
            candidate_root: None,
            divergences: Vec::new(),
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
}
