//! Differential `.drv` comparison over the evaluator seam.
//!
//! The native evaluator rollout needs a byte-oriented gate that compares the
//! C++ Nix oracle with a candidate [`NixEval`] implementation. This module
//! provides the library harness: instantiate both evaluators, compare root
//! paths, and optionally recurse through input derivations by reading the
//! `.drv` ATerm graph.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::NixEval;
use super::drv::{DrvInput, parse_drv_input_drvs};

/// The level of `.drv` comparison to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    /// Compare only the top-level `.drv` store path.
    Path,
    /// Compare root paths and ATerm bytes through the input-derivation closure.
    Byte,
}

/// The side of the differential comparison that diverged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSide {
    /// The C++ Nix oracle side.
    Oracle,
    /// The candidate evaluator side.
    Candidate,
}

/// A single divergence found while comparing `.drv` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrvDiff {
    /// The top-level derivation paths differ.
    RootPath {
        /// Path returned by the oracle evaluator.
        oracle: PathBuf,
        /// Path returned by the candidate evaluator.
        candidate: PathBuf,
    },
    /// One evaluator failed to instantiate while the other succeeded.
    Evaluation {
        /// The side that failed.
        side: DiffSide,
        /// The user-facing error text.
        error: String,
    },
    /// The ATerm bytes differ for a compared derivation pair.
    Bytes {
        /// Oracle-side `.drv` path.
        oracle: PathBuf,
        /// Candidate-side `.drv` path.
        candidate: PathBuf,
    },
    /// The two derivations refer to a different number of input derivations.
    InputCount {
        /// Oracle-side `.drv` path.
        oracle: PathBuf,
        /// Candidate-side `.drv` path.
        candidate: PathBuf,
        /// Number of oracle input derivations.
        oracle_count: usize,
        /// Number of candidate input derivations.
        candidate_count: usize,
    },
    /// Paired input derivations disagree on the requested output names.
    InputOutputs {
        /// Oracle-side input derivation path.
        oracle: PathBuf,
        /// Candidate-side input derivation path.
        candidate: PathBuf,
        /// Oracle-side output names.
        oracle_outputs: Vec<String>,
        /// Candidate-side output names.
        candidate_outputs: Vec<String>,
    },
}

/// Result of comparing two evaluator outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrvDiffReport {
    /// Requested comparison mode.
    pub mode: DiffMode,
    /// Top-level oracle path, when oracle instantiation succeeded.
    pub oracle_root: Option<PathBuf>,
    /// Top-level candidate path, when candidate instantiation succeeded.
    pub candidate_root: Option<PathBuf>,
    /// Divergences found during comparison.
    pub divergences: Vec<DrvDiff>,
}

impl DrvDiffReport {
    /// Returns whether the compared evaluators matched under the requested mode.
    pub fn is_match(&self) -> bool {
        self.divergences.is_empty()
    }
}

/// Instantiates and compares a derivation closure through two evaluators.
///
/// `oracle` should be the permanent C++ Nix implementation. `candidate` is the
/// evaluator under test. In [`DiffMode::Path`], only the root path is compared.
/// In [`DiffMode::Byte`], the harness compares root paths, root bytes, and then
/// recursively follows paired input-derivation edges in declaration order.
///
/// # Errors
///
/// Returns an error when byte mode cannot read or parse a `.drv` file needed
/// for closure traversal.
pub fn diff_closure(
    oracle: &dyn NixEval,
    candidate: &dyn NixEval,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> Result<DrvDiffReport> {
    let oracle_result = oracle.instantiate(file, attr);
    let candidate_result = candidate.instantiate(file, attr);
    let mut report = DrvDiffReport {
        mode,
        oracle_root: oracle_result.as_ref().ok().cloned(),
        candidate_root: candidate_result.as_ref().ok().cloned(),
        divergences: Vec::new(),
    };

    let (oracle_root, candidate_root) = match (oracle_result, candidate_result) {
        (Ok(oracle_root), Ok(candidate_root)) => (oracle_root, candidate_root),
        (Err(error), Ok(_)) => {
            report.divergences.push(DrvDiff::Evaluation {
                side: DiffSide::Oracle,
                error: error.to_string(),
            });
            return Ok(report);
        }
        (Ok(_), Err(error)) => {
            report.divergences.push(DrvDiff::Evaluation {
                side: DiffSide::Candidate,
                error: error.to_string(),
            });
            return Ok(report);
        }
        (Err(_oracle_error), Err(_candidate_error)) => return Ok(report),
    };

    match mode {
        DiffMode::Path => {
            if oracle_root != candidate_root {
                report.divergences.push(DrvDiff::RootPath {
                    oracle: oracle_root,
                    candidate: candidate_root,
                });
            }
        }
        DiffMode::Byte => {
            let mut visited = BTreeSet::new();
            compare_drv_pair(&oracle_root, &candidate_root, &mut visited, &mut report)?;
            if oracle_root != candidate_root {
                report.divergences.push(DrvDiff::RootPath {
                    oracle: oracle_root,
                    candidate: candidate_root,
                });
            }
        }
    }

    Ok(report)
}

fn compare_drv_pair(
    oracle: &Path,
    candidate: &Path,
    visited: &mut BTreeSet<(PathBuf, PathBuf)>,
    report: &mut DrvDiffReport,
) -> Result<()> {
    let key = (oracle.to_path_buf(), candidate.to_path_buf());
    if !visited.insert(key) {
        return Ok(());
    }

    let oracle_inputs = parse_drv_input_drvs(path_str(oracle)?)?;
    let candidate_inputs = parse_drv_input_drvs(path_str(candidate)?)?;
    if oracle_inputs.len() != candidate_inputs.len() {
        report.divergences.push(DrvDiff::InputCount {
            oracle: oracle.to_path_buf(),
            candidate: candidate.to_path_buf(),
            oracle_count: oracle_inputs.len(),
            candidate_count: candidate_inputs.len(),
        });
    }

    for (oracle_input, candidate_input) in oracle_inputs.iter().zip(candidate_inputs.iter()) {
        compare_input_pair(oracle_input, candidate_input, visited, report)?;
    }

    let oracle_bytes = std::fs::read(oracle)
        .with_context(|| format!("reading oracle drv {}", oracle.display()))?;
    let candidate_bytes = std::fs::read(candidate)
        .with_context(|| format!("reading candidate drv {}", candidate.display()))?;
    if oracle_bytes != candidate_bytes {
        report.divergences.push(DrvDiff::Bytes {
            oracle: oracle.to_path_buf(),
            candidate: candidate.to_path_buf(),
        });
    }

    Ok(())
}

fn compare_input_pair(
    oracle: &DrvInput,
    candidate: &DrvInput,
    visited: &mut BTreeSet<(PathBuf, PathBuf)>,
    report: &mut DrvDiffReport,
) -> Result<()> {
    let oracle_path = PathBuf::from(&oracle.drv_path);
    let candidate_path = PathBuf::from(&candidate.drv_path);
    if oracle.outputs != candidate.outputs {
        report.divergences.push(DrvDiff::InputOutputs {
            oracle: oracle_path.clone(),
            candidate: candidate_path.clone(),
            oracle_outputs: oracle.outputs.clone(),
            candidate_outputs: candidate.outputs.clone(),
        });
    }

    compare_drv_pair(&oracle_path, &candidate_path, visited, report)
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("drv path is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct FakeEval {
        result: Result<PathBuf>,
    }

    impl FakeEval {
        fn path(path: PathBuf) -> Self {
            Self { result: Ok(path) }
        }

        fn error(message: &str) -> Self {
            Self {
                result: Err(anyhow::anyhow!(message.to_string())),
            }
        }
    }

    impl NixEval for FakeEval {
        fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
            self.result
                .as_ref()
                .map(PathBuf::clone)
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        }

        fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
            self.instantiate(Path::new("expr"), "")
        }

        fn eval_expr(&self, _expr: &str) -> Result<String> {
            Ok("null".to_string())
        }

        fn name(&self) -> &'static str {
            "fake"
        }
    }

    fn drv(outputs: &[(&str, &[&str])], marker: &str) -> String {
        let inputs = outputs
            .iter()
            .map(|(path, names)| {
                let names = names
                    .iter()
                    .map(|name| format!(r#""{name}""#))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(r#"("{path}",[{names}])"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"Derive([("out","/nix/store/{marker}-out","","")],[{inputs}],[],"x86_64-linux","/nix/store/bash",[],[("name","{marker}")])"#
        )
    }

    #[test]
    fn path_mode_reports_root_path_divergence_without_reading_drv_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle = FakeEval::path(temp.path().join("oracle.drv"));
        let candidate = FakeEval::path(temp.path().join("candidate.drv"));

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Path,
        )?;

        assert!(!report.is_match());
        assert_eq!(report.divergences.len(), 1);
        assert!(matches!(report.divergences[0], DrvDiff::RootPath { .. }));
        Ok(())
    }

    #[test]
    fn byte_mode_walks_input_derivation_pairs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle_input = temp.path().join("oracle-input.drv");
        let candidate_input = temp.path().join("candidate-input.drv");
        let oracle_root = temp.path().join("oracle-root.drv");
        let candidate_root = temp.path().join("candidate-root.drv");
        fs::write(&oracle_input, drv(&[], "input"))?;
        fs::write(&candidate_input, drv(&[], "input-changed"))?;
        fs::write(
            &oracle_root,
            drv(&[(path_str(&oracle_input)?, &["out"])], "root"),
        )?;
        fs::write(
            &candidate_root,
            drv(&[(path_str(&candidate_input)?, &["out"])], "root"),
        )?;
        let oracle = FakeEval::path(oracle_root.clone());
        let candidate = FakeEval::path(candidate_root.clone());

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Byte,
        )?;

        assert!(!report.is_match());
        assert!(matches!(
            report.divergences.first(),
            Some(DrvDiff::Bytes { oracle, candidate })
                if oracle == &oracle_input && candidate == &candidate_input
        ));
        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::RootPath { .. }))
        );
        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                    if oracle == &oracle_input && candidate == &candidate_input))
        );
        Ok(())
    }

    #[test]
    fn diff_closure_reports_one_sided_instantiation_errors() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle = FakeEval::error("oracle failed");
        let candidate = FakeEval::path(temp.path().join("candidate.drv"));

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Path,
        )?;

        assert_eq!(
            report.divergences,
            vec![DrvDiff::Evaluation {
                side: DiffSide::Oracle,
                error: "oracle failed".to_string(),
            }]
        );
        Ok(())
    }

    #[test]
    fn diff_closure_treats_both_sided_instantiation_errors_as_error_parity() -> Result<()> {
        let oracle = FakeEval::error("oracle failed");
        let candidate = FakeEval::error("candidate failed");

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Path,
        )?;

        assert!(report.is_match());
        assert_eq!(report.oracle_root, None);
        assert_eq!(report.candidate_root, None);
        Ok(())
    }
}
