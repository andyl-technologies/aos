//! Differential `.drv` comparison over the evaluator seam.
//!
//! The native evaluator rollout needs a byte-oriented gate that compares the
//! C++ Nix oracle with a candidate [`NixEval`] implementation. This module
//! provides the library harness: instantiate both evaluators, compare root
//! paths, and optionally recurse through input derivations by reading the
//! `.drv` ATerm graph.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix_compat::derivation::Derivation;

use super::drv::{DrvInput, parse_drv_input_drvs_from_bytes};
use super::{DrvClosure, NixEval};

/// The level of `.drv` comparison to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    /// Compare only the top-level `.drv` store path.
    Path,
    /// Compare root paths and ATerm bytes through the input-derivation closure.
    Byte,
    /// Compare bytes and report the first parsed derivation field that differs.
    Structural,
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
    /// Both evaluators failed, but with different user-facing errors.
    EvaluationMismatch {
        /// Oracle-side error text.
        oracle_error: String,
        /// Candidate-side error text.
        candidate_error: String,
    },
    /// The ATerm bytes differ for a compared derivation pair.
    Bytes {
        /// Oracle-side `.drv` path.
        oracle: PathBuf,
        /// Candidate-side `.drv` path.
        candidate: PathBuf,
    },
    /// Parsed derivation fields differ for a compared derivation pair.
    Structural {
        /// Oracle-side `.drv` path.
        oracle: PathBuf,
        /// Candidate-side `.drv` path.
        candidate: PathBuf,
        /// First field that differs after parsing both `.drv` ATerms.
        field: String,
    },
    /// A `.drv` failed structural parsing.
    StructuralParse {
        /// Side whose `.drv` failed structural parsing.
        side: DiffSide,
        /// Path to the `.drv` that failed parsing.
        path: PathBuf,
        /// User-facing parse error text.
        error: String,
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

/// A paired oracle/candidate derivation node in the compared closure graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DrvDiffPair {
    /// Oracle-side `.drv` path.
    pub oracle: PathBuf,
    /// Candidate-side `.drv` path.
    pub candidate: PathBuf,
}

impl DrvDiffPair {
    fn new(oracle: impl Into<PathBuf>, candidate: impl Into<PathBuf>) -> Self {
        Self {
            oracle: oracle.into(),
            candidate: candidate.into(),
        }
    }
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
    /// Divergent `.drv` nodes whose input derivations did not diverge.
    ///
    /// This is populated only by closure-complete modes. [`DiffMode::Path`]
    /// does not inspect input derivations, so it leaves divergence nodes
    /// unclassified.
    pub root_divergences: Vec<DrvDiffPair>,
    /// Divergent `.drv` nodes whose mismatch is downstream of another mismatch.
    ///
    /// This is populated only by closure-complete modes. [`DiffMode::Path`]
    /// does not inspect input derivations, so it leaves divergence nodes
    /// unclassified.
    pub contaminated_divergences: Vec<DrvDiffPair>,
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
    let oracle_result = instantiate_for_mode(oracle, file, attr, mode);
    let candidate_result = instantiate_for_mode(candidate, file, attr, mode);
    let mut report = DrvDiffReport {
        mode,
        oracle_root: oracle_result
            .as_ref()
            .ok()
            .map(|result| result.root.clone()),
        candidate_root: candidate_result
            .as_ref()
            .ok()
            .map(|result| result.root.clone()),
        divergences: Vec::new(),
        root_divergences: Vec::new(),
        contaminated_divergences: Vec::new(),
    };

    let (oracle_result, candidate_result) = match (oracle_result, candidate_result) {
        (Ok(oracle_result), Ok(candidate_result)) => (oracle_result, candidate_result),
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
        (Err(oracle_error), Err(candidate_error)) => {
            let oracle_error = oracle_error.to_string();
            let candidate_error = candidate_error.to_string();
            if oracle_error != candidate_error {
                report.divergences.push(DrvDiff::EvaluationMismatch {
                    oracle_error,
                    candidate_error,
                });
            }
            return Ok(report);
        }
    };

    match mode {
        DiffMode::Path => {
            if oracle_result.root != candidate_result.root {
                report.divergences.push(DrvDiff::RootPath {
                    oracle: oracle_result.root,
                    candidate: candidate_result.root,
                });
            }
        }
        DiffMode::Byte | DiffMode::Structural => {
            let mut visited = BTreeSet::new();
            let mut graph = ClosureDiffGraph::default();
            compare_drv_pair(
                &oracle_result,
                &candidate_result,
                mode == DiffMode::Structural,
                &mut visited,
                &mut graph,
                &mut report,
            )?;
            if oracle_result.root != candidate_result.root {
                graph.record_divergence(DrvDiffPair::new(
                    oracle_result.root.clone(),
                    candidate_result.root.clone(),
                ));
                report.divergences.push(DrvDiff::RootPath {
                    oracle: oracle_result.root,
                    candidate: candidate_result.root,
                });
            }
            graph.classify(&mut report);
        }
    }

    Ok(report)
}

#[derive(Debug)]
struct DiffInstantiation {
    root: PathBuf,
    bytes: DiffByteSource,
}

#[derive(Debug)]
enum DiffByteSource {
    FileSystem,
    Memory(BTreeMap<PathBuf, Vec<u8>>),
}

impl DiffInstantiation {
    fn from_closure(closure: DrvClosure) -> Self {
        let (root, drvs) = closure.into_parts();
        Self {
            root,
            bytes: DiffByteSource::Memory(drvs),
        }
    }

    fn file_backed(root: PathBuf) -> Self {
        Self {
            root,
            bytes: DiffByteSource::FileSystem,
        }
    }

    fn read_drv_bytes(&self, path: &Path, label: &str) -> Result<Vec<u8>> {
        match &self.bytes {
            DiffByteSource::FileSystem => std::fs::read(path)
                .with_context(|| format!("reading {label} drv {}", path.display())),
            DiffByteSource::Memory(drvs) => drvs.get(path).cloned().with_context(|| {
                format!(
                    "{label} evaluator did not provide in-memory drv bytes for {}",
                    path.display()
                )
            }),
        }
    }
}

#[derive(Default)]
struct ClosureDiffGraph {
    edges: BTreeMap<DrvDiffPair, BTreeSet<DrvDiffPair>>,
    divergent: BTreeSet<DrvDiffPair>,
    divergent_order: Vec<DrvDiffPair>,
}

impl ClosureDiffGraph {
    fn record_node(&mut self, pair: DrvDiffPair) {
        self.edges.entry(pair).or_default();
    }

    fn record_edge(&mut self, parent: DrvDiffPair, input: DrvDiffPair) {
        self.edges.entry(parent).or_default().insert(input.clone());
        self.edges.entry(input).or_default();
    }

    fn record_divergence(&mut self, pair: DrvDiffPair) {
        if self.divergent.insert(pair.clone()) {
            self.divergent_order.push(pair);
        }
    }

    fn classify(self, report: &mut DrvDiffReport) {
        for pair in self.divergent_order {
            let has_divergent_input = self
                .edges
                .get(&pair)
                .is_some_and(|inputs| inputs.iter().any(|input| self.divergent.contains(input)));
            if has_divergent_input {
                report.contaminated_divergences.push(pair);
            } else {
                report.root_divergences.push(pair);
            }
        }
    }
}

fn instantiate_for_mode(
    eval: &dyn NixEval,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> Result<DiffInstantiation> {
    match mode {
        DiffMode::Path => eval
            .instantiate(file, attr)
            .map(DiffInstantiation::file_backed),
        DiffMode::Byte | DiffMode::Structural => match eval.instantiate_closure(file, attr)? {
            Some(closure) => Ok(DiffInstantiation::from_closure(closure)),
            None => eval
                .instantiate(file, attr)
                .map(DiffInstantiation::file_backed),
        },
    }
}

fn compare_drv_pair(
    oracle: &DiffInstantiation,
    candidate: &DiffInstantiation,
    structural: bool,
    visited: &mut BTreeSet<(PathBuf, PathBuf)>,
    graph: &mut ClosureDiffGraph,
    report: &mut DrvDiffReport,
) -> Result<()> {
    compare_drv_pair_at(
        oracle,
        candidate,
        &oracle.root,
        &candidate.root,
        structural,
        visited,
        graph,
        report,
    )
}

fn compare_drv_pair_at(
    oracle: &DiffInstantiation,
    candidate: &DiffInstantiation,
    oracle_path: &Path,
    candidate_path: &Path,
    structural: bool,
    visited: &mut BTreeSet<(PathBuf, PathBuf)>,
    graph: &mut ClosureDiffGraph,
    report: &mut DrvDiffReport,
) -> Result<()> {
    let pair = DrvDiffPair::new(oracle_path.to_path_buf(), candidate_path.to_path_buf());
    graph.record_node(pair.clone());
    if !visited.insert((pair.oracle.clone(), pair.candidate.clone())) {
        return Ok(());
    }

    let oracle_bytes = oracle.read_drv_bytes(oracle_path, "oracle")?;
    let candidate_bytes = candidate.read_drv_bytes(candidate_path, "candidate")?;
    let bytes_differ = oracle_bytes != candidate_bytes;
    if structural && bytes_differ {
        graph.record_divergence(pair.clone());
        report.divergences.push(DrvDiff::Bytes {
            oracle: oracle_path.to_path_buf(),
            candidate: candidate_path.to_path_buf(),
        });
    }

    let (oracle_inputs, candidate_inputs) = if structural && bytes_differ {
        let Some((oracle_drv, candidate_drv)) = parse_structural_pair(
            &oracle_bytes,
            &candidate_bytes,
            oracle_path,
            candidate_path,
            report,
        ) else {
            return Ok(());
        };
        let field = first_derivation_diff_field(&oracle_drv, &candidate_drv);
        graph.record_divergence(pair.clone());
        report.divergences.push(DrvDiff::Structural {
            oracle: oracle_path.to_path_buf(),
            candidate: candidate_path.to_path_buf(),
            field: field.to_string(),
        });
        (
            drv_inputs_from_derivation(&oracle_drv),
            drv_inputs_from_derivation(&candidate_drv),
        )
    } else {
        (
            parse_drv_inputs_from_bytes(&oracle_bytes, oracle_path, "oracle")?,
            parse_drv_inputs_from_bytes(&candidate_bytes, candidate_path, "candidate")?,
        )
    };
    if oracle_inputs.len() != candidate_inputs.len() {
        graph.record_divergence(pair.clone());
        report.divergences.push(DrvDiff::InputCount {
            oracle: oracle_path.to_path_buf(),
            candidate: candidate_path.to_path_buf(),
            oracle_count: oracle_inputs.len(),
            candidate_count: candidate_inputs.len(),
        });
    }

    for (oracle_input, candidate_input) in oracle_inputs.iter().zip(candidate_inputs.iter()) {
        compare_input_pair(
            oracle,
            candidate,
            &pair,
            oracle_input,
            candidate_input,
            structural,
            visited,
            graph,
            report,
        )?;
    }

    if !structural && bytes_differ {
        graph.record_divergence(pair);
        report.divergences.push(DrvDiff::Bytes {
            oracle: oracle_path.to_path_buf(),
            candidate: candidate_path.to_path_buf(),
        });
    }

    Ok(())
}

fn compare_input_pair(
    oracle_result: &DiffInstantiation,
    candidate_result: &DiffInstantiation,
    parent: &DrvDiffPair,
    oracle: &DrvInput,
    candidate: &DrvInput,
    structural: bool,
    visited: &mut BTreeSet<(PathBuf, PathBuf)>,
    graph: &mut ClosureDiffGraph,
    report: &mut DrvDiffReport,
) -> Result<()> {
    let oracle_path = PathBuf::from(&oracle.drv_path);
    let candidate_path = PathBuf::from(&candidate.drv_path);
    let pair = DrvDiffPair::new(oracle_path.clone(), candidate_path.clone());
    graph.record_edge(parent.clone(), pair.clone());
    if oracle.outputs != candidate.outputs {
        graph.record_divergence(parent.clone());
        report.divergences.push(DrvDiff::InputOutputs {
            oracle: oracle_path.clone(),
            candidate: candidate_path.clone(),
            oracle_outputs: oracle.outputs.clone(),
            candidate_outputs: candidate.outputs.clone(),
        });
    }

    compare_drv_pair_at(
        oracle_result,
        candidate_result,
        &oracle_path,
        &candidate_path,
        structural,
        visited,
        graph,
        report,
    )
}

fn parse_structural_pair(
    oracle_bytes: &[u8],
    candidate_bytes: &[u8],
    oracle_path: &Path,
    candidate_path: &Path,
    report: &mut DrvDiffReport,
) -> Option<(Derivation, Derivation)> {
    let oracle = parse_derivation(oracle_bytes).map_err(|error| {
        report.divergences.push(DrvDiff::StructuralParse {
            side: DiffSide::Oracle,
            path: oracle_path.to_path_buf(),
            error,
        });
    });
    let candidate = parse_derivation(candidate_bytes).map_err(|error| {
        report.divergences.push(DrvDiff::StructuralParse {
            side: DiffSide::Candidate,
            path: candidate_path.to_path_buf(),
            error,
        });
    });
    match (oracle, candidate) {
        (Ok(oracle), Ok(candidate)) => Some((oracle, candidate)),
        _ => None,
    }
}

fn parse_derivation(bytes: &[u8]) -> Result<Derivation, String> {
    Derivation::from_aterm_bytes(bytes).map_err(|source| format!("{source:?}"))
}

fn drv_inputs_from_derivation(derivation: &Derivation) -> Vec<DrvInput> {
    derivation
        .input_derivations
        .iter()
        .map(|(drv_path, outputs)| DrvInput {
            drv_path: drv_path.to_absolute_path(),
            outputs: outputs.iter().cloned().collect(),
        })
        .collect()
}

fn first_derivation_diff_field(oracle: &Derivation, candidate: &Derivation) -> &'static str {
    if oracle.outputs != candidate.outputs {
        "outputs"
    } else if oracle.input_derivations != candidate.input_derivations {
        "input_derivations"
    } else if oracle.input_sources != candidate.input_sources {
        "input_sources"
    } else if oracle.system != candidate.system {
        "system"
    } else if oracle.builder != candidate.builder {
        "builder"
    } else if oracle.arguments != candidate.arguments {
        "arguments"
    } else if oracle.environment != candidate.environment {
        "environment"
    } else {
        "serialization"
    }
}

fn parse_drv_inputs_from_bytes(bytes: &[u8], path: &Path, label: &str) -> Result<Vec<DrvInput>> {
    parse_drv_input_drvs_from_bytes(bytes)
        .with_context(|| format!("parsing {label} drv inputs {}", path.display()))
}

#[cfg(test)]
fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("drv path is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;

    struct FakeEval {
        result: Result<PathBuf>,
        closure: Option<Result<DrvClosure>>,
    }

    impl FakeEval {
        fn path(path: PathBuf) -> Self {
            Self {
                result: Ok(path),
                closure: None,
            }
        }

        fn path_with_bytes(path: PathBuf, drv_bytes: BTreeMap<PathBuf, Vec<u8>>) -> Self {
            let closure = DrvClosure::new(path.clone(), drv_bytes);
            Self {
                result: Ok(path),
                closure: Some(Ok(closure)),
            }
        }

        fn path_with_closure_error(path: PathBuf, message: &str) -> Self {
            Self {
                result: Ok(path),
                closure: Some(Err(anyhow::anyhow!(message.to_string()))),
            }
        }

        fn error(message: &str) -> Self {
            Self {
                result: Err(anyhow::anyhow!(message.to_string())),
                closure: None,
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

        fn instantiate_closure(&self, _file: &Path, _attr: &str) -> Result<Option<DrvClosure>> {
            match &self.closure {
                Some(Ok(closure)) => Ok(Some(closure.clone())),
                Some(Err(error)) => Err(anyhow::anyhow!(error.to_string())),
                None => Ok(None),
            }
        }

        fn eval_expr(&self, _expr: &str) -> Result<String> {
            Ok("null".to_string())
        }

        fn name(&self) -> &'static str {
            "fake"
        }
    }

    fn drv(outputs: &[(&str, &[&str])], marker: &str) -> String {
        String::from_utf8(drv_bytes(outputs, marker, None)).expect("fixture is UTF-8")
    }

    fn drv_bytes(outputs: &[(&str, &[&str])], marker: &str, extra_env: Option<&[u8]>) -> Vec<u8> {
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
        let mut out = format!(
            r#"Derive([("out","/nix/store/cccccccccccccccccccccccccccccccc-{marker}-out","","")],[{inputs}],[],"x86_64-linux","/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash",[],[("builder","/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash"),("name","{marker}"),("out","/nix/store/cccccccccccccccccccccccccccccccc-{marker}-out"),("system","x86_64-linux")"#
        )
        .into_bytes();
        if let Some(extra_env) = extra_env {
            out.extend_from_slice(br#",("raw",""#);
            out.extend_from_slice(extra_env);
            out.extend_from_slice(br#"")"#);
        }
        out.extend_from_slice(b"])");
        out
    }

    fn drv_input_section_only_bytes(inputs: &[(&str, &[&str])]) -> Vec<u8> {
        let inputs = inputs
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
        format!(r#"Derive([],[{inputs}])"#).into_bytes()
    }

    fn drv_with_malformed_tail_bytes(inputs: &[(&str, &[&str])]) -> Vec<u8> {
        let inputs = inputs
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
        format!(r#"Derive([],[{inputs}],[],[unterminated"#).into_bytes()
    }

    fn structural_drv(name: &str) -> String {
        const OUT: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared";
        const BUILDER: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
        format!(
            r#"Derive([("out","{OUT}","","")],[],[],"x86_64-linux","{BUILDER}",[],[("builder","{BUILDER}"),("name","{name}"),("out","{OUT}"),("system","x86_64-linux")])"#
        )
    }

    fn structural_drv_with_input(input: &str, name: &str) -> String {
        structural_drv_with_input_and_output(
            input,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared",
            name,
        )
    }

    fn structural_placeholder_drv_with_input(input: &str, name: &str) -> String {
        const BUILDER: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
        const PLACEHOLDER: &str = "/0xxkxgc4srd2mmak361la1ixni9jpyradxq3h9sgjxryvlv12gx4";
        format!(
            r#"Derive([("out","{PLACEHOLDER}","","")],[("{input}",["out"])],[],"x86_64-linux","{BUILDER}",[],[("builder","{BUILDER}"),("name","{name}"),("out","{PLACEHOLDER}"),("system","x86_64-linux")])"#
        )
    }

    fn structural_drv_with_input_and_output(input: &str, output: &str, name: &str) -> String {
        const BUILDER: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
        format!(
            r#"Derive([("out","{output}","","")],[("{input}",["out"])],[],"x86_64-linux","{BUILDER}",[],[("builder","{BUILDER}"),("name","{name}"),("out","{output}"),("system","x86_64-linux")])"#
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
        assert!(report.root_divergences.is_empty());
        assert!(report.contaminated_divergences.is_empty());
        Ok(())
    }

    #[test]
    fn path_mode_does_not_require_in_memory_closure_support() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("same.drv");
        let oracle = FakeEval::path(root.clone());
        let candidate = FakeEval::path_with_closure_error(root, "closure failed");

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Path,
        )?;

        assert!(report.is_match());
        Ok(())
    }

    #[test]
    fn byte_mode_walks_input_derivation_pairs() -> Result<()> {
        let oracle_input =
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
        let candidate_input =
            PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
        let oracle_root =
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
        let candidate_root =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
        oracle_bytes.insert(
            oracle_root.clone(),
            drv(&[(path_str(&oracle_input)?, &["out"])], "root").into_bytes(),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(
            candidate_input.clone(),
            drv(&[], "input-changed").into_bytes(),
        );
        candidate_bytes.insert(
            candidate_root.clone(),
            drv(&[(path_str(&candidate_input)?, &["out"])], "root").into_bytes(),
        );
        let oracle = FakeEval::path_with_bytes(oracle_root.clone(), oracle_bytes);
        let candidate = FakeEval::path_with_bytes(candidate_root.clone(), candidate_bytes);

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
        assert_eq!(
            report.root_divergences,
            vec![DrvDiffPair {
                oracle: oracle_input,
                candidate: candidate_input,
            }]
        );
        assert_eq!(
            report.contaminated_divergences,
            vec![DrvDiffPair {
                oracle: oracle_root,
                candidate: candidate_root,
            }]
        );
        Ok(())
    }

    #[test]
    fn byte_mode_classifies_input_output_mismatch_on_parent_drv() -> Result<()> {
        let input = PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-input.drv");
        let root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv");
        let input_bytes = drv(&[], "input").into_bytes();
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(input.clone(), input_bytes.clone());
        oracle_bytes.insert(
            root.clone(),
            drv(&[(path_str(&input)?, &["out"])], "root").into_bytes(),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(input.clone(), input_bytes);
        candidate_bytes.insert(
            root.clone(),
            drv(&[(path_str(&input)?, &["dev"])], "root").into_bytes(),
        );
        let oracle = FakeEval::path_with_bytes(root.clone(), oracle_bytes);
        let candidate = FakeEval::path_with_bytes(root.clone(), candidate_bytes);

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Byte,
        )?;

        assert!(report.divergences.iter().any(
            |diff| matches!(diff, DrvDiff::InputOutputs { oracle, candidate, .. }
                    if oracle == &input && candidate == &input)
        ));
        assert_eq!(
            report.root_divergences,
            vec![DrvDiffPair {
                oracle: root.clone(),
                candidate: root,
            }]
        );
        assert!(report.contaminated_divergences.is_empty());
        Ok(())
    }

    #[test]
    fn byte_mode_requires_complete_in_memory_closure_bytes() -> Result<()> {
        let oracle_input =
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
        let candidate_input =
            PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
        let oracle_root =
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
        let candidate_root =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
        oracle_bytes.insert(
            oracle_root.clone(),
            drv(&[(path_str(&oracle_input)?, &["out"])], "root").into_bytes(),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(
            candidate_root.clone(),
            drv(&[(path_str(&candidate_input)?, &["out"])], "root").into_bytes(),
        );
        let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
        let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

        let error = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Byte,
        )
        .expect_err("in-memory evaluators must provide every traversed drv");

        assert!(
            error
                .to_string()
                .contains("did not provide in-memory drv bytes")
        );
        Ok(())
    }

    #[test]
    fn byte_mode_walks_non_utf8_drv_bytes() -> Result<()> {
        let oracle_input =
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
        let candidate_input =
            PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
        let oracle_root =
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
        let candidate_root =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
        oracle_bytes.insert(
            oracle_root.clone(),
            drv_bytes(
                &[(path_str(&oracle_input)?, &["out"])],
                "root",
                Some(&[0xff]),
            ),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(
            candidate_input.clone(),
            drv(&[], "input-changed").into_bytes(),
        );
        candidate_bytes.insert(
            candidate_root.clone(),
            drv_bytes(
                &[(path_str(&candidate_input)?, &["out"])],
                "root",
                Some(&[0xff]),
            ),
        );
        let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
        let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Byte,
        )?;

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
    fn byte_mode_walks_inputs_without_full_structural_parse() -> Result<()> {
        let oracle_input =
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
        let candidate_input =
            PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
        let oracle_root =
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
        let candidate_root =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
        oracle_bytes.insert(
            oracle_root.clone(),
            drv_input_section_only_bytes(&[(path_str(&oracle_input)?, &["out"])]),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(
            candidate_input.clone(),
            drv(&[], "input-changed").into_bytes(),
        );
        candidate_bytes.insert(
            candidate_root.clone(),
            drv_input_section_only_bytes(&[(path_str(&candidate_input)?, &["out"])]),
        );
        let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
        let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Byte,
        )?;

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
    fn byte_mode_walks_inputs_without_validating_later_sections() -> Result<()> {
        let oracle_input =
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
        let candidate_input =
            PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
        let oracle_root =
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
        let candidate_root =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
        oracle_bytes.insert(
            oracle_root.clone(),
            drv_with_malformed_tail_bytes(&[(path_str(&oracle_input)?, &["out"])]),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(
            candidate_input.clone(),
            drv(&[], "input-changed").into_bytes(),
        );
        candidate_bytes.insert(
            candidate_root.clone(),
            drv_with_malformed_tail_bytes(&[(path_str(&candidate_input)?, &["out"])]),
        );
        let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
        let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Byte,
        )?;

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
    fn structural_mode_reports_first_parsed_field_difference() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle_root = temp.path().join("oracle-root.drv");
        let candidate_root = temp.path().join("candidate-root.drv");
        fs::write(&oracle_root, structural_drv("oracle"))?;
        fs::write(&candidate_root, structural_drv("candidate"))?;
        let oracle = FakeEval::path(oracle_root.clone());
        let candidate = FakeEval::path(candidate_root.clone());

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Structural,
        )?;

        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                    if oracle == &oracle_root && candidate == &candidate_root))
        );
        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                    if field == "environment"))
        );
        Ok(())
    }

    #[test]
    fn structural_mode_classifies_input_path_contamination() -> Result<()> {
        let oracle_input = PathBuf::from("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
        let candidate_input = PathBuf::from("/nix/store/wvza442rgjdb2cyhwm59ax3qy0y9skkk-ca.drv");
        let oracle_root =
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
        let candidate_root =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(oracle_input.clone(), structural_drv("input").into_bytes());
        oracle_bytes.insert(
            oracle_root.clone(),
            structural_drv_with_input(path_str(&oracle_input)?, "root").into_bytes(),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(
            candidate_input.clone(),
            structural_drv("input-changed").into_bytes(),
        );
        candidate_bytes.insert(
            candidate_root.clone(),
            structural_drv_with_input(path_str(&candidate_input)?, "root").into_bytes(),
        );
        let oracle = FakeEval::path_with_bytes(oracle_root.clone(), oracle_bytes);
        let candidate = FakeEval::path_with_bytes(candidate_root.clone(), candidate_bytes);

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Structural,
        )?;

        assert_eq!(
            report.divergences.first(),
            Some(&DrvDiff::Bytes {
                oracle: oracle_root.clone(),
                candidate: candidate_root.clone(),
            })
        );
        assert_eq!(
            report.divergences.get(1),
            Some(&DrvDiff::Structural {
                oracle: oracle_root.clone(),
                candidate: candidate_root.clone(),
                field: "input_derivations".to_string(),
            })
        );
        assert_eq!(
            report.root_divergences,
            vec![DrvDiffPair {
                oracle: oracle_input,
                candidate: candidate_input,
            }]
        );
        assert_eq!(
            report.contaminated_divergences,
            vec![DrvDiffPair {
                oracle: oracle_root,
                candidate: candidate_root,
            }]
        );
        assert!(
            !report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. }))
        );
        Ok(())
    }

    #[test]
    fn structural_mode_walks_equal_placeholder_bytes_without_full_parse() -> Result<()> {
        let input = PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-input.drv");
        let root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv");
        let root_bytes = structural_placeholder_drv_with_input(path_str(&input)?, "root");

        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(input.clone(), structural_drv("input").into_bytes());
        oracle_bytes.insert(root.clone(), root_bytes.clone().into_bytes());
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(input.clone(), structural_drv("input-changed").into_bytes());
        candidate_bytes.insert(root.clone(), root_bytes.into_bytes());
        let oracle = FakeEval::path_with_bytes(root.clone(), oracle_bytes);
        let candidate = FakeEval::path_with_bytes(root, candidate_bytes);

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Structural,
        )?;

        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                    if oracle == &input && candidate == &input))
        );
        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                    if field == "environment"))
        );
        assert!(
            !report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. }))
        );
        Ok(())
    }

    #[test]
    fn structural_mode_classifies_output_and_input_divergence() -> Result<()> {
        let oracle_input = PathBuf::from("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
        let candidate_input = PathBuf::from("/nix/store/wvza442rgjdb2cyhwm59ax3qy0y9skkk-ca.drv");
        let oracle_root =
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
        let candidate_root =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
        let mut oracle_bytes = BTreeMap::new();
        oracle_bytes.insert(oracle_input.clone(), structural_drv("input").into_bytes());
        oracle_bytes.insert(
            oracle_root.clone(),
            structural_drv_with_input_and_output(
                path_str(&oracle_input)?,
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared",
                "root",
            )
            .into_bytes(),
        );
        let mut candidate_bytes = BTreeMap::new();
        candidate_bytes.insert(
            candidate_input.clone(),
            structural_drv("input").into_bytes(),
        );
        candidate_bytes.insert(
            candidate_root.clone(),
            structural_drv_with_input_and_output(
                path_str(&candidate_input)?,
                "/nix/store/c9hhy38jds9ffzzqwkb50vrv2pi8x614-base",
                "root",
            )
            .into_bytes(),
        );
        let oracle = FakeEval::path_with_bytes(oracle_root.clone(), oracle_bytes);
        let candidate = FakeEval::path_with_bytes(candidate_root.clone(), candidate_bytes);

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Structural,
        )?;

        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                    if field == "outputs"))
        );
        assert_eq!(
            report.root_divergences,
            vec![DrvDiffPair {
                oracle: oracle_root,
                candidate: candidate_root,
            }]
        );
        assert!(report.contaminated_divergences.is_empty());
        assert!(
            !report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. }))
        );
        Ok(())
    }

    #[test]
    fn structural_mode_reports_parse_failure_as_divergence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let oracle_root = temp.path().join("oracle-root.drv");
        let candidate_root = temp.path().join("candidate-root.drv");
        fs::write(&oracle_root, structural_drv("oracle"))?;
        fs::write(&candidate_root, b"not-a-derivation")?;
        let oracle = FakeEval::path(oracle_root);
        let candidate = FakeEval::path(candidate_root.clone());

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Structural,
        )?;

        assert!(
            report
                .divergences
                .iter()
                .any(|diff| matches!(diff, DrvDiff::StructuralParse {
                    side: DiffSide::Candidate,
                    path,
                    ..
                } if path == &candidate_root))
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
    fn diff_closure_reports_mismatched_two_sided_instantiation_errors() -> Result<()> {
        let oracle = FakeEval::error("oracle failed");
        let candidate = FakeEval::error("candidate failed");

        let report = diff_closure(
            &oracle,
            &candidate,
            Path::new("default.nix"),
            "pkg",
            DiffMode::Path,
        )?;

        assert_eq!(report.oracle_root, None);
        assert_eq!(report.candidate_root, None);
        assert_eq!(
            report.divergences,
            vec![DrvDiff::EvaluationMismatch {
                oracle_error: "oracle failed".to_string(),
                candidate_error: "candidate failed".to_string(),
            }]
        );
        Ok(())
    }

    #[test]
    fn diff_closure_accepts_matching_two_sided_instantiation_errors() -> Result<()> {
        let oracle = FakeEval::error("same failure");
        let candidate = FakeEval::error("same failure");

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
