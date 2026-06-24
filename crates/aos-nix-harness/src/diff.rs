//! Differential `.drv` comparison over the evaluator seam.
//!
//! The native evaluator rollout needs a byte-oriented gate that compares the
//! C++ Nix oracle with a candidate [`NixEval`] implementation. This module
//! provides the library harness: instantiate both evaluators, compare root
//! paths, and optionally recurse through input derivations by reading the
//! `.drv` ATerm graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use aos_core::nix::{DrvClosure, NixEval};
use aos_nix_compat::drv::DrvInput;

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
        /// Oracle-side parent `.drv` path whose input edge differs.
        parent_oracle: PathBuf,
        /// Candidate-side parent `.drv` path whose input edge differs.
        parent_candidate: PathBuf,
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

/// Persisted closure bytes for a direct node-level reproduction command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrvDiffNodeArtifact {
    /// Logical oracle/candidate `.drv` pair this artifact reproduces.
    pub pair: DrvDiffPair,
    /// Bundle containing oracle-side in-memory closure bytes, when needed.
    pub oracle_bundle: Option<PathBuf>,
    /// Bundle containing candidate-side in-memory closure bytes, when needed.
    pub candidate_bundle: Option<PathBuf>,
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
    /// Compared `.drv` pairs whose bytes came from filesystem paths on both sides.
    ///
    /// Only these pairs can be reproduced by a direct `.drv` pair command
    /// without persisting in-memory closure bytes.
    pub file_backed_pairs: Vec<DrvDiffPair>,
    /// Direct node-level artifacts for pairs whose closure bytes were in memory.
    ///
    /// Each artifact points at JSON bundle files that preserve the original
    /// logical `.drv` paths and the exact ATerm bytes for closure traversal.
    pub node_artifacts: Vec<DrvDiffNodeArtifact>,
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
        file_backed_pairs: Vec::new(),
        node_artifacts: Vec::new(),
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

    compare_instantiated_roots(oracle_result, candidate_result, mode, &mut report)?;

    Ok(report)
}

/// Compares two existing `.drv` roots without evaluating a Nix expression.
///
/// This is the node-level rerun path for root-divergence reports: a developer
/// can compare the exact pair of `.drv` files emitted by a wider
/// [`diff_closure`] run without re-instantiating the original `(file, attr)`.
///
/// # Errors
///
/// Returns an error when byte or structural mode cannot read or parse a `.drv`
/// file needed for closure traversal.
pub fn diff_drv_pair(
    oracle_drv: &Path,
    candidate_drv: &Path,
    mode: DiffMode,
) -> Result<DrvDiffReport> {
    diff_drv_pair_with_bundles(oracle_drv, candidate_drv, None, None, mode)
}

/// Compares two existing `.drv` roots, optionally using persisted closure bundles.
///
/// Bundle files are produced by root-divergence reports when one side of the
/// wider diff came from in-memory native closure bytes. The logical root paths
/// remain the original `.drv` paths; the bundles provide bytes for traversing
/// those roots and their input derivations.
///
/// # Errors
///
/// Returns an error when a bundle cannot be read, decoded, or used for byte or
/// structural traversal.
pub fn diff_drv_pair_with_bundles(
    oracle_drv: &Path,
    candidate_drv: &Path,
    oracle_bundle: Option<&Path>,
    candidate_bundle: Option<&Path>,
    mode: DiffMode,
) -> Result<DrvDiffReport> {
    let oracle_result = DiffInstantiation::file_backed(oracle_drv.to_path_buf());
    let candidate_result = DiffInstantiation::file_backed(candidate_drv.to_path_buf());
    let oracle_result = match oracle_bundle {
        Some(bundle) => DiffInstantiation::bundle_backed(
            oracle_drv.to_path_buf(),
            bundle.to_path_buf(),
            read_drv_closure_bundle(bundle)?,
        ),
        None => oracle_result,
    };
    let candidate_result = match candidate_bundle {
        Some(bundle) => DiffInstantiation::bundle_backed(
            candidate_drv.to_path_buf(),
            bundle.to_path_buf(),
            read_drv_closure_bundle(bundle)?,
        ),
        None => candidate_result,
    };
    let mut report = DrvDiffReport {
        mode,
        oracle_root: Some(oracle_result.root.clone()),
        candidate_root: Some(candidate_result.root.clone()),
        divergences: Vec::new(),
        root_divergences: Vec::new(),
        contaminated_divergences: Vec::new(),
        file_backed_pairs: Vec::new(),
        node_artifacts: Vec::new(),
    };

    compare_instantiated_roots(oracle_result, candidate_result, mode, &mut report)?;

    Ok(report)
}

fn compare_instantiated_roots(
    oracle_result: DiffInstantiation,
    candidate_result: DiffInstantiation,
    mode: DiffMode,
    report: &mut DrvDiffReport,
) -> Result<()> {
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
            let mut artifacts = DiffArtifactState::default();
            compare_drv_pair(
                &oracle_result,
                &candidate_result,
                mode == DiffMode::Structural,
                &mut visited,
                &mut graph,
                &mut artifacts,
                report,
            )?;
            if oracle_result.root != candidate_result.root {
                let pair =
                    DrvDiffPair::new(oracle_result.root.clone(), candidate_result.root.clone());
                graph.record_divergence(pair.clone());
                record_node_artifact(
                    &mut artifacts,
                    report,
                    &pair,
                    &oracle_result,
                    &candidate_result,
                )?;
                report.divergences.push(DrvDiff::RootPath {
                    oracle: oracle_result.root,
                    candidate: candidate_result.root,
                });
            }
            graph.classify(report);
        }
    }

    Ok(())
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
    Bundle {
        path: PathBuf,
        drvs: BTreeMap<PathBuf, Vec<u8>>,
    },
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

    fn bundle_backed(root: PathBuf, path: PathBuf, drvs: BTreeMap<PathBuf, Vec<u8>>) -> Self {
        Self {
            root,
            bytes: DiffByteSource::Bundle { path, drvs },
        }
    }

    fn read_drv_bytes(&self, path: &Path, label: &str) -> Result<Vec<u8>> {
        let resolved = drv_file_path(path);
        let path = resolved.as_path();
        match &self.bytes {
            DiffByteSource::FileSystem => std::fs::read(path)
                .with_context(|| format!("reading {label} drv {}", path.display())),
            DiffByteSource::Memory(drvs) | DiffByteSource::Bundle { drvs, .. } => {
                drvs.get(path).cloned().with_context(|| {
                    format!(
                        "{label} evaluator did not provide in-memory drv bytes for {}",
                        path.display()
                    )
                })
            }
        }
    }

    fn is_file_backed(&self) -> bool {
        matches!(self.bytes, DiffByteSource::FileSystem)
    }

    fn bundle_path(&self) -> Option<&Path> {
        match &self.bytes {
            DiffByteSource::Bundle { path, .. } => Some(path),
            DiffByteSource::FileSystem | DiffByteSource::Memory(_) => None,
        }
    }

    fn memory_drvs(&self) -> Option<&BTreeMap<PathBuf, Vec<u8>>> {
        match &self.bytes {
            DiffByteSource::Memory(drvs) => Some(drvs),
            DiffByteSource::FileSystem | DiffByteSource::Bundle { .. } => None,
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

#[derive(Default)]
struct DiffArtifactState {
    dir: Option<PathBuf>,
    oracle_bundle: Option<PathBuf>,
    candidate_bundle: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct DrvClosureBundleFile {
    version: u32,
    drvs: BTreeMap<String, String>,
}

const DRV_CLOSURE_BUNDLE_VERSION: u32 = 1;

fn record_node_artifact(
    artifacts: &mut DiffArtifactState,
    report: &mut DrvDiffReport,
    pair: &DrvDiffPair,
    oracle: &DiffInstantiation,
    candidate: &DiffInstantiation,
) -> Result<()> {
    if report
        .node_artifacts
        .iter()
        .any(|artifact| artifact.pair == *pair)
    {
        return Ok(());
    }

    let oracle_bundle = artifact_bundle_path(artifacts, oracle, DiffSide::Oracle)?;
    let candidate_bundle = artifact_bundle_path(artifacts, candidate, DiffSide::Candidate)?;
    if oracle_bundle.is_none() && candidate_bundle.is_none() {
        return Ok(());
    }

    report.node_artifacts.push(DrvDiffNodeArtifact {
        pair: pair.clone(),
        oracle_bundle,
        candidate_bundle,
    });
    Ok(())
}

fn artifact_bundle_path(
    artifacts: &mut DiffArtifactState,
    instantiation: &DiffInstantiation,
    side: DiffSide,
) -> Result<Option<PathBuf>> {
    if let Some(path) = instantiation.bundle_path() {
        return Ok(Some(path.to_path_buf()));
    }
    let Some(drvs) = instantiation.memory_drvs() else {
        return Ok(None);
    };

    match side {
        DiffSide::Oracle => {
            if artifacts.oracle_bundle.is_none() {
                let dir = artifact_dir(artifacts)?;
                let path = dir.join("oracle-drv-closure.json");
                write_drv_closure_bundle(&path, drvs)?;
                artifacts.oracle_bundle = Some(path);
            }
            Ok(artifacts.oracle_bundle.clone())
        }
        DiffSide::Candidate => {
            if artifacts.candidate_bundle.is_none() {
                let dir = artifact_dir(artifacts)?;
                let path = dir.join("candidate-drv-closure.json");
                write_drv_closure_bundle(&path, drvs)?;
                artifacts.candidate_bundle = Some(path);
            }
            Ok(artifacts.candidate_bundle.clone())
        }
    }
}

fn artifact_dir(artifacts: &mut DiffArtifactState) -> Result<&Path> {
    if artifacts.dir.is_none() {
        artifacts.dir = Some(create_persistent_artifact_dir()?);
    }
    artifacts
        .dir
        .as_deref()
        .context("nix-diff artifact directory was not initialized")
}

fn create_persistent_artifact_dir() -> Result<PathBuf> {
    let tmp = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..100_u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time is before UNIX_EPOCH")?
            .as_nanos();
        let dir = tmp.join(format!("aos-nix-diff-{pid}-{nanos}-{attempt}"));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating nix-diff artifact dir {}", dir.display()));
            }
        }
    }
    anyhow::bail!(
        "creating unique nix-diff artifact directory in {}",
        tmp.display()
    )
}

fn write_drv_closure_bundle(path: &Path, drvs: &BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
    let encoded = DrvClosureBundleFile {
        version: DRV_CLOSURE_BUNDLE_VERSION,
        drvs: drvs
            .iter()
            .map(|(path, bytes)| {
                let path = path
                    .to_str()
                    .with_context(|| format!("drv path is not UTF-8: {}", path.display()))?;
                Ok((
                    path.to_string(),
                    base64::engine::general_purpose::STANDARD.encode(bytes),
                ))
            })
            .collect::<Result<_>>()?,
    };
    let text = serde_json::to_vec_pretty(&encoded).context("serializing drv closure bundle")?;
    fs::write(path, text).with_context(|| format!("writing drv closure bundle {}", path.display()))
}

fn read_drv_closure_bundle(path: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    let text =
        fs::read(path).with_context(|| format!("reading drv closure bundle {}", path.display()))?;
    let bundle: DrvClosureBundleFile =
        serde_json::from_slice(&text).context("parsing drv closure bundle")?;
    if bundle.version != DRV_CLOSURE_BUNDLE_VERSION {
        anyhow::bail!(
            "unsupported drv closure bundle version {} in {}",
            bundle.version,
            path.display()
        );
    }

    bundle
        .drvs
        .into_iter()
        .map(|(path, encoded)| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .with_context(|| format!("decoding bundle bytes for {path}"))?;
            Ok((PathBuf::from(path), bytes))
        })
        .collect()
}

/// Resolves a derivation path to the on-disk `.drv` file it names.
///
/// An evaluator may return a *deriving path* — a `.drv` followed by an output
/// selector, e.g. `/nix/store/…-glibc-2.39.drv!getent` — when an expression
/// evaluates to a specific output of a multi-output derivation (such as
/// `lib.getOutput "getent" stdenv.glibc`). The selector chooses an output but
/// does not change the derivation, so it is stripped here to read/compare the
/// underlying `.drv`. Plain `.drv` paths (every closure-internal input) are
/// returned unchanged.
fn drv_file_path(path: &Path) -> PathBuf {
    if let Some(text) = path.to_str() {
        if let Some(marker) = text.find(".drv!") {
            return PathBuf::from(&text[..marker + ".drv".len()]);
        }
    }
    path.to_path_buf()
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
    artifacts: &mut DiffArtifactState,
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
        artifacts,
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
    artifacts: &mut DiffArtifactState,
    report: &mut DrvDiffReport,
) -> Result<()> {
    let pair = DrvDiffPair::new(oracle_path.to_path_buf(), candidate_path.to_path_buf());
    graph.record_node(pair.clone());
    if !visited.insert((pair.oracle.clone(), pair.candidate.clone())) {
        return Ok(());
    }
    if oracle.is_file_backed() && candidate.is_file_backed() {
        report.file_backed_pairs.push(pair.clone());
    }

    let oracle_bytes = oracle.read_drv_bytes(oracle_path, "oracle")?;
    let candidate_bytes = candidate.read_drv_bytes(candidate_path, "candidate")?;
    let bytes_differ = oracle_bytes != candidate_bytes;
    if bytes_differ {
        record_node_artifact(artifacts, report, &pair, oracle, candidate)?;
    }
    if structural && bytes_differ {
        graph.record_divergence(pair.clone());
        report.divergences.push(DrvDiff::Bytes {
            oracle: oracle_path.to_path_buf(),
            candidate: candidate_path.to_path_buf(),
        });
    }

    let (oracle_inputs, candidate_inputs) = if structural && bytes_differ {
        let Some((oracle_drv, candidate_drv)) = structural::parse_structural_pair(
            &oracle_bytes,
            &candidate_bytes,
            oracle_path,
            candidate_path,
            report,
        ) else {
            return Ok(());
        };
        let field = structural::first_derivation_diff_field(&oracle_drv, &candidate_drv);
        graph.record_divergence(pair.clone());
        report.divergences.push(DrvDiff::Structural {
            oracle: oracle_path.to_path_buf(),
            candidate: candidate_path.to_path_buf(),
            field: field.to_string(),
        });
        (
            structural::drv_inputs_from_derivation(&oracle_drv),
            structural::drv_inputs_from_derivation(&candidate_drv),
        )
    } else {
        (
            structural::parse_drv_inputs_from_bytes(&oracle_bytes, oracle_path, "oracle")?,
            structural::parse_drv_inputs_from_bytes(&candidate_bytes, candidate_path, "candidate")?,
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
            artifacts,
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
    artifacts: &mut DiffArtifactState,
    report: &mut DrvDiffReport,
) -> Result<()> {
    let oracle_path = PathBuf::from(&oracle.drv_path);
    let candidate_path = PathBuf::from(&candidate.drv_path);
    let pair = DrvDiffPair::new(oracle_path.clone(), candidate_path.clone());
    graph.record_edge(parent.clone(), pair.clone());
    if oracle.outputs != candidate.outputs {
        graph.record_divergence(parent.clone());
        report.divergences.push(DrvDiff::InputOutputs {
            parent_oracle: parent.oracle.clone(),
            parent_candidate: parent.candidate.clone(),
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
        artifacts,
        report,
    )
}

mod structural;

#[cfg(test)]
mod structural_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
