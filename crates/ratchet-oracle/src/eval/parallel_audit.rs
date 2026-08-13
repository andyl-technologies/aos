//! Verification targets for the parallel evaluator audit gate.
//!
//! RFC-0007 requires the parallel evaluator to ship only after the loom, Miri,
//! and ThreadSanitizer audit is green. This module makes the non-loom half of
//! that gate explicit: it names the tool/target matrix and provides small
//! deterministic harnesses that ordinary tests can run today and Miri/TSan can
//! target by filter later.
//!
//! These smoke harnesses are not the final certification run. They are stable
//! entry points for the audit tools and a guard against the target matrix
//! silently drifting away from the code paths it is supposed to cover.

use std::num::NonZeroUsize;

use thiserror::Error;

use crate::{
    compile::{Ir, resolve as resolve_ast},
    eval::{
        ParallelTreeWalkDifferentialError, ParallelTreeWalkDrvDifferentialError,
        ParallelTreeWalkRoot, TreeWalkError, TreeWalkOptions,
        compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts,
        compare_parallel_tree_walk_drv_outputs_chase_lev_standard_worker_counts,
        compare_parallel_tree_walk_raw_chase_lev_across_worker_counts, eval_raw_bytes_with_options,
    },
    syntax::parse_str,
};

const AUDIT_PACKAGE: &str = "ratchet-oracle";
const AUDIT_MANIFEST_PATH: &str = "crates/Cargo.toml";
const AUDIT_WORKER_COUNTS: [usize; 2] = [1, 2];
const CARGO_PROGRAM: &str = "cargo";
const NIGHTLY_CARGO_ARG: &str = "+nightly";
const RUSTFLAGS_ENV: &str = "RUSTFLAGS";
const TSAN_TARGET: &str = "x86_64-unknown-linux-gnu";
const TSAN_RUSTFLAGS: &str = "-Z sanitizer=thread";

const PARALLEL_RUNTIME_AUDIT_TARGETS: [ParallelRuntimeAuditTarget; 6] = [
    ParallelRuntimeAuditTarget::new(
        ParallelRuntimeAuditTool::Loom,
        ParallelRuntimeAuditScope::ThunkCasModel,
        "loom_model_tests",
        "loom exhaustively explores the bounded CAS/waiter state-machine model",
    ),
    ParallelRuntimeAuditTarget::new(
        ParallelRuntimeAuditTool::Miri,
        ParallelRuntimeAuditScope::SafeTreeWalkOracle,
        "parallel_audit_safe_tree_walk_oracle_miri_smoke",
        "Miri must cover the safe serial oracle used as the parallel differential baseline",
    ),
    ParallelRuntimeAuditTarget::new(
        ParallelRuntimeAuditTool::Miri,
        ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
        "parallel_audit_parallel_tree_walk_miri_smoke",
        "Miri must cover the small scheduler-backed raw tree-walk harness",
    ),
    ParallelRuntimeAuditTarget::new(
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
        "parallel_audit_parallel_tree_walk_tsan_smoke",
        "ThreadSanitizer must cover the actual Chase-Lev raw tree-walk harness",
    ),
    ParallelRuntimeAuditTarget::new(
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvHarness,
        "parallel_audit_parallel_tree_walk_drv_tsan_smoke",
        "ThreadSanitizer must cover deterministic .drv collation under the scheduler harness",
    ),
    ParallelRuntimeAuditTarget::new(
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvStandardMatrixHarness,
        "parallel_audit_parallel_tree_walk_drv_standard_matrix_tsan_smoke",
        "ThreadSanitizer must cover the RFC standard worker matrix for deterministic .drv collation",
    ),
];

const REQUIRED_AUDIT_TARGETS: [(ParallelRuntimeAuditTool, ParallelRuntimeAuditScope); 6] = [
    (
        ParallelRuntimeAuditTool::Loom,
        ParallelRuntimeAuditScope::ThunkCasModel,
    ),
    (
        ParallelRuntimeAuditTool::Miri,
        ParallelRuntimeAuditScope::SafeTreeWalkOracle,
    ),
    (
        ParallelRuntimeAuditTool::Miri,
        ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
    ),
    (
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
    ),
    (
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvHarness,
    ),
    (
        ParallelRuntimeAuditTool::ThreadSanitizer,
        ParallelRuntimeAuditScope::ParallelTreeWalkDrvStandardMatrixHarness,
    ),
];

const SAFE_TREE_WALK_CASES: [(&str, &[u8]); 4] = [
    ("1 + 2", b"3"),
    (
        "{ b = 2; a = [ 1 true null ]; }",
        b"{ a = [ 1 true null ]; b = 2; }",
    ),
    (
        "let shared = 1 + 2; in { first = shared; second = shared; }",
        b"{ first = 3; second = 3; }",
    ),
    (
        "builtins.toJSON { z = 1; a = [ true null ]; }",
        br#""{\"a\":[true,null],\"z\":1}""#,
    ),
];

const PARALLEL_RAW_CASES: [&str; 4] = [
    "1 + 2",
    "{ b = 2; a = [ 1 true null ]; }",
    "let shared = 1 + 2; in { first = shared; second = shared; }",
    "builtins.toJSON { z = 1; a = [ true null ]; }",
];

const PARALLEL_DRV_CASES: [&str; 2] = [
    r#"derivation { name = "audit-parallel-a"; system = ":"; builder = ":"; }"#,
    r#"derivation { name = "audit-parallel-b"; system = ":"; builder = ":"; }"#,
];

const PARALLEL_DRV_STANDARD_MATRIX_CASES: [&str; 4] = [
    r#"(derivation { name = "audit-parallel-standard-drvpath"; system = ":"; builder = ":"; }).drvPath"#,
    r#"(derivation { name = "audit-parallel-standard-outpath"; system = ":"; builder = ":"; }).outPath"#,
    r#"[ (derivation { name = "audit-parallel-standard-list-a"; system = ":"; builder = ":"; }) (derivation { name = "audit-parallel-standard-list-b"; system = ":"; builder = ":"; }) ]"#,
    r#"let d = derivation { name = "audit-parallel-standard-lazy"; system = ":"; builder = ":"; }; in {
        type = builtins.foldl' (acc: _: acc) "derivation" [ 1 ];
        drvPath = builtins.foldl' (acc: _: acc) d.drvPath [ 1 ];
    }"#,
];

/// A verification tool required by the parallel runtime audit gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParallelRuntimeAuditTool {
    /// The loom permutation tester for the modeled CAS protocol.
    Loom,
    /// The Miri interpreter for undefined-behavior checks over safe Rust paths.
    Miri,
    /// ThreadSanitizer over the actual multithreaded scheduler harness.
    ThreadSanitizer,
}

/// A code path covered by the parallel runtime audit gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParallelRuntimeAuditScope {
    /// The bounded loom model for the thunk CAS/waiter state machine.
    ThunkCasModel,
    /// The safe serial tree-walk oracle used as the differential baseline.
    SafeTreeWalkOracle,
    /// Scheduler-backed raw tree-walk evaluation over a small root set.
    ParallelTreeWalkRawHarness,
    /// Scheduler-backed `.drv` output collation over a small root set.
    ParallelTreeWalkDrvHarness,
    /// Scheduler-backed `.drv` output collation over the RFC worker matrix.
    ParallelTreeWalkDrvStandardMatrixHarness,
}

/// One cargo test target in the parallel runtime audit matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParallelRuntimeAuditTarget {
    tool: ParallelRuntimeAuditTool,
    scope: ParallelRuntimeAuditScope,
    package: &'static str,
    manifest_path: &'static str,
    test_filter: &'static str,
    rationale: &'static str,
}

impl ParallelRuntimeAuditTarget {
    const fn new(
        tool: ParallelRuntimeAuditTool,
        scope: ParallelRuntimeAuditScope,
        test_filter: &'static str,
        rationale: &'static str,
    ) -> Self {
        Self {
            tool,
            scope,
            package: AUDIT_PACKAGE,
            manifest_path: AUDIT_MANIFEST_PATH,
            test_filter,
            rationale,
        }
    }

    /// Returns the verification tool.
    pub const fn tool(self) -> ParallelRuntimeAuditTool {
        self.tool
    }

    /// Returns the code path covered by this target.
    pub const fn scope(self) -> ParallelRuntimeAuditScope {
        self.scope
    }

    /// Returns the cargo package that owns the target.
    pub const fn package(self) -> &'static str {
        self.package
    }

    /// Returns the workspace cargo manifest path.
    pub const fn manifest_path(self) -> &'static str {
        self.manifest_path
    }

    /// Returns the cargo test filter for this target.
    pub const fn test_filter(self) -> &'static str {
        self.test_filter
    }

    /// Returns why this target belongs in the audit matrix.
    pub const fn rationale(self) -> &'static str {
        self.rationale
    }
}

/// A validated parallel runtime audit target manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParallelRuntimeAuditManifest {
    targets: &'static [ParallelRuntimeAuditTarget],
}

impl ParallelRuntimeAuditManifest {
    /// Returns every audit target.
    pub const fn targets(self) -> &'static [ParallelRuntimeAuditTarget] {
        self.targets
    }

    /// Returns the number of audit targets.
    pub const fn target_count(self) -> usize {
        self.targets.len()
    }

    /// Finds an audit target by tool and scope.
    pub fn target_for(
        self,
        tool: ParallelRuntimeAuditTool,
        scope: ParallelRuntimeAuditScope,
    ) -> Option<ParallelRuntimeAuditTarget> {
        self.targets
            .iter()
            .copied()
            .find(|target| target.tool == tool && target.scope == scope)
    }
}

/// Returns the current parallel runtime audit target manifest.
pub const fn parallel_runtime_audit_manifest() -> ParallelRuntimeAuditManifest {
    ParallelRuntimeAuditManifest {
        targets: &PARALLEL_RUNTIME_AUDIT_TARGETS,
    }
}

/// Validates and returns the parallel runtime audit target manifest.
///
/// # Errors
///
/// Returns [`ParallelRuntimeAuditManifestError`] if a required tool/scope pair
/// is missing or if a target has no test filter or rationale.
pub fn validate_parallel_runtime_audit_manifest()
-> Result<ParallelRuntimeAuditManifest, ParallelRuntimeAuditManifestError> {
    let manifest = parallel_runtime_audit_manifest();
    for target in manifest.targets {
        if target.test_filter.is_empty() {
            return Err(ParallelRuntimeAuditManifestError::EmptyTestFilter {
                tool: target.tool,
                scope: target.scope,
            });
        }
        if target.rationale.is_empty() {
            return Err(ParallelRuntimeAuditManifestError::EmptyRationale {
                tool: target.tool,
                scope: target.scope,
            });
        }
    }
    for (tool, scope) in REQUIRED_AUDIT_TARGETS {
        if manifest.target_for(tool, scope).is_none() {
            return Err(ParallelRuntimeAuditManifestError::MissingTarget { tool, scope });
        }
    }
    Ok(manifest)
}

/// Returns the cargo invocations for the current R-4 audit target matrix.
///
/// The returned commands are not executed by ordinary tests. They provide a
/// stable adapter boundary for CI to run loom, Miri, and ThreadSanitizer without
/// reconstructing command lines from prose.
///
/// # Errors
///
/// Returns [`ParallelRuntimeAuditManifestError`] if the audit target manifest is
/// invalid.
pub fn parallel_runtime_audit_invocations()
-> Result<Vec<ParallelRuntimeAuditInvocation>, ParallelRuntimeAuditManifestError> {
    validate_parallel_runtime_audit_manifest().map(|manifest| {
        manifest
            .targets()
            .iter()
            .copied()
            .map(ParallelRuntimeAuditInvocation::for_target)
            .collect()
    })
}

/// Runs the safe tree-walk oracle smoke target.
///
/// # Errors
///
/// Returns [`ParallelRuntimeAuditSmokeError`] if one of the fixed sources fails
/// to lower, fails to evaluate, or produces bytes that differ from the pinned
/// raw oracle output.
pub fn run_parallel_audit_safe_tree_walk_oracle_smoke()
-> Result<ParallelRuntimeAuditSmokeReport, ParallelRuntimeAuditSmokeError> {
    for (source, expected) in SAFE_TREE_WALK_CASES {
        let ir = lower_audit_source(source)?;
        let actual = eval_raw_bytes_with_options(&ir, TreeWalkOptions::new()).map_err(|error| {
            ParallelRuntimeAuditSmokeError::TreeWalk {
                input: source,
                error: Box::new(error),
            }
        })?;
        if actual != expected {
            return Err(ParallelRuntimeAuditSmokeError::RawMismatch {
                input: source,
                expected,
                actual,
            });
        }
    }
    Ok(ParallelRuntimeAuditSmokeReport {
        scope: ParallelRuntimeAuditScope::SafeTreeWalkOracle,
        case_count: SAFE_TREE_WALK_CASES.len(),
        worker_counts: &[],
    })
}

/// Runs the scheduler-backed raw tree-walk smoke target.
///
/// # Errors
///
/// Returns [`ParallelRuntimeAuditSmokeError`] if a fixed source fails to lower,
/// if a worker count is invalid, or if the Chase-Lev raw differential reports a
/// divergence from the serial tree-walk oracle.
///
/// # Panics
///
/// Panics if the scheduler-backed differential harness cannot spawn scoped
/// worker threads.
pub fn run_parallel_audit_parallel_tree_walk_raw_smoke()
-> Result<ParallelRuntimeAuditSmokeReport, ParallelRuntimeAuditSmokeError> {
    let roots = lower_roots(PARALLEL_RAW_CASES)?
        .into_iter()
        .map(ParallelTreeWalkRoot::expression)
        .collect::<Vec<_>>();
    let worker_counts = audit_worker_counts()?;
    compare_parallel_tree_walk_raw_chase_lev_across_worker_counts(
        roots,
        worker_counts.iter().copied(),
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .map_err(ParallelRuntimeAuditSmokeError::ParallelRaw)?;
    Ok(ParallelRuntimeAuditSmokeReport {
        scope: ParallelRuntimeAuditScope::ParallelTreeWalkRawHarness,
        case_count: PARALLEL_RAW_CASES.len(),
        worker_counts: &AUDIT_WORKER_COUNTS,
    })
}

/// Runs the scheduler-backed `.drv` collation smoke target.
///
/// # Errors
///
/// Returns [`ParallelRuntimeAuditSmokeError`] if a fixed source fails to lower,
/// if a worker count is invalid, or if the Chase-Lev `.drv` differential
/// reports a divergence from the serial tree-walk oracle.
///
/// # Panics
///
/// Panics if the scheduler-backed differential harness cannot spawn scoped
/// worker threads.
pub fn run_parallel_audit_parallel_tree_walk_drv_smoke()
-> Result<ParallelRuntimeAuditSmokeReport, ParallelRuntimeAuditSmokeError> {
    let roots = lower_roots(PARALLEL_DRV_CASES)?
        .into_iter()
        .map(ParallelTreeWalkRoot::expression)
        .collect::<Vec<_>>();
    let worker_counts = audit_worker_counts()?;
    compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts(
        roots,
        worker_counts.iter().copied(),
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .map_err(ParallelRuntimeAuditSmokeError::ParallelDrv)?;
    Ok(ParallelRuntimeAuditSmokeReport {
        scope: ParallelRuntimeAuditScope::ParallelTreeWalkDrvHarness,
        case_count: PARALLEL_DRV_CASES.len(),
        worker_counts: &AUDIT_WORKER_COUNTS,
    })
}

/// Runs the scheduler-backed `.drv` standard-matrix collation smoke target.
///
/// # Errors
///
/// Returns [`ParallelRuntimeAuditSmokeError`] if a fixed source fails to lower,
/// if a worker count is invalid, or if the Chase-Lev `.drv` differential over
/// the RFC standard worker matrix reports a divergence from the serial
/// tree-walk oracle.
///
/// # Panics
///
/// Panics if the scheduler-backed differential harness cannot spawn scoped
/// worker threads.
pub fn run_parallel_audit_parallel_tree_walk_drv_standard_matrix_smoke()
-> Result<ParallelRuntimeAuditStandardMatrixSmokeReport, ParallelRuntimeAuditSmokeError> {
    let roots = lower_roots(PARALLEL_DRV_STANDARD_MATRIX_CASES)?
        .into_iter()
        .map(ParallelTreeWalkRoot::expression)
        .collect::<Vec<_>>();
    let report = compare_parallel_tree_walk_drv_outputs_chase_lev_standard_worker_counts(
        roots,
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    )
    .map_err(ParallelRuntimeAuditSmokeError::ParallelDrv)?;
    Ok(ParallelRuntimeAuditStandardMatrixSmokeReport {
        scope: ParallelRuntimeAuditScope::ParallelTreeWalkDrvStandardMatrixHarness,
        case_count: PARALLEL_DRV_STANDARD_MATRIX_CASES.len(),
        worker_counts: report.worker_counts().to_vec(),
    })
}

fn lower_roots<const N: usize>(
    sources: [&'static str; N],
) -> Result<Vec<Ir>, ParallelRuntimeAuditSmokeError> {
    sources.into_iter().map(lower_audit_source).collect()
}

fn lower_audit_source(source: &'static str) -> Result<Ir, ParallelRuntimeAuditSmokeError> {
    let parsed = parse_str(source).map_err(|error| ParallelRuntimeAuditSmokeError::Lower {
        input: source,
        stage: ParallelRuntimeAuditLowerStage::Parse,
        message: error.to_string(),
    })?;
    let resolved = resolve_ast(parsed).map_err(|error| ParallelRuntimeAuditSmokeError::Lower {
        input: source,
        stage: ParallelRuntimeAuditLowerStage::Resolve,
        message: error.to_string(),
    })?;
    aos_nix_dialect::nix_lower(resolved).map_err(|error| ParallelRuntimeAuditSmokeError::Lower {
        input: source,
        stage: ParallelRuntimeAuditLowerStage::Lower,
        message: error.to_string(),
    })
}

fn audit_worker_counts() -> Result<Vec<NonZeroUsize>, ParallelRuntimeAuditSmokeError> {
    AUDIT_WORKER_COUNTS
        .into_iter()
        .map(|count| {
            NonZeroUsize::new(count)
                .ok_or(ParallelRuntimeAuditSmokeError::InvalidWorkerCount { count })
        })
        .collect()
}

/// A successful audit smoke target report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParallelRuntimeAuditSmokeReport {
    scope: ParallelRuntimeAuditScope,
    case_count: usize,
    worker_counts: &'static [usize],
}

impl ParallelRuntimeAuditSmokeReport {
    /// Returns the scope that was exercised.
    pub const fn scope(self) -> ParallelRuntimeAuditScope {
        self.scope
    }

    /// Returns the number of fixed cases exercised.
    pub const fn case_count(self) -> usize {
        self.case_count
    }

    /// Returns the worker counts used by parallel smoke targets.
    pub const fn worker_counts(self) -> &'static [usize] {
        self.worker_counts
    }
}

/// A successful audit smoke target report for the dynamic RFC worker matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelRuntimeAuditStandardMatrixSmokeReport {
    scope: ParallelRuntimeAuditScope,
    case_count: usize,
    worker_counts: Vec<usize>,
}

impl ParallelRuntimeAuditStandardMatrixSmokeReport {
    /// Returns the scope that was exercised.
    pub const fn scope(&self) -> ParallelRuntimeAuditScope {
        self.scope
    }

    /// Returns the number of fixed cases exercised.
    pub const fn case_count(&self) -> usize {
        self.case_count
    }

    /// Returns the worker counts selected by the RFC standard matrix.
    pub fn worker_counts(&self) -> &[usize] {
        &self.worker_counts
    }
}

/// A cargo command needed to run one parallel runtime audit target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelRuntimeAuditInvocation {
    target: ParallelRuntimeAuditTarget,
    cargo_args: Vec<&'static str>,
    environment: Vec<(&'static str, &'static str)>,
    requires_nightly_toolchain: bool,
}

impl ParallelRuntimeAuditInvocation {
    fn for_target(target: ParallelRuntimeAuditTarget) -> Self {
        match target.tool() {
            ParallelRuntimeAuditTool::Loom => Self {
                target,
                cargo_args: cargo_test_args("test", target),
                environment: Vec::new(),
                requires_nightly_toolchain: false,
            },
            ParallelRuntimeAuditTool::Miri => Self {
                target,
                cargo_args: cargo_miri_test_args(target),
                environment: Vec::new(),
                requires_nightly_toolchain: true,
            },
            ParallelRuntimeAuditTool::ThreadSanitizer => Self {
                target,
                cargo_args: cargo_tsan_test_args(target),
                environment: vec![(RUSTFLAGS_ENV, TSAN_RUSTFLAGS)],
                requires_nightly_toolchain: true,
            },
        }
    }

    /// Returns the audit manifest target this command runs.
    pub const fn target(&self) -> ParallelRuntimeAuditTarget {
        self.target
    }

    /// Returns the cargo executable name.
    pub const fn cargo_program(&self) -> &'static str {
        CARGO_PROGRAM
    }

    /// Returns arguments passed to `cargo`.
    ///
    /// Miri targets use `miri test`; ThreadSanitizer targets use `test` with
    /// nightly, sanitizer environment variables, `-Z build-std`, and the
    /// pinned Linux target triple used by the CI audit runner.
    pub fn cargo_args(&self) -> &[&'static str] {
        &self.cargo_args
    }

    /// Returns environment variables required by this command.
    pub fn environment(&self) -> &[(&'static str, &'static str)] {
        &self.environment
    }

    /// Returns whether the command requires a nightly-capable toolchain.
    pub const fn requires_nightly_toolchain(&self) -> bool {
        self.requires_nightly_toolchain
    }
}

fn cargo_test_args(first: &'static str, target: ParallelRuntimeAuditTarget) -> Vec<&'static str> {
    let mut args = vec![first];
    extend_cargo_test_target_args(&mut args, target);
    args
}

fn cargo_miri_test_args(target: ParallelRuntimeAuditTarget) -> Vec<&'static str> {
    let mut args = vec![NIGHTLY_CARGO_ARG, "miri", "test"];
    extend_cargo_test_target_args(&mut args, target);
    args
}

fn cargo_tsan_test_args(target: ParallelRuntimeAuditTarget) -> Vec<&'static str> {
    let mut args = vec![
        NIGHTLY_CARGO_ARG,
        "test",
        "-Z",
        "build-std",
        "--target",
        TSAN_TARGET,
    ];
    extend_cargo_test_target_args(&mut args, target);
    args
}

fn extend_cargo_test_target_args(args: &mut Vec<&'static str>, target: ParallelRuntimeAuditTarget) {
    args.extend_from_slice(&[
        "--manifest-path",
        target.manifest_path(),
        "-p",
        target.package(),
        target.test_filter(),
        "--",
        "--nocapture",
    ]);
}

/// A frontend stage used while lowering an audit smoke source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParallelRuntimeAuditLowerStage {
    /// The source failed to parse.
    Parse,
    /// The parsed source failed scope resolution.
    Resolve,
    /// The resolved source failed IR lowering.
    Lower,
}

/// Errors raised while validating the audit target manifest.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ParallelRuntimeAuditManifestError {
    /// A required tool/scope target is absent.
    #[error("parallel runtime audit target missing for {tool:?} {scope:?}")]
    MissingTarget {
        /// The missing audit tool.
        tool: ParallelRuntimeAuditTool,
        /// The missing audit scope.
        scope: ParallelRuntimeAuditScope,
    },
    /// A target does not name a cargo test filter.
    #[error("parallel runtime audit target has an empty test filter for {tool:?} {scope:?}")]
    EmptyTestFilter {
        /// The audit tool with an invalid target.
        tool: ParallelRuntimeAuditTool,
        /// The audit scope with an invalid target.
        scope: ParallelRuntimeAuditScope,
    },
    /// A target does not explain why it belongs in the matrix.
    #[error("parallel runtime audit target has an empty rationale for {tool:?} {scope:?}")]
    EmptyRationale {
        /// The audit tool with an invalid target.
        tool: ParallelRuntimeAuditTool,
        /// The audit scope with an invalid target.
        scope: ParallelRuntimeAuditScope,
    },
}

/// Errors raised by an audit smoke target.
#[derive(Debug, Error)]
pub enum ParallelRuntimeAuditSmokeError {
    /// A fixed smoke source failed a frontend stage.
    #[error("parallel audit source {input:?} failed {stage:?}: {message}")]
    Lower {
        /// The fixed source that failed.
        input: &'static str,
        /// The frontend stage that failed.
        stage: ParallelRuntimeAuditLowerStage,
        /// A diagnostic message from the frontend.
        message: String,
    },
    /// A fixed smoke source failed during tree-walk evaluation.
    #[error("parallel audit source {input:?} failed tree-walk evaluation")]
    TreeWalk {
        /// The fixed source that failed.
        input: &'static str,
        /// The evaluator error.
        #[source]
        error: Box<TreeWalkError>,
    },
    /// A fixed raw oracle source produced unexpected bytes.
    #[error("parallel audit source {input:?} produced unexpected raw bytes")]
    RawMismatch {
        /// The fixed source that produced the mismatch.
        input: &'static str,
        /// The expected raw bytes.
        expected: &'static [u8],
        /// The actual raw bytes.
        actual: Vec<u8>,
    },
    /// A worker count in the audit matrix was zero.
    #[error("parallel audit worker count {count} is invalid")]
    InvalidWorkerCount {
        /// The invalid worker count.
        count: usize,
    },
    /// The raw parallel tree-walk differential failed.
    #[error("parallel audit raw tree-walk differential failed")]
    ParallelRaw(#[source] ParallelTreeWalkDifferentialError),
    /// The `.drv` parallel tree-walk differential failed.
    #[error("parallel audit .drv tree-walk differential failed")]
    ParallelDrv(#[source] ParallelTreeWalkDrvDifferentialError),
}

#[cfg(test)]
mod tests;
