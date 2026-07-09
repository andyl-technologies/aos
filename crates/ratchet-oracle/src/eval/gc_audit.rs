//! Verification targets for the safe-tree GC memory-safety gate.
//!
//! RFC-0007 requires the safe tree-walk evaluator and future precise-GC
//! integration points to stay clean under Miri, AddressSanitizer, and
//! undefined-behavior tooling. This module names the precursor tool/target
//! matrix and keeps small deterministic smoke harnesses available under stable
//! test filters so CI can run the same code paths under the heavier tools.
//!
//! These smoke harnesses are not the final precise-GC certification run. They
//! are stable entry points for the audit tools and a guard against the target
//! matrix silently drifting away from the safe tree it is supposed to cover.

use thiserror::Error;

use super::tree_walk::{
    EvalOutcome, TreeWalk, TreeWalkError, TreeWalkOptions, eval_raw_bytes_with_evaluator_owned,
    eval_raw_bytes_with_options, eval_whnf_owned_with_options,
};
use crate::{
    compile::{Ir, resolve as resolve_ast},
    heap::HeapMemoryBudget,
    runtime::alloc::{AllocationGcPollReason, AllocationSafepointState, GcStressPolicy},
    syntax::parse_str,
};

const AUDIT_PACKAGE: &str = "ratchet-oracle";
const AUDIT_MANIFEST_PATH: &str = "crates/Cargo.toml";
const CARGO_PROGRAM: &str = "cargo";
const NIGHTLY_CARGO_ARG: &str = "+nightly";
const RUSTFLAGS_ENV: &str = "RUSTFLAGS";
const SANITIZER_TARGET: &str = "x86_64-unknown-linux-gnu";
const ASAN_RUSTFLAGS: &str = "-Z sanitizer=address";
// Rust nightly does not expose LLVM UBSan as `-Z sanitizer=undefined`; use
// rustc's UB runtime checks as a separate precursor target.
const RUST_UB_CHECKS_RUSTFLAGS: &str = "-Z ub-checks=yes";

const GC_SAFETY_AUDIT_TARGETS: [GcSafetyAuditTarget; 6] = [
    GcSafetyAuditTarget::new(
        GcSafetyAuditTool::Miri,
        GcSafetyAuditScope::SafeTreeWalkOracle,
        "gc_safety_audit_safe_tree_walk_miri_smoke",
        "Miri must cover the serial safe tree-walk oracle",
    ),
    GcSafetyAuditTarget::new(
        GcSafetyAuditTool::AddressSanitizer,
        GcSafetyAuditScope::SafeTreeWalkOracle,
        "gc_safety_audit_safe_tree_walk_asan_smoke",
        "AddressSanitizer must cover the serial safe tree-walk oracle",
    ),
    GcSafetyAuditTarget::new(
        GcSafetyAuditTool::RustUbChecks,
        GcSafetyAuditScope::SafeTreeWalkOracle,
        "gc_safety_audit_safe_tree_walk_rust_ub_checks_smoke",
        "undefined-behavior instrumentation must cover the serial safe tree-walk oracle",
    ),
    GcSafetyAuditTarget::new(
        GcSafetyAuditTool::Miri,
        GcSafetyAuditScope::GcStressSafeTreeWalk,
        "gc_safety_audit_gc_stress_miri_smoke",
        "Miri must cover the GC-stress safe tree-walk bridge",
    ),
    GcSafetyAuditTarget::new(
        GcSafetyAuditTool::AddressSanitizer,
        GcSafetyAuditScope::GcStressSafeTreeWalk,
        "gc_safety_audit_gc_stress_asan_smoke",
        "AddressSanitizer must cover the GC-stress safe tree-walk bridge",
    ),
    GcSafetyAuditTarget::new(
        GcSafetyAuditTool::RustUbChecks,
        GcSafetyAuditScope::GcStressSafeTreeWalk,
        "gc_safety_audit_gc_stress_rust_ub_checks_smoke",
        "undefined-behavior instrumentation must cover the GC-stress safe tree-walk bridge",
    ),
];

const REQUIRED_AUDIT_TARGETS: [(GcSafetyAuditTool, GcSafetyAuditScope); 6] = [
    (
        GcSafetyAuditTool::Miri,
        GcSafetyAuditScope::SafeTreeWalkOracle,
    ),
    (
        GcSafetyAuditTool::AddressSanitizer,
        GcSafetyAuditScope::SafeTreeWalkOracle,
    ),
    (
        GcSafetyAuditTool::RustUbChecks,
        GcSafetyAuditScope::SafeTreeWalkOracle,
    ),
    (
        GcSafetyAuditTool::Miri,
        GcSafetyAuditScope::GcStressSafeTreeWalk,
    ),
    (
        GcSafetyAuditTool::AddressSanitizer,
        GcSafetyAuditScope::GcStressSafeTreeWalk,
    ),
    (
        GcSafetyAuditTool::RustUbChecks,
        GcSafetyAuditScope::GcStressSafeTreeWalk,
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

const GC_STRESS_CASES: [(&str, &[u8]); 4] = [
    ("\"gc-stress-string\"", br#""gc-stress-string""#),
    (
        "let f = x: x + 1; in builtins.map f [ 1 2 3 ]",
        b"[ 2 3 4 ]",
    ),
    (
        "let shared = { a = 1 + 2; b = \"value\"; }; in { inherit shared; again = shared; }",
        b"{ again = { a = 3; b = \"value\"; }; shared = \xc2\xabrepeated\xc2\xbb; }",
    ),
    (
        "builtins.toJSON { path = builtins.storeDir; ok = true; }",
        br#""{\"ok\":true,\"path\":\"/nix/store\"}""#,
    ),
];

const GC_STRESS_ADMISSION_CASE: &str = "x: x";

/// A verification tool required by the safe-tree GC audit gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GcSafetyAuditTool {
    /// The Miri interpreter for undefined-behavior checks over safe Rust paths.
    Miri,
    /// AddressSanitizer for native memory-access instrumentation.
    AddressSanitizer,
    /// The Rust UB-check runner used as a distinct precursor to the UBSan gate.
    RustUbChecks,
}

/// A safe-tree code path covered by the GC audit gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GcSafetyAuditScope {
    /// The serial safe tree-walk oracle without GC-stress options.
    SafeTreeWalkOracle,
    /// The safe tree-walk oracle under every-safepoint GC stress.
    GcStressSafeTreeWalk,
}

/// One cargo test target in the safe-tree GC audit matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcSafetyAuditTarget {
    tool: GcSafetyAuditTool,
    scope: GcSafetyAuditScope,
    package: &'static str,
    manifest_path: &'static str,
    test_filter: &'static str,
    rationale: &'static str,
}

impl GcSafetyAuditTarget {
    const fn new(
        tool: GcSafetyAuditTool,
        scope: GcSafetyAuditScope,
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
    pub const fn tool(self) -> GcSafetyAuditTool {
        self.tool
    }

    /// Returns the safe-tree path covered by this target.
    pub const fn scope(self) -> GcSafetyAuditScope {
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

    /// Returns why this target belongs in the matrix.
    pub const fn rationale(self) -> &'static str {
        self.rationale
    }
}

/// A validated safe-tree GC audit target manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcSafetyAuditManifest {
    targets: &'static [GcSafetyAuditTarget],
}

impl GcSafetyAuditManifest {
    /// Returns every audit target.
    pub const fn targets(self) -> &'static [GcSafetyAuditTarget] {
        self.targets
    }

    /// Returns the number of audit targets.
    pub const fn target_count(self) -> usize {
        self.targets.len()
    }

    /// Finds an audit target by tool and scope.
    pub fn target_for(
        self,
        tool: GcSafetyAuditTool,
        scope: GcSafetyAuditScope,
    ) -> Option<GcSafetyAuditTarget> {
        self.targets
            .iter()
            .copied()
            .find(|target| target.tool == tool && target.scope == scope)
    }
}

/// Returns the current safe-tree GC audit target manifest.
pub const fn gc_safety_audit_manifest() -> GcSafetyAuditManifest {
    GcSafetyAuditManifest {
        targets: &GC_SAFETY_AUDIT_TARGETS,
    }
}

/// Validates and returns the safe-tree GC audit target manifest.
///
/// # Errors
///
/// Returns [`GcSafetyAuditManifestError`] if a required tool/scope pair is
/// missing or if a target has no test filter or rationale.
pub fn validate_gc_safety_audit_manifest()
-> Result<GcSafetyAuditManifest, GcSafetyAuditManifestError> {
    let manifest = gc_safety_audit_manifest();
    for target in manifest.targets {
        if target.test_filter.is_empty() {
            return Err(GcSafetyAuditManifestError::EmptyTestFilter {
                tool: target.tool,
                scope: target.scope,
            });
        }
        if target.rationale.is_empty() {
            return Err(GcSafetyAuditManifestError::EmptyRationale {
                tool: target.tool,
                scope: target.scope,
            });
        }
    }
    for (tool, scope) in REQUIRED_AUDIT_TARGETS {
        if manifest.target_for(tool, scope).is_none() {
            return Err(GcSafetyAuditManifestError::MissingTarget { tool, scope });
        }
    }
    Ok(manifest)
}

/// Returns the cargo invocations for the current safe-tree GC audit matrix.
///
/// The returned commands are not executed by ordinary tests. They provide a
/// stable adapter boundary for CI to run Miri, AddressSanitizer, and
/// undefined-behavior instrumentation without reconstructing command lines from
/// prose.
///
/// # Errors
///
/// Returns [`GcSafetyAuditManifestError`] if the audit target manifest is
/// invalid.
pub fn gc_safety_audit_invocations()
-> Result<Vec<GcSafetyAuditInvocation>, GcSafetyAuditManifestError> {
    validate_gc_safety_audit_manifest().map(|manifest| {
        manifest
            .targets()
            .iter()
            .copied()
            .map(GcSafetyAuditInvocation::for_target)
            .collect()
    })
}

/// Runs the safe tree-walk oracle smoke target.
///
/// # Errors
///
/// Returns [`GcSafetyAuditSmokeError`] if one of the fixed sources fails to
/// lower, fails to evaluate, or produces bytes that differ from the pinned raw
/// oracle output.
pub fn run_gc_safety_audit_safe_tree_walk_smoke()
-> Result<GcSafetyAuditSmokeReport, GcSafetyAuditSmokeError> {
    for (source, expected) in SAFE_TREE_WALK_CASES {
        assert_raw_case(source, expected, TreeWalkOptions::new())?;
    }
    Ok(GcSafetyAuditSmokeReport {
        scope: GcSafetyAuditScope::SafeTreeWalkOracle,
        case_count: SAFE_TREE_WALK_CASES.len(),
        generation_rewrites: 0,
    })
}

/// Runs the GC-stress safe tree-walk smoke target.
///
/// # Errors
///
/// Returns [`GcSafetyAuditSmokeError`] if a fixed source fails to lower, fails
/// to evaluate, produces different raw bytes under GC stress, or fails to
/// exercise allocator safepoints or the Tier-B admission metadata bridge.
pub fn run_gc_safety_audit_gc_stress_smoke()
-> Result<GcSafetyAuditSmokeReport, GcSafetyAuditSmokeError> {
    for (source, expected) in GC_STRESS_CASES {
        assert_gc_stress_raw_case(source, expected)?;
    }

    let outcome = eval_owned_case(GC_STRESS_ADMISSION_CASE, gc_stress_admission_options()?)?;
    let admission = outcome.tier_b_transition_admission_report().ok_or(
        GcSafetyAuditSmokeError::MissingTierBAdmission {
            input: GC_STRESS_ADMISSION_CASE,
        },
    )?;
    if admission.generation_rewrites() == 0 {
        return Err(GcSafetyAuditSmokeError::MissingGenerationRewrite {
            input: GC_STRESS_ADMISSION_CASE,
        });
    }

    Ok(GcSafetyAuditSmokeReport {
        scope: GcSafetyAuditScope::GcStressSafeTreeWalk,
        case_count: GC_STRESS_CASES.len() + 1,
        generation_rewrites: admission.generation_rewrites() as u64,
    })
}

fn assert_raw_case(
    source: &'static str,
    expected: &'static [u8],
    options: TreeWalkOptions,
) -> Result<(), GcSafetyAuditSmokeError> {
    let ir = lower_audit_source(source)?;
    let actual = eval_raw_bytes_with_options(&ir, options).map_err(|error| {
        GcSafetyAuditSmokeError::TreeWalk {
            input: source,
            error: Box::new(error),
        }
    })?;
    if actual != expected {
        return Err(GcSafetyAuditSmokeError::RawMismatch {
            input: source,
            expected,
            actual,
        });
    }
    Ok(())
}

fn assert_gc_stress_raw_case(
    source: &'static str,
    expected: &'static [u8],
) -> Result<(), GcSafetyAuditSmokeError> {
    let ir = lower_audit_source(source)?;
    let evaluator = TreeWalk::with_options(&ir, gc_stress_options());
    let (actual, evaluator) =
        eval_raw_bytes_with_evaluator_owned(&ir, evaluator).map_err(|error| {
            GcSafetyAuditSmokeError::TreeWalk {
                input: source,
                error: Box::new(error),
            }
        })?;
    if actual != expected {
        return Err(GcSafetyAuditSmokeError::RawMismatch {
            input: source,
            expected,
            actual,
        });
    }

    if !saw_gc_stress_safepoint(evaluator.heap().allocation_safepoints())
        && !saw_gc_stress_safepoint(evaluator.heap().permanent_allocation_safepoints())
    {
        return Err(GcSafetyAuditSmokeError::MissingGcStressSafepoint { input: source });
    }

    Ok(())
}

fn saw_gc_stress_safepoint(safepoints: AllocationSafepointState) -> bool {
    safepoints.last().is_some_and(|safepoint| {
        safepoint.gc_poll_reason() == Some(AllocationGcPollReason::GcStressEverySafepoint)
    })
}

fn eval_owned_case(
    source: &'static str,
    options: TreeWalkOptions,
) -> Result<EvalOutcome, GcSafetyAuditSmokeError> {
    let ir = lower_audit_source(source)?;
    eval_whnf_owned_with_options(&ir, options).map_err(|error| GcSafetyAuditSmokeError::TreeWalk {
        input: source,
        error: Box::new(error),
    })
}

fn lower_audit_source(source: &'static str) -> Result<Ir, GcSafetyAuditSmokeError> {
    let parsed = parse_str(source).map_err(|error| GcSafetyAuditSmokeError::Lower {
        input: source,
        stage: GcSafetyAuditLowerStage::Parse,
        message: error.to_string(),
    })?;
    let resolved = resolve_ast(parsed).map_err(|error| GcSafetyAuditSmokeError::Lower {
        input: source,
        stage: GcSafetyAuditLowerStage::Resolve,
        message: error.to_string(),
    })?;
    aos_nix_dialect::nix_lower(resolved).map_err(|error| GcSafetyAuditSmokeError::Lower {
        input: source,
        stage: GcSafetyAuditLowerStage::Lower,
        message: error.to_string(),
    })
}

fn gc_stress_options() -> TreeWalkOptions {
    TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint())
}

fn gc_stress_admission_options() -> Result<TreeWalkOptions, GcSafetyAuditSmokeError> {
    let mut options = gc_stress_options();
    let budget = HeapMemoryBudget::new(1)
        .map_err(|_| GcSafetyAuditSmokeError::InvalidMemoryBudget { bytes: 1 })?;
    options.set_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
    // Generation rewrites live on record-table worker objects (doc 30
    // FV-3 scaffolding placement).
    options.set_record_worker_closures_for_gc_scaffolding(true);
    Ok(options)
}

/// A successful safe-tree GC audit smoke target report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcSafetyAuditSmokeReport {
    scope: GcSafetyAuditScope,
    case_count: usize,
    generation_rewrites: u64,
}

impl GcSafetyAuditSmokeReport {
    /// Returns the scope that was exercised.
    pub const fn scope(self) -> GcSafetyAuditScope {
        self.scope
    }

    /// Returns the number of fixed cases exercised.
    pub const fn case_count(self) -> usize {
        self.case_count
    }

    /// Returns generation rewrites applied by the admission bridge.
    pub const fn generation_rewrites(self) -> u64 {
        self.generation_rewrites
    }
}

/// A cargo command needed to run one safe-tree GC audit target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcSafetyAuditInvocation {
    target: GcSafetyAuditTarget,
    cargo_args: Vec<&'static str>,
    environment: Vec<(&'static str, &'static str)>,
    requires_nightly_toolchain: bool,
}

impl GcSafetyAuditInvocation {
    fn for_target(target: GcSafetyAuditTarget) -> Self {
        match target.tool() {
            GcSafetyAuditTool::Miri => Self {
                target,
                cargo_args: cargo_miri_test_args(target),
                environment: Vec::new(),
                requires_nightly_toolchain: true,
            },
            GcSafetyAuditTool::AddressSanitizer => Self {
                target,
                cargo_args: cargo_sanitizer_test_args(target),
                environment: vec![(RUSTFLAGS_ENV, ASAN_RUSTFLAGS)],
                requires_nightly_toolchain: true,
            },
            GcSafetyAuditTool::RustUbChecks => Self {
                target,
                cargo_args: cargo_sanitizer_test_args(target),
                environment: vec![(RUSTFLAGS_ENV, RUST_UB_CHECKS_RUSTFLAGS)],
                requires_nightly_toolchain: true,
            },
        }
    }

    /// Returns the audit manifest target this command runs.
    pub const fn target(&self) -> GcSafetyAuditTarget {
        self.target
    }

    /// Returns the cargo executable name.
    pub const fn cargo_program(&self) -> &'static str {
        CARGO_PROGRAM
    }

    /// Returns arguments passed to `cargo`.
    ///
    /// Miri targets use `miri test`. AddressSanitizer and Rust UB-check targets
    /// use `test` with nightly, build-std, and the pinned Linux target triple
    /// used by the CI audit runner.
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

fn cargo_miri_test_args(target: GcSafetyAuditTarget) -> Vec<&'static str> {
    let mut args = vec![NIGHTLY_CARGO_ARG, "miri", "test"];
    extend_cargo_test_target_args(&mut args, target);
    args
}

fn cargo_sanitizer_test_args(target: GcSafetyAuditTarget) -> Vec<&'static str> {
    let mut args = vec![
        NIGHTLY_CARGO_ARG,
        "test",
        "-Z",
        "build-std",
        "--target",
        SANITIZER_TARGET,
    ];
    extend_cargo_test_target_args(&mut args, target);
    args
}

fn extend_cargo_test_target_args(args: &mut Vec<&'static str>, target: GcSafetyAuditTarget) {
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

/// A frontend stage used while lowering a safe-tree GC audit smoke source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcSafetyAuditLowerStage {
    /// The source failed to parse.
    Parse,
    /// The parsed source failed scope resolution.
    Resolve,
    /// The resolved source failed IR lowering.
    Lower,
}

/// Errors raised while validating the audit target manifest.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GcSafetyAuditManifestError {
    /// A required tool/scope target is absent.
    #[error("safe-tree GC audit target missing for {tool:?} {scope:?}")]
    MissingTarget {
        /// The missing audit tool.
        tool: GcSafetyAuditTool,
        /// The missing audit scope.
        scope: GcSafetyAuditScope,
    },
    /// A target does not name a cargo test filter.
    #[error("safe-tree GC audit target has an empty test filter for {tool:?} {scope:?}")]
    EmptyTestFilter {
        /// The audit tool with an invalid target.
        tool: GcSafetyAuditTool,
        /// The audit scope with an invalid target.
        scope: GcSafetyAuditScope,
    },
    /// A target does not explain why it belongs in the matrix.
    #[error("safe-tree GC audit target has an empty rationale for {tool:?} {scope:?}")]
    EmptyRationale {
        /// The audit tool with an invalid target.
        tool: GcSafetyAuditTool,
        /// The audit scope with an invalid target.
        scope: GcSafetyAuditScope,
    },
}

/// Errors raised by a safe-tree GC audit smoke target.
#[derive(Debug, Error)]
pub enum GcSafetyAuditSmokeError {
    /// A fixed smoke source failed a frontend stage.
    #[error("safe-tree GC audit source {input:?} failed {stage:?}: {message}")]
    Lower {
        /// The fixed source that failed.
        input: &'static str,
        /// The frontend stage that failed.
        stage: GcSafetyAuditLowerStage,
        /// A diagnostic message from the frontend.
        message: String,
    },
    /// A fixed smoke source failed during tree-walk evaluation.
    #[error("safe-tree GC audit source {input:?} failed tree-walk evaluation")]
    TreeWalk {
        /// The fixed source that failed.
        input: &'static str,
        /// The evaluator error.
        #[source]
        error: Box<TreeWalkError>,
    },
    /// A fixed raw oracle source produced unexpected bytes.
    #[error("safe-tree GC audit source {input:?} produced unexpected raw bytes")]
    RawMismatch {
        /// The fixed source that produced the mismatch.
        input: &'static str,
        /// The expected raw bytes.
        expected: &'static [u8],
        /// The actual raw bytes.
        actual: Vec<u8>,
    },
    /// The GC-stress owned smoke case did not request Tier-B admission.
    #[error("safe-tree GC audit source {input:?} did not record Tier-B admission")]
    MissingTierBAdmission {
        /// The fixed source that failed to exercise admission.
        input: &'static str,
    },
    /// The GC-stress owned smoke case did not rewrite generation metadata.
    #[error("safe-tree GC audit source {input:?} did not rewrite generation metadata")]
    MissingGenerationRewrite {
        /// The fixed source that failed to exercise generation rewrites.
        input: &'static str,
    },
    /// A GC-stress raw smoke case did not record an allocation safepoint.
    #[error("safe-tree GC audit source {input:?} did not record a GC-stress safepoint")]
    MissingGcStressSafepoint {
        /// The fixed source that failed to exercise GC-stress allocation polling.
        input: &'static str,
    },
    /// The fixed GC-stress budget could not be constructed.
    #[error("safe-tree GC audit memory budget {bytes} is invalid")]
    InvalidMemoryBudget {
        /// The configured memory-budget byte count.
        bytes: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_safety_audit_manifest_covers_safe_tree_tool_matrix() {
        let manifest = validate_gc_safety_audit_manifest().expect("audit manifest validates");
        let expected_targets = [
            (
                GcSafetyAuditTool::Miri,
                GcSafetyAuditScope::SafeTreeWalkOracle,
                "gc_safety_audit_safe_tree_walk_miri_smoke",
            ),
            (
                GcSafetyAuditTool::AddressSanitizer,
                GcSafetyAuditScope::SafeTreeWalkOracle,
                "gc_safety_audit_safe_tree_walk_asan_smoke",
            ),
            (
                GcSafetyAuditTool::RustUbChecks,
                GcSafetyAuditScope::SafeTreeWalkOracle,
                "gc_safety_audit_safe_tree_walk_rust_ub_checks_smoke",
            ),
            (
                GcSafetyAuditTool::Miri,
                GcSafetyAuditScope::GcStressSafeTreeWalk,
                "gc_safety_audit_gc_stress_miri_smoke",
            ),
            (
                GcSafetyAuditTool::AddressSanitizer,
                GcSafetyAuditScope::GcStressSafeTreeWalk,
                "gc_safety_audit_gc_stress_asan_smoke",
            ),
            (
                GcSafetyAuditTool::RustUbChecks,
                GcSafetyAuditScope::GcStressSafeTreeWalk,
                "gc_safety_audit_gc_stress_rust_ub_checks_smoke",
            ),
        ];

        assert_eq!(manifest.target_count(), expected_targets.len());
        for (tool, scope, test_filter) in expected_targets {
            let target = manifest
                .target_for(tool, scope)
                .expect("required target is present");
            assert_eq!(target.package(), AUDIT_PACKAGE);
            assert_eq!(target.manifest_path(), AUDIT_MANIFEST_PATH);
            assert_eq!(target.test_filter(), test_filter);
            assert!(!target.rationale().is_empty());
        }
    }

    #[test]
    fn gc_safety_audit_invocations_pin_tool_commands() {
        let invocations = gc_safety_audit_invocations().expect("audit invocations validate");
        assert_eq!(
            invocations.len(),
            validate_gc_safety_audit_manifest()
                .expect("audit manifest validates")
                .target_count()
        );

        let miri = invocation_for(
            &invocations,
            GcSafetyAuditTool::Miri,
            GcSafetyAuditScope::SafeTreeWalkOracle,
        );
        assert_eq!(miri.cargo_program(), "cargo");
        assert_eq!(
            miri.cargo_args(),
            &[
                NIGHTLY_CARGO_ARG,
                "miri",
                "test",
                "--manifest-path",
                AUDIT_MANIFEST_PATH,
                "-p",
                AUDIT_PACKAGE,
                "gc_safety_audit_safe_tree_walk_miri_smoke",
                "--",
                "--nocapture",
            ]
        );
        assert!(miri.environment().is_empty());
        assert!(miri.requires_nightly_toolchain());

        let asan = invocation_for(
            &invocations,
            GcSafetyAuditTool::AddressSanitizer,
            GcSafetyAuditScope::GcStressSafeTreeWalk,
        );
        assert_eq!(
            asan.cargo_args(),
            &[
                NIGHTLY_CARGO_ARG,
                "test",
                "-Z",
                "build-std",
                "--target",
                SANITIZER_TARGET,
                "--manifest-path",
                AUDIT_MANIFEST_PATH,
                "-p",
                AUDIT_PACKAGE,
                "gc_safety_audit_gc_stress_asan_smoke",
                "--",
                "--nocapture",
            ]
        );
        assert_eq!(asan.environment(), &[(RUSTFLAGS_ENV, ASAN_RUSTFLAGS)]);
        assert!(asan.requires_nightly_toolchain());

        let rust_ub_checks = invocation_for(
            &invocations,
            GcSafetyAuditTool::RustUbChecks,
            GcSafetyAuditScope::GcStressSafeTreeWalk,
        );
        assert_eq!(
            rust_ub_checks.cargo_args(),
            &[
                NIGHTLY_CARGO_ARG,
                "test",
                "-Z",
                "build-std",
                "--target",
                SANITIZER_TARGET,
                "--manifest-path",
                AUDIT_MANIFEST_PATH,
                "-p",
                AUDIT_PACKAGE,
                "gc_safety_audit_gc_stress_rust_ub_checks_smoke",
                "--",
                "--nocapture",
            ]
        );
        assert_eq!(
            rust_ub_checks.environment(),
            &[(RUSTFLAGS_ENV, RUST_UB_CHECKS_RUSTFLAGS)]
        );
        assert!(rust_ub_checks.requires_nightly_toolchain());
    }

    fn invocation_for(
        invocations: &[GcSafetyAuditInvocation],
        tool: GcSafetyAuditTool,
        scope: GcSafetyAuditScope,
    ) -> &GcSafetyAuditInvocation {
        invocations
            .iter()
            .find(|invocation| {
                invocation.target().tool() == tool && invocation.target().scope() == scope
            })
            .expect("audit invocation is present")
    }

    #[test]
    fn gc_safety_audit_safe_tree_walk_miri_smoke() {
        assert_safe_tree_report(run_gc_safety_audit_safe_tree_walk_smoke());
    }

    #[test]
    fn gc_safety_audit_safe_tree_walk_asan_smoke() {
        assert_safe_tree_report(run_gc_safety_audit_safe_tree_walk_smoke());
    }

    #[test]
    fn gc_safety_audit_safe_tree_walk_rust_ub_checks_smoke() {
        assert_safe_tree_report(run_gc_safety_audit_safe_tree_walk_smoke());
    }

    #[test]
    fn gc_safety_audit_gc_stress_miri_smoke() {
        assert_gc_stress_report(run_gc_safety_audit_gc_stress_smoke());
    }

    #[test]
    fn gc_safety_audit_gc_stress_asan_smoke() {
        assert_gc_stress_report(run_gc_safety_audit_gc_stress_smoke());
    }

    #[test]
    fn gc_safety_audit_gc_stress_rust_ub_checks_smoke() {
        assert_gc_stress_report(run_gc_safety_audit_gc_stress_smoke());
    }

    fn assert_safe_tree_report(report: Result<GcSafetyAuditSmokeReport, GcSafetyAuditSmokeError>) {
        let report = report.expect("safe tree-walk audit smoke passes");

        assert_eq!(report.scope(), GcSafetyAuditScope::SafeTreeWalkOracle);
        assert_eq!(report.case_count(), SAFE_TREE_WALK_CASES.len());
        assert_eq!(report.generation_rewrites(), 0);
    }

    fn assert_gc_stress_report(report: Result<GcSafetyAuditSmokeReport, GcSafetyAuditSmokeError>) {
        let report = report.expect("GC-stress audit smoke passes");

        assert_eq!(report.scope(), GcSafetyAuditScope::GcStressSafeTreeWalk);
        assert_eq!(report.case_count(), GC_STRESS_CASES.len() + 1);
        assert!(report.generation_rewrites() > 0);
    }
}
