//! GC conformance targets for byte-invisible heap metadata transitions.
//!
//! RFC-0007 requires GC and Tier-B heap metadata to be invisible to the
//! language conformance surfaces. This module adds a narrow precursor target:
//! fixed strict raw evaluations are rendered under Tier A, then rendered again
//! after the current Tier-B transition request has validated and rewritten
//! heap-record generation metadata. Fixed derivationStrict cases additionally
//! compare root `.drvPath` raw bytes before and after admission, plus recorded
//! derivation path/ATerm side-table surfaces under Tier A and Tier-B-configured
//! evaluation. It does not install a precise collector, run the full language
//! conformance harness, or close the checklist's broad Tier-A/Tier-B parity
//! gate.

use thiserror::Error;

use super::{
    heap::EvalHeapTierBAdmissionReport,
    tree_walk::{
        EvalStats, TreeWalkError, TreeWalkOptions, eval_derivation_aterm_surfaces_with_options,
        eval_raw_bytes_with_options, eval_raw_bytes_with_post_render_tier_b_admission,
    },
};
use crate::{
    compile::{Ir, resolve as resolve_ast},
    heap::HeapMemoryBudget,
    syntax::parse_str,
};

const CONFORMANCE_PACKAGE: &str = "ratchet-oracle";
const CONFORMANCE_MANIFEST_PATH: &str = "crates/Cargo.toml";
const CARGO_PROGRAM: &str = "cargo";

const GC_CONFORMANCE_TARGETS: [GcConformanceTarget; 2] = [
    GcConformanceTarget::new(
        GcConformanceScope::TierATierBRawBytes,
        "gc_conformance_tier_a_tier_b_raw_bytes_smoke",
        "Tier-B admission metadata must stay invisible to strict raw bytes for fixed heap-backed cases",
    ),
    GcConformanceTarget::new(
        GcConformanceScope::TierATierBDerivationAtermBytes,
        "gc_conformance_tier_a_tier_b_drv_bytes_smoke",
        "Tier-B metadata must stay invisible to fixed derivationStrict root path bytes and ATerm side-table surfaces",
    ),
];

const REQUIRED_GC_CONFORMANCE_TARGETS: [GcConformanceScope; 2] = [
    GcConformanceScope::TierATierBRawBytes,
    GcConformanceScope::TierATierBDerivationAtermBytes,
];

const TIER_A_TIER_B_RAW_CASES: [(&str, &[u8]); 4] = [
    (
        r#"{ b = 2; a = [ 1 true null ]; }"#,
        b"{ a = [ 1 true null ]; b = 2; }",
    ),
    (
        r#"let shared = { a = 1 + 2; b = "value"; }; in { inherit shared; again = shared; }"#,
        b"{ again = { a = 3; b = \"value\"; }; shared = \xc2\xabrepeated\xc2\xbb; }",
    ),
    (
        "builtins.toJSON { z = 1; a = [ true null ]; }",
        br#""{\"a\":[true,null],\"z\":1}""#,
    ),
    (r#"(x: x) "admitted""#, br#""admitted""#),
];

const TIER_A_TIER_B_DRV_CASES: [&str; 2] = [
    r#"let d = derivationStrict {
         name = "gc-static";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         args = [ "--flag" ];
         env = "value";
       };
       in d.drvPath"#,
    r#"let base = derivationStrict {
         name = "gc-base";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
       };
       downstream = derivationStrict {
         name = "gc-downstream";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         args = [ base.drvPath ];
         baseOut = base.out;
       };
       in downstream.drvPath"#,
];

/// A GC conformance surface covered by a smoke target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GcConformanceScope {
    /// Strict raw bytes before and after Tier-B admission metadata updates.
    TierATierBRawBytes,
    /// Root `.drvPath` bytes and recorded ATerm side-table bytes under Tier B.
    TierATierBDerivationAtermBytes,
}

/// One cargo test target in the GC conformance matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcConformanceTarget {
    scope: GcConformanceScope,
    package: &'static str,
    manifest_path: &'static str,
    test_filter: &'static str,
    rationale: &'static str,
}

impl GcConformanceTarget {
    const fn new(
        scope: GcConformanceScope,
        test_filter: &'static str,
        rationale: &'static str,
    ) -> Self {
        Self {
            scope,
            package: CONFORMANCE_PACKAGE,
            manifest_path: CONFORMANCE_MANIFEST_PATH,
            test_filter,
            rationale,
        }
    }

    /// Returns the conformance surface this target exercises.
    pub const fn scope(self) -> GcConformanceScope {
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

    /// Returns why this target belongs in the conformance matrix.
    pub const fn rationale(self) -> &'static str {
        self.rationale
    }
}

/// A validated GC conformance target manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcConformanceManifest {
    targets: &'static [GcConformanceTarget],
}

impl GcConformanceManifest {
    /// Returns every conformance target.
    pub const fn targets(self) -> &'static [GcConformanceTarget] {
        self.targets
    }

    /// Returns the number of conformance targets.
    pub const fn target_count(self) -> usize {
        self.targets.len()
    }

    /// Finds a conformance target by scope.
    pub fn target_for(self, scope: GcConformanceScope) -> Option<GcConformanceTarget> {
        self.targets
            .iter()
            .copied()
            .find(|target| target.scope == scope)
    }
}

/// Returns the current GC conformance target manifest.
pub const fn gc_conformance_manifest() -> GcConformanceManifest {
    GcConformanceManifest {
        targets: &GC_CONFORMANCE_TARGETS,
    }
}

/// Validates and returns the GC conformance target manifest.
///
/// # Errors
///
/// Returns [`GcConformanceManifestError`] if a required scope is missing or if
/// a target has no test filter or rationale.
pub fn validate_gc_conformance_manifest()
-> Result<GcConformanceManifest, GcConformanceManifestError> {
    let manifest = gc_conformance_manifest();
    for target in manifest.targets {
        if target.test_filter.is_empty() {
            return Err(GcConformanceManifestError::EmptyTestFilter {
                scope: target.scope,
            });
        }
        if target.rationale.is_empty() {
            return Err(GcConformanceManifestError::EmptyRationale {
                scope: target.scope,
            });
        }
    }
    for scope in REQUIRED_GC_CONFORMANCE_TARGETS {
        if manifest.target_for(scope).is_none() {
            return Err(GcConformanceManifestError::MissingTarget { scope });
        }
    }
    Ok(manifest)
}

/// Returns cargo invocations for the current GC conformance matrix.
///
/// # Errors
///
/// Returns [`GcConformanceManifestError`] if the conformance manifest is
/// invalid.
pub fn gc_conformance_invocations()
-> Result<Vec<GcConformanceInvocation>, GcConformanceManifestError> {
    validate_gc_conformance_manifest().map(|manifest| {
        manifest
            .targets()
            .iter()
            .copied()
            .map(GcConformanceInvocation::for_target)
            .collect()
    })
}

/// Runs the Tier-A/Tier-B strict raw byte parity smoke target.
///
/// # Errors
///
/// Returns [`GcConformanceSmokeError`] if a fixed source fails to lower or
/// evaluate, if Tier-A or Tier-B rendering differs from the pinned raw bytes,
/// if Tier-B admission does not run, or if generation rewrites are missing.
pub fn run_gc_conformance_tier_a_tier_b_raw_bytes_smoke()
-> Result<GcConformanceSmokeReport, GcConformanceSmokeError> {
    let mut admissions = 0u64;
    let mut generation_rewrites = 0u64;

    for (source, expected) in TIER_A_TIER_B_RAW_CASES {
        let ir = lower_conformance_source(source)?;
        let tier_a = eval_raw_bytes_with_options(&ir, TreeWalkOptions::new()).map_err(|error| {
            GcConformanceSmokeError::TreeWalk {
                input: source,
                error: Box::new(error),
            }
        })?;
        assert_raw_eq(source, RawRenderMode::TierA, expected, &tier_a)?;

        let (pre_admission, tier_b, admission_report, stats) =
            eval_raw_bytes_with_post_render_tier_b_admission(&ir, tier_b_options()?).map_err(
                |error| GcConformanceSmokeError::TreeWalk {
                    input: source,
                    error: Box::new(error),
                },
            )?;
        assert_raw_eq(
            source,
            RawRenderMode::TierBPreAdmission,
            expected,
            &pre_admission,
        )?;
        assert_raw_eq(source, RawRenderMode::TierBPostAdmission, expected, &tier_b)?;
        if tier_a != tier_b {
            return Err(GcConformanceSmokeError::TierParityMismatch {
                input: source,
                tier_a,
                tier_b,
            });
        }
        if pre_admission != tier_b {
            return Err(GcConformanceSmokeError::AdmissionRenderMismatch {
                input: source,
                pre_admission,
                post_admission: tier_b,
            });
        }

        let admission = admission_report
            .ok_or(GcConformanceSmokeError::MissingTierBAdmission { input: source })?;
        if admission.generation_rewrites() == 0 {
            return Err(GcConformanceSmokeError::MissingGenerationRewrite { input: source });
        }
        assert_admission_stats_match(source, &admission, &stats)?;
        admissions = admissions.saturating_add(1);
        generation_rewrites = generation_rewrites.saturating_add(usize_to_u64(
            admission.generation_rewrites(),
            "Tier-B generation rewrites",
        )?);
    }

    Ok(GcConformanceSmokeReport {
        scope: GcConformanceScope::TierATierBRawBytes,
        case_count: TIER_A_TIER_B_RAW_CASES.len(),
        checked_surface_count: usize_to_u64(
            TIER_A_TIER_B_RAW_CASES.len(),
            "Tier-A/Tier-B raw conformance surfaces",
        )?,
        tier_b_admissions: admissions,
        tier_b_generation_rewrites: generation_rewrites,
    })
}

/// Runs the Tier-A/Tier-B derivation byte-surface parity smoke target.
///
/// # Errors
///
/// Returns [`GcConformanceSmokeError`] if a fixed source fails to lower or
/// evaluate, if no derivation ATerm side-table bytes are observed, if Tier-A
/// and Tier-B configured derivation side-table surfaces differ, if root raw
/// `.drvPath` bytes change, if Tier-B admission does not run, or if generation
/// rewrites are missing.
pub fn run_gc_conformance_tier_a_tier_b_drv_bytes_smoke()
-> Result<GcConformanceSmokeReport, GcConformanceSmokeError> {
    let mut checked_surface_count = 0u64;
    let mut admissions = 0u64;
    let mut generation_rewrites = 0u64;

    for source in TIER_A_TIER_B_DRV_CASES {
        let ir = lower_conformance_source(source)?;
        let tier_a_raw =
            eval_raw_bytes_with_options(&ir, TreeWalkOptions::new()).map_err(|error| {
                GcConformanceSmokeError::TreeWalk {
                    input: source,
                    error: Box::new(error),
                }
            })?;
        let (tier_b_pre_admission_raw, tier_b_post_admission_raw, admission_report, stats) =
            eval_raw_bytes_with_post_render_tier_b_admission(&ir, tier_b_options()?).map_err(
                |error| GcConformanceSmokeError::TreeWalk {
                    input: source,
                    error: Box::new(error),
                },
            )?;
        if tier_a_raw != tier_b_pre_admission_raw {
            return Err(GcConformanceSmokeError::TierParityMismatch {
                input: source,
                tier_a: tier_a_raw,
                tier_b: tier_b_pre_admission_raw,
            });
        }
        if tier_b_pre_admission_raw != tier_b_post_admission_raw {
            return Err(GcConformanceSmokeError::AdmissionRenderMismatch {
                input: source,
                pre_admission: tier_b_pre_admission_raw,
                post_admission: tier_b_post_admission_raw,
            });
        }

        let tier_a = eval_derivation_aterm_surfaces_with_options(&ir, TreeWalkOptions::new())
            .map_err(|error| GcConformanceSmokeError::TreeWalk {
                input: source,
                error: Box::new(error),
            })?;
        let tier_b_configured = eval_derivation_aterm_surfaces_with_options(&ir, tier_b_options()?)
            .map_err(|error| GcConformanceSmokeError::TreeWalk {
                input: source,
                error: Box::new(error),
            })?;

        if tier_a.is_empty() || tier_b_configured.is_empty() {
            return Err(GcConformanceSmokeError::MissingDerivationSurface { input: source });
        }
        if tier_a != tier_b_configured {
            return Err(
                GcConformanceSmokeError::DerivationConfiguredSurfaceMismatch {
                    input: source,
                    tier_a,
                    tier_b_configured,
                },
            );
        }

        let admission = admission_report
            .ok_or(GcConformanceSmokeError::MissingTierBAdmission { input: source })?;
        if admission.generation_rewrites() == 0 {
            return Err(GcConformanceSmokeError::MissingGenerationRewrite { input: source });
        }
        assert_admission_stats_match(source, &admission, &stats)?;
        checked_surface_count = checked_surface_count.saturating_add(usize_to_u64(
            tier_b_configured.len(),
            "Tier-A/Tier-B derivation conformance surfaces",
        )?);
        checked_surface_count = checked_surface_count.saturating_add(1);
        admissions = admissions.saturating_add(1);
        generation_rewrites = generation_rewrites.saturating_add(usize_to_u64(
            admission.generation_rewrites(),
            "Tier-B generation rewrites",
        )?);
    }

    Ok(GcConformanceSmokeReport {
        scope: GcConformanceScope::TierATierBDerivationAtermBytes,
        case_count: TIER_A_TIER_B_DRV_CASES.len(),
        checked_surface_count,
        tier_b_admissions: admissions,
        tier_b_generation_rewrites: generation_rewrites,
    })
}

/// Compares one source under Tier A and post-admission Tier-B raw rendering.
///
/// This is the source-level entry point used by the GC fuzz target. It expects
/// the caller to provide any wrapping needed to force heap allocation. Invalid
/// sources and ordinary Tier-A evaluation failures are returned distinctly so
/// fuzz callers can skip inputs that do not reach the conformance surface.
///
/// # Errors
///
/// Returns [`GcConformanceCaseError`] if the source fails to lower, Tier-A
/// rendering fails, Tier-B rendering or admission fails, Tier-B admission does
/// not run, or the rendered bytes or mirrored admission stats diverge.
pub fn compare_gc_conformance_tier_a_tier_b_raw_bytes_source(
    source: &str,
) -> Result<GcConformanceCaseReport, GcConformanceCaseError> {
    let ir = lower_dynamic_conformance_source(source)?;
    let tier_a = eval_raw_bytes_with_options(&ir, TreeWalkOptions::new()).map_err(|error| {
        GcConformanceCaseError::TierA {
            error: Box::new(error),
        }
    })?;
    let (pre_admission, tier_b, admission_report, stats) =
        eval_raw_bytes_with_post_render_tier_b_admission(&ir, tier_b_case_options()?).map_err(
            |error| GcConformanceCaseError::TierB {
                error: Box::new(error),
            },
        )?;

    if tier_a != pre_admission {
        return Err(GcConformanceCaseError::TierConfiguredRenderMismatch {
            tier_a,
            tier_b_pre_admission: pre_admission,
        });
    }
    if pre_admission != tier_b {
        return Err(GcConformanceCaseError::AdmissionRenderMismatch {
            pre_admission,
            post_admission: tier_b,
        });
    }

    let admission = admission_report.ok_or(GcConformanceCaseError::MissingTierBAdmission)?;
    if admission.generation_rewrites() == 0 {
        return Err(GcConformanceCaseError::MissingGenerationRewrite);
    }
    assert_admission_case_stats_match(&admission, &stats)?;

    Ok(GcConformanceCaseReport {
        raw_bytes: tier_a,
        tier_b_worker_records: usize_to_u64_case(
            admission.worker_records(),
            "Tier-B worker records",
        )?,
        tier_b_permanent_shared_records: usize_to_u64_case(
            admission.permanent_shared_records(),
            "Tier-B permanent shared records",
        )?,
        tier_b_generation_rewrites: usize_to_u64_case(
            admission.generation_rewrites(),
            "Tier-B generation rewrites",
        )?,
    })
}

fn assert_raw_eq(
    input: &'static str,
    mode: RawRenderMode,
    expected: &'static [u8],
    actual: &[u8],
) -> Result<(), GcConformanceSmokeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(GcConformanceSmokeError::RawMismatch {
            input,
            mode,
            expected,
            actual: actual.to_vec(),
        })
    }
}

fn assert_admission_stats_match(
    input: &'static str,
    admission: &EvalHeapTierBAdmissionReport,
    stats: &EvalStats,
) -> Result<(), GcConformanceSmokeError> {
    assert_stat_matches(
        input,
        "heap_tier_b_admission_worker_records",
        usize_to_u64(admission.worker_records(), "Tier-B worker records")?,
        stats.heap_tier_b_admission_worker_records(),
    )?;
    assert_stat_matches(
        input,
        "heap_tier_b_admission_permanent_shared_records",
        usize_to_u64(
            admission.permanent_shared_records(),
            "Tier-B permanent shared records",
        )?,
        stats.heap_tier_b_admission_permanent_shared_records(),
    )?;
    assert_stat_matches(
        input,
        "heap_tier_b_admission_generation_rewrites",
        usize_to_u64(
            admission.generation_rewrites(),
            "Tier-B generation rewrites",
        )?,
        stats.heap_tier_b_admission_generation_rewrites(),
    )
}

fn assert_admission_case_stats_match(
    admission: &EvalHeapTierBAdmissionReport,
    stats: &EvalStats,
) -> Result<(), GcConformanceCaseError> {
    assert_case_stat_matches(
        "heap_tier_b_admission_worker_records",
        usize_to_u64_case(admission.worker_records(), "Tier-B worker records")?,
        stats.heap_tier_b_admission_worker_records(),
    )?;
    assert_case_stat_matches(
        "heap_tier_b_admission_permanent_shared_records",
        usize_to_u64_case(
            admission.permanent_shared_records(),
            "Tier-B permanent shared records",
        )?,
        stats.heap_tier_b_admission_permanent_shared_records(),
    )?;
    assert_case_stat_matches(
        "heap_tier_b_admission_generation_rewrites",
        usize_to_u64_case(
            admission.generation_rewrites(),
            "Tier-B generation rewrites",
        )?,
        stats.heap_tier_b_admission_generation_rewrites(),
    )
}

fn assert_case_stat_matches(
    metric: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), GcConformanceCaseError> {
    if expected == actual {
        Ok(())
    } else {
        Err(GcConformanceCaseError::StatsMismatch {
            metric,
            expected,
            actual,
        })
    }
}

fn assert_stat_matches(
    input: &'static str,
    metric: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), GcConformanceSmokeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(GcConformanceSmokeError::StatsMismatch {
            input,
            metric,
            expected,
            actual,
        })
    }
}

fn lower_conformance_source(source: &'static str) -> Result<Ir, GcConformanceSmokeError> {
    let parsed = parse_str(source).map_err(|error| GcConformanceSmokeError::Lower {
        input: source,
        stage: GcConformanceLowerStage::Parse,
        message: error.to_string(),
    })?;
    let resolved = resolve_ast(parsed).map_err(|error| GcConformanceSmokeError::Lower {
        input: source,
        stage: GcConformanceLowerStage::Resolve,
        message: error.to_string(),
    })?;
    aos_nix_dialect::nix_lower(resolved).map_err(|error| GcConformanceSmokeError::Lower {
        input: source,
        stage: GcConformanceLowerStage::Lower,
        message: error.to_string(),
    })
}

fn lower_dynamic_conformance_source(source: &str) -> Result<Ir, GcConformanceCaseError> {
    let parsed = parse_str(source).map_err(|error| GcConformanceCaseError::Lower {
        stage: GcConformanceLowerStage::Parse,
        message: error.to_string(),
    })?;
    let resolved = resolve_ast(parsed).map_err(|error| GcConformanceCaseError::Lower {
        stage: GcConformanceLowerStage::Resolve,
        message: error.to_string(),
    })?;
    aos_nix_dialect::nix_lower(resolved).map_err(|error| GcConformanceCaseError::Lower {
        stage: GcConformanceLowerStage::Lower,
        message: error.to_string(),
    })
}

fn tier_b_options() -> Result<TreeWalkOptions, GcConformanceSmokeError> {
    let budget = HeapMemoryBudget::new(1)
        .map_err(|_| GcConformanceSmokeError::InvalidMemoryBudget { bytes: 1 })?;
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
    // The conformance harness asserts generation rewrites, which live on
    // record-table worker objects (doc 30 FV-3 scaffolding placement).
    options.set_record_worker_closures_for_gc_scaffolding(true);
    Ok(options)
}

fn tier_b_case_options() -> Result<TreeWalkOptions, GcConformanceCaseError> {
    let budget = HeapMemoryBudget::new(1)
        .map_err(|_| GcConformanceCaseError::InvalidMemoryBudget { bytes: 1 })?;
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
    options.set_record_worker_closures_for_gc_scaffolding(true);
    Ok(options)
}

fn usize_to_u64(value: usize, metric: &'static str) -> Result<u64, GcConformanceSmokeError> {
    u64::try_from(value).map_err(|_| GcConformanceSmokeError::CounterOverflow { metric, value })
}

fn usize_to_u64_case(value: usize, metric: &'static str) -> Result<u64, GcConformanceCaseError> {
    u64::try_from(value).map_err(|_| GcConformanceCaseError::CounterOverflow { metric, value })
}

/// A successful source-level Tier-A/Tier-B conformance comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcConformanceCaseReport {
    raw_bytes: Vec<u8>,
    tier_b_worker_records: u64,
    tier_b_permanent_shared_records: u64,
    tier_b_generation_rewrites: u64,
}

impl GcConformanceCaseReport {
    /// Returns the strict raw bytes shared by Tier A and post-admission Tier B.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Returns worker-domain heap records admitted into Tier B.
    pub const fn tier_b_worker_records(&self) -> u64 {
        self.tier_b_worker_records
    }

    /// Returns permanent-shared heap records preserved during admission.
    pub const fn tier_b_permanent_shared_records(&self) -> u64 {
        self.tier_b_permanent_shared_records
    }

    /// Returns Tier-B admission generation rewrites.
    pub const fn tier_b_generation_rewrites(&self) -> u64 {
        self.tier_b_generation_rewrites
    }
}

/// A successful GC conformance smoke target report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcConformanceSmokeReport {
    scope: GcConformanceScope,
    case_count: usize,
    checked_surface_count: u64,
    tier_b_admissions: u64,
    tier_b_generation_rewrites: u64,
}

impl GcConformanceSmokeReport {
    /// Returns the conformance surface that was exercised.
    pub const fn scope(self) -> GcConformanceScope {
        self.scope
    }

    /// Returns the number of fixed cases exercised.
    pub const fn case_count(self) -> usize {
        self.case_count
    }

    /// Returns how many raw or derivation-byte surfaces were compared.
    pub const fn checked_surface_count(self) -> u64 {
        self.checked_surface_count
    }

    /// Returns how many fixed cases applied Tier-B admission metadata.
    pub const fn tier_b_admissions(self) -> u64 {
        self.tier_b_admissions
    }

    /// Returns total Tier-B admission generation rewrites.
    pub const fn tier_b_generation_rewrites(self) -> u64 {
        self.tier_b_generation_rewrites
    }
}

/// A cargo command needed to run one GC conformance target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcConformanceInvocation {
    target: GcConformanceTarget,
    cargo_args: Vec<&'static str>,
}

impl GcConformanceInvocation {
    fn for_target(target: GcConformanceTarget) -> Self {
        Self {
            target,
            cargo_args: cargo_test_args(target),
        }
    }

    /// Returns the conformance manifest target this command runs.
    pub const fn target(&self) -> GcConformanceTarget {
        self.target
    }

    /// Returns the cargo executable name.
    pub const fn cargo_program(&self) -> &'static str {
        CARGO_PROGRAM
    }

    /// Returns arguments passed to `cargo`.
    pub fn cargo_args(&self) -> &[&'static str] {
        &self.cargo_args
    }
}

fn cargo_test_args(target: GcConformanceTarget) -> Vec<&'static str> {
    vec![
        "test",
        "--manifest-path",
        target.manifest_path(),
        "-p",
        target.package(),
        target.test_filter(),
        "--",
        "--nocapture",
    ]
}

/// A frontend stage used while lowering a GC conformance smoke source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcConformanceLowerStage {
    /// The source failed to parse.
    Parse,
    /// The parsed source failed scope resolution.
    Resolve,
    /// The resolved source failed IR lowering.
    Lower,
}

/// A raw rendering mode checked by the GC conformance smoke target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawRenderMode {
    /// The ordinary Tier-A raw renderer.
    TierA,
    /// The Tier-B configured raw renderer before admission metadata is applied.
    TierBPreAdmission,
    /// The Tier-B configured raw renderer after admission metadata is applied.
    TierBPostAdmission,
}

/// Errors raised while validating the GC conformance manifest.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GcConformanceManifestError {
    /// A required conformance scope target is absent.
    #[error("GC conformance target missing for {scope:?}")]
    MissingTarget {
        /// The missing conformance scope.
        scope: GcConformanceScope,
    },
    /// A target does not name a cargo test filter.
    #[error("GC conformance target has an empty test filter for {scope:?}")]
    EmptyTestFilter {
        /// The conformance scope with an invalid target.
        scope: GcConformanceScope,
    },
    /// A target does not explain why it belongs in the matrix.
    #[error("GC conformance target has an empty rationale for {scope:?}")]
    EmptyRationale {
        /// The conformance scope with an invalid target.
        scope: GcConformanceScope,
    },
}

/// Errors raised by a GC conformance smoke target.
#[derive(Debug, Error)]
pub enum GcConformanceSmokeError {
    /// A fixed smoke source failed a frontend stage.
    #[error("GC conformance source {input:?} failed {stage:?}: {message}")]
    Lower {
        /// The fixed source that failed.
        input: &'static str,
        /// The frontend stage that failed.
        stage: GcConformanceLowerStage,
        /// A diagnostic message from the frontend.
        message: String,
    },
    /// A fixed smoke source failed during tree-walk evaluation.
    #[error("GC conformance source {input:?} failed tree-walk evaluation")]
    TreeWalk {
        /// The fixed source that failed.
        input: &'static str,
        /// The evaluator error.
        #[source]
        error: Box<TreeWalkError>,
    },
    /// The fixed Tier-B budget could not be constructed.
    #[error("GC conformance memory budget {bytes} is invalid")]
    InvalidMemoryBudget {
        /// The configured memory-budget byte count.
        bytes: usize,
    },
    /// A fixed raw rendering produced unexpected bytes.
    #[error("GC conformance source {input:?} produced unexpected {mode:?} raw bytes")]
    RawMismatch {
        /// The fixed source that produced the mismatch.
        input: &'static str,
        /// The render mode that produced the mismatch.
        mode: RawRenderMode,
        /// The expected raw bytes.
        expected: &'static [u8],
        /// The actual raw bytes.
        actual: Vec<u8>,
    },
    /// A fixed derivation smoke source recorded no derivation surface.
    #[error("GC conformance source {input:?} recorded no derivation surfaces")]
    MissingDerivationSurface {
        /// The fixed source that recorded no derivation.
        input: &'static str,
    },
    /// Tier-B configuration changed recorded derivation side-table surfaces.
    #[error(
        "GC conformance source {input:?} changed derivation side-table surfaces under Tier-B configuration"
    )]
    DerivationConfiguredSurfaceMismatch {
        /// The fixed source that diverged.
        input: &'static str,
        /// Tier-A derivation path and ATerm byte surfaces.
        tier_a: Vec<(String, Vec<u8>)>,
        /// Tier-B configured derivation path and ATerm byte surfaces.
        tier_b_configured: Vec<(String, Vec<u8>)>,
    },
    /// Tier-A and Tier-B raw bytes diverged.
    #[error("GC conformance source {input:?} diverged between Tier A and Tier B")]
    TierParityMismatch {
        /// The fixed source that diverged.
        input: &'static str,
        /// Tier-A strict raw bytes.
        tier_a: Vec<u8>,
        /// Tier-B strict raw bytes at the checked comparison point.
        tier_b: Vec<u8>,
    },
    /// Rendering changed when Tier-B admission metadata was applied.
    #[error("GC conformance source {input:?} changed raw bytes after Tier-B admission")]
    AdmissionRenderMismatch {
        /// The fixed source that diverged.
        input: &'static str,
        /// Strict raw bytes before admission metadata was applied.
        pre_admission: Vec<u8>,
        /// Strict raw bytes after admission metadata was applied.
        post_admission: Vec<u8>,
    },
    /// Tier-B configured rendering did not apply admission metadata.
    #[error("GC conformance source {input:?} did not record Tier-B admission")]
    MissingTierBAdmission {
        /// The fixed source that failed to exercise admission.
        input: &'static str,
    },
    /// Tier-B admission did not rewrite generation metadata.
    #[error("GC conformance source {input:?} did not rewrite generation metadata")]
    MissingGenerationRewrite {
        /// The fixed source that failed to exercise generation rewrites.
        input: &'static str,
    },
    /// Mirrored stats disagreed with the Tier-B admission report.
    #[error("GC conformance source {input:?} reported {metric}={actual}, expected {expected}")]
    StatsMismatch {
        /// The fixed source with inconsistent stats.
        input: &'static str,
        /// The metric name.
        metric: &'static str,
        /// The value expected from the admission report.
        expected: u64,
        /// The value reported by mirrored stats.
        actual: u64,
    },
    /// A metric could not be represented in the smoke report.
    #[error("GC conformance metric {metric} value {value} does not fit in u64")]
    CounterOverflow {
        /// The metric that overflowed.
        metric: &'static str,
        /// The original `usize` value.
        value: usize,
    },
}

/// Errors raised by a source-level Tier-A/Tier-B conformance comparison.
#[derive(Debug, Error)]
pub enum GcConformanceCaseError {
    /// The source failed a frontend stage.
    #[error("GC conformance source failed {stage:?}: {message}")]
    Lower {
        /// The frontend stage that failed.
        stage: GcConformanceLowerStage,
        /// A diagnostic message from the frontend.
        message: String,
    },
    /// Tier-A raw rendering failed.
    #[error("GC conformance Tier-A rendering failed")]
    TierA {
        /// The evaluator error.
        #[source]
        error: Box<TreeWalkError>,
    },
    /// Tier-B configured raw rendering or admission failed.
    #[error("GC conformance Tier-B rendering failed")]
    TierB {
        /// The evaluator error.
        #[source]
        error: Box<TreeWalkError>,
    },
    /// The fixed Tier-B budget could not be constructed.
    #[error("GC conformance memory budget {bytes} is invalid")]
    InvalidMemoryBudget {
        /// The configured memory-budget byte count.
        bytes: usize,
    },
    /// Tier-B configuration changed bytes before admission metadata was applied.
    #[error("GC conformance source changed raw bytes before Tier-B admission")]
    TierConfiguredRenderMismatch {
        /// Tier-A strict raw bytes.
        tier_a: Vec<u8>,
        /// Tier-B configured strict raw bytes before admission metadata.
        tier_b_pre_admission: Vec<u8>,
    },
    /// Rendering changed when Tier-B admission metadata was applied.
    #[error("GC conformance source changed raw bytes after Tier-B admission")]
    AdmissionRenderMismatch {
        /// Strict raw bytes before admission metadata was applied.
        pre_admission: Vec<u8>,
        /// Strict raw bytes after admission metadata was applied.
        post_admission: Vec<u8>,
    },
    /// Tier-B configured rendering did not apply admission metadata.
    #[error("GC conformance source did not record Tier-B admission")]
    MissingTierBAdmission,
    /// Tier-B admission did not rewrite generation metadata.
    #[error("GC conformance source did not rewrite generation metadata")]
    MissingGenerationRewrite,
    /// Mirrored stats disagreed with the Tier-B admission report.
    #[error("GC conformance source reported {metric}={actual}, expected {expected}")]
    StatsMismatch {
        /// The metric name.
        metric: &'static str,
        /// The value expected from the admission report.
        expected: u64,
        /// The value reported by mirrored stats.
        actual: u64,
    },
    /// A metric could not be represented in the case report.
    #[error("GC conformance metric {metric} value {value} does not fit in u64")]
    CounterOverflow {
        /// The metric that overflowed.
        metric: &'static str,
        /// The original `usize` value.
        value: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_conformance_manifest_covers_tier_a_tier_b_raw_bytes() {
        let manifest = validate_gc_conformance_manifest().expect("conformance manifest validates");

        assert_eq!(manifest.target_count(), 2);
        let raw_target = manifest
            .target_for(GcConformanceScope::TierATierBRawBytes)
            .expect("Tier-A/Tier-B target is present");
        assert_eq!(raw_target.package(), CONFORMANCE_PACKAGE);
        assert_eq!(raw_target.manifest_path(), CONFORMANCE_MANIFEST_PATH);
        assert_eq!(
            raw_target.test_filter(),
            "gc_conformance_tier_a_tier_b_raw_bytes_smoke"
        );
        assert!(!raw_target.rationale().is_empty());
        let drv_target = manifest
            .target_for(GcConformanceScope::TierATierBDerivationAtermBytes)
            .expect("Tier-A/Tier-B derivation target is present");
        assert_eq!(drv_target.package(), CONFORMANCE_PACKAGE);
        assert_eq!(drv_target.manifest_path(), CONFORMANCE_MANIFEST_PATH);
        assert_eq!(
            drv_target.test_filter(),
            "gc_conformance_tier_a_tier_b_drv_bytes_smoke"
        );
        assert!(!drv_target.rationale().is_empty());
    }

    #[test]
    fn gc_conformance_invocations_pin_cargo_test_filters() {
        let invocations = gc_conformance_invocations().expect("conformance invocations validate");

        assert_eq!(invocations.len(), 2);
        let raw_invocation = invocations
            .iter()
            .find(|invocation| {
                invocation.target().scope() == GcConformanceScope::TierATierBRawBytes
            })
            .expect("Tier-A/Tier-B invocation is present");
        assert_eq!(raw_invocation.cargo_program(), "cargo");
        assert_eq!(
            raw_invocation.cargo_args(),
            &[
                "test",
                "--manifest-path",
                CONFORMANCE_MANIFEST_PATH,
                "-p",
                CONFORMANCE_PACKAGE,
                "gc_conformance_tier_a_tier_b_raw_bytes_smoke",
                "--",
                "--nocapture",
            ]
        );

        let drv_invocation = invocations
            .iter()
            .find(|invocation| {
                invocation.target().scope() == GcConformanceScope::TierATierBDerivationAtermBytes
            })
            .expect("Tier-A/Tier-B derivation invocation is present");
        assert_eq!(drv_invocation.cargo_program(), "cargo");
        assert_eq!(
            drv_invocation.cargo_args(),
            &[
                "test",
                "--manifest-path",
                CONFORMANCE_MANIFEST_PATH,
                "-p",
                CONFORMANCE_PACKAGE,
                "gc_conformance_tier_a_tier_b_drv_bytes_smoke",
                "--",
                "--nocapture",
            ]
        );
    }

    #[test]
    fn gc_conformance_tier_a_tier_b_raw_bytes_smoke() {
        let report = run_gc_conformance_tier_a_tier_b_raw_bytes_smoke()
            .expect("Tier-A/Tier-B raw byte conformance smoke passes");

        assert_eq!(report.scope(), GcConformanceScope::TierATierBRawBytes);
        assert_eq!(report.case_count(), TIER_A_TIER_B_RAW_CASES.len());
        assert_eq!(
            report.checked_surface_count(),
            TIER_A_TIER_B_RAW_CASES.len() as u64
        );
        assert_eq!(
            report.tier_b_admissions(),
            TIER_A_TIER_B_RAW_CASES.len() as u64
        );
        assert!(report.tier_b_generation_rewrites() > 0);
    }

    #[test]
    fn gc_conformance_tier_a_tier_b_drv_bytes_smoke() {
        let report = run_gc_conformance_tier_a_tier_b_drv_bytes_smoke()
            .expect("Tier-A/Tier-B derivation byte conformance smoke passes");

        assert_eq!(
            report.scope(),
            GcConformanceScope::TierATierBDerivationAtermBytes
        );
        assert_eq!(report.case_count(), TIER_A_TIER_B_DRV_CASES.len());
        assert!(report.checked_surface_count() >= TIER_A_TIER_B_DRV_CASES.len() as u64);
        assert_eq!(
            report.tier_b_admissions(),
            TIER_A_TIER_B_DRV_CASES.len() as u64
        );
        assert!(report.tier_b_generation_rewrites() > 0);
    }

    #[test]
    fn gc_conformance_source_case_compares_tier_a_and_tier_b_bytes() {
        let report = compare_gc_conformance_tier_a_tier_b_raw_bytes_source("[ ({ a = 1 + 2; }) ]")
            .expect("source-level conformance case passes");

        assert_eq!(report.raw_bytes(), b"[ { a = 3; } ]");
        assert!(report.tier_b_worker_records() > 0);
        assert!(report.tier_b_generation_rewrites() > 0);
    }
}
