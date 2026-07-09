//! Heap and GC measurement targets for open RFC-0007 decisions.
//!
//! The implementation checklist keeps M-12, M-14, and Q-G open until real
//! daemon-GC and generational measurements exist. This module names stable
//! cargo test targets for those decisions and provides small smoke probes over
//! the telemetry already exposed by the safe tree-walk evaluator. The probes
//! are deliberately narrow: they do not run benchmarks, install a daemon
//! collector, compare against a region-inference implementation, or claim that
//! the decisions are closed.

use thiserror::Error;

use super::tree_walk::{EvalOutcome, TreeWalkError, TreeWalkOptions, eval_whnf_owned_with_options};
use crate::{
    compile::{Ir, resolve as resolve_ast},
    heap::{HeapMemoryBudget, MemoryAdviceKind},
    syntax::parse_str,
};

const MEASUREMENT_PACKAGE: &str = "ratchet-oracle";
const MEASUREMENT_MANIFEST_PATH: &str = "crates/Cargo.toml";
const CARGO_PROGRAM: &str = "cargo";

const M12_CONS_TABLE_SOURCE: &str = "\"m12-cold-hash-consed\"";
const M14_REGION_GENERATIONAL_SOURCE: &str = "[ (1 + 6) ]";
const QG_PER_INVOCATION_SOURCE: &str = "x: x";

const HEAP_GC_MEASUREMENT_TARGETS: [HeapGcMeasurementTarget; 3] = [
    HeapGcMeasurementTarget::new(
        HeapGcMeasurementId::M12ConsTableSizingUnderDaemonGc,
        HeapGcMeasurementScope::ColdHashConsedBudgetTelemetry,
        "heap_gc_measurement_m12_cons_table_sizing_smoke",
        "M-12 needs current cold hash-consed capacity and cheap-memory budget telemetry before daemon-GC cons-table sizing can be measured",
    ),
    HeapGcMeasurementTarget::new(
        HeapGcMeasurementId::M14RegionInferenceVsGenerationalGc,
        HeapGcMeasurementScope::RegionPlanAdmissionTelemetry,
        "heap_gc_measurement_m14_region_vs_generational_smoke",
        "M-14 needs region-plan counters and Tier-B admission metadata before region inference can be compared with generational GC",
    ),
    HeapGcMeasurementTarget::new(
        HeapGcMeasurementId::QGDaemonVsPerInvocation,
        HeapGcMeasurementScope::PerInvocationBudgetTelemetry,
        "heap_gc_measurement_qg_per_invocation_budget_smoke",
        "Q-G is deferred, but the per-invocation budget/admission profile must stay measurable before daemon comparison exists",
    ),
];

const REQUIRED_HEAP_GC_MEASUREMENTS: [(HeapGcMeasurementId, HeapGcMeasurementScope); 3] = [
    (
        HeapGcMeasurementId::M12ConsTableSizingUnderDaemonGc,
        HeapGcMeasurementScope::ColdHashConsedBudgetTelemetry,
    ),
    (
        HeapGcMeasurementId::M14RegionInferenceVsGenerationalGc,
        HeapGcMeasurementScope::RegionPlanAdmissionTelemetry,
    ),
    (
        HeapGcMeasurementId::QGDaemonVsPerInvocation,
        HeapGcMeasurementScope::PerInvocationBudgetTelemetry,
    ),
];

/// An RFC-0007 heap or GC decision that still needs measurement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HeapGcMeasurementId {
    /// M-12: cons-table sizing under daemon GC.
    M12ConsTableSizingUnderDaemonGc,
    /// M-14: region inference compared with generational GC.
    M14RegionInferenceVsGenerationalGc,
    /// Q-G: daemon GC compared with per-invocation GC.
    QGDaemonVsPerInvocation,
}

/// The telemetry surface exercised by a heap/GC measurement target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HeapGcMeasurementScope {
    /// Cold hash-consed capacity and cheap-memory budget planning.
    ColdHashConsedBudgetTelemetry,
    /// Source-region planning and Tier-B admission metadata.
    RegionPlanAdmissionTelemetry,
    /// Per-invocation memory-budget and admission metadata.
    PerInvocationBudgetTelemetry,
}

/// One cargo test target in the heap/GC measurement matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapGcMeasurementTarget {
    measurement_id: HeapGcMeasurementId,
    scope: HeapGcMeasurementScope,
    package: &'static str,
    manifest_path: &'static str,
    test_filter: &'static str,
    rationale: &'static str,
}

impl HeapGcMeasurementTarget {
    const fn new(
        measurement_id: HeapGcMeasurementId,
        scope: HeapGcMeasurementScope,
        test_filter: &'static str,
        rationale: &'static str,
    ) -> Self {
        Self {
            measurement_id,
            scope,
            package: MEASUREMENT_PACKAGE,
            manifest_path: MEASUREMENT_MANIFEST_PATH,
            test_filter,
            rationale,
        }
    }

    /// Returns the RFC measurement or deferred decision this target informs.
    pub const fn measurement_id(self) -> HeapGcMeasurementId {
        self.measurement_id
    }

    /// Returns the telemetry surface this target exercises.
    pub const fn scope(self) -> HeapGcMeasurementScope {
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

    /// Returns why this target belongs in the measurement matrix.
    pub const fn rationale(self) -> &'static str {
        self.rationale
    }
}

/// A validated heap/GC measurement target manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapGcMeasurementManifest {
    targets: &'static [HeapGcMeasurementTarget],
}

impl HeapGcMeasurementManifest {
    /// Returns every measurement target.
    pub const fn targets(self) -> &'static [HeapGcMeasurementTarget] {
        self.targets
    }

    /// Returns the number of measurement targets.
    pub const fn target_count(self) -> usize {
        self.targets.len()
    }

    /// Finds a measurement target by decision id and telemetry scope.
    pub fn target_for(
        self,
        measurement_id: HeapGcMeasurementId,
        scope: HeapGcMeasurementScope,
    ) -> Option<HeapGcMeasurementTarget> {
        self.targets
            .iter()
            .copied()
            .find(|target| target.measurement_id == measurement_id && target.scope == scope)
    }
}

/// Returns the current heap/GC measurement target manifest.
pub const fn heap_gc_measurement_manifest() -> HeapGcMeasurementManifest {
    HeapGcMeasurementManifest {
        targets: &HEAP_GC_MEASUREMENT_TARGETS,
    }
}

/// Validates and returns the heap/GC measurement target manifest.
///
/// # Errors
///
/// Returns [`HeapGcMeasurementManifestError`] if a required measurement/scope
/// pair is missing or if a target has no test filter or rationale.
pub fn validate_heap_gc_measurement_manifest()
-> Result<HeapGcMeasurementManifest, HeapGcMeasurementManifestError> {
    let manifest = heap_gc_measurement_manifest();
    for target in manifest.targets {
        if target.test_filter.is_empty() {
            return Err(HeapGcMeasurementManifestError::EmptyTestFilter {
                measurement_id: target.measurement_id,
                scope: target.scope,
            });
        }
        if target.rationale.is_empty() {
            return Err(HeapGcMeasurementManifestError::EmptyRationale {
                measurement_id: target.measurement_id,
                scope: target.scope,
            });
        }
    }
    for (measurement_id, scope) in REQUIRED_HEAP_GC_MEASUREMENTS {
        if manifest.target_for(measurement_id, scope).is_none() {
            return Err(HeapGcMeasurementManifestError::MissingTarget {
                measurement_id,
                scope,
            });
        }
    }
    Ok(manifest)
}

/// Returns cargo invocations for the current heap/GC measurement matrix.
///
/// The returned commands are not run by ordinary code. They give CI and
/// release checklists a stable adapter around the smoke targets so the
/// measurement matrix is not reconstructed from prose.
///
/// # Errors
///
/// Returns [`HeapGcMeasurementManifestError`] if the measurement manifest is
/// invalid.
pub fn heap_gc_measurement_invocations()
-> Result<Vec<HeapGcMeasurementInvocation>, HeapGcMeasurementManifestError> {
    validate_heap_gc_measurement_manifest().map(|manifest| {
        manifest
            .targets()
            .iter()
            .copied()
            .map(HeapGcMeasurementInvocation::for_target)
            .collect()
    })
}

/// Runs the M-12 cons-table sizing smoke probe.
///
/// # Errors
///
/// Returns [`HeapGcMeasurementSmokeError`] if the fixed source fails to lower
/// or evaluate, if cheap-memory budget telemetry is missing, or if the current
/// cold hash-consed capacity counters stay empty.
pub fn run_heap_gc_measurement_m12_cons_table_sizing_smoke()
-> Result<HeapGcMeasurementSmokeReport, HeapGcMeasurementSmokeError> {
    let outcome = eval_measurement_source(M12_CONS_TABLE_SOURCE, cold_aware_budget_options()?)?;
    let action = outcome.memory_budget_action().ok_or(
        HeapGcMeasurementSmokeError::MissingMemoryBudgetAction {
            input: M12_CONS_TABLE_SOURCE,
        },
    )?;
    let plan = outcome.cheap_memory_budget_plan().ok_or(
        HeapGcMeasurementSmokeError::MissingCheapMemoryBudgetPlan {
            input: M12_CONS_TABLE_SOURCE,
        },
    )?;
    let report = plan.cheap_advice_report().ok_or(
        HeapGcMeasurementSmokeError::MissingCheapMemoryAdviceReport {
            input: M12_CONS_TABLE_SOURCE,
        },
    )?;
    let outcome_report = outcome.cheap_memory_advice_report().ok_or(
        HeapGcMeasurementSmokeError::MissingCheapMemoryAdviceReport {
            input: M12_CONS_TABLE_SOURCE,
        },
    )?;
    if outcome_report != report {
        return Err(HeapGcMeasurementSmokeError::AdviceReportMismatch {
            input: M12_CONS_TABLE_SOURCE,
        });
    }

    let cold_hash_consed = report.cold_hash_consed();
    if cold_hash_consed.kind() != MemoryAdviceKind::Evict {
        return Err(HeapGcMeasurementSmokeError::UnexpectedAdviceKind {
            input: M12_CONS_TABLE_SOURCE,
            expected: MemoryAdviceKind::Evict,
            actual: cold_hash_consed.kind(),
        });
    }
    if cold_hash_consed.records() == 0 {
        return Err(HeapGcMeasurementSmokeError::MissingColdHashConsedRecords {
            input: M12_CONS_TABLE_SOURCE,
        });
    }
    if cold_hash_consed.requested_bytes() == 0
        || plan.decision().sample().cold_hash_consed_bytes() == 0
    {
        return Err(HeapGcMeasurementSmokeError::MissingColdHashConsedBytes {
            input: M12_CONS_TABLE_SOURCE,
        });
    }

    Ok(HeapGcMeasurementSmokeReport {
        measurement_id: HeapGcMeasurementId::M12ConsTableSizingUnderDaemonGc,
        case_count: 1,
        cold_hash_consed_records: usize_to_u64(
            cold_hash_consed.records(),
            "cold hash-consed records",
        )?,
        cold_hash_consed_bytes: usize_to_u64(
            plan.decision().sample().cold_hash_consed_bytes(),
            "cold hash-consed bytes",
        )?,
        region_plan_decisions: 0,
        region_plan_conservative_fallbacks: 0,
        tier_b_requests: u64::from(action.requests_tier_b()),
        tier_b_generation_rewrites: 0,
    })
}

/// Runs the M-14 region-vs-generational smoke probe.
///
/// # Errors
///
/// Returns [`HeapGcMeasurementSmokeError`] if the fixed source fails to lower
/// or evaluate, if source-region counters are absent, or if per-invocation
/// Tier-B admission metadata is not recorded.
pub fn run_heap_gc_measurement_m14_region_vs_generational_smoke()
-> Result<HeapGcMeasurementSmokeReport, HeapGcMeasurementSmokeError> {
    let outcome = eval_measurement_source(
        M14_REGION_GENERATIONAL_SOURCE,
        per_invocation_admission_options()?,
    )?;
    let action = outcome.memory_budget_action().ok_or(
        HeapGcMeasurementSmokeError::MissingMemoryBudgetAction {
            input: M14_REGION_GENERATIONAL_SOURCE,
        },
    )?;
    if !action.requests_tier_b() {
        return Err(HeapGcMeasurementSmokeError::MissingTierBRequest {
            input: M14_REGION_GENERATIONAL_SOURCE,
        });
    }
    let stats = outcome.stats();
    if stats.source_thunk_region_plan_decisions() == 0 {
        return Err(HeapGcMeasurementSmokeError::MissingRegionPlanTelemetry {
            input: M14_REGION_GENERATIONAL_SOURCE,
        });
    }
    let admission = outcome.tier_b_transition_admission_report().ok_or(
        HeapGcMeasurementSmokeError::MissingTierBAdmission {
            input: M14_REGION_GENERATIONAL_SOURCE,
        },
    )?;
    if admission.generation_rewrites() == 0 {
        return Err(HeapGcMeasurementSmokeError::MissingGenerationRewrite {
            input: M14_REGION_GENERATIONAL_SOURCE,
        });
    }
    assert_admission_stats_match(&outcome, M14_REGION_GENERATIONAL_SOURCE)?;

    Ok(HeapGcMeasurementSmokeReport {
        measurement_id: HeapGcMeasurementId::M14RegionInferenceVsGenerationalGc,
        case_count: 1,
        cold_hash_consed_records: 0,
        cold_hash_consed_bytes: 0,
        region_plan_decisions: stats.source_thunk_region_plan_decisions(),
        region_plan_conservative_fallbacks: stats.source_thunk_region_plan_conservative_fallbacks(),
        tier_b_requests: 1,
        tier_b_generation_rewrites: usize_to_u64(
            admission.generation_rewrites(),
            "Tier-B generation rewrites",
        )?,
    })
}

/// Runs the Q-G per-invocation baseline smoke probe.
///
/// # Errors
///
/// Returns [`HeapGcMeasurementSmokeError`] if the default source unexpectedly
/// records budget action, if the per-invocation source fails to lower or
/// evaluate, or if the configured budget/admission path stops producing Tier-B
/// request and admission telemetry.
pub fn run_heap_gc_measurement_qg_per_invocation_budget_smoke()
-> Result<HeapGcMeasurementSmokeReport, HeapGcMeasurementSmokeError> {
    let default_outcome =
        eval_measurement_source(QG_PER_INVOCATION_SOURCE, TreeWalkOptions::new())?;
    if default_outcome.memory_budget_action().is_some() {
        return Err(
            HeapGcMeasurementSmokeError::UnexpectedDefaultMemoryBudgetAction {
                input: QG_PER_INVOCATION_SOURCE,
            },
        );
    }

    let configured_outcome = eval_measurement_source(
        QG_PER_INVOCATION_SOURCE,
        per_invocation_admission_options()?,
    )?;
    let action = configured_outcome.memory_budget_action().ok_or(
        HeapGcMeasurementSmokeError::MissingMemoryBudgetAction {
            input: QG_PER_INVOCATION_SOURCE,
        },
    )?;
    if !action.requests_tier_b() {
        return Err(HeapGcMeasurementSmokeError::MissingTierBRequest {
            input: QG_PER_INVOCATION_SOURCE,
        });
    }
    let admission = configured_outcome
        .tier_b_transition_admission_report()
        .ok_or(HeapGcMeasurementSmokeError::MissingTierBAdmission {
            input: QG_PER_INVOCATION_SOURCE,
        })?;
    if admission.generation_rewrites() == 0 {
        return Err(HeapGcMeasurementSmokeError::MissingGenerationRewrite {
            input: QG_PER_INVOCATION_SOURCE,
        });
    }
    assert_admission_stats_match(&configured_outcome, QG_PER_INVOCATION_SOURCE)?;

    Ok(HeapGcMeasurementSmokeReport {
        measurement_id: HeapGcMeasurementId::QGDaemonVsPerInvocation,
        case_count: 2,
        cold_hash_consed_records: 0,
        cold_hash_consed_bytes: 0,
        region_plan_decisions: configured_outcome
            .stats()
            .source_thunk_region_plan_decisions(),
        region_plan_conservative_fallbacks: configured_outcome
            .stats()
            .source_thunk_region_plan_conservative_fallbacks(),
        tier_b_requests: 1,
        tier_b_generation_rewrites: usize_to_u64(
            admission.generation_rewrites(),
            "Tier-B generation rewrites",
        )?,
    })
}

fn eval_measurement_source(
    source: &'static str,
    options: TreeWalkOptions,
) -> Result<EvalOutcome, HeapGcMeasurementSmokeError> {
    let ir = lower_measurement_source(source)?;
    eval_whnf_owned_with_options(&ir, options).map_err(|error| {
        HeapGcMeasurementSmokeError::TreeWalk {
            input: source,
            error: Box::new(error),
        }
    })
}

fn lower_measurement_source(source: &'static str) -> Result<Ir, HeapGcMeasurementSmokeError> {
    let parsed = parse_str(source).map_err(|error| HeapGcMeasurementSmokeError::Lower {
        input: source,
        stage: HeapGcMeasurementLowerStage::Parse,
        message: error.to_string(),
    })?;
    let resolved = resolve_ast(parsed).map_err(|error| HeapGcMeasurementSmokeError::Lower {
        input: source,
        stage: HeapGcMeasurementLowerStage::Resolve,
        message: error.to_string(),
    })?;
    aos_nix_dialect::nix_lower(resolved).map_err(|error| HeapGcMeasurementSmokeError::Lower {
        input: source,
        stage: HeapGcMeasurementLowerStage::Lower,
        message: error.to_string(),
    })
}

fn cold_aware_budget_options() -> Result<TreeWalkOptions, HeapGcMeasurementSmokeError> {
    let mut options = TreeWalkOptions::with_heap_memory_budget(measurement_budget()?);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);
    Ok(options)
}

fn per_invocation_admission_options() -> Result<TreeWalkOptions, HeapGcMeasurementSmokeError> {
    let mut options = TreeWalkOptions::with_heap_memory_budget(measurement_budget()?);
    options.set_heap_tier_b_transition_admission_enabled(true);
    // Generation rewrites live on record-table worker objects (doc 30
    // FV-3 scaffolding placement).
    options.set_record_worker_closures_for_gc_scaffolding(true);
    Ok(options)
}

fn measurement_budget() -> Result<HeapMemoryBudget, HeapGcMeasurementSmokeError> {
    HeapMemoryBudget::new(1)
        .map_err(|_| HeapGcMeasurementSmokeError::InvalidMemoryBudget { bytes: 1 })
}

fn assert_admission_stats_match(
    outcome: &EvalOutcome,
    input: &'static str,
) -> Result<(), HeapGcMeasurementSmokeError> {
    let Some(report) = outcome.tier_b_transition_admission_report() else {
        return Err(HeapGcMeasurementSmokeError::MissingTierBAdmission { input });
    };
    let stats = outcome.stats();
    assert_stat_matches(
        input,
        "heap_tier_b_admission_worker_records",
        usize_to_u64(report.worker_records(), "Tier-B worker records")?,
        stats.heap_tier_b_admission_worker_records(),
    )?;
    assert_stat_matches(
        input,
        "heap_tier_b_admission_permanent_shared_records",
        usize_to_u64(
            report.permanent_shared_records(),
            "Tier-B permanent shared records",
        )?,
        stats.heap_tier_b_admission_permanent_shared_records(),
    )?;
    assert_stat_matches(
        input,
        "heap_tier_b_admission_generation_rewrites",
        usize_to_u64(report.generation_rewrites(), "Tier-B generation rewrites")?,
        stats.heap_tier_b_admission_generation_rewrites(),
    )
}

fn assert_stat_matches(
    input: &'static str,
    metric: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), HeapGcMeasurementSmokeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(HeapGcMeasurementSmokeError::StatsMismatch {
            input,
            metric,
            expected,
            actual,
        })
    }
}

fn usize_to_u64(value: usize, metric: &'static str) -> Result<u64, HeapGcMeasurementSmokeError> {
    u64::try_from(value).map_err(|_| HeapGcMeasurementSmokeError::CounterOverflow { metric, value })
}

/// A successful heap/GC measurement smoke target report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapGcMeasurementSmokeReport {
    measurement_id: HeapGcMeasurementId,
    case_count: usize,
    cold_hash_consed_records: u64,
    cold_hash_consed_bytes: u64,
    region_plan_decisions: u64,
    region_plan_conservative_fallbacks: u64,
    tier_b_requests: u64,
    tier_b_generation_rewrites: u64,
}

impl HeapGcMeasurementSmokeReport {
    /// Returns the RFC measurement or deferred decision this smoke target informs.
    pub const fn measurement_id(self) -> HeapGcMeasurementId {
        self.measurement_id
    }

    /// Returns the number of fixed cases exercised.
    pub const fn case_count(self) -> usize {
        self.case_count
    }

    /// Returns cold hash-consed records observed by the probe.
    pub const fn cold_hash_consed_records(self) -> u64 {
        self.cold_hash_consed_records
    }

    /// Returns logical cold hash-consed bytes observed by the probe.
    pub const fn cold_hash_consed_bytes(self) -> u64 {
        self.cold_hash_consed_bytes
    }

    /// Returns source thunk region-plan decisions sampled by the probe.
    pub const fn region_plan_decisions(self) -> u64 {
        self.region_plan_decisions
    }

    /// Returns source thunk region-plan conservative fallbacks sampled by the probe.
    pub const fn region_plan_conservative_fallbacks(self) -> u64 {
        self.region_plan_conservative_fallbacks
    }

    /// Returns per-invocation Tier-B requests observed by the probe.
    pub const fn tier_b_requests(self) -> u64 {
        self.tier_b_requests
    }

    /// Returns Tier-B admission generation rewrites observed by the probe.
    pub const fn tier_b_generation_rewrites(self) -> u64 {
        self.tier_b_generation_rewrites
    }
}

/// A cargo command needed to run one heap/GC measurement target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeapGcMeasurementInvocation {
    target: HeapGcMeasurementTarget,
    cargo_args: Vec<&'static str>,
}

impl HeapGcMeasurementInvocation {
    fn for_target(target: HeapGcMeasurementTarget) -> Self {
        Self {
            target,
            cargo_args: cargo_test_args(target),
        }
    }

    /// Returns the measurement manifest target this command runs.
    pub const fn target(&self) -> HeapGcMeasurementTarget {
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

fn cargo_test_args(target: HeapGcMeasurementTarget) -> Vec<&'static str> {
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

/// A frontend stage used while lowering a heap/GC measurement smoke source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapGcMeasurementLowerStage {
    /// The source failed to parse.
    Parse,
    /// The parsed source failed scope resolution.
    Resolve,
    /// The resolved source failed IR lowering.
    Lower,
}

/// Errors raised while validating the heap/GC measurement manifest.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HeapGcMeasurementManifestError {
    /// A required measurement/scope target is absent.
    #[error("heap/GC measurement target missing for {measurement_id:?} {scope:?}")]
    MissingTarget {
        /// The missing measurement id.
        measurement_id: HeapGcMeasurementId,
        /// The missing telemetry scope.
        scope: HeapGcMeasurementScope,
    },
    /// A target does not name a cargo test filter.
    #[error("heap/GC measurement target has an empty test filter for {measurement_id:?} {scope:?}")]
    EmptyTestFilter {
        /// The measurement id with an invalid target.
        measurement_id: HeapGcMeasurementId,
        /// The telemetry scope with an invalid target.
        scope: HeapGcMeasurementScope,
    },
    /// A target does not explain why it belongs in the matrix.
    #[error("heap/GC measurement target has an empty rationale for {measurement_id:?} {scope:?}")]
    EmptyRationale {
        /// The measurement id with an invalid target.
        measurement_id: HeapGcMeasurementId,
        /// The telemetry scope with an invalid target.
        scope: HeapGcMeasurementScope,
    },
}

/// Errors raised by a heap/GC measurement smoke target.
#[derive(Debug, Error)]
pub enum HeapGcMeasurementSmokeError {
    /// A fixed smoke source failed a frontend stage.
    #[error("heap/GC measurement source {input:?} failed {stage:?}: {message}")]
    Lower {
        /// The fixed source that failed.
        input: &'static str,
        /// The frontend stage that failed.
        stage: HeapGcMeasurementLowerStage,
        /// A diagnostic message from the frontend.
        message: String,
    },
    /// A fixed smoke source failed during tree-walk evaluation.
    #[error("heap/GC measurement source {input:?} failed tree-walk evaluation")]
    TreeWalk {
        /// The fixed source that failed.
        input: &'static str,
        /// The evaluator error.
        #[source]
        error: Box<TreeWalkError>,
    },
    /// The fixed measurement budget could not be constructed.
    #[error("heap/GC measurement memory budget {bytes} is invalid")]
    InvalidMemoryBudget {
        /// The configured memory-budget byte count.
        bytes: usize,
    },
    /// A configured source did not record an allocation budget action.
    #[error("heap/GC measurement source {input:?} did not record a memory-budget action")]
    MissingMemoryBudgetAction {
        /// The fixed source that failed to exercise budget telemetry.
        input: &'static str,
    },
    /// A default source recorded a budget action without budget options.
    #[error("heap/GC measurement source {input:?} unexpectedly recorded a memory-budget action")]
    UnexpectedDefaultMemoryBudgetAction {
        /// The fixed source that unexpectedly recorded budget telemetry.
        input: &'static str,
    },
    /// A configured source did not record the cold-aware budget plan.
    #[error("heap/GC measurement source {input:?} did not record a cheap-memory budget plan")]
    MissingCheapMemoryBudgetPlan {
        /// The fixed source that failed to exercise cheap-memory planning.
        input: &'static str,
    },
    /// A configured source did not record cheap-memory advice telemetry.
    #[error("heap/GC measurement source {input:?} did not record cheap-memory advice")]
    MissingCheapMemoryAdviceReport {
        /// The fixed source that failed to exercise cheap-memory advice.
        input: &'static str,
    },
    /// The outcome-level advice report differed from the budget-plan report.
    #[error("heap/GC measurement source {input:?} recorded inconsistent advice reports")]
    AdviceReportMismatch {
        /// The fixed source with inconsistent reports.
        input: &'static str,
    },
    /// The cold hash-consed advice path used a different advice kind.
    #[error(
        "heap/GC measurement source {input:?} used advice kind {actual:?}, expected {expected:?}"
    )]
    UnexpectedAdviceKind {
        /// The fixed source with an unexpected advice kind.
        input: &'static str,
        /// The expected advice kind.
        expected: MemoryAdviceKind,
        /// The actual advice kind.
        actual: MemoryAdviceKind,
    },
    /// The cold hash-consed record counter stayed empty.
    #[error("heap/GC measurement source {input:?} did not report cold hash-consed records")]
    MissingColdHashConsedRecords {
        /// The fixed source that failed to expose cold hash-consed records.
        input: &'static str,
    },
    /// The cold hash-consed byte counter stayed empty.
    #[error("heap/GC measurement source {input:?} did not report cold hash-consed bytes")]
    MissingColdHashConsedBytes {
        /// The fixed source that failed to expose cold hash-consed bytes.
        input: &'static str,
    },
    /// The source-region plan counters stayed empty.
    #[error("heap/GC measurement source {input:?} did not record source-region telemetry")]
    MissingRegionPlanTelemetry {
        /// The fixed source that failed to exercise region-plan telemetry.
        input: &'static str,
    },
    /// The configured source did not request Tier B.
    #[error("heap/GC measurement source {input:?} did not request Tier B")]
    MissingTierBRequest {
        /// The fixed source that failed to request Tier B.
        input: &'static str,
    },
    /// The configured source did not record Tier-B admission.
    #[error("heap/GC measurement source {input:?} did not record Tier-B admission")]
    MissingTierBAdmission {
        /// The fixed source that failed to exercise admission.
        input: &'static str,
    },
    /// The configured source did not rewrite generation metadata.
    #[error("heap/GC measurement source {input:?} did not rewrite generation metadata")]
    MissingGenerationRewrite {
        /// The fixed source that failed to exercise generation rewrites.
        input: &'static str,
    },
    /// Outcome stats disagreed with the report they mirror.
    #[error("heap/GC measurement source {input:?} reported {metric}={actual}, expected {expected}")]
    StatsMismatch {
        /// The fixed source with inconsistent stats.
        input: &'static str,
        /// The metric name.
        metric: &'static str,
        /// The value expected from the source report.
        expected: u64,
        /// The value reported by mirrored stats.
        actual: u64,
    },
    /// A metric could not be represented in the smoke report.
    #[error("heap/GC measurement metric {metric} value {value} does not fit in u64")]
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
    fn heap_gc_measurement_manifest_covers_open_decision_targets() {
        let manifest =
            validate_heap_gc_measurement_manifest().expect("measurement manifest validates");
        let expected_targets = [
            (
                HeapGcMeasurementId::M12ConsTableSizingUnderDaemonGc,
                HeapGcMeasurementScope::ColdHashConsedBudgetTelemetry,
                "heap_gc_measurement_m12_cons_table_sizing_smoke",
            ),
            (
                HeapGcMeasurementId::M14RegionInferenceVsGenerationalGc,
                HeapGcMeasurementScope::RegionPlanAdmissionTelemetry,
                "heap_gc_measurement_m14_region_vs_generational_smoke",
            ),
            (
                HeapGcMeasurementId::QGDaemonVsPerInvocation,
                HeapGcMeasurementScope::PerInvocationBudgetTelemetry,
                "heap_gc_measurement_qg_per_invocation_budget_smoke",
            ),
        ];

        assert_eq!(manifest.target_count(), expected_targets.len());
        for (measurement_id, scope, test_filter) in expected_targets {
            let target = manifest
                .target_for(measurement_id, scope)
                .expect("required target is present");
            assert_eq!(target.package(), MEASUREMENT_PACKAGE);
            assert_eq!(target.manifest_path(), MEASUREMENT_MANIFEST_PATH);
            assert_eq!(target.test_filter(), test_filter);
            assert!(!target.rationale().is_empty());
        }
    }

    #[test]
    fn heap_gc_measurement_invocations_pin_cargo_test_filters() {
        let invocations =
            heap_gc_measurement_invocations().expect("measurement invocations validate");
        assert_eq!(
            invocations.len(),
            validate_heap_gc_measurement_manifest()
                .expect("measurement manifest validates")
                .target_count()
        );

        let m12 = invocation_for(
            &invocations,
            HeapGcMeasurementId::M12ConsTableSizingUnderDaemonGc,
            HeapGcMeasurementScope::ColdHashConsedBudgetTelemetry,
        );
        assert_eq!(m12.cargo_program(), "cargo");
        assert_eq!(
            m12.cargo_args(),
            &[
                "test",
                "--manifest-path",
                MEASUREMENT_MANIFEST_PATH,
                "-p",
                MEASUREMENT_PACKAGE,
                "heap_gc_measurement_m12_cons_table_sizing_smoke",
                "--",
                "--nocapture",
            ]
        );

        let qg = invocation_for(
            &invocations,
            HeapGcMeasurementId::QGDaemonVsPerInvocation,
            HeapGcMeasurementScope::PerInvocationBudgetTelemetry,
        );
        assert_eq!(
            qg.cargo_args(),
            &[
                "test",
                "--manifest-path",
                MEASUREMENT_MANIFEST_PATH,
                "-p",
                MEASUREMENT_PACKAGE,
                "heap_gc_measurement_qg_per_invocation_budget_smoke",
                "--",
                "--nocapture",
            ]
        );
    }

    fn invocation_for(
        invocations: &[HeapGcMeasurementInvocation],
        measurement_id: HeapGcMeasurementId,
        scope: HeapGcMeasurementScope,
    ) -> &HeapGcMeasurementInvocation {
        invocations
            .iter()
            .find(|invocation| {
                invocation.target().measurement_id() == measurement_id
                    && invocation.target().scope() == scope
            })
            .expect("measurement invocation is present")
    }

    #[test]
    fn heap_gc_measurement_m12_cons_table_sizing_smoke() {
        let report = run_heap_gc_measurement_m12_cons_table_sizing_smoke()
            .expect("M-12 measurement smoke passes");

        assert_eq!(
            report.measurement_id(),
            HeapGcMeasurementId::M12ConsTableSizingUnderDaemonGc
        );
        assert_eq!(report.case_count(), 1);
        assert!(report.cold_hash_consed_records() > 0);
        assert!(report.cold_hash_consed_bytes() > 0);
        assert_eq!(report.region_plan_decisions(), 0);
    }

    #[test]
    fn heap_gc_measurement_m14_region_vs_generational_smoke() {
        let report = run_heap_gc_measurement_m14_region_vs_generational_smoke()
            .expect("M-14 measurement smoke passes");

        assert_eq!(
            report.measurement_id(),
            HeapGcMeasurementId::M14RegionInferenceVsGenerationalGc
        );
        assert_eq!(report.case_count(), 1);
        assert!(report.region_plan_decisions() > 0);
        assert!(report.region_plan_conservative_fallbacks() <= report.region_plan_decisions());
        assert_eq!(report.tier_b_requests(), 1);
        assert!(report.tier_b_generation_rewrites() > 0);
    }

    #[test]
    fn heap_gc_measurement_qg_per_invocation_budget_smoke() {
        let report = run_heap_gc_measurement_qg_per_invocation_budget_smoke()
            .expect("Q-G measurement smoke passes");

        assert_eq!(
            report.measurement_id(),
            HeapGcMeasurementId::QGDaemonVsPerInvocation
        );
        assert_eq!(report.case_count(), 2);
        assert_eq!(report.tier_b_requests(), 1);
        assert!(report.tier_b_generation_rewrites() > 0);
    }
}
