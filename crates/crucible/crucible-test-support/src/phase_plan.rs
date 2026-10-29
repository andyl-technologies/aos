//! Phase-gate ordering for the Crucible determinism gates.
//!
//! The catalog records names once; this plan records every occurrence, including repeated gates.
//! `docs/engineering/crucible/testing-and-gates.md` documents the ordering, the layer
//! precedences, and the advanced-feature ladder that this module makes executable.

use std::collections::BTreeSet;

use crate::find_gate;

/// A Crucible determinism-test layer, from L0 runtime primitives up to L4 end-to-end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeterminismLayer {
    /// L0 deterministic runtime and assertion primitives.
    L0,
    /// L1 co-simulation transport and ABI boundary.
    L1,
    /// L2 single-VM QEMU integration.
    L2,
    /// L3 engine, temporal graph, and scheduler.
    L3,
    /// L4 control plane.
    L4,
}

/// The phase where a gate occurrence blocks forward progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PhasePlanPhase {
    /// Phase 0 de-risks design blockers before implementation starts.
    Phase0,
    /// Phase 1 builds the deterministic core, harness, and in-process double.
    Phase1,
    /// Phase 2 builds the transport ABI and per-VM QEMU determinism.
    Phase2,
    /// Phase 3 builds scheduling, I/O sub-nodes, and cross-VM injection.
    Phase3,
    /// Phase 4 builds the engine, spatial graph, temporal graph, and faults.
    Phase4,
    /// Phase 5 builds the control plane, API, CLI, and daemon.
    Phase5,
    /// Phase 6 builds advanced exploration and search.
    Phase6,
    /// Phase 7 builds packaging, performance checks, and final acceptance.
    Phase7,
}

impl PhasePlanPhase {
    /// Returns the lowercase label for this phase, such as `phase3`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Phase0 => "phase0",
            Self::Phase1 => "phase1",
            Self::Phase2 => "phase2",
            Self::Phase3 => "phase3",
            Self::Phase4 => "phase4",
            Self::Phase5 => "phase5",
            Self::Phase6 => "phase6",
            Self::Phase7 => "phase7",
        }
    }
}

/// Every phase in plan order.
pub const PHASE_PLAN_PHASES: &[PhasePlanPhase] = &[
    PhasePlanPhase::Phase0,
    PhasePlanPhase::Phase1,
    PhasePlanPhase::Phase2,
    PhasePlanPhase::Phase3,
    PhasePlanPhase::Phase4,
    PhasePlanPhase::Phase5,
    PhasePlanPhase::Phase6,
    PhasePlanPhase::Phase7,
];

/// The phase by which `crucible_engine::SimDouble` must be available.
pub const SIM_DOUBLE_AVAILABLE_PHASE: PhasePlanPhase = PhasePlanPhase::Phase1;

/// Whether an occurrence is a canonical gate or a phase-local aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseGateKind {
    /// The occurrence names a gate from the canonical gate catalog.
    CatalogGate,
    /// The occurrence names a phase-local aggregate outside the gate catalog.
    NonCatalogAggregate,
}

/// One ordered phase-gate occurrence in the phase plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseGateOccurrence {
    /// The phase whose exit this occurrence guards.
    pub phase: PhasePlanPhase,
    /// The canonical gate name or non-catalog aggregate label.
    pub gate_name: &'static str,
    /// The Nix check attr path that must be green for this occurrence.
    pub attr_path: &'static str,
    /// The kind of gate occurrence.
    pub kind: PhaseGateKind,
    /// A short human-readable description of the occurrence's role.
    pub purpose: &'static str,
    /// Whether this occurrence depends on the Phase 1 in-process double.
    pub requires_sim_double: bool,
    /// Whether this occurrence is the terminal final-acceptance gate.
    pub terminal_acceptance: bool,
}

/// The class of phase-plan invariant failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhasePlanInvariantFailureKind {
    /// A catalog occurrence names a gate absent from the canonical catalog.
    UnknownCatalogGate,
    /// Two occurrences share the same Nix attr path.
    DuplicateAttrPath,
    /// A non-catalog aggregate appears outside Phase 0.
    NonCatalogAggregateAfterPhase0,
    /// An occurrence appears before an earlier phase in the ordered plan.
    OutOfOrderPhase,
    /// A phase has no exit-gate occurrence.
    EmptyPhase,
    /// No Phase 7 terminal `gate:signal-fault-system` occurrence exists.
    MissingTerminalSignalFaultSystem,
    /// A terminal marker is attached to the wrong occurrence.
    InvalidTerminalAcceptanceGate,
    /// A gate occurrence depends on `SimDouble` before Phase 1 makes it available.
    SimDoubleUnavailable,
}

/// A phase-plan invariant failure with optional occurrence context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhasePlanInvariantFailure {
    /// The invariant that failed.
    pub kind: PhasePlanInvariantFailureKind,
    /// The phase associated with the failed invariant, when available.
    pub phase: Option<PhasePlanPhase>,
    /// The gate or aggregate name associated with the failed invariant.
    pub gate_name: Option<&'static str>,
    /// The Nix attr path associated with the failed invariant.
    pub attr_path: Option<&'static str>,
}

/// A required lower-layer-before-higher-layer gate precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerGatePrecedence {
    /// The lower layer whose gate must already be green.
    pub lower_layer: DeterminismLayer,
    /// The higher layer whose gate must not run first.
    pub higher_layer: DeterminismLayer,
    /// The lower-layer gate occurrence attr path.
    pub lower_attr_path: &'static str,
    /// The higher-layer gate occurrence attr path.
    pub higher_attr_path: &'static str,
    /// Why this precedence exists.
    pub rationale: &'static str,
}

/// A failed lower-layer-before-higher-layer precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerGatePrecedenceFailure {
    /// The lower-layer gate occurrence attr path.
    pub lower_attr_path: &'static str,
    /// The higher-layer gate occurrence attr path.
    pub higher_attr_path: &'static str,
    /// Why this precedence exists.
    pub rationale: &'static str,
}

/// One rung in the advanced-feature dependency ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvancedFeatureRung {
    /// Exact deterministic replay is the bedrock below every advanced feature.
    ExactDeterminism,
    /// Oracle-validated save/restore provides correct checkpoint realization.
    SaveRestore,
    /// Fork branches the temporal graph from validated checkpoints.
    Fork,
    /// Search systematically expands frontier decisions.
    Search,
    /// Coverage feedback records observational basic-block guidance.
    CoverageFeedback,
    /// Fuzzing samples and mutates families, schedules, and fault plans.
    Fuzzing,
}

impl AdvancedFeatureRung {
    /// Returns the kebab-case label for this advanced-feature rung.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactDeterminism => "exact-determinism",
            Self::SaveRestore => "save-restore",
            Self::Fork => "fork",
            Self::Search => "search",
            Self::CoverageFeedback => "coverage-feedback",
            Self::Fuzzing => "fuzzing",
        }
    }
}

/// One advanced-feature check bound to the dependency ladder.
///
/// A step is keyed by the Nix attr path of the check that implements it, so the
/// ladder and `tests/crucible/default.nix` name the same thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvancedFeatureStep {
    /// Attr path of the implementing check, such as
    /// `checks.crucible.phase6.coverageGuidedFuzzing`.
    pub attr_path: &'static str,
    /// Ladder rung that owns the step.
    pub rung: AdvancedFeatureRung,
    /// Phase where the step's check is scheduled.
    pub phase: PhasePlanPhase,
    /// Gate occurrences that must already be green before this step can start.
    pub required_green_attr_paths: &'static [&'static str],
    /// Attr paths of earlier ladder steps whose checks this step depends on.
    pub prerequisite_attr_paths: &'static [&'static str],
    /// Short human-readable rationale for the dependency.
    pub rationale: &'static str,
}

/// A failed advanced-feature dependency-ladder ordering rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvancedFeatureLadderFailure {
    /// Attr path of the step whose dependency rule failed.
    pub attr_path: &'static str,
    /// Rung that owns the step.
    pub rung: AdvancedFeatureRung,
    /// Missing or late gate attr path, when the failure concerns a gate.
    pub gate_attr_path: Option<&'static str>,
    /// Missing or late prerequisite step, when the failure concerns step order.
    pub prerequisite_attr_path: Option<&'static str>,
    /// Why this dependency exists.
    pub rationale: &'static str,
}

/// The class of advanced-feature schedule failure found in `tests/crucible/default.nix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvancedFeatureScheduleFailureKind {
    /// No check declares the step's attr path.
    MissingCheck,
    /// The step's check is not wrapped in an advance guard.
    MissingAdvanceGuard,
    /// The step's check does not depend on a required green lower gate.
    MissingGateDependency,
    /// The step's check does not depend on a prerequisite step's check.
    MissingPrerequisiteDependency,
}

/// A failed advanced-feature schedule rule from the actual Nix check graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvancedFeatureScheduleFailure {
    /// Attr path of the ladder step whose check failed the rule.
    pub attr_path: &'static str,
    /// The class of schedule failure.
    pub kind: AdvancedFeatureScheduleFailureKind,
    /// Missing Nix dependency reference, when the failure concerns a dependency.
    pub dependency: Option<String>,
}

/// Layer-gate precedence obligations that make lower-layer-first ordering executable.
pub const LAYER_GATE_PRECEDENCES: &[LayerGatePrecedence] = &[
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L0,
        higher_layer: DeterminismLayer::L1,
        lower_attr_path: "checks.crucible.phase1.gates.layer0Determinism",
        higher_attr_path: "checks.crucible.phase2.gates.abiConformance",
        rationale: "L1 ABI checks build on the green L0 deterministic core",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L1,
        higher_layer: DeterminismLayer::L2,
        lower_attr_path: "checks.crucible.phase2.gates.layer1Injection",
        higher_attr_path: "checks.crucible.phase2.gates.patchMicrotests",
        rationale: "QEMU patch tests cannot stand in for the L1 injection gate",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L1,
        higher_layer: DeterminismLayer::L2,
        lower_attr_path: "checks.crucible.phase2.gates.layer1Injection",
        higher_attr_path: "checks.crucible.phase2.gates.qemuInert",
        rationale: "QEMU inertness sits above the L1 injection gate",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L1,
        higher_layer: DeterminismLayer::L2,
        lower_attr_path: "checks.crucible.phase2.gates.layer1Injection",
        higher_attr_path: "checks.crucible.phase2.gates.singleVmFingerprint",
        rationale: "real-QEMU Contract A cannot cover the L1 injection gate",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L1,
        higher_layer: DeterminismLayer::L2,
        lower_attr_path: "checks.crucible.phase2.gates.layer1Injection",
        higher_attr_path: "checks.crucible.phase2.gates.anyGuest",
        rationale: "unmodified guest boot cannot cover the L1 injection gate",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L2,
        higher_layer: DeterminismLayer::L3,
        lower_attr_path: "checks.crucible.phase2.gates.singleVmFingerprint",
        higher_attr_path: "checks.crucible.phase3.gates.schedulerLiveness",
        rationale: "scheduler liveness must run after real single-VM determinism",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L2,
        higher_layer: DeterminismLayer::L3,
        lower_attr_path: "checks.crucible.phase2.gates.singleVmFingerprint",
        higher_attr_path: "checks.crucible.phase3.gates.adversarialDeterminism",
        rationale: "adversarial cross-layer determinism cannot cover Contract A",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L1,
        higher_layer: DeterminismLayer::L3,
        lower_attr_path: "checks.crucible.phase2.gates.layer1Injection",
        higher_attr_path: "checks.crucible.phase3.gates.schedulerLiveness",
        rationale: "scheduler liveness requires the cross-node injection contract",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L1,
        higher_layer: DeterminismLayer::L3,
        lower_attr_path: "checks.crucible.phase2.gates.layer1Injection",
        higher_attr_path: "checks.crucible.phase3.gates.adversarialDeterminism",
        rationale: "adversarial determinism must not cover Contract B",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L3,
        higher_layer: DeterminismLayer::L4,
        lower_attr_path: "checks.crucible.phase4.gates.replayOracle",
        higher_attr_path: "checks.crucible.phase5.gates.controlResponsive",
        rationale: "control-plane responsiveness rides a green replay/oracle foundation",
    },
    LayerGatePrecedence {
        lower_layer: DeterminismLayer::L3,
        higher_layer: DeterminismLayer::L4,
        lower_attr_path: "checks.crucible.phase4.gates.e2eDeterminism",
        higher_attr_path: "checks.crucible.phase5.gates.controlResponsive",
        rationale: "control-plane checks ride the native end-to-end determinism foundation",
    },
];

const EXACT_DETERMINISM_FOUNDATION: &[&str] = &[
    "checks.crucible.phase2.gates.singleVmFingerprint",
    "checks.crucible.phase4.gates.e2eDeterminism",
];
const REPLAY_ORACLE_FOUNDATION: &[&str] = &[
    "checks.crucible.phase4.gates.replayOracle",
    "checks.crucible.phase4.gates.e2eDeterminism",
];
const CONTROL_PLANE_FOUNDATION: &[&str] = &["checks.crucible.phase5.gates.controlResponsive"];
const ADVANCED_LADDER_FOUNDATION: &[&str] = &[
    "checks.crucible.phase2.gates.singleVmFingerprint",
    "checks.crucible.phase4.gates.e2eDeterminism",
    "checks.crucible.phase5.gates.controlResponsive",
];

/// Advanced-feature entries in dependency-ladder order.
pub const ADVANCED_FEATURE_LADDER: &[AdvancedFeatureStep] = &[
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.advancedDependencyLadder",
        rung: AdvancedFeatureRung::ExactDeterminism,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: ADVANCED_LADDER_FOUNDATION,
        prerequisite_attr_paths: &[],
        rationale: "the ladder check itself is sequenced after deterministic replay and control are green",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.explorationLifecycle",
        rung: AdvancedFeatureRung::ExactDeterminism,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: CONTROL_PLANE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.advancedDependencyLadder"],
        rationale: "exploration lifecycle controls must ride the session actor",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.restoreStrategies",
        rung: AdvancedFeatureRung::SaveRestore,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.advancedDependencyLadder"],
        rationale: "restore strategies require the replay-oracle foundation",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.checkpointMaterialization",
        rung: AdvancedFeatureRung::SaveRestore,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.restoreStrategies"],
        rationale: "savepoints degrade to thin replay only after restore is oracle checked",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.explorationFork",
        rung: AdvancedFeatureRung::Fork,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.checkpointMaterialization"],
        rationale: "fork is instantiate from an oracle-validated checkpoint",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.gates.replayOracle",
        rung: AdvancedFeatureRung::Fork,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.explorationFork"],
        rationale: "fork validation reuses the save/restore replay oracle",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.stateSpaceSearch",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.gates.replayOracle"],
        rationale: "search is systematic fork from validated frontier nodes",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.searchStrategies",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.stateSpaceSearch"],
        rationale: "search strategies order already-valid frontier expansion",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.searchReductions",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.searchStrategies"],
        rationale: "reductions prune search children only after search ordering exists",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.preemptionBranching",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.searchReductions"],
        rationale: "preemption branching is a search dimension",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.appRandomBranching",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.preemptionBranching"],
        rationale: "app-controlled randomness is a search dimension",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.basicBlockCoverage",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: EXACT_DETERMINISM_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.stateSpaceSearch"],
        rationale: "coverage is black-box feedback consumed by search and fuzzing",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.coverageFeedback",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: EXACT_DETERMINISM_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.basicBlockCoverage"],
        rationale: "coverage enters the observational event log after extraction exists",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.guidanceSignals",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &[
            "checks.crucible.phase6.searchStrategies",
            "checks.crucible.phase6.coverageFeedback",
        ],
        rationale: "guidance signals compose deterministic search with coverage feedback",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.adaptiveStrategies",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.guidanceSignals"],
        rationale: "adaptive strategy selection wraps guidance without changing replay",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.guidanceDeterminismLint",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.adaptiveStrategies"],
        rationale: "ordering determinism lint protects guided strategy selection",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.coverageGuidedFuzzing",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &[
            "checks.crucible.phase6.coverageFeedback",
            "checks.crucible.phase6.guidanceDeterminismLint",
            "checks.crucible.phase6.appRandomBranching",
        ],
        rationale: "coverage-guided fuzzing requires search, coverage, and deterministic guidance",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.coverageGuidedCorpus",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.coverageGuidedFuzzing"],
        rationale: "corpus management stores coverage-driven fuzz findings",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.reproductionArtifacts",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.coverageGuidedCorpus"],
        rationale: "reproduction artifacts are emitted from search/fuzz findings",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.minimization",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.reproductionArtifacts"],
        rationale: "minimization shrinks self-contained findings",
    },
    AdvancedFeatureStep {
        attr_path: "checks.crucible.phase6.unifyingView",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        prerequisite_attr_paths: &["checks.crucible.phase6.minimization"],
        rationale: "the unifying-view test requires all advanced operations",
    },
];

/// The full ordered phase-gate plan.
pub const PHASE_GATE_ORDER: &[PhaseGateOccurrence] = &[
    non_catalog_gate(
        PhasePlanPhase::Phase0,
        "phase0:blockers",
        "checks.crucible.phase0.gates.blockers",
        "S1/S2/S4/S3 plus S11 blocker aggregate",
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase0,
        "gate:harness-lint",
        "checks.crucible.phase0.gates.harnessLint",
        "always-on harness lint",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:harness-lint",
        "checks.crucible.phase1.gates.harnessLint",
        "first Phase 1 exit gate",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:license-boundary",
        "checks.crucible.phase1.gates.licenseBoundary",
        "component license and public process boundary",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:layer0-determinism",
        "checks.crucible.phase1.gates.layer0Determinism",
        "production QEMU fingerprint determinism",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:content-address",
        "checks.crucible.phase1.gates.contentAddress",
        "content-addressed store",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:campaign-model",
        "checks.crucible.phase1.gates.campaignModel",
        "canonical campaign identities and repository lifecycle",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:replay-oracle",
        "checks.crucible.phase1.gates.replayOracle",
        "double-backed replay oracle",
        true,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:single-vm-fingerprint",
        "checks.crucible.phase1.gates.singleVmFingerprint",
        "double-backed single-VM fingerprint",
        true,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase1,
        "gate:divergence-bisect",
        "checks.crucible.phase1.gates.divergenceBisect",
        "diagnostic exercised on doubles",
        true,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase2,
        "gate:abi-conformance",
        "checks.crucible.phase2.gates.abiConformance",
        "L1 ABI golden vectors",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase2,
        "gate:typed-choice",
        "checks.crucible.phase2.gates.typedChoice",
        "typed guest choice boundary",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase2,
        "gate:layer1-injection",
        "checks.crucible.phase2.gates.layer1Injection",
        "L1 injection preflight before L2 gates",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase2,
        "gate:patch-microtests",
        "checks.crucible.phase2.gates.patchMicrotests",
        "QEMU patch microtests",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase2,
        "gate:qemu-inert",
        "checks.crucible.phase2.gates.qemuInert",
        "sim-off QEMU behavior",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase2,
        "gate:single-vm-fingerprint",
        "checks.crucible.phase2.gates.singleVmFingerprint",
        "Contract A on real QEMU",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase2,
        "gate:any-guest",
        "checks.crucible.phase2.gates.anyGuest",
        "unmodified guest boot",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase3,
        "gate:layer1-injection",
        "checks.crucible.phase3.gates.layer1Injection",
        "Contract B",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase3,
        "gate:scheduler-liveness",
        "checks.crucible.phase3.gates.schedulerLiveness",
        "production QEMU bounded scheduler progress",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase3,
        "gate:adversarial-determinism",
        "checks.crucible.phase3.gates.adversarialDeterminism",
        "modeled hostile-condition matrix",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase4,
        "gate:replay-oracle",
        "checks.crucible.phase4.gates.replayOracle",
        "full temporal graph replay",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase4,
        "gate:campaign-statistics",
        "checks.crucible.phase4.gates.campaignStatistics",
        "finite static P/Q estimation and intervention exclusion",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase4,
        "gate:e2e-determinism",
        "checks.crucible.phase4.gates.e2eDeterminism",
        "mock backend end-to-end determinism",
        true,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase5,
        "gate:control-responsive",
        "checks.crucible.phase5.gates.controlResponsive",
        "control-plane responsiveness",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase6,
        "gate:replay-oracle",
        "checks.crucible.phase6.gates.replayOracle",
        "active-search replay oracle",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase6,
        "gate:basic-block-coverage",
        "checks.crucible.phase6.basicBlockCoverage",
        "loaded-QEMU coverage boundary",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase6,
        "gate:checkpoint-materialization",
        "checks.crucible.phase6.checkpointMaterialization",
        "exact durable search state",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase6,
        "gate:state-space-search",
        "checks.crucible.phase6.stateSpaceSearch",
        "authenticated frontier expansion",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase7,
        "gate:perf-bench",
        "checks.crucible.phase7.gates.perfBench",
        "performance regression",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase7,
        "gate:e2e-determinism",
        "checks.crucible.phase7.gates.e2eDeterminism",
        "final acceptance",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase7,
        "gate:fleet-equivalence",
        "checks.crucible.phase7.gates.fleetEquivalence",
        "distributed equivalence",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase7,
        "gate:campaign-continuity",
        "checks.crucible.phase7.gates.campaignContinuity",
        "coverage ratchet",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase7,
        "gate:production-rust-plugin-flight",
        "checks.crucible.phase7.productionRustPluginFlight",
        "identity-bound live Rust and plugin boundary proof",
        false,
        false,
    ),
    catalog_gate(
        PhasePlanPhase::Phase7,
        "gate:signal-fault-system",
        "checks.crucible.phase7.gates.signalFaultSystem",
        "complete signal-driven production fault system",
        false,
        true,
    ),
];

/// Returns every ordered phase-gate occurrence.
#[must_use]
pub fn phase_gate_order() -> &'static [PhaseGateOccurrence] {
    PHASE_GATE_ORDER
}

/// Returns the terminal Phase 7 final-acceptance occurrence, if present.
#[must_use]
pub fn terminal_acceptance_gate() -> Option<&'static PhaseGateOccurrence> {
    PHASE_GATE_ORDER
        .iter()
        .find(|occurrence| occurrence.terminal_acceptance)
}

/// Returns invariant failures for a phase-gate plan.
#[must_use]
pub fn phase_plan_invariant_failures(
    plan: &[PhaseGateOccurrence],
) -> Vec<PhasePlanInvariantFailure> {
    let mut failures = Vec::new();
    let mut seen_attr_paths = BTreeSet::new();
    let mut has_terminal_signal_fault_system = false;
    let mut last_phase = None;
    for occurrence in plan {
        if let Some(previous) = last_phase
            && occurrence.phase < previous
        {
            failures.push(failure_for(
                PhasePlanInvariantFailureKind::OutOfOrderPhase,
                occurrence,
            ));
        }
        last_phase = Some(occurrence.phase);
        if !seen_attr_paths.insert(occurrence.attr_path) {
            failures.push(failure_for(
                PhasePlanInvariantFailureKind::DuplicateAttrPath,
                occurrence,
            ));
        }

        match occurrence.kind {
            PhaseGateKind::CatalogGate => {
                if find_gate(occurrence.gate_name).is_none() {
                    failures.push(failure_for(
                        PhasePlanInvariantFailureKind::UnknownCatalogGate,
                        occurrence,
                    ));
                }
            }
            PhaseGateKind::NonCatalogAggregate => {
                if occurrence.phase != PhasePlanPhase::Phase0 {
                    failures.push(failure_for(
                        PhasePlanInvariantFailureKind::NonCatalogAggregateAfterPhase0,
                        occurrence,
                    ));
                }
            }
        }

        if occurrence.terminal_acceptance {
            if occurrence.phase == PhasePlanPhase::Phase7
                && occurrence.kind == PhaseGateKind::CatalogGate
                && occurrence.gate_name == "gate:signal-fault-system"
            {
                has_terminal_signal_fault_system = true;
            } else {
                failures.push(failure_for(
                    PhasePlanInvariantFailureKind::InvalidTerminalAcceptanceGate,
                    occurrence,
                ));
            }
        }

        if occurrence.requires_sim_double && occurrence.phase < SIM_DOUBLE_AVAILABLE_PHASE {
            failures.push(failure_for(
                PhasePlanInvariantFailureKind::SimDoubleUnavailable,
                occurrence,
            ));
        }
    }

    for phase in PHASE_PLAN_PHASES {
        if !plan.iter().any(|occurrence| occurrence.phase == *phase) {
            failures.push(PhasePlanInvariantFailure {
                kind: PhasePlanInvariantFailureKind::EmptyPhase,
                phase: Some(*phase),
                gate_name: None,
                attr_path: None,
            });
        }
    }

    if !has_terminal_signal_fault_system {
        failures.push(PhasePlanInvariantFailure {
            kind: PhasePlanInvariantFailureKind::MissingTerminalSignalFaultSystem,
            phase: Some(PhasePlanPhase::Phase7),
            gate_name: Some("gate:signal-fault-system"),
            attr_path: None,
        });
    }

    failures
}

/// Returns missing earlier phase gates before work can start on `next_phase`.
#[must_use]
pub fn green_before_advance_failures(
    green_attr_paths: &[&str],
    next_phase: PhasePlanPhase,
) -> Vec<&'static PhaseGateOccurrence> {
    let green: BTreeSet<&str> = green_attr_paths.iter().copied().collect();

    PHASE_GATE_ORDER
        .iter()
        .filter(|occurrence| occurrence.phase < next_phase && !green.contains(occurrence.attr_path))
        .collect()
}

/// Returns lower-layer-before-higher-layer ordering failures.
#[must_use]
pub fn layer_gate_precedence_failures(
    plan: &[PhaseGateOccurrence],
    precedences: &[LayerGatePrecedence],
) -> Vec<LayerGatePrecedenceFailure> {
    let mut failures = Vec::new();

    for precedence in precedences {
        let lower_index = plan
            .iter()
            .position(|occurrence| occurrence.attr_path == precedence.lower_attr_path);
        let higher_index = plan
            .iter()
            .position(|occurrence| occurrence.attr_path == precedence.higher_attr_path);

        if !matches!((lower_index, higher_index), (Some(lower), Some(higher)) if lower < higher) {
            failures.push(LayerGatePrecedenceFailure {
                lower_attr_path: precedence.lower_attr_path,
                higher_attr_path: precedence.higher_attr_path,
                rationale: precedence.rationale,
            });
        }
    }

    failures
}

/// Returns every advanced-feature ladder step in dependency order.
#[must_use]
pub fn advanced_feature_ladder() -> &'static [AdvancedFeatureStep] {
    ADVANCED_FEATURE_LADDER
}

/// Returns advanced-feature dependency-ladder failures against the phase-gate plan.
#[must_use]
pub fn advanced_feature_ladder_failures(
    plan: &[PhaseGateOccurrence],
    steps: &[AdvancedFeatureStep],
) -> Vec<AdvancedFeatureLadderFailure> {
    let mut failures = Vec::new();
    let ordered_gate_attrs = plan
        .iter()
        .map(|occurrence| occurrence.attr_path)
        .collect::<Vec<_>>();

    for (step_index, step) in steps.iter().enumerate() {
        let failure = |gate_attr_path, prerequisite_attr_path| AdvancedFeatureLadderFailure {
            attr_path: step.attr_path,
            rung: step.rung,
            gate_attr_path,
            prerequisite_attr_path,
            rationale: step.rationale,
        };

        for &gate_attr_path in step.required_green_attr_paths {
            let gate_index = ordered_gate_attrs
                .iter()
                .position(|candidate| *candidate == gate_attr_path);
            let green_before_step =
                matches!(gate_index, Some(index) if plan[index].phase < step.phase);
            if !green_before_step {
                failures.push(failure(Some(gate_attr_path), None));
            }
        }

        for &prerequisite_attr_path in step.prerequisite_attr_paths {
            let prerequisite_index = steps
                .iter()
                .position(|candidate| candidate.attr_path == prerequisite_attr_path);
            if !matches!(prerequisite_index, Some(index) if index < step_index) {
                failures.push(failure(None, Some(prerequisite_attr_path)));
            }
        }

        // Rungs never descend: a fuzzing step listed before a coverage step
        // would let fuzzing run on an unproven coverage foundation.
        if step_index > 0 {
            let previous = steps[step_index - 1];
            if step.rung < previous.rung {
                failures.push(failure(None, Some(previous.attr_path)));
            }
        }
    }

    failures
}

/// Returns failures where the actual Nix check graph schedules advanced-feature work out of
/// order.
///
/// Each ladder step's check is located in `default_checks` by its `attrPath`. The check must be
/// wrapped in an advance guard whose top-level `dependencies` name every required green gate
/// and every prerequisite step's check, so advanced work cannot bypass its foundation.
#[must_use]
pub fn advanced_feature_schedule_failures(
    default_checks: &str,
    steps: &[AdvancedFeatureStep],
) -> Vec<AdvancedFeatureScheduleFailure> {
    let mut failures = Vec::new();

    for step in steps {
        let failure = |kind, dependency| AdvancedFeatureScheduleFailure {
            attr_path: step.attr_path,
            kind,
            dependency,
        };

        let Some(scheduled) = scheduled_advanced_feature_check(default_checks, step.attr_path)
        else {
            failures.push(failure(
                AdvancedFeatureScheduleFailureKind::MissingCheck,
                None,
            ));
            continue;
        };

        if !scheduled.advance_guarded {
            failures.push(failure(
                AdvancedFeatureScheduleFailureKind::MissingAdvanceGuard,
                None,
            ));
        }

        let required_dependencies = step
            .required_green_attr_paths
            .iter()
            .map(|attr_path| {
                (
                    AdvancedFeatureScheduleFailureKind::MissingGateDependency,
                    attr_path,
                )
            })
            .chain(step.prerequisite_attr_paths.iter().map(|attr_path| {
                (
                    AdvancedFeatureScheduleFailureKind::MissingPrerequisiteDependency,
                    attr_path,
                )
            }));
        for (kind, attr_path) in required_dependencies {
            let dependency = attr_path_to_default_nix_reference(attr_path);
            if !scheduled.dependencies.contains(&dependency) {
                failures.push(failure(kind, Some(dependency)));
            }
        }
    }

    failures
}

#[derive(Clone, Debug)]
struct ScheduledAdvancedFeatureCheck {
    dependencies: BTreeSet<String>,
    advance_guarded: bool,
}

/// Finds the check declaring `attr_path`, preferring an advance-guarded declaration.
///
/// The guard block must own the attr path itself: an unguarded check nested near a guard must
/// not borrow that guard's dependencies.
fn scheduled_advanced_feature_check(
    default_checks: &str,
    attr_path: &str,
) -> Option<ScheduledAdvancedFeatureCheck> {
    let declaration = format!("attrPath = \"{attr_path}\";");
    let mut declared = false;

    for (position, _) in default_checks.match_indices(&declaration) {
        declared = true;
        let Some(block) = enclosing_advance_guard_block(default_checks, position) else {
            continue;
        };
        if attr_path_from_block(block).as_deref() == Some(attr_path) {
            return Some(ScheduledAdvancedFeatureCheck {
                dependencies: top_level_dependency_tokens(block),
                advance_guarded: true,
            });
        }
    }

    declared.then(|| ScheduledAdvancedFeatureCheck {
        dependencies: BTreeSet::new(),
        advance_guarded: false,
    })
}

fn enclosing_advance_guard_block(content: &str, position: usize) -> Option<&str> {
    const MARKERS: [&str; 2] = ["= greenBeforeAdvance {", "= redBeforeAdvance {"];
    let mut candidates = MARKERS
        .iter()
        .flat_map(|marker| {
            content[..position]
                .match_indices(marker)
                .map(move |(index, _)| (index, *marker))
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(index, _)| *index);
    candidates.reverse();

    for (start, marker) in candidates {
        let open_brace = start + marker.len() - 1;
        let Some(end) = matching_brace_end(content, open_brace) else {
            continue;
        };
        if end >= position {
            return Some(&content[start..=end]);
        }
    }

    None
}

fn matching_brace_end(content: &str, open_brace: usize) -> Option<usize> {
    let mut depth = 0_u32;
    let mut in_double_quoted_string = false;
    let mut escaped = false;

    for (offset, character) in content[open_brace..].char_indices() {
        if in_double_quoted_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_double_quoted_string = false;
            }
            continue;
        }

        match character {
            '"' => in_double_quoted_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open_brace + offset);
                }
            }
            _ => {}
        }
    }

    None
}

fn attr_path_from_block(block: &str) -> Option<String> {
    let marker = "attrPath = \"";
    let start = block.find(marker)? + marker.len();
    let end = block[start..].find('"')?;
    Some(block[start..start + end].to_string())
}

fn top_level_dependency_tokens(block: &str) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    let mut depth = 0_u32;
    let mut in_double_quoted_string = false;
    let mut escaped = false;
    let marker = "dependencies = [";

    for (index, character) in block.char_indices() {
        if in_double_quoted_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_double_quoted_string = false;
            }
            continue;
        }

        if block[index..].starts_with(marker) && depth == 1 {
            let list_start = index + marker.len();
            if let Some(relative_end) = block[list_start..].find("];") {
                let list_end = list_start + relative_end;
                dependencies.extend(dependency_list_tokens(&block[list_start..list_end]));
            }
        }

        match character {
            '"' => in_double_quoted_string = true,
            '{' => depth += 1,
            '}' => {
                if let Some(next_depth) = depth.checked_sub(1) {
                    depth = next_depth;
                }
            }
            _ => {}
        }
    }

    dependencies
}

fn dependency_list_tokens(list: &str) -> impl Iterator<Item = String> + '_ {
    list.split_whitespace()
        .filter(|token| !token.is_empty())
        .map(|token| token.trim_matches(|character| character == '(' || character == ')'))
        .map(str::to_string)
}

fn attr_path_to_default_nix_reference(attr_path: &str) -> String {
    attr_path
        .strip_prefix("checks.crucible.")
        .unwrap_or(attr_path)
        .to_string()
}

const fn catalog_gate(
    phase: PhasePlanPhase,
    gate_name: &'static str,
    attr_path: &'static str,
    purpose: &'static str,
    requires_sim_double: bool,
    terminal_acceptance: bool,
) -> PhaseGateOccurrence {
    PhaseGateOccurrence {
        phase,
        gate_name,
        attr_path,
        kind: PhaseGateKind::CatalogGate,
        purpose,
        requires_sim_double,
        terminal_acceptance,
    }
}

const fn non_catalog_gate(
    phase: PhasePlanPhase,
    gate_name: &'static str,
    attr_path: &'static str,
    purpose: &'static str,
    requires_sim_double: bool,
) -> PhaseGateOccurrence {
    PhaseGateOccurrence {
        phase,
        gate_name,
        attr_path,
        kind: PhaseGateKind::NonCatalogAggregate,
        purpose,
        requires_sim_double,
        terminal_acceptance: false,
    }
}

fn failure_for(
    kind: PhasePlanInvariantFailureKind,
    occurrence: &PhaseGateOccurrence,
) -> PhasePlanInvariantFailure {
    PhasePlanInvariantFailure {
        kind,
        phase: Some(occurrence.phase),
        gate_name: Some(occurrence.gate_name),
        attr_path: Some(occurrence.attr_path),
    }
}
