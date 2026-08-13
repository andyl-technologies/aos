//! Phase-gate ordering for RFC-0010.
//!
//! The catalog records names once; this plan records every occurrence, including repeated gates.

use std::collections::{BTreeMap, BTreeSet};

use crate::find_gate;

/// A Crucible determinism-test layer from RFC-0010 file 24 section 2.
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
    /// Returns the lowercase RFC label for this phase.
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

/// Every phase in RFC order.
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

/// The phase by which `crucible::SimDouble` must be available.
pub const SIM_DOUBLE_AVAILABLE_PHASE: PhasePlanPhase = PhasePlanPhase::Phase1;

/// Whether an occurrence is a canonical gate or a phase-local aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseGateKind {
    /// The occurrence names a gate from the canonical RFC-0010 gate catalog.
    CatalogGate,
    /// The occurrence names a phase-local aggregate outside the gate catalog.
    NonCatalogAggregate,
}

/// One ordered phase-gate occurrence from RFC-0010 file 24 section 13.
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

/// A required lower-layer gate precedence from HARN-3.
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

/// A failed HARN-3 lower-layer-before-higher-layer precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerGatePrecedenceFailure {
    /// The lower-layer gate occurrence attr path.
    pub lower_attr_path: &'static str,
    /// The higher-layer gate occurrence attr path.
    pub higher_attr_path: &'static str,
    /// Why this precedence exists.
    pub rationale: &'static str,
}

/// One rung in the advanced-feature dependency ladder from RFC-0010 file 22.
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
    /// Returns the RFC label for this advanced-feature rung.
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

/// One ADV checklist task bound to the dependency ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvancedFeatureTaskOrder {
    /// RFC checklist task identifier such as `T-ADV-12`.
    pub task_id: &'static str,
    /// Ladder rung that owns the task.
    pub rung: AdvancedFeatureRung,
    /// Phase where the task is scheduled by the master implementation plan.
    pub phase: PhasePlanPhase,
    /// Gate occurrences that must already be green before this task can start.
    pub required_green_attr_paths: &'static [&'static str],
    /// Earlier ADV tasks whose completion is a prerequisite for this task.
    pub required_task_ids: &'static [&'static str],
    /// Short human-readable rationale for the dependency.
    pub rationale: &'static str,
}

/// A failed ADV dependency-ladder ordering rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvancedFeatureLadderFailure {
    /// Task whose dependency rule failed.
    pub task_id: &'static str,
    /// Rung that owns the task.
    pub rung: AdvancedFeatureRung,
    /// Missing or late gate attr path, when the failure concerns a gate.
    pub attr_path: Option<&'static str>,
    /// Missing or late prerequisite ADV task, when the failure concerns a task.
    pub prerequisite_task_id: Option<&'static str>,
    /// Why this dependency exists.
    pub rationale: &'static str,
}

/// The class of advanced-feature schedule failure found in `tests/crucible/default.nix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvancedFeatureScheduleFailureKind {
    /// A scheduled ADV task is absent from the dependency ladder.
    UnknownTask,
    /// A scheduled ADV task appears in more than one check.
    DuplicateTaskSchedule,
    /// A scheduled ADV check does not expose a check attr path.
    MissingAttrPath,
    /// A scheduled ADV check is not wrapped in an advance guard.
    MissingAdvanceGuard,
    /// A scheduled ADV check does not depend on a required green lower gate.
    MissingGateDependency,
    /// A scheduled ADV check appears before its prerequisite task has a check.
    MissingTaskSchedule,
    /// A scheduled ADV check does not depend on a prerequisite task check.
    MissingTaskDependency,
    /// A Phase 6 check import does not declare task IDs at the scheduling site.
    MissingExplicitTaskIds,
}

/// A failed advanced-feature schedule rule from the actual Nix check graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvancedFeatureScheduleFailure {
    /// The scheduled task whose dependency rule failed.
    pub task_id: String,
    /// The class of schedule failure.
    pub kind: AdvancedFeatureScheduleFailureKind,
    /// The scheduled check attr path, when it was discoverable.
    pub attr_path: Option<String>,
    /// Required gate attr path or Nix dependency reference, when applicable.
    pub dependency: Option<String>,
    /// Required ADV task, when the failure concerns task order.
    pub prerequisite_task_id: Option<String>,
}

/// Layer-gate precedence obligations that make HARN-3 executable.
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
        rationale: "control-plane checks cannot stand in for mock e2e determinism",
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

/// ADV checklist ordering required by RFC-0010 file 22 section 22.1.
pub const ADVANCED_FEATURE_TASK_ORDER: &[AdvancedFeatureTaskOrder] = &[
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-1",
        rung: AdvancedFeatureRung::ExactDeterminism,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: ADVANCED_LADDER_FOUNDATION,
        required_task_ids: &[],
        rationale: "the ladder check itself is sequenced after deterministic replay and control are green",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-2",
        rung: AdvancedFeatureRung::ExactDeterminism,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: CONTROL_PLANE_FOUNDATION,
        required_task_ids: &["T-ADV-1"],
        rationale: "exploration lifecycle controls must ride the session actor",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-5",
        rung: AdvancedFeatureRung::SaveRestore,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-1"],
        rationale: "restore strategies require the replay-oracle foundation",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-6",
        rung: AdvancedFeatureRung::SaveRestore,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-5"],
        rationale: "savepoints degrade to thin replay only after restore is oracle checked",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-3",
        rung: AdvancedFeatureRung::Fork,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-6"],
        rationale: "fork is instantiate from an oracle-validated checkpoint",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-4",
        rung: AdvancedFeatureRung::Fork,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-3"],
        rationale: "fork validation reuses the save/restore replay oracle",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-7",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-4"],
        rationale: "search is systematic fork from validated frontier nodes",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-8",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-7"],
        rationale: "search strategies order already-valid frontier expansion",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-9",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-8"],
        rationale: "reductions prune search children only after search ordering exists",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-20",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-9"],
        rationale: "preemption branching is a search dimension",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-21",
        rung: AdvancedFeatureRung::Search,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-20"],
        rationale: "app-controlled randomness is a search dimension",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-10",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: EXACT_DETERMINISM_FOUNDATION,
        required_task_ids: &["T-ADV-7"],
        rationale: "coverage is black-box feedback consumed by search and fuzzing",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-11",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: EXACT_DETERMINISM_FOUNDATION,
        required_task_ids: &["T-ADV-10"],
        rationale: "coverage enters the observational event log after extraction exists",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-17",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-8", "T-ADV-11"],
        rationale: "guidance signals compose deterministic search with coverage feedback",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-18",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-17"],
        rationale: "adaptive strategy selection wraps guidance without changing replay",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-19",
        rung: AdvancedFeatureRung::CoverageFeedback,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-18"],
        rationale: "ordering determinism lint protects guided strategy selection",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-12",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-11", "T-ADV-19", "T-ADV-21"],
        rationale: "coverage-guided fuzzing requires search, coverage, and deterministic guidance",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-13",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-12"],
        rationale: "corpus management stores coverage-driven fuzz findings",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-14",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-13"],
        rationale: "reproduction artifacts are emitted from search/fuzz findings",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-15",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-14"],
        rationale: "minimization shrinks self-contained findings",
    },
    AdvancedFeatureTaskOrder {
        task_id: "T-ADV-16",
        rung: AdvancedFeatureRung::Fuzzing,
        phase: PhasePlanPhase::Phase6,
        required_green_attr_paths: REPLAY_ORACLE_FOUNDATION,
        required_task_ids: &["T-ADV-15"],
        rationale: "the unifying-view test requires all advanced operations",
    },
];

/// The full ordered phase-gate plan from RFC-0010 file 24 section 13.
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
        "L0 core",
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
        "scheduler actor liveness",
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

/// Returns HARN-3 lower-layer-before-higher-layer ordering failures.
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

/// Returns every ADV checklist task in dependency order.
#[must_use]
pub fn advanced_feature_task_order() -> &'static [AdvancedFeatureTaskOrder] {
    ADVANCED_FEATURE_TASK_ORDER
}

/// Returns ADV dependency-ladder failures against the phase-gate plan.
#[must_use]
pub fn advanced_feature_ladder_failures(
    plan: &[PhaseGateOccurrence],
    tasks: &[AdvancedFeatureTaskOrder],
) -> Vec<AdvancedFeatureLadderFailure> {
    let mut failures = Vec::new();
    let ordered_gate_attrs = plan
        .iter()
        .map(|occurrence| occurrence.attr_path)
        .collect::<Vec<_>>();

    for (task_index, task) in tasks.iter().enumerate() {
        for &attr_path in task.required_green_attr_paths {
            let Some(gate_index) = ordered_gate_attrs
                .iter()
                .position(|candidate| *candidate == attr_path)
            else {
                failures.push(AdvancedFeatureLadderFailure {
                    task_id: task.task_id,
                    rung: task.rung,
                    attr_path: Some(attr_path),
                    prerequisite_task_id: None,
                    rationale: task.rationale,
                });
                continue;
            };
            if plan[gate_index].phase >= task.phase {
                failures.push(AdvancedFeatureLadderFailure {
                    task_id: task.task_id,
                    rung: task.rung,
                    attr_path: Some(attr_path),
                    prerequisite_task_id: None,
                    rationale: task.rationale,
                });
            }
        }

        for &prerequisite_task_id in task.required_task_ids {
            let prerequisite_index = tasks
                .iter()
                .position(|candidate| candidate.task_id == prerequisite_task_id);
            if !matches!(prerequisite_index, Some(index) if index < task_index) {
                failures.push(AdvancedFeatureLadderFailure {
                    task_id: task.task_id,
                    rung: task.rung,
                    attr_path: None,
                    prerequisite_task_id: Some(prerequisite_task_id),
                    rationale: task.rationale,
                });
            }
        }

        if task_index > 0 {
            let previous = tasks[task_index - 1];
            if task.rung < previous.rung {
                failures.push(AdvancedFeatureLadderFailure {
                    task_id: task.task_id,
                    rung: task.rung,
                    attr_path: None,
                    prerequisite_task_id: Some(previous.task_id),
                    rationale: task.rationale,
                });
            }
        }
    }

    failures
}

/// Returns failures where the actual Nix check graph schedules ADV work out of order.
/// It ties `default_checks` to real wiring so ADV work cannot bypass prerequisite tasks and gates.
#[must_use]
pub fn advanced_feature_schedule_failures(
    default_checks: &str,
    tasks: &[AdvancedFeatureTaskOrder],
) -> Vec<AdvancedFeatureScheduleFailure> {
    let task_map = tasks
        .iter()
        .map(|task| (task.task_id, *task))
        .collect::<BTreeMap<_, _>>();
    let scheduled_checks = scheduled_advanced_feature_checks(default_checks);
    let mut scheduled_by_task = BTreeMap::new();
    let mut failures = phase6_import_task_id_failures(default_checks);

    for scheduled in &scheduled_checks {
        for task_id in &scheduled.task_ids {
            if !task_map.contains_key(task_id.as_str()) {
                failures.push(AdvancedFeatureScheduleFailure {
                    task_id: task_id.clone(),
                    kind: AdvancedFeatureScheduleFailureKind::UnknownTask,
                    attr_path: scheduled.attr_path.clone(),
                    dependency: None,
                    prerequisite_task_id: None,
                });
                continue;
            }

            if let Some(previous) = scheduled_by_task.insert(task_id.clone(), scheduled) {
                failures.push(AdvancedFeatureScheduleFailure {
                    task_id: task_id.clone(),
                    kind: AdvancedFeatureScheduleFailureKind::DuplicateTaskSchedule,
                    attr_path: scheduled
                        .attr_path
                        .clone()
                        .or_else(|| previous.attr_path.clone()),
                    dependency: None,
                    prerequisite_task_id: None,
                });
            }
        }
    }

    for scheduled in &scheduled_checks {
        for task_id in &scheduled.task_ids {
            let Some(task) = task_map.get(task_id.as_str()) else {
                continue;
            };

            if scheduled.attr_path.is_none() {
                failures.push(AdvancedFeatureScheduleFailure {
                    task_id: task_id.clone(),
                    kind: AdvancedFeatureScheduleFailureKind::MissingAttrPath,
                    attr_path: None,
                    dependency: None,
                    prerequisite_task_id: None,
                });
            }

            if !scheduled.advance_guarded {
                failures.push(AdvancedFeatureScheduleFailure {
                    task_id: task_id.clone(),
                    kind: AdvancedFeatureScheduleFailureKind::MissingAdvanceGuard,
                    attr_path: scheduled.attr_path.clone(),
                    dependency: None,
                    prerequisite_task_id: None,
                });
            }

            for &required_attr_path in task.required_green_attr_paths {
                let dependency = attr_path_to_default_nix_reference(required_attr_path);
                if !scheduled
                    .dependencies
                    .iter()
                    .any(|candidate| candidate == &dependency)
                {
                    failures.push(AdvancedFeatureScheduleFailure {
                        task_id: task_id.clone(),
                        kind: AdvancedFeatureScheduleFailureKind::MissingGateDependency,
                        attr_path: scheduled.attr_path.clone(),
                        dependency: Some(dependency),
                        prerequisite_task_id: None,
                    });
                }
            }

            for &required_task_id in task.required_task_ids {
                let Some(prerequisite) = scheduled_by_task.get(required_task_id) else {
                    failures.push(AdvancedFeatureScheduleFailure {
                        task_id: task_id.clone(),
                        kind: AdvancedFeatureScheduleFailureKind::MissingTaskSchedule,
                        attr_path: scheduled.attr_path.clone(),
                        dependency: None,
                        prerequisite_task_id: Some(required_task_id.to_string()),
                    });
                    continue;
                };

                let Some(prerequisite_attr_path) = prerequisite.attr_path.as_deref() else {
                    failures.push(AdvancedFeatureScheduleFailure {
                        task_id: task_id.clone(),
                        kind: AdvancedFeatureScheduleFailureKind::MissingTaskSchedule,
                        attr_path: scheduled.attr_path.clone(),
                        dependency: None,
                        prerequisite_task_id: Some(required_task_id.to_string()),
                    });
                    continue;
                };

                let dependency = attr_path_to_default_nix_reference(prerequisite_attr_path);
                if !scheduled
                    .dependencies
                    .iter()
                    .any(|candidate| candidate == &dependency)
                {
                    failures.push(AdvancedFeatureScheduleFailure {
                        task_id: task_id.clone(),
                        kind: AdvancedFeatureScheduleFailureKind::MissingTaskDependency,
                        attr_path: scheduled.attr_path.clone(),
                        dependency: Some(dependency),
                        prerequisite_task_id: Some(required_task_id.to_string()),
                    });
                }
            }
        }
    }

    failures
}

#[derive(Clone, Debug)]
struct ScheduledAdvancedFeatureCheck {
    attr_path: Option<String>,
    task_ids: Vec<String>,
    dependencies: BTreeSet<String>,
    advance_guarded: bool,
}

fn scheduled_advanced_feature_checks(default_checks: &str) -> Vec<ScheduledAdvancedFeatureCheck> {
    let mut checks = Vec::new();
    let mut search_from = 0;
    while let Some(relative_start) = default_checks[search_from..].find("taskIds = [") {
        let task_ids_start = search_from + relative_start;
        let list_start = task_ids_start + "taskIds = [".len();
        let Some(relative_end) = default_checks[list_start..].find("];") else {
            break;
        };
        let list_end = list_start + relative_end;
        let task_ids = quoted_strings(&default_checks[list_start..list_end])
            .into_iter()
            .filter(|task_id| task_id.starts_with("T-ADV-"))
            .collect::<Vec<_>>();
        search_from = list_end + "];".len();

        if task_ids.is_empty() {
            continue;
        }

        let advance_guard_block =
            enclosing_advance_guard_block(default_checks, task_ids_start).map(str::to_owned);
        let fallback_start = task_ids_start.saturating_sub(1024);
        let fallback_end = default_checks.len().min(search_from + 1024);
        let fallback_block = &default_checks[fallback_start..fallback_end];
        let block = advance_guard_block.as_deref().unwrap_or(fallback_block);

        checks.push(ScheduledAdvancedFeatureCheck {
            attr_path: attr_path_from_block(block),
            task_ids,
            dependencies: if advance_guard_block.is_some() {
                top_level_dependency_tokens(block)
            } else {
                dependency_tokens(block)
            },
            advance_guarded: advance_guard_block.is_some(),
        });
    }

    checks
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

fn dependency_tokens(block: &str) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    let mut search_from = 0;

    while let Some(relative_start) = block[search_from..].find("dependencies = [") {
        let list_start = search_from + relative_start + "dependencies = [".len();
        let Some(relative_end) = block[list_start..].find("];") else {
            break;
        };
        let list_end = list_start + relative_end;
        dependencies.extend(
            block[list_start..list_end]
                .split_whitespace()
                .filter(|token| !token.is_empty())
                .map(|token| token.trim_matches(|character| character == '(' || character == ')'))
                .map(str::to_string),
        );
        search_from = list_end + "];".len();
    }

    dependencies
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

fn quoted_strings(text: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut remaining = text;
    while let Some(start) = remaining.find('"') {
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find('"') else {
            break;
        };
        strings.push(after_start[..end].to_string());
        remaining = &after_start[end + 1..];
    }

    strings
}

fn phase6_import_task_id_failures(default_checks: &str) -> Vec<AdvancedFeatureScheduleFailure> {
    let mut failures = Vec::new();
    let mut search_from = 0;
    let import_marker = "import ./phase6-";

    while let Some(relative_start) = default_checks[search_from..].find(import_marker) {
        let import_start = search_from + relative_start;
        search_from = import_start + import_marker.len();
        let Some(relative_open_brace) = default_checks[import_start..].find('{') else {
            continue;
        };
        let open_brace = import_start + relative_open_brace;
        let Some(end) = matching_brace_end(default_checks, open_brace) else {
            continue;
        };
        let import_args = &default_checks[open_brace..=end];

        if !import_args.contains("taskIds = [") {
            failures.push(AdvancedFeatureScheduleFailure {
                task_id: "T-ADV-*".to_string(),
                kind: AdvancedFeatureScheduleFailureKind::MissingExplicitTaskIds,
                attr_path: attr_path_from_block(import_args),
                dependency: None,
                prerequisite_task_id: None,
            });
        }
    }

    failures
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
