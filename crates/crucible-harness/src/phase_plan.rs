//! Phase-gate ordering for RFC-0010.
//!
//! The canonical gate catalog records each gate name once. The phase plan records
//! every gate occurrence, including repeated gates such as `gate:replay-oracle`
//! and `gate:e2e-determinism`.

use std::collections::BTreeSet;

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
    /// No Phase 7 terminal `gate:e2e-determinism` occurrence exists.
    MissingTerminalE2eDeterminism,
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
        true,
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
    let mut has_terminal_e2e = false;
    let mut last_phase = None;

    for occurrence in plan {
        if let Some(previous) = last_phase {
            if occurrence.phase < previous {
                failures.push(failure_for(
                    PhasePlanInvariantFailureKind::OutOfOrderPhase,
                    occurrence,
                ));
            }
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
                && occurrence.gate_name == "gate:e2e-determinism"
            {
                has_terminal_e2e = true;
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

    if !has_terminal_e2e {
        failures.push(PhasePlanInvariantFailure {
            kind: PhasePlanInvariantFailureKind::MissingTerminalE2eDeterminism,
            phase: Some(PhasePlanPhase::Phase7),
            gate_name: Some("gate:e2e-determinism"),
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
