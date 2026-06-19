//! `crucible-harness` owns cross-crate determinism gate scaffolding.
//!
//! This test-only workspace member will host the fingerprint comparator,
//! divergence bisector, replay-oracle checker, ABI golden-vector runner, and
//! adversarial-host driver described by RFC-0010 files 24 and 27.
//!
//! The crate also exposes the canonical gate catalog used by the RFC lint and
//! the red placeholder targets that make early phase wiring visible before the
//! owning subsystems turn the gates green. It is not an L0-L4 runtime layer and
//! is not a shipped crate.

#![forbid(unsafe_code)]

pub mod abi;
pub mod adversarial;
pub mod divergence;
pub mod fingerprint;
pub mod replay_oracle;

/// A cross-crate harness component hosted by `crucible-harness`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HarnessComponentSpec {
    /// Stable component name used by the crate-structure lint.
    pub name: &'static str,
    /// Public module that hosts the component.
    pub module: &'static str,
    /// Canonical gate primarily served by this component.
    pub gate: &'static str,
}

/// The cross-crate harness components required by RFC-0010 file 27.
pub const HARNESS_COMPONENTS: &[HarnessComponentSpec] = &[
    HarnessComponentSpec {
        name: "fingerprint comparator",
        module: "fingerprint",
        gate: "gate:single-vm-fingerprint",
    },
    HarnessComponentSpec {
        name: "divergence bisector",
        module: "divergence",
        gate: "gate:divergence-bisect",
    },
    HarnessComponentSpec {
        name: "replay-oracle checker",
        module: "replay_oracle",
        gate: "gate:replay-oracle",
    },
    HarnessComponentSpec {
        name: "ABI golden-vector runner",
        module: "abi",
        gate: "gate:abi-conformance",
    },
    HarnessComponentSpec {
        name: "adversarial driver",
        module: "adversarial",
        gate: "gate:adversarial-determinism",
    },
];

/// Returns every cross-crate harness component in RFC order.
#[must_use]
pub fn harness_components() -> &'static [HarnessComponentSpec] {
    HARNESS_COMPONENTS
}

/// A canonical determinism gate from RFC-0010 section 24.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateSpec {
    /// The normative gate name, including the `gate:` prefix.
    pub name: &'static str,
    /// The phase where the gate first blocks forward progress.
    pub phase: GatePhase,
    /// The workspace area that owns the gate implementation.
    pub owner: &'static str,
    /// The implementation status of the local gate target.
    pub status: GateStatus,
}

/// A phase boundary guarded by a determinism gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatePhase {
    /// The gate runs on every change before phase-specific gates.
    Always,
    /// The gate guards Phase 1 foundation work.
    Phase1,
    /// The gate guards Phase 2 VM/backend work.
    Phase2,
    /// The gate guards Phase 3 temporal-graph, scheduler, or control-plane work.
    Phase3,
    /// The gate guards Phase 4 adversarial-host work.
    Phase4,
    /// The gate guards Phase 5 final acceptance.
    Phase5,
}

/// The current local implementation status for a gate target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateStatus {
    /// The gate is listed in the canonical catalog but has no local target yet.
    CatalogOnly,
    /// The gate has a wired target that intentionally fails until implemented.
    RedPlaceholder,
    /// The gate has a local target that performs its initial automated check.
    Implemented,
}

/// The canonical RFC-0010 gate catalog.
pub const CANONICAL_GATES: &[GateSpec] = &[
    GateSpec {
        name: "gate:harness-lint",
        phase: GatePhase::Always,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:layer0-determinism",
        phase: GatePhase::Phase1,
        owner: "crucible-sim",
        status: GateStatus::RedPlaceholder,
    },
    GateSpec {
        name: "gate:single-vm-fingerprint",
        phase: GatePhase::Phase2,
        owner: "crucible-qemu",
        status: GateStatus::RedPlaceholder,
    },
    GateSpec {
        name: "gate:layer1-injection",
        phase: GatePhase::Phase1,
        owner: "crucible-device",
        status: GateStatus::RedPlaceholder,
    },
    GateSpec {
        name: "gate:content-address",
        phase: GatePhase::Phase1,
        owner: "crucible",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:replay-oracle",
        phase: GatePhase::Phase3,
        owner: "crucible",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:divergence-bisect",
        phase: GatePhase::Phase1,
        owner: "crucible-harness",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:scheduler-liveness",
        phase: GatePhase::Phase3,
        owner: "crucible",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:control-responsive",
        phase: GatePhase::Phase3,
        owner: "crucible-session",
        status: GateStatus::RedPlaceholder,
    },
    GateSpec {
        name: "gate:any-guest",
        phase: GatePhase::Phase2,
        owner: "crucible-qemu",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:qemu-inert",
        phase: GatePhase::Phase2,
        owner: "crucible-qemu",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:abi-conformance",
        phase: GatePhase::Phase1,
        owner: "crucible-harness",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:patch-microtests",
        phase: GatePhase::Phase2,
        owner: "crucible-qemu-plugin",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:adversarial-determinism",
        phase: GatePhase::Phase4,
        owner: "crucible-harness",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:e2e-determinism",
        phase: GatePhase::Phase5,
        owner: "crucible-harness",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:perf-bench",
        phase: GatePhase::Phase2,
        owner: "crucible-harness",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:fleet-equivalence",
        phase: GatePhase::Phase3,
        owner: "crucible-harness",
        status: GateStatus::CatalogOnly,
    },
    GateSpec {
        name: "gate:campaign-continuity",
        phase: GatePhase::Phase3,
        owner: "crucible-harness",
        status: GateStatus::CatalogOnly,
    },
];

/// Returns every canonical gate in RFC order.
#[must_use]
pub fn canonical_gates() -> &'static [GateSpec] {
    CANONICAL_GATES
}

/// Finds a canonical gate by its normative name.
#[must_use]
pub fn find_gate(name: &str) -> Option<&'static GateSpec> {
    CANONICAL_GATES.iter().find(|gate| gate.name == name)
}
