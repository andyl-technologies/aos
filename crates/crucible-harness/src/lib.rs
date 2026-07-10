//! `crucible-harness` owns cross-crate determinism gate scaffolding.
//!
//! Spec index: RFC-0010 files 24, 27.
//!
//! This test-only workspace member will host the fingerprint comparator,
//! divergence bisector, replay-oracle checker, ABI golden-vector runner, and
//! adversarial-host driver, and mock e2e gate driver described by RFC-0010
//! files 24 and 27.
//!
//! The crate also exposes the canonical gate catalog used by the RFC lint and
//! the red placeholder targets that make early phase wiring visible before the
//! owning subsystems turn the gates green. It is not an L0-L4 runtime layer and
//! is not a shipped crate.
//!
//! Module map: [`abi`] compares golden vectors, [`adversarial`] compares
//! hostile-profile runs, [`divergence`] localizes mismatches, [`e2e`] runs the
//! mock end-to-end determinism gate, [`fingerprint`] compares fingerprint
//! streams, [`gate_targets`] indexes Cargo gate targets, [`perf`] owns the
//! cost-model perf-bench gate substrate, [`phase_plan`] records the ordered gate
//! occurrences, [`replay_oracle`] compares replay hashes, [`reproduction`] owns
//! the versioned reproduction artifact format, and [`spec_index`] owns the
//! crate-to-RFC map.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod abi;
pub mod adversarial;
pub mod divergence;
pub mod e2e;
pub mod fingerprint;
pub mod gate_targets;
pub mod perf;
pub mod phase_plan;
pub mod replay_oracle;
pub mod reproduction;
pub mod spec_index;

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
    /// The gate guards Phase 3 scheduling and cross-node determinism work.
    Phase3,
    /// The gate guards Phase 4 full engine work.
    Phase4,
    /// The gate guards Phase 5 control-plane work.
    Phase5,
    /// The gate guards Phase 6 exploration work.
    Phase6,
    /// The gate guards Phase 7 packaging, performance, and acceptance work.
    Phase7,
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
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:single-vm-fingerprint",
        phase: GatePhase::Phase1,
        owner: "crucible-qemu",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:layer1-injection",
        phase: GatePhase::Phase2,
        owner: "crucible-device",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:content-address",
        phase: GatePhase::Phase1,
        owner: "crucible",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:replay-oracle",
        phase: GatePhase::Phase1,
        owner: "crucible",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:divergence-bisect",
        phase: GatePhase::Phase1,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:scheduler-liveness",
        phase: GatePhase::Phase3,
        owner: "crucible",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:control-responsive",
        phase: GatePhase::Phase5,
        owner: "crucible-session",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:any-guest",
        phase: GatePhase::Phase2,
        owner: "crucible-qemu",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:qemu-inert",
        phase: GatePhase::Phase2,
        owner: "crucible-qemu",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:abi-conformance",
        phase: GatePhase::Phase2,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:patch-microtests",
        phase: GatePhase::Phase2,
        owner: "crucible-qemu-plugin",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:adversarial-determinism",
        phase: GatePhase::Phase3,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:e2e-determinism",
        phase: GatePhase::Phase4,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:basic-block-coverage",
        phase: GatePhase::Phase6,
        owner: "crucible-qemu-plugin",
        status: GateStatus::RedPlaceholder,
    },
    GateSpec {
        name: "gate:perf-bench",
        phase: GatePhase::Phase7,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:fleet-equivalence",
        phase: GatePhase::Phase7,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
    },
    GateSpec {
        name: "gate:campaign-continuity",
        phase: GatePhase::Phase7,
        owner: "crucible-harness",
        status: GateStatus::Implemented,
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
