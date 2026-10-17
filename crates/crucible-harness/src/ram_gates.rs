//! Records aggregate RAM qualification contracts separately from components.
//!
//! Format and controlled model tests provide useful component evidence. They do
//! not establish deployed host paging, guest transparency, or campaign capacity.
//! A catalog entry becomes implemented only when its required aggregate check
//! runs its required positive and adversarial cases in the declared environment.

use crate::{GatePhase, GateSpec, GateStatus};

/// The execution environment required by an aggregate RAM gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamEvidenceClass {
    /// Independent canonical encoding and cryptographic vectors.
    Format,
    /// Deterministic tests of a controlled logical state machine.
    Model,
    /// A deployed QEMU process, real host memory, and unmodified guest execution.
    LiveVm,
    /// Installed product processes and their authenticated continuation artifacts.
    Packaged,
    /// Reproducible completed campaigns with measured resource and cost evidence.
    Performance,
}

/// A RAM qualification gate and its required aggregate execution environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamGateSpec {
    /// The normative gate identity, owner, and implementation status.
    pub gate: GateSpec,
    /// The required environment; component tests cannot substitute for it.
    pub evidence_class: RamEvidenceClass,
}

const fn declared(
    name: &'static str,
    owner: &'static str,
    evidence_class: RamEvidenceClass,
) -> RamGateSpec {
    RamGateSpec {
        gate: GateSpec {
            name,
            phase: GatePhase::Always,
            owner,
            status: GateStatus::CatalogOnly,
        },
        evidence_class,
    }
}

/// Aggregate qualification gates required by the paged RAM contract.
///
/// Catalog-only entries are pending contracts, not passing qualification or
/// advertised runtime capabilities. The independent component targets appear
/// in [`crate::gate_targets::ram_gate_targets`].
pub const RAM_GATES: &[RamGateSpec] = &[
    declared("gate:ram-format", "crucible-ram", RamEvidenceClass::Format),
    declared(
        "gate:ram-merkle-oracle",
        "crucible-ram",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-dirty-epochs",
        "crucible-qemu",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-paging",
        "crucible-qemu-plugin",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-runtime-policy",
        "crucible-qemu",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-supervision",
        "crucible-qemu",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-guest-transparency",
        "crucible-qemu",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-determinism",
        "crucible-harness",
        RamEvidenceClass::Packaged,
    ),
    declared(
        "gate:ram-continuation",
        "crucible-qemu",
        RamEvidenceClass::Packaged,
    ),
    declared(
        "gate:ram-store-transfer",
        "crucible-cas",
        RamEvidenceClass::Packaged,
    ),
    declared(
        "gate:ram-cutover",
        "crucible-harness",
        RamEvidenceClass::Packaged,
    ),
    declared(
        "gate:ram-fault-progress",
        "crucible-qemu-plugin",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-policy-history",
        "crucible-qemu",
        RamEvidenceClass::Packaged,
    ),
    declared(
        "gate:ram-fork-residency",
        "crucible-qemu",
        RamEvidenceClass::LiveVm,
    ),
    declared(
        "gate:ram-performance",
        "crucible-harness",
        RamEvidenceClass::Performance,
    ),
];

/// Returns the complete aggregate RAM qualification catalog.
#[must_use]
pub fn ram_gates() -> &'static [RamGateSpec] {
    RAM_GATES
}

/// Finds an aggregate RAM gate by its normative name.
#[must_use]
pub fn find_ram_gate(name: &str) -> Option<&'static RamGateSpec> {
    RAM_GATES.iter().find(|spec| spec.gate.name == name)
}
