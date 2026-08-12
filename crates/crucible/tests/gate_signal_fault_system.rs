//! Terminal closed-registry checks for the signal-driven fault system.
//!
//! Live production-backend proofs are composed by the hermetic Phase-7 Nix
//! gate. This addressable Cargo target owns the platform-independent portion:
//! closed vocabulary integrity, specification-only exclusions, and exact user
//! reference coverage.

#[path = "fault_reference.rs"]
mod fault_reference;

use std::collections::BTreeSet;

use crucible::model::{
    EffectKind, FaultAdapter, FaultTargetKind, PureSignalOperator, SignalSourceKind,
    StatefulSignalOperator,
};

#[test]
fn gate_signal_fault_system_has_closed_executable_registries() {
    let effects = EffectKind::all();
    assert_eq!(effects.len(), 71, "the reviewed effect ledger changed");
    assert_eq!(
        effects
            .iter()
            .map(|kind| kind.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        effects.len(),
        "effect keys must be unique"
    );
    for adapter in [
        FaultAdapter::Network,
        FaultAdapter::Storage,
        FaultAdapter::Node,
    ] {
        assert!(
            effects
                .iter()
                .any(|kind| kind.descriptor().adapter == adapter),
            "every production adapter must own at least one effect"
        );
    }

    for values in [
        SignalSourceKind::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        PureSignalOperator::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        StatefulSignalOperator::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        FaultTargetKind::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
    ] {
        assert_eq!(
            values.iter().copied().collect::<BTreeSet<_>>().len(),
            values.len(),
            "every accepted registry value must have one canonical spelling"
        );
        assert!(
            values
                .iter()
                .all(|value| !value.starts_with("sensor") && !value.starts_with("power.")),
            "specification-only device domains must not enter executable registries"
        );
    }
}
