//! Proves the campaign mode matrix inventory equals the current phase plan.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crucible_harness::gate_targets::GATE_TARGETS;
use crucible_harness::phase_plan::{PHASE_GATE_ORDER, PhaseGateKind};
use serde::Deserialize;

const INVENTORY: &str = include_str!("../../../tests/crucible/campaign-gate-matrix-inventory.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: String,
    members: Vec<GateClass>,
    authorities: Vec<GateAuthority>,
    targets: Vec<GateTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateClass {
    class: String,
    gates: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateTarget {
    gate: String,
    package: String,
    test_target: String,
    features: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateAuthority {
    gate: String,
    class: String,
    attr_path: String,
    execution_family: String,
}

#[test]
fn matrix_inventory_covers_each_current_catalog_gate_exactly_once() -> Result<(), Box<dyn Error>> {
    let inventory: Inventory = toml::from_str(INVENTORY)?;
    assert_eq!(
        inventory.schema,
        "aos.crucible.campaign-gate-matrix-inventory.v2"
    );

    let expected_classes = BTreeSet::from([
        "abi",
        "determinism",
        "license",
        "package",
        "qemu",
        "replay",
        "signal-fault",
    ]);
    let actual_classes = inventory
        .members
        .iter()
        .map(|member| member.class.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_classes, expected_classes);
    assert_eq!(inventory.members.len(), expected_classes.len());

    let expected_gates = PHASE_GATE_ORDER
        .iter()
        .filter(|occurrence| occurrence.kind == PhaseGateKind::CatalogGate)
        .map(|occurrence| occurrence.gate_name)
        .collect::<BTreeSet<_>>();
    let listed = inventory
        .members
        .iter()
        .flat_map(|member| member.gates.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let actual_gates = listed.iter().copied().collect::<BTreeSet<_>>();

    assert_eq!(
        listed.len(),
        actual_gates.len(),
        "duplicate gate inventory row"
    );
    assert_eq!(actual_gates, expected_gates);
    assert!(
        inventory
            .members
            .iter()
            .all(|member| !member.gates.is_empty())
    );

    let gate_classes = inventory
        .members
        .iter()
        .flat_map(|member| {
            member
                .gates
                .iter()
                .map(|gate| (gate.as_str(), member.class.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    let expected_authorities = PHASE_GATE_ORDER
        .iter()
        .filter(|occurrence| occurrence.kind == PhaseGateKind::CatalogGate)
        .map(|occurrence| (occurrence.gate_name, occurrence.attr_path))
        .collect::<BTreeMap<_, _>>();
    let actual_authorities = inventory
        .authorities
        .iter()
        .map(|authority| (authority.gate.as_str(), authority.attr_path.as_str()))
        .collect::<BTreeMap<_, _>>();
    let authority_names = inventory
        .authorities
        .iter()
        .map(|authority| authority.gate.as_str())
        .collect::<BTreeSet<_>>();
    let authority_paths = inventory
        .authorities
        .iter()
        .map(|authority| authority.attr_path.as_str())
        .collect::<BTreeSet<_>>();
    let execution_families = BTreeSet::from([
        "fleet-runtime",
        "native-runtime",
        "qemu-runtime",
        "static-closure",
    ]);

    assert_eq!(inventory.authorities.len(), authority_names.len());
    assert_eq!(authority_names, expected_gates);
    assert_eq!(actual_authorities, expected_authorities);
    assert_eq!(authority_paths.len(), inventory.authorities.len());
    for authority in &inventory.authorities {
        assert_eq!(
            gate_classes.get(authority.gate.as_str()),
            Some(&authority.class.as_str())
        );
        assert!(execution_families.contains(authority.execution_family.as_str()));
    }

    let expected_targets = GATE_TARGETS
        .iter()
        .filter(|target| expected_gates.contains(target.gate))
        .map(|target| {
            (
                target.gate,
                target.package,
                target.test_target,
                target.required_features.to_vec(),
            )
        })
        .collect::<BTreeSet<_>>();
    let actual_targets = inventory
        .targets
        .iter()
        .map(|target| {
            (
                target.gate.as_str(),
                target.package.as_str(),
                target.test_target.as_str(),
                target
                    .features
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_targets, expected_targets);
    assert_eq!(inventory.targets.len(), actual_targets.len());

    Ok(())
}
