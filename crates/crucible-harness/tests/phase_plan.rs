//! Checks that the RFC-0010 phase-gate plan is executable ordering data.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::phase_plan::{
    LAYER_GATE_PRECEDENCES, PhaseGateKind, PhaseGateOccurrence, PhasePlanInvariantFailureKind,
    PhasePlanPhase, SIM_DOUBLE_AVAILABLE_PHASE, green_before_advance_failures,
    layer_gate_precedence_failures, phase_gate_order, phase_plan_invariant_failures,
    terminal_acceptance_gate,
};

#[test]
fn phase_gate_plan_matches_rfc_section_13_and_nix_wiring() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let rfc =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/24-determinism-harness-testing.md"))?;
    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;

    let actual: Vec<(&str, &str)> = phase_gate_order()
        .iter()
        .map(|occurrence| (occurrence.phase.label(), occurrence.gate_name))
        .collect();
    let expected = rfc_section_13_phase_order(&rfc)?;
    assert_eq!(actual, expected);

    let mut missing_attrs = Vec::new();
    for occurrence in phase_gate_order() {
        let needle = format!("attrPath = \"{}\";", occurrence.attr_path);
        if !default_checks.contains(&needle) {
            missing_attrs.push(format!(
                "{} {} is missing Nix attr path {}",
                occurrence.phase.label(),
                occurrence.gate_name,
                occurrence.attr_path
            ));
        }
    }
    assert!(
        missing_attrs.is_empty(),
        "phase-plan Nix wiring drift:\n{}",
        missing_attrs.join("\n")
    );

    Ok(())
}

#[test]
fn canonical_phase_plan_satisfies_ordering_invariants() {
    let failures = phase_plan_invariant_failures(phase_gate_order());
    assert!(
        failures.is_empty(),
        "canonical phase-plan invariant drift:\n{failures:#?}"
    );

    let layer_failures = layer_gate_precedence_failures(phase_gate_order(), LAYER_GATE_PRECEDENCES);
    assert!(
        layer_failures.is_empty(),
        "canonical layer-gate ordering drift:\n{layer_failures:#?}"
    );
}

#[test]
fn green_before_advance_requires_every_prior_phase_gate() -> Result<(), Box<dyn Error>> {
    let phase0_green = green_attr_paths_before(PhasePlanPhase::Phase1);
    assert!(green_before_advance_failures(&phase0_green, PhasePlanPhase::Phase1).is_empty());

    let mut phase2_green = green_attr_paths_before(PhasePlanPhase::Phase2);
    phase2_green.retain(|attr_path| {
        *attr_path != "checks.crucible.phase1.gates.replayOracle"
            && *attr_path != "checks.crucible.phase2.gates.abiConformance"
    });

    let missing: Vec<&str> = green_before_advance_failures(&phase2_green, PhasePlanPhase::Phase2)
        .iter()
        .map(|occurrence| occurrence.attr_path)
        .collect();
    assert_eq!(missing, vec!["checks.crucible.phase1.gates.replayOracle"]);

    let phase2_complete = green_attr_paths_before(PhasePlanPhase::Phase2);
    assert!(green_before_advance_failures(&phase2_complete, PhasePlanPhase::Phase2).is_empty());

    let phase4_incomplete = green_attr_paths_before(PhasePlanPhase::Phase4);
    let missing_for_phase5: BTreeSet<&str> =
        green_before_advance_failures(&phase4_incomplete, PhasePlanPhase::Phase5)
            .iter()
            .map(|occurrence| occurrence.attr_path)
            .collect();
    assert_eq!(
        missing_for_phase5,
        BTreeSet::from([
            "checks.crucible.phase4.gates.replayOracle",
            "checks.crucible.phase4.gates.e2eDeterminism",
        ])
    );

    let terminal = terminal_acceptance_gate().ok_or("terminal acceptance gate is missing")?;
    assert_eq!(
        terminal.attr_path,
        "checks.crucible.phase7.gates.e2eDeterminism"
    );

    Ok(())
}

#[test]
fn terminal_e2e_occurrence_remains_in_phase7_acceptance_set() -> Result<(), Box<dyn Error>> {
    let terminal = terminal_acceptance_gate().ok_or("terminal acceptance gate is missing")?;
    assert_eq!(terminal.phase, PhasePlanPhase::Phase7);
    assert_eq!(terminal.kind, PhaseGateKind::CatalogGate);
    assert_eq!(terminal.gate_name, "gate:e2e-determinism");

    let e2e_phases: Vec<PhasePlanPhase> = phase_gate_order()
        .iter()
        .filter_map(|occurrence| {
            if occurrence.gate_name == "gate:e2e-determinism" {
                Some(occurrence.phase)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        e2e_phases,
        vec![PhasePlanPhase::Phase4, PhasePlanPhase::Phase7]
    );

    Ok(())
}

#[test]
fn sim_double_is_available_before_dependent_gate_occurrences() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let sim_double_check = fs::read_to_string(root.join("tests/crucible/phase1-sim-double.nix"))?;

    assert_eq!(SIM_DOUBLE_AVAILABLE_PHASE, PhasePlanPhase::Phase1);
    assert!(default_checks.contains("simDouble = import ./phase1-sim-double.nix"));
    assert!(sim_double_check.contains("Completed by `crucible::SimDouble`"));

    let phase1_dependencies: BTreeSet<&str> = phase_gate_order()
        .iter()
        .filter(|occurrence| {
            occurrence.phase == PhasePlanPhase::Phase1 && occurrence.requires_sim_double
        })
        .map(|occurrence| occurrence.gate_name)
        .collect();
    assert_eq!(
        phase1_dependencies,
        BTreeSet::from([
            "gate:replay-oracle",
            "gate:single-vm-fingerprint",
            "gate:divergence-bisect",
        ])
    );

    for occurrence in phase_gate_order()
        .iter()
        .filter(|occurrence| occurrence.requires_sim_double)
    {
        assert!(
            occurrence.phase >= SIM_DOUBLE_AVAILABLE_PHASE,
            "{} depends on SimDouble before Phase 1",
            occurrence.attr_path
        );
    }

    Ok(())
}

#[test]
fn layer_gate_precedences_keep_lower_layer_checks_first() {
    assert!(layer_gate_precedence_failures(phase_gate_order(), LAYER_GATE_PRECEDENCES).is_empty());

    let mut drifted_plan = phase_gate_order().to_vec();
    let lower_index = drifted_plan
        .iter()
        .position(|occurrence| {
            occurrence.attr_path == "checks.crucible.phase2.gates.layer1Injection"
        })
        .expect("lower layer gate should be present");
    let higher_index = drifted_plan
        .iter()
        .position(|occurrence| {
            occurrence.attr_path == "checks.crucible.phase2.gates.singleVmFingerprint"
        })
        .expect("higher layer gate should be present");
    drifted_plan.swap(lower_index, higher_index);

    let failures = layer_gate_precedence_failures(&drifted_plan, LAYER_GATE_PRECEDENCES);
    assert!(
        failures.iter().any(|failure| {
            failure.lower_attr_path == "checks.crucible.phase2.gates.layer1Injection"
                && failure.higher_attr_path == "checks.crucible.phase2.gates.singleVmFingerprint"
        }),
        "synthetic HARN-3 drift was not rejected: {failures:#?}"
    );
}

#[test]
fn phase_plan_invariants_reject_synthetic_drift() -> Result<(), Box<dyn Error>> {
    let mut missing_terminal = phase_gate_order().to_vec();
    for occurrence in &mut missing_terminal {
        occurrence.terminal_acceptance = false;
    }
    assert!(has_failure_kind(
        &missing_terminal,
        PhasePlanInvariantFailureKind::MissingTerminalE2eDeterminism,
    ));

    let mut invalid_terminal = *terminal_acceptance_gate().ok_or("terminal gate is missing")?;
    invalid_terminal.phase = PhasePlanPhase::Phase4;
    assert!(has_failure_kind(
        &[invalid_terminal],
        PhasePlanInvariantFailureKind::InvalidTerminalAcceptanceGate,
    ));

    let mut early_sim_double = *phase_gate_order()
        .iter()
        .find(|occurrence| occurrence.requires_sim_double)
        .ok_or("SimDouble dependency is missing")?;
    early_sim_double.phase = PhasePlanPhase::Phase0;
    assert!(has_failure_kind(
        &[early_sim_double],
        PhasePlanInvariantFailureKind::SimDoubleUnavailable,
    ));

    let unknown_gate = PhaseGateOccurrence {
        phase: PhasePlanPhase::Phase1,
        gate_name: "gate:unknown",
        attr_path: "checks.crucible.phase1.gates.unknown",
        kind: PhaseGateKind::CatalogGate,
        purpose: "synthetic unknown gate",
        requires_sim_double: false,
        terminal_acceptance: false,
    };
    assert!(has_failure_kind(
        &[unknown_gate],
        PhasePlanInvariantFailureKind::UnknownCatalogGate,
    ));

    Ok(())
}

fn rfc_section_13_phase_order(content: &str) -> Result<Vec<(&str, &str)>, Box<dyn Error>> {
    let mut in_section = false;
    let mut in_block = false;
    let mut order = Vec::new();

    for line in content.lines() {
        if line.starts_with("## 13. How the gates compose into the phase plan") {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("## ") {
            break;
        }
        if !in_section {
            continue;
        }
        if line.trim() == "```text" {
            in_block = true;
            continue;
        }
        if in_block && line.trim() == "```" {
            break;
        }
        if !in_block {
            continue;
        }

        let mut parts = line.split_whitespace();
        let phase = match parts.next() {
            Some(value) if value.starts_with("phase") => value,
            _ => continue,
        };
        let gate = parts
            .next()
            .ok_or("phase-plan line is missing a gate name")?;
        order.push((phase, gate));
    }

    Ok(order)
}

fn green_attr_paths_before(phase: PhasePlanPhase) -> Vec<&'static str> {
    phase_gate_order()
        .iter()
        .filter_map(|occurrence| {
            if occurrence.phase < phase {
                Some(occurrence.attr_path)
            } else {
                None
            }
        })
        .collect()
}

fn has_failure_kind(plan: &[PhaseGateOccurrence], kind: PhasePlanInvariantFailureKind) -> bool {
    phase_plan_invariant_failures(plan)
        .iter()
        .any(|failure| failure.kind == kind)
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}
