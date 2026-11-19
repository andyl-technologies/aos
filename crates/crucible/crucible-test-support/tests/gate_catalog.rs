//! Checks that the canonical gate catalog stays aligned across code and docs.
//!
//! The engineering page `docs/engineering/crucible/testing-and-gates.md` holds
//! the documented gate table and the gate-ordering plan. Every canonical gate
//! must appear in the table, and the rest of that page must name exactly the
//! canonical gates, so the page cannot cite an undefined gate or leave a
//! defined gate undocumented.

#[path = "support/workspace.rs"]
mod workspace;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use crucible_test_support::{GatePhase, GateStatus, canonical_gates, find_gate};

/// The engineering page that owns the gate catalog table.
const GATE_CATALOG_DOC: &str = "docs/engineering/crucible/testing-and-gates.md";

#[test]
fn canonical_gate_catalog_matches_documented_table_and_references() -> Result<(), Box<dyn Error>> {
    let catalog_doc = fs::read_to_string(workspace_root().join(GATE_CATALOG_DOC))?;

    let implemented: BTreeSet<String> = canonical_gates()
        .iter()
        .map(|gate| gate.name.to_owned())
        .collect();
    let table = table_gate_names(&catalog_doc);
    assert_eq!(implemented, table);

    let referenced = referenced_gate_names(&catalog_doc);
    assert_eq!(implemented, referenced);

    Ok(())
}

#[test]
fn canonical_gate_statuses_are_current() {
    let placeholders: BTreeSet<&str> = canonical_gates()
        .iter()
        .filter_map(|gate| {
            if gate.status == GateStatus::RedPlaceholder {
                Some(gate.name)
            } else {
                None
            }
        })
        .collect();
    let expected = BTreeSet::new();

    assert_eq!(placeholders, expected);

    assert!(matches!(
        find_gate("gate:perf-bench").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:harness-lint").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:license-boundary").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:layer0-determinism").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:single-vm-fingerprint").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:layer1-injection").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:content-address").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:campaign-model").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:campaign-statistics").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:replay-oracle").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:divergence-bisect").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:scheduler-liveness").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:control-responsive").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:qemu-inert").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:abi-conformance").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:any-guest").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:patch-microtests").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:adversarial-determinism").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:e2e-determinism").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:fleet-equivalence").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:campaign-continuity").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:production-rust-plugin-flight").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:basic-block-coverage").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:checkpoint-materialization").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:state-space-search").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));
    assert!(matches!(
        find_gate("gate:signal-fault-system").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));

    let expected_phases = BTreeMap::from([
        ("gate:harness-lint", GatePhase::Always),
        ("gate:license-boundary", GatePhase::Always),
        ("gate:layer0-determinism", GatePhase::Phase1),
        ("gate:single-vm-fingerprint", GatePhase::Phase1),
        ("gate:layer1-injection", GatePhase::Phase2),
        ("gate:content-address", GatePhase::Phase1),
        ("gate:campaign-model", GatePhase::Phase1),
        ("gate:campaign-statistics", GatePhase::Phase4),
        ("gate:replay-oracle", GatePhase::Phase1),
        ("gate:divergence-bisect", GatePhase::Phase1),
        ("gate:scheduler-liveness", GatePhase::Phase3),
        ("gate:control-responsive", GatePhase::Phase5),
        ("gate:any-guest", GatePhase::Phase2),
        ("gate:qemu-inert", GatePhase::Phase2),
        ("gate:abi-conformance", GatePhase::Phase2),
        ("gate:patch-microtests", GatePhase::Phase2),
        ("gate:adversarial-determinism", GatePhase::Phase3),
        ("gate:e2e-determinism", GatePhase::Phase4),
        ("gate:basic-block-coverage", GatePhase::Phase6),
        ("gate:checkpoint-materialization", GatePhase::Phase6),
        ("gate:state-space-search", GatePhase::Phase6),
        ("gate:perf-bench", GatePhase::Phase7),
        ("gate:fleet-equivalence", GatePhase::Phase7),
        ("gate:campaign-continuity", GatePhase::Phase7),
        ("gate:production-rust-plugin-flight", GatePhase::Phase7),
        ("gate:signal-fault-system", GatePhase::Phase7),
    ]);

    for (gate, phase) in expected_phases {
        assert_eq!(find_gate(gate).map(|spec| spec.phase), Some(phase));
    }
}

#[test]
fn canonical_gates_have_phase_gate_ci_targets() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let phase_gate_wiring =
        fs::read_to_string(root.join("tests/crucible/phase1-phase-gate-wiring.nix"))?;
    let mut missing = Vec::new();

    for gate in canonical_gates()
        .iter()
        .filter(|gate| gate.status != GateStatus::CatalogOnly)
    {
        let needle = format!("gate = \"{}\";", gate.name);
        if !phase_gate_wiring.contains(&needle) {
            missing.push(format!(
                "{}: canonical gate is absent from phase-gate CI target wiring",
                gate.name
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "canonical gate CI target wiring drift:\n{}",
        missing.join("\n")
    );

    Ok(())
}

fn workspace_root() -> PathBuf {
    workspace::repository_root()
}

fn table_gate_names(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter(|line| line.trim_start().starts_with("| `gate:"))
        .flat_map(gate_names_in_text)
        .collect()
}

/// Collects gate names cited on the page outside the catalog table rows.
fn referenced_gate_names(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with("| `gate:"))
        .flat_map(gate_names_in_text)
        .collect()
}

fn gate_names_in_text(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut remaining = text;

    while let Some(start) = remaining.find("gate:") {
        let after_start = &remaining[start..];
        let suffix_len: usize = after_start["gate:".len()..]
            .chars()
            .take_while(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || *ch == '-')
            .map(char::len_utf8)
            .sum();
        let byte_len = "gate:".len() + suffix_len;

        if suffix_len > 0 {
            names.insert(after_start[..byte_len].to_owned());
        }
        remaining = &after_start[byte_len..];
    }

    names
}
