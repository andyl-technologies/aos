//! Checks that the phase-gate plan is executable ordering data.
//!
//! The documented ordering, layer precedences, and advanced-feature ladder live
//! in `docs/engineering/crucible/testing-and-gates.md`; these tests keep that
//! page, `crucible_test_support::phase_plan`, and the Nix wiring aligned.

#![forbid(unsafe_code)]

#[path = "support/workspace.rs"]
mod workspace;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use crucible_test_support::phase_plan::{
    ADVANCED_FEATURE_LADDER, AdvancedFeatureRung, AdvancedFeatureScheduleFailureKind,
    AdvancedFeatureStep, LAYER_GATE_PRECEDENCES, PhaseGateKind, PhaseGateOccurrence,
    PhasePlanInvariantFailureKind, PhasePlanPhase, SIM_DOUBLE_AVAILABLE_PHASE,
    advanced_feature_ladder, advanced_feature_ladder_failures, advanced_feature_schedule_failures,
    green_before_advance_failures, layer_gate_precedence_failures, phase_gate_order,
    phase_plan_invariant_failures, terminal_acceptance_gate,
};

/// The engineering page that documents the phase-gate plan.
const TESTING_AND_GATES_DOC: &str = "docs/engineering/crucible/testing-and-gates.md";

#[test]
fn phase_gate_plan_matches_documented_order_and_nix_wiring() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let testing_and_gates = fs::read_to_string(root.join(TESTING_AND_GATES_DOC))?;
    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;

    let actual: Vec<(&str, &str, &str)> = phase_gate_order()
        .iter()
        .map(|occurrence| {
            (
                occurrence.phase.label(),
                occurrence.gate_name,
                occurrence.attr_path,
            )
        })
        .collect();
    let expected = documented_phase_gate_order(&testing_and_gates)?;
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
            "checks.crucible.phase4.gates.campaignStatistics",
            "checks.crucible.phase4.gates.e2eDeterminism",
        ])
    );

    let terminal = terminal_acceptance_gate().ok_or("terminal acceptance gate is missing")?;
    assert_eq!(
        terminal.attr_path,
        "checks.crucible.phase7.gates.signalFaultSystem"
    );

    Ok(())
}

#[test]
fn terminal_signal_fault_occurrence_remains_in_phase7_acceptance_set() -> Result<(), Box<dyn Error>>
{
    let terminal = terminal_acceptance_gate().ok_or("terminal acceptance gate is missing")?;
    assert_eq!(terminal.phase, PhasePlanPhase::Phase7);
    assert_eq!(terminal.kind, PhaseGateKind::CatalogGate);
    assert_eq!(terminal.gate_name, "gate:signal-fault-system");

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

    assert_eq!(SIM_DOUBLE_AVAILABLE_PHASE, PhasePlanPhase::Phase1);
    assert!(default_checks.contains("simDouble = import ./phase1-sim-double.nix"));

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
    let lower_index = match drifted_plan.iter().position(|occurrence| {
        occurrence.attr_path == "checks.crucible.phase2.gates.layer1Injection"
    }) {
        Some(index) => index,
        None => panic!("lower layer gate should be present"),
    };
    let higher_index = match drifted_plan.iter().position(|occurrence| {
        occurrence.attr_path == "checks.crucible.phase2.gates.singleVmFingerprint"
    }) {
        Some(index) => index,
        None => panic!("higher layer gate should be present"),
    };
    drifted_plan.swap(lower_index, higher_index);

    let failures = layer_gate_precedence_failures(&drifted_plan, LAYER_GATE_PRECEDENCES);
    assert!(
        failures.iter().any(|failure| {
            failure.lower_attr_path == "checks.crucible.phase2.gates.layer1Injection"
                && failure.higher_attr_path == "checks.crucible.phase2.gates.singleVmFingerprint"
        }),
        "synthetic layer-precedence drift was not rejected: {failures:#?}"
    );
}

#[test]
fn advanced_feature_ladder_keeps_fuzzing_above_search_and_coverage() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let testing_and_gates = fs::read_to_string(root.join(TESTING_AND_GATES_DOC))?;
    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;

    assert!(
        advanced_feature_ladder_failures(phase_gate_order(), advanced_feature_ladder()).is_empty()
    );
    assert!(default_checks.contains("checks.crucible.phase6.gates.replayOracle"));

    // The documented ladder chain and per-rung entry counts must match the code.
    let rung_labels = ADVANCED_FEATURE_RUNGS
        .iter()
        .map(|rung| rung.label())
        .collect::<Vec<_>>();
    assert!(
        testing_and_gates.contains(&rung_labels.join(" -> ")),
        "{TESTING_AND_GATES_DOC} does not document the ladder `{}`",
        rung_labels.join(" -> ")
    );

    let mut code_entry_counts = BTreeMap::new();
    for step in advanced_feature_ladder() {
        *code_entry_counts
            .entry(step.rung.label())
            .or_insert(0_usize) += 1;
    }
    assert_eq!(
        documented_ladder_entry_counts(&testing_and_gates)?,
        code_entry_counts
    );
    let schedule_failures =
        advanced_feature_schedule_failures(&default_checks, advanced_feature_ladder());
    assert!(
        schedule_failures.is_empty(),
        "advanced-feature schedule failures: {schedule_failures:#?}"
    );

    // Every step names a distinct Phase 6 check.
    let attr_paths = advanced_feature_ladder()
        .iter()
        .map(|step| step.attr_path)
        .collect::<BTreeSet<_>>();
    assert_eq!(attr_paths.len(), ADVANCED_FEATURE_LADDER.len());
    assert_eq!(attr_paths.len(), 21);
    assert!(
        attr_paths
            .iter()
            .all(|attr_path| attr_path.starts_with("checks.crucible.phase6.")),
        "every advanced-feature step must be a Phase 6 check: {attr_paths:#?}"
    );

    let fuzzing = ladder_step(COVERAGE_GUIDED_FUZZING)?;
    assert_eq!(fuzzing.rung, AdvancedFeatureRung::Fuzzing);
    for prerequisite in [
        COVERAGE_FEEDBACK,
        "checks.crucible.phase6.guidanceDeterminismLint",
        "checks.crucible.phase6.appRandomBranching",
    ] {
        assert!(
            fuzzing.prerequisite_attr_paths.contains(&prerequisite),
            "fuzzing must depend on {prerequisite}"
        );
    }

    let ladder = ladder_step(ADVANCED_DEPENDENCY_LADDER)?;
    assert!(
        ladder
            .required_green_attr_paths
            .contains(&"checks.crucible.phase5.gates.controlResponsive")
    );

    let coverage = ladder_step(COVERAGE_FEEDBACK)?;
    assert_eq!(coverage.rung, AdvancedFeatureRung::CoverageFeedback);
    assert_eq!(coverage.rung.label(), "coverage-feedback");

    Ok(())
}

#[test]
fn advanced_feature_schedule_rejects_unwrapped_default_check() {
    let default_checks = r#"
      phase6 = {
        coverageGuidedFuzzing = import ./phase6-coverage-guided-fuzzing.nix {
          attrPath = "checks.crucible.phase6.coverageGuidedFuzzing";
        };
      };
    "#;

    let failures = advanced_feature_schedule_failures(default_checks, advanced_feature_ladder());
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == COVERAGE_GUIDED_FUZZING
                && failure.kind == AdvancedFeatureScheduleFailureKind::MissingAdvanceGuard
        }),
        "synthetic unwrapped advanced check was not rejected: {failures:#?}"
    );
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == COVERAGE_GUIDED_FUZZING
                && failure.kind == AdvancedFeatureScheduleFailureKind::MissingPrerequisiteDependency
                && failure.dependency.as_deref() == Some("phase6.coverageFeedback")
        }),
        "synthetic fuzz check without coverage prerequisite was not rejected: {failures:#?}"
    );
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == COVERAGE_FEEDBACK
                && failure.kind == AdvancedFeatureScheduleFailureKind::MissingCheck
        }),
        "an advanced step without a declared check was not rejected: {failures:#?}"
    );
}

#[test]
fn advanced_feature_schedule_rejects_check_borrowing_a_nearby_guard() {
    let default_checks = r#"
      phase6 = {
        coverageFeedback = greenBeforeAdvance {
          attrPath = "checks.crucible.phase6.coverageFeedback";
          gate = import ./phase6-coverage-guided-fuzzing.nix {
            attrPath = "checks.crucible.phase6.coverageGuidedFuzzing";
          };
          dependencies = [phase6.coverageFeedback];
        };
      };
    "#;

    let failures = advanced_feature_schedule_failures(default_checks, advanced_feature_ladder());
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == COVERAGE_GUIDED_FUZZING
                && failure.kind == AdvancedFeatureScheduleFailureKind::MissingAdvanceGuard
        }),
        "an advanced check nested in another check's guard was accepted: {failures:#?}"
    );
}

#[test]
fn advanced_feature_schedule_accepts_red_advance_guard() {
    let default_checks = r#"
      phase6 = {
        advancedDependencyLadder = redBeforeAdvance {
          attrPath = "checks.crucible.phase6.advancedDependencyLadder";
          gate = import ./phase6-advanced-dependency-ladder.nix {
            attrPath = "checks.crucible.phase6.advancedDependencyLadder";
          };
          dependencies = [
            phase2.gates.singleVmFingerprint
            phase4.gates.e2eDeterminism
            phase5.gates.controlResponsive
          ];
          phase = "phase6";
          reason = "live evidence is pending";
        };
      };
    "#;

    let failures = advanced_feature_schedule_failures(default_checks, advanced_feature_ladder());
    assert!(
        !failures.iter().any(|failure| {
            failure.attr_path == ADVANCED_DEPENDENCY_LADDER
                && failure.kind == AdvancedFeatureScheduleFailureKind::MissingAdvanceGuard
        }),
        "red guard did not safely block advanced work: {failures:#?}"
    );
}

#[test]
fn advanced_feature_schedule_rejects_missing_green_gate_dependency() {
    let default_checks = r#"
      phase6 = {
        advancedDependencyLadder = greenBeforeAdvance {
          attrPath = "checks.crucible.phase6.advancedDependencyLadder";
          gate = import ./phase6-advanced-dependency-ladder.nix {
            attrPath = "checks.crucible.phase6.advancedDependencyLadder";
          };
          dependencies = [phase2.gates.singleVmFingerprint phase4.gates.e2eDeterminism];
        };
      };
    "#;

    let failures = advanced_feature_schedule_failures(default_checks, advanced_feature_ladder());
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == ADVANCED_DEPENDENCY_LADDER
                && failure.kind == AdvancedFeatureScheduleFailureKind::MissingGateDependency
                && failure.dependency.as_deref() == Some("phase5.gates.controlResponsive")
        }),
        "synthetic advanced check without a green control dependency was not rejected: {failures:#?}"
    );
}

#[test]
fn advanced_feature_schedule_rejects_inner_only_gate_dependency() {
    let default_checks = r#"
      phase6 = {
        advancedDependencyLadder = greenBeforeAdvance {
          attrPath = "checks.crucible.phase6.advancedDependencyLadder";
          gate = import ./phase6-advanced-dependency-ladder.nix {
            attrPath = "checks.crucible.phase6.advancedDependencyLadder";
            dependencies = [phase4.gates.e2eDeterminism.rawGate];
          };
          dependencies = [
            phase2.gates.singleVmFingerprint
            phase5.gates.controlResponsive
          ];
        };
      };
    "#;

    let failures = advanced_feature_schedule_failures(default_checks, advanced_feature_ladder());
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == ADVANCED_DEPENDENCY_LADDER
                && failure.kind == AdvancedFeatureScheduleFailureKind::MissingGateDependency
                && failure.dependency.as_deref() == Some("phase4.gates.e2eDeterminism")
        }),
        "synthetic advanced check with only inner raw e2e dependency was not rejected: {failures:#?}"
    );
}

#[test]
fn advanced_feature_ladder_rejects_fuzzing_before_coverage() {
    let mut drifted = advanced_feature_ladder().to_vec();
    let fuzz_index = match drifted
        .iter()
        .position(|step| step.attr_path == COVERAGE_GUIDED_FUZZING)
    {
        Some(index) => index,
        None => panic!("fuzz step should be present"),
    };
    let coverage_index = match drifted
        .iter()
        .position(|step| step.attr_path == COVERAGE_FEEDBACK)
    {
        Some(index) => index,
        None => panic!("coverage step should be present"),
    };
    drifted.swap(fuzz_index, coverage_index);

    let failures = advanced_feature_ladder_failures(phase_gate_order(), &drifted);
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == COVERAGE_GUIDED_FUZZING
                && failure.rung == AdvancedFeatureRung::Fuzzing
                && failure.prerequisite_attr_path == Some(COVERAGE_FEEDBACK)
        }),
        "synthetic fuzz-before-coverage drift was not rejected: {failures:#?}"
    );
}

#[test]
fn advanced_feature_ladder_rejects_steps_before_foundation_gates() {
    let mut drifted_plan = phase_gate_order().to_vec();
    let phase4_e2e = match drifted_plan
        .iter_mut()
        .find(|occurrence| occurrence.attr_path == "checks.crucible.phase4.gates.e2eDeterminism")
    {
        Some(occurrence) => occurrence,
        None => panic!("phase4 e2e gate should be present"),
    };
    phase4_e2e.phase = PhasePlanPhase::Phase6;

    let failures = advanced_feature_ladder_failures(&drifted_plan, advanced_feature_ladder());
    assert!(
        failures.iter().any(|failure| {
            failure.attr_path == ADVANCED_DEPENDENCY_LADDER
                && failure.gate_attr_path == Some("checks.crucible.phase4.gates.e2eDeterminism")
        }),
        "synthetic late determinism gate was not rejected: {failures:#?}"
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
        PhasePlanInvariantFailureKind::MissingTerminalSignalFaultSystem,
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

/// The ladder's own scheduling check, the lowest advanced-feature step.
const ADVANCED_DEPENDENCY_LADDER: &str = "checks.crucible.phase6.advancedDependencyLadder";

/// The coverage-feedback step that fuzzing must follow.
const COVERAGE_FEEDBACK: &str = "checks.crucible.phase6.coverageFeedback";

/// The first fuzzing step.
const COVERAGE_GUIDED_FUZZING: &str = "checks.crucible.phase6.coverageGuidedFuzzing";

/// Every advanced-feature rung, lowest first.
const ADVANCED_FEATURE_RUNGS: [AdvancedFeatureRung; 6] = [
    AdvancedFeatureRung::ExactDeterminism,
    AdvancedFeatureRung::SaveRestore,
    AdvancedFeatureRung::Fork,
    AdvancedFeatureRung::Search,
    AdvancedFeatureRung::CoverageFeedback,
    AdvancedFeatureRung::Fuzzing,
];

/// Parses the `phase gate attr-path` lines of the first text block under the
/// page's "Gate ordering" heading.
fn documented_phase_gate_order(content: &str) -> Result<Vec<(&str, &str, &str)>, Box<dyn Error>> {
    let section = section_after_heading(content, "## Gate ordering")?;
    let mut order = Vec::new();

    for line in first_text_block(section)?.lines() {
        let mut parts = line.split_whitespace();
        let phase = match parts.next() {
            Some(value) if value.starts_with("phase") => value,
            _ => continue,
        };
        let gate = parts
            .next()
            .ok_or("phase-plan line is missing a gate name")?;
        let attr_path = parts
            .next()
            .ok_or("phase-plan line is missing a Nix attribute path")?;
        order.push((phase, gate, attr_path));
    }

    Ok(order)
}

/// Returns the ladder step whose check has `attr_path`.
fn ladder_step(attr_path: &str) -> Result<&'static AdvancedFeatureStep, String> {
    advanced_feature_ladder()
        .iter()
        .find(|step| step.attr_path == attr_path)
        .ok_or_else(|| format!("{attr_path} is missing from the advanced-feature ladder"))
}

/// Parses the rung-to-entry-count table under the "Advanced-feature ladder"
/// heading.
fn documented_ladder_entry_counts(content: &str) -> Result<BTreeMap<&str, usize>, Box<dyn Error>> {
    let section = section_after_heading(content, "### Advanced-feature ladder")?;
    let mut counts = BTreeMap::new();

    for line in section.lines().filter(|line| line.starts_with("| `")) {
        let mut cells = line.split('|').map(str::trim).skip(1);
        let rung = cells
            .next()
            .map(|cell| cell.trim_matches('`'))
            .ok_or("ladder row is missing a rung")?;
        let entries = cells
            .next()
            .ok_or("ladder row is missing an entry count")?
            .parse::<usize>()?;
        counts.insert(rung, entries);
    }

    Ok(counts)
}

/// Returns the text after `heading` up to the next heading of the same or a
/// higher level.
fn section_after_heading<'a>(content: &'a str, heading: &str) -> Result<&'a str, Box<dyn Error>> {
    let level = heading.chars().take_while(|ch| *ch == '#').count();
    let mut offset = 0;
    let mut found = false;

    for line in content.split_inclusive('\n') {
        offset += line.len();
        if line.trim_end() == heading {
            found = true;
            break;
        }
    }
    if !found {
        return Err(format!("missing `{heading}` heading").into());
    }

    let body = &content[offset..];
    let mut end = 0;
    for line in body.split_inclusive('\n') {
        let hashes = line.chars().take_while(|ch| *ch == '#').count();
        if hashes > 0 && hashes <= level && line[hashes..].starts_with(' ') {
            break;
        }
        end += line.len();
    }

    Ok(&body[..end])
}

/// Returns the body of the first fenced `text` block in `section`.
fn first_text_block(section: &str) -> Result<&str, Box<dyn Error>> {
    let fence = "```text\n";
    let start = section.find(fence).ok_or("missing text block")? + fence.len();
    let end = section[start..]
        .find("```")
        .ok_or("unterminated text block")?;
    Ok(&section[start..start + end])
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
    workspace::repository_root()
}
