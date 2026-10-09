//! Exercises inspectable policy expansion and exact immutable analysis.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use dispatch::{
    AccountingPhase, Assignment, ConstraintRule, Enforcement, Problem, ProblemBuilder, Quantity,
    Target, analysis, recipes, validate,
};

fn fixture() -> Problem {
    serde_json::from_str(include_str!("../examples/fixtures/packing.problem.json")).unwrap()
}

fn assignment(document: &str) -> Assignment {
    serde_json::from_str(document).unwrap()
}

#[test]
fn comparison_reports_exact_improvement_and_binding_changes() {
    let problem = validate(fixture()).unwrap();
    let before = assignment(include_str!("../examples/fixtures/packing.before.json"));
    let after = assignment(include_str!("../examples/fixtures/packing.after.json"));

    let comparison = analysis::compare(&problem, &before, &after).unwrap();

    assert_eq!(
        comparison.objective_ordering,
        analysis::ObjectiveOrdering::Better
    );
    assert_eq!(comparison.binding_changes.len(), 1);
    assert_eq!(comparison.binding_changes[0].item, "y");
}

#[test]
fn duplicate_builder_definitions_do_not_replace_the_original() {
    let target = Target {
        capacities: BTreeMap::new(),
        fixed_load: BTreeMap::new(),
    };
    let builder = ProblemBuilder::new()
        .target("A", target.clone())
        .target("A", target);

    assert_eq!(builder.as_problem().targets.len(), 1);
    assert!(builder.build().is_err());
}

#[test]
fn packing_expansion_is_explicit_and_collision_failure_is_atomic() {
    let mut problem = fixture();
    let expansion = recipes::packing_capacity(
        "capacity",
        &problem,
        &["slots".into()],
        AccountingPhase::Overlap,
        Enforcement::Repair,
    )
    .unwrap();
    assert_eq!(expansion.constraints.len(), 2);
    assert!(expansion.objectives.is_empty());
    assert!(
        expansion
            .constraints
            .iter()
            .all(|constraint| constraint.enforcement == Enforcement::Repair)
    );

    expansion.clone().apply(&mut problem).unwrap();
    let accepted = problem.clone();
    let collision = expansion.apply(&mut problem);

    assert!(collision.is_err());
    assert_eq!(problem, accepted);
}

#[test]
fn replica_policy_requires_admission_and_actual_scope_separation() {
    let mut problem = fixture();
    recipes::replica_spread("replicas", "pair", 2, "host", 2, Some(1))
        .apply(&mut problem)
        .unwrap();
    let problem = validate(problem).unwrap();
    let before = assignment(include_str!("../examples/fixtures/packing.before.json"));
    let after = assignment(include_str!("../examples/fixtures/packing.after.json"));

    assert!(dispatch::verify(&problem, before).is_ok());
    assert!(dispatch::verify(&problem, after).is_err());
}

#[test]
fn evacuation_preserves_observed_source_while_restricting_final_placement() {
    let mut problem = fixture();
    let expansion = recipes::evacuate(
        "evacuate-A",
        &problem,
        vec!["x".into(), "y".into()],
        &["A".into()],
    )
    .unwrap();
    assert!(
        matches!(&expansion.constraints[0].rule, ConstraintRule::Eligibility { targets, .. } if targets == &vec!["B".to_owned()])
    );

    expansion.apply(&mut problem).unwrap();

    assert!(problem.targets.contains_key("A"));
    assert_eq!(problem.observed["x"].charges["slots"], Quantity::new(1));
    assert!(validate(problem).is_ok());
}

#[test]
fn what_if_preserves_original_and_prevents_cross_problem_score_ordering() {
    let original = validate(fixture()).unwrap();
    let assignment = assignment(include_str!("../examples/fixtures/packing.after.json"));
    let revised = analysis::what_if(&original, |problem| {
        problem
            .observation_basis
            .insert("inventory".into(), "revision-2".into());
    })
    .unwrap();

    let comparison =
        analysis::compare_problems(&original, &assignment, &revised, &assignment).unwrap();

    assert_eq!(
        original.problem().observation_basis["inventory"],
        "revision-1"
    );
    assert!(!comparison.same_problem);
    assert!(comparison.objective_ordering.is_none());
    assert_eq!(
        comparison.model_changes[0].path,
        "/observation_basis/inventory"
    );
    assert!(analysis::what_if(&original, |_| {}).is_err());
    assert!(
        analysis::what_if(&original, |problem| {
            problem.domains.get_mut("all").unwrap().reverse();
        })
        .is_err()
    );
}
