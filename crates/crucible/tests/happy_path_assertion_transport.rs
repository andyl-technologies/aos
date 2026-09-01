//! Checks that the opaque happy-path example uses observable assertion state.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use crucible::{
    AssertionPhase, HAPPY_PATH_SCENARIO_NAME, Predicate, Property, built_in_example_corpus,
};

#[test]
fn opaque_happy_path_does_not_parse_network_payloads_as_application_verdicts() {
    let corpus = built_in_example_corpus().expect("built-in corpus should validate");
    let fixture = corpus
        .iter()
        .find(|fixture| fixture.name == HAPPY_PATH_SCENARIO_NAME)
        .expect("happy path should be shipped in the built-in corpus");

    assert!(
        fixture
            .scenario
            .properties()
            .assertions()
            .iter()
            .all(|assertion| !property_has_network_match(&assertion.property))
    );
    let graph = fixture.scenario.plan().event_graph();
    let pass_trigger = graph.events()[0]
        .trigger
        .as_ref()
        .expect("pass event should have an assertion-gated trigger");
    assert!(predicate_has_satisfied_assertion_state(
        pass_trigger,
        "all-requests-succeed"
    ));
}

fn property_has_network_match(property: &Property) -> bool {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => predicate_has_network_match(predicate),
        Property::Eventually {
            trigger, property, ..
        } => predicate_has_network_match(trigger) || predicate_has_network_match(property),
    }
}

fn predicate_has_network_match(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::NetworkMatch { .. } => true,
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            predicates.iter().any(predicate_has_network_match)
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            predicate_has_network_match(predicate)
        }
        Predicate::At { .. }
        | Predicate::After { .. }
        | Predicate::Timer { .. }
        | Predicate::ConsoleMatch { .. }
        | Predicate::CoveragePoint { .. }
        | Predicate::MemoryPredicate { .. }
        | Predicate::IoPattern { .. }
        | Predicate::NodeState { .. }
        | Predicate::AssertionState { .. }
        | Predicate::Quiescent
        | Predicate::Named { .. }
        | Predicate::GuestMarker { .. } => false,
    }
}

fn predicate_has_satisfied_assertion_state(predicate: &Predicate, expected: &str) -> bool {
    match predicate {
        Predicate::AssertionState { name, state } => {
            name.name == expected && *state == AssertionPhase::Satisfied
        }
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => predicates
            .iter()
            .any(|predicate| predicate_has_satisfied_assertion_state(predicate, expected)),
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            predicate_has_satisfied_assertion_state(predicate, expected)
        }
        Predicate::At { .. }
        | Predicate::After { .. }
        | Predicate::Timer { .. }
        | Predicate::NetworkMatch { .. }
        | Predicate::ConsoleMatch { .. }
        | Predicate::CoveragePoint { .. }
        | Predicate::MemoryPredicate { .. }
        | Predicate::IoPattern { .. }
        | Predicate::NodeState { .. }
        | Predicate::Quiescent
        | Predicate::Named { .. }
        | Predicate::GuestMarker { .. } => false,
    }
}
