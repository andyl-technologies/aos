//! Checks RFC-0010 T-EX-1 built-in worked-example corpus coverage.

#![forbid(unsafe_code)]

use crucible::{
    Action, Decision, ExampleCorpusError, ExampleScenarioRunOutcome, GuestWorkloadBinary,
    GuestWorkloadParameterKey, HAPPY_PATH_SCENARIO_NAME, Predicate, Property, ScenarioDefForm,
    WhiteBoxPolicy, built_in_example_corpus, happy_path_scenario, run_example_scenario,
    verify_example_scenario_runs,
};

#[test]
fn happy_path_is_shipped_as_builtin_corpus_fixture() -> Result<(), ExampleCorpusError> {
    let corpus = built_in_example_corpus()?;
    assert_eq!(corpus.len(), 1);
    let fixture = &corpus[0];

    assert_eq!(fixture.name, HAPPY_PATH_SCENARIO_NAME);
    assert_eq!(fixture.rfc_section, "33.A.1");
    assert!(fixture.zero_guest_components);
    assert!(!fixture.requires_white_box);
    assert!(fixture.scenario.world().nodes().len() == 2);
    assert!(fixture.scenario.world().links().len() == 1);
    Ok(())
}

#[test]
fn happy_path_authoring_uses_only_black_box_guest_observables() -> Result<(), ExampleCorpusError> {
    let fixture = happy_path_scenario()?;
    let world = fixture.scenario.world();
    let nodes = world.nodes();
    let server = nodes
        .iter()
        .find(|node| node.id.name == "server")
        .expect("happy path should include server");
    let client = nodes
        .iter()
        .find(|node| node.id.name == "client")
        .expect("happy path should include client");

    assert_eq!(server.white_box, WhiteBoxPolicy::Disabled);
    assert_eq!(client.white_box, WhiteBoxPolicy::Disabled);
    assert!(server.kernel.is_some());
    assert!(server.root_image.is_some());
    assert!(client.kernel.is_some());
    assert!(client.root_image.is_some());
    assert_eq!(server.guest_workload(), Some(GuestWorkloadBinary::Httpd));
    assert_eq!(
        client.guest_workload(),
        Some(GuestWorkloadBinary::ClientLoop)
    );
    let client_parameters = client.guest_workload_scalar_parameters();
    assert_eq!(
        client_parameters.get(&GuestWorkloadParameterKey::Target),
        Some(&String::from("server:8080"))
    );
    assert_eq!(
        client_parameters.get(&GuestWorkloadParameterKey::Count),
        Some(&String::from("100"))
    );

    for assertion in fixture.scenario.properties().assertions() {
        assert_black_box_property(&assertion.property);
    }
    let graph = fixture
        .scenario
        .plan()
        .event_graph()
        .expect("happy path uses graph-native pass plan");
    assert_eq!(graph.events().len(), 1);
    assert_eq!(graph.events()[0].id.name, "pass-on-quiescence");
    assert!(action_passes(&graph.events()[0].action));
    assert_black_box_predicate(
        graph.events()[0]
            .trigger
            .as_ref()
            .expect("pass event has observable trigger"),
    );
    Ok(())
}

#[test]
fn happy_path_round_trips_as_reproducible_scenario_material() -> Result<(), ExampleCorpusError> {
    let fixture = happy_path_scenario()?;
    let toml = fixture.scenario.to_canonical_toml()?;
    assert!(toml.contains("id = \"server\""));
    assert!(toml.contains("id = \"client\""));
    assert!(toml.contains("crucible.workload=httpd"));
    assert!(toml.contains("crucible.workload=httpget"));
    assert!(toml.contains("target=server:8080"));
    assert!(toml.contains("count=100"));
    assert!(toml.contains("pass-on-quiescence"));

    let from_toml = ScenarioDefForm::from_canonical_toml(&toml)?;
    let from_binary = ScenarioDefForm::from_compact_binary(&fixture.scenario.to_compact_binary())?;
    assert_eq!(from_toml.id(), fixture.scenario.id());
    assert_eq!(from_binary.id(), fixture.scenario.id());
    assert_eq!(
        from_toml.canonical_bytes(),
        fixture.scenario.canonical_bytes()
    );
    assert_eq!(
        from_binary.canonical_bytes(),
        fixture.scenario.canonical_bytes()
    );
    Ok(())
}

#[test]
fn happy_path_run_passes_and_verify_runs_are_byte_identical() -> Result<(), ExampleCorpusError> {
    let fixture = happy_path_scenario()?;
    let run = run_example_scenario(&fixture)?;
    assert_eq!(run.scenario_name, HAPPY_PATH_SCENARIO_NAME);
    assert_eq!(run.outcome, ExampleScenarioRunOutcome::Passed);
    assert!(!run.canonical_event_log.is_empty());
    assert!(!run.fingerprint_stream.is_empty());
    assert!(!run.assertion_report.verdict().is_failed());
    assert!(run.assertion_report.violations().is_empty());
    let outcome_names = run
        .assertion_report
        .outcomes()
        .iter()
        .map(|outcome| outcome.assertion.name.as_str())
        .collect::<Vec<_>>();
    assert!(outcome_names.contains(&"no-crashes"));
    assert!(outcome_names.contains(&"all-requests-succeed"));
    assert!(
        run.firings
            .iter()
            .any(|firing| firing.event().name == "pass-on-quiescence")
    );
    assert_eq!(run.reproduction.scenario_form().id(), fixture.scenario.id());
    assert_eq!(run.reproduction.replay()?.scenario, fixture.scenario.id());
    assert_eq!(
        run.reproduction.schedule().decisions().len(),
        fixture.observations().len() + 1
    );
    assert!(
        run.reproduction
            .schedule()
            .decisions()
            .iter()
            .all(|decision| matches!(decision, Decision::Override(_)))
    );
    assert_eq!(run.replayed_canonical_event_log, run.canonical_event_log);
    assert_eq!(run.replayed_fingerprint_stream, run.fingerprint_stream);

    let verified = verify_example_scenario_runs(&fixture, 5)?;
    assert_eq!(verified.scenario_name, HAPPY_PATH_SCENARIO_NAME);
    assert_eq!(verified.runs, 5);
    assert_eq!(verified.canonical_event_log, run.canonical_event_log);
    assert_eq!(verified.fingerprint_stream, run.fingerprint_stream);
    Ok(())
}

#[test]
fn verify_requires_at_least_one_run() -> Result<(), ExampleCorpusError> {
    let fixture = happy_path_scenario()?;
    let error =
        verify_example_scenario_runs(&fixture, 0).expect_err("zero verify runs should be rejected");
    assert!(matches!(error, ExampleCorpusError::VerifyRunsZero { .. }));
    Ok(())
}

fn assert_black_box_property(property: &Property) {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => assert_black_box_predicate(predicate),
        Property::Eventually {
            trigger, property, ..
        } => {
            assert_black_box_predicate(trigger);
            assert_black_box_predicate(property);
        }
    }
}

fn assert_black_box_predicate(predicate: &Predicate) {
    match predicate {
        Predicate::GuestMarker { .. } => panic!("happy path must not require guest markers"),
        Predicate::Named { .. } => panic!("happy path must not require host-private named leaves"),
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            for child in predicates {
                assert_black_box_predicate(child);
            }
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            assert_black_box_predicate(predicate);
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
        | Predicate::AssertionState { .. }
        | Predicate::Quiescent
        | Predicate::FaultActive { .. } => {}
    }
}

fn action_passes(action: &Action) -> bool {
    match action {
        Action::Pass => true,
        Action::Group(actions) => actions.iter().any(action_passes),
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Fail { .. }
        | Action::Log { .. } => false,
    }
}
