//! Checks RFC-0010 built-in worked-example corpus coverage.

#![forbid(unsafe_code)]

use crucible::{
    Action, AssertionPhase, Decision, ExampleCorpusError, ExampleScenarioRunOutcome,
    GuestWorkloadBinary, GuestWorkloadParameterKey, HAPPY_PATH_SCENARIO_NAME,
    HostAssertionOutcomeKind, MembershipFault, PARTITION_RECOVERY_SCENARIO_NAME, Predicate,
    Property, ScenarioDefForm, WhiteBoxPolicy, built_in_example_corpus, happy_path_scenario,
    partition_recovery_scenario, run_example_scenario, verify_example_scenario_runs,
};

#[test]
fn happy_path_is_shipped_as_builtin_corpus_fixture() -> Result<(), ExampleCorpusError> {
    let corpus = built_in_example_corpus()?;
    assert_eq!(corpus.len(), 2);
    let fixture = corpus
        .iter()
        .find(|fixture| fixture.name == HAPPY_PATH_SCENARIO_NAME)
        .expect("happy path should be shipped in the built-in corpus");

    assert_eq!(fixture.name, HAPPY_PATH_SCENARIO_NAME);
    assert_eq!(fixture.rfc_section, "33.A.1");
    assert!(fixture.zero_guest_components);
    assert!(!fixture.requires_white_box);
    assert!(fixture.scenario.world().nodes().len() == 2);
    assert!(fixture.scenario.world().links().len() == 1);
    Ok(())
}

#[test]
fn partition_recovery_is_shipped_as_builtin_corpus_fixture() -> Result<(), ExampleCorpusError> {
    let corpus = built_in_example_corpus()?;
    let fixture = corpus
        .iter()
        .find(|fixture| fixture.name == PARTITION_RECOVERY_SCENARIO_NAME)
        .expect("partition recovery should be shipped in the built-in corpus");

    assert_eq!(fixture.rfc_section, "33.A.2");
    assert!(fixture.zero_guest_components);
    assert!(!fixture.requires_white_box);
    assert_eq!(fixture.scenario.world().nodes().len(), 3);
    assert_eq!(fixture.scenario.world().links().len(), 3);
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
fn partition_recovery_uses_observable_trigger_graph() -> Result<(), ExampleCorpusError> {
    let fixture = partition_recovery_scenario()?;
    let world = fixture.scenario.world();
    assert_eq!(world.nodes().len(), 3);
    for node in world.nodes() {
        assert_eq!(node.white_box, WhiteBoxPolicy::Disabled);
        assert!(node.kernel.is_some());
        assert!(node.root_image.is_some());
        assert!(node.cmdline.contains("store.role=replica"));
        assert!(node.cmdline.contains("cluster=crucible-a2"));
    }

    let assertion_names = fixture
        .scenario
        .properties()
        .assertions()
        .iter()
        .map(|assertion| assertion.id.name.as_str())
        .collect::<Vec<_>>();
    assert!(assertion_names.contains(&"split-active"));
    assert!(assertion_names.contains(&"no-split-brain"));
    assert!(assertion_names.contains(&"converges-after-heal"));
    let convergence_assertion = fixture
        .scenario
        .properties()
        .assertions()
        .iter()
        .find(|assertion| assertion.id.name == "converges-after-heal")
        .expect("partition recovery declares convergence assertion");
    assert!(matches!(
        &convergence_assertion.property,
        Property::Eventually {
            trigger: Predicate::AssertionState { name, state },
            ..
        } if name.name == "split-active" && *state == AssertionPhase::Satisfied
    ));
    for assertion in fixture.scenario.properties().assertions() {
        assert_black_box_property(&assertion.property);
    }

    let graph = fixture
        .scenario
        .plan()
        .event_graph()
        .expect("partition recovery uses graph-native trigger choreography");
    assert_eq!(graph.events().len(), 3);
    let wait_ready = &graph.events()[0];
    let heal = &graph.events()[1];
    let pass_on_converge = &graph.events()[2];

    assert_eq!(wait_ready.id.name, "wait-ready");
    assert_ready_trigger_shape(
        wait_ready
            .trigger
            .as_ref()
            .expect("wait-ready has observable readiness trigger"),
    );
    let Action::Group(actions) = &wait_ready.action else {
        panic!("wait-ready must inject the split and arm the heal timer as a group");
    };
    assert_partition_injection(actions);
    assert!(actions.iter().any(|action| matches!(
        action,
        Action::ArmTimer { name, after }
            if name.name == "heal-after" && after.nanos == 10_000_000_000
    )));

    assert_eq!(heal.id.name, "heal");
    assert!(matches!(
        heal.trigger.as_ref().expect("heal is timer-triggered"),
        Predicate::Timer { name } if name.name == "heal-after"
    ));
    assert!(matches!(
        &heal.action,
        Action::HealFault { tag } if tag.name == "split"
    ));

    assert_eq!(pass_on_converge.id.name, "pass-on-converge");
    assert!(action_passes(&pass_on_converge.action));
    assert_convergence_trigger_shape(
        pass_on_converge
            .trigger
            .as_ref()
            .expect("pass-on-converge has observable convergence trigger"),
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
fn partition_recovery_round_trips_as_reproducible_scenario_material()
-> Result<(), ExampleCorpusError> {
    let fixture = partition_recovery_scenario()?;
    let toml = fixture.scenario.to_canonical_toml()?;
    assert!(toml.contains("id = \"db-0\""));
    assert!(toml.contains("id = \"db-1\""));
    assert!(toml.contains("id = \"db-2\""));
    assert!(toml.contains("ready to accept connections"));
    assert!(toml.contains("wait-ready"));
    assert!(toml.contains("pass-on-converge"));
    assert!(toml.contains("no-split-brain"));
    assert!(toml.contains("converges-after-heal"));

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
fn partition_recovery_run_passes_and_verify_runs_are_byte_identical()
-> Result<(), ExampleCorpusError> {
    let fixture = partition_recovery_scenario()?;
    let run = run_example_scenario(&fixture)?;
    assert_eq!(run.scenario_name, PARTITION_RECOVERY_SCENARIO_NAME);
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
    assert!(outcome_names.contains(&"split-active"));
    assert!(outcome_names.contains(&"no-split-brain"));
    assert!(outcome_names.contains(&"converges-after-heal"));
    assert!(
        run.firings
            .iter()
            .any(|firing| firing.event().name == "pass-on-converge")
    );
    assert_eq!(
        outcome_kind(&run, "split-active"),
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome_kind(&run, "no-split-brain"),
        HostAssertionOutcomeKind::Passed
    );
    assert_eq!(
        outcome_kind(&run, "converges-after-heal"),
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(run.reproduction.scenario_form().id(), fixture.scenario.id());
    assert_eq!(run.reproduction.replay()?.scenario, fixture.scenario.id());
    assert_eq!(run.reproduction.schedule().decisions().len(), 3);
    assert!(
        run.reproduction
            .schedule()
            .decisions()
            .iter()
            .all(|decision| matches!(decision, Decision::Override(_)))
    );
    assert!(
        run.reproduction
            .schedule()
            .decisions()
            .iter()
            .all(|decision| match decision {
                Decision::Override(override_decision) => !override_decision
                    .choice
                    .name
                    .contains("assertion-state-changed"),
                Decision::DeliveryOrder(_)
                | Decision::FaultFires(_)
                | Decision::RngDraw(_)
                | Decision::Preemption(_)
                | Decision::AppRandom(_)
                | Decision::ControlFault(_) => false,
            })
    );
    assert_eq!(run.replayed_canonical_event_log, run.canonical_event_log);
    assert_eq!(run.replayed_fingerprint_stream, run.fingerprint_stream);

    let verified = verify_example_scenario_runs(&fixture, 5)?;
    assert_eq!(verified.scenario_name, PARTITION_RECOVERY_SCENARIO_NAME);
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
        Predicate::GuestMarker { .. } => {
            panic!("example corpus must not require guest markers")
        }
        Predicate::Named { .. } => {
            panic!("example corpus must not require host-private named leaves")
        }
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

fn assert_ready_trigger_shape(predicate: &Predicate) {
    assert_black_box_predicate(predicate);
    let Predicate::AllOf { predicates } = predicate else {
        panic!("wait-ready trigger must be an AllOf readiness graph");
    };
    assert_eq!(predicates.len(), 4);
    assert_eq!(
        predicates
            .iter()
            .filter(|predicate| matches!(predicate, Predicate::ConsoleMatch { .. }))
            .count(),
        3
    );
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Once { predicate }
            if matches!(predicate.as_ref(), Predicate::CoveragePoint { node, .. } if node.name == "db-0")
    )));
}

fn assert_partition_injection(actions: &[Action]) {
    assert!(actions.iter().any(|action| {
        matches!(
            action,
            Action::InjectFault {
                tag,
                fault: MembershipFault::Isolate { node },
            } if tag.name == "split" && node.name == "db-0"
        )
    }));
}

fn assert_convergence_trigger_shape(predicate: &Predicate) {
    assert_black_box_predicate(predicate);
    let Predicate::AllOf { predicates } = predicate else {
        panic!("pass-on-converge trigger must combine network convergence and quiescence");
    };
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Once { predicate }
            if matches!(predicate.as_ref(), Predicate::AssertionState { name, state } if name.name == "split-active" && *state == AssertionPhase::Satisfied)
    )));
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Not { predicate }
            if matches!(predicate.as_ref(), Predicate::FaultActive { tag } if tag.name == "split")
    )));
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Once { predicate }
            if matches!(predicate.as_ref(), Predicate::NetworkMatch { link: Some(link), .. } if link.name == "db-0--db-1")
    )));
    assert!(
        predicates
            .iter()
            .any(|predicate| matches!(predicate, Predicate::Quiescent))
    );
}

fn outcome_kind(
    run: &crucible::ExampleScenarioRunReport,
    assertion: &str,
) -> HostAssertionOutcomeKind {
    run.assertion_report
        .outcomes()
        .iter()
        .find(|outcome| outcome.assertion.name == assertion)
        .map(|outcome| outcome.kind)
        .expect("assertion should have an outcome")
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
