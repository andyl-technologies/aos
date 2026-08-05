//! Checks RFC-0010 built-in worked-example corpus coverage.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AssertionPhase, CRASH_RESTART_SCENARIO_NAME, Decision, ExampleCorpusError,
    ExampleScenarioRunOutcome, FAULT_CAMPAIGN_FAMILY_NAME, FindingDiscoveryPath,
    GuestAssertionKind, GuestWorkloadBinary, GuestWorkloadParameterKey, HAPPY_PATH_SCENARIO_NAME,
    HostAssertionOutcomeKind, IoEventKind, MembershipFault, ObservableEventPayload,
    PARTITION_RECOVERY_SCENARIO_NAME, Predicate, Property, RestartPolicy, ScenarioDefForm,
    SchedulerTopologyChangeTrigger, UnifiedGraphOperationKind, WhiteBoxPolicy,
    built_in_example_corpus, crash_restart_scenario, fault_campaign_family, happy_path_scenario,
    partition_recovery_scenario, run_example_scenario, run_fault_campaign_example_default,
    verify_example_scenario_runs,
};

#[test]
fn happy_path_is_shipped_as_builtin_corpus_fixture() -> Result<(), ExampleCorpusError> {
    let corpus = built_in_example_corpus()?;
    assert_eq!(corpus.len(), 3);
    let fixture = corpus
        .iter()
        .find(|fixture| fixture.name == HAPPY_PATH_SCENARIO_NAME)
        .expect("happy path should be shipped in the built-in corpus");

    assert_eq!(fixture.name, HAPPY_PATH_SCENARIO_NAME);
    assert_eq!(fixture.rfc_section, "33.A.1");
    assert!(fixture.zero_guest_components);
    assert!(!fixture.requires_white_box);
    assert!(fixture.scenario.world().vm_nodes().len() == 2);
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
    assert!(!fixture.zero_guest_components);
    assert!(fixture.requires_white_box);
    assert_eq!(fixture.scenario.world().vm_nodes().len(), 3);
    assert_eq!(fixture.scenario.world().links().len(), 3);
    Ok(())
}

#[test]
fn crash_restart_is_shipped_as_builtin_corpus_fixture() -> Result<(), ExampleCorpusError> {
    let corpus = built_in_example_corpus()?;
    let fixture = corpus
        .iter()
        .find(|fixture| fixture.name == CRASH_RESTART_SCENARIO_NAME)
        .expect("crash restart should be shipped in the built-in corpus");

    assert_eq!(fixture.rfc_section, "33.A.3");
    assert!(!fixture.zero_guest_components);
    assert!(fixture.requires_white_box);
    assert_eq!(fixture.scenario.world().vm_nodes().len(), 3);
    assert_eq!(fixture.scenario.world().links().len(), 3);
    Ok(())
}

#[test]
fn fault_campaign_is_shipped_as_builtin_family() -> Result<(), ExampleCorpusError> {
    let family = fault_campaign_family()?;
    assert_eq!(FAULT_CAMPAIGN_FAMILY_NAME, "fault-campaign.fam");
    assert_eq!(family.space().seeds().len(), 8);
    assert_eq!(family.space().topology_size().min(), 3);
    assert_eq!(family.space().topology_size().max(), 5);
    assert_eq!(
        family.space().topology_shapes(),
        &[crucible::TopologyShape::Ring, crucible::TopologyShape::Mesh]
    );
    assert!(
        family.space().fault_density().min().millionths() > 0,
        "A.4 family must generate an actual fault campaign"
    );

    let sample = family.instantiate_sample(0)?;
    assert_eq!(sample.form().world().vm_nodes().len(), 3);
    assert!(!sample.form().plan().entries().is_empty());
    assert!(
        sample
            .form()
            .plan()
            .entries()
            .iter()
            .any(|entry| matches!(entry, crucible::PlanEntry::Activate { .. }))
    );
    assert!(
        sample
            .form()
            .properties()
            .assertions()
            .iter()
            .any(|assertion| assertion.id.name == "no-split-brain")
    );
    assert!(sample.form().world().vm_nodes().iter().all(|node| {
        node.white_box == WhiteBoxPolicy::Enabled && node.cmdline.contains("cluster=crucible-a4")
    }));
    Ok(())
}

#[test]
fn fault_campaign_fuzz_replay_save_resume_and_fork_are_proven() -> Result<(), ExampleCorpusError> {
    let report = run_fault_campaign_example_default()?;
    assert_eq!(report.family_name, FAULT_CAMPAIGN_FAMILY_NAME);
    assert_eq!(
        report.fuzz_run.iterations.len(),
        report.config.iterations as usize
    );
    assert_eq!(report.coverage_fingerprints.len(), 2);
    assert!(
        report
            .fuzz_run
            .iterations
            .iter()
            .any(|iteration| iteration.new_coverage)
    );
    assert_eq!(
        report.finding.discovery_path,
        FindingDiscoveryPath::CoverageGuidedFuzzing
    );
    assert!(!report.violation_observations.is_empty());
    assert!(!report.violation_event_log.is_empty());
    assert!(report.violation_observations.iter().any(|observation| {
        matches!(
            observation.payload(),
            ObservableEventPayload::GuestAssertionMarker { marker, .. }
                if marker.id.name == "no-split-brain"
                    && marker.kind == GuestAssertionKind::Unreachable
                    && marker.condition
        )
    }));
    assert!(report.violation_report.verdict().is_failed());
    assert!(
        report
            .violation_report
            .violations()
            .iter()
            .any(|violation| {
                violation.assertion.name == "no-split-brain"
                    && violation
                        .detail
                        .contains("guest unreachable marker was reached")
            })
    );
    assert!(
        report
            .violation_report
            .outcomes()
            .iter()
            .any(|outcome| outcome.assertion.name == "no-split-brain"
                && outcome.kind == HostAssertionOutcomeKind::Violated)
    );
    assert_eq!(
        report.violation_replay.artifact,
        report.finding.artifact.id()
    );
    assert_eq!(
        report.violation_replay.replay.artifact,
        report.finding.artifact.id()
    );
    assert_eq!(
        report.violation_replay.expected,
        report.violation_replay.reproduced
    );
    assert_eq!(report.violation_report, report.violation_replay.reproduced);
    assert!(
        report
            .violation_replay
            .reproduced
            .violations()
            .iter()
            .any(
                |violation| violation.reproduction_artifact == report.finding.artifact.id()
                    && violation.assertion.name == "no-split-brain"
            )
    );
    assert_ne!(
        report.finding.configuration,
        report.discovered_iteration.configuration_id()
    );
    assert_eq!(
        report.finding.artifact.scenario_form().id(),
        report.discovered_iteration.scenario.form().id()
    );
    assert_eq!(
        report.finding.artifact.schedule().len(),
        report.discovered_iteration.schedule().len() + 1
    );
    assert!(matches!(
        report.finding.artifact.schedule().decisions().last(),
        Some(Decision::Override(override_decision))
            if override_decision
                .point
                .key
                .contains("fault-campaign/violation")
                && override_decision.choice.name.contains("guest-assertion-marker")
    ));
    assert_eq!(report.finding.artifact.replay()?, report.finding.replay);
    assert_eq!(
        report.fuzz_report.operation,
        UnifiedGraphOperationKind::CoverageGuidedFuzzing
    );
    assert_eq!(
        report.reproduction_report.operation,
        UnifiedGraphOperationKind::ReproductionArtifact
    );
    assert_eq!(
        report.save_report.operation,
        UnifiedGraphOperationKind::Save
    );
    assert_eq!(
        report.resume_report.operation,
        UnifiedGraphOperationKind::Resume
    );
    assert_eq!(
        report.fork_report.operation,
        UnifiedGraphOperationKind::Fork
    );
    assert_eq!(report.save.configuration, report.resume.configuration);
    assert_eq!(report.save.checkpoint, report.resume.checkpoint);
    assert_ne!(report.fork.branch.id(), report.save.configuration);
    assert_eq!(report.fork.branch.schedule.len(), 1);
    assert!(matches!(
        report.fork.branch.schedule.decisions(),
        [Decision::Override(_)]
    ));
    Ok(())
}

#[test]
fn happy_path_authoring_uses_only_black_box_guest_observables() -> Result<(), ExampleCorpusError> {
    let fixture = happy_path_scenario()?;
    let world = fixture.scenario.world();
    let nodes = world.vm_nodes();
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
    assert_eq!(world.vm_nodes().len(), 3);
    for node in world.vm_nodes() {
        assert_eq!(node.white_box, WhiteBoxPolicy::Enabled);
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
    assert!(assertion_names.contains(&"replicas-reconciled"));
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
fn crash_restart_uses_observable_trigger_graph() -> Result<(), ExampleCorpusError> {
    let fixture = crash_restart_scenario()?;
    let world = fixture.scenario.world();
    assert_eq!(world.vm_nodes().len(), 3);
    for node in world.vm_nodes() {
        assert_eq!(node.white_box, WhiteBoxPolicy::Enabled);
        assert!(node.kernel.is_some());
        assert!(node.root_image.is_some());
        assert!(node.cmdline.contains("store.role=replica"));
        assert!(node.cmdline.contains("cluster=crucible-a3"));
    }
    assert!(fixture.observations().iter().any(|event| matches!(
        event.payload(),
        ObservableEventPayload::IoCompletion {
            node,
            kind: IoEventKind::BlockWrite,
            payload,
        } if node.name == "db-1" && payload.windows(b"region=wal".len()).any(|window| window == b"region=wal")
    )));

    let assertion_names = fixture
        .scenario
        .properties()
        .assertions()
        .iter()
        .map(|assertion| assertion.id.name.as_str())
        .collect::<Vec<_>>();
    assert!(assertion_names.contains(&"data-not-lost"));
    assert!(assertion_names.contains(&"committed-write-survived"));
    assert!(assertion_names.contains(&"replicas-reconciled"));
    assert!(assertion_names.contains(&"reconverges"));
    let reconverges = fixture
        .scenario
        .properties()
        .assertions()
        .iter()
        .find(|assertion| assertion.id.name == "reconverges")
        .expect("crash restart declares reconverges assertion");
    assert!(matches!(
        &reconverges.property,
        Property::Eventually {
            trigger: Predicate::NodeState { node, state },
            ..
        } if node.name == "db-1" && *state == crucible::NodeLifecycle::Crashed
    ));

    let graph = fixture
        .scenario
        .plan()
        .event_graph()
        .expect("crash restart uses graph-native trigger choreography");
    assert_eq!(graph.events().len(), 3);
    let crash_after_commit = &graph.events()[0];
    let restart = &graph.events()[1];
    let pass_on_reconverge = &graph.events()[2];

    assert_eq!(crash_after_commit.id.name, "crash-after-commit");
    assert_crash_after_commit_trigger_shape(
        crash_after_commit
            .trigger
            .as_ref()
            .expect("crash trigger observes lifecycle and WAL write"),
    );
    assert!(matches!(
        &crash_after_commit.action,
        Action::InjectFault {
            tag,
            fault: MembershipFault::Crash { node, restart },
        } if tag.name == "kill" && node.name == "db-1" && *restart == RestartPolicy::FromReadyPoint
    ));

    assert_eq!(restart.id.name, "restart");
    assert!(matches!(
        restart.trigger.as_ref().expect("restart is after-triggered"),
        Predicate::After { duration, of }
            if duration.nanos == 5_000_000_000 && of.name == "crash-after-commit"
    ));
    let Action::Group(actions) = &restart.action else {
        panic!("restart must heal the crash and StartNode db-1 as a group");
    };
    assert!(actions.iter().any(|action| matches!(
        action,
        Action::HealFault { tag } if tag.name == "kill"
    )));
    assert!(actions.iter().any(|action| matches!(
        action,
        Action::StartNode { node } if node.name == "db-1"
    )));

    assert_eq!(pass_on_reconverge.id.name, "pass-on-reconverge");
    assert!(action_passes(&pass_on_reconverge.action));
    assert_crash_reconvergence_trigger_shape(
        pass_on_reconverge
            .trigger
            .as_ref()
            .expect("pass-on-reconverge has observable convergence trigger"),
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
fn crash_restart_round_trips_as_reproducible_scenario_material() -> Result<(), ExampleCorpusError> {
    let fixture = crash_restart_scenario()?;
    let toml = fixture.scenario.to_canonical_toml()?;
    assert!(toml.contains("id = \"db-0\""));
    assert!(toml.contains("id = \"db-1\""));
    assert!(toml.contains("id = \"db-2\""));
    assert!(toml.contains("cluster=crucible-a3"));
    assert!(toml.contains("crash-after-commit"));
    assert!(toml.contains("restart"));
    assert!(toml.contains("pass-on-reconverge"));
    assert!(toml.contains("data-not-lost"));
    assert!(toml.contains("reconverges"));
    assert!(toml.contains("from_ready_point") || toml.contains("from-ready-point"));

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
    assert!(outcome_names.contains(&"replicas-reconciled"));
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
        outcome_kind(&run, "replicas-reconciled"),
        HostAssertionOutcomeKind::Satisfied
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
fn crash_restart_run_passes_and_verify_runs_are_byte_identical() -> Result<(), ExampleCorpusError> {
    let fixture = crash_restart_scenario()?;
    let run = run_example_scenario(&fixture)?;
    assert_eq!(run.scenario_name, CRASH_RESTART_SCENARIO_NAME);
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
    assert!(outcome_names.contains(&"data-not-lost"));
    assert!(outcome_names.contains(&"committed-write-survived"));
    assert!(outcome_names.contains(&"replicas-reconciled"));
    assert!(outcome_names.contains(&"reconverges"));
    assert!(
        run.firings
            .iter()
            .any(|firing| firing.event().name == "pass-on-reconverge")
    );
    assert_eq!(
        outcome_kind(&run, "data-not-lost"),
        HostAssertionOutcomeKind::Passed
    );
    assert_eq!(
        outcome_kind(&run, "committed-write-survived"),
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome_kind(&run, "replicas-reconciled"),
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(
        outcome_kind(&run, "reconverges"),
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(run.reproduction.scenario_form().id(), fixture.scenario.id());
    assert_eq!(run.scheduler_crash_applications.len(), 1);
    assert_eq!(run.scheduler_crash_applications[0].node.name, "db-1");
    assert_eq!(
        run.scheduler_crash_applications[0].restart,
        RestartPolicy::FromReadyPoint
    );
    assert_eq!(run.scheduler_crash_applications[0].removed_edges.len(), 4);
    assert_eq!(run.scheduler_restart_applications.len(), 1);
    assert_eq!(run.scheduler_restart_applications[0].node.name, "db-1");
    assert!(run.scheduler_restart_applications[0].restarted);
    assert_eq!(
        run.scheduler_restart_applications[0].restart,
        RestartPolicy::FromReadyPoint
    );
    assert_eq!(
        run.scheduler_restart_applications[0].restored_edges.len(),
        4
    );
    assert!(
        run.scheduler_topology_change_applications
            .iter()
            .any(|application| application.trigger
                == SchedulerTopologyChangeTrigger::FaultActivation)
    );
    assert!(
        run.scheduler_topology_change_applications
            .iter()
            .any(|application| application.trigger == SchedulerTopologyChangeTrigger::Heal)
    );
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
            .any(|decision| match decision {
                Decision::Override(override_decision) => {
                    override_decision.choice.name.contains("io-completion")
                        && override_decision.choice.name.contains("block-write")
                }
                Decision::DeliveryOrder(_)
                | Decision::FaultFires(_)
                | Decision::RngDraw(_)
                | Decision::Preemption(_)
                | Decision::AppRandom(_)
                | Decision::ControlFault(_) => false,
            })
    );
    assert!(
        run.reproduction
            .schedule()
            .decisions()
            .iter()
            .all(|decision| match decision {
                Decision::Override(override_decision) =>
                    !override_decision
                        .choice
                        .name
                        .contains("assertion-state-changed")
                        && !override_decision
                            .choice
                            .name
                            .contains("node-state|30|db-1|crashed"),
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
    assert_eq!(verified.scenario_name, CRASH_RESTART_SCENARIO_NAME);
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
        panic!("pass-on-converge trigger must combine guest-reported convergence and quiescence");
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
            if matches!(predicate.as_ref(), Predicate::AssertionState { name, state } if name.name == "replicas-reconciled" && *state == AssertionPhase::Satisfied)
    )));
    assert!(
        predicates
            .iter()
            .any(|predicate| matches!(predicate, Predicate::Quiescent))
    );
}

fn assert_crash_after_commit_trigger_shape(predicate: &Predicate) {
    assert_black_box_predicate(predicate);
    let Predicate::AllOf { predicates } = predicate else {
        panic!("crash-after-commit trigger must combine lifecycle and WAL write observations");
    };
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::NodeState { node, state }
            if node.name == "db-1" && *state == crucible::NodeLifecycle::Started
    )));
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Once { predicate }
            if matches!(
                predicate.as_ref(),
                Predicate::IoPattern { node, kind }
                    if node.name == "db-1" && *kind == IoEventKind::BlockWrite
            )
    )));
}

fn assert_crash_reconvergence_trigger_shape(predicate: &Predicate) {
    assert_black_box_predicate(predicate);
    let Predicate::AllOf { predicates } = predicate else {
        panic!(
            "pass-on-reconverge trigger must combine restart, heal, convergence, and quiescence"
        );
    };
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Once { predicate }
            if matches!(
                predicate.as_ref(),
                Predicate::NodeState { node, state }
                    if node.name == "db-1" && *state == crucible::NodeLifecycle::Started
            )
    )));
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Not { predicate }
            if matches!(predicate.as_ref(), Predicate::FaultActive { tag } if tag.name == "kill")
    )));
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Once { predicate }
            if matches!(
                predicate.as_ref(),
                Predicate::AssertionState { name, state }
                    if name.name == "committed-write-survived"
                        && *state == AssertionPhase::Satisfied
            )
    )));
    assert!(predicates.iter().any(|predicate| matches!(
        predicate,
        Predicate::Once { predicate }
            if matches!(
                predicate.as_ref(),
                Predicate::AssertionState { name, state }
                    if name.name == "replicas-reconciled"
                        && *state == AssertionPhase::Satisfied
            )
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
