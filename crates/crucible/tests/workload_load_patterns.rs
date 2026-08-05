//! Checks RFC-0010 T-WL-4 and T-WL-5 load-pattern mappings.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, EngineError, Fault, GuestWorkloadBinary, GuestWorkloadLoadPatternFixture,
    GuestWorkloadPattern, GuestWorkloadSpikeMode, GuestWorkloadTimeSource, Icount, MembershipFault,
    NetworkFault, NodeFault, NodeTemplate, Plan, Predicate, Properties, ScenarioBuilder,
    ScenarioDefForm, Seed, WORKLOAD_HOST_WALL_CLOCK_LOAD_SHAPES_ALLOWED,
    WORKLOAD_LOAD_PATTERN_BLACK_BOX_CONFIG_SUFFICES, WORKLOAD_LOAD_PATTERN_REQUIRES_WHITE_BOX,
    WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER, WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER,
    WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER, WORKLOAD_TIME_VARIATION_REQUIRES_VIRTUAL_TIME,
    WhiteBoxPolicy,
};

#[test]
fn load_pattern_mappings_are_plain_cmdline_parameters() {
    let supported = GuestWorkloadPattern::SUPPORTED
        .map(|pattern| (pattern.display_name(), pattern.scenario_parameter_value()));
    assert_eq!(
        supported,
        [
            ("steady", "steady"),
            ("spike", "spike"),
            ("cardinality growth", "cardinality_growth"),
            ("correlated failure", "correlated_failure"),
        ]
    );
    assert_eq!(WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER, "load_pattern");
    assert_eq!(WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER, "spike_mode");
    assert_eq!(WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER, "load_time_source");
    const { assert!(WORKLOAD_LOAD_PATTERN_BLACK_BOX_CONFIG_SUFFICES) };
    const { assert!(!WORKLOAD_LOAD_PATTERN_REQUIRES_WHITE_BOX) };
    const { assert!(WORKLOAD_TIME_VARIATION_REQUIRES_VIRTUAL_TIME) };
    const { assert!(!WORKLOAD_HOST_WALL_CLOCK_LOAD_SHAPES_ALLOWED) };

    let selected = GuestWorkloadPattern::Steady.selected_cmdline("console=ttyS0 quiet");
    assert_eq!(selected, "console=ttyS0 quiet load_pattern=steady");
    assert_eq!(
        GuestWorkloadPattern::from_cmdline(&selected),
        Some(GuestWorkloadPattern::Steady)
    );

    let replaced = GuestWorkloadPattern::CardinalityGrowth
        .selected_cmdline("console=ttyS0 load_pattern=steady");
    assert_eq!(replaced, "console=ttyS0 load_pattern=cardinality_growth");
    assert_eq!(
        GuestWorkloadPattern::from_cmdline(&replaced),
        Some(GuestWorkloadPattern::CardinalityGrowth)
    );

    let spike_selected = GuestWorkloadSpikeMode::StartNodeBurst
        .selected_cmdline("console=ttyS0 spike_mode=virtual_time_rate");
    assert_eq!(spike_selected, "console=ttyS0 spike_mode=start_node_burst");
    assert_eq!(
        GuestWorkloadSpikeMode::from_cmdline(&spike_selected),
        Some(GuestWorkloadSpikeMode::StartNodeBurst)
    );

    let time_selected =
        GuestWorkloadTimeSource::VirtualTime.selected_cmdline("console=ttyS0 load_time_source=old");
    assert_eq!(time_selected, "console=ttyS0 load_time_source=virtual_time");
    assert_eq!(
        GuestWorkloadTimeSource::from_cmdline(&time_selected),
        Some(GuestWorkloadTimeSource::VirtualTime)
    );
}

#[test]
fn steady_fixture_is_guest_loop_plus_rate_parameter() -> Result<(), EngineError> {
    let fixture = GuestWorkloadLoadPatternFixture::steady()?;
    assert_eq!(fixture.pattern(), GuestWorkloadPattern::Steady);
    assert_eq!(fixture.spike_mode(), None);
    assert_empty_plan(fixture.plan());

    let node = only_node(fixture.world().vm_nodes());
    assert_eq!(node.guest_workload(), Some(GuestWorkloadBinary::ClientLoop));
    assert_eq!(
        node.guest_workload_pattern(),
        Some(GuestWorkloadPattern::Steady)
    );
    assert_eq!(node.guest_workload_spike_mode(), None);
    assert_eq!(node.white_box, WhiteBoxPolicy::Disabled);
    assert!(node.cmdline.contains("rate_per_sec=100"));
    Ok(())
}

#[test]
fn spike_fixture_can_be_guest_virtual_time_rate() -> Result<(), EngineError> {
    let fixture = GuestWorkloadLoadPatternFixture::spike_virtual_time_rate()?;
    assert_eq!(fixture.pattern(), GuestWorkloadPattern::Spike);
    assert_eq!(
        fixture.spike_mode(),
        Some(GuestWorkloadSpikeMode::VirtualTimeRate)
    );
    assert_eq!(
        fixture.time_source(),
        Some(GuestWorkloadTimeSource::VirtualTime)
    );
    assert_empty_plan(fixture.plan());

    let node = only_node(fixture.world().vm_nodes());
    assert_eq!(
        node.guest_workload_pattern(),
        Some(GuestWorkloadPattern::Spike)
    );
    assert_eq!(
        node.guest_workload_spike_mode(),
        Some(GuestWorkloadSpikeMode::VirtualTimeRate)
    );
    assert_eq!(
        node.guest_workload_time_source(),
        Some(GuestWorkloadTimeSource::VirtualTime)
    );
    assert!(node.cmdline.contains("base_rate_per_sec=10"));
    assert!(node.cmdline.contains("peak_rate_per_sec=500"));
    assert!(node.cmdline.contains("spike_at_ticks=50"));
    Ok(())
}

#[test]
fn spike_fixture_can_be_planned_start_node_burst() -> Result<(), EngineError> {
    let fixture = GuestWorkloadLoadPatternFixture::spike_start_node_burst()?;
    assert_eq!(fixture.pattern(), GuestWorkloadPattern::Spike);
    assert_eq!(
        fixture.spike_mode(),
        Some(GuestWorkloadSpikeMode::StartNodeBurst)
    );
    assert_eq!(
        fixture.time_source(),
        Some(GuestWorkloadTimeSource::VirtualTime)
    );
    assert_eq!(fixture.world().vm_nodes().len(), 2);
    assert!(
        fixture
            .world()
            .vm_nodes()
            .iter()
            .all(|node| node.guest_workload_pattern() == Some(GuestWorkloadPattern::Spike))
    );
    assert!(fixture.world().vm_nodes().iter().all(|node| {
        node.guest_workload_time_source() == Some(GuestWorkloadTimeSource::VirtualTime)
    }));

    let graph = fixture
        .plan()
        .event_graph()
        .expect("StartNode burst fixture should use an event graph plan");
    assert_eq!(graph.events().len(), 2);
    let hold = graph
        .events()
        .iter()
        .find(|event| event.id.name == "hold-burst-at-genesis")
        .expect("burst fixture should hold the burst node inactive at genesis");
    assert!(hold.trigger.is_none());
    assert!(matches!(
        &hold.action,
        Action::InjectFault {
            fault: MembershipFault::NotYetJoined { node },
            ..
        } if node.name == "client-burst"
    ));

    let event = graph
        .events()
        .iter()
        .find(|event| event.id.name == "start-burst-at-vt")
        .expect("burst fixture should schedule a virtual-time start event");
    assert!(matches!(
        event.trigger.as_ref(),
        Some(Predicate::At { at }) if at.ticks == 50
    ));
    let Action::Group(actions) = &event.action else {
        panic!("start-burst event should heal the hold and start the node");
    };
    assert!(actions.iter().any(|action| matches!(
        action,
        Action::HealFault { tag } if tag.name == "burst-not-yet-joined"
    )));
    assert!(actions.iter().any(|action| matches!(
        action,
        Action::StartNode { node } if node.name == "client-burst"
    )));
    Ok(())
}

#[test]
fn cardinality_growth_fixture_is_guest_key_policy() -> Result<(), EngineError> {
    let fixture = GuestWorkloadLoadPatternFixture::cardinality_growth()?;
    assert_eq!(fixture.pattern(), GuestWorkloadPattern::CardinalityGrowth);
    assert_eq!(
        fixture.time_source(),
        Some(GuestWorkloadTimeSource::VirtualTime)
    );
    assert_empty_plan(fixture.plan());

    let node = only_node(fixture.world().vm_nodes());
    assert_eq!(
        node.guest_workload_pattern(),
        Some(GuestWorkloadPattern::CardinalityGrowth)
    );
    assert_eq!(
        node.guest_workload_time_source(),
        Some(GuestWorkloadTimeSource::VirtualTime)
    );
    assert!(node.cmdline.contains("initial_keys=8"));
    assert!(node.cmdline.contains("key_growth_per_sec=4"));
    assert!(node.cmdline.contains("key_cap=1024"));
    Ok(())
}

#[test]
fn correlated_failure_fixture_is_an_event_graph_campaign() -> Result<(), EngineError> {
    let fixture = GuestWorkloadLoadPatternFixture::correlated_failure_campaign()?;
    assert_eq!(fixture.pattern(), GuestWorkloadPattern::CorrelatedFailure);
    assert_eq!(fixture.world().vm_nodes().len(), 2);
    assert_eq!(fixture.world().links().len(), 1);
    let graph = fixture
        .plan()
        .event_graph()
        .expect("correlated-failure fixture should use an event graph");
    assert_eq!(graph.events().len(), 5);
    assert!(graph.events().iter().any(|event| matches!(
        &event.action,
        Action::InjectFault {
            fault: MembershipFault::Taxonomy {
                fault: Fault::Network(NetworkFault::Partition { .. })
            },
            ..
        }
    )));
    assert!(graph.events().iter().any(|event| matches!(
        &event.action,
        Action::InjectFault {
            fault: MembershipFault::Taxonomy {
                fault: Fault::Network(NetworkFault::Loss { .. })
            },
            ..
        }
    )));
    assert!(graph.events().iter().any(|event| matches!(
        &event.action,
        Action::InjectFault {
            fault: MembershipFault::Taxonomy {
                fault: Fault::Node(NodeFault::Crash { .. })
            },
            ..
        }
    )));
    Ok(())
}

#[test]
fn load_pattern_fixtures_change_scenario_identity_without_global_seed() -> Result<(), EngineError> {
    let seed = Seed::from_u64(7);
    let steady = GuestWorkloadLoadPatternFixture::steady()?.scenario_def(seed)?;
    let cardinality = GuestWorkloadLoadPatternFixture::cardinality_growth()?.scenario_def(seed)?;
    let correlated =
        GuestWorkloadLoadPatternFixture::correlated_failure_campaign()?.scenario_def(seed)?;

    assert_ne!(steady.id(), cardinality.id());
    assert_ne!(cardinality.id(), correlated.id());
    assert_eq!(steady.seed(), cardinality.seed());
    assert_eq!(cardinality.seed(), correlated.seed());
    Ok(())
}

#[test]
fn time_varying_load_fixtures_reproduce_bit_identically() -> Result<(), EngineError> {
    assert_fixture_reproduces(GuestWorkloadLoadPatternFixture::spike_virtual_time_rate)?;
    assert_fixture_reproduces(GuestWorkloadLoadPatternFixture::spike_start_node_burst)?;
    assert_fixture_reproduces(GuestWorkloadLoadPatternFixture::cardinality_growth)?;
    Ok(())
}

#[test]
fn load_pattern_reserved_parameters_reject_unknown_and_duplicate_values() {
    assert_unsupported_pattern(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 load_pattern=badpattern"),
            )
            .seed(Seed::from_u64(7))
            .build(),
        "badpattern",
    );

    assert_duplicate_pattern(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 load_pattern=steady load_pattern=spike"),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );

    assert_unsupported_spike_mode(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 spike_mode=badmode"),
            )
            .seed(Seed::from_u64(7))
            .build(),
        "badmode",
    );

    assert_duplicate_spike_mode(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 }).cmdline(
                    "console=ttyS0 spike_mode=virtual_time_rate spike_mode=start_node_burst",
                ),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );

    assert_missing_spike_mode(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 load_pattern=spike"),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );

    assert_stray_spike_mode(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 load_pattern=steady spike_mode=start_node_burst"),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );

    assert_unsupported_time_source(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 }).cmdline(
                    "console=ttyS0 load_pattern=cardinality_growth load_time_source=host_wall_clock",
                ),
            )
            .seed(Seed::from_u64(7))
            .build(),
        "host_wall_clock",
    );

    assert_duplicate_time_source(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 }).cmdline(
                    "console=ttyS0 load_time_source=virtual_time load_time_source=virtual_time",
                ),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );

    assert_missing_virtual_time_source(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 load_pattern=cardinality_growth"),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );

    assert_missing_virtual_time_source(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 load_pattern=spike spike_mode=virtual_time_rate"),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );

    assert_stray_time_source(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 load_pattern=steady load_time_source=virtual_time"),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );
}

fn assert_fixture_reproduces(
    build: fn() -> Result<GuestWorkloadLoadPatternFixture, EngineError>,
) -> Result<(), EngineError> {
    let seed = Seed::from_u64(7);
    let first = build()?;
    let second = build()?;
    let first_form = ScenarioDefForm::from_components_with_app_random_draw_cap(
        first.world(),
        first.plan(),
        &Properties::empty(),
        seed,
        10,
    )?;
    let second_form = ScenarioDefForm::from_components_with_app_random_draw_cap(
        second.world(),
        second.plan(),
        &Properties::empty(),
        seed,
        10,
    )?;

    assert_eq!(
        first.world().canonical_bytes(),
        second.world().canonical_bytes()
    );
    assert_eq!(
        first.plan().canonical_bytes(),
        second.plan().canonical_bytes()
    );
    assert_eq!(
        first_form.to_compact_binary(),
        second_form.to_compact_binary()
    );
    assert_eq!(
        first_form.to_canonical_toml()?,
        second_form.to_canonical_toml()?
    );
    assert_eq!(
        first_form.scenario_def().id(),
        second_form.scenario_def().id()
    );
    Ok(())
}

fn assert_empty_plan(plan: &Plan) {
    assert!(plan.entries().is_empty());
    assert!(plan.event_graph().is_none());
}

fn only_node(nodes: &[crucible::WorldNode]) -> &crucible::WorldNode {
    assert_eq!(nodes.len(), 1);
    &nodes[0]
}

fn assert_unsupported_pattern<T: std::fmt::Debug>(result: Result<T, EngineError>, expected: &str) {
    match result {
        Err(EngineError::WorldNodeUnsupportedWorkloadPattern { value, .. }) => {
            assert_eq!(value, expected);
        }
        other => panic!("expected unsupported workload pattern {expected}, got {other:?}"),
    }
}

fn assert_duplicate_pattern<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeDuplicateWorkloadPattern { .. }) => {}
        other => panic!("expected duplicate workload pattern rejection, got {other:?}"),
    }
}

fn assert_unsupported_spike_mode<T: std::fmt::Debug>(
    result: Result<T, EngineError>,
    expected: &str,
) {
    match result {
        Err(EngineError::WorldNodeUnsupportedWorkloadSpikeMode { value, .. }) => {
            assert_eq!(value, expected);
        }
        other => panic!("expected unsupported workload spike mode {expected}, got {other:?}"),
    }
}

fn assert_duplicate_spike_mode<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeDuplicateWorkloadSpikeMode { .. }) => {}
        other => panic!("expected duplicate workload spike mode rejection, got {other:?}"),
    }
}

fn assert_missing_spike_mode<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeWorkloadSpikePatternMissingMode { .. }) => {}
        other => panic!("expected missing workload spike mode rejection, got {other:?}"),
    }
}

fn assert_stray_spike_mode<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeWorkloadSpikeModeWithoutSpikePattern { .. }) => {}
        other => panic!("expected stray workload spike mode rejection, got {other:?}"),
    }
}

fn assert_unsupported_time_source<T: std::fmt::Debug>(
    result: Result<T, EngineError>,
    expected: &str,
) {
    match result {
        Err(EngineError::WorldNodeUnsupportedWorkloadTimeSource { value, .. }) => {
            assert_eq!(value, expected);
        }
        other => panic!("expected unsupported workload time source {expected}, got {other:?}"),
    }
}

fn assert_duplicate_time_source<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeDuplicateWorkloadTimeSource { .. }) => {}
        other => panic!("expected duplicate workload time source rejection, got {other:?}"),
    }
}

fn assert_missing_virtual_time_source<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeWorkloadTimeVaryingPatternMissingVirtualTimeSource {
            ..
        }) => {}
        other => panic!("expected missing virtual-time source rejection, got {other:?}"),
    }
}

fn assert_stray_time_source<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeWorkloadTimeSourceWithoutTimeVaryingPattern { .. }) => {}
        other => panic!("expected stray workload time source rejection, got {other:?}"),
    }
}
