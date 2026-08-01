//! Gates debug target resolution from operator-facing coordinates.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::error::Error;

use crucible::test_support::{
    condition_observation_entry_for_test, condition_open_payload_entry_for_test,
};
use crucible::{
    AssertionId, AssertionPhase, ChoiceTag, Configuration, DebugAttachRequest,
    DebugDivergenceCoordinate, DebugFailureFooterCommand, DebugTargetResolverRequest,
    DebugTargetSelector, EngineError, EventAttributeValue, EventDiagnosticPayload, EventLevel,
    EventLogCausalDivergencePoint, EventLogIcountStamp, EventPayload, EventSource, Icount, NodeId,
    NodeTemplate, ObservableEvent, OverrideDecision, ReadyPoint, SchedulerEventLogClass,
    SchedulerEventLogPayload, SchedulingPoint, TemporalGraph, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode, bake, try_step,
};

#[test]
fn debug_target_resolver_accepts_all_t_dbg_7_selectors() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-target-resolver")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/target", "first"))?;
    let second = try_step(&first, override_decision("debug/target", "second"))?;
    let third = try_step(&second, override_decision("debug/target", "third"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.materialize_checkpoint(&first)?;
    graph.record_thin_checkpoint(&second)?;
    graph.record_thin_checkpoint(&third)?;
    let attach = graph.debug_attach(&attach_request(&third)?)?;
    let event_log = vec![
        condition_observation_entry_for_test(
            7,
            &ObservableEvent::assertion_state_changed(
                VirtualTime { ticks: 1 },
                assertion_id("still-ok"),
                AssertionPhase::Satisfied,
            ),
        ),
        condition_observation_entry_for_test(
            9,
            &ObservableEvent::assertion_state_changed(
                VirtualTime { ticks: 2 },
                assertion_id("first-failure"),
                AssertionPhase::Violated,
            ),
        ),
    ];

    let by_at = graph.debug_resolve_target(
        &DebugTargetResolverRequest::new(
            third.clone(),
            DebugTargetSelector::at_node_icount(node_id("guest-a"), Icount { retired: 102 }),
        ),
        &event_log,
    )?;
    assert_eq!(by_at.target_configuration, second.id());
    assert!(by_at.proves_debug_target_resolution());
    assert_eq!(
        graph
            .debug_goto(&attach, &by_at.goto_request)?
            .target_configuration,
        second.id()
    );

    let by_event = graph.debug_resolve_target(
        &DebugTargetResolverRequest::new(third.clone(), DebugTargetSelector::at_event(7))
            .with_event_coordinate(7, first.clone()),
        &event_log,
    )?;
    assert_eq!(by_event.target_configuration, first.id());
    assert!(by_event.proves_debug_target_resolution());
    assert_eq!(
        graph
            .debug_goto(&attach, &by_event.goto_request)?
            .target_configuration,
        first.id()
    );

    let by_failure = graph.debug_resolve_target(
        &DebugTargetResolverRequest::new(third.clone(), DebugTargetSelector::at_failure())
            .with_event_coordinate(9, second.clone())
            .with_failure_footer_artifact("./.crucible/repro-first-failure.crucible"),
        &event_log,
    )?;
    assert_eq!(by_failure.failure_event_sequence, Some(9));
    assert_eq!(by_failure.target_configuration, second.id());
    assert!(by_failure.proves_debug_target_resolution());
    assert!(by_failure.has_copy_pasteable_at_failure_footer());
    assert_eq!(
        graph
            .debug_goto(&attach, &by_failure.goto_request)?
            .target_configuration,
        second.id()
    );

    let open_failure_log = vec![open_assertion_violation_entry(11)];
    let by_open_failure = graph.debug_resolve_target(
        &DebugTargetResolverRequest::new(third.clone(), DebugTargetSelector::at_failure())
            .with_event_coordinate(11, second.clone()),
        &open_failure_log,
    )?;
    assert_eq!(by_open_failure.failure_event_sequence, Some(11));
    assert_eq!(by_open_failure.target_configuration, second.id());
    assert!(by_open_failure.proves_debug_target_resolution());

    let by_checkpoint = graph.debug_resolve_target(
        &DebugTargetResolverRequest::new(
            third.clone(),
            DebugTargetSelector::at_checkpoint(first.id()),
        ),
        &event_log,
    )?;
    assert_eq!(by_checkpoint.target_configuration, first.id());
    assert!(by_checkpoint.proves_debug_target_resolution());

    let divergence_point = EventLogCausalDivergencePoint {
        raw_index: 1,
        at: EventLogIcountStamp {
            node: Some(node_id("guest-a")),
            icount: Icount { retired: 102 },
        },
        source: EventSource::Node {
            node: node_id("guest-a"),
        },
        kind: String::from("assertion_state_changed"),
    };
    let divergence = DebugDivergenceCoordinate::from_event_log_causal_divergence(&divergence_point)
        .ok_or("node-local divergence point should convert")?;
    let by_divergence = graph.debug_resolve_target(
        &DebugTargetResolverRequest::new(
            third.clone(),
            DebugTargetSelector::divergence(divergence),
        ),
        &event_log,
    )?;
    assert_eq!(by_divergence.target_configuration, second.id());
    assert_eq!(
        by_divergence
            .divergence
            .as_ref()
            .map(|coordinate| coordinate.kind.as_str()),
        Some("assertion_state_changed")
    );
    assert!(by_divergence.proves_debug_target_resolution());
    assert_eq!(
        by_divergence.resolved_coordinate,
        crucible::DebugCoordinate::configuration(second.clone())
    );
    assert_eq!(
        graph
            .debug_goto(&attach, &by_divergence.goto_request)?
            .target_configuration,
        second.id()
    );

    let rounded_divergence = graph
        .debug_resolve_target(
            &DebugTargetResolverRequest::new(
                third,
                DebugTargetSelector::divergence(DebugDivergenceCoordinate::new(
                    node_id("guest-a"),
                    Icount { retired: 150 },
                    "assertion_state_changed",
                )),
            ),
            &event_log,
        )
        .unwrap_err();
    assert!(matches!(
        rounded_divergence,
        EngineError::DebugTimeTravelCoordinateNotFound { .. }
    ));

    let quoted_footer = DebugFailureFooterCommand::new("./artifact dir/repro 'one'.crucible");
    assert_eq!(
        quoted_footer.debug_command,
        "crucible debug './artifact dir/repro '\\''one'\\''.crucible' --at-failure"
    );
    assert!(quoted_footer.is_copy_pasteable_at_failure());

    Ok(())
}

#[test]
fn at_failure_requires_assertion_violation_event() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-target-resolver-no-failure")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/target", "first"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.record_thin_checkpoint(&first)?;
    let event_log = vec![condition_observation_entry_for_test(
        7,
        &ObservableEvent::assertion_state_changed(
            VirtualTime { ticks: 1 },
            assertion_id("still-ok"),
            AssertionPhase::Satisfied,
        ),
    )];

    let error = graph
        .debug_resolve_target(
            &DebugTargetResolverRequest::new(first.clone(), DebugTargetSelector::at_failure()),
            &event_log,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        EngineError::DebugTargetResolverFailureNotFound { .. }
    ));

    let missing_event = graph
        .debug_resolve_target(
            &DebugTargetResolverRequest::new(first.clone(), DebugTargetSelector::at_event(99))
                .with_event_coordinate(99, first),
            &event_log,
        )
        .unwrap_err();
    assert!(matches!(
        missing_event,
        EngineError::DebugTimeTravelMissingEventCoordinate { .. }
    ));

    Ok(())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-debug-target-resolver={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId {
        name: name.to_owned(),
    }
}

fn override_decision(point: &str, choice: &str) -> crucible::Decision {
    crucible::Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

fn attach_request(configuration: &Configuration) -> Result<DebugAttachRequest, EngineError> {
    DebugAttachRequest::new(
        configuration.clone(),
        node_id("guest-a"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )
}

fn open_assertion_violation_entry(sequence: u64) -> crucible::SchedulerEventLogEntry {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("id"),
        EventAttributeValue::String(String::from("open-first-failure")),
    );
    attributes.insert(
        String::from("new_state"),
        EventAttributeValue::String(String::from("Violated")),
    );
    condition_open_payload_entry_for_test(
        sequence,
        VirtualTime { ticks: sequence },
        SchedulerEventLogClass::Causal,
        EventPayload::new("assertion_state_changed", attributes),
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "compat.assertion_state_changed",
            EventLevel::Info,
            BTreeMap::new(),
        )),
    )
}
