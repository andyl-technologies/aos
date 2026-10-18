//! Trigger unit tests separated from production condition and event-graph code.

use std::collections::BTreeMap;

use super::*;
use crate::model::{NodeTemplate, RngDecision, VmArchitecture, WorldNode};
use crate::scheduler::EventDiagnosticPayload;

#[test]
fn ready_point_keeps_raw_retirement_separate_from_exact_time() {
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let raw = Icount { retired: 20 };
    let fixed = resolution_from_icount(&node, ReadyPointResolutionKind::FixedIcount, raw)
        .unwrap_or_else(|error| panic!("fixed ready point should fit: {error}"));
    let clock = resolution_from_virtual_time(
        &node,
        ReadyPointResolutionKind::FirstNetworkIdle,
        VirtualTime { ticks: 1_001 },
    )
    .unwrap_or_else(|error| panic!("clock ready point should resolve: {error}"));

    assert_eq!(fixed.icount(), Some(raw));
    assert_eq!(fixed.virtual_time(), VirtualTime { ticks: 1_000 });
    assert_eq!(clock.icount(), None);
    assert_eq!(clock.virtual_time(), VirtualTime { ticks: 1_001 });
}

#[test]
fn backend_poll_boundary_preserves_physical_icount_and_moves_guest_pulses_forward() {
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let boundary = VirtualTime { ticks: 10 };
    let console =
        ObservableEvent::console_output(VirtualTime { ticks: 5 }, node.clone(), b"ready".to_vec())
            .normalize_backend_poll_boundary(boundary);
    let coverage = ObservableEvent::coverage_block(Icount { retired: 5 }, node.clone(), 0x4010, 4)
        .normalize_backend_poll_boundary(boundary);
    let marker = ObservableEvent::guest_marker(
        Icount { retired: 5 },
        node.clone(),
        MarkerId::from_name("commit"),
    )
    .normalize_backend_poll_boundary(boundary);
    let network =
        ObservableEvent::network_delivered(VirtualTime { ticks: 5 }, None, b"frame".to_vec())
            .normalize_backend_poll_boundary(boundary);
    let completion = ObservableEvent::io_completion(
        VirtualTime { ticks: 5 },
        node.clone(),
        IoEventKind::BlockRead,
        b"done".to_vec(),
    )
    .normalize_backend_poll_boundary(boundary);
    let node_state =
        ObservableEvent::node_state(VirtualTime { ticks: 5 }, node, NodeLifecycle::Started)
            .normalize_backend_poll_boundary(boundary);

    assert_eq!(console.at(), boundary);
    assert_eq!(coverage.at(), boundary);
    assert_eq!(marker.at(), boundary);
    assert_eq!(network.at(), VirtualTime { ticks: 5 });
    assert_eq!(completion.at(), VirtualTime { ticks: 5 });
    assert_eq!(node_state.at(), VirtualTime { ticks: 5 });
    assert!(matches!(
        coverage.payload(),
        ObservableEventPayload::CoverageBlock {
            execution_icount: Icount { retired: 5 },
            ..
        }
    ));
    assert!(matches!(
        marker.payload(),
        ObservableEventPayload::GuestMarker {
            retired_icount: Icount { retired: 5 },
            ..
        }
    ));
}

#[test]
fn polled_guest_marker_after_a_later_boundary_reaches_assertion_and_graph() {
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let marker = MarkerId::from_name("selected-fast-q7");
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("marker world should build");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("known-midpoint-failure"),
            message: String::from("selected fast recovery is unsafe"),
            property: Property::Always {
                predicate: Predicate::not(Predicate::guest_marker(marker.clone())),
            },
        }],
    )
    .expect("marker property should validate");
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            EventId::from_name("marker-received"),
            Some(Predicate::once(Predicate::guest_marker(marker.clone()))),
            Action::Pass,
        )],
        &world,
    )
    .expect("marker graph should validate");

    let boundary = VirtualTime { ticks: 100 };
    let physical_marker = ObservableEvent::guest_marker(Icount { retired: 5 }, node, marker);
    let observed_marker = physical_marker.normalize_backend_poll_boundary(boundary);
    let entries = vec![
        SchedulerEventLogEntry::evaluation_boundary(
            0,
            boundary,
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
        SchedulerEventLogEntry::with_payload_for_test(
            1,
            observed_marker.at(),
            SchedulerEventLogPayload::Observable(observed_marker.payload().clone()),
        ),
        SchedulerEventLogEntry::evaluation_boundary(
            2,
            boundary,
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    let prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries(entries)
        .expect("atomic marker batch should form a checked prefix");

    let mut assertions =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(&world);
    let outcomes = assertions.observe_prefix(&prefix, &mut BlackBoxHostOracle);
    assert!(outcomes.iter().any(|outcome| {
        outcome.assertion.name == "known-midpoint-failure"
            && outcome.kind == HostAssertionOutcomeKind::Violated
    }));

    let mut pass = ConditionEvaluationPass::from_log_prefix(prefix, false_condition_leaf)
        .with_world_white_box_policies(&world);
    let firings = pass.evaluate_event_graph(&graph, &mut EventGraphState::new());
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "marker-received");
}

#[test]
fn causal_projection_comparison_ignores_observational_entries() {
    let causal = SchedulerEventLogEntry::with_payload_for_test(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("causal-projection"),
            value: 11,
        })),
    );
    let diagnostic = SchedulerEventLogEntry::with_payload_for_test(
        1,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "executor.poll",
            EventLevel::Warn,
            BTreeMap::new(),
        )),
    );

    let expected = vec![causal.clone()];
    let reproduced = vec![diagnostic, causal];

    assert_ne!(expected, reproduced);
    assert!(event_log_causal_projections_match(&expected, &reproduced));
}

#[test]
fn facts_through_point_preserves_resumed_event_log_base_sequence() {
    let first = SchedulerEventLogEntry::with_payload_for_test(
        5,
        VirtualTime { ticks: 5 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("resumed-prefix-a"),
            value: 17,
        })),
    );
    let second = SchedulerEventLogEntry::with_payload_for_test(
        6,
        VirtualTime { ticks: 7 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("resumed-prefix-b"),
            value: 23,
        })),
    );
    let prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base(
        vec![first.clone(), second],
        5,
    )
    .expect("resumed nonzero event-log sequence should build");

    let through_first = prefix
        .with_facts_through_point(EventEvaluationPoint::event_log_entry(&first))
        .expect("resumed prefix through first entry should be retained");

    assert_eq!(through_first.scheduler_entries.len(), 1);
    assert_eq!(through_first.scheduler_entries[0].sequence(), 5);
    assert_eq!(through_first.base_sequence, 5);
    assert_eq!(through_first.event_log_offset().events, 6);
}
