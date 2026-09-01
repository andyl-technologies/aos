//! Checks that signal-driven fault evidence uses the canonical event log.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup.
#![allow(clippy::expect_used)]

use crucible::{
    ContentHash, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, SchedulerEventLogClass,
    SchedulerEventLogPayload, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulingNodeKind, Shift, SimInstant, SingleScheduler, VirtualTime,
    model::{FaultCoordinate, FaultObjectId, FaultObservation, FaultObservationKind},
};

#[test]
fn fault_observations_append_as_typed_causal_evidence() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "fault-observation-log",
        Shift::new(0).expect("zero shift should be valid"),
        8,
        SimInstant { nanos: 100 },
        vec![SchedulerScenarioNode {
            id: SchedulerNodeId {
                node: NodeId {
                    name: String::from("node-a"),
                },
                kind: SchedulingNodeKind::Vm,
            },
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");
    let observation = FaultObservation {
        semantic_version: 1,
        kind: FaultObservationKind::EffectApplied,
        coordinate: FaultCoordinate {
            virtual_nanos: 37,
            retired_instructions: Some(91),
        },
        binding: Some(FaultObjectId::parse("network-delay").expect("test binding id should parse")),
        target: None,
        opportunity: Some(ContentHash::from_bytes(b"opportunity")),
        evidence: ContentHash::from_bytes(b"applied evidence"),
    };

    let append = scheduler
        .append_fault_observations([observation.clone()])
        .expect("fault evidence should append");

    assert_eq!(append.entries.len(), 1);
    let entry = &append.entries[0];
    assert_eq!(entry.sequence(), 0);
    assert_eq!(entry.at(), VirtualTime { ticks: 37 });
    assert_eq!(entry.class(), SchedulerEventLogClass::Causal);
    assert_eq!(entry.event_payload().kind(), "effect_applied");
    assert_eq!(
        entry.payload(),
        &SchedulerEventLogPayload::FaultObservation(observation)
    );
    assert!(entry.has_valid_content_hash());
    assert!(
        append
            .segment_text
            .contains("entry.payload.kind=effect_applied")
    );
    assert!(append.segment_hash.is_some());
    assert_eq!(scheduler.event_log_offset(), append.offset);
}
