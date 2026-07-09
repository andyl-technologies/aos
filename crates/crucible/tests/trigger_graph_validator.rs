//! Checks T-TRIG-15 build-time event-graph validation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, Event, EventGraph, EventGraphError, EventId, FaultTag, FramePredicate, Icount, LinkDef,
    LinkId, MembershipFault, NodeId, NodeTemplate, PartitionDirection, Predicate, ReadyPoint,
    RegexProgram, RestartPolicy, SimDuration, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn link(name: &str) -> LinkId {
    LinkId::from_name(name)
}

fn canonical_link(left: &str, right: &str) -> LinkId {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.len(),
        endpoint_a,
        endpoint_b.len(),
        endpoint_b
    ))
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world_with_link() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("validator test world should build")
}

fn world_without_links() -> World {
    World::from_nodes_and_links(vec![ready_node("db-0"), ready_node("db-1")], Vec::new())
        .expect("validator test world without links should build")
}

#[test]
fn validator_rejects_dangling_topology_and_fault_tag_references() {
    let missing_node = EventGraph::new_for_world(
        vec![Event::once(
            event_id("missing-console-node"),
            Some(Predicate::console_match(
                node("missing"),
                RegexProgram::from_pattern("ready"),
            )),
            Action::Pass,
        )],
        &world_with_link(),
    );
    assert_eq!(
        missing_node,
        Err(EventGraphError::UnknownNodeReference {
            event: event_id("missing-console-node"),
            node: node("missing"),
        })
    );

    let needs_world = EventGraph::new(vec![Event::once(
        event_id("console-without-world"),
        Some(Predicate::console_match(
            node("db-0"),
            RegexProgram::from_pattern("ready"),
        )),
        Action::Pass,
    )]);
    assert_eq!(
        needs_world,
        Err(EventGraphError::NodeReferenceRequiresWorld {
            event: event_id("console-without-world"),
            node: node("db-0"),
        })
    );

    let link_needs_world = EventGraph::new(vec![Event::once(
        event_id("network-without-world"),
        Some(Predicate::network_match(
            Some(link("db-0--db-1")),
            FramePredicate::any(),
        )),
        Action::Pass,
    )]);
    assert_eq!(
        link_needs_world,
        Err(EventGraphError::LinkReferenceRequiresWorld {
            event: event_id("network-without-world"),
            link: link("db-0--db-1"),
        })
    );

    let missing_link = EventGraph::new_for_world(
        vec![Event::once(
            event_id("missing-link"),
            Some(Predicate::network_match(
                Some(link("db-0--db-2")),
                FramePredicate::any(),
            )),
            Action::Pass,
        )],
        &world_with_link(),
    );
    assert_eq!(
        missing_link,
        Err(EventGraphError::UnknownLinkReference {
            event: event_id("missing-link"),
            link: link("db-0--db-2"),
        })
    );

    let missing_tag = EventGraph::new(vec![Event::once(
        event_id("heal-missing-tag"),
        None,
        Action::HealFault { tag: tag("split") },
    )]);
    assert_eq!(
        missing_tag,
        Err(EventGraphError::UnknownFaultTagReference {
            event: event_id("heal-missing-tag"),
            tag: tag("split"),
        })
    );
}

#[test]
fn validator_rejects_injected_faults_with_unknown_nodes_or_links() {
    let missing_fault_node = EventGraph::new_for_world(
        vec![Event::once(
            event_id("crash-missing-node"),
            None,
            Action::InjectFault {
                tag: tag("crash"),
                fault: MembershipFault::Crash {
                    node: node("missing"),
                    restart: RestartPolicy::StayDown,
                },
            },
        )],
        &world_with_link(),
    );
    assert_eq!(
        missing_fault_node,
        Err(EventGraphError::UnknownNodeReference {
            event: event_id("crash-missing-node"),
            node: node("missing"),
        })
    );

    let missing_partition_node = EventGraph::new_for_world(
        vec![Event::once(
            event_id("partition-missing-link"),
            None,
            Action::InjectFault {
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node("db-0"),
                    endpoint_b: node("missing"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
        )],
        &world_with_link(),
    );
    assert_eq!(
        missing_partition_node,
        Err(EventGraphError::UnknownNodeReference {
            event: event_id("partition-missing-link"),
            node: node("missing"),
        })
    );

    let missing_fault_link = EventGraph::new_for_world(
        vec![Event::once(
            event_id("partition-without-link"),
            None,
            Action::InjectFault {
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node("db-0"),
                    endpoint_b: node("db-1"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
        )],
        &world_without_links(),
    );
    assert_eq!(
        missing_fault_link,
        Err(EventGraphError::UnknownLinkReference {
            event: event_id("partition-without-link"),
            link: canonical_link("db-0", "db-1"),
        })
    );
}

#[test]
fn validator_rejects_empty_compounds_with_local_event_errors() {
    let empty_any = EventGraph::new(vec![Event::once(
        event_id("empty-any"),
        Some(Predicate::not(Predicate::any_of(Vec::new()))),
        Action::Pass,
    )]);
    assert_eq!(
        empty_any,
        Err(EventGraphError::EmptyCompound {
            event: event_id("empty-any"),
            kind: "any-of",
        })
    );
}

#[test]
fn validator_rejects_non_repeatable_after_cycles() {
    let cycle = EventGraph::new(vec![
        Event::once(
            event_id("a"),
            Some(Predicate::after(duration(1), event_id("b"))),
            Action::Pass,
        ),
        Event::once(
            event_id("b"),
            Some(Predicate::after(duration(1), event_id("a"))),
            Action::Pass,
        ),
    ]);
    assert_eq!(
        cycle,
        Err(EventGraphError::NonRepeatableCycle {
            events: vec![event_id("a"), event_id("b"), event_id("a")],
        })
    );
}

#[test]
fn validator_rejects_unreachable_events_after_cycle_exclusions() {
    let unreachable = EventGraph::new(vec![
        Event::repeatable(
            event_id("pulse"),
            Some(Predicate::after(duration(1), event_id("finish"))),
            Action::Pass,
        ),
        Event::once(
            event_id("finish"),
            Some(Predicate::after(duration(1), event_id("pulse"))),
            Action::Pass,
        ),
    ]);
    assert_eq!(
        unreachable,
        Err(EventGraphError::UnreachableEvent {
            event: event_id("pulse"),
        })
    );
}

#[test]
fn validator_accepts_reachable_repeatable_feedback() {
    let graph = EventGraph::new(vec![
        Event::repeatable(
            event_id("pulse"),
            Some(Predicate::named("pulse")),
            Action::Pass,
        ),
        Event::once(
            event_id("finish"),
            Some(Predicate::any_of(vec![
                Predicate::named("seed"),
                Predicate::after(duration(1), event_id("pulse")),
            ])),
            Action::Pass,
        ),
    ]);
    assert!(graph.is_ok(), "repeatable feedback with a root must build");
}
