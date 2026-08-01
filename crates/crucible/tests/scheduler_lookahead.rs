//! Checks the T-SCHED-2 scheduler lookahead graph.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Icount, LinkDef, LinkLossProbability, NetworkLookahead, NodeId, NodeTemplate, ReadyPoint,
    SchedulerLookaheadEdge, SchedulerLookaheadGraph, SchedulerNodeId, SchedulingNodeKind,
    SimDuration, WhiteBoxPolicy, World, WorldNode, lookahead_for_node,
};

#[test]
fn scheduler_lookahead_uses_minimum_inbound_latency() {
    let graph = SchedulerLookaheadGraph::from_edges(vec![
        edge("b", "a", 9),
        edge("c", "a", 4),
        edge("a", "b", 2),
    ]);

    assert_eq!(
        graph.lookahead(&scheduler_node("a")),
        NetworkLookahead::Finite(duration(4))
    );
}

#[test]
fn scheduler_lookahead_is_infinite_without_inbound_edges() {
    let graph = SchedulerLookaheadGraph::from_edges(vec![edge("a", "b", 7)]);
    let lookahead = graph.lookahead(&scheduler_node("a"));

    assert_eq!(lookahead, NetworkLookahead::Infinite);
    assert!(lookahead.is_infinite());
    assert_eq!(lookahead.finite_duration(), None);
}

#[test]
fn scheduler_lookahead_is_directional() {
    let graph = SchedulerLookaheadGraph::from_edges(vec![edge("a", "b", 7)]);

    assert_eq!(
        graph.lookahead(&scheduler_node("b")),
        NetworkLookahead::Finite(duration(7))
    );
    assert_eq!(
        graph.lookahead(&scheduler_node("a")),
        NetworkLookahead::Infinite
    );
}

#[test]
fn scheduler_lookahead_edges_are_canonical_and_duplicate_stable() {
    let graph = SchedulerLookaheadGraph::from_edges(vec![
        edge("c", "a", 7),
        edge("b", "a", 3),
        edge("b", "a", 3),
        edge("a", "c", 11),
    ]);
    let expected = vec![edge("a", "c", 11), edge("b", "a", 3), edge("c", "a", 7)];

    assert_eq!(graph.edges(), expected.as_slice());
    assert_eq!(
        lookahead_for_node(graph.edges(), &scheduler_node("a")),
        NetworkLookahead::Finite(duration(3))
    );
}

#[test]
fn scheduler_lookahead_consumes_world_static_topology_edges() {
    let world = World::from_nodes_and_links(
        vec![
            world_node("a"),
            world_node("b"),
            world_node("c"),
            world_node("isolated"),
        ],
        vec![
            transport_link("a", "b", 10, 2),
            transport_link("b", "c", 5, 1),
        ],
    )
    .expect("test world topology should be valid");

    let graph = SchedulerLookaheadGraph::from_world_edges(&world.static_topology().lookahead_graph);

    assert_eq!(graph.edges().len(), 4);
    assert!(graph.edges().contains(&edge("a", "b", 8)));
    assert!(graph.edges().contains(&edge("c", "b", 4)));
    assert_eq!(
        graph.lookahead(&scheduler_node("b")),
        NetworkLookahead::Finite(duration(4))
    );
    assert_eq!(
        graph.lookahead(&scheduler_node("a")),
        NetworkLookahead::Finite(duration(8))
    );
    assert_eq!(
        graph.lookahead(&scheduler_node("isolated")),
        NetworkLookahead::Infinite
    );
}

fn edge(from: &str, to: &str, latency_ns: u64) -> SchedulerLookaheadEdge {
    SchedulerLookaheadEdge::new(
        scheduler_node(from),
        scheduler_node(to),
        duration(latency_ns),
    )
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node_id(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn world_node(name: &str) -> WorldNode {
    WorldNode {
        id: node_id(name),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn transport_link(left: &str, right: &str, latency_ns: u64, jitter_ns: u64) -> LinkDef {
    LinkDef::with_transport(
        node_id(left),
        node_id(right),
        duration(latency_ns),
        duration(jitter_ns),
        LinkLossProbability::ZERO,
        None,
    )
    .expect("test link should be valid")
}
