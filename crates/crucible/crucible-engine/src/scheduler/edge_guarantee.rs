//! Per-edge time guarantees that bound each node's conservative horizon.
//!
//! RFC-0010 [SCHED-9] bounds a node's RUN by the earliest time any other node
//! could still affect it. This module computes that bound in the
//! Chandy-Misra-Bryant promise form: every directed coupling edge `j -> k`
//! carries an [`EdgeGuarantee`], the promise that nothing crosses the edge
//! before its `no_delivery_before` time. A node's inbound bound is the minimum
//! guarantee over its inbound edges ([`inbound_bound`]).
//!
//! # Emission floors
//!
//! A guarantee starts from the producer's [`EmissionFloor`], a time strictly
//! before the producer's next possible emission:
//!
//! - An [`EmissionFloor::Active`] node may emit at any retirement after its
//!   floor, so its floor alone bounds every outbound edge.
//! - An [`EmissionFloor::Reactive`] node emits only after its own next local
//!   event or after an input arrives. Its effective floor is the earlier of
//!   its own wake and every inbound guarantee, but never below its own clock.
//!   Reactive nodes are how a guarantee travels along a multi-hop path: an
//!   idle router forwards its upstream promise plus its own link latency.
//!
//! The effective floors are the least fixed point of
//!
//! ```text
//! floor(k) = active(k)                                         if k is active
//! floor(k) = max(clock(k), min(wake(k), min_{j->k} floor(j) + latency(j->k)))
//!                                                              if k is reactive
//! guarantee(j->k) = floor(j) + latency(j->k)
//! ```
//!
//! Latencies are non-negative, so the fixed point is found in one pass in
//! increasing floor order, as in Dijkstra's shortest-path algorithm. A zero
//! latency edge makes its endpoints a lockstep group: they share one bound and
//! advance together. A node with no path from any finite floor has no inbound
//! bound at all.
//!
//! # Transport independence
//!
//! The computation reads only floors and the effective edge set, never another
//! node's mutable state. One process can therefore compute every guarantee
//! locally, as the single scheduler does, while a distributed world could
//! exchange the same versioned [`EdgeGuarantee`] messages over a transport.
//! A guarantee is a lower bound, so receiving it late in wall time can only
//! delay a consumer; it never changes virtual time or ordering.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

use super::{SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint, SchedulerNodeId};
use crate::model::SimInstant;

/// Wire version of [`EdgeGuarantee`].
pub const EDGE_GUARANTEE_VERSION: u16 = 1;

/// One directed coupling edge's promise that nothing crosses it earlier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeGuarantee {
    /// Message shape version; [`EDGE_GUARANTEE_VERSION`] for this release.
    pub version: u16,
    /// Directed coupling edge the promise covers.
    pub edge: SchedulerLookaheadEdgeEndpoint,
    /// No delivery crosses `edge` at or before this time.
    ///
    /// A consumer may settle through this tick. The producer's next emission
    /// is strictly after its floor, so the first possible delivery is
    /// strictly after `no_delivery_before`.
    pub no_delivery_before: SimInstant,
    /// Effective-topology epoch whose edge latency produced the promise.
    pub topology_epoch: u64,
}

/// A producer's lower bound on its next emission time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmissionFloor {
    /// The node runs and may emit at any retirement strictly after `floor`.
    Active {
        /// Time strictly before the node's next possible emission.
        floor: SimInstant,
    },
    /// The node emits only after its own wake or an inbound delivery.
    Reactive {
        /// The node's own clock; it never emits at or before this time.
        clock: SimInstant,
        /// The node's next own local event, when one is armed.
        wake: Option<SimInstant>,
    },
}

impl EmissionFloor {
    /// Returns the floor before any inbound promise is applied.
    fn initial(self) -> Option<SimInstant> {
        match self {
            Self::Active { floor } => Some(floor),
            Self::Reactive { clock, wake } => wake.map(|wake| wake.max(clock)),
        }
    }

    /// Returns the floor a reactive node reaches through one inbound promise.
    fn through(self, inbound: SimInstant) -> Option<SimInstant> {
        match self {
            Self::Active { .. } => None,
            Self::Reactive { clock, .. } => Some(inbound.max(clock)),
        }
    }
}

/// Computes the guarantee carried by every effective edge.
///
/// Edges from a producer without a finite effective floor carry no guarantee
/// and therefore impose no bound. Producers absent from `floors` are treated
/// the same way; callers supply a floor for every scheduler node.
#[must_use]
pub fn propagate_edge_guarantees(
    edges: &[SchedulerLookaheadEdge],
    floors: &BTreeMap<SchedulerNodeId, EmissionFloor>,
    topology_epoch: u64,
) -> BTreeMap<SchedulerLookaheadEdgeEndpoint, EdgeGuarantee> {
    let effective = effective_floors(edges, floors);

    edges
        .iter()
        .filter(|edge| edge.from != edge.to)
        .filter_map(|edge| {
            let floor = effective.get(&edge.from)?;
            let no_delivery_before = SimInstant {
                ticks: floor.ticks.saturating_add(edge.minimum_latency.ticks),
            };
            Some((
                edge.endpoint(),
                EdgeGuarantee {
                    version: EDGE_GUARANTEE_VERSION,
                    edge: edge.endpoint(),
                    no_delivery_before,
                    topology_epoch,
                },
            ))
        })
        .collect()
}

/// Returns the earliest inbound promise for `node`, if any edge bounds it.
#[must_use]
pub fn inbound_bound(
    guarantees: &BTreeMap<SchedulerLookaheadEdgeEndpoint, EdgeGuarantee>,
    node: &SchedulerNodeId,
) -> Option<SimInstant> {
    guarantees
        .values()
        .filter(|guarantee| &guarantee.edge.to == node && &guarantee.edge.from != node)
        .map(|guarantee| guarantee.no_delivery_before)
        .min()
}

/// Solves the least fixed point of every node's effective emission floor.
fn effective_floors(
    edges: &[SchedulerLookaheadEdge],
    floors: &BTreeMap<SchedulerNodeId, EmissionFloor>,
) -> BTreeMap<SchedulerNodeId, SimInstant> {
    let mut settled = BTreeMap::new();
    let mut best = BTreeMap::new();
    let mut frontier = BinaryHeap::new();
    for (node, floor) in floors {
        if let Some(initial) = floor.initial() {
            best.insert(node.clone(), initial);
            frontier.push(Reverse((initial, node.clone())));
        }
    }

    // Each node settles at its smallest candidate floor. Ties pop in node
    // order, which keeps the traversal itself canonical.
    while let Some(Reverse((floor, node))) = frontier.pop() {
        if settled.contains_key(&node) || best.get(&node) != Some(&floor) {
            continue;
        }
        settled.insert(node.clone(), floor);

        for edge in edges
            .iter()
            .filter(|edge| edge.from == node && edge.to != node)
        {
            if settled.contains_key(&edge.to) {
                continue;
            }
            let Some(consumer) = floors.get(&edge.to) else {
                continue;
            };
            let inbound = SimInstant {
                ticks: floor.ticks.saturating_add(edge.minimum_latency.ticks),
            };
            let Some(candidate) = consumer.through(inbound) else {
                continue;
            };
            if best
                .get(&edge.to)
                .is_none_or(|current| candidate < *current)
            {
                best.insert(edge.to.clone(), candidate);
                frontier.push(Reverse((candidate, edge.to.clone())));
            }
        }
    }

    settled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NodeId, SimDuration};
    use crate::scheduler::SchedulingNodeKind;

    fn vm(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: NodeId {
                name: String::from(name),
            },
            kind: SchedulingNodeKind::Vm,
        }
    }

    fn edge(from: &str, to: &str, latency: u64) -> SchedulerLookaheadEdge {
        SchedulerLookaheadEdge::new(vm(from), vm(to), SimDuration { ticks: latency })
    }

    fn both(left: &str, right: &str, latency: u64) -> [SchedulerLookaheadEdge; 2] {
        [edge(left, right, latency), edge(right, left, latency)]
    }

    fn active(ticks: u64) -> EmissionFloor {
        EmissionFloor::Active {
            floor: SimInstant { ticks },
        }
    }

    fn reactive(clock: u64, wake: Option<u64>) -> EmissionFloor {
        EmissionFloor::Reactive {
            clock: SimInstant { ticks: clock },
            wake: wake.map(|ticks| SimInstant { ticks }),
        }
    }

    fn bound_of(
        edges: &[SchedulerLookaheadEdge],
        floors: &[(&str, EmissionFloor)],
        node: &str,
    ) -> Option<u64> {
        let floors = floors
            .iter()
            .map(|(name, floor)| (vm(name), *floor))
            .collect::<BTreeMap<_, _>>();
        let guarantees = propagate_edge_guarantees(edges, &floors, 7);
        assert!(guarantees.values().all(|guarantee| {
            guarantee.version == EDGE_GUARANTEE_VERSION && guarantee.topology_epoch == 7
        }));
        inbound_bound(&guarantees, &vm(node)).map(|instant| instant.ticks)
    }

    #[test]
    fn active_producers_bound_direct_consumers_from_their_own_clocks() {
        let edges = [both("a", "b", 10), both("b", "c", 10)].concat();
        let floors = [("a", active(0)), ("b", active(500)), ("c", active(9_000))];

        // Nodes on different clocks: each bound follows its own upstream.
        assert_eq!(bound_of(&edges, &floors, "a"), Some(510));
        assert_eq!(bound_of(&edges, &floors, "b"), Some(10));
        assert_eq!(bound_of(&edges, &floors, "c"), Some(510));
    }

    #[test]
    fn a_disconnected_node_imposes_no_bound() {
        // A reaches B and C; D reaches nobody, so D never bounds A.
        let edges = [both("a", "b", 10), both("a", "c", 10)].concat();
        let floors = [
            ("a", active(100)),
            ("b", active(100)),
            ("c", active(100)),
            ("d", active(0)),
        ];

        assert_eq!(bound_of(&edges, &floors, "a"), Some(110));
        assert_eq!(bound_of(&edges, &floors, "d"), None);
    }

    #[test]
    fn idle_intermediates_forward_the_shortest_upstream_path() {
        // a -> r1 -> r2 -> b with an idle router chain, plus a slow direct edge.
        let edges = [
            both("a", "r1", 10),
            both("r1", "r2", 20),
            both("r2", "b", 30),
            both("a", "b", 100),
        ]
        .concat();
        let floors = [
            ("a", active(1_000)),
            ("r1", reactive(0, None)),
            ("r2", reactive(0, None)),
            ("b", active(1_000)),
        ];

        // The three-hop path (60) is shorter than the direct link (100).
        assert_eq!(bound_of(&edges, &floors, "b"), Some(1_060));
        // A's own frame can return through the idle router r1 at 1010 + 10.
        assert_eq!(bound_of(&edges, &floors, "a"), Some(1_020));
    }

    #[test]
    fn a_reactive_node_never_promises_before_its_own_clock_or_after_its_wake() {
        let edges = [both("a", "r", 10), both("r", "b", 10)].concat();

        let ahead = [
            ("a", active(0)),
            ("r", reactive(500, None)),
            ("b", active(0)),
        ];
        // R cannot emit before its own clock even though A is far behind.
        assert_eq!(bound_of(&edges, &ahead, "b"), Some(510));

        let waking = [
            ("a", active(1_000)),
            ("r", reactive(0, Some(40))),
            ("b", active(1_000)),
        ];
        // R's own wake at 40 comes before any forwarded promise.
        assert_eq!(bound_of(&edges, &waking, "b"), Some(50));
    }

    #[test]
    fn a_reactive_cycle_without_a_finite_source_imposes_no_bound() {
        let edges = [both("r1", "r2", 10)].concat();
        let floors = [("r1", reactive(0, None)), ("r2", reactive(0, None))];

        assert_eq!(bound_of(&edges, &floors, "r1"), None);
        assert_eq!(bound_of(&edges, &floors, "r2"), None);
    }

    #[test]
    fn zero_latency_edges_form_a_lockstep_group() {
        let edges = [both("a", "b", 0)].concat();
        let floors = [("a", active(300)), ("b", active(300))];

        assert_eq!(bound_of(&edges, &floors, "a"), Some(300));
        assert_eq!(bound_of(&edges, &floors, "b"), Some(300));
    }

    #[test]
    fn guarantees_reduce_to_own_clock_plus_lookahead_on_a_common_clock() {
        let edges = [both("a", "b", 25).as_slice(), &[edge("c", "a", 40)]].concat();
        let floors = [("a", active(200)), ("b", active(200)), ("c", active(200))];

        assert_eq!(bound_of(&edges, &floors, "a"), Some(225));
        assert_eq!(bound_of(&edges, &floors, "b"), Some(225));
        assert_eq!(bound_of(&edges, &floors, "c"), None);
    }
}
