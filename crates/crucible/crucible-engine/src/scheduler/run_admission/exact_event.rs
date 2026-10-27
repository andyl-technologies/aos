//! Exact-event stop conditions for scheduler RUN ceilings.
//!
//! A RUN ceiling is an upper bound (RFC-0010 SCHED-12): the node stops at its
//! last retirement at or below it and settles through the rest. A ceiling that
//! is itself a modeled event is different. A halted node arrives there
//! exactly, by an idle advance. A runnable node never moves its clock without
//! a retirement: when no retirement lands on the ceiling it settles through
//! it at its last boundary below, and takes the event at its first boundary
//! at or after it (TIME-30).
//!
//! This module owns the scheduler's decision for fault-timed topology swaps
//! (SCHED-39). A swap at activation time `A` is an exact event only for the
//! nodes whose effective links the swap changes. Every other node treats `A` as
//! an ordinary bound and settles through it without moving its clock. The
//! decision is attached to each sealed [`PreparedRunAdmission`] so the
//! backend can publish it with the ceiling.
//!
//! Affected nodes are found by applying each pending change to the effective
//! lookahead graph in boundary order and diffing directed edges, latency
//! included. A listed edge whose state the change does not alter (removing an
//! absent edge, or restoring an edge already present) affects no node.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// How a backend must end a RUN at its dispatch ceiling.
///
/// The scheduler attaches this to every sealed [`PreparedRunAdmission`].
/// Backends publish it to the node together with the ceiling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RunCeilingStop {
    /// The ceiling is an upper bound.
    ///
    /// The node stops at its last retirement or exact event at or below the
    /// ceiling and attests settlement through the ceiling without moving its
    /// clock there (RFC-0010 SCHED-12).
    #[default]
    Bound,
    /// The ceiling is a modeled exact event for this node.
    ///
    /// A halted node arrives at the ceiling exactly by an idle advance, and an
    /// idle park below it is refused. A runnable node whose retirements do not
    /// land on it settles through it with its clock at its last boundary
    /// below, and takes the event at its next boundary (TIME-30).
    ExactEvent,
}

impl SingleScheduler {
    /// Returns the stop condition for `node`'s RUN dispatched to `dispatch_counter`.
    ///
    /// The ceiling is an exact event only when it maps exactly to the
    /// activation time of a pending fault-timed topology change that alters
    /// one of this VM's effective links. A ceiling tightened below the
    /// activation, for example by an input replan, is an ordinary bound.
    pub(in crate::scheduler) fn run_ceiling_stop(
        &self,
        node: &RuntimeSchedulerNode,
        dispatch_counter: u64,
    ) -> Result<RunCeilingStop, SchedulerError> {
        if node.id.kind != SchedulingNodeKind::Vm || self.topology_changes.is_empty() {
            return Ok(RunCeilingStop::Bound);
        }

        let dispatch_time = self.node_time_for_counter(
            node,
            NodeCounter {
                ticks: dispatch_counter,
            },
        )?;
        let exact =
            self.timed_topology_footprints()
                .into_iter()
                .any(|(activation_time, affected)| {
                    activation_time == dispatch_time && affected.contains(&node.id.node)
                });

        Ok(if exact {
            RunCeilingStop::ExactEvent
        } else {
            RunCeilingStop::Bound
        })
    }

    /// Returns each pending activation time with the nodes its swap affects.
    fn timed_topology_footprints(&self) -> BTreeMap<SimInstant, BTreeSet<NodeId>> {
        timed_topology_footprints(&self.effective_topology, &self.topology_changes)
    }
}

/// Maps each pending activation time to the nodes whose effective links change.
///
/// Untimed changes apply at the next boundary, before any timed change can
/// become ready, so they shape the graph that timed changes modify but affect
/// no node themselves. Timed changes then apply in activation order and, at one
/// activation time, in the scheduler's canonical change order.
pub(in crate::scheduler) fn timed_topology_footprints(
    current: &SchedulerLookaheadGraph,
    changes: &[SchedulerTopologyChange],
) -> BTreeMap<SimInstant, BTreeSet<NodeId>> {
    let mut ordered = changes.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| topology_change_order(left, right));

    let mut working = current.clone();
    for change in ordered
        .iter()
        .filter(|change| change.activation_time.is_none())
    {
        working = working.with_effect(&change.effect);
    }

    let mut timed = ordered
        .into_iter()
        .filter_map(|change| change.activation_time.map(|at| (at, change)))
        .collect::<Vec<_>>();
    timed.sort_by(|(left_at, left), (right_at, right)| {
        left_at
            .cmp(right_at)
            .then_with(|| topology_change_order(left, right))
    });

    let mut footprints = BTreeMap::<SimInstant, BTreeSet<NodeId>>::new();
    for (activation_time, change) in timed {
        let next = working.with_effect(&change.effect);
        footprints
            .entry(activation_time)
            .or_default()
            .extend(changed_link_nodes(&working, &next));
        working = next;
    }
    footprints
}

/// Returns the nodes at either end of every directed edge that differs.
///
/// An edge differs when it is present in only one graph or its minimum latency
/// changed. Device sub-node endpoints name their owning VM, so they map to it.
fn changed_link_nodes(
    before: &SchedulerLookaheadGraph,
    after: &SchedulerLookaheadGraph,
) -> BTreeSet<NodeId> {
    let latencies = |graph: &SchedulerLookaheadGraph| {
        graph
            .edges()
            .iter()
            .map(|edge| (edge.endpoint(), edge.minimum_latency))
            .collect::<BTreeMap<_, _>>()
    };
    let before = latencies(before);
    let after = latencies(after);

    before
        .keys()
        .chain(after.keys())
        .filter(|endpoint| before.get(endpoint) != after.get(endpoint))
        .flat_map(|endpoint| [endpoint.from.node.clone(), endpoint.to.node.clone()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: node(name),
            kind: SchedulingNodeKind::Vm,
        }
    }

    fn node(name: &str) -> NodeId {
        NodeId {
            name: String::from(name),
        }
    }

    fn edge(from: &str, to: &str, latency: u64) -> SchedulerLookaheadEdge {
        SchedulerLookaheadEdge::new(vm(from), vm(to), SimDuration { ticks: latency })
    }

    fn endpoint(from: &str, to: &str) -> SchedulerLookaheadEdgeEndpoint {
        SchedulerLookaheadEdgeEndpoint::new(vm(from), vm(to))
    }

    /// A full mesh over three VMs with symmetric 100-tick links.
    fn triangle() -> SchedulerLookaheadGraph {
        SchedulerLookaheadGraph::from_edges([
            edge("a", "b", 100),
            edge("b", "a", 100),
            edge("a", "c", 100),
            edge("c", "a", 100),
            edge("b", "c", 100),
            edge("c", "b", 100),
        ])
    }

    fn nodes(names: &[&str]) -> BTreeSet<NodeId> {
        names.iter().map(|name| node(name)).collect()
    }

    const AT: SimInstant = SimInstant {
        ticks: 1_234_567_891,
    };

    #[test]
    fn a_partition_affects_only_the_partitioned_link_endpoints() {
        let partition =
            SchedulerTopologyChange::partition(1, vec![endpoint("a", "b"), endpoint("b", "a")])
                .with_activation_time(AT);

        let footprints = timed_topology_footprints(&triangle(), &[partition]);

        assert_eq!(footprints, BTreeMap::from([(AT, nodes(&["a", "b"]))]));
    }

    #[test]
    fn a_latency_change_affects_both_ends_of_the_changed_edge_only() {
        let update = SchedulerTopologyChange::update_effective_edges(
            1,
            SchedulerTopologyChangeTrigger::LatencyChange,
            vec![edge("b", "c", 40), edge("a", "c", 100)],
        )
        .with_activation_time(AT);

        let footprints = timed_topology_footprints(&triangle(), &[update]);

        // a -> c keeps its latency, so `a` is not affected.
        assert_eq!(footprints, BTreeMap::from([(AT, nodes(&["b", "c"]))]));
    }

    #[test]
    fn a_change_that_alters_no_edge_affects_no_node() {
        let absent = SchedulerTopologyChange::partition(1, vec![endpoint("a", "z")])
            .with_activation_time(AT);
        let present =
            SchedulerTopologyChange::heal(2, vec![edge("c", "a", 100)]).with_activation_time(AT);

        let footprints = timed_topology_footprints(&triangle(), &[absent, present]);

        assert_eq!(footprints, BTreeMap::from([(AT, BTreeSet::new())]));
    }

    #[test]
    fn timed_changes_apply_after_untimed_ones_in_activation_order() {
        let later = SimInstant {
            ticks: AT.ticks + 7,
        };
        // The untimed partition removes b -> c first, so the timed heal at
        // `AT` restores it and affects b and c. The later heal of the same
        // edge then changes nothing.
        let untimed = SchedulerTopologyChange::partition(3, vec![endpoint("b", "c")]);
        let heal_later =
            SchedulerTopologyChange::heal(1, vec![edge("b", "c", 100)]).with_activation_time(later);
        let heal =
            SchedulerTopologyChange::heal(2, vec![edge("b", "c", 100)]).with_activation_time(AT);

        let footprints = timed_topology_footprints(&triangle(), &[heal_later, untimed, heal]);

        assert_eq!(
            footprints,
            BTreeMap::from([(AT, nodes(&["b", "c"])), (later, BTreeSet::new())])
        );
    }

    #[test]
    fn a_full_replacement_affects_endpoints_of_every_added_removed_or_changed_edge() {
        let replace = SchedulerTopologyChange::new(
            1,
            SchedulerTopologyChangeTrigger::EdgeRemoval,
            vec![
                edge("a", "b", 100),
                edge("b", "a", 100),
                edge("a", "c", 100),
                edge("c", "a", 100),
                edge("c", "d", 100),
            ],
        )
        .with_activation_time(AT);

        let footprints = timed_topology_footprints(&triangle(), &[replace]);

        // b <-> c disappear and c -> d appears; a's links are unchanged.
        assert_eq!(footprints, BTreeMap::from([(AT, nodes(&["b", "c", "d"]))]));
    }
}
