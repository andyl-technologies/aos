//! Scheduler emission floors and the graph-derived network horizon.
//!
//! RFC-0010 [SCHED-9] bounds each node by the earliest time any other node can
//! still influence it. The scheduler projects every node's state to an
//! [`EmissionFloor`], propagates the per-edge guarantees of
//! [`super::edge_guarantee`] over the effective topology, and takes the
//! minimum inbound guarantee as the node's network bound `net(n)`.
//!
//! Nodes keep their own clocks: the bound is computed from each upstream
//! node's actual clock and the shortest-path latency to `n`, never from a
//! shared frontier. When every upstream clock equals `vt(n)` it reduces to the
//! classic `vt(n) + lookahead(n)`.
//!
//! # Coupling coverage
//!
//! The effective lookahead graph carries the World's network links. Other
//! influences are handled as follows:
//!
//! - Device sub-nodes (disk, 9p) belong to one VM; their completions are that
//!   node's own exact local events, not edges between nodes.
//! - Signal-fault and trigger evaluations act on every node. They stay global
//!   evaluation barriers folded into each node's own exact local event, which
//!   is conservative: no node passes an armed evaluation point.
//! - A campaign-parked VM emits nothing before its all-VM join, which happens
//!   at or beyond the shared frontier, so its floor is raised to that frontier.
//!
//! # Held evidence
//!
//! While a host-concurrent RUN set publishes, completed peer RUNs are held
//! outside the staged scheduler. The scheduler's held peer evidence carries
//! each held peer's proven emission floor so a catch-up RUN of another
//! node may use that evidence instead of the peer's stale pre-RUN clock.
//!
//! # Global deadlines
//!
//! Signal-fault and trigger evaluations must observe every live node at their
//! coordinate. Because nodes run on their own clocks, arming such a deadline
//! is refused when a live node's settled time, or the point a held VM has
//! physically executed through, already lies beyond it.

use std::collections::BTreeMap;

use super::*;

impl SingleScheduler {
    /// Projects every scheduler node to its emission floor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a node's clock cannot be projected to
    /// virtual time.
    pub(super) fn emission_floors(
        &self,
    ) -> Result<BTreeMap<SchedulerNodeId, EmissionFloor>, SchedulerError> {
        let mut floors = BTreeMap::new();
        for node in &self.nodes {
            let scheduler_time = self.node_scheduler_time(node)?;
            let mut floor = if node.campaign_parked {
                // The all-VM join anchors the parked VM at or beyond the
                // shared frontier, and it emits nothing before that join.
                let parked = if node.idle_parked {
                    scheduler_time
                } else {
                    self.node_physical_time(node)?
                };
                EmissionFloor::Active {
                    floor: parked.max(SimInstant {
                        ticks: self.frontier.ticks,
                    }),
                }
            } else {
                match self.effective_node_activity(node) {
                    // A runnable node may emit at any retirement after its
                    // clock. An idle-parked node settled its ceiling without a
                    // pending emission, so its settled time bounds it (SCHED-28).
                    SchedulerNodeActivity::Runnable => EmissionFloor::Active {
                        floor: if node.idle_parked {
                            scheduler_time
                        } else {
                            self.node_physical_time(node)?
                        },
                    },
                    SchedulerNodeActivity::Idle => EmissionFloor::Reactive {
                        clock: scheduler_time,
                        wake: self.idle_wake_time(node)?,
                    },
                    // Only an input can make a halted or finished node act.
                    SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => {
                        EmissionFloor::Reactive {
                            clock: scheduler_time,
                            wake: self.earliest_pending_event_for(&node.id),
                        }
                    }
                }
            };
            if let Some(held) = self.held_peer_evidence.get(&node.id.node) {
                floor = raise_floor(floor, held.emission_floor);
            }
            floors.insert(node.id.clone(), floor);
        }
        Ok(floors)
    }

    /// Returns `net(n)`, the earliest time another node can influence `node`.
    ///
    /// `None` means no coupling path reaches the node from a node that can
    /// emit, so the network term imposes no bound. An edge whose producer is
    /// not a scheduler node has no observable clock; it keeps the classic
    /// bound `vt(n) + latency` from the consumer's own scheduler time.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when emission floors cannot be projected.
    pub(super) fn graph_network_bound(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<SimInstant>, SchedulerError> {
        let floors = self.emission_floors()?;
        let guarantees = propagate_edge_guarantees(
            self.effective_topology.edges(),
            &floors,
            self.topology_epoch,
        );
        let current = self.node_scheduler_time(node)?;
        let unobserved = self
            .effective_topology
            .edges()
            .iter()
            .filter(|edge| edge.to == node.id && edge.from != node.id)
            .filter(|edge| !floors.contains_key(&edge.from))
            .map(|edge| SimInstant {
                ticks: current.ticks.saturating_add(edge.minimum_latency.ticks),
            })
            .min();

        Ok(match (inbound_bound(&guarantees, &node.id), unobserved) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (bound, None) | (None, bound) => bound,
        })
    }

    /// Replaces the held peer evidence used by catch-up horizon planning and
    /// by global deadline checks.
    pub(super) fn set_held_peer_evidence(&mut self, evidence: BTreeMap<NodeId, HeldPeerEvidence>) {
        self.held_peer_evidence = evidence;
    }

    /// Refuses a global evaluation deadline that a live node already passed.
    ///
    /// A halted or finished node acts only on an input, which the evaluation
    /// precedes, so only the other nodes are checked. While a host-concurrent
    /// RUN set publishes, a peer's completed RUN is held outside this
    /// scheduler; the point its VM has physically executed through counts as
    /// its clock.
    pub(super) fn require_no_live_node_beyond(
        &self,
        deadline: SimInstant,
        what: &str,
    ) -> Result<(), SchedulerError> {
        for node in &self.nodes {
            if matches!(
                self.effective_node_activity(node),
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                continue;
            }
            let settled = self.node_scheduler_time(node)?;
            let clock = self
                .held_peer_evidence
                .get(&node.id.node)
                .map_or(settled, |held| held.executed_through.max(settled));
            if clock > deadline {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "{what} {} is behind live node {} at {}",
                        deadline.ticks, node.id.node.name, clock.ticks
                    ),
                });
            }
        }
        Ok(())
    }

    fn earliest_pending_event_for(&self, node: &SchedulerNodeId) -> Option<SimInstant> {
        self.pending_events
            .iter()
            .filter(|event| event.key.consumer() == node)
            .map(|event| SimInstant {
                ticks: event.key.virtual_time().ticks,
            })
            .min()
    }
}

/// Raises a floor to proven held evidence; evidence never lowers it.
fn raise_floor(floor: EmissionFloor, held: SimInstant) -> EmissionFloor {
    match floor {
        EmissionFloor::Active { floor } => EmissionFloor::Active {
            floor: floor.max(held),
        },
        EmissionFloor::Reactive { clock, wake } => EmissionFloor::Reactive {
            clock: clock.max(held),
            wake,
        },
    }
}
