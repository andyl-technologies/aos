//! Scheduler topology transitions, advancement planning, authoritative quantum drive, and control drain.

use super::*;
impl SingleScheduler {
    pub(super) fn queue_control(&mut self, operation: ControlOperation) {
        self.accept_control_at_boundary(operation);
    }

    pub(super) fn validate_max_host_workers(
        &self,
        max_host_workers: usize,
    ) -> Result<(), SchedulerError> {
        if max_host_workers == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("concurrent scheduler max_host_workers must be positive"),
            });
        }
        Ok(())
    }

    pub(super) fn vm_node_index(&self, node: &NodeId) -> Result<usize, SchedulerError> {
        self.nodes
            .iter()
            .position(|candidate| {
                candidate.id.node == *node && candidate.id.kind == SchedulingNodeKind::Vm
            })
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!("node timing fault targets missing VM node: {}", node.name),
            })
    }

    pub(super) fn node_current_time(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<SimInstant, SchedulerError> {
        self.node_time_for_counter(node, node.counter)
    }

    pub(super) fn node_time_for_counter(
        &self,
        node: &RuntimeSchedulerNode,
        counter: NodeCounter,
    ) -> Result<SimInstant, SchedulerError> {
        if node.id.kind == SchedulingNodeKind::Vm {
            node.timing_faults
                .faulted_virtual_time(counter, self.timeline.shift())
                .map_err(SchedulerError::from)
        } else {
            counter
                .to_virtual(self.timeline.shift())
                .map_err(SchedulerError::from)
        }
    }

    pub(super) fn node_counter_for_time_ceil(
        &self,
        node: &RuntimeSchedulerNode,
        target_time: SimInstant,
    ) -> Result<NodeCounter, SchedulerError> {
        if node.id.kind == SchedulingNodeKind::Vm {
            node.timing_faults
                .counter_for_faulted_virtual_time_ceil(target_time, self.timeline.shift())
                .map_err(SchedulerError::from)
        } else {
            Ok(NodeCounter {
                ticks: self
                    .timeline
                    .max_advance_icount_for_horizon(target_time)?
                    .retired,
            })
        }
    }

    pub(super) fn node_timeline_key(
        &self,
        node: &RuntimeSchedulerNode,
        sequence: u64,
    ) -> Result<SharedTimelineKey, SchedulerError> {
        Ok(SharedTimelineKey {
            virtual_time: self.node_current_time(node)?,
            node: node.id.clone(),
            sequence,
        })
    }

    pub(super) fn vm_delivery_time_for_icount(
        &self,
        node: &NodeId,
        icount: Icount,
    ) -> Result<SimInstant, SchedulerError> {
        let index = self.vm_node_index(node)?;
        self.node_time_for_counter(&self.nodes[index], NodeCounter::from_icount(icount))
    }

    pub(super) fn network_time_for_icount(
        &self,
        icount: u64,
    ) -> Result<SimInstant, SchedulerError> {
        NodeCounter { ticks: icount }
            .to_virtual(self.timeline.shift())
            .map_err(SchedulerError::from)
    }

    pub(super) fn network_icount_for_time_ceil(
        &self,
        time: SimInstant,
    ) -> Result<u64, SchedulerError> {
        Ok(self.timeline.max_advance_icount_for_horizon(time)?.retired)
    }

    pub(super) fn project_device_decisions_for_vm_time(
        &self,
        node: &NodeId,
        decisions: Vec<Decision>,
    ) -> Result<Vec<Decision>, SchedulerError> {
        decisions
            .into_iter()
            .map(|decision| match decision {
                Decision::FaultFires(mut fault) => {
                    let virtual_time = self.vm_delivery_time_for_icount(
                        node,
                        Icount {
                            retired: fault.at.ticks,
                        },
                    )?;
                    fault.at = VirtualTime {
                        ticks: virtual_time.nanos,
                    };
                    Ok(Decision::FaultFires(fault))
                }
                decision => Ok(decision),
            })
            .collect()
    }

    pub(super) fn effective_node_activity(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> SchedulerNodeActivity {
        if self.node_execution_stopped(node) {
            SchedulerNodeActivity::Halted
        } else if node.activity == SchedulerNodeActivity::Idle
            && node
                .vcpu_idle_states
                .iter()
                .any(|state| !state.halted || state.pending_input)
        {
            SchedulerNodeActivity::Runnable
        } else {
            node.activity
        }
    }

    pub(super) fn is_node_down(&self, node: &NodeId) -> bool {
        self.nodes.iter().any(|runtime| {
            runtime.id.node == *node
                && runtime.id.kind == SchedulingNodeKind::Vm
                && self.node_execution_stopped(runtime)
        })
    }

    pub(super) fn node_execution_stopped(&self, node: &RuntimeSchedulerNode) -> bool {
        node.crash.is_some() || node.stopped_crash.is_some()
    }

    pub(super) fn incident_effective_edges(
        &self,
        node: &SchedulerNodeId,
    ) -> Vec<SchedulerLookaheadEdge> {
        self.effective_topology
            .edges()
            .iter()
            .filter(|edge| &edge.from == node || &edge.to == node)
            .cloned()
            .collect()
    }

    pub(super) fn discard_pending_events_for_node(
        &mut self,
        node: &SchedulerNodeId,
    ) -> Vec<SchedulerDiscardedEvent> {
        let mut pending = Vec::with_capacity(self.pending_events.len());
        let mut discarded = Vec::new();
        for event in std::mem::take(&mut self.pending_events) {
            if event.key.consumer() == node || event.key.producer() == node {
                let class = scheduled_event_resolve_class(&event);
                discarded.push(SchedulerDiscardedEvent {
                    key: event.key,
                    class,
                });
            } else {
                pending.push(event);
            }
        }
        discarded.sort_by(|left, right| left.key.cmp(&right.key));
        self.pending_events = pending;
        discarded
    }

    pub(super) fn discard_device_completions_for_node(
        &mut self,
        node: &NodeId,
    ) -> Vec<SchedulerDiscardedIoCompletion> {
        let Some(sub_nodes) = self.device_sub_nodes.get_mut(node) else {
            return Vec::new();
        };
        let mut discarded = Vec::new();
        for sub_node in sub_nodes {
            discarded.extend(sub_node.discard_in_flight());
        }
        discarded.sort_by(|left, right| {
            left.delivery_icount
                .cmp(&right.delivery_icount)
                .then_with(|| left.sub_node.cmp(&right.sub_node))
                .then_with(|| left.source_node.cmp(&right.source_node))
                .then_with(|| left.sequence.cmp(&right.sequence))
                .then_with(|| left.target.cmp(&right.target))
                .then_with(|| left.payload.cmp(&right.payload))
        });
        discarded
    }

    pub(super) fn suppress_down_edges(
        &mut self,
        graph: SchedulerLookaheadGraph,
    ) -> SchedulerLookaheadGraph {
        let down = self
            .nodes
            .iter()
            .filter(|node| self.node_execution_stopped(node))
            .map(|node| node.id.clone())
            .collect::<BTreeSet<_>>();
        if down.is_empty() {
            return graph;
        }
        let mut live_edges = Vec::new();
        for edge in graph.edges() {
            if down.contains(&edge.from) || down.contains(&edge.to) {
                self.remember_suppressed_down_edge(edge);
            } else {
                live_edges.push(edge.clone());
            }
        }
        SchedulerLookaheadGraph::from_edges(live_edges)
    }

    pub(super) fn replace_suppressed_down_edges(&mut self, edges: &[SchedulerLookaheadEdge]) {
        for node in &mut self.nodes {
            if node.crash.is_none() && node.stopped_crash.is_none() {
                continue;
            }
            let incident = canonical_edges_by_endpoint(
                edges
                    .iter()
                    .filter(|edge| edge.from == node.id || edge.to == node.id)
                    .cloned(),
            );
            if let Some(state) = &mut node.crash {
                state.removed_edges = incident.clone();
            }
            if let Some(state) = &mut node.stopped_crash {
                state.removed_edges = incident.clone();
            }
        }
    }

    pub(super) fn remove_suppressed_down_edges(
        &mut self,
        sequence: u64,
        endpoints: &[SchedulerLookaheadEdgeEndpoint],
    ) {
        let endpoints = endpoints.iter().cloned().collect::<BTreeSet<_>>();
        for node in &mut self.nodes {
            if let Some(state) = &mut node.crash
                && state.activation_sequence != sequence
            {
                state
                    .removed_edges
                    .retain(|edge| !endpoints.contains(&edge.endpoint()));
            }
            if let Some(state) = &mut node.stopped_crash
                && state.activation_sequence != sequence
            {
                state
                    .removed_edges
                    .retain(|edge| !endpoints.contains(&edge.endpoint()));
            }
        }
    }

    pub(super) fn update_suppressed_down_edges(
        &mut self,
        updated_edges: &[SchedulerLookaheadEdge],
    ) {
        let updates = updated_edges
            .iter()
            .map(|edge| (edge.endpoint(), edge.clone()))
            .collect::<BTreeMap<_, _>>();
        for node in &mut self.nodes {
            if let Some(state) = &mut node.crash {
                replace_existing_edges_by_endpoint(&mut state.removed_edges, &updates);
            }
            if let Some(state) = &mut node.stopped_crash {
                replace_existing_edges_by_endpoint(&mut state.removed_edges, &updates);
            }
        }
    }

    pub(super) fn suppressed_down_edge_exists(
        &self,
        endpoint: &SchedulerLookaheadEdgeEndpoint,
    ) -> bool {
        let has_endpoint = |edges: &[SchedulerLookaheadEdge]| {
            edges.iter().any(|edge| edge.endpoint() == *endpoint)
        };
        self.nodes.iter().any(|node| {
            node.crash
                .as_ref()
                .is_some_and(|state| has_endpoint(&state.removed_edges))
                || node
                    .stopped_crash
                    .as_ref()
                    .is_some_and(|state| has_endpoint(&state.removed_edges))
        })
    }

    pub(super) fn remember_suppressed_down_edge(&mut self, edge: &SchedulerLookaheadEdge) {
        for node in &mut self.nodes {
            if node.id != edge.from && node.id != edge.to {
                continue;
            }
            if let Some(state) = &mut node.crash {
                upsert_edge_by_endpoint(&mut state.removed_edges, edge.clone());
            }
            if let Some(state) = &mut node.stopped_crash {
                upsert_edge_by_endpoint(&mut state.removed_edges, edge.clone());
            }
        }
    }

    pub(super) fn vcpu_quiescence_blockers(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Vec<SchedulerQuiescenceBlocker> {
        let mut states = node.vcpu_idle_states.clone();
        states.sort();
        let mut blockers = Vec::new();
        for state in states {
            if !state.halted {
                blockers.push(SchedulerQuiescenceBlocker::ActiveVcpu {
                    node: node.id.clone(),
                    vcpu: state.vcpu,
                });
            }
            if let Some(deadline) = state.next_deadline {
                blockers.push(SchedulerQuiescenceBlocker::PendingVcpuTimer {
                    node: node.id.clone(),
                    vcpu: state.vcpu,
                    deadline,
                });
            }
            if state.pending_input {
                blockers.push(SchedulerQuiescenceBlocker::PendingVcpuInput {
                    node: node.id.clone(),
                    vcpu: state.vcpu,
                });
            }
        }
        blockers
    }

    /// Queues a topology change for the next quantum boundary.
    ///
    /// This is the infallible legacy entry point and is signature-compatible with
    /// its prior form. A change armed at an activation virtual time the run has
    /// already passed (`at < frontier`) cannot apply — its activation cap can never
    /// reach an instant below the frontier. Rather than wedge the run with a vague,
    /// repeating per-node "missed exact virtual time" boundary error at apply time,
    /// such a change is still enqueued but the next boundary surfaces a clear,
    /// localized [`SchedulerError::TopologyActivationInPast`] (see
    /// `SingleScheduler::apply_topology_changes_at_boundary`). Callers that can
    /// observe a `Result` should prefer [`SingleScheduler::schedule_topology_change`],
    /// which rejects the same condition at enqueue time.
    pub fn queue_topology_change(&mut self, change: SchedulerTopologyChange) {
        self.topology_changes.push(change);
        self.topology_changes.sort_by(topology_change_order);
    }

    /// Consumes a network-link latency recompute signal and schedules lookahead refresh.
    ///
    /// `crucible-device` owns the live network-link fault table. When a link's
    /// conservative minimum-latency bound changes, [`crucible_device::NetLink`]
    /// raises a one-shot recompute flag. This adapter consumes that flag and, when
    /// set, queues a [`SchedulerTopologyChangeTrigger::LatencyChange`] that updates
    /// exactly the directed scheduler edge `from -> to`, when that edge is still
    /// present, with the link's current
    /// [`crucible_device::NetLink::effective_latency_ns`] value. The existing
    /// topology-change path then applies the new edge set at the next quantum
    /// boundary before PICK, preserving the scheduler's boundary invariant while
    /// making live I/O fault latency changes visible to lookahead ([IO-33]).
    ///
    /// Returns `Ok(true)` when a change was queued and `Ok(false)` when the link
    /// had no pending recompute flag.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] if the link reports a zero
    /// effective latency or if the directed edge is absent from the current
    /// effective topology or from a topology edge suppressed by a crashed or
    /// stopped node. Returns [`SchedulerError::TopologyActivationInPast`] if
    /// enqueue-time validation observes an impossible activation time, which does
    /// not occur for this no-activation latency-change path but is propagated from
    /// [`SingleScheduler::schedule_topology_change`] for uniformity.
    pub fn schedule_link_latency_recompute(
        &mut self,
        sequence: u64,
        from: SchedulerNodeId,
        to: SchedulerNodeId,
        link: &mut crucible_device::NetLink,
    ) -> Result<bool, SchedulerError> {
        if !link.lookahead_recompute_pending() {
            return Ok(false);
        }
        let effective_latency_ns = link.effective_latency_ns();
        if effective_latency_ns == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network link effective latency must be strictly positive"),
            });
        }
        let endpoint = SchedulerLookaheadEdgeEndpoint::new(from.clone(), to.clone());
        let mut found = false;
        let updated_edge = SchedulerLookaheadEdge::new(
            from.clone(),
            to.clone(),
            SimDuration {
                nanos: effective_latency_ns,
            },
        );
        for edge in self.effective_topology.edges() {
            if edge.endpoint() == endpoint {
                found = true;
                break;
            }
        }
        if !found {
            found = self.suppressed_down_edge_exists(&endpoint);
        }
        if !found {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "network link latency recompute has no effective topology edge: producer={}:{:?} consumer={}:{:?}",
                    from.node.name, from.kind, to.node.name, to.kind
                ),
            });
        }
        self.schedule_topology_change(SchedulerTopologyChange::update_effective_edges(
            sequence,
            SchedulerTopologyChangeTrigger::LatencyChange,
            vec![updated_edge],
        ))?;
        let consumed = link.take_lookahead_recompute();
        if !consumed {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network link recompute flag disappeared before queueing"),
            });
        }
        Ok(true)
    }

    /// Schedules a topology change for the next quantum boundary, validating the
    /// activation time at enqueue time.
    ///
    /// An activation-timed change is enqueued when `at` is at or above the current
    /// frontier and applied at the next quantum boundary once every node has
    /// converged on the activation instant (via the activation cap); it is rejected
    /// at enqueue time when `at` is strictly below the frontier, since the
    /// activation cap could never move a node backwards onto a passed instant.
    /// Changes with no activation time are always enqueued.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::TopologyActivationInPast`] when `change`'s
    /// activation virtual time is strictly below the current frontier.
    pub fn schedule_topology_change(
        &mut self,
        change: SchedulerTopologyChange,
    ) -> Result<(), SchedulerError> {
        if let Some(activation_time) = change.activation_time {
            let frontier = SimInstant {
                nanos: self.frontier.ticks,
            };
            if activation_time < frontier {
                return Err(SchedulerError::TopologyActivationInPast {
                    at: activation_time.nanos,
                    frontier: frontier.nanos,
                });
            }
        }
        self.topology_changes.push(change);
        self.topology_changes.sort_by(topology_change_order);
        Ok(())
    }

    /// Applies queued topology changes at the current scheduler boundary.
    ///
    /// This is the topology-only portion of the authoritative quantum boundary.
    /// Callers that already own a checked event-log boundary can use it after
    /// deterministic trigger actions enqueue crash, heal, partition, or latency
    /// topology changes, without also running PICK/RUN/RESOLVE for a synthetic
    /// scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by the scheduler topology boundary,
    /// including topology activations armed in the past or inconsistent
    /// activation rendezvous state.
    pub fn apply_queued_topology_changes_at_boundary(&mut self) -> Result<bool, SchedulerError> {
        self.apply_topology_changes_at_boundary()
    }

    pub(super) fn apply_topology_changes_at_boundary(&mut self) -> Result<bool, SchedulerError> {
        if self.topology_changes.is_empty() {
            return Ok(false);
        }

        let mut changes = std::mem::take(&mut self.topology_changes);
        changes.sort_by(topology_change_order);
        let mut deferred = Vec::new();
        let mut applied = false;

        let frontier = SimInstant {
            nanos: self.frontier.ticks,
        };
        for change in changes {
            if let Some(activation_time) = change.activation_time {
                // Fail loud and localized for a change armed in the past. The
                // infallible `queue_topology_change` entry point cannot reject at
                // enqueue time, so an `at < frontier` change reaches here; surface a
                // clear `TopologyActivationInPast` rather than deferring it forever
                // (a silent wedge) or letting `topology_activation_ready` report a
                // vague per-node skew error.
                if activation_time < frontier {
                    return Err(SchedulerError::TopologyActivationInPast {
                        at: activation_time.nanos,
                        frontier: frontier.nanos,
                    });
                }
                if !self.topology_activation_ready(activation_time)? {
                    deferred.push(change);
                    continue;
                }
            }

            let SchedulerTopologyChange {
                sequence,
                trigger,
                activation_time,
                effect,
            } = change;
            if let Some(activation_time) = activation_time {
                self.record_rendezvous(SchedulerRendezvousPurpose::TopologySwap, activation_time)?;
            }
            let graph = match effect {
                SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(effective_edges) => {
                    self.replace_suppressed_down_edges(&effective_edges);
                    SchedulerLookaheadGraph::from_edges(effective_edges)
                }
                SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
                    self.remove_suppressed_down_edges(sequence, &endpoints);
                    self.effective_topology.remove_effective_edges(endpoints)
                }
                SchedulerTopologyChangeEffect::UpdateEffectiveEdges(updated_edges) => {
                    self.update_suppressed_down_edges(&updated_edges);
                    self.effective_topology
                        .update_effective_edges(updated_edges)
                }
                SchedulerTopologyChangeEffect::RestoreEffectiveEdges(restored_edges) => self
                    .effective_topology
                    .restore_effective_edges(restored_edges),
            };
            let graph = self.suppress_down_edges(graph);
            let mut updates = Vec::with_capacity(self.nodes.len());
            for node in &mut self.nodes {
                let previous_lookahead = node.network_lookahead;
                let recomputed_lookahead = graph.lookahead(&node.id);
                node.network_lookahead = recomputed_lookahead;
                updates.push(SchedulerTopologyLookaheadUpdate {
                    node: node.id.clone(),
                    previous_lookahead,
                    recomputed_lookahead,
                });
            }

            self.effective_topology = graph;
            self.topology_epoch = self.topology_epoch.checked_add(1).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("scheduler topology epoch overflow"),
                }
            })?;
            self.topology_change_applications
                .push(SchedulerTopologyChangeApplication {
                    topology_epoch: self.topology_epoch,
                    sequence,
                    trigger,
                    activation_time,
                    updates,
                });
            applied = true;
        }

        deferred.sort_by(topology_change_order);
        self.topology_changes = deferred;

        Ok(applied)
    }

    pub(super) fn record_rendezvous(
        &mut self,
        purpose: SchedulerRendezvousPurpose,
        virtual_time: SimInstant,
    ) -> Result<(), SchedulerError> {
        let mut nodes = Vec::new();
        for node in &self.nodes {
            if matches!(
                node.activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                continue;
            }

            let current_time = self.node_current_time(node)?;
            if current_time != virtual_time {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "scheduler {:?} rendezvous requires zero skew for {}:{:?}: current={} rendezvous={}",
                        purpose,
                        node.id.node.name,
                        node.id.kind,
                        current_time.nanos,
                        virtual_time.nanos
                    ),
                });
            }
            nodes.push(SchedulerRendezvousNode {
                node: node.id.clone(),
                virtual_time: current_time,
            });
        }

        self.rendezvous_records.push(SchedulerRendezvousRecord {
            sequence: self.rendezvous_records.len() as u64,
            purpose,
            virtual_time,
            nodes,
        });
        Ok(())
    }

    pub(super) fn actor_state_snapshot(&self) -> SchedulerActorStateSnapshot {
        SchedulerActorStateSnapshot {
            configuration: self.configuration.clone(),
            node_counters: self
                .nodes
                .iter()
                .map(|node| (node.id.clone(), node.counter))
                .collect(),
            pending_event_count: self.pending_events.len(),
            pending_control_count: self.control_inbox.len(),
            decision_rng_cursor: self.decision_rng_cursor.clone(),
            control_applications: self.control_applications.clone(),
            preemption_applications: self.preemption_applications.clone(),
            boundary_yields: self.boundary_yields,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub(super) fn reached_time_limit(&self) -> Result<bool, SchedulerError> {
        let mut saw_time_limited_state = false;

        for node in &self.nodes {
            let has_finite_projection = match self.effective_node_activity(node) {
                SchedulerNodeActivity::Runnable => true,
                SchedulerNodeActivity::Idle => self.idle_wake_time(node)?.is_some(),
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => false,
            };
            if has_finite_projection {
                saw_time_limited_state = true;
                let current_time = self.node_current_time(node)?;
                if current_time < self.time_limit {
                    return Ok(false);
                }
            }
        }

        Ok(saw_time_limited_state)
    }

    pub(super) fn exhausted_quantum_budget(&self) -> bool {
        self.quanta >= self.quantum_budget
    }

    pub(super) fn pick_global_minimum_horizon_node(
        &self,
    ) -> Result<Option<AdvanceCandidate>, SchedulerError> {
        Ok(self.advance_candidates()?.into_iter().next())
    }

    pub(super) fn advance_candidates(&self) -> Result<Vec<AdvanceCandidate>, SchedulerError> {
        let mut candidates = Vec::new();
        let rendezvous_cap = self.shared_rendezvous_cap()?;
        let topology_activation_cap = self.pending_topology_activation_cap()?;

        for (index, node) in self.nodes.iter().enumerate() {
            if let Some(candidate) =
                self.advance_candidate(index, node, rendezvous_cap, topology_activation_cap)?
            {
                candidates.push(candidate);
            }
        }

        candidates.sort_by(|left, right| {
            left.target_time
                .cmp(&right.target_time)
                .then_with(|| left.key.node.cmp(&right.key.node))
                .then_with(|| left.key.virtual_time.cmp(&right.key.virtual_time))
                .then_with(|| left.index.cmp(&right.index))
        });

        Ok(candidates)
    }

    pub(super) fn concurrent_run_set_from_candidates(
        &self,
        max_host_workers: usize,
        candidates: &[AdvanceCandidate],
    ) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        self.validate_max_host_workers(max_host_workers)?;
        let mut selected = Vec::new();
        let frontier = SimInstant {
            nanos: self.frontier.ticks,
        };
        let target_time = candidates.first().map(|candidate| candidate.target_time);
        // A parked peer can hold the global frontier behind the canonical
        // global-minimum candidate. Batching frontier peers in that state would
        // reorder PICK relative to the authoritative serial path. Advance only
        // that canonical first candidate; normal independent batches resume
        // once the common frontier is restored.
        if let Some(candidate) = candidates.first() {
            let draft = self.advance_plan_draft(candidate)?;
            let current_time =
                self.node_time_for_counter(&self.nodes[draft.index], draft.before)?;
            if current_time != frontier {
                selected.push(SchedulerConcurrentRunCandidate {
                    node: draft.node,
                    current_time,
                    target_time: candidate.target_time,
                    max_advance_icount: draft.target_counter,
                });
                return Ok(SchedulerConcurrentRunSet {
                    max_host_workers,
                    candidates: selected,
                });
            }
        }

        for candidate in candidates.iter() {
            if selected.len() >= max_host_workers {
                break;
            }
            if Some(candidate.target_time) != target_time {
                break;
            }
            let draft = self.advance_plan_draft(candidate)?;
            let current_time =
                self.node_time_for_counter(&self.nodes[draft.index], draft.before)?;
            if current_time != frontier {
                continue;
            }
            selected.push(SchedulerConcurrentRunCandidate {
                node: draft.node,
                current_time,
                target_time: candidate.target_time,
                max_advance_icount: draft.target_counter,
            });
        }

        Ok(SchedulerConcurrentRunSet {
            max_host_workers,
            candidates: selected,
        })
    }

    pub(super) fn advance_plan_draft(
        &self,
        candidate: &AdvanceCandidate,
    ) -> Result<AdvancePlanDraft, SchedulerError> {
        let selected_index = candidate.index;
        let selected_node = self.nodes[selected_index].id.clone();
        let before = self.nodes[selected_index].counter;
        let selected_runtime_node = &self.nodes[selected_index];
        let target_counter = self
            .node_counter_for_time_ceil(selected_runtime_node, candidate.target_time)?
            .ticks;
        let projected_target = self.node_time_for_counter(
            selected_runtime_node,
            NodeCounter {
                ticks: target_counter,
            },
        )?;
        if !candidate.allow_ceil_past_target && projected_target > candidate.target_time {
            return Err(scheduler_ceiling_overshoot_error(
                &selected_node,
                "target_at",
                candidate.target_time,
                projected_target,
            ));
        }
        if projected_target > candidate.target_time {
            let current_time = self.node_time_for_counter(selected_runtime_node, before)?;
            if let NetworkLookahead::Finite(duration) = selected_runtime_node.network_lookahead {
                let network_target = current_time + duration;
                if network_target > candidate.target_time && projected_target > network_target {
                    return Err(scheduler_ceiling_overshoot_error(
                        &selected_node,
                        "network_cap_at",
                        network_target,
                        projected_target,
                    ));
                }
            }
            if self.time_limit > candidate.target_time && projected_target > self.time_limit {
                return Err(scheduler_ceiling_overshoot_error(
                    &selected_node,
                    "time_limit_at",
                    self.time_limit,
                    projected_target,
                ));
            }
            if let Some(cap) = self.shared_rendezvous_cap()?
                && cap > candidate.target_time
                && projected_target > cap
            {
                return Err(scheduler_ceiling_overshoot_error(
                    &selected_node,
                    "rendezvous_at",
                    cap,
                    projected_target,
                ));
            }
            if let Some(dependency) =
                unresolved_cross_node_dependencies(&selected_node, &self.pending_events)
                    .into_iter()
                    .find(|dependency| {
                        dependency.virtual_time > candidate.target_time
                            && projected_target > dependency.virtual_time
                    })
            {
                return Err(scheduler_ceiling_overshoot_error(
                    &selected_node,
                    "dependency_at",
                    dependency.virtual_time,
                    projected_target,
                ));
            }
            for event in &self.pending_events {
                if event.key.consumer() == &selected_node {
                    let event_time = SimInstant {
                        nanos: event.key.virtual_time().ticks,
                    };
                    if event_time > candidate.target_time && projected_target > event_time {
                        return Err(scheduler_ceiling_overshoot_error(
                            &selected_node,
                            "pending_event_at",
                            event_time,
                            projected_target,
                        ));
                    }
                }
            }
        } else if let Some(dependency) = &candidate.conservative_dependency
            && projected_target > dependency.virtual_time
        {
            return Err(scheduler_ceiling_overshoot_error(
                &selected_node,
                "dependency_at",
                dependency.virtual_time,
                projected_target,
            ));
        }

        Ok(AdvancePlanDraft {
            index: selected_index,
            node: selected_node,
            before,
            target_counter,
            projected_target_time: projected_target,
            quiescent_horizon: candidate.quiescent_horizon,
        })
    }

    pub(super) fn advance_candidate(
        &self,
        index: usize,
        node: &RuntimeSchedulerNode,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<Option<AdvanceCandidate>, SchedulerError> {
        let current_time = self.node_current_time(node)?;
        let EffectiveHorizonProjection::Finite {
            target_time,
            quiescent_horizon,
            conservative_dependency,
            allow_ceil_past_target,
        } = self.effective_horizon(node, current_time, rendezvous_cap, topology_activation_cap)?
        else {
            return Ok(None);
        };

        if current_time >= target_time {
            return Ok(None);
        }

        Ok(Some(AdvanceCandidate {
            index,
            key: self.node_timeline_key(node, index as u64)?,
            target_time,
            quiescent_horizon,
            conservative_dependency,
            allow_ceil_past_target,
        }))
    }

    pub(super) fn effective_horizon(
        &self,
        node: &RuntimeSchedulerNode,
        current_time: SimInstant,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<EffectiveHorizonProjection, SchedulerError> {
        match self.effective_node_activity(node) {
            SchedulerNodeActivity::Runnable => {
                let window = self.advance_window(
                    node,
                    current_time,
                    rendezvous_cap,
                    topology_activation_cap,
                )?;
                Ok(EffectiveHorizonProjection::Finite {
                    target_time: window.target_time,
                    quiescent_horizon: window.quiescent_horizon,
                    conservative_dependency: window.conservative_dependency,
                    allow_ceil_past_target: window.allow_ceil_past_target,
                })
            }
            SchedulerNodeActivity::Idle => {
                self.idle_advance_candidate(node, rendezvous_cap, topology_activation_cap)
            }
            SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => {
                Ok(EffectiveHorizonProjection::Infinite)
            }
        }
    }

    pub(super) fn idle_advance_candidate(
        &self,
        node: &RuntimeSchedulerNode,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<EffectiveHorizonProjection, SchedulerError> {
        let projection = self.effective_clock_for_node(node)?;
        if projection.source != SchedulerEffectiveClockSource::IdleWake {
            if let Some(activation_time) = topology_activation_cap {
                let requested_target = rendezvous_cap.unwrap_or(activation_time);
                let target_time = min_instant(requested_target, self.time_limit);
                if projection.current_time < target_time {
                    return Ok(EffectiveHorizonProjection::Finite {
                        target_time,
                        quiescent_horizon: None,
                        conservative_dependency: None,
                        allow_ceil_past_target: false,
                    });
                }
            }
            return Ok(EffectiveHorizonProjection::Infinite);
        }
        let Some(wake_target) = self.idle_wake_target(node)? else {
            return Ok(EffectiveHorizonProjection::Infinite);
        };
        let mut wake_time = wake_target.wake_time;
        let mut allow_ceil_past_target = wake_target.allow_ceil_past_target;
        wake_time = min_instant(wake_time, self.time_limit);
        if self.time_limit <= wake_target.wake_time {
            allow_ceil_past_target = false;
        }
        if let Some(cap) = rendezvous_cap {
            if cap <= wake_time {
                allow_ceil_past_target = false;
            }
            wake_time = min_instant(wake_time, cap);
        }

        Ok(EffectiveHorizonProjection::Finite {
            target_time: wake_time,
            quiescent_horizon: Some(wake_time),
            conservative_dependency: None,
            allow_ceil_past_target,
        })
    }

    pub(super) fn effective_clock_for_node(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<SchedulerEffectiveClock, SchedulerError> {
        let current_time = self.node_current_time(node)?;
        let (effective_time, source) = match self.effective_node_activity(node) {
            SchedulerNodeActivity::Idle => match self.idle_wake_time(node)? {
                Some(wake_time) if wake_time > current_time => {
                    (wake_time, SchedulerEffectiveClockSource::IdleWake)
                }
                _ => (current_time, SchedulerEffectiveClockSource::Current),
            },
            SchedulerNodeActivity::Runnable
            | SchedulerNodeActivity::Halted
            | SchedulerNodeActivity::Done => (current_time, SchedulerEffectiveClockSource::Current),
        };

        Ok(SchedulerEffectiveClock {
            node: node.id.clone(),
            current_time,
            effective_time,
            source,
        })
    }

    pub(super) fn idle_wake_time(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<SimInstant>, SchedulerError> {
        Ok(self.idle_wake_target(node)?.map(|target| target.wake_time))
    }

    pub(super) fn effective_exact_local_event(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<ExactLocalEvent, SchedulerError> {
        let mut exact_local_event = next_exact_local_event(
            &node.id,
            node.exact_local_event.clone(),
            &self.pending_events,
            self.timeline.shift(),
        )?;
        // Fold the device sub-node's in-flight head into the node's exact horizon
        // ([IO-3], [SCHED-10]): the requester is fast-forwarded EXACTLY to its next
        // device completion, with no conservative slack. The term wins only when it
        // is at or before any timer/pending term already selected.
        if let Some(device_time) = self.device_horizons.get(&node.id.node).copied() {
            let device_event = ExactLocalEvent::IoCompletion {
                virtual_time: device_time,
                sub_node: node.id.clone(),
            };
            match exact_local_event.virtual_time() {
                Some(current) if current <= device_time => {}
                _ => exact_local_event = device_event,
            }
        }
        if let Some(vcpu_deadline) = self.earliest_vcpu_deadline(node) {
            match exact_local_event.virtual_time() {
                Some(current) if current <= vcpu_deadline => {}
                _ => {
                    exact_local_event = ExactLocalEvent::TimerDeadline {
                        virtual_time: vcpu_deadline,
                    };
                }
            }
        }
        Ok(exact_local_event)
    }

    pub(super) fn idle_wake_target(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<IdleWakeTarget>, SchedulerError> {
        let exact_local_event = self.effective_exact_local_event(node)?;
        let mut target = exact_local_event
            .virtual_time()
            .map(|wake_time| IdleWakeTarget {
                wake_time,
                allow_ceil_past_target: horizon_source_allows_ceiling_past_target(
                    exact_local_event_horizon_source(&exact_local_event),
                ),
            });

        for event in &self.pending_events {
            if event.key.consumer() == &node.id {
                let event_time = SimInstant {
                    nanos: event.key.virtual_time().ticks,
                };
                merge_idle_wake_target(&mut target, event_time, false);
            }
        }

        Ok(target)
    }

    pub(super) fn earliest_vcpu_deadline(&self, node: &RuntimeSchedulerNode) -> Option<SimInstant> {
        node.vcpu_idle_states
            .iter()
            .filter_map(|state| state.next_deadline)
            .min()
    }

    pub(super) fn advance_window(
        &self,
        node: &RuntimeSchedulerNode,
        current_time: SimInstant,
        rendezvous_cap: Option<SimInstant>,
        topology_activation_cap: Option<SimInstant>,
    ) -> Result<AdvanceWindow, SchedulerError> {
        let exact_local_event = self.effective_exact_local_event(node)?;
        let horizon = horizon_from_network_lookahead(
            current_time,
            node.network_lookahead,
            exact_local_event,
            self.timeline.shift(),
        )?;
        let finite_horizon = horizon.virtual_time().unwrap_or(self.time_limit);
        let mut allow_ceil_past_target = horizon
            .virtual_time()
            .is_some_and(|_| horizon_source_allows_ceiling_past_target(horizon.source));
        if let NetworkLookahead::Finite(duration) = node.network_lookahead {
            let network_target = current_time + duration;
            if network_target <= finite_horizon {
                allow_ceil_past_target = false;
            }
        }
        let mut requested_target = min_instant(finite_horizon, self.time_limit);
        if self.time_limit <= finite_horizon {
            allow_ceil_past_target = false;
        }
        if let Some(cap) = rendezvous_cap {
            if cap <= requested_target {
                allow_ceil_past_target = false;
            }
            requested_target = min_instant(requested_target, cap);
        }
        let authorization = authorize_conservative_advance(
            &node.id,
            current_time,
            requested_target,
            &self.pending_events,
        )?;
        let mut target_time = authorization.authorized_target;
        let conservative_dependency = authorization.blocking_dependency;
        if conservative_dependency.is_some() {
            allow_ceil_past_target = false;
        }

        for event in &self.pending_events {
            if event.key.consumer() == &node.id {
                let event_time = SimInstant {
                    nanos: event.key.virtual_time().ticks,
                };
                if event_time > current_time && event_time <= target_time {
                    if event_time < target_time {
                        target_time = event_time;
                    }
                    allow_ceil_past_target = false;
                }
            }
        }

        let mut quiescent_horizon = horizon.virtual_time();
        // A node bound by the conservative network-lookahead term *derived from a
        // live effective topology* is held at a *moving* cap (`vt(n) +
        // lookahead(n)`), not a genuine local quiescence point: as the global
        // frontier climbs, that bound climbs with it. Parking such a node `Idle` is
        // the freeze defect of RFC-0010 [SCHED-7]/[SCHED-8] — the only
        // `Idle -> Runnable` re-promotion path (`effective_node_activity`) requires
        // a non-halted or pending-input vCPU, so a network/disk sub-node, or a VM
        // whose vCPUs are all halted with no pending input, would never be re-PICKed
        // and the run would freeze. Only a genuine local stop (an exact-local timer
        // / I/O completion / fault, the same set that
        // `horizon_source_allows_ceiling_past_target` admits) is a quiescence
        // point. A node held at the moving network cap keeps no `quiescent_horizon`,
        // so it stays `Runnable` and is re-PICKed for the next interval (iterative
        // conservative-PDES advance, [SCHED-5]).
        //
        // The gate on a non-empty `effective_topology` mirrors the synthetic-
        // liveness exemption: when no live edge set is installed, the per-node
        // `network_lookahead` is a pre-supplied fixed parking point rather than a
        // frontier-tracking CMB bound, so the legacy idle-on-reach behavior is
        // retained.
        let network_bounded = !self.effective_topology.edges().is_empty()
            && horizon.source == SchedulerHorizonSource::NetworkLookahead;
        if network_bounded {
            quiescent_horizon = None;
        }
        if let (Some(horizon_time), Some(activation_time)) =
            (quiescent_horizon, topology_activation_cap)
            && current_time < activation_time
            && horizon_time < activation_time
        {
            quiescent_horizon = None;
        }

        Ok(AdvanceWindow {
            target_time,
            quiescent_horizon,
            conservative_dependency,
            allow_ceil_past_target,
        })
    }

    pub(super) fn publish_run_ceiling(
        &mut self,
        node: SchedulerNodeId,
        current_icount: NodeCounter,
        max_advance_icount: u64,
        target_time: SimInstant,
    ) -> Result<SchedulerRunCeilingPublication, SchedulerError> {
        if max_advance_icount < current_icount.ticks {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "RUN max-advance ceiling for {}:{:?} is before current icount: current={} ceiling={}",
                    node.node.name, node.kind, current_icount.ticks, max_advance_icount
                ),
            });
        }

        let publication = SchedulerRunCeilingPublication {
            sequence: self.ceiling_publications.len() as u64,
            quantum: self.quanta,
            node,
            current_icount,
            max_advance_icount,
            icount_shift: self.timeline.shift(),
            target_time,
        };
        self.ceiling_publications.push(publication.clone());
        Ok(publication)
    }

    pub(super) fn planned_run_subdivision(
        &self,
        node: &SchedulerNodeId,
        current_icount: NodeCounter,
        max_advance_icount: u64,
    ) -> Result<Option<PlannedRunSubdivision>, SchedulerError> {
        let Some(policy) = self
            .run_subdivision_policies
            .iter()
            .find(|policy| &policy.node == node)
        else {
            return Ok(None);
        };
        let slices = scheduler_rr_run_subdivision(
            current_icount,
            max_advance_icount,
            policy.vcpu_count,
            policy.rr_switch_quantum,
        )?;

        Ok(Some(PlannedRunSubdivision {
            policy: policy.clone(),
            slices,
        }))
    }

    pub(super) fn record_run_subdivision(
        &mut self,
        planned: PlannedRunSubdivision,
        ceiling: SchedulerRunCeilingPublication,
    ) {
        self.run_subdivision_records
            .push(SchedulerRunSubdivisionRecord {
                sequence: self.run_subdivision_records.len() as u64,
                quantum: ceiling.quantum,
                policy: planned.policy,
                ceiling,
                slices: planned.slices,
            });
    }

    pub(super) fn planned_preemptions_for_run(
        &self,
        node: &SchedulerNodeId,
        current_icount: NodeCounter,
        ceiling: &SchedulerRunCeilingPublication,
    ) -> Result<Vec<PlannedPreemptionApplication>, SchedulerError> {
        let Some(runtime_node) = self.nodes.iter().find(|runtime| &runtime.id == node) else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "preemption targets missing scheduler node: {}:{:?}",
                    node.node.name, node.kind
                ),
            });
        };
        let deadline_icount = Icount {
            retired: current_icount.ticks,
        };
        let horizon_icount = Icount {
            retired: ceiling.max_advance_icount,
        };
        let mut decisions = self
            .preemption_requests
            .iter()
            .filter(|decision| decision.node == node.node && node.kind == SchedulingNodeKind::Vm)
            .cloned()
            .collect::<Vec<_>>();
        decisions.sort_by(preemption_decision_order);
        if decisions.len() > 1 {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "multiple explorer preemptions for one RUN are not supported: node={} count={}",
                    node.node.name,
                    decisions.len()
                ),
            });
        }

        let mut planned = Vec::with_capacity(decisions.len());
        for decision in decisions {
            if decision.at < deadline_icount || decision.at > horizon_icount {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "explorer preemption for {} outside authorized window: at={} deadline={} horizon={} ceiling={}",
                        decision.node.name,
                        decision.at.retired,
                        deadline_icount.retired,
                        horizon_icount.retired,
                        ceiling.max_advance_icount
                    ),
                });
            }
            let virtual_time =
                self.node_time_for_counter(runtime_node, NodeCounter::from_icount(decision.at))?;
            planned.push(PlannedPreemptionApplication {
                node: node.clone(),
                decision,
                virtual_time,
                deadline_icount,
                horizon_icount,
                ceiling: ceiling.clone(),
            });
        }

        Ok(planned)
    }

    pub(super) fn commit_preemption_applications(
        &mut self,
        planned: Vec<PlannedPreemptionApplication>,
    ) {
        for planned in planned {
            if let Some(index) = self
                .preemption_requests
                .iter()
                .position(|decision| decision == &planned.decision)
            {
                self.preemption_requests.remove(index);
            }
            self.preemption_applications
                .push(SchedulerPreemptionApplication {
                    sequence: self.preemption_applications.len() as u64,
                    quantum: planned.ceiling.quantum,
                    node: planned.node,
                    decision: planned.decision,
                    virtual_time: planned.virtual_time,
                    deadline_icount: planned.deadline_icount,
                    horizon_icount: planned.horizon_icount,
                    ceiling: planned.ceiling,
                });
        }
    }

    pub(super) fn topology_activation_ready(
        &self,
        activation_time: SimInstant,
    ) -> Result<bool, SchedulerError> {
        for node in &self.nodes {
            if matches!(
                node.activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                continue;
            }

            let current_time = self.node_current_time(node)?;
            if current_time > activation_time {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "topology activation rendezvous missed exact virtual time for {}:{:?}: current={} activation={}",
                        node.id.node.name, node.id.kind, current_time.nanos, activation_time.nanos
                    ),
                });
            }
            if current_time < activation_time {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub(super) fn pending_topology_activation_cap(
        &self,
    ) -> Result<Option<SimInstant>, SchedulerError> {
        let mut cap = None;

        for change in &self.topology_changes {
            let Some(activation_time) = change.activation_time else {
                continue;
            };
            if self.topology_activation_ready(activation_time)? {
                continue;
            }

            cap = Some(match cap {
                Some(current) => min_instant(current, activation_time),
                None => activation_time,
            });
        }

        Ok(cap)
    }

    pub(super) fn shared_rendezvous_cap(&self) -> Result<Option<SimInstant>, SchedulerError> {
        let fixed_cap = rendezvous_cap_for(
            SimInstant {
                nanos: self.frontier.ticks,
            },
            self.rendezvous,
        )?;
        let topology_cap = self.pending_topology_activation_cap()?;
        Ok([fixed_cap, topology_cap, self.branch_frontier_cap]
            .into_iter()
            .flatten()
            .min())
    }

    pub(super) fn drive_concurrent_authoritative_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError> {
        self.validate_max_host_workers(max_host_workers)?;
        if request.configuration != self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum request configuration is not the scheduler frontier",
                ),
            });
        }

        self.last_advance = None;
        self.last_topology_recompute = false;

        // Fold each device sub-node's in-flight head into its target node's exact
        // I/O-completion horizon term BEFORE PICK, so a requester's horizon is the
        // device's real next completion ([IO-3], [SCHED-10]).
        self.refresh_device_horizons()?;

        self.admit_control_at_boundary(request.control);
        let SchedulerControlDrain {
            events: mut boundary_resolved_events,
            applications: mut boundary_control_applications,
        } = self.drain_control_events()?;
        let topology_recomputed = self.apply_topology_changes_at_boundary()?;
        self.last_topology_recompute = topology_recomputed;

        let candidates = self.advance_candidates()?;
        let run_set = self.concurrent_run_set_from_candidates(max_host_workers, &candidates)?;
        let selected_candidates = candidates
            .into_iter()
            .filter(|candidate| {
                run_set
                    .candidates
                    .iter()
                    .any(|run| run.node == self.nodes[candidate.index].id)
            })
            .collect::<Vec<_>>();

        if selected_candidates.is_empty() {
            let at = SimInstant {
                nanos: self.frontier.ticks,
            };
            let decisions = self.emit_quantum_decisions(&boundary_resolved_events, &[], &[], at)?;
            let emit_boundary = !decisions.is_empty() || topology_recomputed;
            let event_log = self.emit_quantum_event_log(
                &boundary_resolved_events,
                &decisions,
                &[],
                at,
                emit_boundary,
            )?;
            let configuration = self.step_quantum(&decisions);
            if !decisions.is_empty() {
                self.configuration = configuration.clone();
                self.quanta = self.quanta.saturating_add(1);
                self.yield_to_control_inbox();
            } else if topology_recomputed {
                self.quanta = self.quanta.saturating_add(1);
                self.yield_to_control_inbox();
            }
            self.commit_control_applications(boundary_control_applications);
            let outcome = QuantumOutcome {
                configuration,
                frontier: self.frontier,
                advanced_node: None,
                resolved_events: boundary_resolved_events,
                decisions,
                event_log_entries: event_log.entries,
                event_log_segment_bytes: event_log.segment_bytes,
                event_log_segment_text: event_log.segment_text,
                event_log_segment_hash: event_log.segment_hash,
                event_log_offset: event_log.offset,
                scheduler_quiescence: Some(self.quiescence()?),
            };
            return Ok(SchedulerConcurrentQuantumOutcome {
                run_set,
                outcomes: vec![outcome],
            });
        }

        let mut plans = Vec::with_capacity(selected_candidates.len());
        for candidate in selected_candidates {
            let plan = {
                let critical_section = SchedulerCriticalSection::enter(self);
                critical_section.advance_plan(candidate)?
            };
            plans.push(plan);
        }

        let plan_preemptions = plans
            .iter()
            .map(|plan| self.planned_preemptions_for_run(&plan.node, plan.before, &plan.ceiling))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ordered_plans = plans
            .into_iter()
            .zip(plan_preemptions.into_iter())
            .enumerate()
            .map(|(index, (plan, preemptions))| {
                Ok((
                    concurrent_completion_order_key(&plan, &preemptions, self.timeline.shift())?,
                    index,
                    plan,
                    preemptions,
                ))
            })
            .collect::<Result<Vec<_>, SchedulerError>>()?;
        ordered_plans.sort_by(|left, right| {
            left.0
                .ticks
                .cmp(&right.0.ticks)
                .then_with(|| left.1.cmp(&right.1))
        });

        let mut outcomes = Vec::with_capacity(ordered_plans.len());
        for (_, _, plan, preemptions) in ordered_plans {
            let selected_node = plan.node.clone();
            let before = plan.before;
            let (after, after_time, yielded_before_advance) =
                self.advance_node_after_yield(&plan)?;
            let mut resolved_events = if outcomes.is_empty() {
                std::mem::take(&mut boundary_resolved_events)
            } else {
                Vec::new()
            };
            let control_applications = if outcomes.is_empty() {
                std::mem::take(&mut boundary_control_applications)
            } else {
                Vec::new()
            };
            let shift = self.timeline.shift();
            let frame_deliveries = resolve_due_scheduled_events(
                &mut self.pending_events,
                &selected_node,
                after_time,
                shift,
            )?;

            // Device I/O completions are cross-node events too: drain each
            // targeting sub-node's due completions at the exact delivery icount
            // ([SCHED-29]), minting their sequence from the owned counter on the
            // LIVE RESOLVE path ([SCHED-18]), and append the fault decisions they
            // drew ([SCHED-30]).
            let (device_events, device_decisions) =
                self.resolve_device_completions(&selected_node, after.ticks)?;
            // Order (frame ++ device) deliveries together by the §8.6 key, keeping
            // the control/boundary events prefixed exactly as the no-device path
            // does ([SCHED-33]).
            resolved_events.extend(merge_node_deliveries(frame_deliveries, device_events));

            let decisions = self.emit_quantum_decisions(
                &resolved_events,
                &preemptions,
                &device_decisions,
                after_time,
            )?;
            let event_log = self.emit_quantum_event_log(
                &resolved_events,
                &decisions,
                &preemptions,
                after_time,
                true,
            )?;
            let configuration = self.step_quantum(&decisions);
            let frontier = frontier_for(&self.nodes, self.timeline.shift())?;

            self.configuration = configuration.clone();
            self.frontier = frontier;
            self.quanta = self.quanta.saturating_add(1);
            self.last_advance = Some(NodeAdvance {
                node: selected_node.clone(),
                before,
                after,
                ceiling: plan.ceiling.clone(),
                yielded_before_advance,
            });
            self.yield_to_control_inbox();
            self.commit_control_applications(control_applications);
            if let Some(subdivision) = plan.subdivision {
                self.record_run_subdivision(subdivision, plan.ceiling.clone());
            }
            self.commit_preemption_applications(preemptions);

            outcomes.push(QuantumOutcome {
                configuration,
                frontier: self.frontier,
                advanced_node: Some(selected_node),
                resolved_events,
                decisions,
                event_log_entries: event_log.entries,
                event_log_segment_bytes: event_log.segment_bytes,
                event_log_segment_text: event_log.segment_text,
                event_log_segment_hash: event_log.segment_hash,
                event_log_offset: event_log.offset,
                scheduler_quiescence: Some(self.quiescence()?),
            });
        }

        Ok(SchedulerConcurrentQuantumOutcome { run_set, outcomes })
    }

    pub(super) fn drive_authoritative_quantum(
        &mut self,
        request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        if request.configuration != self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum request configuration is not the scheduler frontier",
                ),
            });
        }

        self.last_advance = None;
        self.last_topology_recompute = false;

        // Fold each device sub-node's in-flight head into its target node's exact
        // I/O-completion horizon term BEFORE PICK, so the requester's horizon is
        // the device's real next completion ([IO-3], [SCHED-10]).
        self.refresh_device_horizons()?;

        // Boundary admission phase: accept control exposed by the previous STEP yield.
        self.admit_control_at_boundary(request.control);
        let SchedulerControlDrain {
            events: mut resolved_events,
            applications: mut control_applications,
        } = self.drain_control_events()?;
        let topology_recomputed = self.apply_topology_changes_at_boundary()?;
        self.last_topology_recompute = topology_recomputed;
        // PICK phase: select the next effective-horizon candidate once.
        let candidate = match self.pick_global_minimum_horizon_node()? {
            Some(candidate) => candidate,
            None => {
                // Control-only EMIT/STEP: no node RUN occurs.
                let decisions = self.emit_quantum_decisions(
                    &resolved_events,
                    &[],
                    &[],
                    SimInstant {
                        nanos: self.frontier.ticks,
                    },
                )?;
                let emit_boundary = !decisions.is_empty() || topology_recomputed;
                let event_log = self.emit_quantum_event_log(
                    &resolved_events,
                    &decisions,
                    &[],
                    SimInstant {
                        nanos: self.frontier.ticks,
                    },
                    emit_boundary,
                )?;
                let configuration = self.step_quantum(&decisions);
                if !decisions.is_empty() {
                    self.configuration = configuration.clone();
                    self.quanta = self.quanta.saturating_add(1);
                    // STEP yield phase: expose the control inbox before the next PICK.
                    self.yield_to_control_inbox();
                } else if topology_recomputed {
                    self.quanta = self.quanta.saturating_add(1);
                    self.yield_to_control_inbox();
                }
                self.commit_control_applications(std::mem::take(&mut control_applications));
                return Ok(QuantumOutcome {
                    configuration,
                    frontier: self.frontier,
                    advanced_node: None,
                    resolved_events,
                    decisions,
                    event_log_entries: event_log.entries,
                    event_log_segment_bytes: event_log.segment_bytes,
                    event_log_segment_text: event_log.segment_text,
                    event_log_segment_hash: event_log.segment_hash,
                    event_log_offset: event_log.offset,
                    scheduler_quiescence: Some(self.quiescence()?),
                });
            }
        };

        // RUN phase: compute one plan under the scheduler lock, then advance after yield.
        let plan = {
            let critical_section = SchedulerCriticalSection::enter(self);
            critical_section.advance_plan(candidate)?
        };

        let selected_node = plan.node.clone();
        let before = plan.before;
        let preemptions =
            self.planned_preemptions_for_run(&selected_node, before, &plan.ceiling)?;
        let (after, after_time, yielded_before_advance) = self.advance_node_after_yield(&plan)?;
        // RESOLVE phase: collect due events for the node that just advanced.
        let shift = self.timeline.shift();
        let frame_deliveries = resolve_due_scheduled_events(
            &mut self.pending_events,
            &selected_node,
            after_time,
            shift,
        )?;

        // Device I/O completions are cross-node events too: drain each targeting
        // sub-node's due completions at the exact delivery icount ([SCHED-29]),
        // minting their sequence from the owned counter on the LIVE RESOLVE path
        // ([SCHED-18]), and append the fault decisions they drew ([SCHED-30]).
        let (device_events, device_decisions) =
            self.resolve_device_completions(&selected_node, after.ticks)?;
        // Order (frame ++ device) deliveries together by the §8.6 key, keeping the
        // control events prefixed exactly as the no-device path does ([SCHED-33]).
        resolved_events.extend(merge_node_deliveries(frame_deliveries, device_events));

        // EMIT phase: convert happenings into decisions and append event-log entries.
        let decisions = self.emit_quantum_decisions(
            &resolved_events,
            &preemptions,
            &device_decisions,
            after_time,
        )?;
        let event_log = self.emit_quantum_event_log(
            &resolved_events,
            &decisions,
            &preemptions,
            after_time,
            true,
        )?;
        // STEP phase: apply the emitted decisions to the frontier configuration.
        let configuration = self.step_quantum(&decisions);
        let frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        self.configuration = configuration.clone();
        self.frontier = frontier;
        self.quanta = self.quanta.saturating_add(1);
        self.last_advance = Some(NodeAdvance {
            node: selected_node.clone(),
            before,
            after,
            ceiling: plan.ceiling.clone(),
            yielded_before_advance,
        });
        // STEP yield phase: expose the control inbox before the next PICK.
        self.yield_to_control_inbox();
        self.commit_control_applications(std::mem::take(&mut control_applications));
        if let Some(subdivision) = plan.subdivision {
            self.record_run_subdivision(subdivision, plan.ceiling.clone());
        }
        self.commit_preemption_applications(preemptions);

        Ok(QuantumOutcome {
            configuration,
            frontier: self.frontier,
            advanced_node: Some(selected_node),
            resolved_events,
            decisions,
            event_log_entries: event_log.entries,
            event_log_segment_bytes: event_log.segment_bytes,
            event_log_segment_text: event_log.segment_text,
            event_log_segment_hash: event_log.segment_hash,
            event_log_offset: event_log.offset,
            scheduler_quiescence: Some(self.quiescence()?),
        })
    }

    pub(super) fn emit_quantum_event_log(
        &mut self,
        resolved_events: &[ScheduledEvent],
        decisions: &[Decision],
        preemptions: &[PlannedPreemptionApplication],
        at: SimInstant,
        emit_boundary: bool,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let evaluation_at =
            VirtualTime { ticks: at.nanos }.max(self.event_log.condition_prefix().point().at());
        let mut payloads = Vec::with_capacity(resolved_events.len() + decisions.len());
        let preemption_times = preemption_event_times(preemptions);

        for event in ordered_scheduled_events(resolved_events) {
            payloads.push((
                event.key.virtual_time(),
                SchedulerEventLogPayload::ResolvedHappening(event.clone()),
            ));
            if let ScheduledEventPayload::BackendInput(input) = &event.payload
                && let Some(link) = self
                    .world_network_links
                    .values()
                    .find(|runtime| &runtime.scheduler_node == event.key.producer())
                    .map(|runtime| {
                        runtime
                            .legacy_id
                            .clone()
                            .unwrap_or_else(|| runtime.canonical_id.clone())
                    })
            {
                // The resolved happening retains the link's exact delivery
                // time. Its black-box observation becomes visible at this
                // monotone evaluation boundary so a node-local RUN ahead of
                // the conservative frontier cannot make condition time move
                // backwards.
                let observation = ObservableEvent::network_delivered(
                    evaluation_at,
                    Some(link),
                    input.payload.clone(),
                );
                payloads.push((
                    observation.at(),
                    SchedulerEventLogPayload::Observable(observation.payload().clone()),
                ));
            }
        }
        for decision in decisions {
            payloads.push((
                scheduler_decision_event_log_time(
                    decision,
                    at,
                    self.timeline.shift(),
                    &preemption_times,
                )?,
                SchedulerEventLogPayload::Decision(decision.clone()),
            ));
        }
        payloads.sort_by(|left, right| left.0.ticks.cmp(&right.0.ticks));

        let mut entries = Vec::with_capacity(payloads.len() + 1);
        for (entry_time, payload) in payloads {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(sequence, entry_time, payload));
        }
        if emit_boundary {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                evaluation_at,
                SchedulerEventLogPayload::EvaluationBoundary(
                    SchedulerEvaluationBoundaryKind::Quantum,
                ),
            ));
        }

        self.event_log.append_entries(entries)
    }

    pub(super) fn step_quantum(&self, decisions: &[Decision]) -> Configuration {
        let mut configuration = self.configuration.clone();
        for decision in decisions {
            configuration = step(&configuration, decision.clone());
        }
        configuration
    }

    pub(super) fn admit_control_at_boundary(&mut self, control: Vec<ControlOperation>) {
        for operation in control {
            self.accept_control_at_boundary(operation);
        }
    }

    pub(super) fn accept_control_at_boundary(&mut self, operation: ControlOperation) {
        self.control_admissions.push(SchedulerControlAdmission {
            operation: operation.clone(),
            accepted_after_quanta: self.quanta,
            accepted_after_boundary_yield: self.boundary_yields,
        });
        self.control_inbox.push(operation);
    }

    pub(super) fn yield_to_control_inbox(&mut self) {
        self.boundary_yields = self.boundary_yields.saturating_add(1);
    }

    pub(super) fn take_control_admission(
        &mut self,
        operation: &ControlOperation,
    ) -> Result<SchedulerControlAdmission, SchedulerError> {
        let Some(index) = self
            .control_admissions
            .iter()
            .position(|admission| &admission.operation == operation)
        else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler control operation missing boundary admission: sequence={} kind={}",
                    operation.sequence,
                    control_operation_kind_label(&operation.kind)
                ),
            });
        };

        Ok(self.control_admissions.remove(index))
    }

    pub(super) fn commit_control_applications(
        &mut self,
        mut applications: Vec<SchedulerControlApplication>,
    ) {
        self.control_applications.append(&mut applications);
    }

    pub(super) fn drain_control_events(&mut self) -> Result<SchedulerControlDrain, SchedulerError> {
        let mut control = std::mem::take(&mut self.control_inbox);
        control.sort();
        let node = SchedulerNodeId {
            node: NodeId {
                name: String::from("control-plane"),
            },
            kind: SchedulingNodeKind::ControlPlane,
        };

        let mut events = Vec::with_capacity(control.len());
        let mut applications = Vec::with_capacity(control.len());
        for operation in control {
            let admission = self.take_control_admission(&operation)?;
            let key = next_scheduled_event_key(
                &mut self.event_sequences,
                self.frontier,
                node.clone(),
                node.clone(),
            )?;
            let application_delta_quanta = self
                .quanta
                .checked_sub(admission.accepted_after_quanta)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "scheduler control operation applied before admission: sequence={} kind={}",
                        operation.sequence,
                        control_operation_kind_label(&operation.kind)
                    ),
                })?;
            if application_delta_quanta > SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "scheduler control operation exceeded quantum response bound: sequence={} kind={} delta={} bound={}",
                        operation.sequence,
                        control_operation_kind_label(&operation.kind),
                        application_delta_quanta,
                        SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA
                    ),
                });
            }
            applications.push(SchedulerControlApplication {
                sequence: (self.control_applications.len() + applications.len()) as u64,
                operation: operation.clone(),
                accepted_after_quanta: admission.accepted_after_quanta,
                applied_in_quantum: self.quanta,
                application_delta_quanta,
                accepted_after_boundary_yield: admission.accepted_after_boundary_yield,
                applied_at_boundary_yield: self.boundary_yields,
                event_key: key.clone(),
            });
            events.push(ScheduledEvent {
                key,
                payload: ScheduledEventPayload::Control(operation),
            });
        }
        if applications
            .iter()
            .any(|application| matches!(application.operation.kind, ControlOperationKind::Snapshot))
        {
            let nodes = self
                .nodes
                .iter()
                .filter(|runtime| runtime.id.kind == SchedulingNodeKind::Vm)
                .map(|runtime| runtime.id.node.clone())
                .collect::<Vec<_>>();
            for node in nodes {
                self.record_node_checkpoint(&node)?;
            }
        }
        Ok(SchedulerControlDrain {
            events,
            applications,
        })
    }

    pub(super) fn advance_decision_rng_cursor_for(&mut self, stream: RngStreamId) {
        let position = self
            .decision_rng_cursor
            .positions
            .entry(stream)
            .or_insert_with(|| RngStreamPosition::new(0));
        position.draws = position.draws.saturating_add(1);
    }

    pub(super) fn advance_node_after_yield(
        &mut self,
        plan: &AdvancePlan,
    ) -> Result<(NodeCounter, SimInstant, bool), SchedulerError> {
        if self.lock_held {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("scheduler lock spans node advance"),
            });
        }
        if plan.ceiling.max_advance_icount != plan.target_counter {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "RUN target for {}:{:?} diverged from published max-advance ceiling: target={} ceiling={}",
                    plan.node.node.name,
                    plan.node.kind,
                    plan.target_counter,
                    plan.ceiling.max_advance_icount
                ),
            });
        }

        let after = NodeCounter {
            ticks: plan.target_counter,
        };
        self.nodes[plan.index].counter = after;
        let after_time = self.node_time_for_counter(&self.nodes[plan.index], after)?;
        if self.nodes[plan.index]
            .exact_local_event
            .virtual_time()
            .is_some_and(|virtual_time| after_time >= virtual_time)
        {
            self.nodes[plan.index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        }
        for state in &mut self.nodes[plan.index].vcpu_idle_states {
            if state
                .next_deadline
                .is_some_and(|deadline| after_time >= deadline)
            {
                state.next_deadline = None;
            }
        }
        if plan
            .quiescent_horizon
            .is_some_and(|horizon| after_time >= horizon)
        {
            // Don't park `Idle` if this node still owes a later device completion:
            // its next sequential completion is a fresh exact local event it must
            // advance to, so keep it `Runnable` ([SCHED-29]). The next quantum's
            // `refresh_device_horizons` re-activation also covers this; this guard
            // avoids a spurious one-quantum park.
            if self
                .device_completion_due_after(&plan.node, after_time)?
                .is_none()
            {
                self.nodes[plan.index].activity = SchedulerNodeActivity::Idle;
            }
        }

        Ok((after, after_time, true))
    }

    pub(super) fn stalled_active_node(&self) -> Option<&RuntimeSchedulerNode> {
        self.nodes
            .iter()
            .find(|node| self.effective_node_activity(node) == SchedulerNodeActivity::Runnable)
    }
}
