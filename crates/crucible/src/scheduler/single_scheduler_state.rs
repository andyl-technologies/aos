//! Scheduler construction, World/device attachment, materialization, faults, and lifecycle.

use super::*;
impl SingleScheduler {
    /// Builds a scheduler from a finite generated liveness scenario.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fixed timeline shift cannot be
    /// represented or when an initial node counter cannot be projected onto the
    /// shared virtual timeline.
    pub fn new(scenario: SchedulerLivenessScenario) -> Result<Self, SchedulerError> {
        Self::new_with_event_log(scenario, EventLog::new())
    }

    /// Builds a production scheduler from a logical World and artifact store.
    ///
    /// This consumes every static topology product: VM participants must match
    /// the runtime scenario, LinkDefs become the effective lookahead graph and
    /// first-class network scheduling identities, and block/9p declarations are
    /// resolved from `store` into concrete [`DeviceSchedulingSubNode`](crate::DeviceSchedulingSubNode)
    /// values. Physical ring capacities and source numbers come from `policy` at
    /// this boundary and do not affect World/scenario identity ([SPAT-14],
    /// [SPAT-15]). The per-device RNG uses the scenario's authoritative seed.
    ///
    /// The resulting scheduler implements [`QuantumLoop`], so it can be handed
    /// directly to the L4 session engine; trigger/control faults then update the
    /// attached live devices through the normal scheduler fault path.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWorldInstantiationError::VmTopologyMismatch`] when the
    /// scenario's VM nodes do not exactly match the World, an I/O-instantiation
    /// error when an artifact cannot be resolved/validated, or a scheduler error
    /// when initial active faults or device horizons cannot be installed.
    pub fn from_world(
        scenario: SchedulerLivenessScenario,
        world: &World,
        store: &dyn DagStore,
        policy: WorldIoLayoutPolicy,
    ) -> Result<Self, SchedulerWorldInstantiationError> {
        let seed = scenario.configuration.def.seed();
        let shift = scenario.shift;
        let mut scheduler = Self::new(scenario.with_world(world))?;
        let expected = scheduler
            .world_scheduling_nodes
            .iter()
            .filter(|node| node.kind == SchedulingNodeKind::Vm)
            .cloned()
            .collect::<Vec<_>>();
        let actual = scheduler
            .nodes
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        if actual != expected {
            return Err(SchedulerWorldInstantiationError::VmTopologyMismatch { expected, actual });
        }

        for sub_node in instantiate_world_io_sub_nodes(world, store, seed, policy)? {
            scheduler
                .device_sub_nodes
                .entry(sub_node.target().clone())
                .or_default()
                .push(sub_node);
        }
        for sub_nodes in scheduler.device_sub_nodes.values_mut() {
            sub_nodes.sort_by(|left, right| left.sub_node().cmp(right.sub_node()));
        }
        scheduler.world_network_links = instantiate_world_network_links(world, shift)?;
        scheduler.world_network_rng_positions = scheduler
            .world_network_links
            .keys()
            .map(|(link, _direction)| (link.clone(), 0))
            .collect();
        let active = scheduler.trigger_actions.combined_faults();
        scheduler.apply_trigger_device_faults(&active)?;
        Ok(scheduler)
    }

    /// Builds a production scheduler resumed from materialized World-link state.
    ///
    /// The supplied state must contain exactly one cursor for every directed
    /// link instantiated from `world`. In-flight payloads are resolved through
    /// `store`, and both directions of a logical link must report the same
    /// shared RNG cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWorldInstantiationError`] when ordinary World
    /// instantiation fails, the directed cursor set is incomplete or foreign,
    /// the two directions disagree about their shared RNG cursor, an in-flight
    /// payload is absent/corrupt, or a concrete link snapshot cannot be restored.
    pub fn from_world_with_scheduler_state(
        scenario: SchedulerLivenessScenario,
        world: &World,
        store: &dyn DagStore,
        policy: WorldIoLayoutPolicy,
        state: &SchedulerState,
    ) -> Result<Self, SchedulerWorldInstantiationError> {
        let mut scheduler = Self::from_world(scenario, world, store, policy)?;
        let expected = scheduler
            .world_network_links
            .values()
            .map(|runtime| runtime.fault_id.clone())
            .collect::<BTreeSet<_>>();
        let actual = state
            .network_link_cursors
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(SchedulerWorldInstantiationError::NetworkStateMismatch {
                reason: format!(
                    "directed cursor keys differ (expected {expected:?}, found {actual:?})"
                ),
            });
        }

        scheduler.event_sequences = state.event_sequences.clone();
        scheduler.world_network_decisions = state.pending_device_decisions.clone();
        scheduler.trigger_actions.active_faults = state.active_fault_tags.clone();
        scheduler.effective_topology =
            SchedulerLookaheadGraph::from_edges(state.effective_topology_edges.clone());
        for node in &mut scheduler.nodes {
            node.network_lookahead = scheduler.effective_topology.lookahead(&node.id);
        }
        scheduler.topology_changes = state.pending_topology_changes.clone();
        scheduler.topology_epoch = state.topology_epoch;
        scheduler.apply_trigger_device_faults(&state.active_fault_table.combined)?;

        let mut shared_positions = BTreeMap::new();
        for runtime in scheduler.world_network_links.values_mut() {
            let cursor = state
                .network_link_cursors
                .get(&runtime.fault_id)
                .ok_or_else(|| SchedulerWorldInstantiationError::NetworkStateMismatch {
                    reason: format!("missing directed cursor {:?}", runtime.fault_id.name),
                })?;
            if let Some(existing) = shared_positions.get(&runtime.canonical_id)
                && *existing != cursor.rng_position
            {
                return Err(SchedulerWorldInstantiationError::NetworkStateMismatch {
                    reason: format!(
                        "logical link {:?} has divergent directional RNG cursors ({existing} and {})",
                        runtime.canonical_id.name, cursor.rng_position
                    ),
                });
            }
            shared_positions.insert(runtime.canonical_id.clone(), cursor.rng_position);

            let mut snapshot = runtime.link.snapshot();
            snapshot.current_icount = cursor.current_icount;
            snapshot.next_seq = cursor.next_sequence;
            snapshot.rng_position = cursor.rng_position;
            let src_node = snapshot.src_node;
            snapshot.inflight = cursor
                .inflight
                .iter()
                .map(|pending| {
                    let payload = store.get(&pending.payload)?;
                    Ok(crucible_device::PendingResponse::from_parts(
                        pending.delivery_icount.retired,
                        src_node,
                        pending.sequence,
                        crucible_device::Response::new(
                            pending.frame_id,
                            crucible_device::ResponseStatus::Ok,
                            payload,
                        ),
                    ))
                })
                .collect::<Result<Vec<_>, crate::DagStoreError>>()?;
            runtime.link = crucible_device::NetLink::restore(&snapshot).map_err(|source| {
                SchedulerWorldInstantiationError::Network {
                    link: runtime.canonical_id.clone(),
                    direction: runtime.direction,
                    source,
                }
            })?;
        }
        scheduler.world_network_rng_positions = shared_positions;
        scheduler.refresh_device_horizons()?;
        Ok(scheduler)
    }

    /// Builds a scheduler whose event log writes segments into `store`.
    ///
    /// Use this constructor when the scheduler and temporal graph share one
    /// content-addressed store: every non-empty EMIT appends canonical binary
    /// segment bytes at their BLAKE3 key before the quantum outcome is returned.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fixed timeline shift cannot be
    /// represented or when an initial node counter cannot be projected onto the
    /// shared virtual timeline.
    pub fn new_with_event_log_segment_store(
        scenario: SchedulerLivenessScenario,
        store: Arc<dyn DagStore>,
    ) -> Result<Self, SchedulerError> {
        Self::new_with_event_log(scenario, EventLog::with_segment_store(store))
    }

    /// Builds a scheduler resumed from `event_log_offset` and backed by `store`.
    ///
    /// The next EMIT append starts at the recorded byte and event offsets, and
    /// uses the reconstructed content prefix from `event_log_offset` as the
    /// parent prefix for the new segment.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fixed timeline shift cannot be
    /// represented or when an initial node counter cannot be projected onto the
    /// shared virtual timeline.
    pub fn new_with_event_log_offset_and_segment_store(
        scenario: SchedulerLivenessScenario,
        event_log_offset: EventLogOffset,
        store: Arc<dyn DagStore>,
    ) -> Result<Self, SchedulerError> {
        Self::new_with_event_log(
            scenario,
            EventLog::from_offset_with_segment_store(event_log_offset, store),
        )
    }

    pub(super) fn new_with_event_log(
        scenario: SchedulerLivenessScenario,
        event_log: EventLog,
    ) -> Result<Self, SchedulerError> {
        let timeline = SharedTimeline::new(scenario.shift)?;
        let configuration = scenario.canonical_configuration();
        let ready_point_counters = scenario.ready_point_counters;
        let mut nodes = scenario
            .nodes
            .into_iter()
            .map(RuntimeSchedulerNode::from)
            .collect::<Vec<_>>();
        for (node, counter) in ready_point_counters {
            let runtime = nodes
                .iter_mut()
                .find(|runtime| runtime.id == node)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "ready-point counter references unknown scheduler node {}:{:?}",
                        node.node.name, node.kind
                    ),
                })?;
            runtime.ready_counter = counter;
            runtime.timing_faults.anchor_counter = counter;
            runtime.timing_faults.anchor_time = SimInstant::EPOCH;
        }
        nodes.sort_by(|left, right| left.id.cmp(&right.id));
        let mut run_subdivision_policies = scenario.run_subdivision_policies;
        run_subdivision_policies.sort();
        let mut preemption_requests = scenario.preemption_requests;
        preemption_requests.sort_by(preemption_decision_order);
        let mut vcpu_idle_snapshots = scenario.vcpu_idle_snapshots;
        assign_vcpu_idle_snapshots(
            &mut nodes,
            &mut vcpu_idle_snapshots,
            &run_subdivision_policies,
        )?;

        let frontier = frontier_for(&nodes, scenario.shift)?;
        let trigger_actions = TriggerActionState::default();

        let world_scheduling_nodes = scenario
            .trigger_static_topology
            .as_ref()
            .map(|topology| topology.scheduling_nodes.iter().cloned().collect())
            .unwrap_or_default();
        let decision_seed = configuration.def.seed();
        let scheduler = Self {
            configuration,
            timeline,
            quantum_budget: scenario.quantum_budget,
            time_limit: scenario.time_limit,
            branch_frontier_cap: None,
            rendezvous: scenario.rendezvous,
            effective_topology: scenario.effective_topology,
            nodes,
            topology_changes: scenario.topology_changes,
            run_subdivision_policies,
            run_subdivision_records: Vec::new(),
            preemption_requests,
            preemption_applications: Vec::new(),
            control_admissions: Vec::new(),
            control_applications: Vec::new(),
            pending_events: scenario.pending_events,
            event_sequences: scenario.event_sequences,
            device_sub_nodes: BTreeMap::new(),
            world_network_links: BTreeMap::new(),
            world_network_rng_positions: BTreeMap::new(),
            world_network_decisions: Vec::new(),
            device_horizons: BTreeMap::new(),
            #[cfg(test)]
            broken_device_delivery_stamp: false,
            control_inbox: Vec::new(),
            decision_seed,
            decision_rng_cursor: DecisionRngState::empty(),
            branch_fault_choices: Vec::new(),
            branch_network_choices: Vec::new(),
            search_frontiers: Vec::new(),
            event_log,
            trigger_actions,
            trigger_static_topology: scenario.trigger_static_topology,
            world_scheduling_nodes,
            frontier,
            quanta: 0,
            topology_epoch: 0,
            topology_change_applications: Vec::new(),
            node_crash_applications: Vec::new(),
            node_restart_applications: Vec::new(),
            rendezvous_records: Vec::new(),
            boundary_yields: 0,
            ceiling_publications: Vec::new(),
            lock_held: false,
            last_advance: None,
            last_topology_recompute: false,
        };
        Ok(scheduler)
    }

    /// Returns the current scheduler configuration.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Installs a deterministic exact-completion I/O sub-node (disk/9p) on its target VM node
    /// (RFC-0010 [IO-1], [IO-3], §15.1).
    ///
    /// The sub-node's in-flight head delivery icount is the **real** source of the
    /// owning node's exact I/O-completion horizon term, so an otherwise-idle
    /// requester is fast-forwarded to the scheduler-time projection of its next
    /// exact I/O completion ([IO-3], [SCHED-10]), and
    /// [`SingleScheduler::resolve_device_completions`] delivers the completion at
    /// that exact delivery icount's scheduler-time projection in the canonical
    /// `(delivery_icount, src_node, seq)` order ([SCHED-29]). Several sub-nodes
    /// may target one VM node; their horizon terms are folded with `min`.
    ///
    /// Submit requests through the returned sub-node before driving the scheduler;
    /// fold the device's live in-flight head into the node's horizon with
    /// [`SingleScheduler::refresh_device_horizons`].
    #[must_use]
    pub fn with_device_sub_node(
        mut self,
        sub_node: crate::device_subnode::DeviceSchedulingSubNode,
    ) -> Self {
        self.device_sub_nodes
            .entry(sub_node.target().clone())
            .or_default()
            .push(sub_node);
        self
    }

    /// Returns a mutable view of the I/O sub-nodes targeting `node`, if any.
    ///
    /// Used by a driver to submit device requests between quanta; the next horizon
    /// refresh folds the device's in-flight head into the node's horizon.
    pub fn device_sub_nodes_for_mut(
        &mut self,
        node: &NodeId,
    ) -> Option<&mut Vec<crate::device_subnode::DeviceSchedulingSubNode>> {
        self.device_sub_nodes.get_mut(node)
    }

    /// **Test-only.** Forces I/O completions to be stamped at the consumer's
    /// frontier icount instead of their exact `delivery_icount`, modeling the
    /// freeze-time bug ([IO-2], [DET-19]).
    ///
    /// Exists solely to prove the determinism gates are falsifiable: with this
    /// set, a scenario whose requester reaches a completion at a frontier
    /// *different* from the completion's exact icount produces a different
    /// resolved order, so the gate goes red. Never used in production.
    #[cfg(test)]
    pub(crate) fn with_broken_device_delivery_stamp(mut self) -> Self {
        self.broken_device_delivery_stamp = true;
        self
    }

    /// Returns whether any device sub-node holds an undelivered completion.
    ///
    /// While any I/O completion is still in flight the system is not quiescent,
    /// even when every node is parked `Idle` ([SCHED-22], [SCHED-29]).
    #[must_use]
    pub fn has_undelivered_device_completion(&self) -> bool {
        self.device_sub_nodes
            .values()
            .flatten()
            .any(|sub_node| sub_node.next_exact_local_event().is_some())
            || self
                .world_network_links
                .values()
                .any(|runtime| runtime.link.next_exact_local_event().is_some())
    }

    /// Returns the earliest undelivered device completion for `node` due
    /// **strictly after** `instant`, if any ([SCHED-29]).
    ///
    /// Scans every targeting sub-node's next exact local event; used to keep a
    /// requester `Runnable` when it still owes a later completion, so an idle park
    /// can never strand a sequential read.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::TimeConversion`] when a completion delivery
    /// icount cannot be converted under the timeline shift.
    pub fn device_completion_due_after(
        &self,
        node: &SchedulerNodeId,
        instant: SimInstant,
    ) -> Result<Option<SimInstant>, SchedulerError> {
        let mut earliest: Option<SimInstant> = None;
        if let Some(sub_nodes) = self.device_sub_nodes.get(&node.node) {
            for sub_node in sub_nodes {
                if let Some(delivery_icount) = sub_node.next_exact_local_event() {
                    let due = self.vm_delivery_time_for_icount(
                        &node.node,
                        Icount {
                            retired: delivery_icount,
                        },
                    )?;
                    if due > instant {
                        earliest = Some(match earliest {
                            Some(current) => current.min(due),
                            None => due,
                        });
                    }
                }
            }
        }
        for runtime in self
            .world_network_links
            .values()
            .filter(|runtime| runtime.target() == &node.node)
        {
            if let Some(delivery_icount) = runtime.link.next_exact_local_event() {
                let due = self.network_time_for_icount(delivery_icount)?;
                if due > instant {
                    earliest = Some(earliest.map_or(due, |current| current.min(due)));
                }
            }
        }
        Ok(earliest)
    }

    /// Folds every device sub-node's in-flight head into its target node's exact
    /// I/O-completion horizon term and re-activates a parked target that still
    /// owes a completion ([IO-3], [SCHED-9], [SCHED-10], [SCHED-29]).
    ///
    /// Called at the start of each quantum so the horizon the scheduler reads is
    /// the device's *current* next completion — the real exact local event with no
    /// conservative slack. The earliest undelivered completion per target is
    /// recorded in `device_horizons`, which `effective_exact_local_event` mins into
    /// the node's effective horizon. No deliverable event is injected, so delivery
    /// stays solely on the RESOLVE path through
    /// [`resolve_device_completions`](Self::resolve_device_completions) and is
    /// never double-counted; the term is recomputed from scratch so a refresh is
    /// idempotent.
    ///
    /// # Re-activation of an idle requester
    ///
    /// A node parks `Idle` at one completion's exact icount; its *next* sequential
    /// completion is a fresh exact local event it must still advance to. So
    /// whenever a targeting sub-node has an undelivered completion this flips the
    /// node back to `Runnable`, so it is re-PICKed and advanced to the next
    /// completion — without this an idle requester would silently drop a normal
    /// sequential read ([SCHED-29]).
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::TimeConversion`] when a completion delivery
    /// icount cannot be converted under the timeline shift.
    pub fn refresh_device_horizons(&mut self) -> Result<(), SchedulerError> {
        // Recompute the earliest undelivered completion per target; the in-flight
        // queues are the single source of truth. Ordered by `NodeId` (BTreeMap
        // iteration) so the refresh is deterministic.
        let mut earliest_by_target: Vec<(NodeId, SimInstant)> = Vec::new();
        for (target, sub_nodes) in &self.device_sub_nodes {
            if self.is_node_down(target) {
                continue;
            }
            let mut earliest: Option<SimInstant> = None;
            for sub_node in sub_nodes {
                if let Some(delivery_icount) = sub_node.next_exact_local_event() {
                    let instant = self.vm_delivery_time_for_icount(
                        target,
                        Icount {
                            retired: delivery_icount,
                        },
                    )?;
                    earliest = Some(match earliest {
                        Some(current) => current.min(instant),
                        None => instant,
                    });
                }
            }
            if let Some(instant) = earliest {
                earliest_by_target.push((target.clone(), instant));
            }
        }
        for runtime in self.world_network_links.values() {
            let target = runtime.target();
            if self.is_node_down(target) {
                continue;
            }
            let Some(delivery_icount) = runtime.link.next_exact_local_event() else {
                continue;
            };
            let instant = self.network_time_for_icount(delivery_icount)?;
            if let Some((_, current)) = earliest_by_target
                .iter_mut()
                .find(|(candidate, _)| candidate == target)
            {
                *current = (*current).min(instant);
            } else {
                earliest_by_target.push((target.clone(), instant));
            }
        }
        earliest_by_target.sort_by(|left, right| left.0.cmp(&right.0));

        self.device_horizons.clear();
        for (target, instant) in earliest_by_target {
            self.device_horizons.insert(target.clone(), instant);
            // Re-activate a parked requester so the next sequential completion is
            // observed ([SCHED-29]); a `Runnable` node is left as-is.
            if let Some(runtime) = self
                .nodes
                .iter_mut()
                .find(|runtime| runtime.id.node == target)
                && runtime.crash.is_none()
                && runtime.stopped_crash.is_none()
                && runtime.activity == SchedulerNodeActivity::Idle
            {
                runtime.activity = SchedulerNodeActivity::Runnable;
            }
        }
        Ok(())
    }

    /// RESOLVEs every device completion for `node` due at or before
    /// `consumer_icount` (RFC-0010 [SCHED-29], [SCHED-30], §8.9.4).
    ///
    /// Drains each targeting sub-node's due completions in the canonical
    /// `(delivery_icount, src_node, seq)` order, mints each event's `sequence`
    /// from the live [`EventSequenceState`] for its `(sub_node, target)` pair
    /// ([SCHED-18]), and returns the [`IoCompletion`] events plus the fault
    /// [`Decision`]s they drew, all in delivery order. The completion is made
    /// visible at the scheduler-time projection of **exactly** its
    /// `delivery_icount` ([SCHED-29], [IO-2]), never the consumer's
    /// `consumer_icount` frontier.
    ///
    /// # Errors
    ///
    /// This currently never returns an error; the `Result` is kept for forward
    /// compatibility with sequence-exhaustion guards.
    pub fn resolve_device_completions(
        &mut self,
        node: &SchedulerNodeId,
        consumer_icount: u64,
    ) -> Result<(Vec<ScheduledEvent>, Vec<Decision>), SchedulerError> {
        let mut events = Vec::new();
        let mut decisions = Vec::new();
        // Collect every due completion across this node's sub-nodes first (the
        // borrow of `sub_nodes` ends here), then mint sequences against the
        // scheduler-owned counter on the live RESOLVE path.
        let mut due: Vec<crate::device_subnode::DeviceDelivery> = Vec::new();
        if let Some(sub_nodes) = self.device_sub_nodes.get_mut(&node.node) {
            for sub_node in sub_nodes.iter_mut() {
                due.extend(sub_node.deliver_due(consumer_icount));
            }
        }
        // Canonical (delivery_icount, then producer sub-node id) order so the
        // resolved order is a pure function of the keys, not host iteration.
        due.sort_by(|left, right| {
            (
                left.delivery_icount,
                &left.sub_node,
                left.source_node,
                left.sequence,
            )
                .cmp(&(
                    right.delivery_icount,
                    &right.sub_node,
                    right.source_node,
                    right.sequence,
                ))
        });
        for delivery in due {
            let completion_decisions =
                self.project_device_decisions_for_vm_time(&node.node, delivery.decisions)?;
            decisions.extend(completion_decisions);

            let Some(completion) = delivery.completion else {
                continue;
            };
            let producer = completion.sub_node.clone();
            let consumer = SchedulerNodeId {
                node: completion.target.clone(),
                kind: SchedulingNodeKind::Vm,
            };
            // SCHED-18 on the LIVE path: the sequence comes from the owned counter.
            let sequence = self.event_sequences.next_sequence(&producer, &consumer);
            self.event_sequences.set_next_sequence(
                producer.clone(),
                consumer.clone(),
                sequence + 1,
            );
            // The completion is made visible at the scheduler-time projection of
            // EXACTLY its delivery icount ([SCHED-29], [IO-2]) — never the
            // consumer's frontier. The test-only broken stamp models the
            // freeze-time bug to prove the gates catch it.
            let stamp_icount = completion.delivery_icount.retired;
            #[cfg(test)]
            let stamp_icount = if self.broken_device_delivery_stamp {
                consumer_icount
            } else {
                stamp_icount
            };
            let instant = self.vm_delivery_time_for_icount(
                &completion.target,
                Icount {
                    retired: stamp_icount,
                },
            )?;
            let virtual_time = VirtualTime {
                ticks: instant.nanos,
            };
            let key = ScheduledEventKey::from_parts(virtual_time, consumer, producer, sequence);
            events.push(ScheduledEvent {
                key,
                payload: ScheduledEventPayload::IoCompletion(completion),
            });
        }

        let consumer_time = self.node_current_time(&self.nodes[self.vm_node_index(&node.node)?])?;
        let network_consumer_icount = self.network_icount_for_time_ceil(consumer_time)?;
        let mut network_due = Vec::new();
        for runtime in self
            .world_network_links
            .values_mut()
            .filter(|runtime| runtime.target() == &node.node)
        {
            let deliveries = runtime
                .link
                .advance_to(network_consumer_icount)
                .map_err(|source| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "World network link {:?} ({:?}) could not advance to logical consumer icount {network_consumer_icount}: {source}",
                        runtime.canonical_id.name, runtime.direction
                    ),
                }
            })?;
            for delivery in deliveries {
                network_due.push((
                    delivery,
                    runtime.scheduler_node.clone(),
                    runtime.source().clone(),
                    runtime.target().clone(),
                ));
            }
        }
        network_due.sort_by(|left, right| {
            (&left.0.key, &left.1, &left.2, &left.3).cmp(&(
                &right.0.key,
                &right.1,
                &right.2,
                &right.3,
            ))
        });
        for (delivery, producer, _source, target) in network_due {
            let consumer = SchedulerNodeId {
                node: target.clone(),
                kind: SchedulingNodeKind::Vm,
            };
            let sequence = self.event_sequences.next_sequence(&producer, &consumer);
            self.event_sequences.set_next_sequence(
                producer.clone(),
                consumer.clone(),
                sequence.saturating_add(1),
            );
            let instant = self.network_time_for_icount(delivery.delivery_icount())?;
            let key = ScheduledEventKey::from_parts(
                VirtualTime {
                    ticks: instant.nanos,
                },
                consumer,
                producer,
                sequence,
            );
            events.push(ScheduledEvent {
                key,
                payload: ScheduledEventPayload::BackendInput(BackendInput {
                    node: target,
                    payload: delivery.payload,
                }),
            });
        }
        events.sort_by(|left, right| left.key.cmp(&right.key));
        // Reconcile the cached device horizon term with the in-flight queues now
        // that this target's due completions have drained: a delivered head is no
        // longer a future exact local event, so the term must drop or fall back to
        // the next in-flight head IMMEDIATELY (not wait for the next pre-PICK
        // refresh). Otherwise a stale term would keep the node non-quiescent and
        // distort its effective horizon after the completion was already resolved.
        let next_head = self
            .device_sub_nodes
            .get(&node.node)
            .into_iter()
            .flatten()
            .filter_map(|sub_node| sub_node.next_exact_local_event())
            .map(|delivery_icount| {
                self.vm_delivery_time_for_icount(
                    &node.node,
                    Icount {
                        retired: delivery_icount,
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .chain(
                self.world_network_links
                    .values()
                    .filter(|runtime| runtime.target() == &node.node)
                    .filter_map(|runtime| runtime.link.next_exact_local_event())
                    .map(|delivery_icount| self.network_time_for_icount(delivery_icount))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .min();
        match next_head {
            Some(instant) => {
                self.device_horizons.insert(node.node.clone(), instant);
            }
            None => {
                self.device_horizons.remove(&node.node);
            }
        }
        Ok((events, decisions))
    }

    /// Returns the current shared-timeline frontier.
    #[must_use]
    pub fn frontier(&self) -> VirtualTime {
        self.frontier
    }

    /// Returns the number of quanta already driven.
    #[must_use]
    pub fn quanta(&self) -> u64 {
        self.quanta
    }

    /// Returns the event-log offset reached by completed scheduler EMIT phases.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log.offset()
    }

    /// Returns the scheduler-owned condition-evaluation prefix.
    #[must_use]
    pub fn condition_event_log_prefix(&self) -> &ConditionEventLogPrefix {
        self.event_log.condition_prefix()
    }

    /// Returns the scheduler-owned trigger action state.
    #[must_use]
    pub fn trigger_actions(&self) -> &TriggerActionState {
        &self.trigger_actions
    }

    /// Captures the scheduler-owned state that must survive a materialized checkpoint.
    #[must_use]
    pub fn materialized_scheduler_state(&self) -> SchedulerState {
        match self.materialized_scheduler_state_with_payload_refs(|payload| {
            Ok::<_, std::convert::Infallible>(ContentHash::from_bytes(payload))
        }) {
            Ok(state) => state,
            Err(never) => match never {},
        }
    }

    /// Captures scheduler state and persists every in-flight link payload.
    ///
    /// Use this form when the state may later be passed to
    /// [`SingleScheduler::from_world_with_scheduler_state`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::DagStoreError`] when an in-flight payload cannot be
    /// persisted in the supplied content-addressed store.
    pub fn materialized_scheduler_state_with_store(
        &self,
        store: &dyn DagStore,
    ) -> Result<SchedulerState, crate::DagStoreError> {
        self.materialized_scheduler_state_with_payload_refs(|payload| store.put(payload))
    }

    pub(super) fn materialized_scheduler_state_with_payload_refs<E>(
        &self,
        mut payload_ref: impl FnMut(&[u8]) -> Result<ContentHash, E>,
    ) -> Result<SchedulerState, E> {
        let mut state = SchedulerState::empty();
        state.pending_frames = pending_frames_from_scheduled_events(&self.pending_events);
        state
            .horizons
            .extend(self.device_horizons.iter().map(|(node, horizon)| {
                (
                    node.clone(),
                    VirtualTime {
                        ticks: horizon.nanos,
                    },
                )
            }));
        for runtime in self.world_network_links.values() {
            let snapshot = runtime.link.snapshot();
            let inflight = snapshot
                .inflight
                .iter()
                .map(|pending| {
                    Ok(NetworkLinkPendingFrame {
                        sequence: pending.key.seq,
                        delivery_icount: Icount {
                            retired: pending.key.delivery_icount,
                        },
                        frame_id: pending.response.request_id,
                        payload: payload_ref(&pending.response.payload)?,
                    })
                })
                .collect::<Result<Vec<_>, E>>()?;
            state.network_link_cursors.insert(
                runtime.fault_id.clone(),
                crate::NetworkLinkRuntimeCursor {
                    current_icount: snapshot.current_icount,
                    next_sequence: snapshot.next_seq,
                    rng_position: self
                        .world_network_rng_positions
                        .get(&runtime.canonical_id)
                        .copied()
                        .unwrap_or(snapshot.rng_position),
                    inflight: inflight.clone(),
                },
            );
            if !inflight.is_empty() {
                let frames = state
                    .pending_frames
                    .entry(runtime.target().clone())
                    .or_default();
                frames.extend(inflight.iter().map(|pending| PendingFrame {
                    source: runtime.source().clone(),
                    sequence: u64::from(pending.sequence),
                    delivery_icount: pending.delivery_icount,
                    payload: pending.payload,
                }));
                frames.sort_by(|left, right| {
                    (left.delivery_icount, &left.source, left.sequence).cmp(&(
                        right.delivery_icount,
                        &right.source,
                        right.sequence,
                    ))
                });
            }
        }
        state.event_sequences = self.event_sequences.clone();
        state.topology_epoch = self.topology_epoch;
        state.effective_topology_edges = self.effective_topology.edges().to_vec();
        state.pending_topology_changes = self.topology_changes.clone();
        state.active_fault_tags = self.trigger_actions.active_faults.clone();
        state.recompute_active_fault_table();
        state.pending_device_decisions = self.world_network_decisions.clone();
        state.search_frontier = search_frontier_choices_from_scheduled_events(
            self.configuration.clone(),
            &self.pending_events,
        );
        Ok(state)
    }

    /// Returns the world-derived static topology used for trigger action validation.
    #[must_use]
    pub fn trigger_static_topology(&self) -> Option<&WorldStaticTopology> {
        self.trigger_static_topology.as_ref()
    }

    /// Returns the canonical World scheduler identities consumed at instantiation.
    ///
    /// The set includes every VM, concrete block/9p sub-node, and one
    /// content-derived network scheduling node per logical LinkDef ([IO-1]).
    #[must_use]
    pub fn world_scheduling_nodes(&self) -> &BTreeSet<SchedulerNodeId> {
        &self.world_scheduling_nodes
    }

    /// Returns the number of concrete directed World network links owned by the scheduler.
    ///
    /// A logical symmetric [`LinkDef`] contributes two directed links.
    #[must_use]
    pub fn world_network_link_count(&self) -> usize {
        self.world_network_links.len()
    }

    /// Returns a scheduler-owned directed World network link.
    ///
    /// `link` may be either the canonical structured identifier or an
    /// unambiguous legacy `endpoint-a--endpoint-b` spelling.
    #[must_use]
    pub fn world_network_link(
        &self,
        link: &LinkId,
        direction: NetworkLinkDirection,
    ) -> Option<&crucible_device::NetLink> {
        self.world_network_links
            .values()
            .find(|candidate| candidate.matches(link, direction))
            .map(|candidate| &candidate.link)
    }

    /// Emits a frame through a scheduler-owned directed World network link.
    ///
    /// The scheduler selects the World-declared RNG stream, retains the raw and
    /// derived fault decisions for the next EMIT/STEP boundary, and refreshes the
    /// destination VM's exact network-delivery horizon. Callers cannot substitute
    /// an identity-external RNG label.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `link` is unknown or
    /// ambiguous, or when the concrete link rejects the frame. Returns a time
    /// conversion error when the emitted delivery cannot be projected onto the
    /// destination VM's scheduler timeline.
    pub fn emit_world_network_frame(
        &mut self,
        link: &LinkId,
        direction: NetworkLinkDirection,
        seed: Seed,
        frame: &crucible_device::Frame,
        policy: crucible_device::PastDeliveryPolicy,
    ) -> Result<crate::LinkEmitDecisionRecord, SchedulerError> {
        let runtime_key = self
            .world_network_links
            .iter()
            .find_map(|(key, candidate)| candidate.matches(link, direction).then(|| key.clone()))
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "World network link is unknown or ambiguous: {:?} ({direction:?})",
                    link.name
                ),
            })?;
        let rng_position = self
            .world_network_rng_positions
            .get(&runtime_key.0)
            .copied()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "World network link {:?} has no logical RNG cursor",
                    runtime_key.0.name
                ),
            })?;
        let (record, next_rng_position) = {
            let runtime = self
                .world_network_links
                .get_mut(&runtime_key)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "World network link disappeared during emission: {:?} ({direction:?})",
                        runtime_key.0.name
                    ),
                })?;
            let record = runtime
                .emit_from_position(seed, rng_position, frame, policy)
                .map_err(|source| SchedulerError::BoundaryViolation {
                    message: format!(
                        "World network link {:?} ({direction:?}) rejected a frame: {source}",
                        runtime.canonical_id.name
                    ),
                })?;
            (record, runtime.link.rng_position())
        };
        self.world_network_rng_positions
            .insert(runtime_key.0, next_rng_position);
        self.world_network_decisions
            .extend(record.decisions.iter().cloned());
        self.refresh_device_horizons()?;
        Ok(record)
    }

    /// Appends black-box observable condition facts to the scheduler event log.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the event-log segment would overflow the scheduler offsets, or
    /// when the resulting condition prefix is invalid.
    pub fn append_observable_events(
        &mut self,
        events: impl IntoIterator<Item = ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_observable_events(events)
    }

    /// Appends typed signal-driven fault evidence to the unified event log.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the canonical segment would overflow scheduler offsets.
    pub fn append_fault_observations(
        &mut self,
        observations: impl IntoIterator<Item = crate::model::FaultObservation>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_fault_observations(observations)
    }

    /// Appends assertion-proximity steering feedback to the scheduler event log.
    ///
    /// `report` remains a transient assertion-layer view. The persisted steering
    /// facts are appended as typed observational `assertion_proximity` entries in
    /// the unified log, so downstream projections read one log instead of a
    /// parallel proximity record.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences or
    /// appending the event-log segment would overflow the scheduler offsets, or
    /// when the resulting condition prefix is invalid.
    pub fn append_assertion_proximity_events(
        &mut self,
        report: &HostAssertionReport,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.append_observable_events(report.proximities().iter().map(|proximity| {
            ObservableEvent::assertion_proximity(
                proximity.at,
                proximity.assertion.clone(),
                proximity.quantifier,
                proximity.distance,
                None,
            )
        }))
    }

    /// Appends a deterministic trigger/assertion evaluation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning the dense event-log sequence or
    /// appending the event-log segment would overflow the scheduler offsets, or
    /// when the boundary would make the checked condition prefix invalid.
    pub fn append_evaluation_boundary(
        &mut self,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_evaluation_boundary(at, kind)
    }

    /// Evaluates an event graph over this scheduler's current condition prefix.
    ///
    /// Armed trigger timers are made visible to `Timer` leaves from the
    /// scheduler-owned [`TriggerActionState`], so a timer fires exactly at the
    /// virtual time produced by the `ArmTimer` action that armed it.
    pub fn evaluate_event_graph<O>(
        &self,
        graph: &EventGraph,
        state: &mut EventGraphState,
        oracle: O,
    ) -> EventFirings
    where
        O: ConditionLeafOracle,
    {
        let mut pass = ConditionEvaluationPass::from_log_prefix(
            self.event_log.condition_prefix().clone(),
            oracle,
        )
        .with_timer_fires(self.trigger_actions.armed_timers.clone());
        pass.evaluate_event_graph(graph, state)
    }

    /// Appends deterministic trigger firings as causal event-log entries.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the firings were computed at a different
    /// condition prefix than the scheduler's current prefix, or when appending the
    /// event-log segment would overflow the event-log offsets.
    pub fn append_trigger_firings(
        &mut self,
        firings: &EventFirings,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.validate_trigger_firings(firings)?;
        let entries = self.trigger_firing_entries(firings)?;
        self.event_log.append_entries(entries)
    }

    /// Applies deterministic trigger firings and their action effects atomically.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the firings were computed at a different
    /// condition prefix than the scheduler's current prefix, when a timer action
    /// would overflow virtual time, when a node scheduling action references a
    /// node outside the scheduler's world-derived static topology, or when
    /// appending the event-log segment would overflow the event-log offsets.
    pub fn apply_trigger_firings(
        &mut self,
        firings: &EventFirings,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.validate_trigger_firings(firings)?;
        let mut entries = self.trigger_firing_entries(firings)?;
        let previous_faults = self.trigger_actions.combined_faults();
        let mut trigger_actions = self.trigger_actions.clone();
        let mut action_entries = Vec::new();
        for firing in firings.iter() {
            let mut path = Vec::new();
            apply_trigger_action(
                &mut trigger_actions,
                self.trigger_static_topology.as_ref(),
                firing,
                firing.action(),
                &mut path,
                &mut action_entries,
            )?;
        }
        let next_faults = trigger_actions.combined_faults();
        let fault_sequence = u64::try_from(trigger_actions.applications.len()).map_err(|_| {
            SchedulerError::BoundaryViolation {
                message: String::from("trigger fault application sequence exceeds u64"),
            }
        })?;
        self.apply_trigger_taxonomy_faults(fault_sequence, &previous_faults, &next_faults)?;
        for application in &action_entries {
            if let Action::StartNode { node } = &application.action
                && self.is_node_stopped_after_crash(node)
            {
                self.restart_stopped_node(application.sequence, node)?;
            }
        }
        for application in action_entries {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                application.at,
                SchedulerEventLogPayload::TriggerActionApplied(application),
            ));
        }
        let append = self.event_log.append_entries(entries)?;
        self.trigger_actions = trigger_actions;
        Ok(append)
    }

    /// Applies active trigger-owned network faults to one live directed link.
    ///
    /// Trigger action application owns the deterministic fault set and the
    /// scheduler-owned topology effects, while the concrete [`crucible_device::NetLink`]
    /// fault table is owned by the caller's network device. This bridge reads the
    /// current trigger taxonomy projection for `link_id`, installs the resulting
    /// [`crucible_device::LinkFaults`] on `link`, queues any partition topology
    /// change through the scheduler, and consumes any link latency recompute signal
    /// when the directed edge is still live.
    ///
    /// Pass `restored_edges` when this call follows a heal that may restore edges
    /// previously removed by a partition. For ordinary activation or non-partition
    /// updates, pass an empty vector.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the scheduler rejects a topology or latency
    /// recompute queued by the applied network fault set.
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_trigger_network_faults_to_link(
        &mut self,
        sequence: u64,
        link_id: &LinkId,
        endpoint_a: SchedulerNodeId,
        endpoint_b: SchedulerNodeId,
        link: &mut crucible_device::NetLink,
        direction: NetworkLinkDirection,
        restored_edges: Vec<SchedulerLookaheadEdge>,
    ) -> Result<NetworkFaultApplication, SchedulerError> {
        let combined = self.trigger_actions.combined_faults();
        let faults = combined_network_faults_for_link(
            &combined.network,
            link_id,
            &endpoint_a.node,
            &endpoint_b.node,
        );
        let has_restored_edges = !restored_edges.is_empty();
        let application = if has_restored_edges {
            heal_combined_network_faults_to_scheduler(
                sequence,
                endpoint_a.clone(),
                endpoint_b.clone(),
                link,
                &faults,
                direction,
                restored_edges,
                self,
            )?
        } else {
            apply_combined_network_faults_to_scheduler(
                sequence,
                endpoint_a.clone(),
                endpoint_b.clone(),
                link,
                &faults,
                direction,
                self,
            )?
        };

        let partitioned = faults
            .partition
            .as_ref()
            .is_some_and(|partition| network_direction_is_partitioned(direction, partition));
        if !partitioned && !has_restored_edges {
            let _ = self.schedule_link_latency_recompute(sequence, endpoint_a, endpoint_b, link)?;
        }

        Ok(application)
    }

    pub(super) fn apply_trigger_taxonomy_faults(
        &mut self,
        sequence: u64,
        previous: &CombinedFaults,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        if previous == next {
            return Ok(());
        }

        self.apply_trigger_node_faults(sequence, previous, next)?;
        self.apply_trigger_network_topology_faults(sequence, previous, next)?;
        self.apply_trigger_device_faults(next)?;
        Ok(())
    }

    pub(super) fn apply_trigger_node_faults(
        &mut self,
        sequence: u64,
        previous: &CombinedFaults,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        let mut nodes = previous.node.keys().cloned().collect::<BTreeSet<_>>();
        nodes.extend(next.node.keys().cloned());
        for node in nodes {
            let previous_faults = previous.node.get(&node).cloned().unwrap_or_default();
            let next_faults = next.node.get(&node).cloned().unwrap_or_default();
            let previous_crashed = previous_faults.is_crashed();
            let next_crashed = next_faults.is_crashed();
            if !previous_crashed && next_crashed {
                if let Some(restart) = next_faults.crash_restart {
                    self.apply_node_crash(sequence, &node, restart)?;
                }
            } else if previous_crashed && !next_crashed {
                let _ = self.heal_node_crash(sequence, &node)?;
            }
            self.apply_combined_node_timing_faults(&node, &next_faults)?;
        }
        Ok(())
    }

    pub(super) fn apply_trigger_network_topology_faults(
        &mut self,
        sequence: u64,
        previous: &CombinedFaults,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        let previous_topology = network_topology_faults(&previous.network);
        let next_topology = network_topology_faults(&next.network);
        if previous_topology == next_topology {
            return Ok(());
        }
        let Some(static_topology) = &self.trigger_static_topology else {
            return Ok(());
        };
        let legacy_counts =
            legacy_link_id_counts_from_world_edges(&static_topology.lookahead_graph);
        let trigger = if network_topology_faults_were_relaxed(&previous_topology, &next_topology) {
            SchedulerTopologyChangeTrigger::Heal
        } else {
            SchedulerTopologyChangeTrigger::FaultActivation
        };
        let effective_edges = static_topology
            .lookahead_graph
            .iter()
            .filter_map(|edge| world_edge_with_network_faults(edge, &next.network, &legacy_counts))
            .collect::<Vec<_>>();
        self.schedule_topology_change(SchedulerTopologyChange::new(
            sequence,
            trigger,
            effective_edges,
        ))
    }

    pub(super) fn apply_trigger_device_faults(
        &mut self,
        next: &CombinedFaults,
    ) -> Result<(), SchedulerError> {
        for sub_nodes in self.device_sub_nodes.values_mut() {
            for sub_node in sub_nodes {
                match sub_node.sub_node().kind {
                    SchedulingNodeKind::Disk => {
                        let faults = next.block.get(sub_node.device_id());
                        let table = faults.map_or_else(
                            crucible_device::IoFaults::none,
                            block_faults_from_combined_block,
                        );
                        sub_node.set_io_faults(table);
                    }
                    SchedulingNodeKind::NineP => {
                        let faults = next.ninep.get(sub_node.device_id());
                        let table = faults.map_or_else(
                            crucible_device::IoFaults::none,
                            ninep_faults_from_combined_ninep,
                        );
                        sub_node.set_io_faults(table);
                    }
                    SchedulingNodeKind::Vm
                    | SchedulingNodeKind::Network
                    | SchedulingNodeKind::ControlPlane => {}
                }
            }
        }
        for network in self.world_network_links.values_mut() {
            let active = combined_network_faults_for_world_link(
                &next.network,
                &network.canonical_id,
                network.legacy_id.as_ref(),
            );
            let table =
                merge_world_network_faults(&network.base_faults, &active, network.direction);
            network.link.set_faults(table);
            let _ = network.link.take_lookahead_recompute();
        }
        self.refresh_device_horizons()
    }

    pub(super) fn validate_trigger_firings(
        &self,
        firings: &EventFirings,
    ) -> Result<(), SchedulerError> {
        let current_point = self.event_log.condition_prefix().point();
        let current_offset = self.event_log_offset();
        if firings.point() != current_point {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "trigger firings were evaluated at {:?}, but scheduler condition prefix is {:?}",
                    firings.point(),
                    current_point
                ),
            });
        }
        if firings.event_log_offset() != current_offset {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "trigger firings were evaluated at event-log offset {:?}, but scheduler offset is {:?}",
                    firings.event_log_offset(),
                    current_offset
                ),
            });
        }
        if firings.timer_fires() != &self.trigger_actions.armed_timers {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "trigger firings were evaluated with timer state that does not match scheduler trigger action state",
                ),
            });
        }
        Ok(())
    }

    pub(super) fn trigger_firing_entries(
        &self,
        firings: &EventFirings,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let mut entries = Vec::with_capacity(firings.len());
        for firing in firings.iter() {
            let sequence = self.event_log.next_sequence(entries.len())?;
            entries.push(scheduler_event_log_entry(
                sequence,
                firing.at(),
                SchedulerEventLogPayload::TriggerFired(firing.clone()),
            ));
        }
        Ok(entries)
    }

    /// Returns the RUN max-advance ceilings published by this scheduler.
    #[must_use]
    pub fn run_ceiling_publications(&self) -> &[SchedulerRunCeilingPublication] {
        &self.ceiling_publications
    }

    /// Returns plugin-internal RR subdivision evidence for completed RUNs.
    #[must_use]
    pub fn run_subdivision_records(&self) -> &[SchedulerRunSubdivisionRecord] {
        &self.run_subdivision_records
    }

    /// Returns explorer-supplied preemptions applied by completed RESOLVE phases.
    #[must_use]
    pub fn preemption_applications(&self) -> &[SchedulerPreemptionApplication] {
        &self.preemption_applications
    }

    /// Returns topology changes applied at completed scheduler boundaries.
    #[must_use]
    pub fn topology_change_applications(&self) -> &[SchedulerTopologyChangeApplication] {
        &self.topology_change_applications
    }

    /// Returns node crash applications completed by this scheduler.
    #[must_use]
    pub fn node_crash_applications(&self) -> &[SchedulerNodeCrashApplication] {
        &self.node_crash_applications
    }

    /// Returns node heal/restart applications completed by this scheduler.
    #[must_use]
    pub fn node_restart_applications(&self) -> &[SchedulerNodeRestartApplication] {
        &self.node_restart_applications
    }

    /// Returns allowed rendezvous records completed at scheduler boundaries.
    #[must_use]
    pub fn rendezvous_records(&self) -> &[SchedulerRendezvousRecord] {
        &self.rendezvous_records
    }

    /// Returns scheduler-side control applications completed at boundaries.
    #[must_use]
    pub fn control_applications(&self) -> &[SchedulerControlApplication] {
        &self.control_applications
    }

    /// Returns the deterministic RUN set eligible for host-level concurrency.
    ///
    /// The set is bounded by both the scheduler's conservative horizon
    /// computation and `max_host_workers`. RESOLVE and EMIT are not performed by
    /// this read-only query.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if `max_host_workers` is zero or if horizon
    /// projection discovers inconsistent scheduler state.
    pub fn concurrent_run_set(
        &self,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        self.validate_max_host_workers(max_host_workers)?;
        let candidates = self.advance_candidates()?;
        self.concurrent_run_set_from_candidates(max_host_workers, &candidates)
    }

    /// Authorizes one cross-node frame emission under the current topology.
    ///
    /// Backends use this as the scheduler-side send freeze: when a topology
    /// change is pending, no new cross-node frame may be emitted until the next
    /// boundary recomputes lookahead. The authorization also proves the
    /// producer-to-consumer edge is live in the current effective edge set.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when a topology change is
    /// waiting for the boundary recompute, or when the producer-to-consumer edge
    /// is absent from the current effective topology.
    pub fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        if !self.topology_changes.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "cross-node sends frozen while topology change is pending: producer={}:{:?} consumer={}:{:?}",
                    producer.node.name, producer.kind, consumer.node.name, consumer.kind
                ),
            });
        }
        if !self.effective_topology.has_edge(producer, consumer) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "cross-node send has no effective topology edge: producer={}:{:?} consumer={}:{:?}",
                    producer.node.name, producer.kind, consumer.node.name, consumer.kind
                ),
            });
        }

        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: self.topology_epoch,
        })
    }

    /// Returns per-node effective clocks in canonical scheduler-node order.
    ///
    /// Runnable, halted, and done nodes use their current virtual time. Idle nodes
    /// with a finite exact wake project to that wake time, so they do not hold
    /// back peers whose clocks are still behind the wake.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when projecting a node counter or reducing an
    /// idle wake discovers inconsistent scheduler state.
    pub fn effective_clocks(&self) -> Result<Vec<SchedulerEffectiveClock>, SchedulerError> {
        self.nodes
            .iter()
            .map(|node| self.effective_clock_for_node(node))
            .collect()
    }

    /// Applies combined node timing faults to a VM scheduler node.
    ///
    /// Slowdown is installed as an anchored counter-to-virtual-time projection
    /// at the node's current counter, preserving continuity on the scheduler
    /// axis. Clock skew is stored only in the node's guest-visible timing
    /// projection. Crash and restart effects are intentionally outside this
    /// timing-only entry point.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node in this scheduler, or [`SchedulerError::TimeConversion`]
    /// when the current timing projection cannot be computed.
    pub fn apply_combined_node_timing_faults(
        &mut self,
        node: &NodeId,
        faults: &CombinedNodeFaults,
    ) -> Result<NodeTimingFaults, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let anchor_counter = self.nodes[index].counter;
        let anchor_time = self.node_current_time(&self.nodes[index])?;
        let timing_faults =
            node_timing_faults_from_combined_node(faults, anchor_counter, anchor_time);
        self.nodes[index].timing_faults = timing_faults;
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;
        Ok(timing_faults)
    }

    /// Projects one VM node's current counter under active timing faults.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node in this scheduler, or [`SchedulerError::TimeConversion`]
    /// when the projection cannot be computed.
    pub fn node_timing_projection(
        &self,
        node: &NodeId,
    ) -> Result<NodeTimingProjection, SchedulerError> {
        let index = self.vm_node_index(node)?;
        self.nodes[index]
            .timing_faults
            .project(self.nodes[index].counter, self.timeline.shift())
            .map_err(SchedulerError::from)
    }

    /// Returns one VM node's guest-visible time under active clock skew.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the node cannot be found or its timing
    /// projection cannot be computed.
    pub fn guest_visible_time_for_node(&self, node: &NodeId) -> Result<SimInstant, SchedulerError> {
        Ok(self.node_timing_projection(node)?.guest_visible_time)
    }

    /// Computes terminal quiescence from authoritative scheduler state only.
    ///
    /// The predicate is independent of host wall-clock time. A system is
    /// quiescent only when no node is runnable, no exact local wakeup remains
    /// armed, no scheduler event remains queued, and no control operation is
    /// waiting at the boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when exact local event projection discovers
    /// inconsistent scheduler state, such as a scheduled I/O completion whose
    /// key and payload disagree.
    pub fn quiescence(&self) -> Result<SchedulerQuiescence, SchedulerError> {
        let mut blockers = Vec::new();

        let mut control = self.control_inbox.clone();
        control.sort();
        blockers.extend(
            control
                .into_iter()
                .map(|operation| SchedulerQuiescenceBlocker::PendingControl { operation }),
        );

        let mut preemptions = self.preemption_requests.clone();
        preemptions.sort_by(preemption_decision_order);
        blockers.extend(
            preemptions
                .into_iter()
                .map(|decision| SchedulerQuiescenceBlocker::PendingPreemption { decision }),
        );

        let mut topology_changes = self.topology_changes.clone();
        topology_changes.sort_by(topology_change_order);
        blockers.extend(topology_changes.into_iter().map(|change| {
            SchedulerQuiescenceBlocker::PendingTopologyChange {
                sequence: change.sequence,
                trigger: change.trigger,
                activation_time: change.activation_time,
            }
        }));

        blockers.extend(
            ordered_scheduled_events(&self.pending_events)
                .into_iter()
                .map(|event| SchedulerQuiescenceBlocker::PendingEvent {
                    key: event.key.clone(),
                }),
        );

        // An in-flight device completion is a future happening ([SCHED-29]); the
        // system is not quiescent while one is undelivered, even when every node
        // is parked `Idle`. Ordered by target `NodeId` (BTreeMap iteration).
        for (target, sub_nodes) in &self.device_sub_nodes {
            if self.is_node_down(target) {
                continue;
            }
            if sub_nodes
                .iter()
                .any(|sub_node| sub_node.next_exact_local_event().is_some())
            {
                blockers.push(SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                    target: target.clone(),
                });
            }
        }
        let mut network_targets = self
            .world_network_links
            .values()
            .filter(|runtime| runtime.link.next_exact_local_event().is_some())
            .map(|runtime| runtime.target().clone())
            .collect::<Vec<_>>();
        network_targets.sort();
        network_targets.dedup();
        blockers.extend(
            network_targets
                .into_iter()
                .filter(|target| !self.is_node_down(target))
                .map(|target| SchedulerQuiescenceBlocker::DeviceCompletionInFlight { target }),
        );

        for node in &self.nodes {
            blockers.extend(self.vcpu_quiescence_blockers(node));

            match self.effective_node_activity(node) {
                SchedulerNodeActivity::Runnable => {
                    blockers.push(SchedulerQuiescenceBlocker::RunnableNode {
                        node: node.id.clone(),
                    });
                }
                SchedulerNodeActivity::Idle => {}
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done => continue,
            }

            let exact_local_event = self.effective_exact_local_event(node)?;
            if !matches!(exact_local_event, ExactLocalEvent::NoArmedTimer) {
                blockers.push(SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                    node: node.id.clone(),
                    event: exact_local_event,
                });
            }
        }

        Ok(SchedulerQuiescence { blockers })
    }
}
