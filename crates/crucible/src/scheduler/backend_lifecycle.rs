//! Live-backend attachment, observation, crash, checkpoint, and restart boundaries.

use super::*;

impl SingleScheduler {
    /// Attaches the scheduler-owned directed links declared by `world`.
    ///
    /// This is the live-backend counterpart to [`SingleScheduler::from_world`]:
    /// QEMU owns its concrete block devices, while the authoritative scheduler
    /// still owns every modeled network link, its RNG cursor, in-flight frames,
    /// and active fault projection.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWorldInstantiationError`] when the World network
    /// definitions cannot be instantiated or links were already attached.
    pub fn attach_world_network_links(
        &mut self,
        world: &World,
    ) -> Result<(), SchedulerWorldInstantiationError> {
        if !self.world_network_links.is_empty() || !self.world_network_rng_positions.is_empty() {
            return Err(SchedulerWorldInstantiationError::NetworkStateMismatch {
                reason: String::from("World network links are already attached"),
            });
        }
        self.world_network_links = instantiate_world_network_links(world, self.timeline.shift())?;
        self.world_network_rng_positions = self
            .world_network_links
            .keys()
            .map(|(link, _direction)| (link.clone(), 0))
            .collect();
        let active = self.trigger_actions.combined_faults();
        self.apply_trigger_device_faults(&active)
            .map_err(SchedulerWorldInstantiationError::from)
    }

    /// Atomically appends observations and their completed evaluation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when assigning dense event-log sequences,
    /// appending the segment, or validating the resulting condition prefix
    /// fails.
    pub fn append_observations_at_boundary(
        &mut self,
        events: impl IntoIterator<Item = ObservableEvent>,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.event_log
            .append_observations_at_boundary(events, at, kind)
    }

    /// Applies a crash fault to a VM scheduler node.
    ///
    /// The crash stops the runtime, removes all incident effective topology
    /// edges, clears exact local wakeups, discards scheduler-owned events whose
    /// producer or consumer is the crashed node, and voids all in-flight device
    /// completions targeting the node. The returned application records the
    /// deterministic discard set used for replay.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or the node is already crashed. Returns
    /// [`SchedulerError::TimeConversion`] when the crash activation time cannot
    /// be projected.
    pub fn apply_node_crash(
        &mut self,
        sequence: u64,
        node: &NodeId,
        restart: RestartPolicy,
    ) -> Result<SchedulerNodeCrashApplication, SchedulerError> {
        let index = self.vm_node_index(node)?;
        if self.node_execution_stopped(&self.nodes[index]) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node crash or stop already active for {}", node.name),
            });
        }

        let scheduler_node = self.nodes[index].id.clone();
        let at = self.node_current_time(&self.nodes[index])?;
        let counter = self.nodes[index].counter;
        let previous_activity = self.nodes[index].activity;
        let timing_faults_at_crash = self.nodes[index].timing_faults;
        let checkpoint = self.nodes[index].last_checkpoint.clone();
        let removed_edges = self.incident_effective_edges(&scheduler_node);
        let removed_endpoints = removed_edges
            .iter()
            .map(SchedulerLookaheadEdge::endpoint)
            .collect::<Vec<_>>();
        let discarded_events = self.discard_pending_events_for_node(&scheduler_node);
        let discarded_io = self.discard_device_completions_for_node(node);
        self.preemption_requests
            .retain(|decision| decision.node != *node);
        self.device_horizons.remove(node);

        self.nodes[index].crash = Some(RuntimeNodeCrashState {
            activation_sequence: sequence,
            restart,
            previous_activity,
            counter_at_crash: counter,
            timing_faults_at_crash,
            removed_edges: removed_edges.clone(),
            checkpoint: checkpoint.clone(),
        });
        self.nodes[index].activity = SchedulerNodeActivity::Halted;
        self.nodes[index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        self.nodes[index].vcpu_idle_states.clear();

        if !removed_endpoints.is_empty() {
            self.schedule_topology_change(SchedulerTopologyChange::partition(
                sequence,
                removed_endpoints,
            ))?;
        }
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        let application = SchedulerNodeCrashApplication {
            sequence,
            node: node.clone(),
            restart,
            at,
            counter,
            previous_activity,
            discarded_events,
            discarded_io,
            removed_edges,
            checkpoint,
        };
        self.node_crash_applications.push(application.clone());
        Ok(application)
    }

    /// Records the current VM node counter as its last checkpoint anchor.
    ///
    /// This scheduler-side anchor is the crash/restart contract needed by
    /// [`RestartPolicy::FromLastCheckpoint`]. Materialized VM/device state lives
    /// in the temporal graph; the scheduler records the counter/time identity
    /// that a checkpoint restore must resume from.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or that node is currently stopped by a crash. Returns
    /// [`SchedulerError::TimeConversion`] when the checkpoint time cannot be
    /// projected.
    pub fn record_node_checkpoint(
        &mut self,
        node: &NodeId,
    ) -> Result<SchedulerNodeCheckpoint, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let counter = self.nodes[index].counter;
        self.record_node_checkpoint_at(node, counter)
    }

    /// Records an observed VM backend counter as its last checkpoint anchor.
    ///
    /// Production backends use this entry point when their physical stop
    /// counter differs from the scheduler's requested quantum ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or that node is currently stopped by a crash. Returns
    /// [`SchedulerError::TimeConversion`] when `counter` cannot be projected.
    pub fn record_node_checkpoint_at(
        &mut self,
        node: &NodeId,
        counter: NodeCounter,
    ) -> Result<SchedulerNodeCheckpoint, SchedulerError> {
        let index = self.vm_node_index(node)?;
        if self.node_execution_stopped(&self.nodes[index]) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("cannot checkpoint stopped node {}", node.name),
            });
        }
        let checkpoint = SchedulerNodeCheckpoint {
            node: node.clone(),
            counter,
            at: self.node_time_for_counter(&self.nodes[index], counter)?,
        };
        self.nodes[index].last_checkpoint = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Returns the scheduler-owned logical time for one VM node.
    ///
    /// Production lifecycle replay compares this authoritative clock rather than
    /// a QEMU process's current physical counter. A VM may pause below an
    /// authorized ceiling while the scheduler safely advances its logical clock
    /// to that ceiling, so those values are intentionally not interchangeable.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` is not a VM
    /// scheduler node, or [`SchedulerError::TimeConversion`] when its current
    /// counter cannot be projected.
    pub fn scheduler_time_for_node(&self, node: &NodeId) -> Result<VirtualTime, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let instant = self.node_current_time(&self.nodes[index])?;
        Ok(VirtualTime {
            ticks: instant.nanos,
        })
    }

    /// Sets the scheduler-time boundary used to terminate replay.
    ///
    /// Production thin replay uses the recorded logical checkpoint time rather
    /// than reusing a raw launch ceiling whose physical counter origin can vary
    /// across boots.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `time_limit` precedes
    /// the scheduler's committed frontier.
    pub fn set_replay_time_limit(&mut self, time_limit: VirtualTime) -> Result<(), SchedulerError> {
        if time_limit < self.frontier {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "replay time limit {} precedes committed frontier {}",
                    time_limit.ticks, self.frontier.ticks
                ),
            });
        }
        self.time_limit = SimInstant {
            nanos: time_limit.ticks,
        };
        Ok(())
    }

    /// Caps advancement at an exact runtime-only branch frontier.
    ///
    /// Unlike the scenario time limit, this cap is not terminal and does not
    /// participate in configuration identity. It lets production replay stop at
    /// a saved frontier even when no causal decision occurs there.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `frontier` precedes
    /// the scheduler's committed frontier.
    pub fn set_branch_frontier_cap(&mut self, frontier: VirtualTime) -> Result<(), SchedulerError> {
        if frontier < self.frontier {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "branch frontier {} precedes committed frontier {}",
                    frontier.ticks, self.frontier.ticks
                ),
            });
        }
        self.branch_frontier_cap = Some(SimInstant {
            nanos: frontier.ticks,
        });
        Ok(())
    }

    /// Clears the runtime-only production branch frontier cap.
    pub fn clear_branch_frontier_cap(&mut self) {
        self.branch_frontier_cap = None;
    }

    /// Re-anchors a restarted VM to its replacement backend's physical counter.
    ///
    /// The scheduler time at the restart boundary is preserved. Only the
    /// physical counter origin changes, allowing a freshly booted or thin-
    /// replayed QEMU process to continue the same logical execution even when
    /// its boot-ready counter differs from the process it replaces.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` is not a live
    /// VM scheduler node, or [`SchedulerError::TimeConversion`] when its current
    /// scheduler time cannot be projected.
    pub fn rebase_restarted_backend_counter(
        &mut self,
        node: &NodeId,
        counter: NodeCounter,
    ) -> Result<(), SchedulerError> {
        let index = self.vm_node_index(node)?;
        if self.node_execution_stopped(&self.nodes[index]) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("cannot rebase stopped node {}", node.name),
            });
        }
        let anchor_time = self.node_current_time(&self.nodes[index])?;
        self.nodes[index].counter = counter;
        self.nodes[index].timing_faults.anchor_counter = counter;
        self.nodes[index].timing_faults.anchor_time = anchor_time;
        Ok(())
    }

    /// Heals an active crash fault and applies the node's restart policy.
    ///
    /// [`RestartPolicy::FromReadyPoint`] reboots the node from the baked counter
    /// admitted when the scheduler was constructed.
    /// [`RestartPolicy::FromLastCheckpoint`] resumes from the node's last
    /// recorded pre-crash checkpoint. Both policies re-anchor the node's active
    /// timing projection at the current frontier and queue restoration of the
    /// edges removed by the crash.
    /// [`RestartPolicy::StayDown`] records the heal but leaves the node stopped
    /// until a future explicit restart command.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or no crash is active for the node.
    pub fn heal_node_crash(
        &mut self,
        sequence: u64,
        node: &NodeId,
    ) -> Result<SchedulerNodeRestartApplication, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let Some(state) = self.nodes[index].crash.clone() else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node crash is not active for {}", node.name),
            });
        };
        if state.restart == RestartPolicy::FromLastCheckpoint && state.checkpoint.is_none() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "checkpoint restart requested for {} without a recorded pre-crash checkpoint",
                    node.name
                ),
            });
        }
        let Some(state) = self.nodes[index].crash.take() else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node crash is not active for {}", node.name),
            });
        };

        let restart_time = SimInstant {
            nanos: self.frontier.ticks,
        };
        if state.restart == RestartPolicy::StayDown {
            self.nodes[index].stopped_crash = Some(RuntimeNodeStoppedState {
                activation_sequence: state.activation_sequence,
                previous_activity: state.previous_activity,
                timing_faults_at_stop: state.timing_faults_at_crash,
                removed_edges: state.removed_edges,
            });
            let application = SchedulerNodeRestartApplication {
                sequence,
                node: node.clone(),
                restart: state.restart,
                at: restart_time,
                restarted: false,
                counter: self.nodes[index].counter,
                restored_edges: Vec::new(),
                checkpoint: state.checkpoint,
            };
            self.node_restart_applications.push(application.clone());
            return Ok(application);
        }

        let checkpoint = match state.restart {
            RestartPolicy::FromLastCheckpoint => state.checkpoint.clone(),
            RestartPolicy::FromReadyPoint | RestartPolicy::StayDown => state.checkpoint.clone(),
        };
        let counter = match state.restart {
            RestartPolicy::FromReadyPoint => self.nodes[index].ready_counter,
            RestartPolicy::FromLastCheckpoint => checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.counter)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "checkpoint restart requested for {} without a recorded pre-crash checkpoint",
                        node.name
                    ),
                })?,
            RestartPolicy::StayDown => state.counter_at_crash,
        };
        let mut timing_faults = state.timing_faults_at_crash;
        timing_faults.anchor_counter = counter;
        timing_faults.anchor_time = restart_time;

        self.nodes[index].counter = counter;
        self.nodes[index].timing_faults = timing_faults;
        self.nodes[index].activity = state.previous_activity;
        self.nodes[index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        self.nodes[index].vcpu_idle_states.clear();
        if state.restart == RestartPolicy::FromReadyPoint {
            self.nodes[index].last_checkpoint = None;
        }

        if !state.removed_edges.is_empty() {
            self.schedule_topology_change(SchedulerTopologyChange::heal(
                sequence,
                state.removed_edges.clone(),
            ))?;
        }
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        let application = SchedulerNodeRestartApplication {
            sequence,
            node: node.clone(),
            restart: state.restart,
            at: restart_time,
            restarted: true,
            counter,
            restored_edges: state.removed_edges,
            checkpoint,
        };
        self.node_restart_applications.push(application.clone());
        Ok(application)
    }

    /// Explicitly restarts a node left stopped by [`RestartPolicy::StayDown`].
    ///
    /// The restart uses the baked ready-point counter and restores the effective
    /// topology edges that were suppressed while the node was down.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node or the node is not waiting in the StayDown stopped
    /// state.
    pub fn restart_stopped_node(
        &mut self,
        sequence: u64,
        node: &NodeId,
    ) -> Result<SchedulerNodeRestartApplication, SchedulerError> {
        let index = self.vm_node_index(node)?;
        let Some(state) = self.nodes[index].stopped_crash.take() else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("node is not stopped after crash: {}", node.name),
            });
        };

        let restart_time = SimInstant {
            nanos: self.frontier.ticks,
        };
        let counter = self.nodes[index].ready_counter;
        let mut timing_faults = state.timing_faults_at_stop;
        timing_faults.anchor_counter = counter;
        timing_faults.anchor_time = restart_time;

        self.nodes[index].counter = counter;
        self.nodes[index].timing_faults = timing_faults;
        self.nodes[index].activity = state.previous_activity;
        self.nodes[index].exact_local_event = ExactLocalEvent::NoArmedTimer;
        self.nodes[index].vcpu_idle_states.clear();
        self.nodes[index].last_checkpoint = None;

        if !state.removed_edges.is_empty() {
            self.schedule_topology_change(SchedulerTopologyChange::heal(
                sequence,
                state.removed_edges.clone(),
            ))?;
        }
        self.frontier = frontier_for(&self.nodes, self.timeline.shift())?;

        let application = SchedulerNodeRestartApplication {
            sequence,
            node: node.clone(),
            restart: RestartPolicy::StayDown,
            at: restart_time,
            restarted: true,
            counter,
            restored_edges: state.removed_edges,
            checkpoint: None,
        };
        self.node_restart_applications.push(application.clone());
        Ok(application)
    }

    /// Returns whether a VM node is currently crashed.
    #[must_use]
    pub fn is_node_crashed(&self, node: &NodeId) -> bool {
        self.nodes.iter().any(|runtime| {
            runtime.id.node == *node
                && runtime.id.kind == SchedulingNodeKind::Vm
                && runtime.crash.is_some()
        })
    }

    /// Returns whether a VM node is stopped after a healed StayDown crash.
    #[must_use]
    pub fn is_node_stopped_after_crash(&self, node: &NodeId) -> bool {
        self.nodes.iter().any(|runtime| {
            runtime.id.node == *node
                && runtime.id.kind == SchedulingNodeKind::Vm
                && runtime.stopped_crash.is_some()
        })
    }
}
