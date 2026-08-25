//! Live-backend attachment, observation, checkpoint, and counter boundaries.

use super::*;

impl SingleScheduler {
    /// Adopts the exact suffix appended by one paused live-backend operation.
    ///
    /// The backend receives a clone of [`Self::event_log`] while it drains or
    /// shuts down. This method then replays only entries at or after the
    /// scheduler's current dense sequence through the authoritative append
    /// path and requires the resulting offset to equal the backend's complete
    /// offset. It therefore cannot splice a foreign prefix or silently omit a
    /// backend-observed suffix.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `backend_log` does
    /// not extend the exact current prefix, does not retain the required
    /// suffix, or the replayed entries produce another final offset.
    pub fn adopt_live_backend_event_log_suffix(
        &mut self,
        backend_log: &EventLog,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let before = self.event_log.offset();
        if backend_log.offset().events < before.events
            || backend_log.offset().bytes < before.bytes
            || backend_log.condition_base_events > before.events
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live backend event log does not retain the scheduler's current prefix",
                ),
            });
        }
        let suffix = backend_log
            .condition_entries
            .iter()
            .filter(|entry| entry.sequence() >= before.events)
            .cloned()
            .collect::<Vec<_>>();
        let mut staged = self.event_log.clone();
        let appended = staged.append_entries(suffix)?;
        if staged.offset() != backend_log.offset() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live backend event-log suffix does not reproduce its final offset",
                ),
            });
        }
        self.event_log = staged;
        Ok(appended)
    }

    /// Validates one VM identity without changing scheduler state.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name
    /// exactly one VM scheduler node.
    pub fn validate_vm_node_activity_target(&self, node: &NodeId) -> Result<(), SchedulerError> {
        let _index = self.vm_node_index(node)?;
        Ok(())
    }

    /// Requires one VM to have the scheduler activity owned by a lifecycle stage.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` is not a VM or
    /// its authoritative scheduler activity differs from `expected`.
    pub fn require_vm_node_activity(
        &self,
        node: &NodeId,
        expected: SchedulerNodeActivity,
    ) -> Result<(), SchedulerError> {
        let index = self.vm_node_index(node)?;
        let actual = self.nodes[index].activity;
        if actual != expected {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "VM node `{}` has scheduler activity {actual:?}, expected {expected:?}",
                    node.name
                ),
            });
        }
        Ok(())
    }

    /// Returns the scheduler-owned activity of one VM node.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` is not a VM.
    pub fn vm_node_activity(&self, node: &NodeId) -> Result<SchedulerNodeActivity, SchedulerError> {
        let index = self.vm_node_index(node)?;
        Ok(self.nodes[index].activity)
    }

    /// Replaces one VM's scheduler activity at an authenticated lifecycle boundary.
    ///
    /// `Halted` models a powered-off VM that may later return to `Runnable`;
    /// `Done` models permanent failure. The node counter is preserved so a
    /// replacement QEMU process generation can resume the same logical timeline.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name
    /// exactly one VM scheduler node.
    pub fn set_vm_node_activity(
        &mut self,
        node: &NodeId,
        activity: SchedulerNodeActivity,
    ) -> Result<(), SchedulerError> {
        let index = self.vm_node_index(node)?;
        self.nodes[index].activity = activity;
        if matches!(
            activity,
            SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
        ) {
            self.device_horizons.remove(node);
        }
        Ok(())
    }

    /// Atomically changes activity for a set of VM scheduler nodes.
    ///
    /// Every identity is validated before any scheduler state changes. This is
    /// used when one fault boundary closes or replaces multiple VM process
    /// generations as a single transaction.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when any identity is absent or is not a VM.
    /// The scheduler is unchanged on error.
    pub fn set_vm_node_activities(
        &mut self,
        activities: &[(NodeId, SchedulerNodeActivity)],
    ) -> Result<(), SchedulerError> {
        for (node, _) in activities {
            let _index = self.vm_node_index(node)?;
        }
        for (node, activity) in activities {
            let index = self.vm_node_index(node)?;
            self.nodes[index].activity = *activity;
            if matches!(
                activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                self.device_horizons.remove(node);
            }
        }
        Ok(())
    }

    /// Atomically gives one activity to a validated VM-node set without allocation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when any identity is absent or is not a VM.
    pub fn set_vm_nodes_activity(
        &mut self,
        nodes: &[NodeId],
        activity: SchedulerNodeActivity,
    ) -> Result<(), SchedulerError> {
        for node in nodes {
            let _index = self.vm_node_index(node)?;
        }
        for node in nodes {
            let index = self.vm_node_index(node)?;
            self.nodes[index].activity = activity;
            if matches!(
                activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                self.device_horizons.remove(node);
            }
        }
        Ok(())
    }

    /// Captures every scheduler-owned network continuation component.
    #[must_use]
    pub fn network_checkpoint(&self) -> SchedulerNetworkCheckpoint {
        SchedulerNetworkCheckpoint {
            links: self
                .world_network_links
                .iter()
                .map(
                    |((link, direction), runtime)| SchedulerNetworkLinkCheckpoint {
                        link: link.clone(),
                        direction: *direction,
                        state: runtime.link.snapshot(),
                    },
                )
                .collect(),
            rng_positions: self
                .world_network_rng_positions
                .iter()
                .map(|(link, position)| (link.clone(), *position))
                .collect(),
            signal_fault_wakeup_nanos: self.signal_fault_wakeup.map(|wakeup| wakeup.nanos),
        }
    }

    /// Atomically restores scheduler-owned links, RNG cursors, and fault wakeup.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] if checkpoint link/RNG
    /// identities differ from the admitted World or a link snapshot is invalid.
    pub fn restore_network_checkpoint(
        &mut self,
        checkpoint: &SchedulerNetworkCheckpoint,
    ) -> Result<(), SchedulerError> {
        let mut staged = self.clone();
        let checkpoint_keys = checkpoint
            .links
            .iter()
            .map(|link| (link.link.clone(), link.direction))
            .collect::<BTreeSet<_>>();
        let runtime_keys = staged
            .world_network_links
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if checkpoint_keys.len() != checkpoint.links.len() || checkpoint_keys != runtime_keys {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "network checkpoint directed links differ from the admitted World",
                ),
            });
        }
        if checkpoint
            .rng_positions
            .iter()
            .map(|(link, _position)| link)
            .ne(staged.world_network_rng_positions.keys())
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "network checkpoint RNG links differ from the admitted World",
                ),
            });
        }
        let mut restored = BTreeMap::new();
        for link in &checkpoint.links {
            let state = crucible_device::NetLink::restore(&link.state).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "restore network checkpoint link `{}` {:?}: {error}",
                        link.link.name, link.direction
                    ),
                }
            })?;
            restored.insert((link.link.clone(), link.direction), state);
        }
        let wakeup = checkpoint.signal_fault_wakeup_nanos;
        if wakeup.is_some_and(|coordinate| coordinate <= staged.frontier.ticks) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "network checkpoint fault wakeup is not after the scheduler frontier",
                ),
            });
        }
        for (key, link) in restored {
            let runtime = staged.world_network_links.get_mut(&key).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("validated network checkpoint link disappeared"),
                }
            })?;
            runtime.link = link;
        }
        for (link, position) in &checkpoint.rng_positions {
            let runtime_position = staged
                .world_network_rng_positions
                .get_mut(link)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("validated network checkpoint RNG link disappeared"),
                })?;
            *runtime_position = *position;
        }
        staged.signal_fault_wakeup = wakeup.map(|nanos| SimInstant { nanos });
        staged.refresh_device_horizons()?;
        *self = staged;
        Ok(())
    }

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
        Ok(())
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

    /// Records the current VM node counter as its last checkpoint anchor.
    ///
    /// Materialized VM/device state lives in the temporal graph; the scheduler
    /// records the counter/time identity that a checkpoint restore resumes from.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` does not name a
    /// VM scheduler node. Returns [`SchedulerError::TimeConversion`] when the
    /// checkpoint time cannot be projected.
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
    /// VM scheduler node. Returns [`SchedulerError::TimeConversion`] when
    /// `counter` cannot be projected.
    pub fn record_node_checkpoint_at(
        &mut self,
        node: &NodeId,
        counter: NodeCounter,
    ) -> Result<SchedulerNodeCheckpoint, SchedulerError> {
        let index = self.vm_node_index(node)?;
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
        let anchor_time = self.node_current_time(&self.nodes[index])?;
        self.nodes[index].counter = counter;
        self.nodes[index].time_mapping.anchor_counter = counter;
        self.nodes[index].time_mapping.anchor_time = anchor_time;
        Ok(())
    }
}
