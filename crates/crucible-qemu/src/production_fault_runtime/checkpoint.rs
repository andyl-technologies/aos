//! Runtime checkpoint capture and continuation accessors.

use super::*;

impl ProductionFaultRuntime {
    /// Captures the complete evaluator, host-device, and live-QEMU continuation.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when any live QEMU node cannot
    /// supply its authenticated execution fingerprint.
    pub fn checkpoint(
        &self,
        nodes: &mut QemuNodeSet,
    ) -> Result<ProductionFaultRuntimeCheckpoint, ProductionFaultRuntimeError> {
        if nodes.has_pending_fault_events()?
            || !self.pending_node_lifecycle.is_empty()
            || !self.pending_node_boot.is_empty()
        {
            return Err(ProductionFaultRuntimeError::PendingQemuFaultEvents);
        }
        if !self.pending_search_choices.is_empty() {
            return Err(ProductionFaultRuntimeError::PendingSearchChoices);
        }
        validate_production_event_state(
            &self.emitted_events,
            &[],
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let runtime = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.checkpoint().clone());
        let host = self.host.state().clone();
        let qemu_fingerprints =
            qemu_node_map(nodes.execution_fingerprints()?, self.resource_limits)?;
        let qemu_fault_sequences =
            qemu_node_map(nodes.fault_command_sequences(), self.resource_limits)?;
        let qemu_fault_event_sequences =
            qemu_node_map(nodes.fault_event_sequences(), self.resource_limits)?;
        validate_pending_qemu_event_sequences(
            &self.pending_qemu_events,
            &qemu_fault_event_sequences,
        )?;
        let identity = production_checkpoint_identity(
            self.plan_id,
            self.resource_limits,
            runtime.as_ref(),
            &host,
            &qemu_fingerprints,
            &qemu_fault_sequences,
            &qemu_fault_event_sequences,
            &self.qemu_issued_actions,
            &self.qemu_action_commits,
            &self.qemu_active_rule_ids,
            self.restored_network_state.as_ref(),
            &self.emitted_events,
            &self.pending_qemu_observations,
            &self.pending_qemu_events,
        )?;
        Ok(ProductionFaultRuntimeCheckpoint {
            runtime,
            host,
            qemu_fingerprints,
            qemu_fault_sequences,
            qemu_fault_event_sequences,
            qemu_issued_actions: self.qemu_issued_actions.try_clone().map_err(|_| {
                checkpoint_collection_allocation(
                    "event_records",
                    self.qemu_issued_actions.len(),
                    self.resource_limits,
                )
            })?,
            qemu_action_commits: self.qemu_action_commits.try_clone().map_err(|_| {
                checkpoint_collection_allocation(
                    "event_records",
                    self.qemu_action_commits.len(),
                    self.resource_limits,
                )
            })?,
            qemu_active_rule_ids: self.qemu_active_rule_ids.try_clone().map_err(|_| {
                checkpoint_collection_allocation(
                    "event_records",
                    self.qemu_active_rule_ids.len(),
                    self.resource_limits,
                )
            })?,
            network_state: self.restored_network_state.clone(),
            emitted_events: self.emitted_events.clone(),
            pending_qemu_observations: self.pending_qemu_observations.clone(),
            pending_qemu_events: self.pending_qemu_events.try_clone().map_err(|_| {
                checkpoint_collection_allocation(
                    "nodes",
                    self.pending_qemu_events.len(),
                    self.resource_limits,
                )
            })?,
            identity,
        })
    }

    /// Reports whether the live or restored continuation carries explorer overrides.
    #[must_use]
    pub fn has_search_overrides(&self) -> bool {
        self.runtime
            .as_ref()
            .is_some_and(OwnedFaultExecutionRuntime::has_search_overrides)
    }

    /// Captures the complete continuation with scheduler-owned network state.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] under the same conditions as
    /// [`Self::checkpoint`].
    pub fn checkpoint_with_network_state(
        &self,
        nodes: &mut QemuNodeSet,
        network_state: ProductionNetworkStateCheckpoint,
    ) -> Result<ProductionFaultRuntimeCheckpoint, ProductionFaultRuntimeError> {
        let mut checkpoint = self.checkpoint(nodes)?;
        checkpoint.network_state = Some(network_state);
        checkpoint.identity = production_checkpoint_identity(
            self.plan_id,
            self.resource_limits,
            checkpoint.runtime.as_ref(),
            &checkpoint.host,
            &checkpoint.qemu_fingerprints,
            &checkpoint.qemu_fault_sequences,
            &checkpoint.qemu_fault_event_sequences,
            &checkpoint.qemu_issued_actions,
            &checkpoint.qemu_action_commits,
            &checkpoint.qemu_active_rule_ids,
            checkpoint.network_state.as_ref(),
            &checkpoint.emitted_events,
            &checkpoint.pending_qemu_observations,
            &checkpoint.pending_qemu_events,
        )?;
        Ok(checkpoint)
    }

    /// Returns committed typed host actions consumed by network and storage.
    #[must_use]
    pub const fn host_state(&self) -> &HostFaultActionState {
        self.host.state()
    }

    /// Returns referenced signal events in exact evaluation order.
    #[must_use]
    pub fn emitted_events(&self) -> &[ReferencedSignalEvent] {
        &self.emitted_events
    }

    /// Returns node lifecycle decisions after the enclosing boundary commits.
    ///
    /// The caller must supervise every returned decision before another fault
    /// boundary, scheduler quantum, or checkpoint. Decisions are published only
    /// after the complete drained event batch and its resource reservations have
    /// validated, so taking them never exposes a partially authenticated batch.
    #[must_use]
    pub fn node_lifecycle_decisions(&self) -> &[QemuNodeLifecycleDecision] {
        &self.pending_node_lifecycle
    }

    /// Acknowledges that every pending terminal lifecycle decision was
    /// independently supervised to its exact process status.
    ///
    /// Callers must invoke this method only after all decisions returned by
    /// [`Self::node_lifecycle_decisions`] have completed successfully. A
    /// supervision error deliberately leaves the decisions pending so the
    /// continuation cannot checkpoint or advance as though the outcome were
    /// known.
    pub fn acknowledge_node_lifecycle_decisions(&mut self) {
        self.pending_node_lifecycle.clear();
    }

    /// Returns nodes whose committed lifecycle action requests a boot.
    ///
    /// The host uses this edge to resume a natively paused power-off
    /// generation before the scheduler can select it again.
    #[must_use]
    pub fn node_boot_requests(&self) -> &BTreeSet<NodeId> {
        &self.pending_node_boot
    }

    /// Acknowledges boot requests after every requested node is activated.
    pub fn acknowledge_node_boot_requests(&mut self) {
        self.pending_node_boot.clear();
    }

    /// Removes finite explorer choices after the scheduler has recorded them.
    #[must_use]
    pub fn drain_search_choices(&mut self) -> Vec<(FaultCoordinate, Vec<BindingSearchChoice>)> {
        std::mem::take(&mut self.pending_search_choices)
    }

    pub(super) fn retain_search_choices(
        &mut self,
        coordinate: FaultCoordinate,
        choices: &[BindingSearchChoice],
    ) {
        if !choices.is_empty() {
            self.pending_search_choices
                .push((coordinate, choices.to_vec()));
        }
    }

    /// Removes committed host impulses for exact device-opportunity execution.
    ///
    /// Callers must apply the returned actions before evaluating another fault
    /// boundary or opportunity; the host sink rejects new work while impulses
    /// remain unconsumed.
    pub fn drain_host_impulses(&mut self) -> Vec<crucible::model::ResolvedBindingAction> {
        self.host.state_mut().drain_impulses()
    }

    /// Permanently poisons a continuation after coupled adapter visibility becomes ambiguous.
    pub fn poison(&mut self) {
        if let Some(runtime) = &mut self.runtime {
            runtime.poison();
        }
    }

    /// Returns the authoritative scenario seed for keyed host-adapter choices.
    #[must_use]
    pub fn scenario_seed(&self) -> Option<ContentHash> {
        self.runtime
            .as_ref()
            .map(OwnedFaultExecutionRuntime::scenario_seed)
    }
}

fn qemu_node_map<V>(
    values: BTreeMap<NodeId, V>,
    limits: FaultResourceLimits,
) -> Result<QemuNodeMap<V>, ProductionFaultRuntimeError> {
    let count = values.len();
    limits.reserve(
        "nodes",
        0,
        u64::try_from(count).map_err(|_| FaultResourceLimitError::Representation {
            field: "nodes",
            value: u64::MAX,
        })?,
    )?;
    let mut mapped = QemuNodeMap::new();
    for (node, value) in values {
        mapped
            .try_insert(node, value)
            .map_err(|_| checkpoint_collection_allocation("nodes", count, limits))?;
    }
    Ok(mapped)
}

fn checkpoint_collection_allocation(
    field: &'static str,
    requested: usize,
    limits: FaultResourceLimits,
) -> ProductionFaultRuntimeError {
    let requested = u64::try_from(requested).unwrap_or(u64::MAX);
    FaultResourceLimitError::Exceeded {
        field,
        current: 0,
        requested,
        configured: limits.configured(field).unwrap_or(0),
        hard: FaultResourceLimits::compiled_maximum()
            .configured(field)
            .unwrap_or(0),
    }
    .into()
}
