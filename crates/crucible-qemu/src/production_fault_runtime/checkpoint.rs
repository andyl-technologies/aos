//! Runtime checkpoint capture and continuation accessors.

use super::*;

impl ProductionFaultRuntime {
    /// Returns the admitted scenario resource ceilings.
    #[must_use]
    pub const fn resource_limits(&self) -> FaultResourceLimits {
        self.resource_limits
    }

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
        if self.lifecycle_work_in_flight.is_some() {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
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
        let remaining_event_records = self.event_staging_capacity(&[], None)?;
        nodes.set_fault_event_staging_limit(
            remaining_event_records,
            usize::try_from(self.resource_limits.event_records).map_err(|_| {
                FaultResourceLimitError::Representation {
                    field: "event_records",
                    value: self.resource_limits.event_records,
                }
            })?,
        )?;
        let runtime = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.checkpoint().clone());
        let host = self.host.state().clone();
        let qemu_fingerprints =
            qemu_fingerprint_map(nodes, self.resource_limits, remaining_event_records)?;
        // Fingerprint publication is itself a tokenized plugin control pump.
        // It may make an asynchronous occurrence visible after the entry check;
        // canonical capture must reject that continuation rather than omit the
        // host-runtime staging buffer from the durable envelope.
        if nodes.has_pending_fault_events()? {
            return Err(ProductionFaultRuntimeError::PendingQemuFaultEvents);
        }
        let qemu_fault_sequences = qemu_sequence_map(
            nodes.fault_command_sequence_entries(),
            nodes.len(),
            self.resource_limits,
        )?;
        let qemu_fault_event_sequences = qemu_sequence_map(
            nodes.fault_event_sequence_entries(),
            nodes.len(),
            self.resource_limits,
        )?;
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
            qemu_issued_actions: self.qemu_issued_actions.try_clone_with(
                |identity| Ok(*identity),
                |action| {
                    try_clone_action(action, || {
                        checkpoint_collection_allocation(
                            "event_records",
                            self.qemu_issued_actions.len(),
                            self.resource_limits,
                        )
                    })
                },
                || {
                    checkpoint_collection_allocation(
                        "event_records",
                        self.qemu_issued_actions.len(),
                        self.resource_limits,
                    )
                },
            )?,
            qemu_action_commits: self.qemu_action_commits.try_clone_with(
                |identity| Ok(*identity),
                |commit| Ok(*commit),
                || {
                    checkpoint_collection_allocation(
                        "event_records",
                        self.qemu_action_commits.len(),
                        self.resource_limits,
                    )
                },
            )?,
            qemu_active_rule_ids: self.qemu_active_rule_ids.try_clone_with(
                |identity| Ok(*identity),
                || {
                    checkpoint_collection_allocation(
                        "event_records",
                        self.qemu_active_rule_ids.len(),
                        self.resource_limits,
                    )
                },
            )?,
            network_state: self.restored_network_state.clone(),
            emitted_events: self.emitted_events.clone(),
            pending_qemu_observations: self.pending_qemu_observations.clone(),
            pending_qemu_events: self.pending_qemu_events.try_clone_with(
                |node| {
                    try_clone_ledger_node_id(node, || {
                        checkpoint_collection_allocation(
                            "nodes",
                            self.pending_qemu_events.len(),
                            self.resource_limits,
                        )
                    })
                },
                |events| {
                    try_clone_fault_events(events, || {
                        checkpoint_collection_allocation(
                            "event_records",
                            self.pending_qemu_events
                                .values()
                                .map(Vec::len)
                                .fold(0_usize, usize::saturating_add),
                            self.resource_limits,
                        )
                    })
                },
                || {
                    checkpoint_collection_allocation(
                        "nodes",
                        self.pending_qemu_events.len(),
                        self.resource_limits,
                    )
                },
            )?,
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
    pub fn node_boot_requests(&self) -> &[NodeId] {
        &self.pending_node_boot
    }

    /// Acknowledges boot requests after every requested node is activated.
    pub fn acknowledge_node_boot_requests(&mut self) {
        self.pending_node_boot.clear();
    }

    /// Transfers the complete authenticated lifecycle batch to its sole host consumer.
    ///
    /// The runtime retains a checkpoint barrier until the returned owner is
    /// passed to [`Self::acknowledge_node_lifecycle_work`].
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError::PendingNodeLifecycleWork`] when a
    /// prior transferred batch has not been acknowledged.
    #[must_use]
    pub fn take_node_lifecycle_work(
        &mut self,
    ) -> Result<QemuNodeLifecycleWork, ProductionFaultRuntimeError> {
        if self.lifecycle_work_in_flight.is_some() {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
        }
        let has_work =
            !self.pending_node_lifecycle.is_empty() || !self.pending_node_boot.is_empty();
        let token = if has_work {
            let token = self.lifecycle_work_sequence;
            self.lifecycle_work_sequence = self.lifecycle_work_sequence.checked_add(1).ok_or(
                FaultResourceLimitError::Representation {
                    field: "event_records",
                    value: u64::MAX,
                },
            )?;
            self.lifecycle_work_in_flight = Some(token);
            Some(token)
        } else {
            None
        };
        Ok(QemuNodeLifecycleWork {
            token,
            decisions: std::mem::take(&mut self.pending_node_lifecycle),
            boot_requests: std::mem::take(&mut self.pending_node_boot),
        })
    }

    /// Acknowledges complete host consumption of one transferred lifecycle batch.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError::PendingNodeLifecycleWork`] when
    /// `work` is not the runtime's current sole transferred owner.
    pub fn acknowledge_node_lifecycle_work(
        &mut self,
        work: QemuNodeLifecycleWork,
    ) -> Result<(), ProductionFaultRuntimeError> {
        if self.lifecycle_work_in_flight != work.token
            || (work.token.is_none()
                && (!work.decisions.is_empty() || !work.boot_requests.is_empty()))
        {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
        }
        self.lifecycle_work_in_flight = None;
        Ok(())
    }

    /// Removes finite explorer choices after the scheduler has recorded them.
    #[must_use]
    pub fn drain_search_choices(&mut self) -> Vec<(FaultCoordinate, Vec<BindingSearchChoice>)> {
        std::mem::take(&mut self.pending_search_choices)
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

pub(super) fn qemu_fingerprint_map(
    nodes: &mut QemuNodeSet,
    limits: FaultResourceLimits,
    maximum_event_records: usize,
) -> Result<QemuNodeMap<ContentHash>, ProductionFaultRuntimeError> {
    let count = nodes.len();
    admit_qemu_node_count(count, limits)?;
    let mut mapped = QemuNodeMap::new();
    let configured_event_records = usize::try_from(limits.event_records).map_err(|_| {
        FaultResourceLimitError::Representation {
            field: "event_records",
            value: limits.event_records,
        }
    })?;
    for observed in
        nodes.execution_fingerprint_entries(maximum_event_records, configured_event_records)?
    {
        let (node, fingerprint) = observed?;
        mapped
            .try_insert(try_clone_node_id(node, limits)?, fingerprint)
            .map_err(|_| checkpoint_collection_allocation("nodes", count, limits))?;
    }
    Ok(mapped)
}

fn qemu_sequence_map<'a>(
    values: impl Iterator<Item = (&'a NodeId, u64)>,
    count: usize,
    limits: FaultResourceLimits,
) -> Result<QemuNodeMap<u64>, ProductionFaultRuntimeError> {
    admit_qemu_node_count(count, limits)?;
    let mut mapped = QemuNodeMap::new();
    for (node, value) in values {
        mapped
            .try_insert(try_clone_node_id(node, limits)?, value)
            .map_err(|_| checkpoint_collection_allocation("nodes", count, limits))?;
    }
    Ok(mapped)
}

fn admit_qemu_node_count(
    count: usize,
    limits: FaultResourceLimits,
) -> Result<(), ProductionFaultRuntimeError> {
    limits
        .reserve(
            "nodes",
            0,
            u64::try_from(count).map_err(|_| FaultResourceLimitError::Representation {
                field: "nodes",
                value: u64::MAX,
            })?,
        )
        .map_err(ProductionFaultRuntimeError::from)
}

fn try_clone_node_id(
    node: &NodeId,
    limits: FaultResourceLimits,
) -> Result<NodeId, ProductionFaultRuntimeError> {
    let mut name = String::new();
    name.try_reserve_exact(node.name.len())
        .map_err(|_| checkpoint_collection_allocation("nodes", 1, limits))?;
    name.push_str(&node.name);
    Ok(NodeId { name })
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
