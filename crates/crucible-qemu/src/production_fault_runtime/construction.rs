//! Runtime construction, restore, replay, and trace access.

use super::*;

impl ProductionFaultRuntime {
    /// Fallibly clones the live production continuation for transactional rollback.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when canonical ledger storage
    /// cannot be reserved for the clone.
    pub fn try_clone(&self) -> Result<Self, ProductionFaultRuntimeError> {
        Ok(Self {
            plan_id: self.plan_id,
            resource_limits: self.resource_limits,
            runtime: self.runtime.clone(),
            host: self.host.clone(),
            restored_network_state: self.restored_network_state.clone(),
            emitted_events: self.emitted_events.clone(),
            qemu_issued_actions: self.qemu_issued_actions.try_clone().map_err(|_| {
                runtime_clone_allocation(
                    "event_records",
                    self.qemu_issued_actions.len(),
                    self.resource_limits,
                )
            })?,
            qemu_action_commits: self.qemu_action_commits.try_clone().map_err(|_| {
                runtime_clone_allocation(
                    "event_records",
                    self.qemu_action_commits.len(),
                    self.resource_limits,
                )
            })?,
            qemu_active_rule_ids: self.qemu_active_rule_ids.try_clone().map_err(|_| {
                runtime_clone_allocation(
                    "event_records",
                    self.qemu_active_rule_ids.len(),
                    self.resource_limits,
                )
            })?,
            pending_qemu_observations: self.pending_qemu_observations.clone(),
            pending_qemu_events: self.pending_qemu_events.try_clone().map_err(|_| {
                runtime_clone_allocation(
                    "nodes",
                    self.pending_qemu_events.len(),
                    self.resource_limits,
                )
            })?,
            pending_node_lifecycle: self.pending_node_lifecycle.clone(),
            pending_node_boot: self.pending_node_boot.clone(),
            pending_search_choices: self.pending_search_choices.clone(),
        })
    }

    /// Admits a complete plan and creates an empty production continuation.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when graph state or an exact backend
    /// capability required by a nonempty plan cannot be admitted.
    pub fn new(
        plan: FaultSignalPlan,
        artifacts: Option<Arc<dyn SignalArtifactProvider>>,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        host_manifests: HostFaultAdapterManifests,
        nodes: &QemuNodeSet,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        Self::new_with_search_overrides(
            plan,
            artifacts,
            boundary,
            scenario_seed,
            host_manifests,
            nodes,
            BTreeMap::new(),
        )
    }

    /// Admits a complete plan with concrete finite explorer overrides.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] under the same conditions as
    /// [`Self::new`], or when the override set exceeds admitted bounds.
    pub fn new_with_search_overrides(
        plan: FaultSignalPlan,
        artifacts: Option<Arc<dyn SignalArtifactProvider>>,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        host_manifests: HostFaultAdapterManifests,
        nodes: &QemuNodeSet,
        search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        validate_ready_marker_admission(&plan, nodes)?;
        let manifests = production_manifests(nodes, host_manifests)?;
        let plan_id = plan.id();
        let resource_limits = plan.resource_limits();
        let runtime = if plan.programs().is_empty() {
            None
        } else {
            let artifacts =
                artifacts.ok_or(ProductionFaultRuntimeError::MissingArtifactProvider)?;
            Some(OwnedFaultExecutionRuntime::new_with_search_overrides(
                plan,
                artifacts,
                boundary,
                scenario_seed,
                manifests,
                search_overrides,
            )?)
        };
        Ok(Self {
            plan_id,
            resource_limits,
            runtime,
            host: HostFaultActionSink::new(resource_limits),
            restored_network_state: None,
            emitted_events: Vec::new(),
            qemu_issued_actions: QemuActionMap::new(),
            qemu_action_commits: QemuActionMap::new(),
            qemu_active_rule_ids: QemuActionSet::new(),
            pending_qemu_observations: Vec::new(),
            pending_qemu_events: PendingQemuEventMap::new(),
            pending_node_lifecycle: Vec::new(),
            pending_node_boot: BTreeSet::new(),
            pending_search_choices: Vec::new(),
        })
    }

    /// Restores one authenticated production continuation.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when the checkpoint's runtime presence
    /// disagrees with the plan or any runtime identity/capability check fails.
    pub fn restore(
        plan: FaultSignalPlan,
        artifacts: Option<Arc<dyn SignalArtifactProvider>>,
        scenario_seed: ContentHash,
        checkpoint: ProductionFaultRuntimeCheckpoint,
        host_manifests: HostFaultAdapterManifests,
        nodes: &mut QemuNodeSet,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        validate_ready_marker_admission(&plan, nodes)?;
        let manifests = production_manifests(nodes, host_manifests)?;
        let plan_id = plan.id();
        let resource_limits = plan.resource_limits();
        validate_production_event_state(
            &checkpoint.emitted_events,
            &[],
            &checkpoint.pending_qemu_observations,
            &[],
            &checkpoint.pending_qemu_events,
            resource_limits,
        )?;
        validate_pending_qemu_event_sequences(
            &checkpoint.pending_qemu_events,
            &checkpoint.qemu_fault_event_sequences,
        )?;
        validate_qemu_action_ledger(
            &checkpoint.qemu_issued_actions,
            &checkpoint.qemu_action_commits,
            &checkpoint.qemu_active_rule_ids,
        )?;
        if checkpoint.identity
            != production_checkpoint_identity(
                plan.id(),
                resource_limits,
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
            )?
        {
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        let observed_qemu_fingerprints =
            super::checkpoint::qemu_fingerprint_map(nodes, resource_limits)?;
        validate_checkpoint_qemu_fingerprints(
            &checkpoint.qemu_fingerprints,
            &observed_qemu_fingerprints,
        )?;
        if plan.programs().is_empty() && !checkpoint.host.is_empty() {
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        checkpoint
            .host
            .validate_mirror(
                &checkpoint
                    .runtime
                    .as_ref()
                    .map_or_else(Default::default, |runtime| {
                        runtime.binding_runtime.active.clone()
                    }),
            )
            .map_err(FaultExecutionError::from)?;
        let qemu_fault_sequences = checkpoint.qemu_fault_sequences;
        let qemu_fault_event_sequences = checkpoint.qemu_fault_event_sequences;
        let qemu_issued_actions = checkpoint.qemu_issued_actions;
        let qemu_action_commits = checkpoint.qemu_action_commits;
        let qemu_active_rule_ids = checkpoint.qemu_active_rule_ids;
        let host = checkpoint.host;
        let restored_network_state = checkpoint.network_state;
        let emitted_events = checkpoint.emitted_events;
        let pending_qemu_observations = checkpoint.pending_qemu_observations;
        let pending_qemu_events = checkpoint.pending_qemu_events;
        let runtime = match (plan.programs().is_empty(), checkpoint.runtime) {
            (true, None) => None,
            (false, Some(checkpoint)) => {
                let artifacts =
                    artifacts.ok_or(ProductionFaultRuntimeError::MissingArtifactProvider)?;
                Some(OwnedFaultExecutionRuntime::restore(
                    plan,
                    artifacts,
                    scenario_seed,
                    manifests,
                    checkpoint,
                )?)
            }
            _ => return Err(FaultExecutionError::CheckpointPresence.into()),
        };
        nodes.restore_ordered_fault_sequences(
            qemu_fault_sequences.as_slice(),
            qemu_fault_event_sequences.as_slice(),
        )?;
        Ok(Self {
            plan_id,
            resource_limits,
            runtime,
            host: HostFaultActionSink::from_state(host, resource_limits),
            restored_network_state,
            emitted_events,
            qemu_issued_actions,
            qemu_action_commits,
            qemu_active_rule_ids,
            pending_qemu_observations,
            pending_qemu_events,
            pending_node_lifecycle: Vec::new(),
            pending_node_boot: BTreeSet::new(),
            pending_search_choices: Vec::new(),
        })
    }

    /// Takes the authenticated network continuation paired with this restore.
    #[must_use]
    pub fn take_restored_network_state(&mut self) -> Option<ProductionNetworkStateCheckpoint> {
        self.restored_network_state.take()
    }

    /// Installs a fresh authoritative replay trace for subsequent live execution.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when the plan is inert or the
    /// trace is malformed, oversized, already consumed, or mode-incompatible.
    pub fn install_replay(
        &mut self,
        trace: ResolvedEffectTrace,
    ) -> Result<(), ProductionFaultRuntimeError> {
        self.runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?
            .install_replay(trace)?;
        Ok(())
    }

    /// Requires every installed replay record to have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when no trace is installed or
    /// the run stopped before consuming the complete trace.
    pub fn verify_replay_exhausted(&self) -> Result<(), ProductionFaultRuntimeError> {
        self.runtime
            .as_ref()
            .ok_or(FaultExecutionError::CheckpointPresence)?
            .verify_replay_exhausted()?;
        Ok(())
    }

    /// Requires every installed finite search override to be consumed once.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when the plan is inert or an
    /// installed override was never reached.
    pub fn verify_search_overrides_consumed(&self) -> Result<(), ProductionFaultRuntimeError> {
        self.runtime
            .as_ref()
            .ok_or(FaultExecutionError::CheckpointPresence)?
            .verify_search_overrides_consumed()?;
        Ok(())
    }

    /// Returns every committed production effect as an unconsumed replay trace.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when the plan is inert or the
    /// selected replay mode rejects one of the recorded effects.
    pub fn recorded_trace(
        &self,
        mode: FaultReplayMode,
    ) -> Result<ResolvedEffectTrace, ProductionFaultRuntimeError> {
        Ok(self
            .runtime
            .as_ref()
            .ok_or(FaultExecutionError::CheckpointPresence)?
            .recorded_trace(mode)?)
    }
}

fn runtime_clone_allocation(
    field: &'static str,
    requested: usize,
    limits: FaultResourceLimits,
) -> ProductionFaultRuntimeError {
    FaultResourceLimitError::Exceeded {
        field,
        current: 0,
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: limits.configured(field).unwrap_or(0),
        hard: FaultResourceLimits::compiled_maximum()
            .configured(field)
            .unwrap_or(0),
    }
    .into()
}

pub(crate) fn validate_qemu_fingerprints(
    expected: &BTreeMap<NodeId, ContentHash>,
    observed: &BTreeMap<NodeId, ContentHash>,
) -> Result<(), ProductionFaultRuntimeError> {
    if expected.len() == observed.len()
        && expected
            .iter()
            .all(|(node, fingerprint)| observed.get(node) == Some(fingerprint))
    {
        return Ok(());
    }

    let node = expected
        .keys()
        .chain(observed.keys())
        .find(|node| expected.get(*node) != observed.get(*node))
        .cloned()
        .ok_or(FaultExecutionError::CheckpointPresence)?;
    Err(ProductionFaultRuntimeError::QemuFingerprintMismatch {
        expected: expected
            .get(&node)
            .map_or_else(|| String::from("<missing>"), |hash| (*hash).to_hex()),
        observed: observed
            .get(&node)
            .map_or_else(|| String::from("<missing>"), |hash| (*hash).to_hex()),
        node: node.name,
    })
}

fn validate_checkpoint_qemu_fingerprints(
    expected: &QemuNodeMap<ContentHash>,
    observed: &QemuNodeMap<ContentHash>,
) -> Result<(), ProductionFaultRuntimeError> {
    if expected.len() == observed.len()
        && expected
            .iter()
            .all(|(node, fingerprint)| observed.get(node) == Some(fingerprint))
    {
        return Ok(());
    }

    let node = expected
        .keys()
        .chain(observed.keys())
        .find(|node| expected.get(*node) != observed.get(*node))
        .cloned()
        .ok_or(FaultExecutionError::CheckpointPresence)?;
    Err(ProductionFaultRuntimeError::QemuFingerprintMismatch {
        expected: expected
            .get(&node)
            .map_or_else(|| String::from("<missing>"), |hash| (*hash).to_hex()),
        observed: observed
            .get(&node)
            .map_or_else(|| String::from("<missing>"), |hash| (*hash).to_hex()),
        node: node.name,
    })
}
