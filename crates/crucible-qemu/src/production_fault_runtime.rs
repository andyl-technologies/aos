//! Owning production runtime for signal-driven host and QEMU faults.
//!
//! This module keeps the evaluator continuation, canonical adapter ledger,
//! host device state, and live-QEMU transaction routing behind one checkpoint
//! surface. An empty plan has no hidden evaluator and remains a valid inert
//! production configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible::model::{
    BindingActionKind, BindingEvaluation, ContentHash, EffectKind, EffectSpecification,
    FaultAdapterManifests, FaultCapabilityId, FaultCapabilityManifest, FaultCoordinate,
    FaultExecutionError, FaultObjectId, FaultObservation, FaultObservationKind, FaultOpportunity,
    FaultReplayMode, FaultResourceLimitError, FaultResourceLimits, FaultRuntimeCheckpoint,
    FaultSignalPlan, HostFaultActionSink, HostFaultActionState, NodeBootPolicy,
    NodeEffectSpecification, NodeHangScope, NodeLifecycleTransition, NodeStatePolicy,
    NodeWatchdogPolicy, OwnedFaultExecutionRuntime, ReferencedSignalEvent, ResolvedBindingAction,
    ResolvedEffectTrace, SignalArtifactProvider, SignalBoundarySnapshot,
};
use crucible::{BackendError, BackendNetworkOutput, NodeId, SchedulerNetworkCheckpoint};
use crucible_shmem::{DequeuedFaultEvent, FaultEventOutcomeV1};
use sha2::{Digest as _, Sha256};

use crate::{ProductionFaultActionSink, QemuNodeSet};

/// Complete resumable state for the production fault runtime.
#[derive(Clone, Debug)]
pub struct ProductionFaultRuntimeCheckpoint {
    /// Signal evaluator, binding, canonical adapter, replay, and search state.
    runtime: Option<FaultRuntimeCheckpoint>,
    /// Committed host network and storage adapter state.
    host: HostFaultActionState,
    /// Execution fingerprints of the exact QEMU snapshots paired with this state.
    qemu_fingerprints: BTreeMap<NodeId, ContentHash>,
    /// Per-node fault-command continuation paired with the QEMU snapshots.
    qemu_fault_sequences: BTreeMap<NodeId, u64>,
    /// Per-node fault-event continuation paired with the QEMU snapshots.
    qemu_fault_event_sequences: BTreeMap<NodeId, u64>,
    /// Issued QEMU actions needed to authenticate asynchronous occurrence events.
    qemu_issued_actions: BTreeMap<ContentHash, ResolvedBindingAction>,
    /// Issued persistent rules that remain installed in QEMU.
    qemu_active_rule_ids: BTreeSet<ContentHash>,
    /// Scheduler-owned network queues, pending outputs, and transition ledger.
    network_state: Option<ProductionNetworkStateCheckpoint>,
    /// Referenced event occurrences retained for device recovery subscriptions.
    emitted_events: Vec<ReferencedSignalEvent>,
    /// Drained QEMU occurrences awaiting a successfully committed boundary.
    pending_qemu_observations: Vec<FaultObservation>,
    /// Raw drained QEMU events retained until validation succeeds atomically.
    pending_qemu_events: BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    /// Aggregate identity binding every continuation component to the plan.
    identity: ContentHash,
}

/// Complete host/scheduler network continuation paired with QEMU snapshots.
#[derive(Clone, Debug)]
pub struct ProductionNetworkStateCheckpoint {
    identity: ContentHash,
    scheduler: SchedulerNetworkCheckpoint,
    pending_outputs: Vec<BackendNetworkOutput>,
    adapter_state: Vec<u8>,
}

impl ProductionNetworkStateCheckpoint {
    /// Creates a network continuation with its independently recomputable identity.
    #[must_use]
    pub fn new(
        identity: ContentHash,
        scheduler: SchedulerNetworkCheckpoint,
        pending_outputs: Vec<BackendNetworkOutput>,
        adapter_state: Vec<u8>,
    ) -> Self {
        Self {
            identity,
            scheduler,
            pending_outputs,
            adapter_state,
        }
    }

    /// Returns the expected identity of the complete network continuation.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.identity
    }

    /// Consumes the checkpoint into scheduler, pending-frame, and adapter state.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SchedulerNetworkCheckpoint,
        Vec<BackendNetworkOutput>,
        Vec<u8>,
        ContentHash,
    ) {
        (
            self.scheduler,
            self.pending_outputs,
            self.adapter_state,
            self.identity,
        )
    }
}

impl ProductionFaultRuntimeCheckpoint {
    /// Returns the aggregate content identity of this continuation.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.identity
    }

    /// Returns the scheduler and adapter continuation paired with this checkpoint.
    #[must_use]
    pub const fn network_state(&self) -> Option<&ProductionNetworkStateCheckpoint> {
        self.network_state.as_ref()
    }

    /// Returns the captured execution fingerprint for one QEMU node.
    #[must_use]
    pub fn qemu_fingerprint(&self, node: &NodeId) -> Option<ContentHash> {
        self.qemu_fingerprints.get(node).copied()
    }

    /// Returns the next fault-command sequence captured for one QEMU node.
    #[must_use]
    pub fn qemu_fault_sequence(&self, node: &NodeId) -> Option<u64> {
        self.qemu_fault_sequences.get(node).copied()
    }

    /// Returns the next required QEMU fault-event sequence for one node.
    #[must_use]
    pub fn qemu_fault_event_sequence(&self, node: &NodeId) -> Option<u64> {
        self.qemu_fault_event_sequences.get(node).copied()
    }
}

/// Failure to admit, execute, checkpoint, or restore the production runtime.
#[derive(Debug, thiserror::Error)]
pub enum ProductionFaultRuntimeError {
    /// A nonempty plan was admitted without its immutable artifact provider.
    #[error("a nonempty signal fault plan requires an artifact provider")]
    MissingArtifactProvider,
    /// Signal evaluation, capability admission, or adapter execution failed.
    #[error(transparent)]
    Execution(#[from] FaultExecutionError),
    /// A live QEMU node could not provide required state or evidence.
    #[error(transparent)]
    Backend(#[from] BackendError),
    /// Restored live QEMU state differs from the paired fault checkpoint.
    #[error("live QEMU execution fingerprints do not match the fault checkpoint")]
    QemuFingerprintMismatch,
    /// A QEMU occurrence event has not yet entered the authoritative log.
    #[error("cannot checkpoint while QEMU fault events await boundary admission")]
    PendingQemuFaultEvents,
    /// A scenario-owned production resource reservation failed.
    #[error(transparent)]
    ResourceLimit(#[from] FaultResourceLimitError),
}

/// One fully authenticated node lifecycle decision awaiting host application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuNodeLifecycleDecision {
    /// Scheduler node whose exact process generation produced the event.
    pub node: NodeId,
    /// Resolved action identity carried by the QEMU event.
    pub action: ContentHash,
    /// Transition requested by the authored node effect.
    pub requested_transition: NodeLifecycleTransition,
    /// Effective terminal transition after retry or fail-closed resolution.
    pub effective_transition: NodeLifecycleTransition,
    /// Closed terminal cause tag from `CRUCLIF1` version 4.
    pub cause: u32,
    /// Exit status required from this child, or `None` for a live transition.
    pub expected_exit_code: Option<i32>,
    /// QEMU-observed instruction coordinate for the terminal decision.
    pub observed_icount: u64,
    /// Measured pre-exit state digest when QEMU could produce one.
    pub pre_exit_hash: Option<ContentHash>,
    /// Authenticated QEMU event evidence digest.
    pub event_evidence: ContentHash,
}

/// Owning signal runtime coupled to host devices and live patched QEMU.
#[derive(Clone)]
pub struct ProductionFaultRuntime {
    plan_id: ContentHash,
    resource_limits: FaultResourceLimits,
    runtime: Option<OwnedFaultExecutionRuntime>,
    host: HostFaultActionSink,
    restored_network_state: Option<ProductionNetworkStateCheckpoint>,
    emitted_events: Vec<ReferencedSignalEvent>,
    qemu_issued_actions: BTreeMap<ContentHash, ResolvedBindingAction>,
    qemu_active_rule_ids: BTreeSet<ContentHash>,
    pending_qemu_observations: Vec<FaultObservation>,
    pending_qemu_events: BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    pending_node_lifecycle: Vec<QemuNodeLifecycleDecision>,
    pending_node_boot: BTreeSet<NodeId>,
}

impl ProductionFaultRuntime {
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
        nodes: &QemuNodeSet,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        validate_ready_marker_admission(&plan, nodes)?;
        let manifests = production_manifests(nodes)?;
        let plan_id = plan.id();
        let resource_limits = plan.resource_limits();
        let runtime = if plan.programs().is_empty() {
            None
        } else {
            let artifacts =
                artifacts.ok_or(ProductionFaultRuntimeError::MissingArtifactProvider)?;
            Some(OwnedFaultExecutionRuntime::new(
                plan,
                artifacts,
                boundary,
                scenario_seed,
                manifests,
            )?)
        };
        Ok(Self {
            plan_id,
            resource_limits,
            runtime,
            host: HostFaultActionSink::new(resource_limits),
            restored_network_state: None,
            emitted_events: Vec::new(),
            qemu_issued_actions: BTreeMap::new(),
            qemu_active_rule_ids: BTreeSet::new(),
            pending_qemu_observations: Vec::new(),
            pending_qemu_events: BTreeMap::new(),
            pending_node_lifecycle: Vec::new(),
            pending_node_boot: BTreeSet::new(),
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
        nodes: &mut QemuNodeSet,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        validate_ready_marker_admission(&plan, nodes)?;
        let manifests = production_manifests(nodes)?;
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
            &checkpoint.qemu_active_rule_ids,
        )?;
        if checkpoint.identity
            != production_checkpoint_identity(
                plan.id(),
                checkpoint.runtime.as_ref(),
                &checkpoint.host,
                &checkpoint.qemu_fingerprints,
                &checkpoint.qemu_fault_sequences,
                &checkpoint.qemu_fault_event_sequences,
                &checkpoint.qemu_issued_actions,
                &checkpoint.qemu_active_rule_ids,
                checkpoint.network_state.as_ref(),
                &checkpoint.emitted_events,
                &checkpoint.pending_qemu_observations,
                &checkpoint.pending_qemu_events,
            )?
        {
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        if checkpoint.qemu_fingerprints != nodes.execution_fingerprints()? {
            return Err(ProductionFaultRuntimeError::QemuFingerprintMismatch);
        }
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
        nodes.restore_fault_command_sequences(&qemu_fault_sequences)?;
        nodes.restore_fault_event_sequences(&qemu_fault_event_sequences)?;
        Ok(Self {
            plan_id,
            resource_limits,
            runtime,
            host: HostFaultActionSink::from_state(host, resource_limits),
            restored_network_state,
            emitted_events,
            qemu_issued_actions,
            qemu_active_rule_ids,
            pending_qemu_observations,
            pending_qemu_events,
            pending_node_lifecycle: Vec::new(),
            pending_node_boot: BTreeSet::new(),
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

    /// Evaluates one scheduler boundary against host devices and live QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when evaluation, preparation, live
    /// application, evidence validation, or checkpointing fails.
    pub fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        let Some(runtime) = self.runtime.as_ref() else {
            self.drain_qemu_observations(nodes, coordinate)?;
            if self.pending_qemu_observations.is_empty() {
                return Ok(BindingEvaluation::default());
            }
            return Err(BackendError::Rejected {
                message: String::from("QEMU produced fault events for an inert fault plan"),
            }
            .into());
        };
        let preview = runtime.preview_boundary(coordinate, same_coordinate_sequence)?;
        self.drain_qemu_observations(nodes, coordinate)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let mut sink = ProductionFaultActionSink::new(&mut self.host, nodes);
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let mut evaluation = match runtime.evaluate_boundary_with_backend(
            coordinate,
            same_coordinate_sequence,
            &mut sink,
        ) {
            Ok(evaluation) => evaluation,
            Err(error) => return Err(error.into()),
        };
        if evaluation.emitted_events != preview.emitted_events
            || evaluation.state_machine_events != preview.state_machine_events
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        if let Err(error) = self.update_qemu_action_ledger(&evaluation.actions) {
            if let Some(runtime) = &mut self.runtime {
                runtime.poison();
            }
            return Err(error);
        }
        // QEMU publishes typed occurrence evidence while committing a command.
        // Drain again only after the issued-action ledger is committed so a
        // one-shot lifecycle action and a persistent-rule removal can both be
        // authenticated at the boundary that caused them. Delaying this until
        // the next scheduler boundary would also lose terminal evidence when
        // the command intentionally exits the child.
        if let Err(error) = self.drain_qemu_observations(nodes, coordinate) {
            if let Some(runtime) = &mut self.runtime {
                runtime.poison();
            }
            return Err(error);
        }
        let mut qemu_observations = std::mem::take(&mut self.pending_qemu_observations);
        qemu_observations.append(&mut evaluation.observations);
        evaluation.observations = qemu_observations;
        self.emitted_events
            .extend(evaluation.emitted_events.iter().cloned());
        self.pending_node_boot
            .extend(node_boot_requests(&evaluation.actions)?);
        Ok(evaluation)
    }

    fn drain_qemu_observations(
        &mut self,
        nodes: &mut QemuNodeSet,
        boundary: FaultCoordinate,
    ) -> Result<(), ProductionFaultRuntimeError> {
        let mut drained = BTreeMap::new();
        let drain_result = nodes.drain_fault_events(&mut drained);
        for (node, mut events) in drained {
            if !events.is_empty() {
                self.pending_qemu_events
                    .entry(node)
                    .or_default()
                    .append(&mut events);
            }
        }
        drain_result?;
        validate_production_event_state(
            &self.emitted_events,
            &[],
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        validate_pending_qemu_event_sequences(
            &self.pending_qemu_events,
            &nodes.fault_event_sequences(),
        )?;
        let mut observations = Vec::new();
        let mut lifecycle_decisions = BTreeMap::new();
        for (node, events) in &self.pending_qemu_events {
            for event in events {
                let action_identity = ContentHash {
                    bytes: event.header.action_hash,
                };
                let action = self
                    .qemu_issued_actions
                    .get(&action_identity)
                    .ok_or_else(|| BackendError::Rejected {
                        message: format!(
                            "QEMU fault event {} names an action that was not issued {}",
                            event.header.event_sequence,
                            action_identity.to_hex()
                        ),
                    })?;
                let binding_hash = ContentHash::from_canonical_material(
                    "crucible.fault-binding.v1",
                    action.binding.as_str(),
                );
                let target_hash = ContentHash::from_canonical_material(
                    "crucible.resolved-fault-target.v1",
                    &action.target.canonical_material(),
                );
                if event.header.binding_hash != binding_hash.bytes
                    || event.header.target_hash != target_hash.bytes
                    || event.header.generation != action.transition_sequence
                    || boundary
                        .retired_instructions
                        .is_none_or(|retired| event.header.observed_icount > retired)
                {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "QEMU fault event {} does not match its active rule",
                            event.header.event_sequence
                        ),
                    }
                    .into());
                }
                validate_node_event_evidence(event, action)?;
                if let Some(decision) = node_lifecycle_decision(node, action_identity, event)
                    && lifecycle_decisions.insert(node.clone(), decision).is_some()
                {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "QEMU node `{}` produced more than one lifecycle decision in one boundary",
                            node.name
                        ),
                    }
                    .into());
                }
                let opportunity =
                    (event.header.opportunity_hash != [0; 32]).then_some(ContentHash {
                        bytes: event.header.opportunity_hash,
                    });
                let mut evidence = Vec::new();
                evidence.extend_from_slice(&(event.header.command_kind as u16).to_be_bytes());
                evidence.extend_from_slice(&(event.header.outcome as u16).to_be_bytes());
                evidence.extend_from_slice(&event.header.event_sequence.to_be_bytes());
                evidence.extend_from_slice(&event.header.rule_command_sequence.to_be_bytes());
                evidence.extend_from_slice(&event.header.observed_icount.to_be_bytes());
                evidence.extend_from_slice(&event.header.generation.to_be_bytes());
                evidence.extend_from_slice(&event.header.before_hash);
                evidence.extend_from_slice(&event.header.after_hash);
                evidence.extend_from_slice(&event.header.evidence_hash);
                evidence.extend_from_slice(&event.payload);
                observations.push(FaultObservation {
                    semantic_version: crucible::model::FAULT_RUNTIME_STATE_VERSION,
                    kind: if event.header.outcome == crucible_shmem::FaultEventOutcomeV1::Passed {
                        FaultObservationKind::FaultOpportunity
                    } else {
                        FaultObservationKind::EffectApplied
                    },
                    coordinate: FaultCoordinate {
                        virtual_nanos: boundary.virtual_nanos,
                        retired_instructions: Some(event.header.observed_icount),
                    },
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity,
                    evidence: ContentHash::from_bytes(&evidence),
                });
            }
        }
        validate_production_event_state(
            &self.emitted_events,
            &[],
            &self.pending_qemu_observations,
            &observations,
            &BTreeMap::new(),
            self.resource_limits,
        )?;
        self.pending_node_lifecycle
            .extend(lifecycle_decisions.into_values());
        self.pending_qemu_observations.extend(observations);
        self.pending_qemu_events.clear();
        Ok(())
    }

    fn update_qemu_action_ledger(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<(), ProductionFaultRuntimeError> {
        for action in actions
            .iter()
            .filter(|action| matches!(action.effect.specification(), EffectSpecification::Node(_)))
        {
            match action.kind {
                BindingActionKind::UpsertPersistent | BindingActionKind::Apply => {
                    let identity = action.id();
                    let retained = u64::try_from(self.qemu_issued_actions.len()).map_err(|_| {
                        FaultResourceLimitError::Representation {
                            field: "event_records",
                            value: u64::MAX,
                        }
                    })?;
                    self.resource_limits.reserve("event_records", retained, 1)?;
                    if self
                        .qemu_issued_actions
                        .insert(identity, action.clone())
                        .is_some()
                    {
                        return Err(BackendError::Rejected {
                            message: format!(
                                "QEMU action identity {} was issued more than once",
                                identity.to_hex()
                            ),
                        }
                        .into());
                    }
                    if action.kind == BindingActionKind::UpsertPersistent {
                        self.qemu_active_rule_ids.retain(|active_id| {
                            self.qemu_issued_actions
                                .get(active_id)
                                .is_none_or(|active| {
                                    active.binding != action.binding
                                        || active.target != action.target
                                        || active.phase != action.phase
                                })
                        });
                        self.qemu_active_rule_ids.insert(identity);
                    }
                }
                BindingActionKind::RemovePersistent => {
                    let prior_len = self.qemu_active_rule_ids.len();
                    self.qemu_active_rule_ids.retain(|active_id| {
                        self.qemu_issued_actions
                            .get(active_id)
                            .is_none_or(|active| {
                                active.binding != action.binding
                                    || active.target != action.target
                                    || active.phase != action.phase
                            })
                    });
                    if self.qemu_active_rule_ids.len() == prior_len {
                        return Err(BackendError::Rejected {
                            message: format!(
                                "QEMU removed an unissued persistent rule for binding `{}`",
                                action.binding.as_str()
                            ),
                        }
                        .into());
                    }
                }
            }
        }
        Ok(())
    }

    /// Evaluates one exact device or architectural opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same transaction and evidence
    /// rules as [`Self::evaluate_boundary`].
    pub fn evaluate_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(BindingEvaluation::default());
        };
        let preview = runtime.preview_opportunity(opportunity, same_coordinate_sequence)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let mut sink = ProductionFaultActionSink::new(&mut self.host, nodes);
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let evaluation = runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut sink,
        )?;
        if evaluation.emitted_events != preview.emitted_events
            || evaluation.state_machine_events != preview.state_machine_events
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        self.emitted_events
            .extend(evaluation.emitted_events.iter().cloned());
        Ok(evaluation)
    }

    /// Evaluates one host-device opportunity without borrowing the live node set.
    ///
    /// Storage and 9p opportunities can arise while a node's host-I/O runtime is
    /// itself inside `advance_to_ceiling`, so re-borrowing that node set would be
    /// impossible and semantically unnecessary. Opportunity targeting guarantees
    /// that only host-adapter actions can match; a node action is rejected by the
    /// host sink and poisons the same authoritative continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when evaluation, transactional host
    /// application, evidence validation, or checkpointing fails.
    pub fn evaluate_host_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(BindingEvaluation::default());
        };
        let preview = runtime.preview_opportunity(opportunity, same_coordinate_sequence)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let evaluation = runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut self.host,
        )?;
        if evaluation.emitted_events != preview.emitted_events
            || evaluation.state_machine_events != preview.state_machine_events
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        self.emitted_events
            .extend(evaluation.emitted_events.iter().cloned());
        Ok(evaluation)
    }

    /// Replaces the one-boundary-delayed telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the snapshot is invalid or the
    /// current continuation cannot be authenticated and checkpointed.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), ProductionFaultRuntimeError> {
        if let Some(runtime) = &mut self.runtime {
            runtime.set_boundary_snapshot(boundary)?;
        }
        Ok(())
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
        let qemu_fingerprints = nodes.execution_fingerprints()?;
        let qemu_fault_sequences = nodes.fault_command_sequences();
        let qemu_fault_event_sequences = nodes.fault_event_sequences();
        validate_pending_qemu_event_sequences(
            &self.pending_qemu_events,
            &qemu_fault_event_sequences,
        )?;
        let identity = production_checkpoint_identity(
            self.plan_id,
            runtime.as_ref(),
            &host,
            &qemu_fingerprints,
            &qemu_fault_sequences,
            &qemu_fault_event_sequences,
            &self.qemu_issued_actions,
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
            qemu_issued_actions: self.qemu_issued_actions.clone(),
            qemu_active_rule_ids: self.qemu_active_rule_ids.clone(),
            network_state: self.restored_network_state.clone(),
            emitted_events: self.emitted_events.clone(),
            pending_qemu_observations: self.pending_qemu_observations.clone(),
            pending_qemu_events: self.pending_qemu_events.clone(),
            identity,
        })
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
            checkpoint.runtime.as_ref(),
            &checkpoint.host,
            &checkpoint.qemu_fingerprints,
            &checkpoint.qemu_fault_sequences,
            &checkpoint.qemu_fault_event_sequences,
            &checkpoint.qemu_issued_actions,
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

const LIFECYCLE_EVIDENCE_BYTES: usize = 304;
const HANG_EVIDENCE_BYTES: usize = 192;
const LIFECYCLE_TERMINAL_CAUSE_NONE: u32 = 0;
const LIFECYCLE_TERMINAL_CAUSE_DIRECT: u32 = 1;
const LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED: u32 = 2;
const LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED: u32 = 3;
const LIFECYCLE_TERMINAL_PRE_EXIT_VALID: u32 = 1 << 0;
const LIFECYCLE_TERMINAL_EXIT_REQUIRED: u32 = 1 << 1;
const LIFECYCLE_TERMINAL_KNOWN_FLAGS: u32 =
    LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED;

fn validate_node_event_evidence(
    event: &DequeuedFaultEvent,
    action: &ResolvedBindingAction,
) -> Result<(), ProductionFaultRuntimeError> {
    let EffectSpecification::Node(effect) = action.effect.specification() else {
        return Ok(());
    };
    let valid = match event.header.command_kind {
        crucible_shmem::FaultCommandKind::NodeLifecycle => {
            validate_lifecycle_evidence(event, effect)
        }
        crucible_shmem::FaultCommandKind::NodeHang
            if event.payload.get(0..8) == Some(b"CRUCLIF1") =>
        {
            validate_lifecycle_evidence(event, effect)
        }
        crucible_shmem::FaultCommandKind::NodeHang => validate_hang_evidence(event, effect),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(BackendError::Rejected {
            message: format!(
                "QEMU fault event {} contains malformed or inconsistent typed evidence",
                event.header.event_sequence
            ),
        }
        .into())
    }
}

fn node_lifecycle_decision(
    node: &NodeId,
    action_identity: ContentHash,
    event: &DequeuedFaultEvent,
) -> Option<QemuNodeLifecycleDecision> {
    if event.payload.get(0..8) != Some(b"CRUCLIF1") {
        return None;
    }
    let requested_transition =
        lifecycle_transition_from_tag(u32::from(read_u16(&event.payload, 10)?))?;
    let effective_transition = lifecycle_transition_from_tag(read_u32(&event.payload, 288)?)?;
    let flags = read_u32(&event.payload, 296)?;
    let expected_exit_code = if flags & LIFECYCLE_TERMINAL_EXIT_REQUIRED != 0 {
        Some(match effective_transition {
            NodeLifecycleTransition::Crash => 70,
            NodeLifecycleTransition::PowerOff => 71,
            NodeLifecycleTransition::PermanentFailure => 72,
            _ => return None,
        })
    } else {
        None
    };
    let pre_exit_hash = if flags & 1 != 0 {
        Some(ContentHash {
            bytes: event.payload[256..288].try_into().ok()?,
        })
    } else {
        None
    };
    Some(QemuNodeLifecycleDecision {
        node: node.clone(),
        action: action_identity,
        requested_transition,
        effective_transition,
        cause: read_u32(&event.payload, 292)?,
        expected_exit_code,
        observed_icount: event.header.observed_icount,
        pre_exit_hash,
        event_evidence: ContentHash {
            bytes: event.header.evidence_hash,
        },
    })
}

fn node_boot_requests(
    actions: &[ResolvedBindingAction],
) -> Result<BTreeSet<NodeId>, ProductionFaultRuntimeError> {
    let mut nodes = BTreeSet::new();
    for action in actions {
        let EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Boot,
            ..
        }) = action.effect.specification()
        else {
            continue;
        };
        let crucible::model::ResolvedFaultTarget::Node { node } = &action.target else {
            return Err(BackendError::Rejected {
                message: format!(
                    "boot lifecycle action `{}` resolved to a non-node target",
                    action.binding
                ),
            }
            .into());
        };
        nodes.insert(NodeId {
            name: node.as_str().to_owned(),
        });
    }
    Ok(nodes)
}

const fn lifecycle_transition_from_tag(tag: u32) -> Option<NodeLifecycleTransition> {
    match tag {
        1 => Some(NodeLifecycleTransition::Boot),
        2 => Some(NodeLifecycleTransition::Crash),
        3 => Some(NodeLifecycleTransition::Reset),
        4 => Some(NodeLifecycleTransition::PowerOff),
        5 => Some(NodeLifecycleTransition::PowerCycle),
        6 => Some(NodeLifecycleTransition::PermanentFailure),
        _ => None,
    }
}

fn validate_lifecycle_evidence(
    event: &DequeuedFaultEvent,
    effect: &NodeEffectSpecification,
) -> bool {
    let bytes = event.payload.as_slice();
    if bytes.len() != LIFECYCLE_EVIDENCE_BYTES
        || bytes.get(0..8) != Some(b"CRUCLIF1")
        || read_u16(bytes, 8) != Some(4)
        || !matches!(
            event.header.outcome,
            FaultEventOutcomeV1::Applied | FaultEventOutcomeV1::Error
        )
        || read_u64(bytes, 24) != Some(event.header.observed_icount)
        || bytes.get(64..96) != Some(event.header.binding_hash.as_slice())
        || bytes.get(128..160) != Some(event.header.before_hash.as_slice())
        || bytes.get(160..192) != Some(event.header.after_hash.as_slice())
    {
        return false;
    }
    let Some(transition) = read_u16(bytes, 10) else {
        return false;
    };
    let Some(volatile_policy) = read_u32(bytes, 12) else {
        return false;
    };
    let Some(device_policy) = read_u32(bytes, 16) else {
        return false;
    };
    let Some(preserved_domains) = read_u32(bytes, 20) else {
        return false;
    };
    let Some(virtual_before) = read_u64(bytes, 32) else {
        return false;
    };
    let Some(downtime) = read_u64(bytes, 40) else {
        return false;
    };
    let Some(virtual_after) = read_u64(bytes, 96) else {
        return false;
    };
    if !(1..=6).contains(&transition)
        || !(1..=2).contains(&volatile_policy)
        || !(1..=3).contains(&device_policy)
        || preserved_domains
            != u32::from(volatile_policy == 1) | (u32::from(device_policy == 1) << 1)
        || virtual_before.checked_add(downtime) != Some(virtual_after)
        || read_u64(bytes, 48).is_none_or(|value| value == 0)
        || read_u64(bytes, 56).is_none_or(|value| value == 0)
    {
        return false;
    }
    let Some(effective_transition) = read_u32(bytes, 288) else {
        return false;
    };
    let Some(terminal_cause) = read_u32(bytes, 292) else {
        return false;
    };
    let Some(terminal_flags) = read_u32(bytes, 296) else {
        return false;
    };
    if !(1..=6).contains(&effective_transition)
        || terminal_flags & !LIFECYCLE_TERMINAL_KNOWN_FLAGS != 0
        || bytes.get(300..304) != Some([0_u8; 4].as_slice())
        || !validate_lifecycle_terminal_shape(
            event,
            bytes,
            transition,
            effective_transition,
            terminal_cause,
            terminal_flags,
        )
    {
        return false;
    }
    match effect {
        NodeEffectSpecification::Lifecycle {
            transition: expected_transition,
            downtime_nanos,
            boot_policy,
            volatile_state_policy,
            device_state_policy,
        } => {
            let boot_is_valid = validate_boot_evidence(bytes, boot_policy);
            transition == lifecycle_tag(*expected_transition)
                && downtime == *downtime_nanos
                && volatile_policy == state_policy_tag(*volatile_state_policy)
                && device_policy == state_policy_tag(*device_state_policy)
                && boot_is_valid
                && validate_lifecycle_terminal_policy(
                    boot_policy,
                    effective_transition,
                    terminal_cause,
                )
        }
        NodeEffectSpecification::Hang {
            watchdog_policy: NodeWatchdogPolicy::TransitionAfter { boot_policy, .. },
            ..
        } => {
            validate_boot_evidence_shape(bytes)
                && validate_lifecycle_terminal_policy(
                    boot_policy,
                    effective_transition,
                    terminal_cause,
                )
        }
        _ => false,
    }
}

fn validate_lifecycle_terminal_shape(
    event: &DequeuedFaultEvent,
    bytes: &[u8],
    requested_transition: u16,
    effective_transition: u32,
    cause: u32,
    flags: u32,
) -> bool {
    let pre_exit = bytes.get(256..288);
    let pre_exit_valid = flags & LIFECYCLE_TERMINAL_PRE_EXIT_VALID != 0;
    let exit_required = flags & LIFECYCLE_TERMINAL_EXIT_REQUIRED != 0;
    let effective_is_terminal = matches!(effective_transition, 2 | 4 | 6);
    let digest_is_valid = pre_exit_valid
        && pre_exit.is_some_and(|hash| {
            let mut material = [0_u8; 48];
            material[0..8].copy_from_slice(b"CRUCTRM1");
            material[8..12].copy_from_slice(&effective_transition.to_le_bytes());
            material[16..48].copy_from_slice(hash);
            let derived: [u8; 32] = Sha256::digest(material).into();
            hash != [0_u8; 32] && derived == event.header.after_hash
        });

    match cause {
        LIFECYCLE_TERMINAL_CAUSE_NONE => {
            event.header.outcome == FaultEventOutcomeV1::Applied
                && effective_transition == u32::from(requested_transition)
                && flags == 0
                && pre_exit == Some([0_u8; 32].as_slice())
                && lifecycle_after_counts_are_nonzero(bytes)
        }
        LIFECYCLE_TERMINAL_CAUSE_DIRECT => {
            event.header.outcome == FaultEventOutcomeV1::Applied
                && matches!(requested_transition, 2 | 4 | 6)
                && effective_transition == u32::from(requested_transition)
                && flags == LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED
                && digest_is_valid
                && lifecycle_after_counts_are_nonzero(bytes)
        }
        LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED => {
            event.header.outcome == FaultEventOutcomeV1::Applied
                && effective_is_terminal
                && flags == LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED
                && digest_is_valid
                && lifecycle_after_counts_are_nonzero(bytes)
        }
        LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED => {
            event.header.outcome == FaultEventOutcomeV1::Error
                && effective_transition
                    == u32::from(lifecycle_tag(NodeLifecycleTransition::PermanentFailure))
                && exit_required
                && if pre_exit_valid {
                    digest_is_valid && lifecycle_after_counts_are_nonzero(bytes)
                } else {
                    pre_exit == Some([0_u8; 32].as_slice())
                        && event.header.after_hash == event.header.before_hash
                        && read_u64(bytes, 112) == Some(0)
                        && read_u64(bytes, 120) == Some(0)
                }
        }
        _ => false,
    }
}

fn lifecycle_after_counts_are_nonzero(bytes: &[u8]) -> bool {
    read_u64(bytes, 112).is_some_and(|value| value > 0)
        && read_u64(bytes, 120).is_some_and(|value| value > 0)
}

fn validate_lifecycle_terminal_policy(
    boot_policy: &NodeBootPolicy,
    effective_transition: u32,
    cause: u32,
) -> bool {
    match cause {
        LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED => matches!(
            boot_policy,
            NodeBootPolicy::RequireReady { exhausted, .. }
                if effective_transition == u32::from(lifecycle_tag(*exhausted))
        ),
        LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED => {
            matches!(
                boot_policy,
                NodeBootPolicy::RequireReady { .. } | NodeBootPolicy::Immediate
            )
        }
        _ => true,
    }
}

fn validate_boot_evidence(bytes: &[u8], policy: &NodeBootPolicy) -> bool {
    match policy {
        NodeBootPolicy::Immediate => {
            read_u32(bytes, 192) == Some(1)
                && read_u32(bytes, 196) == Some(1)
                && read_u32(bytes, 200) == Some(1)
                && read_u32(bytes, 204) == Some(0)
                && read_u64(bytes, 208) == Some(0)
                && read_u64(bytes, 216) == Some(u64::MAX)
                && bytes.get(224..256) == Some([0_u8; 32].as_slice())
        }
        NodeBootPolicy::RequireReady {
            ready_marker,
            maximum_attempts,
            retry_delay_nanos,
            exhausted,
        } => {
            let marker_hash: [u8; 32] = Sha256::digest(ready_marker.as_str().as_bytes()).into();
            read_u32(bytes, 192) == Some(2)
                && read_u32(bytes, 196)
                    .is_some_and(|attempt| attempt > 0 && attempt <= maximum_attempts.get())
                && read_u32(bytes, 200) == Some(maximum_attempts.get())
                && read_u32(bytes, 204) == Some(u32::from(lifecycle_tag(*exhausted)))
                && read_u64(bytes, 208) == Some(*retry_delay_nanos)
                && read_u64(bytes, 216).is_some_and(|deadline| deadline != u64::MAX)
                && bytes.get(224..256) == Some(marker_hash.as_slice())
        }
    }
}

fn validate_boot_evidence_shape(bytes: &[u8]) -> bool {
    match read_u32(bytes, 192) {
        Some(1) => {
            read_u32(bytes, 196) == Some(1)
                && read_u32(bytes, 200) == Some(1)
                && read_u32(bytes, 204) == Some(0)
                && read_u64(bytes, 208) == Some(0)
                && read_u64(bytes, 216) == Some(u64::MAX)
                && bytes.get(224..256) == Some([0_u8; 32].as_slice())
        }
        Some(2) => {
            read_u32(bytes, 196).is_some_and(|attempt| attempt > 0)
                && read_u32(bytes, 200).is_some_and(|maximum| maximum > 0)
                && read_u32(bytes, 196) <= read_u32(bytes, 200)
                && read_u32(bytes, 204).is_some_and(|transition| (2..=6).contains(&transition))
                && read_u64(bytes, 216).is_some_and(|deadline| deadline != u64::MAX)
                && bytes.get(224..256).is_some_and(|hash| hash != [0_u8; 32])
        }
        _ => false,
    }
}

fn validate_hang_evidence(event: &DequeuedFaultEvent, effect: &NodeEffectSpecification) -> bool {
    let NodeEffectSpecification::Hang {
        scope,
        watchdog_policy,
        ..
    } = effect
    else {
        return false;
    };
    let bytes = event.payload.as_slice();
    if bytes.len() != HANG_EVIDENCE_BYTES || event.header.outcome != FaultEventOutcomeV1::Applied {
        return false;
    }
    match bytes.get(0..8) {
        Some(b"CRUCHNG1") => {
            read_u16(bytes, 8) == Some(1)
                && read_u16(bytes, 10).is_some_and(|kind| kind == 1 || kind == 2)
                && read_u32(bytes, 12) == Some(hang_scope_tag(scope))
                && read_u64(bytes, 56) == Some(event.header.observed_icount)
                && read_u64(bytes, 48) == Some(event.header.generation)
                && bytes.get(64..96) == Some(event.header.binding_hash.as_slice())
                && bytes.get(96..128) == Some(event.header.action_hash.as_slice())
                && bytes.get(128..160) == Some(event.header.before_hash.as_slice())
                && bytes.get(160..192) == Some(event.header.after_hash.as_slice())
        }
        Some(b"CRUCWDC1") => {
            let NodeWatchdogPolicy::TransitionAfter {
                transition,
                downtime_nanos,
                volatile_state_policy,
                device_state_policy,
                ..
            } = watchdog_policy
            else {
                return false;
            };
            read_u16(bytes, 8) == Some(1)
                && read_u16(bytes, 10) == Some(lifecycle_tag(*transition))
                && read_u16(bytes, 12).is_some_and(|value| (1..=6).contains(&value))
                && read_u32(bytes, 16) == Some(state_policy_tag(*volatile_state_policy))
                && read_u32(bytes, 20) == Some(state_policy_tag(*device_state_policy))
                && read_u32(bytes, 24).is_some_and(|value| (1..=2).contains(&value))
                && read_u32(bytes, 28).is_some_and(|value| (1..=3).contains(&value))
                && read_u64(bytes, 32) == Some(*downtime_nanos)
                && read_u64(bytes, 48) == read_u64(bytes, 56)
                && bytes.get(64..96) == Some(event.header.binding_hash.as_slice())
                && bytes.get(128..160) == Some(event.header.action_hash.as_slice())
                && bytes.get(96..128).is_some_and(|hash| hash != [0_u8; 32])
                && bytes.get(160..192).is_some_and(|hash| hash != [0_u8; 32])
        }
        _ => false,
    }
}

const fn lifecycle_tag(value: NodeLifecycleTransition) -> u16 {
    match value {
        NodeLifecycleTransition::Boot => 1,
        NodeLifecycleTransition::Crash => 2,
        NodeLifecycleTransition::Reset => 3,
        NodeLifecycleTransition::PowerOff => 4,
        NodeLifecycleTransition::PowerCycle => 5,
        NodeLifecycleTransition::PermanentFailure => 6,
    }
}

const fn state_policy_tag(value: NodeStatePolicy) -> u32 {
    match value {
        NodeStatePolicy::Preserve => 1,
        NodeStatePolicy::Clear => 2,
        NodeStatePolicy::DeviceReset => 3,
    }
}

const fn hang_scope_tag(value: &NodeHangScope) -> u32 {
    match value {
        NodeHangScope::Node => 1,
        NodeHangScope::Vcpus(_) => 2,
        NodeHangScope::Device(_) => 3,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn validate_production_event_state(
    emitted_events: &[ReferencedSignalEvent],
    additional_emitted_events: &[ReferencedSignalEvent],
    pending_observations: &[FaultObservation],
    additional_observations: &[FaultObservation],
    pending_qemu_events: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    resource_limits: FaultResourceLimits,
) -> Result<(), ProductionFaultRuntimeError> {
    let (records, bytes) = extend_referenced_event_usage(emitted_events, resource_limits, 0, 0)?;
    let (records, bytes) =
        extend_referenced_event_usage(additional_emitted_events, resource_limits, records, bytes)?;
    let (records, bytes) =
        extend_observation_usage(pending_observations, resource_limits, records, bytes)?;
    let (records, bytes) =
        extend_observation_usage(additional_observations, resource_limits, records, bytes)?;
    let _ = extend_pending_qemu_event_usage(pending_qemu_events, resource_limits, records, bytes)?;
    Ok(())
}

fn validate_pending_qemu_event_sequences(
    pending_qemu_events: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    next_sequences: &BTreeMap<NodeId, u64>,
) -> Result<(), ProductionFaultRuntimeError> {
    for (node, events) in pending_qemu_events {
        let Some(first) = events.first() else {
            continue;
        };
        let next_sequence = next_sequences
            .get(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "pending QEMU fault events name unknown node `{}`",
                    node.name
                ),
            })?;
        if first.header.event_sequence == 0 {
            return Err(BackendError::Rejected {
                message: format!(
                    "pending QEMU fault events for `{}` begin with sequence zero",
                    node.name
                ),
            }
            .into());
        }
        for pair in events.windows(2) {
            let expected = pair[0]
                .header
                .event_sequence
                .checked_add(1)
                .ok_or_else(|| BackendError::Rejected {
                    message: format!(
                        "pending QEMU fault-event sequence for `{}` is exhausted",
                        node.name
                    ),
                })?;
            if pair[1].header.event_sequence != expected {
                return Err(BackendError::Rejected {
                    message: format!(
                        "pending QEMU fault events for `{}` are not contiguous: expected {}, observed {}",
                        node.name, expected, pair[1].header.event_sequence
                    ),
                }
                .into());
            }
        }
        let observed_next = events
            .last()
            .and_then(|event| event.header.event_sequence.checked_add(1))
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "pending QEMU fault-event sequence for `{}` is exhausted",
                    node.name
                ),
            })?;
        if observed_next != *next_sequence {
            return Err(BackendError::Rejected {
                message: format!(
                    "pending QEMU fault events for `{}` end before sequence {}, but the live continuation requires {}",
                    node.name, observed_next, next_sequence
                ),
            }
            .into());
        }
    }
    Ok(())
}

fn extend_referenced_event_usage(
    events: &[ReferencedSignalEvent],
    resource_limits: FaultResourceLimits,
    mut records: u64,
    mut total_bytes: u64,
) -> Result<(u64, u64), ProductionFaultRuntimeError> {
    for event in events {
        let (evidence, bytes) = event
            .canonical_value_identity()
            .map_err(FaultExecutionError::from)?;
        if evidence != event.evidence {
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        resource_limits.reserve("event_records", records, 1)?;
        records += 1;
        let value_bytes =
            u64::try_from(bytes).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_inline_payload_bytes",
                value: u64::MAX,
            })?;
        resource_limits.reserve("event_inline_payload_bytes", 0, value_bytes)?;
        let signal_bytes = u64::try_from(event.signal.as_str().len()).map_err(|_| {
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            }
        })?;
        let record_bytes = signal_bytes
            .checked_add(value_bytes)
            .and_then(|value| value.checked_add(81))
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            })?;
        resource_limits.reserve("event_log_bytes", total_bytes, record_bytes)?;
        total_bytes += record_bytes;
    }
    Ok((records, total_bytes))
}

fn extend_observation_usage(
    observations: &[FaultObservation],
    resource_limits: FaultResourceLimits,
    mut records: u64,
    mut total_bytes: u64,
) -> Result<(u64, u64), ProductionFaultRuntimeError> {
    for observation in observations {
        let material = observation_identity_material(observation)?;
        resource_limits.reserve("event_records", records, 1)?;
        records = records
            .checked_add(1)
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            })?;
        let record_bytes =
            u64::try_from(material.len()).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            })?;
        resource_limits.reserve("event_log_bytes", total_bytes, record_bytes)?;
        total_bytes = total_bytes.checked_add(record_bytes).ok_or(
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            },
        )?;
    }
    Ok((records, total_bytes))
}

fn extend_pending_qemu_event_usage(
    events_by_node: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    resource_limits: FaultResourceLimits,
    mut records: u64,
    mut total_bytes: u64,
) -> Result<(u64, u64), ProductionFaultRuntimeError> {
    for events in events_by_node.values() {
        for event in events {
            resource_limits.reserve("event_records", records, 1)?;
            records = records
                .checked_add(1)
                .ok_or(FaultResourceLimitError::Representation {
                    field: "event_records",
                    value: u64::MAX,
                })?;
            let payload_bytes = u64::try_from(event.payload.len()).map_err(|_| {
                FaultResourceLimitError::Representation {
                    field: "event_inline_payload_bytes",
                    value: u64::MAX,
                }
            })?;
            resource_limits.reserve("event_inline_payload_bytes", 0, payload_bytes)?;
            let header_bytes =
                u64::try_from(crucible_shmem::FAULT_EVENT_HEADER_V1_BYTES).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "event_log_bytes",
                        value: u64::MAX,
                    }
                })?;
            let record_bytes = payload_bytes.checked_add(header_bytes).ok_or(
                FaultResourceLimitError::Representation {
                    field: "event_log_bytes",
                    value: u64::MAX,
                },
            )?;
            resource_limits.reserve("event_log_bytes", total_bytes, record_bytes)?;
            total_bytes = total_bytes.checked_add(record_bytes).ok_or(
                FaultResourceLimitError::Representation {
                    field: "event_log_bytes",
                    value: u64::MAX,
                },
            )?;
        }
    }
    Ok((records, total_bytes))
}

fn observation_identity_material(
    observation: &FaultObservation,
) -> Result<Vec<u8>, ProductionFaultRuntimeError> {
    if observation.semantic_version != crucible::model::FAULT_RUNTIME_STATE_VERSION
        || observation.evidence == ContentHash::default()
        || !matches!(
            observation.kind,
            FaultObservationKind::FaultOpportunity | FaultObservationKind::EffectApplied
        )
        || observation.binding.is_none()
        || observation.target.is_none()
        || observation
            .target
            .as_ref()
            .is_some_and(|target| target.validate().is_err())
    {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    let mut material = Vec::new();
    material.extend_from_slice(&observation.semantic_version.to_be_bytes());
    append_length_prefixed(&mut material, observation.kind.as_str().as_bytes())?;
    material.extend_from_slice(&observation.coordinate.virtual_nanos.to_be_bytes());
    match observation.coordinate.retired_instructions {
        Some(retired) => {
            material.push(1);
            material.extend_from_slice(&retired.to_be_bytes());
        }
        None => material.push(0),
    }
    match &observation.binding {
        Some(binding) => {
            material.push(1);
            append_length_prefixed(&mut material, binding.as_str().as_bytes())?;
        }
        None => material.push(0),
    }
    match &observation.target {
        Some(target) => {
            material.push(1);
            append_length_prefixed(&mut material, target.canonical_material().as_bytes())?;
        }
        None => material.push(0),
    }
    match observation.opportunity {
        Some(opportunity) => {
            material.push(1);
            material.extend_from_slice(&opportunity.bytes);
        }
        None => material.push(0),
    }
    material.extend_from_slice(&observation.evidence.bytes);
    Ok(material)
}

fn append_length_prefixed(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), ProductionFaultRuntimeError> {
    let length =
        u64::try_from(value.len()).map_err(|_| FaultResourceLimitError::Representation {
            field: "event_log_bytes",
            value: u64::MAX,
        })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn production_checkpoint_identity(
    plan: ContentHash,
    runtime: Option<&FaultRuntimeCheckpoint>,
    host: &HostFaultActionState,
    qemu_fingerprints: &BTreeMap<NodeId, ContentHash>,
    qemu_fault_sequences: &BTreeMap<NodeId, u64>,
    qemu_fault_event_sequences: &BTreeMap<NodeId, u64>,
    qemu_issued_actions: &BTreeMap<ContentHash, ResolvedBindingAction>,
    qemu_active_rule_ids: &BTreeSet<ContentHash>,
    network_state: Option<&ProductionNetworkStateCheckpoint>,
    emitted_events: &[ReferencedSignalEvent],
    pending_qemu_observations: &[FaultObservation],
    pending_qemu_events: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
) -> Result<ContentHash, ProductionFaultRuntimeError> {
    let mut material = Vec::new();
    material.extend_from_slice(&plan.bytes);
    material.extend_from_slice(&host.digest().bytes);
    match network_state {
        Some(network_state) => {
            material.push(1);
            material.extend_from_slice(&network_state.id().bytes);
        }
        None => material.push(0),
    }
    if let Some(runtime) = runtime {
        material.extend_from_slice(
            &runtime
                .content_id()
                .map_err(FaultExecutionError::from)?
                .bytes,
        );
    }
    for event in emitted_events {
        material.extend_from_slice(event.signal.as_str().as_bytes());
        material.push(0);
        material.extend_from_slice(&event.coordinate.virtual_nanos.to_be_bytes());
        material.extend_from_slice(
            &event
                .coordinate
                .retired_instructions
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        material.extend_from_slice(&event.same_coordinate_sequence.to_be_bytes());
        material.extend_from_slice(&event.evidence.bytes);
    }
    for observation in pending_qemu_observations {
        append_length_prefixed(&mut material, &observation_identity_material(observation)?)?;
    }
    for (node, events) in pending_qemu_events {
        material.extend_from_slice(node.name.as_bytes());
        material.push(0);
        for event in events {
            material.extend_from_slice(&event.header.encode());
            material.extend_from_slice(&event.payload);
        }
    }
    for (node, fingerprint) in qemu_fingerprints {
        material.extend_from_slice(node.name.as_bytes());
        material.push(0);
        material.extend_from_slice(&fingerprint.bytes);
        if let Some(sequence) = qemu_fault_sequences.get(node) {
            material.extend_from_slice(&sequence.to_be_bytes());
        }
        if let Some(sequence) = qemu_fault_event_sequences.get(node) {
            material.extend_from_slice(&sequence.to_be_bytes());
        }
    }
    for (identity, action) in qemu_issued_actions {
        material.extend_from_slice(&identity.bytes);
        material.extend_from_slice(&action.id().bytes);
    }
    for identity in qemu_active_rule_ids {
        material.extend_from_slice(&identity.bytes);
    }
    Ok(ContentHash::from_canonical_material(
        "crucible.production-fault-runtime-checkpoint.v7",
        &hex_bytes(&material),
    ))
}

fn validate_qemu_action_ledger(
    actions: &BTreeMap<ContentHash, ResolvedBindingAction>,
    active_rule_ids: &BTreeSet<ContentHash>,
) -> Result<(), ProductionFaultRuntimeError> {
    if actions.iter().any(|(identity, action)| {
        *identity != action.id()
            || !matches!(
                action.kind,
                BindingActionKind::UpsertPersistent | BindingActionKind::Apply
            )
            || !matches!(action.effect.specification(), EffectSpecification::Node(_))
    }) {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    if active_rule_ids.iter().any(|identity| {
        actions
            .get(identity)
            .is_none_or(|action| action.kind != BindingActionKind::UpsertPersistent)
    }) {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    Ok(())
}

fn production_manifests(
    nodes: &QemuNodeSet,
) -> Result<FaultAdapterManifests, ProductionFaultRuntimeError> {
    Ok(FaultAdapterManifests {
        network: host_production_manifest(
            "network-host",
            EffectKind::all().iter().copied().filter(|effect| {
                effect.descriptor().adapter == crucible::model::FaultAdapter::Network
            }),
        )?,
        storage: host_production_manifest(
            "storage-host",
            EffectKind::all().iter().copied().filter(|effect| {
                effect.descriptor().adapter == crucible::model::FaultAdapter::Storage
            }),
        )?,
        node: nodes.fault_capability_manifest()?,
    })
}

fn validate_ready_marker_admission(
    plan: &FaultSignalPlan,
    nodes: &QemuNodeSet,
) -> Result<(), ProductionFaultRuntimeError> {
    for binding in plan.bindings() {
        let EffectSpecification::Node(effect) = binding.effect().specification() else {
            continue;
        };
        let marker = match effect {
            NodeEffectSpecification::Lifecycle {
                boot_policy: NodeBootPolicy::RequireReady { ready_marker, .. },
                ..
            }
            | NodeEffectSpecification::Hang {
                watchdog_policy:
                    NodeWatchdogPolicy::TransitionAfter {
                        boot_policy: NodeBootPolicy::RequireReady { ready_marker, .. },
                        ..
                    },
                ..
            } => ready_marker,
            _ => continue,
        };
        for target in binding.selector().resolved().targets() {
            let crucible::model::ResolvedFaultTarget::Node { node } = target else {
                return Err(BackendError::Rejected {
                    message: format!(
                        "ready-marker binding `{}` contains a non-node target",
                        binding.id()
                    ),
                }
                .into());
            };
            if !nodes.admits_ready_marker(node, marker) {
                return Err(BackendError::Rejected {
                    message: format!(
                        "ready marker `{}` is absent from live node `{}` launch manifest",
                        marker.as_str(),
                        node.as_str()
                    ),
                }
                .into());
            }
        }
    }
    Ok(())
}

fn host_production_manifest(
    backend: &str,
    effects: impl IntoIterator<Item = EffectKind>,
) -> Result<FaultCapabilityManifest, ProductionFaultRuntimeError> {
    let backend = FaultObjectId::parse(backend)
        .map_err(crucible::model::FaultRuntimeError::Contract)
        .map_err(FaultExecutionError::from)?;
    let capabilities = effects
        .into_iter()
        .map(|effect| FaultCapabilityId::parse(effect.descriptor().capability))
        .collect::<Result<_, _>>()
        .map_err(crucible::model::FaultRuntimeError::Contract)
        .map_err(FaultExecutionError::from)?;
    Ok(FaultCapabilityManifest {
        backend,
        capabilities,
        bounds: BTreeMap::new(),
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::model::{
        BindingActionCause, BindingEventParent, BindingMapping, BindingMappingRegistry,
        BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy, CountLimit,
        EFFECT_SEMANTIC_VERSION, EffectKind, EffectLifetime, EffectRequest, EffectSpecification,
        EvaluatedSignal, FaultBinding, FaultDirection, FaultPhase, InverseCdfTable,
        NetworkAvailabilityState, NetworkEffectSpecification, NetworkInFlightPolicy, PositiveU64,
        ResolvedFaultTarget, ResolvedMappingOutput, ResolvedTargetSet, SampleObservation,
        SignalChoiceContext, SignalCoordinate, SignalDomain, SignalEvaluationError, SignalId,
        SignalNode, SignalNodeKind, SignalPoint, SignalResourceLimits, SignalShape,
        SignalSourceSpecification, SignalUnit, SignalValue, SignalValueType,
        StateTransitionTableDeclaration, StorageEffectSpecification, TargetSelector,
    };

    struct NoArtifacts;

    impl SignalArtifactProvider for NoArtifacts {
        fn inverse_cdf_table(
            &self,
            content: &ContentHash,
        ) -> Result<InverseCdfTable, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactContentMismatch(*content))
        }

        fn evaluate_artifact_source(
            &self,
            node: &SignalNode,
            _source: &SignalSourceSpecification,
            _coordinate: &SignalCoordinate,
            _same_coordinate_sequence: u64,
            _choice: &SignalChoiceContext,
            _inputs: &[EvaluatedSignal],
            _resource_limits: FaultResourceLimits,
        ) -> Result<EvaluatedSignal, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactSourceRequired(
                node.id.clone(),
            ))
        }
    }

    fn object_id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
    }

    fn signal_id(value: &str) -> SignalId {
        SignalId::parse(value)
            .unwrap_or_else(|error| panic!("test signal ID should be valid: {error}"))
    }

    fn lifecycle_action(
        transition: NodeLifecycleTransition,
        boot_policy: NodeBootPolicy,
    ) -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition,
                downtime_nanos: 32,
                boot_policy,
                volatile_state_policy: NodeStatePolicy::Preserve,
                device_state_policy: NodeStatePolicy::Clear,
            }),
        )
        .unwrap_or_else(|error| panic!("test lifecycle effect should be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::Apply,
            binding: object_id("node-reset"),
            target: ResolvedFaultTarget::Node {
                node: object_id("node-a"),
            },
            phase: FaultPhase::Boundary,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash::from_bytes(b"node-reset-mapping"),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 100,
                retired_instructions: Some(44),
            },
            cause: BindingActionCause::Signal,
            expected_precondition: None,
        }
    }

    fn lifecycle_event(action: &ResolvedBindingAction) -> DequeuedFaultEvent {
        let mut payload = vec![0_u8; LIFECYCLE_EVIDENCE_BYTES];
        let before_hash = [5_u8; 32];
        let transition = match action.effect.specification() {
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition, ..
            }) => lifecycle_tag(*transition),
            other => panic!("test lifecycle action contains {other:?}"),
        };
        let mut after_hash = [6_u8; 32];
        payload[0..8].copy_from_slice(b"CRUCLIF1");
        payload[8..10].copy_from_slice(&4_u16.to_le_bytes());
        payload[10..12].copy_from_slice(&transition.to_le_bytes());
        payload[12..16].copy_from_slice(&1_u32.to_le_bytes());
        payload[16..20].copy_from_slice(&2_u32.to_le_bytes());
        payload[20..24].copy_from_slice(&1_u32.to_le_bytes());
        payload[24..32].copy_from_slice(&44_u64.to_le_bytes());
        payload[32..40].copy_from_slice(&100_u64.to_le_bytes());
        payload[40..48].copy_from_slice(&32_u64.to_le_bytes());
        payload[48..56].copy_from_slice(&4096_u64.to_le_bytes());
        payload[56..64].copy_from_slice(&128_u64.to_le_bytes());
        let binding_hash = ContentHash::from_canonical_material(
            "crucible.fault-binding.v1",
            action.binding.as_str(),
        );
        payload[64..96].copy_from_slice(&binding_hash.bytes);
        payload[96..104].copy_from_slice(&132_u64.to_le_bytes());
        payload[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        payload[120..128].copy_from_slice(&128_u64.to_le_bytes());
        payload[128..160].copy_from_slice(&before_hash);
        payload[160..192].copy_from_slice(&after_hash);
        let boot_policy = match action.effect.specification() {
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                boot_policy, ..
            }) => boot_policy,
            other => panic!("test lifecycle action contains {other:?}"),
        };
        match boot_policy {
            NodeBootPolicy::Immediate => {
                payload[192..196].copy_from_slice(&1_u32.to_le_bytes());
                payload[196..200].copy_from_slice(&1_u32.to_le_bytes());
                payload[200..204].copy_from_slice(&1_u32.to_le_bytes());
                payload[216..224].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            NodeBootPolicy::RequireReady {
                ready_marker,
                maximum_attempts,
                retry_delay_nanos,
                exhausted,
            } => {
                payload[192..196].copy_from_slice(&2_u32.to_le_bytes());
                payload[196..200].copy_from_slice(&1_u32.to_le_bytes());
                payload[200..204].copy_from_slice(&maximum_attempts.get().to_le_bytes());
                payload[204..208]
                    .copy_from_slice(&u32::from(lifecycle_tag(*exhausted)).to_le_bytes());
                payload[208..216].copy_from_slice(&retry_delay_nanos.to_le_bytes());
                payload[216..224].copy_from_slice(&4200_u64.to_le_bytes());
                let marker_hash: [u8; 32] = Sha256::digest(ready_marker.as_str().as_bytes()).into();
                payload[224..256].copy_from_slice(&marker_hash);
            }
        }
        payload[288..292].copy_from_slice(&u32::from(transition).to_le_bytes());
        if matches!(transition, 2 | 4 | 6) {
            let pre_exit_hash = [9_u8; 32];
            let mut material = [0_u8; 48];
            material[0..8].copy_from_slice(b"CRUCTRM1");
            material[8..12].copy_from_slice(&u32::from(transition).to_le_bytes());
            material[16..48].copy_from_slice(&pre_exit_hash);
            after_hash = Sha256::digest(material).into();
            payload[160..192].copy_from_slice(&after_hash);
            payload[256..288].copy_from_slice(&pre_exit_hash);
            payload[292..296].copy_from_slice(&LIFECYCLE_TERMINAL_CAUSE_DIRECT.to_le_bytes());
            payload[296..300].copy_from_slice(
                &(LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED)
                    .to_le_bytes(),
            );
        }
        DequeuedFaultEvent {
            header: crucible_shmem::FaultEventHeaderV1 {
                command_kind: crucible_shmem::FaultCommandKind::NodeLifecycle,
                outcome: FaultEventOutcomeV1::Applied,
                event_sequence: 1,
                rule_command_sequence: 2,
                observed_icount: 44,
                model_phase: 1,
                target_kind: 1,
                generation: 1,
                binding_hash: binding_hash.bytes,
                opportunity_hash: [2; 32],
                action_hash: action.id().bytes,
                target_hash: ContentHash::from_canonical_material(
                    "crucible.resolved-fault-target.v1",
                    &action.target.canonical_material(),
                )
                .bytes,
                before_hash,
                after_hash,
                evidence_hash: Sha256::digest(&payload).into(),
                payload_hash: *blake3::hash(&payload).as_bytes(),
                payload_offset: 0,
                payload_length: LIFECYCLE_EVIDENCE_BYTES as u32,
            },
            payload,
        }
    }

    #[test]
    fn typed_lifecycle_evidence_rejects_policy_and_marker_mismatch() {
        let immediate = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
        let event = lifecycle_event(&immediate);
        assert!(validate_node_event_evidence(&event, &immediate).is_ok());

        let mut corrupt = event.clone();
        corrupt.payload[12..16].copy_from_slice(&2_u32.to_le_bytes());
        assert!(validate_node_event_evidence(&corrupt, &immediate).is_err());

        let ready = lifecycle_action(
            NodeLifecycleTransition::Reset,
            NodeBootPolicy::RequireReady {
                ready_marker: object_id("guest-ready"),
                maximum_attempts: crucible::model::BoundedCount::new(
                    CountLimit::LargeStateEntries,
                    2,
                )
                .unwrap_or_else(|error| panic!("test attempt count should be valid: {error}")),
                retry_delay_nanos: 4096,
                exhausted: NodeLifecycleTransition::PermanentFailure,
            },
        );
        assert!(validate_node_event_evidence(&event, &ready).is_err());
    }

    #[test]
    fn terminal_lifecycle_evidence_reconstructs_the_pre_exit_digest() {
        let crash = lifecycle_action(NodeLifecycleTransition::Crash, NodeBootPolicy::Immediate);
        let event = lifecycle_event(&crash);
        assert!(validate_node_event_evidence(&event, &crash).is_ok());
        let decision = node_lifecycle_decision(
            &NodeId {
                name: "node-a".to_owned(),
            },
            crash.id(),
            &event,
        )
        .unwrap_or_else(|| panic!("terminal event should produce a supervision decision"));
        assert_eq!(decision.expected_exit_code, Some(70));
        assert_eq!(
            decision.requested_transition,
            NodeLifecycleTransition::Crash
        );
        assert_eq!(
            decision.effective_transition,
            NodeLifecycleTransition::Crash
        );

        let mut substituted = event.clone();
        substituted.payload[256] ^= 1;
        assert!(validate_node_event_evidence(&substituted, &crash).is_err());
    }

    #[test]
    fn ready_exhaustion_names_the_effective_terminal_transition() {
        let reset = lifecycle_action(
            NodeLifecycleTransition::Reset,
            NodeBootPolicy::RequireReady {
                ready_marker: object_id("guest-ready"),
                maximum_attempts: crucible::model::BoundedCount::new(
                    CountLimit::LargeStateEntries,
                    2,
                )
                .unwrap_or_else(|error| panic!("test attempt count should be valid: {error}")),
                retry_delay_nanos: 4096,
                exhausted: NodeLifecycleTransition::PowerOff,
            },
        );
        let mut event = lifecycle_event(&reset);
        let pre_exit_hash = [11_u8; 32];
        let mut material = [0_u8; 48];
        material[0..8].copy_from_slice(b"CRUCTRM1");
        material[8..12].copy_from_slice(
            &u32::from(lifecycle_tag(NodeLifecycleTransition::PowerOff)).to_le_bytes(),
        );
        material[16..48].copy_from_slice(&pre_exit_hash);
        let after_hash: [u8; 32] = Sha256::digest(material).into();
        event.payload[196..200].copy_from_slice(&2_u32.to_le_bytes());
        event.payload[160..192].copy_from_slice(&after_hash);
        event.payload[256..288].copy_from_slice(&pre_exit_hash);
        event.payload[288..292].copy_from_slice(
            &u32::from(lifecycle_tag(NodeLifecycleTransition::PowerOff)).to_le_bytes(),
        );
        event.payload[292..296]
            .copy_from_slice(&LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED.to_le_bytes());
        event.payload[296..300].copy_from_slice(
            &(LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED).to_le_bytes(),
        );
        event.header.after_hash = after_hash;
        assert!(validate_node_event_evidence(&event, &reset).is_ok());

        let decision = node_lifecycle_decision(
            &NodeId {
                name: "node-a".to_owned(),
            },
            reset.id(),
            &event,
        )
        .unwrap_or_else(|| panic!("exhaustion should produce a supervision decision"));
        assert_eq!(
            decision.requested_transition,
            NodeLifecycleTransition::Reset
        );
        assert_eq!(
            decision.effective_transition,
            NodeLifecycleTransition::PowerOff
        );
        assert_eq!(decision.expected_exit_code, Some(71));
    }

    #[test]
    fn fail_closed_lifecycle_accepts_an_explicit_missing_pre_exit_measurement() {
        let reset = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
        let mut event = lifecycle_event(&reset);
        event.header.outcome = FaultEventOutcomeV1::Error;
        event.header.after_hash = event.header.before_hash;
        event.payload[112..120].fill(0);
        event.payload[120..128].fill(0);
        event.payload[160..192].copy_from_slice(&event.header.before_hash);
        event.payload[288..292].copy_from_slice(
            &u32::from(lifecycle_tag(NodeLifecycleTransition::PermanentFailure)).to_le_bytes(),
        );
        event.payload[292..296]
            .copy_from_slice(&LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED.to_le_bytes());
        event.payload[296..300].copy_from_slice(&LIFECYCLE_TERMINAL_EXIT_REQUIRED.to_le_bytes());
        assert!(validate_node_event_evidence(&event, &reset).is_ok());

        event.payload[256] = 1;
        assert!(validate_node_event_evidence(&event, &reset).is_err());
    }

    #[test]
    fn qemu_action_ledger_retains_impulses_and_removed_rules_for_events() {
        let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
        let nodes = QemuNodeSet::new();
        let mut runtime = ProductionFaultRuntime::new(
            plan,
            None,
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"qemu-action-ledger"),
            &nodes,
        )
        .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));

        let impulse = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
        runtime
            .update_qemu_action_ledger(std::slice::from_ref(&impulse))
            .unwrap_or_else(|error| panic!("impulse should enter issued ledger: {error}"));
        assert_eq!(
            runtime.qemu_issued_actions.get(&impulse.id()),
            Some(&impulse)
        );

        let mut persistent = impulse.clone();
        persistent.kind = BindingActionKind::UpsertPersistent;
        persistent.binding = object_id("node-hang");
        persistent.transition_sequence = 2;
        runtime
            .update_qemu_action_ledger(std::slice::from_ref(&persistent))
            .unwrap_or_else(|error| panic!("persistent rule should enter issued ledger: {error}"));

        let mut remove = persistent.clone();
        remove.kind = BindingActionKind::RemovePersistent;
        remove.transition_sequence = 3;
        runtime
            .update_qemu_action_ledger(std::slice::from_ref(&remove))
            .unwrap_or_else(|error| panic!("known rule should be removable: {error}"));
        assert_eq!(
            runtime.qemu_issued_actions.get(&persistent.id()),
            Some(&persistent),
            "recovery evidence names the issued upsert after removal"
        );
        assert!(runtime.qemu_active_rule_ids.is_empty());
        assert!(
            runtime
                .update_qemu_action_ledger(std::slice::from_ref(&remove))
                .is_err()
        );
    }

    #[test]
    fn checkpoint_rejects_unacknowledged_node_boot_edge() {
        let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
        let mut nodes = QemuNodeSet::new();
        let mut runtime = ProductionFaultRuntime::new(
            plan,
            None,
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"pending-node-boot"),
            &nodes,
        )
        .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
        runtime
            .pending_node_boot
            .insert(NodeId { name: String::from("node-a") });

        assert!(matches!(
            runtime.checkpoint(&mut nodes),
            Err(ProductionFaultRuntimeError::PendingQemuFaultEvents)
        ));
        runtime.acknowledge_node_boot_requests();
        runtime
            .checkpoint(&mut nodes)
            .unwrap_or_else(|error| panic!("acknowledged boot edge should checkpoint: {error}"));
    }

    fn pending_qemu_observation() -> FaultObservation {
        FaultObservation {
            semantic_version: crucible::model::FAULT_RUNTIME_STATE_VERSION,
            kind: FaultObservationKind::EffectApplied,
            coordinate: FaultCoordinate {
                virtual_nanos: 7,
                retired_instructions: Some(11),
            },
            binding: Some(object_id("node-fault")),
            target: Some(ResolvedFaultTarget::Node {
                node: object_id("node-a"),
            }),
            opportunity: Some(ContentHash::from_bytes(b"node-opportunity")),
            evidence: ContentHash::from_bytes(b"qemu-evidence"),
        }
    }

    fn availability_plan(
        target: &ResolvedFaultTarget,
        phase: FaultPhase,
        state: NetworkAvailabilityState,
        queued_policy: NetworkInFlightPolicy,
        in_flight_policy: NetworkInFlightPolicy,
    ) -> FaultSignalPlan {
        let output = signal_id("network-down");
        let program = crucible::model::SignalProgram::new(
            vec![SignalNode {
                id: output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                    .unwrap_or_else(|error| panic!("test signal shape should be valid: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::Bool(true),
                },
            }],
            vec![output],
            SignalResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test signal program should be valid: {error}"));
        let targets = ResolvedTargetSet::new(vec![target.clone()], false)
            .unwrap_or_else(|error| panic!("test target set should be valid: {error}"));
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state,
                queued_policy,
                in_flight_policy,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
        let binding = FaultBinding::new(
            object_id("network-down-binding"),
            program.exported_outputs().to_vec(),
            BindingSampling::AtBoundary,
            BindingMapping::ActiveWhenTrue { invert: false },
            TargetSelector::Exact(targets),
            [phase].into_iter().collect(),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: true,
            },
            &program,
        )
        .unwrap_or_else(|error| panic!("test binding should be valid: {error}"));
        FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("test plan should be valid: {error}"))
    }

    #[test]
    fn production_host_manifest_advertises_every_implemented_network_effect() {
        let network = host_production_manifest(
            "network-host",
            EffectKind::all().iter().copied().filter(|effect| {
                effect.descriptor().adapter == crucible::model::FaultAdapter::Network
            }),
        )
        .unwrap_or_else(|error| panic!("network manifest should build: {error}"));
        let availability =
            FaultCapabilityId::parse(EffectKind::NetworkAvailability.descriptor().capability)
                .unwrap_or_else(|error| panic!("availability capability should parse: {error}"));
        let mtu = FaultCapabilityId::parse(EffectKind::NetworkMtu.descriptor().capability)
            .unwrap_or_else(|error| panic!("MTU capability should parse: {error}"));
        let expected_network_capabilities = EffectKind::all()
            .iter()
            .filter(|effect| effect.descriptor().adapter == crucible::model::FaultAdapter::Network)
            .count();
        assert_eq!(network.capabilities.len(), expected_network_capabilities);
        assert!(network.capabilities.contains(&availability));
        assert!(network.capabilities.contains(&mtu));

        let storage = host_production_manifest("storage-host", std::iter::empty())
            .unwrap_or_else(|error| panic!("empty storage manifest should build: {error}"));
        assert!(storage.capabilities.is_empty());
    }

    #[test]
    fn empty_plan_checkpoint_preserves_custom_resource_identity() {
        let mut limits = FaultResourceLimits::default();
        limits.event_records -= 1;
        let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), limits)
            .unwrap_or_else(|error| panic!("custom empty plan should be valid: {error}"));
        let mut nodes = QemuNodeSet::new();
        let seed = ContentHash::from_bytes(b"custom-empty-plan");
        let runtime = ProductionFaultRuntime::new(
            plan.clone(),
            None,
            SignalBoundarySnapshot::default(),
            seed,
            &nodes,
        )
        .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
        let checkpoint = runtime
            .checkpoint(&mut nodes)
            .unwrap_or_else(|error| panic!("empty checkpoint should encode: {error}"));
        ProductionFaultRuntime::restore(plan, None, seed, checkpoint, &mut nodes)
            .unwrap_or_else(|error| panic!("custom empty checkpoint should restore: {error}"));
    }

    #[test]
    fn production_availability_survives_checkpoint_restore() {
        let target = ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-left-right"),
            direction: FaultDirection::AToB,
        };
        let plan = availability_plan(
            &target,
            FaultPhase::Admit,
            NetworkAvailabilityState::Down,
            NetworkInFlightPolicy::Drop,
            NetworkInFlightPolicy::Drop,
        );
        let artifacts: Arc<dyn SignalArtifactProvider> = Arc::new(NoArtifacts);
        let mut nodes = QemuNodeSet::new();
        let seed = ContentHash::from_bytes(b"production-availability-test");
        let coordinate = FaultCoordinate {
            virtual_nanos: 17,
            retired_instructions: None,
        };
        let mut runtime = ProductionFaultRuntime::new(
            plan.clone(),
            Some(Arc::clone(&artifacts)),
            SignalBoundarySnapshot::default(),
            seed,
            &nodes,
        )
        .unwrap_or_else(|error| panic!("production plan should be admitted: {error}"));

        let evaluation = runtime
            .evaluate_boundary(coordinate, 0, &mut nodes)
            .unwrap_or_else(|error| panic!("availability boundary should execute: {error}"));
        assert_eq!(evaluation.actions.len(), 1);
        let action = runtime
            .host_state()
            .matching(&target, FaultPhase::Admit)
            .next()
            .unwrap_or_else(|| panic!("availability action should be committed"));
        assert!(matches!(
            action.effect.specification(),
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                ..
            })
        ));

        let checkpoint = runtime
            .checkpoint(&mut nodes)
            .unwrap_or_else(|error| panic!("production checkpoint should succeed: {error}"));
        let restored =
            ProductionFaultRuntime::restore(plan, Some(artifacts), seed, checkpoint, &mut nodes)
                .unwrap_or_else(|error| panic!("production checkpoint should restore: {error}"));
        assert_eq!(
            restored
                .host_state()
                .matching(&target, FaultPhase::Admit)
                .count(),
            1
        );
    }

    #[test]
    fn production_admits_every_availability_target_phase_state_and_policy() {
        let targets = [
            ResolvedFaultTarget::NetworkInterface {
                endpoint: object_id("endpoint-a"),
                interface: object_id("interface-a"),
            },
            ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-left-right"),
                direction: FaultDirection::AToB,
            },
            ResolvedFaultTarget::NetworkMedium {
                medium: object_id("medium-a"),
                resource: object_id("channel-a"),
            },
            ResolvedFaultTarget::NetworkQueue {
                owner: object_id("forwarder-a"),
                queue: object_id("queue-a"),
            },
            ResolvedFaultTarget::NetworkForwarder {
                forwarder: object_id("forwarder-a"),
            },
            ResolvedFaultTarget::NetworkPath {
                path_version: object_id("path-v1"),
                direction: FaultDirection::AToB,
            },
            ResolvedFaultTarget::NetworkAttachment {
                endpoint: object_id("endpoint-a"),
                interface: object_id("interface-a"),
                attachment: object_id("attachment-a"),
            },
            ResolvedFaultTarget::NetworkContact {
                plan: object_id("contact-plan-a"),
                endpoint_a: object_id("endpoint-a"),
                endpoint_b: object_id("endpoint-b"),
                contact: object_id("contact-a"),
            },
        ];
        let nodes = QemuNodeSet::new();
        for target in targets {
            for phase in [FaultPhase::Admit, FaultPhase::Resolve] {
                for state in [
                    NetworkAvailabilityState::Up,
                    NetworkAvailabilityState::Down,
                    NetworkAvailabilityState::ReceiveOnly,
                    NetworkAvailabilityState::TransmitOnly,
                ] {
                    for queued in [
                        NetworkInFlightPolicy::Preserve,
                        NetworkInFlightPolicy::Reevaluate,
                        NetworkInFlightPolicy::Drop,
                        NetworkInFlightPolicy::TypedError,
                    ] {
                        for in_flight in [
                            NetworkInFlightPolicy::Preserve,
                            NetworkInFlightPolicy::Reevaluate,
                            NetworkInFlightPolicy::Drop,
                            NetworkInFlightPolicy::TypedError,
                        ] {
                            let result = ProductionFaultRuntime::new(
                                availability_plan(&target, phase, state, queued, in_flight),
                                Some(Arc::new(NoArtifacts)),
                                SignalBoundarySnapshot::default(),
                                ContentHash::from_bytes(b"availability-admission-matrix"),
                                &nodes,
                            );
                            assert!(
                                result.is_ok(),
                                "target {:?}, phase {phase:?}, state {state:?}, policy pair {queued:?}/{in_flight:?}",
                                target.kind()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn production_checkpoints_referenced_storage_recovery_events() {
        let active = signal_id("stall-transition");
        let recovery = signal_id("storage-recovered");
        let schema = signal_id("storage-recovery-v1");
        let transition_schema = signal_id("storage-transition-v1");
        let transition_value = SignalValue::Event {
            schema: transition_schema.clone(),
            payload: vec![1],
        };
        let program = crucible::model::SignalProgram::new(
            vec![
                SignalNode {
                    id: active.clone(),
                    domain: SignalDomain::Event,
                    output: SignalShape::new(
                        SignalValueType::Event(transition_schema),
                        SignalUnit::Dimensionless,
                        0,
                    )
                    .unwrap_or_else(|error| panic!("test signal shape should be valid: {error}")),
                    inputs: Vec::new(),
                    kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                        events: vec![SignalPoint {
                            coordinate: SignalCoordinate::Event {
                                parent: Box::new(SignalCoordinate::VirtualTime { nanos: 0 }),
                                sequence: 0,
                            },
                            sequence: 0,
                            value: transition_value.clone(),
                        }],
                    }),
                },
                SignalNode {
                    id: recovery.clone(),
                    domain: SignalDomain::Event,
                    output: SignalShape::new(
                        SignalValueType::Event(schema.clone()),
                        SignalUnit::Dimensionless,
                        0,
                    )
                    .unwrap_or_else(|error| panic!("test event shape should be valid: {error}")),
                    inputs: Vec::new(),
                    kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                        events: vec![SignalPoint {
                            coordinate: SignalCoordinate::Event {
                                parent: Box::new(SignalCoordinate::VirtualTime { nanos: 5 }),
                                sequence: 0,
                            },
                            sequence: 0,
                            value: SignalValue::Event {
                                schema,
                                payload: vec![1],
                            },
                        }],
                    }),
                },
            ],
            vec![active.clone(), recovery.clone()],
            SignalResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test signal program should be valid: {error}"));
        let target = ResolvedFaultTarget::BlockDevice {
            device: ContentHash::from_bytes(b"storage-recovery-device"),
        };
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::StateMachine,
            EffectSpecification::Storage(StorageEffectSpecification::StallTimeout {
                stall_nanos: PositiveU64::new("stall_nanos", 20)
                    .unwrap_or_else(|error| panic!("test stall should be positive: {error}")),
                recovery_event: Some(object_id(recovery.as_str())),
                timeout_result: object_id("timeout-result"),
            }),
        )
        .unwrap_or_else(|error| panic!("test stall effect should be valid: {error}"));
        let transition_table = object_id("storage-stall-transition-table");
        let mapping_registry = BindingMappingRegistry::new(
            vec![StateTransitionTableDeclaration {
                id: transition_table.clone(),
                semantic_version: 1,
                input: transition_value
                    .value_type()
                    .unwrap_or_else(|| panic!("test transition value should be typed")),
                effect: EffectKind::StorageStallTimeout,
                transitions: [(transition_value, object_id("retain-completion"))]
                    .into_iter()
                    .collect(),
                default_transition: object_id("retain-completion"),
            }],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test mapping registry should be valid: {error}"));
        let binding = FaultBinding::new_with_registry(
            object_id("storage-stall-binding"),
            vec![active],
            BindingSampling::AtEvent(BindingEventParent::VirtualTime),
            BindingMapping::StateTransition { transition_table },
            TargetSelector::Exact(
                ResolvedTargetSet::new(vec![target], false)
                    .unwrap_or_else(|error| panic!("test target should be valid: {error}")),
            ),
            [FaultPhase::Resolve].into_iter().collect(),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: true,
            },
            &program,
            &mapping_registry,
        )
        .unwrap_or_else(|error| panic!("test binding should be valid: {error}"));
        let plan =
            FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
                .unwrap_or_else(|error| panic!("test plan should be valid: {error}"));
        let artifacts: Arc<dyn SignalArtifactProvider> = Arc::new(NoArtifacts);
        let mut nodes = QemuNodeSet::new();
        let seed = ContentHash::from_bytes(b"storage-recovery-event-test");
        let mut runtime = ProductionFaultRuntime::new(
            plan.clone(),
            Some(Arc::clone(&artifacts)),
            SignalBoundarySnapshot::default(),
            seed,
            &nodes,
        )
        .unwrap_or_else(|error| panic!("production plan should be admitted: {error}"));

        let first = runtime
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                0,
                &mut nodes,
            )
            .unwrap_or_else(|error| panic!("initial boundary should execute: {error}"));
        assert_eq!(first.next_wakeup_nanos, Some(5));
        assert!(first.emitted_events.is_empty());
        let recovered = runtime
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 5,
                    retired_instructions: None,
                },
                0,
                &mut nodes,
            )
            .unwrap_or_else(|error| panic!("recovery boundary should execute: {error}"));
        assert_eq!(recovered.emitted_events.len(), 1);
        assert_eq!(recovered.emitted_events[0].signal, recovery);

        let checkpoint = runtime
            .checkpoint(&mut nodes)
            .unwrap_or_else(|error| panic!("production checkpoint should succeed: {error}"));
        let restored =
            ProductionFaultRuntime::restore(plan, Some(artifacts), seed, checkpoint, &mut nodes)
                .unwrap_or_else(|error| panic!("production checkpoint should restore: {error}"));
        assert_eq!(restored.emitted_events(), runtime.emitted_events());
    }

    #[test]
    fn rejected_qemu_event_validation_retains_the_raw_event() {
        let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
        let mut nodes = QemuNodeSet::new();
        let mut runtime = ProductionFaultRuntime::new(
            plan,
            None,
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"retain-rejected-qemu-event"),
            &nodes,
        )
        .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
        let node = NodeId {
            name: String::from("node-a"),
        };
        let payload = vec![1, 2, 3];
        let event = DequeuedFaultEvent {
            header: crucible_shmem::FaultEventHeaderV1 {
                command_kind: crucible_shmem::FaultCommandKind::CpuService,
                outcome: crucible_shmem::FaultEventOutcomeV1::Applied,
                event_sequence: 1,
                rule_command_sequence: 1,
                observed_icount: 1,
                model_phase: 1,
                target_kind: 1,
                generation: 1,
                binding_hash: [1; 32],
                opportunity_hash: [2; 32],
                action_hash: [3; 32],
                target_hash: [4; 32],
                before_hash: [5; 32],
                after_hash: [6; 32],
                evidence_hash: [7; 32],
                payload_hash: *blake3::hash(&payload).as_bytes(),
                payload_offset: 0,
                payload_length: u32::try_from(payload.len())
                    .unwrap_or_else(|_| panic!("test payload length should fit")),
            },
            payload,
        };
        runtime
            .pending_qemu_events
            .insert(node.clone(), vec![event.clone()]);

        let result = runtime.drain_qemu_observations(
            &mut nodes,
            FaultCoordinate {
                virtual_nanos: 1,
                retired_instructions: Some(1),
            },
        );

        assert!(result.is_err());
        assert_eq!(
            runtime.pending_qemu_events.get(&node),
            Some(&vec![event.clone()])
        );

        let mut second = event.clone();
        second.header.event_sequence = 2;
        let sequences = BTreeMap::from([(node.clone(), 3)]);
        assert!(
            validate_pending_qemu_event_sequences(
                &BTreeMap::from([(node.clone(), vec![event.clone(), second.clone()])]),
                &sequences,
            )
            .is_ok()
        );
        second.header.event_sequence = 3;
        assert!(
            validate_pending_qemu_event_sequences(
                &BTreeMap::from([(node, vec![event, second])]),
                &sequences,
            )
            .is_err()
        );
    }

    #[test]
    fn production_event_limits_cover_all_retained_event_classes_in_aggregate() {
        let mut limits = FaultResourceLimits::default();
        limits.event_records = 1;
        let observations = vec![pending_qemu_observation(), pending_qemu_observation()];

        assert!(
            validate_production_event_state(
                &[],
                &[],
                &observations,
                &[],
                &BTreeMap::new(),
                limits,
            )
            .is_err()
        );
    }

    #[test]
    fn pending_qemu_observation_identity_covers_kind_binding_and_target() {
        let original = pending_qemu_observation();
        let original_material = observation_identity_material(&original)
            .unwrap_or_else(|error| panic!("observation should encode: {error}"));

        let mut changed_kind = original.clone();
        changed_kind.kind = FaultObservationKind::FaultOpportunity;
        let mut changed_binding = original.clone();
        changed_binding.binding = Some(object_id("other-binding"));
        let mut changed_target = original;
        changed_target.target = Some(ResolvedFaultTarget::Node {
            node: object_id("node-b"),
        });

        for changed in [changed_kind, changed_binding, changed_target] {
            assert_ne!(
                observation_identity_material(&changed)
                    .unwrap_or_else(|error| panic!("changed observation should encode: {error}")),
                original_material
            );
        }
    }
}
