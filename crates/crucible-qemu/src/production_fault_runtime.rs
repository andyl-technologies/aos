//! Owning production runtime for signal-driven host and QEMU faults.
//!
//! This module keeps the evaluator continuation, canonical adapter ledger,
//! host device state, and live-QEMU transaction routing behind one checkpoint
//! surface. An empty plan has no hidden evaluator and remains a valid inert
//! production configuration.

use std::collections::BTreeMap;
use std::sync::Arc;

use crucible::model::{
    BindingEvaluation, ContentHash, EffectKind, FaultAdapterManifests, FaultCapabilityId,
    FaultCapabilityManifest, FaultCoordinate, FaultExecutionError, FaultObjectId, FaultOpportunity,
    FaultRuntimeCheckpoint, FaultSignalPlan, HostFaultActionSink, HostFaultActionState,
    OwnedFaultExecutionRuntime, ReferencedSignalEvent, SignalArtifactProvider,
    SignalBoundarySnapshot,
};
use crucible::{BackendError, BackendNetworkOutput, NodeId, SchedulerNetworkCheckpoint};

use crate::{ProductionFaultActionSink, QemuNodeSet};

/// Hard bound on recovery-event occurrences retained for device subscriptions.
const HARD_PRODUCTION_REFERENCED_EVENTS: usize = 262_144;

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
    /// Scheduler-owned network queues, pending outputs, and transition ledger.
    network_state: Option<ProductionNetworkStateCheckpoint>,
    /// Referenced event occurrences retained for device recovery subscriptions.
    emitted_events: Vec<ReferencedSignalEvent>,
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
    /// Referenced recovery-event history reached its declared hard bound.
    #[error(
        "production referenced-event history exceeds {HARD_PRODUCTION_REFERENCED_EVENTS} entries"
    )]
    ReferencedEventLimit,
}

/// Owning signal runtime coupled to host devices and live patched QEMU.
pub struct ProductionFaultRuntime {
    runtime: Option<OwnedFaultExecutionRuntime>,
    host: HostFaultActionSink,
    restored_network_state: Option<ProductionNetworkStateCheckpoint>,
    emitted_events: Vec<ReferencedSignalEvent>,
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
        let manifests = production_manifests(nodes)?;
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
            runtime,
            host: HostFaultActionSink::new(),
            restored_network_state: None,
            emitted_events: Vec::new(),
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
        let manifests = production_manifests(nodes)?;
        if checkpoint.emitted_events.len() > HARD_PRODUCTION_REFERENCED_EVENTS {
            return Err(ProductionFaultRuntimeError::ReferencedEventLimit);
        }
        if checkpoint.identity
            != production_checkpoint_identity(
                plan.id(),
                checkpoint.runtime.as_ref(),
                &checkpoint.host,
                &checkpoint.qemu_fingerprints,
                &checkpoint.qemu_fault_sequences,
                checkpoint.network_state.as_ref(),
                &checkpoint.emitted_events,
            )
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
        let host = checkpoint.host;
        let restored_network_state = checkpoint.network_state;
        let emitted_events = checkpoint.emitted_events;
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
        Ok(Self {
            runtime,
            host: HostFaultActionSink::from_state(host),
            restored_network_state,
            emitted_events,
        })
    }

    /// Takes the authenticated network continuation paired with this restore.
    #[must_use]
    pub fn take_restored_network_state(&mut self) -> Option<ProductionNetworkStateCheckpoint> {
        self.restored_network_state.take()
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
        let Some(runtime) = &mut self.runtime else {
            return Ok(BindingEvaluation::default());
        };
        if self
            .emitted_events
            .len()
            .checked_add(referenced_event_signal_count(runtime.plan()))
            .is_none_or(|count| count > HARD_PRODUCTION_REFERENCED_EVENTS)
        {
            return Err(ProductionFaultRuntimeError::ReferencedEventLimit);
        }
        let mut sink = ProductionFaultActionSink::new(&mut self.host, nodes);
        let evaluation = runtime.evaluate_boundary_with_backend(
            coordinate,
            same_coordinate_sequence,
            &mut sink,
        )?;
        self.emitted_events
            .extend(evaluation.emitted_events.iter().cloned());
        Ok(evaluation)
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
        let Some(runtime) = &mut self.runtime else {
            return Ok(BindingEvaluation::default());
        };
        let mut sink = ProductionFaultActionSink::new(&mut self.host, nodes);
        Ok(runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut sink,
        )?)
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
        let Some(runtime) = &mut self.runtime else {
            return Ok(BindingEvaluation::default());
        };
        Ok(runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut self.host,
        )?)
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
        let runtime = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.checkpoint().clone());
        let host = self.host.state().clone();
        let qemu_fingerprints = nodes.execution_fingerprints()?;
        let qemu_fault_sequences = nodes.fault_command_sequences();
        let plan = self.runtime.as_ref().map_or_else(
            || FaultSignalPlan::empty().id(),
            |runtime| runtime.plan().id(),
        );
        let identity = production_checkpoint_identity(
            plan,
            runtime.as_ref(),
            &host,
            &qemu_fingerprints,
            &qemu_fault_sequences,
            self.restored_network_state.as_ref(),
            &self.emitted_events,
        );
        Ok(ProductionFaultRuntimeCheckpoint {
            runtime,
            host,
            qemu_fingerprints,
            qemu_fault_sequences,
            network_state: self.restored_network_state.clone(),
            emitted_events: self.emitted_events.clone(),
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
        let plan = self.runtime.as_ref().map_or_else(
            || FaultSignalPlan::empty().id(),
            |runtime| runtime.plan().id(),
        );
        checkpoint.network_state = Some(network_state);
        checkpoint.identity = production_checkpoint_identity(
            plan,
            checkpoint.runtime.as_ref(),
            &checkpoint.host,
            &checkpoint.qemu_fingerprints,
            &checkpoint.qemu_fault_sequences,
            checkpoint.network_state.as_ref(),
            &checkpoint.emitted_events,
        );
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

fn referenced_event_signal_count(plan: &FaultSignalPlan) -> usize {
    plan.bindings()
        .iter()
        .filter_map(|binding| match binding.effect().specification() {
            crucible::model::EffectSpecification::Storage(
                crucible::model::StorageEffectSpecification::StallTimeout {
                    recovery_event, ..
                }
                | crucible::model::StorageEffectSpecification::FlushDisposition {
                    recovery_event,
                    ..
                },
            ) => recovery_event.as_ref(),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

fn production_checkpoint_identity(
    plan: ContentHash,
    runtime: Option<&FaultRuntimeCheckpoint>,
    host: &HostFaultActionState,
    qemu_fingerprints: &BTreeMap<NodeId, ContentHash>,
    qemu_fault_sequences: &BTreeMap<NodeId, u64>,
    network_state: Option<&ProductionNetworkStateCheckpoint>,
    emitted_events: &[ReferencedSignalEvent],
) -> ContentHash {
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
        material.extend_from_slice(&runtime.binding_runtime.evaluator.content().bytes);
        material.push(u8::from(runtime.poisoned));
        for (adapter, state) in &runtime.adapters {
            material.push(match adapter {
                crucible::model::FaultAdapter::Network => 1,
                crucible::model::FaultAdapter::Storage => 2,
                crucible::model::FaultAdapter::Node => 3,
            });
            material.extend_from_slice(&state.digest.bytes);
        }
        if let Some(cursor) = runtime.binding_runtime.scheduler_cursor {
            material.extend_from_slice(&cursor.virtual_nanos.to_be_bytes());
            material.extend_from_slice(&cursor.same_coordinate_sequence.to_be_bytes());
        }
        if let Some(cursor) = runtime.binding_runtime.boundary_completed_cursor {
            material.extend_from_slice(&cursor.virtual_nanos.to_be_bytes());
            material.extend_from_slice(&cursor.same_coordinate_sequence.to_be_bytes());
        }
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
    for (node, fingerprint) in qemu_fingerprints {
        material.extend_from_slice(node.name.as_bytes());
        material.push(0);
        material.extend_from_slice(&fingerprint.bytes);
        if let Some(sequence) = qemu_fault_sequences.get(node) {
            material.extend_from_slice(&sequence.to_be_bytes());
        }
    }
    ContentHash::from_canonical_material(
        "crucible.production-fault-runtime-checkpoint.v2",
        &hex_bytes(&material),
    )
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
        BindingEventParent, BindingMapping, BindingMappingRegistry, BindingObservabilityPolicy,
        BindingSampling, BindingSearchPolicy, EFFECT_SEMANTIC_VERSION, EffectKind, EffectLifetime,
        EffectRequest, EffectSpecification, EvaluatedSignal, FaultBinding, FaultDirection,
        FaultPhase, InverseCdfTable, NetworkAvailabilityState, NetworkEffectSpecification,
        NetworkInFlightPolicy, PositiveU64, ResolvedFaultTarget, ResolvedTargetSet,
        SampleObservation, SignalChoiceContext, SignalCoordinate, SignalDomain,
        SignalEvaluationError, SignalId, SignalNode, SignalNodeKind, SignalPoint,
        SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit, SignalValue,
        SignalValueType, StateTransitionTableDeclaration, StorageEffectSpecification,
        TargetSelector,
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
        FaultSignalPlan::new(vec![program], vec![binding])
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
        let plan = FaultSignalPlan::new(vec![program], vec![binding])
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
}
