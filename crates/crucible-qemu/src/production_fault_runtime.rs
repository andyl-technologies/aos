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
    OwnedFaultExecutionRuntime, SignalArtifactProvider, SignalBoundarySnapshot,
};
use crucible::{BackendError, NodeId};

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
    /// Aggregate identity binding every continuation component to the plan.
    identity: ContentHash,
}

impl ProductionFaultRuntimeCheckpoint {
    /// Returns the aggregate content identity of this continuation.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.identity
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
}

/// Owning signal runtime coupled to host devices and live patched QEMU.
pub struct ProductionFaultRuntime {
    runtime: Option<OwnedFaultExecutionRuntime>,
    host: HostFaultActionSink,
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
        if checkpoint.identity
            != production_checkpoint_identity(
                plan.id(),
                checkpoint.runtime.as_ref(),
                &checkpoint.host,
                &checkpoint.qemu_fingerprints,
                &checkpoint.qemu_fault_sequences,
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
        })
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
        let mut sink = ProductionFaultActionSink::new(&mut self.host, nodes);
        Ok(runtime.evaluate_boundary_with_backend(
            coordinate,
            same_coordinate_sequence,
            &mut sink,
        )?)
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
        );
        Ok(ProductionFaultRuntimeCheckpoint {
            runtime,
            host,
            qemu_fingerprints,
            qemu_fault_sequences,
            identity,
        })
    }

    /// Returns committed typed host actions consumed by network and storage.
    #[must_use]
    pub const fn host_state(&self) -> &HostFaultActionState {
        self.host.state()
    }

    /// Removes committed host impulses for exact device-opportunity execution.
    ///
    /// Callers must apply the returned actions before evaluating another fault
    /// boundary or opportunity; the host sink rejects new work while impulses
    /// remain unconsumed.
    pub fn drain_host_impulses(&mut self) -> Vec<crucible::model::ResolvedBindingAction> {
        self.host.state_mut().drain_impulses()
    }
}

fn production_checkpoint_identity(
    plan: ContentHash,
    runtime: Option<&FaultRuntimeCheckpoint>,
    host: &HostFaultActionState,
    qemu_fingerprints: &BTreeMap<NodeId, ContentHash>,
    qemu_fault_sequences: &BTreeMap<NodeId, u64>,
) -> ContentHash {
    let mut material = Vec::new();
    material.extend_from_slice(&plan.bytes);
    material.extend_from_slice(&host.digest().bytes);
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
    for (node, fingerprint) in qemu_fingerprints {
        material.extend_from_slice(node.name.as_bytes());
        material.push(0);
        material.extend_from_slice(&fingerprint.bytes);
        if let Some(sequence) = qemu_fault_sequences.get(node) {
            material.extend_from_slice(&sequence.to_be_bytes());
        }
    }
    ContentHash::from_canonical_material(
        "crucible.production-fault-runtime-checkpoint.v1",
        &hex_bytes(&material),
    )
}

fn production_manifests(
    nodes: &QemuNodeSet,
) -> Result<FaultAdapterManifests, ProductionFaultRuntimeError> {
    Ok(FaultAdapterManifests {
        network: host_production_manifest("network-host", &[EffectKind::NetworkAvailability])?,
        storage: host_production_manifest("storage-host", &[])?,
        node: nodes.fault_capability_manifest()?,
    })
}

fn host_production_manifest(
    backend: &str,
    effects: &[EffectKind],
) -> Result<FaultCapabilityManifest, ProductionFaultRuntimeError> {
    let backend = FaultObjectId::parse(backend)
        .map_err(crucible::model::FaultRuntimeError::Contract)
        .map_err(FaultExecutionError::from)?;
    let capabilities = effects
        .iter()
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
        BindingMapping, BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy,
        EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest, EffectSpecification,
        EvaluatedSignal, FaultBinding, FaultDirection, FaultPhase, InverseCdfTable,
        NetworkAvailabilityState, NetworkEffectSpecification, NetworkInFlightPolicy,
        ResolvedFaultTarget, ResolvedTargetSet, SampleObservation, SignalChoiceContext,
        SignalCoordinate, SignalDomain, SignalEvaluationError, SignalId, SignalNode,
        SignalNodeKind, SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit,
        SignalValue, SignalValueType, TargetSelector,
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

    fn availability_plan(target: &ResolvedFaultTarget) -> FaultSignalPlan {
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
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
        let binding = FaultBinding::new(
            object_id("network-down-binding"),
            program.exported_outputs().to_vec(),
            BindingSampling::AtBoundary,
            BindingMapping::ActiveWhenTrue { invert: false },
            TargetSelector::Exact(targets),
            [FaultPhase::Admit].into_iter().collect(),
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
    fn production_host_manifest_does_not_advertise_unimplemented_effects() {
        let network = host_production_manifest("network-host", &[EffectKind::NetworkAvailability])
            .unwrap_or_else(|error| panic!("network manifest should build: {error}"));
        let availability =
            FaultCapabilityId::parse(EffectKind::NetworkAvailability.descriptor().capability)
                .unwrap_or_else(|error| panic!("availability capability should parse: {error}"));
        let mtu = FaultCapabilityId::parse(EffectKind::NetworkMtu.descriptor().capability)
            .unwrap_or_else(|error| panic!("MTU capability should parse: {error}"));
        assert_eq!(network.capabilities.len(), 1);
        assert!(network.capabilities.contains(&availability));
        assert!(!network.capabilities.contains(&mtu));

        let storage = host_production_manifest("storage-host", &[])
            .unwrap_or_else(|error| panic!("empty storage manifest should build: {error}"));
        assert!(storage.capabilities.is_empty());
    }

    #[test]
    fn production_availability_survives_checkpoint_restore() {
        let target = ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-left-right"),
            direction: FaultDirection::AToB,
        };
        let plan = availability_plan(&target);
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
}
