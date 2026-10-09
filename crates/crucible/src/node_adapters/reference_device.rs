//! Common quantized-node adapter for the actual controlled checksum child.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::Path,
    rc::Rc,
    task::{Context, Poll, Waker},
};

use crucible_node_contract::{
    CaptureScope, ContentRef, Continuation, Direction, Endpoint, Id, NodeBinding, NodeDescriptor,
    Phase, Position, U64, canonical,
};
use crucible_node_provider::reference_device::{
    DeviceGrant, DeviceReceipt, DeviceStatus, MAX_INPUT_BYTES, ReferenceDevice,
};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::*,
    node_scheduling::{
        ExecutionPolicy, InputIdentity, InputPayload, NativeInputAcknowledgement,
        NativeInputProgress, NativeOutputBound, NativeProducerBound, NativePublication,
        NativeSchedulingObservation, RuntimeInputBatch,
    },
};

pub(crate) mod control;
pub use control::ControlledReference;

/// Identifies the installed coarse controlled-checksum execution facet.
pub const REFERENCE_DEVICE_QUANTIZED_PROFILE: &str = "reference-device/quantized-v1";

/// Authenticates the actual prepared child and its complete realized profile.
///
/// The host must check installed qualification, private-peer custody, live
/// session/realization identity and all future-affecting state. The adapter also
/// independently measures the actual running executable and checks the native
/// owner identity. A syntax-valid content reference cannot issue authority.
pub trait ReferenceDeviceQualification {
    /// Qualifies the original prepared native child against the sealed contract.
    ///
    /// # Errors
    /// Rejects unqualified binaries, source-family mismatch, incomplete live
    /// authority, unsupported input/output schemas or a changed selected profile.
    fn authenticate_child(
        &self,
        child: &ReferenceDevice,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure>;
}

struct Staged {
    original: Rc<RuntimeInputBatch>,
    bytes: Vec<u8>,
    acknowledgement: NativeInputAcknowledgement,
}

struct Window {
    original: OperationAdmission,
    grant: DeviceGrant,
    input: Rc<RuntimeInputBatch>,
    receipt: Option<DeviceReceipt>,
    outcome: Option<OperationOutcome>,
    evidence: Vec<InputPayload>,
    acknowledged: bool,
    failure: Option<OperationFailure>,
}

struct QuantizedDescription(Id);
impl FacetDescription for QuantizedDescription {
    fn profile(&self) -> &Id {
        &self.0
    }
}
impl RoleDescription for QuantizedDescription {
    fn role_profile(&self) -> &Id {
        &self.0
    }
}

/// Integrates an actual controlled child with immutable input cuts and host grants.
///
/// The profile deliberately supports coarse controller-window visibility only.
/// Application-level park does not establish physical OS suspension. Native
/// process memory preservation, durable restart and exact execution are refused.
pub struct ControlledReferenceNode<C: ControlledReference> {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    child: C,
    world_hash: crucible_node_contract::HashRef,
    thread: std::thread::ThreadId,
    profile: QuantizedDescription,
    quantum_ps: u64,
    host_budget_ns: u64,
    next_quantum: U64,
    boundary: Position,
    output: Endpoint,
    ready: Option<(ActivationRecord, ReadyAttestation)>,
    activation_authority: Option<Rc<()>>,
    staged: Option<Staged>,
    windows: BTreeMap<Id, Window>,
    active: Option<Id>,
    waiter: Option<Waker>,
    maximum_operations: usize,
    reclaimed: Option<NativeReclamationReceipt>,
    quarantined: bool,
    observation: Option<(WorldActivation, NativeSchedulingObservation)>,
    boundary_evidence: BTreeMap<crucible_node_contract::HashRef, InputPayload>,
    boundary_evidence_bytes: usize,
    boundary_evidence_activation: Option<WorldActivation>,
}

/// Retains the original native reference-device adapter and constructor API.
pub type ReferenceDeviceNode = ControlledReferenceNode<ReferenceDevice>;

impl ControlledReferenceNode<ReferenceDevice> {
    /// Takes custody of a real prepared child already authenticated by admission.
    ///
    /// Preparation precedes whole-graph sealing; this constructor does not create
    /// native authority by spawning a replacement after admission. The actual
    /// executable is measured through `/proc/<pid>/exe` using bounded streaming.
    ///
    /// # Errors
    /// Rejects inactive-child, owner, executable, selected mode/facet/schema or
    /// initialization mismatch; unsupported state fidelity; and invalid limits.
    pub fn from_prepared(
        graph: &AdmittedGraph,
        node: &Id,
        child: ReferenceDevice,
        qualification: &dyn ReferenceDeviceQualification,
        maximum_operations: usize,
    ) -> Result<Self, OperationFailure> {
        Self::from_controlled_prepared(
            graph,
            node,
            child,
            &|child, descriptor, binding| {
                qualification.authenticate_child(child, descriptor, binding)
            },
            maximum_operations,
        )
    }
}

impl<C: ControlledReference> ControlledReferenceNode<C> {
    pub(crate) fn from_controlled_prepared(
        graph: &AdmittedGraph,
        node: &Id,
        child: C,
        authenticate: &impl Fn(&C, &NodeDescriptor, &NodeBinding) -> Result<(), OperationFailure>,
        maximum_operations: usize,
    ) -> Result<Self, OperationFailure> {
        let descriptor = graph
            .descriptor(node)
            .ok_or_else(|| no_effect("external node absent from sealed graph"))?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| no_effect("external binding absent from sealed graph"))?;
        let guarantees = graph
            .guarantees(node)
            .ok_or_else(|| no_effect("external guarantee scope absent"))?;
        if maximum_operations == 0
            || maximum_operations > 65_536
            || descriptor.roles.len() != 1
            || descriptor.roles[0].as_str() != "external_device"
            || binding.compatibility.execution_owner != binding.compatibility.capture_owner
            || binding
                .compatibility
                .execution_owner
                .participant_ids
                .as_slice()
                != std::slice::from_ref(node)
            || child.status() != DeviceStatus::Parked
            || child.owner_id() != &binding.compatibility.execution_owner.id
            || child.incarnation_id() != &binding.authority.incarnation_id
            || child.generation() != binding.authority.owner_generation
            || guarantees.capture_scope != CaptureScope::None
            || guarantees.continuation != Continuation::Unsupported
            || guarantees.durable_restart
            || guarantees.isolated_fork
            || guarantees.conditional_replay
        {
            return Err(no_effect(
                "reference child role, live custody or limited-state profile mismatch",
            ));
        }
        let (quantum_ps, host_budget_ns) = match graph.operating_policy(node) {
            Some(ExecutionPolicy::Quantized {
                quantum_ps,
                phase_ps,
                host_budget_ns,
                ..
            }) if phase_ps.get() == 0 => (quantum_ps.get(), host_budget_ns.get()),
            _ => {
                return Err(no_effect(
                    "reference child requires a phase-zero quantized policy",
                ));
            }
        };
        let profile =
            Id::new("reference-device/quantized-v1").map_err(|e| no_effect(&e.to_string()))?;
        let selected = &binding.compatibility.operating_contract.facets;
        if selected.len() != 1 || selected[0].id != profile || selected[0].version != 1 {
            return Err(no_effect(
                "reference child selected facet differs from installed profile",
            ));
        }
        authenticate(&child, descriptor, binding)?;
        let executable = binding
            .compatibility
            .implementation
            .artifacts
            .iter()
            .find(|artifact| artifact.role.as_str() == "device-executable")
            .ok_or_else(|| no_effect("admitted actual device executable identity absent"))?;
        verify_executable(
            Path::new(&format!("/proc/{}/exe", child.child_pid())),
            &executable.content,
        )?;
        let initial = initial_bytes()?;
        let initial_ref =
            canonical::content_ref(&initial, &descriptor.initialization_ref.media_type)
                .map_err(|e| no_effect(&e.to_string()))?;
        if initial_ref != descriptor.initialization_ref {
            return Err(no_effect(
                "native initialized checksum state differs from admitted initialization",
            ));
        }
        let mut outputs = descriptor.ports.iter().flat_map(|port| {
            port.lanes
                .iter()
                .filter(|lane| lane.direction == Direction::Output)
                .map(move |lane| Endpoint {
                    node_id: node.clone(),
                    port_id: port.id.clone(),
                    lane_id: lane.id.clone(),
                })
        });
        let output = outputs
            .next()
            .ok_or_else(|| no_effect("reference output lane absent"))?;
        if outputs.next().is_some() {
            return Err(no_effect(
                "reference profile supports exactly one output lane",
            ));
        }
        let owner = OwnerIdentity {
            owner: binding.compatibility.execution_owner.id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        Ok(Self {
            descriptor: descriptor.clone(),
            binding: binding.clone(),
            route: NodeRoute {
                node: node.clone(),
                owners: vec![owner],
            },
            child,
            world_hash: graph.world_binding_hash().clone(),
            thread: std::thread::current().id(),
            profile: QuantizedDescription(profile),
            quantum_ps,
            host_budget_ns,
            next_quantum: 0.into(),
            boundary: root(0, Phase::BoundaryControl),
            output,
            ready: None,
            activation_authority: None,
            staged: None,
            windows: BTreeMap::new(),
            active: None,
            waiter: None,
            maximum_operations,
            reclaimed: None,
            quarantined: false,
            observation: None,
            boundary_evidence: BTreeMap::new(),
            boundary_evidence_bytes: 0,
            boundary_evidence_activation: None,
        })
    }

    fn same_world(&self, activation: &WorldActivation) -> bool {
        self.ready
            .as_ref()
            .is_some_and(|(record, _)| record == activation.record())
            && self
                .activation_authority
                .as_ref()
                .is_none_or(|authority| Rc::ptr_eq(authority, &activation.authority))
    }

    fn reserve_boundary_evidence(&self, object: &InputPayload) -> Result<(), OperationFailure> {
        object
            .reference
            .verify(&object.bytes)
            .map_err(|error| no_effect(&error.to_string()))?;
        if let Some(original) = self.boundary_evidence.get(&object.reference.hash) {
            if original != object {
                return Err(no_effect(
                    "original reference proof content or metadata changed",
                ));
            }
            return Ok(());
        }
        // Historical proofs remain available after ACK. Admission bounds their
        // complete lifetime inventory rather than discarding earlier custody.
        if self.boundary_evidence.len()
            >= self.maximum_operations.saturating_mul(2).saturating_add(1)
            || self
                .boundary_evidence_bytes
                .checked_add(object.bytes.len())
                .is_none_or(|total| total > 16 * 1024 * 1024)
        {
            return Err(no_effect(
                "reference historical boundary proof inventory exhausted",
            ));
        }
        Ok(())
    }

    fn retain_boundary_evidence(
        &mut self,
        activation: &WorldActivation,
        object: InputPayload,
    ) -> Result<(), OperationFailure> {
        self.reserve_boundary_evidence(&object)?;
        if !self.same_world(activation)
            || self
                .boundary_evidence_activation
                .as_ref()
                .is_some_and(|original| {
                    original.record() != activation.record()
                        || !Rc::ptr_eq(&original.authority, &activation.authority)
                })
        {
            return Err(no_effect("reference boundary evidence activation changed"));
        }
        if !self.boundary_evidence.contains_key(&object.reference.hash) {
            self.boundary_evidence_bytes += object.bytes.len();
            self.boundary_evidence
                .insert(object.reference.hash.clone(), object);
        }
        self.boundary_evidence_activation = Some(activation.clone());
        Ok(())
    }

    fn original(&self, token: &OperationToken) -> Result<&Window, OperationFailure> {
        let window = self
            .windows
            .get(token.operation())
            .ok_or_else(|| no_effect("unknown original device operation"))?;
        if token.route() != &self.route
            || !Rc::ptr_eq(&window.original.token.authority, &token.authority)
        {
            return Err(no_effect("foreign original device operation custody"));
        }
        Ok(window)
    }

    fn observation(
        &self,
        receipt: &DeviceReceipt,
        input: &RuntimeInputBatch,
        operation: &Id,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        let payload_bytes = json_bytes(&receipt.output)?;
        let payload = canonical::content_ref(&payload_bytes, self.child.output_media_type())
            .map_err(|e| no_effect(&e.to_string()))?;
        let proof = canonical::content_ref(&json_bytes(receipt)?, "application/json")
            .map_err(|e| no_effect(&e.to_string()))?;
        let local_publication_id = Id::new(format!(
            "output/{}",
            canonical::hash(
                "cnp.reference-publication.v1",
                operation.as_str().as_bytes()
            )
            .map_err(|e| no_effect(&e.to_string()))?
            .digest
        ))
        .map_err(|e| no_effect(&e.to_string()))?;
        let (publication_id, native_sequence) = self
            .child
            .publication_identity(receipt)?
            .unwrap_or((local_publication_id, receipt.grant.quantum));
        let next = receipt
            .grant
            .publication
            .time_ps
            .get()
            .checked_add(self.quantum_ps)
            .ok_or_else(|| no_effect("next reference-device boundary overflow"))?;
        Ok(NativeSchedulingObservation {
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            reached: root(
                receipt.grant.publication.time_ps.get(),
                Phase::BoundaryControl,
            ),
            closed_prefix: root(
                receipt.grant.publication.time_ps.get(),
                Phase::BoundaryControl,
            ),
            bounds: vec![NativeProducerBound {
                producer: self.route.node.clone(),
                bound: NativeOutputBound::At(root(next, Phase::Publication)),
                proof_ref: proof.clone(),
            }],
            publications: vec![NativePublication {
                publication_id,
                endpoint: self.output.clone(),
                native_sequence,
                publication: receipt.grant.publication,
                evaluation: None,
                causal_parents: input
                    .deliveries()
                    .iter()
                    .map(|delivery| delivery.delivery)
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                payload,
                payload_bytes,
            }],
            external_inputs: Vec::new(),
            input_progress: Some(NativeInputProgress {
                batch: input.batch().clone(),
                consumed: input
                    .deliveries()
                    .iter()
                    .map(|delivery| InputIdentity {
                        producer: delivery.producer.clone(),
                        source_sequence: delivery.source_sequence,
                    })
                    .collect(),
                proof_ref: proof.clone(),
            }),
            proof_ref: proof,
        })
    }
}

impl<C: ControlledReference> ExternalDeviceNode for ControlledReferenceNode<C> {
    fn external_description(&self) -> &dyn RoleDescription {
        &self.profile
    }
}

#[path = "reference_device/runtime.rs"]
mod runtime;

fn root(time_ps: u64, phase: Phase) -> Position {
    Position::new(time_ps.into(), 0.into(), phase)
}
fn json_bytes(value: &impl serde::Serialize) -> Result<Vec<u8>, OperationFailure> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(|e| no_effect(&e.to_string()))?)
        .map_err(|e| no_effect(&e.to_string()))
}
/// Encodes the actual freshly initialized controlled checksum application state.
///
/// These bytes describe the private source-built application protocol, not a
/// process-memory checkpoint. The initialized child must independently confirm
/// this state before the host seals its live binding.
///
/// # Errors
/// Returns a serialization error when the canonical state cannot be encoded.
pub fn reference_device_initial_bytes() -> Result<Vec<u8>, OperationFailure> {
    json_bytes(
        &serde_json::json!({"schema_version":1,"quantum":"0","bytes_processed":"0","checksum":"0","input":"empty"}),
    )
}

fn initial_bytes() -> Result<Vec<u8>, OperationFailure> {
    reference_device_initial_bytes()
}
fn no_effect(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}
fn native_failure(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: reason.into(),
    }
}

fn verify_executable(path: &Path, expected: &ContentRef) -> Result<(), OperationFailure> {
    if expected.hash.algorithm != "blake3-256" || expected.length.get() > 512 * 1024 * 1024 {
        return Err(no_effect(
            "reference executable identity exceeds bounded installed profile",
        ));
    }
    let mut file = File::open(path).map_err(|e| no_effect(&e.to_string()))?;
    if file
        .metadata()
        .map_err(|e| no_effect(&e.to_string()))?
        .len()
        != expected.length.get()
    {
        return Err(no_effect(
            "actual running reference executable length mismatch",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&(expected.hash.domain.len() as u32).to_be_bytes());
    hasher.update(expected.hash.domain.as_bytes());
    hasher.update(&expected.length.get().to_be_bytes());
    let mut bytes = [0u8; 8192];
    let mut read = 0u64;
    loop {
        let count = file
            .read(&mut bytes)
            .map_err(|e| no_effect(&e.to_string()))?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(count as u64)
            .filter(|length| *length <= expected.length.get())
            .ok_or_else(|| no_effect("actual reference executable changed during measurement"))?;
        hasher.update(&bytes[..count]);
    }
    if read != expected.length.get() || hasher.finalize().to_hex().as_str() != expected.hash.digest
    {
        return Err(no_effect(
            "actual running executable differs from admitted device artifact",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "reference_device_tests.rs"]
mod tests;
