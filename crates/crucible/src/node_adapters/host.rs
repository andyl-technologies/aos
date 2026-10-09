//! Exact event execution, inactive readiness and complete custody of owned host models.

use std::{
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible_device::{clock::VirtualClock, netlink::NetLink};
use crucible_node_contract::{
    ContentRef, Direction, Endpoint, HashRef, Id, NodeBinding, NodeDescriptor, Phase, Position,
    canonical,
};

use crate::{device_subnode::ScheduledIoNode, node_admission::AdmittedGraph, node_contract::*};

pub use state::archive::{HostContinuationInventory, validate_host_continuation};

/// Identifies the complete host-model preservation facet.
pub const HOST_PRESERVATION_PROFILE: &str = "host/preservation-v1";
/// Identifies genuine suspension of a locally owned nonautonomous host model.
pub const HOST_PHYSICAL_PAUSE_PROFILE: &str = "host/physical-pause-v1";
/// Identifies bounded exact host-model event execution and boundary settlement.
pub const HOST_EXACT_PROFILE: &str = "host/exact-v1";

/// Encodes the complete integer clock continuation without guest timer state.
pub fn host_clock_initial_bytes(time_ps: u64) -> Vec<u8> {
    let mut bytes = b"crucible.host-clock.v1\0".to_vec();
    bytes.extend_from_slice(&time_ps.to_le_bytes());
    bytes
}

/// Contains an actual deterministic model with exclusive local custody.
pub enum HostModel {
    /// Owns the complete block or filesystem device and scheduler bridge.
    Io(Box<ScheduledIoNode>),
    /// Owns the directed link's full pending deliveries, faults and RNG cursor.
    Link(Box<NetLink>),
    /// Owns an exact integer coordinator-clock model, without guest timers.
    Clock(VirtualClock),
    /// Owns a finite immutable public request script and its exact native cursor.
    ScriptedSource(Box<super::ScriptedSource>),
}

impl HostModel {
    /// Encodes the complete native initialization state using its existing codec.
    ///
    /// # Errors
    /// Rejects codec failures or state exceeding the requested retention ceiling.
    pub fn initialization_bytes(&self, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
        self.capture(maximum)
    }
    fn role(&self) -> &'static str {
        match self {
            Self::Io(node) if node.block_device().is_some() => "block",
            Self::Io(_) => "filesystem",
            Self::Link(_) => "network_link",
            Self::Clock(_) => "clock",
            Self::ScriptedSource(_) => "scripted_source",
        }
    }

    fn time_ps(&self) -> Result<u64, OperationFailure> {
        match self {
            Self::Io(node) => node
                .block_device()
                .map(|d| d.core().current_icount())
                .or_else(|| node.ninep_device().map(|d| d.core().current_icount()))
                .ok_or_else(|| failure("unknown concrete host I/O device")),
            Self::Link(link) => Ok(link.current_icount()),
            Self::Clock(clock) => Ok(clock.current_icount()),
            Self::ScriptedSource(source) => Ok(source.time_ps()),
        }
    }

    fn capture(&self, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
        let bytes = match self {
            Self::Io(node) => node
                .checkpoint()
                .canonical_bytes()
                .map_err(|e| failure(&e.to_string()))?,
            Self::Link(link) => link
                .snapshot()
                .canonical_bytes_with_limit(maximum as u64)
                .map_err(|e| failure(&e.to_string()))?,
            Self::Clock(clock) => host_clock_initial_bytes(clock.current_icount()),
            Self::ScriptedSource(source) => source.capture()?,
        };
        if bytes.len() > maximum {
            return Err(failure(
                "host model continuation exceeds admitted byte ceiling",
            ));
        }
        Ok(bytes)
    }
}

/// Authenticates installed host code and complete immutable model inputs.
///
/// This trusted host boundary must inspect the actual supplied model, its
/// immutable block base or served filesystem tree, installed implementation
/// artifacts and selected profile. Matching a label, hash syntax, or mutable
/// checkpoint alone is insufficient. Implementations must not accept a vendor
/// self-issued qualification claim.
pub trait HostModelQualification {
    /// Qualifies the actual owned model and realized contract without effects.
    ///
    /// # Errors
    /// Rejects missing installed-code evidence, immutable artifact mismatches,
    /// unsupported model semantics or incomplete future-affecting inventory.
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure>;

    /// Authenticates complete native capture and isolated original custody lineage.
    ///
    /// # Errors
    /// The default refuses restoration. Installed implementations must verify
    /// the actual complete capture, immutable native inputs, original host
    /// runtime inventory and fresh destination owner generations.
    fn authenticate_continuation(
        &self,
        _model: &HostModel,
        _descriptor: &NodeDescriptor,
        _binding: &NodeBinding,
        _native: &[u8],
        _source: &RuntimeSnapshot,
        _target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        Err(failure(
            "installed host continuation qualification unavailable",
        ))
    }
}

/// Bounds host continuation and original-operation evidence custody.
#[derive(Clone, Copy, Debug)]
pub struct HostModelResources {
    /// Bounds each native continuation retained by the administrative adapter.
    pub maximum_capture_bytes: usize,
    /// Bounds original operation tombstones, which are never recycled.
    pub maximum_operations: usize,
}

impl Default for HostModelResources {
    fn default() -> Self {
        Self {
            maximum_capture_bytes: 16 * 1024 * 1024,
            maximum_operations: 65_536,
        }
    }
}

struct Completed {
    original: OperationAdmission,
    outcome: OperationOutcome,
    capture: Option<Rc<Vec<u8>>>,
    acknowledged: bool,
    evidence: Vec<crate::node_scheduling::InputPayload>,
}

/// Exposes a genuinely owned host model through common node operations.
///
/// The qualified exact facet settles authentic staged requests and pending
/// device or link events within half-open grants. Administrative profiles also
/// support inactive readiness, physical suspension, complete preservation and
/// supervised destruction. Legacy model codecs remain unchanged.
pub struct HostModelNode {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    model: Option<HostModel>,
    initial: Rc<Vec<u8>>,
    boundary: Position,
    thread: std::thread::ThreadId,
    facets: Vec<FacetKind>,
    preservation: HostFacet,
    pause: HostFacet,
    world_hash: HashRef,
    limits: HostModelResources,
    readiness: Option<(ActivationRecord, ReadyAttestation)>,
    completed: BTreeMap<Id, Completed>,
    failed: BTreeMap<Id, (OperationAdmission, OperationFailure)>,
    reclamations: BTreeMap<OwnerIdentity, NativeReclamationReceipt>,
    quarantined: bool,
    activation_authority: Option<Rc<()>>,
    execution: HostFacet,
    input_endpoint: Option<Endpoint>,
    output_endpoint: Option<Endpoint>,
    maximum_microsteps: crucible_node_contract::U64,
    staged: Option<execution::Staged>,
    input_history: BTreeMap<Id, execution::Staged>,
    pending_causes: BTreeMap<(u64, u32, u32), Vec<Position>>,
    native_sequence: u64,
    scheduling_observation: Option<(
        WorldActivation,
        crate::node_scheduling::NativeSchedulingObservation,
    )>,
    prepared_continuation: Option<state::PreparedHostContinuation>,
    readiness_inventory: ContentRef,
}

impl HostModelNode {
    /// Takes exclusive custody of a qualified inactive model from a sealed graph.
    ///
    /// Initialization bytes must be the model's actual existing continuation
    /// codec. The clock edition uses its documented little-endian integer tick.
    /// Distinct execution/capture owners require a shared owning actor and are
    /// refused by this single-owner adapter.
    ///
    /// # Errors
    /// Rejects absent graph membership, unsupported selected facets, incomplete
    /// installed-model qualification, owner aliasing, initialization mismatch,
    /// or exceeded native continuation/resource ceilings.
    pub fn new(
        graph: &AdmittedGraph,
        node: &Id,
        model: HostModel,
        qualification: &dyn HostModelQualification,
        limits: HostModelResources,
    ) -> Result<Self, OperationFailure> {
        let descriptor = graph
            .descriptor(node)
            .ok_or_else(|| failure("host node absent from sealed graph"))?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| failure("host binding absent from sealed graph"))?;
        if limits.maximum_capture_bytes == 0
            || limits.maximum_operations == 0
            || descriptor.roles.len() != 1
            || descriptor.roles[0].as_str() != model.role()
            || binding.compatibility.execution_owner != binding.compatibility.capture_owner
            || binding
                .compatibility
                .execution_owner
                .participant_ids
                .as_slice()
                != std::slice::from_ref(node)
        {
            return Err(failure(
                "host model role, single-owner custody or resource contract mismatch",
            ));
        }
        qualification.authenticate_model(&model, descriptor, binding)?;
        let mut facets = Vec::new();
        let preservation = Id::new("host/preservation-v1").map_err(|e| failure(&e.to_string()))?;
        let pause = Id::new("host/physical-pause-v1").map_err(|e| failure(&e.to_string()))?;
        let execution = Id::new(HOST_EXACT_PROFILE).map_err(|e| failure(&e.to_string()))?;
        for selected in &binding.compatibility.operating_contract.facets {
            if selected.id == preservation {
                facets.push(FacetKind::Preservation);
            } else if selected.id == pause {
                facets.push(FacetKind::PhysicalPause);
            } else if selected.id == execution && selected.version == 1 {
                facets.push(FacetKind::ExactExecution);
            } else {
                return Err(failure(
                    "host selected facet lacks an installed execution adapter",
                ));
            }
        }
        facets.sort();
        let (input_endpoint, output_endpoint) =
            execution::validate_inventory(graph, node, &model, &facets)?;
        let initial = model.capture(limits.maximum_capture_bytes)?;
        let reference = canonical::content_ref(&initial, &descriptor.initialization_ref.media_type)
            .map_err(|e| failure(&e.to_string()))?;
        if reference != descriptor.initialization_ref {
            return Err(failure(
                "actual host continuation differs from admitted initialization",
            ));
        }
        let boundary = Position::new(model.time_ps()?.into(), 0.into(), Phase::BoundaryControl);
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
            model: Some(model),
            initial: Rc::new(initial),
            boundary,
            thread: std::thread::current().id(),
            facets,
            preservation: HostFacet(preservation),
            pause: HostFacet(pause),
            world_hash: graph.world_binding_hash().clone(),
            limits,
            readiness: None,
            completed: BTreeMap::new(),
            failed: BTreeMap::new(),
            reclamations: BTreeMap::new(),
            quarantined: false,
            activation_authority: None,
            execution: HostFacet(execution),
            input_endpoint,
            output_endpoint,
            maximum_microsteps: graph.coordinator_policy().maximum_microsteps_per_instant,
            staged: None,
            input_history: BTreeMap::new(),
            pending_causes: BTreeMap::new(),
            native_sequence: 0,
            scheduling_observation: None,
            prepared_continuation: None,
            readiness_inventory: descriptor.initialization_ref.clone(),
        })
    }

    /// Returns the actual retained continuation for an original completed capture.
    ///
    /// # Errors
    /// Rejects foreign token custody or an operation that did not capture state.
    pub fn captured_bytes(&self, original: &OperationToken) -> Result<&[u8], OperationFailure> {
        self.original(original)?
            .capture
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .ok_or_else(|| failure("original operation did not capture state"))
    }

    fn original(&self, token: &OperationToken) -> Result<&Completed, OperationFailure> {
        let completed = self
            .completed
            .get(token.operation())
            .ok_or_else(|| failure("unknown original host operation"))?;
        if !Rc::ptr_eq(&completed.original.token.authority, &token.authority)
            || token.route() != &self.route
        {
            return Err(failure("foreign host operation authority"));
        }
        Ok(completed)
    }

    fn capture(&self) -> Result<Vec<u8>, OperationFailure> {
        self.model
            .as_ref()
            .ok_or_else(|| failure("host model released"))?
            .capture(self.limits.maximum_capture_bytes)
    }

    fn receipt(&self, label: &str) -> Result<ContentRef, OperationFailure> {
        canonical::content_ref(&self.receipt_bytes(label), "application/octet-stream")
            .map_err(|e| failure(&e.to_string()))
    }

    fn receipt_bytes(&self, label: &str) -> Vec<u8> {
        let mut bytes = label.as_bytes().to_vec();
        bytes.extend_from_slice(&self.boundary.time_ps.get().to_le_bytes());
        for owner in &self.route.owners {
            bytes.extend_from_slice(owner.owner.as_str().as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(owner.incarnation.as_str().as_bytes());
            bytes.extend_from_slice(&owner.generation.get().to_le_bytes());
        }
        bytes
    }
}

impl FacetDescription for HostModelNode {
    fn profile(&self) -> &Id {
        &self.preservation.0
    }
}

struct HostFacet(Id);
impl FacetDescription for HostFacet {
    fn profile(&self) -> &Id {
        &self.0
    }
}

impl SimulationNode for HostModelNode {
    fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }
    fn binding(&self) -> &NodeBinding {
        &self.binding
    }
    fn route(&self) -> &NodeRoute {
        &self.route
    }
    fn thread_affinity(&self) -> ThreadAffinity {
        ThreadAffinity::OwnerThread(self.thread)
    }
    fn facets(&self) -> &[FacetKind] {
        &self.facets
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        Ok(NodeStatus {
            lifecycle: if self.model.is_none() {
                Lifecycle::Released
            } else if self.quarantined {
                Lifecycle::Quarantined
            } else {
                Lifecycle::Stopped
            },
            physical: PhysicalState::Suspended,
            boundary: Some(self.boundary),
        })
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if self.quarantined
            || world.boundary != self.boundary
            || world.world_binding_hash != self.world_hash
            || !self
                .route
                .owners
                .iter()
                .all(|owner| world.owners.contains(owner))
            || self.capture()?.as_slice() != self.initial.as_slice()
        {
            return Err(failure(
                "host readiness has changed state, world or original boundary",
            ));
        }
        let ready = ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: self.boundary,
            state_inventory: self.readiness_inventory.clone(),
            ready_receipt: self.receipt("host-model-owned-inactive-v1")?,
        };
        if let Some((original, retained)) = &self.readiness
            && (original != world || retained != &ready)
        {
            return Err(failure("host already armed for another world"));
        }
        self.readiness = Some((world.clone(), ready.clone()));
        Ok(ready)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.readiness.as_ref() != Some(&(world.clone(), ready.clone()))
            || self.model.is_none()
            || self.quarantined
            || self.capture()?.as_slice() != self.initial.as_slice()
        {
            return Err(failure(
                "host readiness lacks original owned inactive state custody",
            ));
        }
        Ok(())
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        if matches!(
            admission.request(),
            OperationRequest::ExactRun { .. } | OperationRequest::BoundarySettle { .. }
        ) {
            return self.begin_exact(admission);
        }
        let run = || {
            if self.quarantined
                || self.model.is_none()
                || admission.token().route() != &self.route
                || self.readiness.as_ref().map(|r| &r.0) != Some(admission.activation().record())
                || self.activation_authority.as_ref().is_some_and(|authority| {
                    !Rc::ptr_eq(authority, &admission.activation.authority)
                })
                || self.completed.len() >= self.limits.maximum_operations
                || self.completed.contains_key(admission.token().operation())
            {
                return Err(failure(
                    "host operation lacks available original activated custody",
                ));
            }
            let (progress, capture) = match admission.request() {
                OperationRequest::Observe => (ProgressEvidence::Administrative, None),
                OperationRequest::Capture if self.facets.contains(&FacetKind::Preservation) => (
                    ProgressEvidence::Administrative,
                    Some(Rc::new(self.capture_continuation()?)),
                ),
                OperationRequest::Pause if self.facets.contains(&FacetKind::PhysicalPause) => (
                    ProgressEvidence::Paused {
                        reached: Some(self.boundary),
                        stop_receipt: self.receipt("host-model-no-autonomous-worker-v1")?,
                    },
                    None,
                ),
                OperationRequest::Shutdown => (ProgressEvidence::Administrative, None),
                _ => {
                    return Err(failure(
                        "host semantic execution requires qualified staged-input/publication adapter",
                    ));
                }
            };
            let evidence = match &progress {
                ProgressEvidence::Paused { stop_receipt, .. } => {
                    vec![crate::node_scheduling::InputPayload {
                        reference: stop_receipt.clone(),
                        bytes: self.receipt_bytes("host-model-no-autonomous-worker-v1"),
                    }]
                }
                _ => Vec::new(),
            };
            Ok((
                OperationOutcome {
                    operation: admission.token().operation().clone(),
                    node: self.route.node.clone(),
                    owners: self.route.owners.clone(),
                    progress,
                    retained_outputs: Vec::new(),
                    scheduling: None,
                },
                capture,
                evidence,
            ))
        };
        match run() {
            Err(error) => Submission::Refused(Refusal {
                reason: error.reason,
            }),
            Ok((outcome, capture, evidence)) => {
                self.activation_authority = Some(Rc::clone(&admission.activation.authority));
                if matches!(admission.request(), OperationRequest::Shutdown) {
                    self.model.take();
                }
                self.completed.insert(
                    outcome.operation.clone(),
                    Completed {
                        original: admission.clone(),
                        outcome,
                        capture,
                        acknowledged: false,
                        evidence,
                    },
                );
                Submission::Accepted
            }
        }
    }

    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        _context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        if let Some((original, failure)) = self.failed.get(operation.operation()) {
            return Poll::Ready(
                if Rc::ptr_eq(&original.token.authority, &operation.authority)
                    && operation.route() == &self.route
                {
                    Err(failure.clone())
                } else {
                    Err(self::failure("foreign failed host operation authority"))
                },
            );
        }
        Poll::Ready(
            self.original(operation)
                .map(|completed| completed.outcome.clone()),
        )
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        let completed = self.original(original.token())?;
        if completed.outcome != *outcome
            || completed.original.request() != original.request()
            || !Rc::ptr_eq(
                &completed.original.activation.authority,
                &original.activation.authority,
            )
        {
            return Err(failure(
                "host outcome lacks original retained operation custody",
            ));
        }
        Ok(())
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        let completed = self.original(original.token())?;
        self.validate_outcome(original, &completed.outcome)?;
        if references.len() > completed.evidence.len() {
            return Err(failure(
                "host evidence request exceeds original retained inventory",
            ));
        }
        references
            .iter()
            .map(|reference| {
                completed
                    .evidence
                    .iter()
                    .find(|object| &object.reference == reference)
                    .cloned()
                    .ok_or_else(|| {
                        failure("host evidence is absent from original native receipt registry")
                    })
            })
            .collect()
    }

    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
        objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_operation_evidence(original, references)? != objects {
            return Err(failure("original host evidence bytes changed"));
        }
        Ok(())
    }

    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        self.original(operation)?;
        Ok(CancelStatus::Terminal)
    }

    fn close_quantum(&mut self, _original: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "host model has no quantized execution facet".into(),
        })
    }

    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let completed = self.original(operation)?;
        if completed.outcome.retained_outputs != outputs {
            return Err(failure("host output inventory mismatch"));
        }
        let original = operation.operation().clone();
        if let Some(completed) = self.completed.get_mut(&original) {
            completed.acknowledged = true;
        }
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if !self.facets.contains(&kind) {
            return Err(Refusal {
                reason: "host facet unadvertised".into(),
            });
        }
        match kind {
            FacetKind::Preservation => Ok(NodeFacet::Preservation(&self.preservation)),
            // Both profiles use distinct fields of a retained descriptor. A
            // borrowed trait object must itself outlive the returned view.
            FacetKind::PhysicalPause => Ok(NodeFacet::PhysicalPause(&self.pause)),
            FacetKind::ExactExecution => Ok(NodeFacet::ExactExecution(&self.execution)),
            _ => Err(Refusal {
                reason: "host facet unsupported".into(),
            }),
        }
    }

    fn stage_inputs(
        &mut self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<crate::node_scheduling::NativeInputAcknowledgement, OperationFailure> {
        self.stage_exact_inputs(batch)
    }

    fn capture_host_continuation(
        &self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        maximum_bytes: usize,
    ) -> Result<HostNativeCapture, OperationFailure> {
        state::capture_live(self, activation, source, maximum_bytes)
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
        acknowledgement: &crate::node_scheduling::NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.validate_staged_inputs(batch, acknowledgement)
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<crate::node_scheduling::NativeSchedulingObservation, OperationFailure> {
        self.observe_exact(activation)
    }

    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &crate::node_scheduling::NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.validate_exact_observation(activation, observation)
    }

    fn install_restored_custody(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<crate::node_scheduling::RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.install_native_custody(activation, source, operations, inputs)
    }

    fn quarantine_resources(&mut self) {
        self.quarantined = true;
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        _context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if !self.quarantined || !self.route.owners.contains(owner) {
            return Poll::Ready(Err(failure("host owner not under original quarantine")));
        }
        self.model.take();
        let result =
            self.receipt("host-model-dropped-v1")
                .map(|receipt| NativeReclamationReceipt {
                    owner: owner.clone(),
                    receipt,
                });
        if let Ok(receipt) = &result {
            self.reclamations.insert(owner.clone(), receipt.clone());
        }
        Poll::Ready(result)
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.model.is_some() || self.reclamations.get(&receipt.owner) != Some(receipt) {
            return Err(failure(
                "host model not actually destroyed under retained owner custody",
            ));
        }
        Ok(())
    }
}

#[path = "host_execution.rs"]
mod execution;

#[path = "host_state.rs"]
mod state;

pub(super) fn failure(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
