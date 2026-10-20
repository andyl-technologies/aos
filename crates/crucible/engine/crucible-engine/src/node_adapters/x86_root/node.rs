//! Owns qualified Root execution, genuine public preparation and kernel retirement.
//!
//! Public readiness is issued only from the actual original raw Ready session
//! and a current independently audited native authority. This live adapter does
//! not advertise continuation until its distinct signed Root codec is selected.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_format::{
    CaptureScope, ContentRef, Continuation, Direction, Endpoint, Id, NodeBinding, NodeDescriptor,
    OperatingMode, PreparedOwner, U64, canonical,
};
use crucible_node_transport::gem5::X86RootExactAuthority;
use serde::Serialize;

use crate::{
    node_admission::AdmittedGraph,
    node_contract::*,
    node_scheduling::{
        InputPayload, NativeOutputBound, NativeProducerBound, NativePublication,
        NativeSchedulingObservation,
    },
};

use super::{
    X86_ROOT_EXACT_PROFILE, X86RootNodePreparation,
    capture::{
        RootCapture, X86_ROOT_PRESERVATION_PROFILE, X86RootArchiveInstallation,
        x86_root_continuation_schema,
    },
    encoding,
    ledger::RootLedger,
    preparation_mapping::X86RootPreparedMapping,
    refusal,
};

/// Names the public lane carrying unchanged native UART octets.
pub const X86_ROOT_SERIAL_INTERFACE: &str = "crucible.serial/octet-output";
/// Names the byte payload format of a genuine native terminal callback.
pub const X86_ROOT_SERIAL_SCHEMA: &str = "crucible/serial-octet-v1";
/// Defines byte preservation without inventing guest stdout process identities.
pub const X86_ROOT_SERIAL_SPECIFICATION: &str = "x86 root Serial octet v1: one original PC UART terminal callback byte; native serial facet and system.pc.com_1.device identity; source-model causal parent zero; original callback event/tick ordinal and superdense birth retained; no guest PID, file descriptor, text decoding or timing-fidelity claim";

#[derive(Serialize)]
struct StoppedWire<'a> {
    schema: &'static str,
    boundary: &'a crucible_node_transport::gem5::Gem5Boundary,
    closure: &'a ContentRef,
    owners: &'a [OwnerIdentity],
    activation: SavedRuntimeActivation,
}

/// Bounds original common operations, native callbacks and retained proof bodies.
#[derive(Clone, Copy, Debug)]
pub struct X86RootNodeResources {
    /// Limits unrecycled original common operations over the owner lifetime.
    pub maximum_operations: usize,
    /// Limits unrecycled original native successful or refused Polls.
    pub maximum_prefixes: usize,
    /// Limits complete original raw receipt, preparation and output bodies.
    pub maximum_retained_bytes: usize,
    /// Limits actual callbacks in each subordinate native Poll before effects.
    pub maximum_events_per_poll: U64,
}

impl Default for X86RootNodeResources {
    fn default() -> Self {
        Self {
            maximum_operations: 1024,
            maximum_prefixes: 512,
            maximum_retained_bytes: 256 * 1024 * 1024,
            maximum_events_per_poll: 262_144.into(),
        }
    }
}

/// Retains the actual preparation and current authority after qualification fails.
pub struct X86RootQualifiedFailure {
    /// Describes the inactive common conversion refusal.
    pub error: OperationFailure,
    /// Owns the genuine stopped native peer and its reserved supervisor slot.
    pub preparation: X86RootNodePreparation,
    /// Owns the independently audited authority belonging to this actual peer.
    pub authority: X86RootExactAuthority,
    /// Retains signed original history when fresh conversion is refused.
    pub restored: Option<super::AuthenticatedX86RootContinuation>,
}

struct RootExactFacet(Id);

impl FacetDescription for RootExactFacet {
    fn profile(&self) -> &Id {
        &self.0
    }
}

/// Mediates closed source-installed Root callbacks beneath authentic common grants.
///
/// The node retains original raw successful/refused prefixes and Serial births.
/// Administrative budget ACKs never complete the common grant, and output ACKs
/// require the original common publication inventory. Restored preparation and
/// signed continuation require their separate explicitly selected codec.
pub struct QualifiedX86RootNode {
    pub(super) preparation: X86RootNodePreparation,
    pub(super) authority: X86RootExactAuthority,
    pub(super) resources: X86RootNodeResources,
    pub(super) ledger: RootLedger,
    pub(super) mapping: Option<X86RootPreparedMapping>,
    pub(super) active: Option<Id>,
    pub(super) activation_authority: Option<Rc<()>>,
    pub(super) observation: Option<(Rc<()>, NativeSchedulingObservation)>,
    pub(super) observations: Vec<ContentRef>,
    pub(super) output: Endpoint,
    pub(super) sequence: u64,
    pub(super) quarantined: bool,
    pub(super) archive: Option<X86RootArchiveInstallation>,
    pub(super) captures: Vec<RootCapture>,
    pub(super) restored: Option<super::AuthenticatedX86RootContinuation>,
    reclamation: Option<NativeReclamationReceipt>,
    thread: std::thread::ThreadId,
    facet: RootExactFacet,
    preservation: RootExactFacet,
}

impl X86RootNodePreparation {
    /// Consumes actual preparation and fresh opaque authority into a live common node.
    ///
    /// # Errors
    /// Returns complete original custody for a changed graph, unsupported lane or
    /// clock/facet contract, substituted owner, invalid finite credits, historical
    /// preparation or advertised continuation without the selected Root codec.
    pub fn into_qualified_node(
        self,
        graph: &AdmittedGraph,
        authority: X86RootExactAuthority,
        resources: X86RootNodeResources,
    ) -> Result<QualifiedX86RootNode, Box<X86RootQualifiedFailure>> {
        self.into_selected_node(graph, authority, resources, None, None)
    }

    /// Selects the preparation-bearing Root codec beneath actual native ownership.
    ///
    /// # Errors
    /// Returns the complete preparation and current authority for unavailable
    /// archive roots, unsupported selected schema/facets or foreign graph policy.
    pub fn into_qualified_preserving_node(
        self,
        graph: &AdmittedGraph,
        authority: X86RootExactAuthority,
        resources: X86RootNodeResources,
        archive: X86RootArchiveInstallation,
    ) -> Result<QualifiedX86RootNode, Box<X86RootQualifiedFailure>> {
        self.into_selected_node(graph, authority, resources, Some(archive), None)
    }

    /// Reattaches signed original Root history beneath a freshly audited native peer.
    ///
    /// Original operation permissions remain inert until the common runtime
    /// supplies its newly issued opaque restored handles after publication.
    ///
    /// # Errors
    /// Returns native custody, fresh authority and original signed history for
    /// changed source ledgers, stale owner fencing or incompatible selected policy.
    pub fn into_qualified_restored_node(
        self,
        graph: &AdmittedGraph,
        authority: X86RootExactAuthority,
        resources: X86RootNodeResources,
        archive: X86RootArchiveInstallation,
        restored: super::AuthenticatedX86RootContinuation,
    ) -> Result<QualifiedX86RootNode, Box<X86RootQualifiedFailure>> {
        self.into_selected_node(graph, authority, resources, Some(archive), Some(restored))
    }

    fn into_selected_node(
        self,
        graph: &AdmittedGraph,
        authority: X86RootExactAuthority,
        resources: X86RootNodeResources,
        archive: Option<X86RootArchiveInstallation>,
        restored: Option<super::AuthenticatedX86RootContinuation>,
    ) -> Result<QualifiedX86RootNode, Box<X86RootQualifiedFailure>> {
        let validate = || -> Result<(RootLedger, Endpoint, Id, Id), OperationFailure> {
            let node = &self.route.node;
            if graph.world_binding_hash() != &self.world_binding_hash
                || graph.descriptor(node) != Some(&self.descriptor)
                || graph.binding(node) != Some(&self.binding)
                || authority.maximum_microsteps()
                    != graph.coordinator_policy().maximum_microsteps_per_instant
                || resources.maximum_events_per_poll.get() != 262_144
                || !graph.selected_extensions().is_empty()
                || graph
                    .world()
                    .connections
                    .iter()
                    .any(|edge| &edge.consumer.node_id == node)
                || graph
                    .coordinator_policy()
                    .external_inputs
                    .iter()
                    .any(|endpoint| &endpoint.node_id == node)
            {
                return Err(refusal(
                    "x86 exact graph, finite native policy or closed ingress differs",
                ));
            }
            let operating = &self.binding.compatibility.operating_contract;
            if operating.mode != OperatingMode::Exact
                || operating.resolution_ps != Some(1.into())
                || operating.phase_ps != Some(0.into())
                || operating.facets.len() != if archive.is_some() { 2 } else { 1 }
                || !operating
                    .facets
                    .iter()
                    .any(|facet| facet.id.as_str() == X86_ROOT_EXACT_PROFILE && facet.version == 1)
                || operating.facets.iter().any(|facet| {
                    facet.version != 1
                        || (facet.id.as_str() != X86_ROOT_EXACT_PROFILE
                            && (archive.is_none()
                                || facet.id.as_str() != X86_ROOT_PRESERVATION_PROFILE))
                })
            {
                return Err(refusal(
                    "x86 source-owned exact facet or one-picosecond clock differs",
                ));
            }
            let guarantees = graph
                .guarantees(node)
                .ok_or_else(|| refusal("x86 admitted guarantees are absent"))?;
            if guarantees.capture_scope
                != if archive.is_some() {
                    CaptureScope::CompleteModel
                } else {
                    CaptureScope::None
                }
                || guarantees.continuation
                    != if archive.is_some() {
                        Continuation::Exact
                    } else {
                        Continuation::Unsupported
                    }
                || ((guarantees.durable_restart || guarantees.isolated_fork) && archive.is_none())
                || guarantees.conditional_replay
            {
                return Err(refusal(
                    "x86 live edition does not advertise an unqualified cold codec",
                ));
            }
            if let Some(archive) = &archive {
                archive.validate(&self.native)?;
                if !self
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&x86_root_continuation_schema()?)
                {
                    return Err(refusal("x86 selected preparation-bearing schema is absent"));
                }
            }
            if let Some(restored) = &restored {
                super::restore::validate_fresh(&self, &authority, resources, restored)?;
            } else {
                self.native
                    .initial_prepared_session(&authority)
                    .map_err(|error| refusal(&error.to_string()))?;
            }
            self.native
                .next_publication_bound(&authority)
                .map_err(|error| refusal(&error.to_string()))?;
            let definition =
                canonical::content_ref(X86_ROOT_SERIAL_SPECIFICATION.as_bytes(), "text/plain")
                    .map_err(|error| refusal(&error.to_string()))?;
            let mut output = None;
            for port in &self.descriptor.ports {
                if port.interface_id.as_str() != X86_ROOT_SERIAL_INTERFACE
                    || !port.features.is_empty()
                {
                    return Err(refusal("x86 terminal interface has foreign semantics"));
                }
                for lane in &port.lanes {
                    if output.is_some()
                        || lane.direction != Direction::Output
                        || lane.maximum_payload_bytes.get() != 1
                        || lane.payload_schema.id.as_str() != X86_ROOT_SERIAL_SCHEMA
                        || lane.payload_schema.version != 1
                        || lane.payload_schema.definition != definition
                    {
                        return Err(refusal(
                            "x86 selected terminal requires one genuine one-byte Serial lane",
                        ));
                    }
                    output = Some(Endpoint {
                        node_id: node.clone(),
                        port_id: port.id.clone(),
                        lane_id: lane.id.clone(),
                    });
                }
            }
            let output =
                output.ok_or_else(|| refusal("x86 genuine terminal publication lane is absent"))?;
            let ledger = RootLedger::new(
                resources.maximum_operations,
                resources.maximum_prefixes,
                resources.maximum_retained_bytes,
            )?;
            let facet =
                Id::new(X86_ROOT_EXACT_PROFILE).map_err(|error| refusal(&error.to_string()))?;
            Ok((
                ledger,
                output,
                facet,
                Id::new(X86_ROOT_PRESERVATION_PROFILE)
                    .map_err(|error| refusal(&error.to_string()))?,
            ))
        };
        match validate() {
            Ok((ledger, output, facet, preservation)) => Ok(QualifiedX86RootNode {
                preparation: self,
                authority,
                resources,
                ledger,
                output,
                mapping: None,
                active: None,
                activation_authority: None,
                observation: None,
                observations: Vec::new(),
                sequence: 0,
                quarantined: false,
                reclamation: None,
                archive,
                captures: Vec::new(),
                restored,
                thread: std::thread::current().id(),
                facet: RootExactFacet(facet),
                preservation: RootExactFacet(preservation),
            }),
            Err(error) => Err(Box::new(X86RootQualifiedFailure {
                error,
                preparation: self,
                authority,
                restored,
            })),
        }
    }
}

impl QualifiedX86RootNode {
    pub(super) fn same_world(&self, activation: &WorldActivation) -> bool {
        self.mapping
            .as_ref()
            .is_some_and(|mapping| &mapping.world == activation.record())
            && self
                .activation_authority
                .as_ref()
                .is_none_or(|original| Rc::ptr_eq(original, &activation.authority))
    }

    pub(super) fn scheduling(
        &self,
        proof: ContentRef,
        publications: Vec<NativePublication>,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        let bound = self
            .preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(|error| refusal(&error.to_string()))?
            .map_or(
                NativeOutputBound::AfterInstant(U64::new(u64::MAX)),
                NativeOutputBound::At,
            );
        let reached = self.preparation.native.logical_position();
        Ok(NativeSchedulingObservation {
            node: self.preparation.route.node.clone(),
            owners: self.preparation.route.owners.clone(),
            reached,
            closed_prefix: reached,
            bounds: vec![NativeProducerBound {
                producer: self.preparation.route.node.clone(),
                bound,
                proof_ref: proof.clone(),
            }],
            publications,
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: proof,
        })
    }

    fn validate_mapping(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.quarantined || self.active.is_some() || !self.ledger.operations.is_empty() {
            return Err(refusal(
                "x86 initial public preparation has acquired later custody",
            ));
        }
        self.mapping
            .as_ref()
            .ok_or_else(|| refusal("x86 original public mapping is absent"))?
            .validate_current(
                &self.preparation,
                &self.authority,
                world,
                ready,
                self.restored.as_ref(),
            )
    }
}

impl SimulationNode for QualifiedX86RootNode {
    fn descriptor(&self) -> &NodeDescriptor {
        &self.preparation.descriptor
    }
    fn binding(&self) -> &NodeBinding {
        &self.preparation.binding
    }
    fn route(&self) -> &NodeRoute {
        &self.preparation.route
    }
    fn thread_affinity(&self) -> ThreadAffinity {
        ThreadAffinity::OwnerThread(self.thread)
    }
    fn facets(&self) -> &[FacetKind] {
        if self.archive.is_some() {
            &[FacetKind::ExactExecution, FacetKind::Preservation]
        } else {
            &[FacetKind::ExactExecution]
        }
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        Ok(NodeStatus {
            lifecycle: if self.quarantined {
                Lifecycle::Quarantined
            } else if self.active.is_some() {
                Lifecycle::Executing
            } else {
                Lifecycle::Stopped
            },
            physical: PhysicalState::Unknown,
            boundary: (!self.quarantined).then(|| self.preparation.native.logical_position()),
        })
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if self.quarantined || self.active.is_some() || !self.ledger.operations.is_empty() {
            return Err(refusal(
                "x86 initial Ready requires untouched original native custody",
            ));
        }
        if let Some(mapping) = &self.mapping {
            self.validate_mapping(world, &mapping.ready)?;
            return Ok(mapping.ready.clone());
        }
        let mapping = X86RootPreparedMapping::prepare(
            &self.preparation,
            &self.authority,
            world,
            self.resources.maximum_retained_bytes,
            &mut self.ledger,
            self.restored.as_ref(),
        )?;
        let ready = mapping.ready.clone();
        self.mapping = Some(mapping);
        Ok(ready)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_mapping(world, ready)
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        self.validate_mapping(world, ready)?;
        let mapping = self
            .mapping
            .as_ref()
            .ok_or_else(|| refusal("x86 original mapping disappeared"))?;
        Ok(Some(vec![mapping.owner.clone()]))
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        if self.prepared_owners(world, ready)?.as_deref() != Some(owners) {
            return Err(refusal(
                "x86 public owner mapping has changed original preparation",
            ));
        }
        Ok(())
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.restored.is_some() {
            return Err(refusal(
                "x86 reconstructed preparation cannot acquire initial authority",
            ));
        }
        self.validate_mapping(world, ready)
    }

    fn install_restored_custody(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<crate::node_scheduling::RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.install_original_custody(activation, source, operations, inputs)
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if !self.same_world(activation) || self.quarantined || self.active.is_some() {
            return Err(refusal(
                "x86 stopped observation has foreign or active native custody",
            ));
        }
        self.preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(|error| refusal(&error.to_string()))?;
        let (closure, closure_bytes) = self.authority.evidence();
        let remaining = self
            .ledger
            .remaining_bytes()
            .checked_sub(closure_bytes.len())
            .ok_or_else(|| refusal("x86 stopped observation lacks complete closure body credit"))?;
        if self.observations.len() >= 8192 {
            return Err(refusal(
                "x86 original stopped-observation slots are exhausted",
            ));
        }
        self.observations
            .try_reserve_exact(1)
            .map_err(|_| refusal("x86 original stopped-observation slot is unavailable"))?;
        let bytes = encoding::record(
            &StoppedWire {
                schema: "crucible.gem5.x86-root-observation.v1",
                boundary: self.preparation.native.boundary(),
                closure,
                owners: &self.preparation.route.owners,
                activation: SavedRuntimeActivation::from(activation.record()),
            },
            remaining,
        )?;
        let proof = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        self.ledger
            .retain_standalone(&[(&proof, &bytes), (closure, closure_bytes)])?;
        if !self.observations.contains(&proof) {
            self.observations.push(proof.clone());
        }
        let observation = self.scheduling(proof, Vec::new())?;
        self.observation = Some((Rc::clone(&activation.authority), observation.clone()));
        Ok(observation)
    }

    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        if !self.same_world(activation)
            || self.quarantined
            || self.preparation.native.logical_position() != observation.reached
            || !self
                .observation
                .as_ref()
                .is_some_and(|(authority, retained)| {
                    Rc::ptr_eq(authority, &activation.authority) && retained == observation
                })
        {
            return Err(refusal(
                "x86 observation differs from actual retained native boundary",
            ));
        }
        self.preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(|error| refusal(&error.to_string()))?;
        Ok(())
    }

    fn read_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        if references
            .iter()
            .try_fold(0u64, |total, reference| {
                total.checked_add(reference.length.get())
            })
            .is_none_or(|total| total > maximum_bytes as u64)
        {
            return Err(refusal("x86 boundary evidence exceeds caller byte credit"));
        }
        if !self.same_world(activation) {
            return Err(refusal("x86 boundary evidence has foreign activation"));
        }
        self.ledger.boundary_evidence(references)
    }

    fn validate_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_boundary_evidence(
            activation,
            references,
            self.resources.maximum_retained_bytes,
        )? != objects
        {
            return Err(refusal("x86 retained boundary evidence changed"));
        }
        Ok(())
    }

    fn input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        self.stopped_dependencies(activation, root, limits)
    }

    fn validate_input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        dependencies: &[ContentRef],
    ) -> Result<(), OperationFailure> {
        if self.stopped_dependencies(
            activation,
            root,
            InputProvenanceLimits {
                maximum_objects: 2,
                maximum_bytes: self.resources.maximum_retained_bytes,
            },
        )? != dependencies
        {
            return Err(refusal("x86 original stopped dependency row changed"));
        }
        Ok(())
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        self.begin(admission)
    }
    fn poll_operation(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.poll_original(token, context)
    }
    fn validate_outcome(
        &self,
        admission: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.authenticate_outcome(admission, outcome)
    }
    fn read_operation_evidence(
        &self,
        admission: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.ledger.evidence(admission.token(), references)
    }
    fn validate_operation_evidence(
        &self,
        admission: &OperationAdmission,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.ledger.evidence(admission.token(), references)? != objects {
            return Err(refusal("x86 original operation evidence changed"));
        }
        Ok(())
    }

    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.acknowledge_original(token, outputs)
    }
    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        let original = self.ledger.original(token)?;
        if original.outcome.is_some() || original.failure.is_some() {
            return Ok(CancelStatus::Terminal);
        }
        self.quarantine_resources();
        Ok(CancelStatus::Requested)
    }
    fn close_quantum(&mut self, _admission: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "x86 fixed root model has no quantum facet".to_owned(),
        })
    }
    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if kind == FacetKind::Preservation && self.archive.is_some() {
            return Ok(NodeFacet::Preservation(&self.preservation));
        }
        if kind != FacetKind::ExactExecution {
            return Err(Refusal {
                reason: "x86 fixed root model has no selected facet".to_owned(),
            });
        }
        Ok(NodeFacet::ExactExecution(&self.facet))
    }

    fn capture_native_continuation(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        self.capture_root(activation, source, limits)
    }

    fn quarantine_resources(&mut self) {
        self.quarantined = true;
        let _retained_failure = self.preparation.native.begin_quarantine();
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if !self.quarantined
            || self.preparation.route.owners.as_slice() != std::slice::from_ref(owner)
        {
            return Poll::Ready(Err(refusal(
                "x86 kernel reclamation lacks its original quarantined owner",
            )));
        }
        if let Some(receipt) = &self.reclamation {
            return Poll::Ready(Ok(receipt.clone()));
        }
        match self.preparation.native.poll_reclamation() {
            Ok(false) => {
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(error) => {
                return Poll::Ready(Err(OperationFailure {
                    effects: EffectKnowledge::Unknown,
                    reason: error.to_string(),
                }));
            }
            Ok(true) => {}
        }
        // This receipt is created only after the retained native custody engine
        // has waited the original child and censused every original helper group.
        let bytes = match canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.gem5.x86-root-reclamation.v1", "owner":owner,
            "original_closure":self.authority.evidence().0,
            "last_native_position":self.preparation.native.logical_position(),
        })) {
            Ok(bytes) => bytes,
            Err(error) => return Poll::Ready(Err(refusal(&error.to_string()))),
        };
        let reference = match canonical::content_ref(&bytes, "application/json") {
            Ok(reference) => reference,
            Err(error) => return Poll::Ready(Err(refusal(&error.to_string()))),
        };
        if let Err(error) = self.ledger.retain_standalone(&[(&reference, &bytes)]) {
            return Poll::Ready(Err(error));
        }
        let receipt = NativeReclamationReceipt {
            owner: owner.clone(),
            receipt: reference,
        };
        self.reclamation = Some(receipt.clone());
        Poll::Ready(Ok(receipt))
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.reclamation.as_ref() != Some(receipt) {
            return Err(refusal(
                "x86 reclamation receipt lacks actual original kernel proof",
            ));
        }
        Ok(())
    }
}
