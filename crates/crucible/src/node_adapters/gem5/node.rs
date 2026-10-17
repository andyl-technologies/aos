//! Qualified live gem5 ownership, readiness, observation, and containment.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{
    CaptureScope, ContentRef, Continuation, Direction, Endpoint, Id, NodeBinding, NodeDescriptor,
    OperatingMode, U64, canonical,
};
use crucible_node_provider::gem5::{GEM5_NATIVE_FRAME_BYTES, Gem5ExactAuthority};
use crucible_node_provider::reference_service::profile::{
    NATIVE_OCTET_INTERFACE_ID, NATIVE_OCTET_SCHEMA_ID, NATIVE_OCTET_SPECIFICATION,
};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::*,
    node_scheduling::{
        InputPayload, NativeOutputBound, NativeProducerBound, NativeSchedulingObservation,
    },
};

use super::{
    GEM5_CLOSED_EXACT_PROFILE, GEM5_OPAQUE_PRESERVATION_PROFILE, Gem5NodePreparation,
    capture::{Gem5ArchiveInstallation, RetainedCapture, gem5_native_continuation_schema},
    continuation::Gem5AuthenticatedContinuation,
    ledger::OperationLedger,
    refusal,
};

/// Bounds original operations and actual native prefixes before dispatch.
#[derive(Clone, Copy, Debug)]
pub struct Gem5NodeResources {
    /// Limits original common operations without recycling identities.
    pub maximum_operations: usize,
    /// Limits all original native Poll prefixes over the node's lifetime.
    pub maximum_prefixes: usize,
    /// Limits retained original receipt and output evidence bytes.
    pub maximum_retained_bytes: usize,
    /// Limits actual native callbacks in one bounded common Poll.
    pub maximum_events_per_poll: U64,
}

impl Default for Gem5NodeResources {
    fn default() -> Self {
        Self {
            maximum_operations: 4096,
            maximum_prefixes: 65_536,
            maximum_retained_bytes: 256 * 1024 * 1024,
            maximum_events_per_poll: U64::new(1024),
        }
    }
}

/// Retains complete actual native custody after qualified conversion is refused.
pub struct Gem5QualifiedNodeFailure {
    /// Describes the positively no-effect conversion refusal.
    pub error: OperationFailure,
    /// Retains the original parked native preparation and admitted identity.
    pub preparation: Gem5NodePreparation,
    /// Retains the sealed live native authority without transferring it elsewhere.
    pub authority: Gem5ExactAuthority,
}

struct ExactFacet(Id);

impl FacetDescription for ExactFacet {
    fn profile(&self) -> &Id {
        &self.0
    }
}

/// Adapts an independently qualified, closed native O3 owner to common exact grants.
///
/// The adapter mediates actual native callbacks at their full superdense
/// positions. It retains immutable original prefixes before administrative
/// acknowledgements and never retries a failed native effect as a new grant.
/// Input and fresh common continuation remain unsupported in this edition.
pub struct QualifiedGem5Node {
    pub(super) preparation: Gem5NodePreparation,
    pub(super) authority: Gem5ExactAuthority,
    pub(super) ledger: OperationLedger,
    pub(super) resources: Gem5NodeResources,
    pub(super) active: Option<Id>,
    pub(super) world: Option<(ActivationRecord, ReadyAttestation)>,
    pub(super) activation_authority: Option<Rc<()>>,
    pub(super) output: Option<Endpoint>,
    pub(super) maximum_payload: u64,
    pub(super) sequence: u64,
    pub(super) quarantined: bool,
    pub(super) observation: Option<(Rc<()>, NativeSchedulingObservation)>,
    pub(super) reclamation: Option<NativeReclamationReceipt>,
    pub(super) archive: Option<Gem5ArchiveInstallation>,
    pub(super) captures: Vec<RetainedCapture>,
    pub(super) capture_roots: Vec<std::path::PathBuf>,
    pub(super) restored: Option<Gem5AuthenticatedContinuation>,
    pub(super) public_preparation: bool,
    pub(super) public_continuation: bool,
    pub(super) prepared_mapping: Option<super::preparation_mapping::Gem5PreparedMapping>,
    thread: std::thread::ThreadId,
    facet: ExactFacet,
    preservation: ExactFacet,
    facets: Vec<FacetKind>,
}

impl QualifiedGem5Node {
    pub(super) fn from_qualified(
        preparation: Gem5NodePreparation,
        graph: &AdmittedGraph,
        authority: Gem5ExactAuthority,
        resources: Gem5NodeResources,
        archive: Option<Gem5ArchiveInstallation>,
        restored: Option<Gem5AuthenticatedContinuation>,
    ) -> Result<Self, Box<Gem5QualifiedNodeFailure>> {
        let validate =
            || -> Result<(OperationLedger, Option<Endpoint>, u64, Id), OperationFailure> {
                let node = &preparation.route.node;
                if preparation
                    .binding
                    .compatibility
                    .execution_owner
                    .participant_ids
                    .as_slice()
                    != std::slice::from_ref(node)
                    || graph.world_binding_hash() != &preparation.world_binding_hash
                    || graph.descriptor(node) != Some(&preparation.descriptor)
                    || graph.binding(node) != Some(&preparation.binding)
                    || authority.maximum_microsteps()
                        != graph.coordinator_policy().maximum_microsteps_per_instant
                    || resources.maximum_events_per_poll.get() == 0
                    || resources.maximum_events_per_poll.get() > 10_000_000
                {
                    return Err(refusal(
                        "gem5 qualified native scope, graph or finite callback credit differs",
                    ));
                }
                let public_preservation = preparation
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&super::public_continuation::gem5_public_continuation_schema()?);
                let epoch_preservation = preparation
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(
                        &super::public_continuation::gem5_public_epoch_continuation_schema()?,
                    );
                let preservation_profile = if epoch_preservation {
                    super::public_continuation::GEM5_PUBLIC_EPOCH_CONTINUATION_PROFILE
                } else if public_preservation {
                    super::public_continuation::GEM5_PUBLIC_CONTINUATION_PROFILE
                } else {
                    GEM5_OPAQUE_PRESERVATION_PROFILE
                };
                let operating = &preparation.binding.compatibility.operating_contract;
                if operating.mode != OperatingMode::Exact
                    || operating.resolution_ps != Some(1.into())
                    || operating.phase_ps != Some(0.into())
                    || operating.facets.len() != if archive.is_some() { 2 } else { 1 }
                    || !operating.facets.iter().any(|facet| {
                        facet.id.as_str() == GEM5_CLOSED_EXACT_PROFILE && facet.version == 1
                    })
                    || operating.facets.iter().any(|facet| {
                        facet.version != 1
                            || (facet.id.as_str() != GEM5_CLOSED_EXACT_PROFILE
                                && (archive.is_none() || facet.id.as_str() != preservation_profile))
                    })
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
                        "gem5 installed exact edition requires the closed no-ingress facet and one-picosecond grid",
                    ));
                }
                let guarantees = graph
                    .guarantees(node)
                    .ok_or_else(|| refusal("gem5 admitted guarantee absent"))?;
                let capture_scope = if archive.is_some() {
                    CaptureScope::CompleteModel
                } else {
                    CaptureScope::None
                };
                if guarantees.capture_scope != capture_scope
                    || (guarantees.continuation != Continuation::Unsupported
                        && (archive.is_none() || guarantees.continuation != Continuation::Exact))
                    || ((guarantees.durable_restart || guarantees.isolated_fork)
                        && (archive.is_none() || guarantees.continuation != Continuation::Exact))
                    || guarantees.conditional_replay
                {
                    return Err(refusal(
                        "gem5 common preservation and replay require a separately installed native archive bridge",
                    ));
                }
                if let Some(archive) = &archive {
                    archive.validate(&preparation.native, authority.maximum_microsteps())?;
                    if !preparation
                        .binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&gem5_native_continuation_schema()?)
                    {
                        return Err(refusal(
                            "gem5 installed capture codec absent from admitted formats",
                        ));
                    }
                }
                preparation
                    .native
                    .next_publication_bound(&authority)
                    .map_err(native_refusal)?;
                if let Some(restored) = &restored {
                    super::restore::validate_fresh_continuation(&preparation, restored)?;
                    if let Some(public) = &restored.public_preparation {
                        let selected_schema = match public.wire.schema_version {
                            1 => super::public_continuation::gem5_public_continuation_schema()?,
                            2 => {
                                super::public_continuation::gem5_public_epoch_continuation_schema()?
                            }
                            _ => {
                                return Err(refusal(
                                    "restored public native source edition is unsupported",
                                ));
                            }
                        };
                        if public.world.activation != restored.source.source_activation
                            || !preparation
                                .binding
                                .compatibility
                                .implementation
                                .formats
                                .contains(&selected_schema)
                        {
                            return Err(refusal(
                                "restored public native source differs from its selected graph",
                            ));
                        }
                        preparation
                            .native
                            .restored_prepared_session(&authority)
                            .map_err(native_refusal)?;
                    }
                } else if preparation.native.pending_completion().is_some() {
                    return Err(refusal(
                        "gem5 initial qualification retains an unbound native publication",
                    ));
                }
                let definition =
                    canonical::content_ref(NATIVE_OCTET_SPECIFICATION.as_bytes(), "text/plain")
                        .map_err(|error| refusal(&error.to_string()))?;
                let mut output = None;
                let mut maximum_payload = 0;
                for port in &preparation.descriptor.ports {
                    if port.interface_id.as_str() != NATIVE_OCTET_INTERFACE_ID
                        || !port.features.is_empty()
                    {
                        return Err(refusal(
                            "gem5 stdout interface differs from installed original-octet semantics",
                        ));
                    }
                    for lane in &port.lanes {
                        if lane.direction != Direction::Output
                            || output.is_some()
                            || lane.payload_schema.id.as_str() != NATIVE_OCTET_SCHEMA_ID
                            || lane.payload_schema.version != 1
                            || lane.payload_schema.definition != definition
                            || lane.maximum_payload_bytes.get() > GEM5_NATIVE_FRAME_BYTES as u64
                        {
                            return Err(refusal(
                                "gem5 installed profile supports one bounded original-octet stdout lane",
                            ));
                        }
                        output = Some(Endpoint {
                            node_id: node.clone(),
                            port_id: port.id.clone(),
                            lane_id: lane.id.clone(),
                        });
                        maximum_payload = lane.maximum_payload_bytes.get();
                    }
                }
                let ledger = OperationLedger::new(
                    resources.maximum_operations,
                    resources.maximum_prefixes,
                    resources.maximum_retained_bytes,
                )?;
                ledger.can_run_prefix(super::ledger::PREFIX_STORAGE_CREDIT)?;
                let facet = Id::new(GEM5_CLOSED_EXACT_PROFILE)
                    .map_err(|error| refusal(&error.to_string()))?;
                Ok((ledger, output, maximum_payload, facet))
            };
        match validate() {
            Ok((ledger, output, maximum_payload, facet)) => {
                let preservation = preparation
                    .binding
                    .compatibility
                    .operating_contract
                    .facets
                    .iter()
                    .find(|selected| {
                        matches!(
                            selected.id.as_str(),
                            GEM5_OPAQUE_PRESERVATION_PROFILE
                                | super::public_continuation::GEM5_PUBLIC_CONTINUATION_PROFILE
                                | super::public_continuation::GEM5_PUBLIC_EPOCH_CONTINUATION_PROFILE
                        )
                    })
                    .map(|selected| selected.id.clone())
                    .unwrap_or_else(|| facet.clone());
                let sequence = preparation
                    .native
                    .completed_prefixes()
                    .flat_map(|prefix| prefix.publications.iter())
                    .map(|birth| birth.output_id.get())
                    .max()
                    .unwrap_or(0);
                let public_continuation = restored
                    .as_ref()
                    .is_some_and(|source| source.public_preparation.is_some());
                Ok(Self {
                    preparation,
                    authority,
                    ledger,
                    resources,
                    active: None,
                    world: None,
                    activation_authority: None,
                    output,
                    maximum_payload,
                    sequence,
                    quarantined: false,
                    observation: None,
                    reclamation: None,
                    facets: if archive.is_some() {
                        vec![FacetKind::ExactExecution, FacetKind::Preservation]
                    } else {
                        vec![FacetKind::ExactExecution]
                    },
                    archive,
                    captures: Vec::new(),
                    capture_roots: Vec::new(),
                    restored,
                    public_preparation: public_continuation,
                    public_continuation,
                    prepared_mapping: None,
                    thread: std::thread::current().id(),
                    facet: ExactFacet(facet),
                    preservation: ExactFacet(preservation),
                })
            }
            Err(error) => Err(Box::new(Gem5QualifiedNodeFailure {
                error,
                preparation,
                authority,
            })),
        }
    }

    pub(super) fn same_world(&self, activation: &WorldActivation) -> bool {
        self.world
            .as_ref()
            .is_some_and(|(record, _)| record == activation.record())
            && self
                .activation_authority
                .as_ref()
                .is_none_or(|authority| Rc::ptr_eq(authority, &activation.authority))
    }

    pub(super) fn readiness_boundary(
        &self,
    ) -> Result<crucible_node_contract::Position, OperationFailure> {
        if let Some(restored) = &self.restored {
            // A latent original operation may be ahead of the coordinator cut.
            // That original Ready applies only while the entire native journal
            // remains unchanged, including zero-event operations and ACKs.
            super::restore::validate_fresh_continuation(&self.preparation, restored)?;
            Ok(restored.source.capture_cut)
        } else {
            Ok(self.preparation.native.logical_position())
        }
    }

    pub(super) fn scheduling(
        &self,
        proof_ref: ContentRef,
        publications: Vec<crate::node_scheduling::NativePublication>,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        let bound = self
            .preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(native_refusal)?;
        // The independent installed authority proves a closed ingress inventory.
        // An empty native heap therefore cannot spontaneously create a callback.
        let bound = bound.map_or(
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
                proof_ref: proof_ref.clone(),
            }],
            publications,
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref,
        })
    }
}

pub(super) fn native_refusal(error: crucible_node_provider::ProviderError) -> OperationFailure {
    refusal(&error.to_string())
}

impl SimulationNode for QualifiedGem5Node {
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
        &self.facets
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
        if self.quarantined
            || self.active.is_some()
            || world.world_binding_hash != self.preparation.world_binding_hash
            || world.boundary != self.readiness_boundary()?
            || !self
                .preparation
                .route
                .owners
                .iter()
                .all(|owner| world.owners.contains(owner))
        {
            return Err(refusal(
                "gem5 readiness differs from actual original parked native scope",
            ));
        }
        self.preparation.native.observe().map_err(native_refusal)?;
        if world.boundary != self.readiness_boundary()? {
            return Err(refusal(
                "gem5 original readiness changed during native observation",
            ));
        }
        self.preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(native_refusal)?;
        let (inventory, _) = self.authority.evidence();
        let value = serde_json::json!({"schema":"crucible.gem5.common-readiness.v1","activation":world.activation_id,"world_generation":world.generation,"world_hash":world.world_binding_hash,"owners":self.preparation.route.owners,"boundary":self.preparation.native.boundary(),"independent_closure":inventory});
        let bytes =
            canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))?;
        let ready = ReadyAttestation {
            owners: self.preparation.route.owners.clone(),
            boundary: world.boundary,
            state_inventory: inventory.clone(),
            ready_receipt: canonical::content_ref(&bytes, "application/json")
                .map_err(|error| refusal(&error.to_string()))?,
        };
        if self
            .world
            .as_ref()
            .is_some_and(|original| original != &(world.clone(), ready.clone()))
        {
            return Err(refusal(
                "gem5 native owner is already armed for another activation",
            ));
        }
        if self.public_preparation && self.prepared_mapping.is_none() {
            let mapping = self.retain_original_preparation_mapping(world, &ready, &bytes)?;
            self.prepared_mapping = Some(mapping);
        }
        self.world = Some((world.clone(), ready.clone()));
        Ok(ready)
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<crucible_node_contract::PreparedOwner>>, OperationFailure> {
        if !self.public_preparation {
            return Ok(None);
        }
        let mapping = self.prepared_mapping.as_ref().ok_or_else(|| {
            refusal("public gem5 owner mapping has no original armed native preparation")
        })?;
        self.original_prepared_owners(mapping, world, ready)
            .map(Some)
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[crucible_node_contract::PreparedOwner],
    ) -> Result<(), OperationFailure> {
        let mapping = self
            .prepared_mapping
            .as_ref()
            .ok_or_else(|| refusal("public gem5 owner mapping is not selected or armed"))?;
        if self.original_prepared_owners(mapping, world, ready)? != owners {
            return Err(refusal(
                "public gem5 owner mapping differs from original native custody",
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
                "restored public native custody cannot authenticate initial preparation",
            ));
        }
        let mapping = self.prepared_mapping.as_ref().ok_or_else(|| {
            refusal("gem5 source did not select genuine public initial preparation")
        })?;
        self.validate_original_preparation_mapping(mapping, world, ready)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.quarantined
            || self.active.is_some()
            || self.world.as_ref() != Some(&(world.clone(), ready.clone()))
            || self.readiness_boundary()? != ready.boundary
        {
            return Err(refusal("gem5 authentic parked readiness custody changed"));
        }
        self.preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(native_refusal)?;
        Ok(())
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if !self.same_world(activation) || self.quarantined || self.active.is_some() {
            return Err(refusal(
                "gem5 stopped observation has foreign or active native custody",
            ));
        }
        self.preparation.native.observe().map_err(native_refusal)?;
        let (closure, _) = self.authority.evidence();
        let bytes = canonical::canonical_json(&serde_json::json!({"schema":"crucible.gem5.common-observation.v1","boundary":self.preparation.native.boundary(),"closure":closure,"owners":self.preparation.route.owners,"activation_id":activation.record().activation_id})).map_err(|error| refusal(&error.to_string()))?;
        let proof = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        let (closure_reference, closure_bytes) = self.authority.evidence();
        self.ledger
            .retain_standalone(&[(&proof, &bytes), (closure_reference, closure_bytes)])?;
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
            || !self
                .observation
                .as_ref()
                .is_some_and(|(authority, original)| {
                    Rc::ptr_eq(authority, &activation.authority) && original == observation
                })
            || self.preparation.native.logical_position() != observation.reached
            || self.quarantined
        {
            return Err(refusal(
                "gem5 scheduling observation lacks original actual native custody",
            ));
        }
        self.preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(native_refusal)?;
        Ok(())
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        self.begin(admission)
    }
    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.poll_original(operation, context)
    }
    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.authenticate_outcome(original, outcome)
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.ledger.evidence(original.token(), references)
    }
    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.ledger.evidence(original.token(), references)? != objects {
            return Err(refusal("gem5 retained original evidence differs"));
        }
        Ok(())
    }

    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        let original = self.ledger.original(operation)?;
        if original.outcome.is_some() || original.failure.is_some() {
            return Ok(CancelStatus::Terminal);
        }
        self.quarantine_resources();
        Ok(CancelStatus::Requested)
    }
    fn close_quantum(&mut self, _original: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "gem5 installed profile has no quantized execution facet".to_owned(),
        })
    }
    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.acknowledge_original(operation, outputs)
    }
    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if kind == FacetKind::Preservation && self.archive.is_some() {
            return Ok(NodeFacet::Preservation(&self.preservation));
        }
        if kind != FacetKind::ExactExecution {
            return Err(Refusal {
                reason: "gem5 selected native profile does not implement this facet".to_owned(),
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
        if self.public_continuation {
            return self.capture_public_installed(activation, source, limits);
        }
        if self.public_preparation {
            return Err(refusal(
                "public gem5 preparation requires a distinct preparation-bearing capture codec",
            ));
        }
        self.capture_installed(activation, source, limits)
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

    fn quarantine_resources(&mut self) {
        self.quarantined = true;
        // Native custody remains in the owning process even if termination fails.
        // Its Drop supervisor retains the real child, prefixes and source image.
        let _retained_failure = self.preparation.native.begin_quarantine();
    }

    fn graceful_retirement_available(&self) -> bool {
        self.preparation.native.graceful_shutdown_available()
    }

    fn shutdown_resources(&mut self) -> Result<(), OperationFailure> {
        self.quarantined = true;
        self.preparation
            .native
            .begin_graceful_shutdown()
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: error.to_string(),
            })
    }

    fn transfer_retirement_resources(&mut self) -> Result<(), OperationFailure> {
        if !self.quarantined || self.reclamation.is_none() {
            return Err(refusal(
                "original gem5 supervisor transfer precedes actual reclamation",
            ));
        }
        self.preparation
            .native
            .transfer_gracefully_reclaimed_to_supervisor()
            .map_err(|error| refusal(&error.to_string()))
    }

    fn retirement_history_pending(&self) -> bool {
        self.preparation.native.graceful_retirement_requested()
    }

    fn retirement_history_credit(&self) -> Option<usize> {
        Some(64 * 1024 * 1024 + 65_536 * (2 * 516 + 128 + 9) + 64)
    }

    fn retirement_history(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        super::retirement::history(self, maximum_bytes)
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if self.preparation.route.owners.as_slice() != std::slice::from_ref(owner) {
            return Poll::Ready(Err(refusal(
                "gem5 reclamation owner differs from original incarnation",
            )));
        }
        let proof = match self.preparation.native.poll_reclamation() {
            Ok(Some(proof)) => proof,
            Ok(None) => {
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(error) => {
                return Poll::Ready(Err(OperationFailure {
                    effects: EffectKnowledge::Unknown,
                    reason: error.to_string(),
                }));
            }
        };
        if proof.owner() != &owner.owner
            || proof.incarnation() != &owner.incarnation
            || proof.generation() != owner.generation
        {
            return Poll::Ready(Err(refusal(
                "gem5 authentic kernel reclamation scope differs",
            )));
        }
        let receipt = NativeReclamationReceipt {
            owner: owner.clone(),
            receipt: proof.evidence().0.clone(),
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
                "gem5 reclamation lacks original authentic kernel proof",
            ));
        }
        Ok(())
    }
}
