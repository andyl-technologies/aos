//! Nonautonomous conditional node execution from an authenticated original prefix.

use std::{
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{
    ContentRef, Extensions, HashRef, Id, NodeBinding, NodeDescriptor, OperatingMode, Position,
    PreparedOwner, canonical,
};

use crate::{node_admission::AdmittedGraph, node_contract::*, node_scheduling::*};

use super::{
    archive::AuthenticatedTranscript,
    codec::{TranscriptError, encode, invalid},
    control::*,
    proof::RecordedProofClosure,
    replay::{InstalledReplayPolicy, ReplayCursor, ReplayCursorSnapshot},
    types::*,
};

#[path = "continuation.rs"]
mod continuation;

pub use continuation::{
    AuthenticatedReplayContinuation, TRANSCRIPT_REPLAY_PRESERVATION_PROFILE,
    authenticate_replay_continuation, transcript_replay_continuation_definition,
    transcript_replay_continuation_schema,
};

#[cfg(test)]
#[path = "node_guards.rs"]
mod tests;

/// Identifies conditional original-boundary replay, not native computation.
pub const TRANSCRIPT_REPLAY_PROFILE: &str = "transcript/conditional-replay-v1";

struct ReplayFacet(Id);
impl FacetDescription for ReplayFacet {
    fn profile(&self) -> &Id {
        &self.0
    }
}

struct ReplayOperation {
    admission: OperationAdmission,
    outcome: Option<OperationOutcome>,
    evidence: Vec<InputPayload>,
    acknowledged: bool,
    close_submission: Option<Submission>,
}

/// Owns a recorded node boundary under explicit installed conditional qualification.
///
/// Each response comes from exact original request applicability. The node has
/// no physical fallback, resampling path or external source connection. Its
/// origin's nondeterminism and physical uncertainty remain in the source and
/// admitted guarantees even though the recorded boundary prefix is reproducible.
pub struct TranscriptReplayNode {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    cursor: Option<ReplayCursor>,
    facets: Vec<FacetKind>,
    profile: ReplayFacet,
    thread: std::thread::ThreadId,
    boundary: Position,
    ready: Option<(ActivationRecord, ReadyAttestation)>,
    inputs: BTreeMap<Id, (Rc<RuntimeInputBatch>, NativeInputAcknowledgement)>,
    operations: BTreeMap<Id, ReplayOperation>,
    observations: Vec<(WorldActivation, NativeSchedulingObservation)>,
    quarantined: bool,
    reclamations: BTreeMap<OwnerIdentity, NativeReclamationReceipt>,
    owner_binding_hashes: BTreeMap<Id, Vec<HashRef>>,
    preservation: Option<ReplayFacet>,
    restored: Option<AuthenticatedReplayContinuation>,
    custody_objects: BTreeMap<ContentRef, InputPayload>,
}

impl TranscriptReplayNode {
    /// Borrows independently qualified original lineage beneath the current cutoff.
    ///
    /// This historical view does not install runtime input authority, preserve a
    /// physical backend or expose unconsumed native responses.
    ///
    /// # Errors
    /// Refuses missing Tape2 qualification or reclaimed original source custody.
    pub fn original_lineage_tape(
        &self,
    ) -> Result<super::tape2::OriginalLineageTapePrefix<'_>, TranscriptError> {
        let cursor = self
            .cursor
            .as_ref()
            .ok_or_else(|| invalid("original replay source was reclaimed"))?;
        super::tape2::OriginalLineageTapePrefix::from_cursor(cursor)
    }

    /// Qualifies an independently authenticated source against a fresh sealed graph.
    ///
    /// # Errors
    /// Refuses missing installed source/context qualification, changed semantics,
    /// unsupported replay facets, original-taint promotion or foreign owner scope.
    /// Complete preservation also refuses original negative or uncertain controls
    /// outside its selected codec before any readiness or response.
    pub fn prepare(
        source: AuthenticatedTranscript,
        graph: &AdmittedGraph,
        route: NodeRoute,
        context: &[InputPayload],
        policy: &dyn InstalledReplayPolicy,
    ) -> Result<Self, TranscriptError> {
        let cursor = ReplayCursor::prepare(source, graph, route.clone(), context, policy)?;
        let descriptor = graph
            .descriptor(&route.node)
            .ok_or_else(|| TranscriptError::Unqualified("replay descriptor absent".into()))?
            .clone();
        let binding = graph
            .binding(&route.node)
            .ok_or_else(|| TranscriptError::Unqualified("replay binding absent".into()))?
            .clone();
        let selected = &binding.compatibility.operating_contract.facets;
        if !selected
            .iter()
            .any(|facet| facet.id.as_str() == TRANSCRIPT_REPLAY_PROFILE)
        {
            return Err(TranscriptError::Unqualified(
                "conditional replay facet not explicitly selected".into(),
            ));
        }
        let mode = binding.compatibility.operating_contract.mode;
        let execution = match mode {
            OperatingMode::Exact => FacetKind::ExactExecution,
            OperatingMode::Quantized => FacetKind::QuantizedExecution,
        };
        let boundary = cursor.source.data.origin.activation.boundary;
        let preservation = if selected.iter().any(|facet| {
            facet.id.as_str() == TRANSCRIPT_REPLAY_PRESERVATION_PROFILE && facet.version == 1
        }) {
            if cursor.original_lineage.is_some() {
                return Err(invalid(
                    "Tape2 original lineage requires a separately qualified complete continuation codec",
                ));
            }
            continuation::validate_preservation_trajectory(&cursor.source)?;
            let schema =
                transcript_replay_continuation_schema().map_err(|error| invalid(error.reason))?;
            if route.owners.len() != 1
                || binding.compatibility.capture_owner.id != route.owners[0].owner
                || binding.compatibility.execution_owner.id != route.owners[0].owner
                || binding
                    .compatibility
                    .capture_owner
                    .participant_ids
                    .as_slice()
                    != std::slice::from_ref(&route.node)
                || !binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&schema)
            {
                return Err(invalid(
                    "complete replay capture owner or selected codec differs",
                ));
            }
            Some(ReplayFacet(
                Id::new(TRANSCRIPT_REPLAY_PRESERVATION_PROFILE).map_err(invalid)?,
            ))
        } else {
            None
        };
        let mut facets = vec![execution, FacetKind::Replay];
        if preservation.is_some() {
            facets.push(FacetKind::Preservation);
        }
        facets.sort();
        let mut owner_binding_hashes = BTreeMap::new();
        for owner in &route.owners {
            let installed = graph.owner(&owner.owner).ok_or_else(|| {
                TranscriptError::Unqualified("replay owner binding absent".into())
            })?;
            let mut hashes: Vec<_> = installed
                .node_bindings
                .iter()
                .map(|binding| binding.binding_hash.clone())
                .collect();
            hashes.sort();
            owner_binding_hashes.insert(owner.owner.clone(), hashes);
        }
        Ok(Self {
            descriptor,
            binding,
            route,
            cursor: Some(cursor),
            facets,
            profile: ReplayFacet(Id::new(TRANSCRIPT_REPLAY_PROFILE).map_err(invalid)?),
            thread: std::thread::current().id(),
            boundary,
            ready: None,
            inputs: BTreeMap::new(),
            operations: BTreeMap::new(),
            observations: Vec::new(),
            quarantined: false,
            reclamations: BTreeMap::new(),
            owner_binding_hashes,
            preservation,
            restored: None,
            custody_objects: BTreeMap::new(),
        })
    }

    /// Borrows the original source without granting new physical execution.
    pub fn source(&self) -> Option<&AuthenticatedTranscript> {
        self.cursor.as_ref().map(|cursor| &cursor.source)
    }

    /// Reads the next original request for semantic ID selection before admission.
    pub fn next_request(&self) -> Option<&TranscriptRequest> {
        self.cursor.as_ref()?.peek().map(|record| &record.request)
    }

    /// Reads cursor state without authorizing a caller-selected resume point.
    pub fn cursor_snapshot(&self) -> Option<ReplayCursorSnapshot> {
        self.cursor.as_ref().map(ReplayCursor::snapshot)
    }

    fn same_world(&self, activation: &WorldActivation) -> Result<(), OperationFailure> {
        if self.quarantined
            || self
                .ready
                .as_ref()
                .is_none_or(|(world, _)| world != activation.record())
        {
            return Err(failure(
                "replay activation is unavailable or differs",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn original(&self, token: &OperationToken) -> Result<&ReplayOperation, OperationFailure> {
        let operation = self
            .operations
            .get(token.operation())
            .ok_or_else(|| failure("original replay operation absent", EffectKnowledge::None))?;
        if !Rc::ptr_eq(&operation.admission.token().authority, &token.authority)
            || operation.admission.token().route() != token.route()
        {
            return Err(failure(
                "foreign replay operation token",
                EffectKnowledge::None,
            ));
        }
        Ok(operation)
    }

    fn replay(
        &mut self,
        action: TranscriptAction,
        id: Id,
        body: &ControlRequest,
    ) -> Result<TranscriptRecord, OperationFailure> {
        if self.quarantined {
            return Err(failure("replay is quarantined", EffectKnowledge::None));
        }
        let cursor = self
            .cursor
            .as_mut()
            .ok_or_else(|| failure("replay model was reclaimed", EffectKnowledge::None))?;
        let request = request(
            action,
            id,
            self.boundary,
            cursor.qualification.source_context.clone(),
            body,
        )
        .map_err(|error| failure(error, EffectKnowledge::None))?;
        cursor
            .replay(&request)
            .map_err(|error| failure(error, EffectKnowledge::None))
    }

    fn response(record: &TranscriptRecord) -> Result<ControlResponse, OperationFailure> {
        serde_json::from_slice(&record.response_bytes)
            .map_err(|error| failure(error, EffectKnowledge::None))
    }

    fn source_owners(&self) -> Result<&[OwnerIdentity], OperationFailure> {
        self.cursor
            .as_ref()
            .map(|cursor| cursor.source.data.origin.route.owners.as_slice())
            .ok_or_else(|| failure("replay source reclaimed", EffectKnowledge::None))
    }

    fn rebind_observation(
        &self,
        mut observation: NativeSchedulingObservation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if observation.node != self.route.node || observation.owners != self.source_owners()? {
            return Err(failure(
                "authenticated original observation scope differs",
                EffectKnowledge::None,
            ));
        }
        observation.owners = self.route.owners.clone();
        Ok(observation)
    }

    fn refusal(error: OperationFailure) -> Submission {
        Submission::Refused(Refusal {
            reason: error.reason,
        })
    }

    fn divergence(&mut self, reason: &str) -> OperationFailure {
        match self.cursor.as_mut() {
            Some(cursor) => failure(cursor.fail(reason), EffectKnowledge::None),
            None => failure("replay model was reclaimed", EffectKnowledge::None),
        }
    }
}

impl TranscriptReplayNode {
    fn replay_stage(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: Option<&InputProvenanceClosure>,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.same_world(batch.activation())?;
        if batch.node() != &self.route.node || batch.owners() != self.route.owners {
            return Err(failure(
                "replay input target or original staging identity differs",
                EffectKnowledge::None,
            ));
        }
        let input = RecordedInput::with_provenance(batch, self.source_owners()?, provenance)
            .map_err(|_| self.divergence("original input provenance scope differs"))?;
        // Reserve the complete initial replay-model ACK before consuming its
        // original source interaction. The physical proof remains unchanged
        // beneath this distinct current-model custody receipt.
        let custody = if self.preservation.is_some() {
            let cursor = self
                .cursor
                .as_ref()
                .ok_or_else(|| failure("replay cursor absent", EffectKnowledge::None))?;
            let next = cursor.peek().ok_or_else(|| {
                failure("original input interaction absent", EffectKnowledge::None)
            })?;
            let ControlResponse::Input(original) = Self::response(next)? else {
                return Err(self.divergence("next original response is not input staging"));
            };
            if original.owners != self.source_owners()? {
                return Err(failure(
                    "original input custody owner differs",
                    EffectKnowledge::None,
                ));
            }
            let receipt = continuation::ReplayInputCustody {
                schema: "crucible.transcript-replay.input-admission.v1".into(),
                source_state: cursor.source.reference().clone(),
                source_ack: (*original).clone(),
                target: SavedRuntimeActivation::from(batch.activation().record()),
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                batch: batch.batch().clone(),
                stage_operation: batch.stage_operation().clone(),
                inventory: batch.inventory().clone(),
                cutoff: batch.cutoff(),
            };
            let bytes = continuation::bounded_canonical(&receipt, 64 * 1024 * 1024)?;
            let reference = canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(error, EffectKnowledge::None))?;
            let total = self
                .custody_objects
                .values()
                .try_fold(bytes.len(), |total, object| {
                    total.checked_add(object.bytes.len())
                })
                .filter(|total| *total <= 64 * 1024 * 1024);
            if total.is_none()
                || (!self.custody_objects.contains_key(&reference)
                    && self.custody_objects.len() >= 8192)
            {
                return Err(failure(
                    "initial replay input custody exceeds reserved credit",
                    EffectKnowledge::None,
                ));
            }
            Some(((*original).clone(), InputPayload { reference, bytes }))
        } else {
            None
        };
        let record = self.replay(
            TranscriptAction::StageInput,
            batch.stage_operation().clone(),
            &ControlRequest::Stage { input },
        )?;
        let ControlResponse::Input(ack) = Self::response(&record)? else {
            return Err(failure(
                "recorded input response differs",
                EffectKnowledge::None,
            ));
        };
        let mut ack = *ack;
        if ack.owners != self.source_owners()? {
            return Err(failure(
                "original source input owner differs",
                EffectKnowledge::None,
            ));
        }
        ack.owners = self.route.owners.clone();
        if let Some((original, object)) = custody {
            let mut expected = ack.clone();
            expected.owners = original.owners.clone();
            if expected != original {
                return Err(failure(
                    "original input response changed during replay",
                    EffectKnowledge::MayHaveProgressed,
                ));
            }
            ack.proof_ref = object.reference.clone();
            self.custody_objects
                .insert(object.reference.clone(), object);
        }
        self.inputs.insert(
            batch.batch().clone(),
            (Rc::new(batch.retained_copy()), ack.clone()),
        );
        Ok(ack)
    }
}

impl SimulationNode for TranscriptReplayNode {
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
            lifecycle: if self.cursor.is_none() {
                Lifecycle::Released
            } else if self.quarantined {
                Lifecycle::Quarantined
            } else if self
                .operations
                .values()
                .any(|operation| operation.outcome.is_none())
            {
                Lifecycle::Executing
            } else {
                Lifecycle::Stopped
            },
            physical: PhysicalState::Suspended,
            boundary: Some(self.boundary),
        })
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        let cursor = self
            .cursor
            .as_ref()
            .ok_or_else(|| failure("replay model unavailable", EffectKnowledge::None))?;
        if self.preservation.is_some() {
            continuation::validate_preservation_trajectory(&cursor.source)
                .map_err(|error| failure(error, EffectKnowledge::None))?;
        }
        let cut = self
            .restored
            .as_ref()
            .map_or(self.boundary, |source| source.wire.runtime.capture_cut);
        if self.quarantined
            || world.world_binding_hash != cursor.qualification.target_world
            || world.boundary != cut
            || self
                .route
                .owners
                .iter()
                .any(|owner| !world.owners.contains(owner))
            || self
                .ready
                .as_ref()
                .is_some_and(|(original, _)| original != world)
        {
            return Err(failure(
                "replay readiness differs from actual installed scope",
                EffectKnowledge::None,
            ));
        }
        let bytes=encode(&serde_json::json!({"format":"crucible.transcript-replay-ready.v1","source":cursor.source.reference,"qualification":cursor.qualification.proof.reference,"activation":SavedRuntimeActivation::from(world),"route":self.route,"cursor":cursor.snapshot(),"boundary":self.boundary})).map_err(|error|failure(error,EffectKnowledge::None))?;
        let receipt = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let ready = ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: world.boundary,
            state_inventory: self.restored.as_ref().map_or_else(
                || cursor.source.reference.clone(),
                |source| source.reference.clone(),
            ),
            ready_receipt: receipt,
        };
        self.ready = Some((world.clone(), ready.clone()));
        Ok(ready)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.ready.as_ref() != Some(&(world.clone(), ready.clone()))
            || self.quarantined
            || self.cursor.is_none()
        {
            return Err(failure(
                "replay actual local readiness differs",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        self.validate_readiness(world, ready)?;
        let owners = self
            .route
            .owners
            .iter()
            .map(|owner| {
                let binding_hashes = self
                    .owner_binding_hashes
                    .get(&owner.owner)
                    .cloned()
                    .ok_or_else(|| {
                        failure(
                            "original installed replay owner bindings absent",
                            EffectKnowledge::None,
                        )
                    })?;
                Ok(PreparedOwner {
                    owner_id: owner.owner.clone(),
                    incarnation_id: owner.incarnation.clone(),
                    owner_generation: owner.generation,
                    prepared_token: self.binding.authority.realization_id.clone(),
                    binding_hashes,
                    ready_receipt: ready.ready_receipt.clone(),
                    extensions: Extensions::default(),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        Ok(Some(owners))
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        if self.prepared_owners(world, ready)?.as_deref() != Some(owners) {
            return Err(failure(
                "original installed replay preparation mapping differs",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(world, ready)?;
        if self.restored.is_some()
            || !self.operations.is_empty()
            || !self.inputs.is_empty()
            || !self.observations.is_empty()
            || self
                .cursor_snapshot()
                .is_none_or(|snapshot| snapshot.next_record.get() != 0 || snapshot.diverged)
        {
            return Err(failure(
                "replay original initial cursor and custody have changed",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.same_world(activation)?;
        let Some(id) = self.next_request().map(|request| request.identity.clone()) else {
            return Err(self.divergence("unrecorded producer observation after original prefix"));
        };
        let record = self.replay(TranscriptAction::Observe, id, &ControlRequest::Observe)?;
        let ControlResponse::Observation(observation) = Self::response(&record)? else {
            return Err(failure(
                "recorded observation response differs",
                EffectKnowledge::None,
            ));
        };
        let observation = self.rebind_observation(*observation)?;
        self.observations
            .push((activation.clone(), observation.clone()));
        Ok(observation)
    }

    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.same_world(activation)?;
        if !self.observations.iter().any(|(world, retained)| {
            Rc::ptr_eq(&world.authority, &activation.authority) && retained == observation
        }) {
            return Err(failure(
                "observation does not belong to original replay cursor",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn read_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.same_world(activation)?;
        if self.thread != std::thread::current().id()
            || !(self
                .observations
                .iter()
                .any(|(original, _)| Rc::ptr_eq(&original.authority, &activation.authority))
                || self.inputs.values().any(|(original, _)| {
                    Rc::ptr_eq(&original.activation().authority, &activation.authority)
                })
                || self.operations.values().any(|original| {
                    Rc::ptr_eq(
                        &original.admission.activation().authority,
                        &activation.authority,
                    )
                }))
        {
            return Err(failure(
                "replay proof custody belongs to another activation or thread",
                EffectKnowledge::None,
            ));
        }
        let cursor = self
            .cursor
            .as_ref()
            .ok_or_else(|| failure("replay proof source was reclaimed", EffectKnowledge::None))?;
        let mut bytes = 0usize;
        let mut objects = Vec::new();
        for reference in references {
            // Reading a future record would leak a response before its original
            // applicability checks. Only the consumed prefix owns evidence here.
            let object = self
                .custody_objects
                .get(reference)
                .or_else(|| {
                    cursor.source.data.records[..cursor.next]
                        .iter()
                        .flat_map(|record| &record.evidence)
                        .find(|object| object.reference == *reference)
                })
                .ok_or_else(|| {
                    failure(
                        "proof is absent from consumed original replay prefix",
                        EffectKnowledge::None,
                    )
                })?;
            bytes = bytes
                .checked_add(object.bytes.len())
                .ok_or_else(|| failure("replay proof extent overflow", EffectKnowledge::None))?;
            if bytes > maximum_bytes {
                return Err(failure(
                    "replay proof read budget exhausted",
                    EffectKnowledge::None,
                ));
            }
            objects.push(object.clone());
        }
        Ok(objects)
    }

    fn validate_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        let maximum = objects
            .iter()
            .try_fold(0usize, |bytes, object| {
                bytes.checked_add(object.bytes.len())
            })
            .ok_or_else(|| failure("replay proof extent overflow", EffectKnowledge::None))?;
        if self.read_boundary_evidence(activation, references, maximum)? != objects {
            return Err(failure(
                "consumed original replay proof body changed",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        self.read_boundary_evidence(activation, std::slice::from_ref(root), limits.maximum_bytes)?;
        if self.custody_objects.contains_key(root)
            && self.inputs.values().any(|(_, ack)| ack.proof_ref == *root)
        {
            // The installed continuation receipt commits to actual replay
            // buffers; its source/inventory references grant no body access.
            return Ok(Vec::new());
        }
        let cursor = self
            .cursor
            .as_ref()
            .ok_or_else(|| failure("replay source was reclaimed", EffectKnowledge::None))?;
        for record in &cursor.source.data.records[..cursor.next] {
            for object in &record.evidence {
                if let Some(closure) =
                    RecordedProofClosure::decode(object, &cursor.source.data.origin)
                        .map_err(|error| failure(error, EffectKnowledge::None))?
                    && closure.root == *root
                {
                    if closure
                        .dependencies
                        .len()
                        .checked_add(1)
                        .is_none_or(|count| count > limits.maximum_objects)
                    {
                        return Err(failure(
                            "original replay proof closure exceeds object budget",
                            EffectKnowledge::None,
                        ));
                    }
                    let mut complete = vec![root.clone()];
                    complete.extend_from_slice(&closure.dependencies);
                    self.read_boundary_evidence(activation, &complete, limits.maximum_bytes)?;
                    return Ok(closure.dependencies);
                }
            }
        }
        Err(failure(
            "original replay proof has no authenticated source codec inventory",
            EffectKnowledge::None,
        ))
    }

    fn validate_input_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        dependencies: &[ContentRef],
    ) -> Result<(), OperationFailure> {
        if self.input_provenance_dependencies(activation, root, InputProvenanceLimits::default())?
            != dependencies
        {
            return Err(failure(
                "original replay producer proof closure changed",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.replay_stage(batch, None)
    }

    fn stage_inputs_with_provenance(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.replay_stage(batch, Some(provenance))
    }

    fn requires_input_provenance(&self, batch: &RuntimeInputBatch) -> bool {
        self.next_request().and_then(|request|serde_json::from_slice::<ControlRequest>(&request.bytes).ok()).is_some_and(|request|matches!(request,ControlRequest::Stage {input} if input.provenance.is_some())) && batch.node()==&self.route.node
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        ack: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.same_world(batch.activation())?;
        if self
            .inputs
            .get(batch.batch())
            .is_none_or(|(original, retained)| {
                retained != ack
                    || original.inventory() != batch.inventory()
                    || original.payloads() != batch.payloads()
                    || original.deliveries() != batch.deliveries()
                    || original.cutoff() != batch.cutoff()
            })
        {
            return Err(failure(
                "input custody differs from the frozen recorded prefix",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        let result = (|| {
            self.same_world(admission.activation())?;
            if admission.token().route() != &self.route {
                return Err(failure(
                    "replay operation scope or identity differs",
                    EffectKnowledge::None,
                ));
            }
            if self.operations.contains_key(admission.token().operation()) {
                return Err(self.divergence("unrecorded duplicate original Begin"));
            }
            let body = ControlRequest::begin(admission, self.source_owners()?);
            let record = self.replay(
                TranscriptAction::Begin,
                admission.token().operation().clone(),
                &body,
            )?;
            let ControlResponse::Submission(submission) = Self::response(&record)? else {
                return Err(failure(
                    "recorded Begin response differs",
                    EffectKnowledge::None,
                ));
            };
            if submission == Submission::Accepted {
                self.operations.insert(
                    admission.token().operation().clone(),
                    ReplayOperation {
                        admission: admission.clone(),
                        outcome: None,
                        evidence: Vec::new(),
                        acknowledged: false,
                        close_submission: None,
                    },
                );
            }
            Ok(submission)
        })();
        result.unwrap_or_else(Self::refusal)
    }

    fn poll_operation(
        &mut self,
        token: &OperationToken,
        cx: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        let original = match self.original(token) {
            Ok(value) => value,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Some(outcome) = &original.outcome {
            return Poll::Ready(Ok(outcome.clone()));
        }
        if self
            .next_request()
            .is_some_and(|request| request.action == TranscriptAction::CloseWindow)
        {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = (|| {
            let record = self.replay(
                TranscriptAction::Complete,
                token.operation().clone(),
                &ControlRequest::Complete {
                    operation: token.operation().clone(),
                },
            )?;
            let ControlResponse::Outcome(outcome) = Self::response(&record)? else {
                return Err(failure(
                    "recorded original terminal response differs",
                    EffectKnowledge::None,
                ));
            };
            let mut outcome = *outcome;
            if outcome.node != self.route.node
                || outcome.operation != *token.operation()
                || outcome.owners != self.source_owners()?
            {
                return Err(failure(
                    "recorded original terminal scope differs",
                    EffectKnowledge::None,
                ));
            }
            outcome.owners = self.route.owners.clone();
            if let Some(observation) = outcome.scheduling.take() {
                outcome.scheduling = Some(self.rebind_observation(observation)?);
            }
            let operation = self
                .operations
                .get_mut(token.operation())
                .ok_or_else(|| failure("original operation unavailable", EffectKnowledge::None))?;
            operation.outcome = Some(outcome.clone());
            operation.evidence = record.evidence;
            Ok(outcome)
        })();
        Poll::Ready(result)
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.same_world(original.activation())?;
        let operation = self.original(original.token())?;
        if operation.admission.request() != original.request()
            || operation.outcome.as_ref() != Some(outcome)
        {
            return Err(failure(
                "result differs from authenticated original replay response",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        refs: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        let operation = self.original(original.token())?;
        refs.iter()
            .map(|reference| {
                operation
                    .evidence
                    .iter()
                    .find(|object| &object.reference == reference)
                    .cloned()
                    .ok_or_else(|| {
                        failure("original replay proof bytes absent", EffectKnowledge::None)
                    })
            })
            .collect()
    }
    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        refs: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_operation_evidence(original, refs)? != objects {
            return Err(failure(
                "original replay evidence changed",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        let result = (|| {
            let operation = self.original(original.token())?;
            if let Some(submission) = &operation.close_submission {
                return Ok(submission.clone());
            }
            let record = self.replay(
                TranscriptAction::CloseWindow,
                original.token().operation().clone(),
                &ControlRequest::Close {
                    operation: original.token().operation().clone(),
                    request: original.request().clone(),
                },
            )?;
            let ControlResponse::Submission(submission) = Self::response(&record)? else {
                return Err(failure(
                    "recorded close response differs",
                    EffectKnowledge::None,
                ));
            };
            if let Some(operation) = self.operations.get_mut(original.token().operation()) {
                operation.close_submission = Some(submission.clone());
            }
            Ok(submission)
        })();
        result.unwrap_or_else(Self::refusal)
    }

    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        self.original(token)?;
        Err(self.divergence("unrecorded cancellation is a counterfactual"))
    }

    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let operation = self.original(token)?;
        if operation
            .outcome
            .as_ref()
            .is_none_or(|outcome| outcome.retained_outputs != outputs)
        {
            return Err(self.divergence("original replay publication inventory differs"));
        }
        if operation.acknowledged {
            return Ok(());
        }
        let record = self.replay(
            TranscriptAction::Acknowledge,
            token.operation().clone(),
            &ControlRequest::Acknowledge {
                operation: token.operation().clone(),
                outputs: outputs.to_vec(),
            },
        )?;
        if Self::response(&record)? != ControlResponse::Acknowledged {
            return Err(failure(
                "recorded custody acknowledgement differs",
                EffectKnowledge::None,
            ));
        }
        self.boundary = record.assigned_positions.first().copied().ok_or_else(|| {
            failure(
                "recorded acknowledged source boundary absent",
                EffectKnowledge::None,
            )
        })?;
        if let Some(operation) = self.operations.get_mut(token.operation()) {
            operation.acknowledged = true;
        }
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if !self.facets.contains(&kind) {
            return Err(Refusal {
                reason: "replay facet not selected".into(),
            });
        }
        match kind {
            FacetKind::ExactExecution => Ok(NodeFacet::ExactExecution(&self.profile)),
            FacetKind::QuantizedExecution => Ok(NodeFacet::QuantizedExecution(&self.profile)),
            FacetKind::Replay => Ok(NodeFacet::Replay(&self.profile)),
            FacetKind::Preservation => self
                .preservation
                .as_ref()
                .map(|facet| NodeFacet::Preservation(facet as &dyn FacetDescription))
                .ok_or_else(|| Refusal {
                    reason: "complete replay preservation absent".into(),
                }),
            _ => Err(Refusal {
                reason: "replay facet unsupported".into(),
            }),
        }
    }

    fn quarantine_resources(&mut self) {
        self.quarantined = true;
    }

    fn capture_native_continuation(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        self.capture_replay_state(activation, source, limits)
    }

    fn install_restored_custody(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.install_replay_custody(activation, source, operations, inputs)
    }
    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if !self.quarantined || !self.route.owners.contains(owner) {
            return Poll::Ready(Err(failure(
                "replay owner is not contained",
                EffectKnowledge::None,
            )));
        }
        if let Some(receipt) = self.reclamations.get(owner) {
            return Poll::Ready(Ok(receipt.clone()));
        }
        self.cursor.take();
        self.inputs.clear();
        self.operations.clear();
        self.observations.clear();
        self.ready.take();
        self.restored.take();
        self.custody_objects.clear();
        let result = (|| {
            let bytes=encode(&serde_json::json!({"format":"crucible.transcript-replay-reclaimed.v1","owner":owner,"boundary":self.boundary,"mutable_cursor_destroyed":true})).map_err(|error|failure(error,EffectKnowledge::None))?;
            let receipt = canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(error, EffectKnowledge::None))?;
            Ok(NativeReclamationReceipt {
                owner: owner.clone(),
                receipt,
            })
        })();
        if let Ok(receipt) = &result {
            self.reclamations.insert(owner.clone(), receipt.clone());
        }
        Poll::Ready(result)
    }
    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.cursor.is_some() || self.reclamations.get(&receipt.owner) != Some(receipt) {
            return Err(failure(
                "original replay mutable custody remains",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }
}
