//! Fresh replay-model custody beneath original authenticated cursor state.

use super::*;

impl TranscriptReplayNode {
    /// Reconstructs an inactive replay model from authenticated complete native state.
    ///
    /// The installed policy independently checks the original physical transcript
    /// and fresh target applicability. Original permissions remain inert until
    /// complete-world activation remints their original operation and input IDs.
    ///
    /// # Errors
    /// Refuses changed compatibility, nonfresh owners, unsupported preservation,
    /// missing installed qualification or a counterfactual target context.
    pub fn prepare_restored(
        source: AuthenticatedReplayContinuation,
        graph: &AdmittedGraph,
        route: NodeRoute,
        context: &[InputPayload],
        policy: &dyn InstalledReplayPolicy,
    ) -> Result<Self, TranscriptError> {
        let binding = graph
            .binding(&route.node)
            .ok_or_else(|| invalid("fresh replay binding absent"))?;
        if binding.compatibility != source.wire.binding.compatibility
            || graph.world_binding_hash()
                != &source.wire.runtime.source_activation.world_binding_hash
            || route.node != source.wire.route.node
            || route.owners.len() != source.wire.route.owners.len()
            || route
                .owners
                .iter()
                .zip(&source.wire.route.owners)
                .any(|(fresh, old)| {
                    fresh.owner != old.owner
                        || fresh.incarnation == old.incarnation
                        || fresh.generation <= old.generation
                })
        {
            return Err(invalid(
                "fresh replay scope differs from authenticated original model",
            ));
        }
        let mut model = Self::prepare(source.source.clone(), graph, route, context, policy)?;
        if !model.facets.contains(&FacetKind::Preservation) {
            return Err(invalid("complete replay preservation was not selected"));
        }
        let cursor = model
            .cursor
            .as_mut()
            .ok_or_else(|| invalid("fresh replay cursor absent"))?;
        cursor.next = usize::try_from(source.wire.cursor.next_record.get()).map_err(invalid)?;
        cursor.diverged = source.wire.cursor.diverged;
        model.boundary = source.wire.boundary;
        model.custody_objects = source
            .wire
            .custody_objects
            .iter()
            .map(|object| (object.reference.clone(), object.clone()))
            .collect();
        model.restored = Some(source);
        Ok(model)
    }

    /// Authenticates actually reconstructed replay buffers under a fresh complete world.
    ///
    /// This proves preservation of the conditional replay model only. Historical
    /// physical receipt bodies retain their original lineage; they are never
    /// presented as fresh physical backend authority or deterministic origins.
    ///
    /// # Errors
    /// Refuses altered source runtime, stale target scope, changed cursor/cache,
    /// missing complete original input custody or an exceeded receipt budget.
    pub fn restored_continuation_evidence(
        &self,
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, OperationFailure> {
        let original = self.restored.as_ref().ok_or_else(|| {
            failure(
                "authenticated replay continuation absent",
                EffectKnowledge::None,
            )
        })?;
        if source != &original.wire.runtime
            || target.world_binding_hash != source.source_activation.world_binding_hash
            || target.boundary != source.capture_cut
            || target.activation_id == source.source_activation.activation_id
            || target.generation <= source.source_activation.generation
            || !self
                .route
                .owners
                .iter()
                .all(|owner| target.owners.contains(owner))
            || self.cursor_snapshot().as_ref() != Some(&original.wire.cursor)
            || self.boundary != original.wire.boundary
            || self.quarantined
        {
            return Err(failure(
                "fresh replay continuation does not preserve its original cut",
                EffectKnowledge::None,
            ));
        }
        let input_acknowledgements = self
            .fresh_input_custody(target)?
            .into_iter()
            .map(|(ack, _)| ack)
            .collect();
        #[derive(Serialize)]
        struct Attestation<'a> {
            schema: &'static str,
            source_state: &'a ContentRef,
            source_runtime: &'a RuntimeSnapshot,
            target: SavedRuntimeActivation,
            route: &'a NodeRoute,
            cursor: &'a ReplayCursorSnapshot,
            local_boundary: Position,
            physical_origin: &'a TranscriptOrigin,
        }
        let bytes = bounded_canonical(
            &Attestation {
                schema: "crucible.transcript-replay.continuation-attestation.v1",
                source_state: &original.reference,
                source_runtime: source,
                target: SavedRuntimeActivation::from(target),
                route: &self.route,
                cursor: &original.wire.cursor,
                local_boundary: self.boundary,
                physical_origin: &original.source.data.origin,
            },
            MAXIMUM_STATE_BYTES,
        )?;
        Ok(NativeRuntimeContinuationEvidence {
            proof: canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(error, EffectKnowledge::None))?,
            input_acknowledgements,
        })
    }

    fn fresh_input_custody(
        &self,
        target: &ActivationRecord,
    ) -> Result<Vec<(NativeInputAcknowledgement, InputPayload)>, OperationFailure> {
        let restored = self
            .restored
            .as_ref()
            .ok_or_else(|| failure("original replay input model absent", EffectKnowledge::None))?;
        let mut receipts = Vec::new();
        // Existing receipts remain authoritative lineage after a later capture.
        // Reserve one aggregate finite budget for historical and fresh bodies.
        let mut total = self
            .custody_objects
            .values()
            .try_fold(0usize, |total, object| {
                total
                    .checked_add(object.bytes.len())
                    .filter(|total| *total <= MAXIMUM_STATE_BYTES)
                    .ok_or_else(|| {
                        failure(
                            "historical replay input custody exceeds credit",
                            EffectKnowledge::None,
                        )
                    })
            })?;
        if self
            .custody_objects
            .len()
            .checked_add(restored.wire.inputs.len())
            .is_none_or(|count| count > MAXIMUM_OBJECTS)
        {
            return Err(failure(
                "fresh replay receipt inventory exceeds credit",
                EffectKnowledge::None,
            ));
        }
        for input in &restored.wire.inputs {
            let original = input.acknowledgement.as_ref().ok_or_else(|| {
                failure("original replay input ACK absent", EffectKnowledge::None)
            })?;
            // These references are custody commitments, not grants to fetch
            // another producer's evidence. The complete source is already owned.
            let receipt = ReplayInputCustody {
                schema: "crucible.transcript-replay.input-custody.v1".into(),
                source_state: restored.reference.clone(),
                source_ack: original.clone(),
                target: SavedRuntimeActivation::from(target),
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                batch: input.batch.clone(),
                stage_operation: input.stage_operation.clone(),
                inventory: input.inventory.clone(),
                cutoff: input.cutoff,
            };
            let bytes = bounded_canonical(&receipt, MAXIMUM_STATE_BYTES)?;
            total = total
                .checked_add(bytes.len())
                .filter(|total| *total <= MAXIMUM_STATE_BYTES)
                .ok_or_else(|| {
                    failure(
                        "fresh replay input receipts exceed finite custody credit",
                        EffectKnowledge::None,
                    )
                })?;
            let proof_ref = canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(error, EffectKnowledge::None))?;
            let mut ack = original.clone();
            ack.owners = self.route.owners.clone();
            ack.proof_ref = proof_ref.clone();
            receipts.push((
                ack,
                InputPayload {
                    reference: proof_ref,
                    bytes,
                },
            ));
        }
        Ok(receipts)
    }

    pub(in super::super) fn install_replay_custody(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        operations: &[OperationAdmission],
        inputs: &[Rc<RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.same_world(activation)?;
        self.restored_continuation_evidence(source, activation.record())?;
        if !self.operations.is_empty() || !self.inputs.is_empty() || !self.observations.is_empty() {
            return Err(failure(
                "restored replay custody was already installed",
                EffectKnowledge::None,
            ));
        }
        let restored = self
            .restored
            .as_ref()
            .ok_or_else(|| failure("authenticated replay source absent", EffectKnowledge::None))?;
        if operations.len() != restored.wire.operations.len()
            || inputs.len() != restored.wire.inputs.len()
        {
            return Err(failure(
                "reminted replay original handle roster is incomplete",
                EffectKnowledge::None,
            ));
        }
        let mut installed_operations = BTreeMap::new();
        for cached in &restored.wire.operations {
            let original = operations
                .iter()
                .find(|admission| admission.token().operation() == &cached.original.operation)
                .ok_or_else(|| {
                    failure(
                        "reminted replay original operation is absent",
                        EffectKnowledge::None,
                    )
                })?;
            if original.token().route() != &self.route
                || original.request() != &cached.original.request
                || original.inputs().map(|batch| batch.batch())
                    != cached.original.input_batch.as_ref()
                || !Rc::ptr_eq(&original.activation.authority, &activation.authority)
                || installed_operations.contains_key(original.token().operation())
            {
                return Err(failure(
                    "reminted replay original permission changed",
                    EffectKnowledge::None,
                ));
            }
            let outcome = match &cached.original.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => {
                    let mut outcome = outcome.clone();
                    outcome.owners = self.route.owners.clone();
                    if let Some(observation) = &mut outcome.scheduling {
                        observation.owners = self.route.owners.clone();
                    }
                    Some(outcome)
                }
                SavedRuntimeResult::Pending | SavedRuntimeResult::Failed(_) => None,
            };
            installed_operations.insert(
                original.token().operation().clone(),
                ReplayOperation {
                    admission: original.clone(),
                    outcome,
                    evidence: cached.evidence.clone(),
                    acknowledged: matches!(
                        cached.original.result,
                        SavedRuntimeResult::Acknowledged(_)
                    ),
                    close_submission: cached.original.close_submission.clone(),
                },
            );
        }
        let receipts = self.fresh_input_custody(activation.record())?;
        let mut installed_inputs = BTreeMap::new();
        let mut objects = self.custody_objects.clone();
        for (ack, object) in receipts {
            let saved = restored
                .wire
                .inputs
                .iter()
                .find(|input| input.batch == ack.batch)
                .ok_or_else(|| failure("original replay input is absent", EffectKnowledge::None))?;
            let batch = inputs
                .iter()
                .find(|batch| batch.batch() == &ack.batch)
                .ok_or_else(|| failure("reminted replay input is absent", EffectKnowledge::None))?;
            if batch.node() != &self.route.node
                || batch.owners() != self.route.owners
                || batch.stage_operation() != &saved.stage_operation
                || batch.cutoff() != saved.cutoff
                || batch.inventory() != &saved.inventory
                || batch.deliveries() != saved.deliveries
                || batch.payloads() != saved.payloads
                || !Rc::ptr_eq(&batch.activation().authority, &activation.authority)
                || installed_inputs.contains_key(batch.batch())
            {
                return Err(failure(
                    "reminted replay frozen input changed",
                    EffectKnowledge::None,
                ));
            }
            objects.insert(object.reference.clone(), object);
            installed_inputs.insert(batch.batch().clone(), (Rc::clone(batch), ack));
        }
        if objects.len() > MAXIMUM_OBJECTS {
            return Err(failure(
                "restored replay receipt registry exceeds finite credit",
                EffectKnowledge::None,
            ));
        }
        let observations = restored
            .wire
            .observations
            .iter()
            .map(|observation| {
                let mut observation = observation.clone();
                observation.owners = self.route.owners.clone();
                (activation.clone(), observation)
            })
            .collect();
        // Install the complete replacement only after every check succeeds.
        // No original Begin, Stage, Poll or ACK is executed by this transition.
        self.operations = installed_operations;
        self.inputs = installed_inputs;
        self.observations = observations;
        self.custody_objects = objects;
        Ok(())
    }
}
