//! Rebinds complete Tape2 journals beneath an actually published Runtime7 world.
//!
//! Original FIRST and SOURCE-CAPTURE facts remain in the authenticated source
//! pin. Fresh local permission and ACK handles are installed together only after
//! exact journal comparisons; no Stage, Begin, Poll, Close or ACK is reexecuted.

use super::continuation::{
    MAXIMUM_OBJECTS, MAXIMUM_STATE_BYTES, ReplayInputCustody, bounded_canonical,
};
use super::*;

impl TranscriptReplayNode {
    /// Inspects current model buffers and derives inert fresh-target ACK evidence.
    ///
    /// The source pin has already authenticated the complete consumed tape and
    /// original native journals. An installed verifier must still authenticate
    /// this evidence against the complete world before a restoration context is
    /// created. This method issues no permission, readiness or native class.
    ///
    /// # Errors
    /// Refuses another thread, changed source cursor, foreign target/owner scope,
    /// populated model caches or exhausted aggregate receipt credit.
    pub fn original_lineage_restoration_evidence(
        &self,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, OperationFailure> {
        let source = self.tape2_inactive_target(target)?;
        let receipts = self.tape2_input_receipts(target)?;
        #[derive(serde::Serialize)]
        struct Attestation<'a> {
            schema: &'static str,
            source_state: &'a ContentRef,
            source_runtime: &'a ContentRef,
            target: SavedRuntimeActivation,
            route: &'a NodeRoute,
            cursor: &'a ReplayCursorSnapshot,
            boundary: Position,
        }
        let bytes = bounded_canonical(
            &Attestation {
                schema: "crucible.transcript-replay.original-lineage-restoration.v2",
                source_state: source.source.native_state_reference(),
                source_runtime: source.source.runtime_reference(),
                target: SavedRuntimeActivation::from(target),
                route: &self.route,
                cursor: &source.wire.cursor,
                boundary: self.boundary,
            },
            MAXIMUM_STATE_BYTES,
        )?;
        Ok(NativeRuntimeContinuationEvidence {
            proof: canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(error, EffectKnowledge::None))?,
            input_acknowledgements: receipts.into_iter().map(|(ack, _)| ack).collect(),
        })
    }

    fn tape2_inactive_target(
        &self,
        target: &ActivationRecord,
    ) -> Result<&super::super::PinnedTape2Continuation, OperationFailure> {
        let source = self.restored_lineage.as_ref().ok_or_else(|| {
            failure(
                "authenticated Tape2 source is absent",
                EffectKnowledge::None,
            )
        })?;
        let saved = source.source.runtime();
        if self.thread != std::thread::current().id()
            || self.quarantined
            || !self.operations.is_empty()
            || !self.inputs.is_empty()
            || !self.observations.is_empty()
            || target.world_binding_hash != saved.source_activation.world_binding_hash
            || target.boundary != saved.capture_cut
            || target.generation <= saved.source_activation.generation
            || target.activation_id == saved.source_activation.activation_id
            || self.cursor_snapshot().as_ref() != Some(&source.wire.cursor)
            || self.boundary != source.wire.boundary
            || self
                .route
                .owners
                .iter()
                .any(|owner| !target.owners.contains(owner))
            || self
                .restored_lineage_target
                .as_ref()
                .is_some_and(|actual| actual != target)
            || self
                .ready
                .as_ref()
                .is_some_and(|(actual, _)| actual != target)
        {
            return Err(failure(
                "inactive Tape2 target differs from its source",
                EffectKnowledge::None,
            ));
        }
        Ok(source)
    }

    pub(super) fn tape2_input_receipts(
        &self,
        target: &ActivationRecord,
    ) -> Result<Vec<(NativeInputAcknowledgement, InputPayload)>, OperationFailure> {
        let source = self.tape2_inactive_target(target)?;
        let selected = source
            .source
            .runtime()
            .inputs
            .iter()
            .filter(|input| input.node == self.route.node);
        let mut receipts = reserve(selected.clone().count())?;
        let mut bytes_remaining = MAXIMUM_STATE_BYTES;
        for reference in &source.wire.custody_objects {
            charge(&mut bytes_remaining, reference.length.get())?;
        }
        if source
            .wire
            .custody_objects
            .len()
            .checked_add(selected.clone().count())
            .is_none_or(|count| count > MAXIMUM_OBJECTS)
        {
            return Err(failure(
                "Tape2 ACK role credit exhausted",
                EffectKnowledge::None,
            ));
        }
        for input in selected {
            // Unsupported uncertain staging is not promoted to a successful ACK.
            let original = input.acknowledgement.as_ref().ok_or_else(|| {
                failure("original Tape2 input ACK is absent", EffectKnowledge::None)
            })?;
            let receipt = ReplayInputCustody {
                schema: "crucible.transcript-replay.input-custody.v1".into(),
                source_state: source.source.native_state_reference().clone(),
                source_ack: original.clone(),
                target: SavedRuntimeActivation::from(target),
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                batch: input.batch.clone(),
                stage_operation: input.stage_operation.clone(),
                inventory: input.inventory.clone(),
                cutoff: input.cutoff,
            };
            let bytes = bounded_canonical(&receipt, bytes_remaining)?;
            charge(&mut bytes_remaining, bytes.len() as u64)?;
            let reference = canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(error, EffectKnowledge::None))?;
            let mut ack = original.clone();
            ack.owners = self.route.owners.clone();
            ack.proof_ref = reference.clone();
            receipts.push((ack, InputPayload { reference, bytes }));
        }
        receipts.sort_by(|left, right| left.0.stage_operation.cmp(&right.0.stage_operation));
        Ok(receipts)
    }

    pub(super) fn install_tape2_custody(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
        activation: &WorldActivation,
        operations: &[OperationAdmission],
        inputs: &[Rc<RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.same_world(activation)?;
        let source = self.tape2_inactive_target(activation.record())?;
        if self.restored_lineage_target.as_ref() != Some(activation.record())
            || context.target() != activation.record()
            || context.source_record() != source.source.runtime_reference()
            || context.record() != source.source.runtime()
        {
            return Err(failure(
                "Tape2 publication/context differs",
                EffectKnowledge::None,
            ));
        }
        let saved_operations = context
            .record()
            .operations
            .iter()
            .filter(|saved| saved.route.node == self.route.node);
        let saved_inputs = context
            .record()
            .inputs
            .iter()
            .filter(|saved| saved.node == self.route.node);
        if operations.len() != saved_operations.clone().count()
            || inputs.len() != saved_inputs.clone().count()
        {
            return Err(failure(
                "Tape2 reminted handle roster differs",
                EffectKnowledge::None,
            ));
        }
        let receipts = self.tape2_input_receipts(activation.record())?;
        if !receipts.iter().map(|(ack, _)| ack).eq(context
            .input_acknowledgements()
            .iter()
            .filter(|ack| ack.node == self.route.node))
        {
            return Err(failure(
                "Tape2 current input ACK journal differs",
                EffectKnowledge::None,
            ));
        }

        // Charge every copied proof role before materializing the replacement.
        // Repeated typed roles are charged for each retained body occurrence.
        let mut remaining = MAXIMUM_STATE_BYTES;
        for reference in source
            .wire
            .operation_evidence
            .iter()
            .flat_map(|row| &row.objects)
            .chain(&source.wire.custody_objects)
        {
            charge(&mut remaining, reference.length.get())?;
        }
        for (_, object) in &receipts {
            charge(&mut remaining, object.bytes.len() as u64)?;
        }
        let mut installed_operations = BTreeMap::new();
        for saved in saved_operations {
            let original = operations
                .iter()
                .find(|operation| operation.token().operation() == &saved.operation)
                .ok_or_else(|| {
                    failure("Tape2 original permission absent", EffectKnowledge::None)
                })?;
            if original.token().route() != &self.route
                || original.request() != &saved.request
                || original.inputs().map(|batch| batch.batch()) != saved.input_batch.as_ref()
                || !Rc::ptr_eq(&original.activation.authority, &activation.authority)
                || installed_operations.contains_key(&saved.operation)
            {
                return Err(failure(
                    "Tape2 original permission changed",
                    EffectKnowledge::None,
                ));
            }
            let outcome = match &saved.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => {
                    if outcome.node != saved.route.node
                        || outcome.owners != saved.route.owners
                        || outcome.scheduling.as_ref().is_some_and(|observation| {
                            observation.node != saved.route.node
                                || observation.owners != saved.route.owners
                        })
                    {
                        return Err(failure(
                            "Tape2 original outcome scope changed",
                            EffectKnowledge::None,
                        ));
                    }
                    let mut outcome = outcome.clone();
                    outcome.owners = self.route.owners.clone();
                    if let Some(observation) = &mut outcome.scheduling {
                        observation.owners = self.route.owners.clone();
                    }
                    Some(outcome)
                }
                SavedRuntimeResult::Pending => None,
                SavedRuntimeResult::Failed(_) => {
                    return Err(failure(
                        "Tape2 failed permission unsupported",
                        EffectKnowledge::None,
                    ));
                }
            };
            let row = source
                .wire
                .operation_evidence
                .iter()
                .find(|row| row.operation == saved.operation)
                .ok_or_else(|| failure("Tape2 proof journal absent", EffectKnowledge::None))?;
            let evidence = copy_roles(source, &row.objects)?;
            installed_operations.insert(
                saved.operation.clone(),
                ReplayOperation {
                    admission: original.clone(),
                    outcome,
                    evidence,
                    acknowledged: matches!(saved.result, SavedRuntimeResult::Acknowledged(_)),
                    close_submission: saved.close_submission.clone(),
                },
            );
        }
        let mut objects = BTreeMap::new();
        for object in copy_roles(source, &source.wire.custody_objects)? {
            objects.insert(object.reference.clone(), object);
        }
        let mut installed_inputs = BTreeMap::new();
        for ((ack, object), saved) in receipts.into_iter().zip(saved_inputs) {
            // Inputs are ordered by staging identity in the closed Runtime7.
            let batch = inputs
                .iter()
                .find(|batch| batch.stage_operation() == &saved.stage_operation)
                .ok_or_else(|| failure("Tape2 reminted batch absent", EffectKnowledge::None))?;
            if batch.node() != &self.route.node
                || batch.owners() != self.route.owners
                || batch.batch() != &saved.batch
                || batch.cutoff() != saved.cutoff
                || batch.inventory() != &saved.inventory
                || batch.deliveries() != saved.deliveries
                || !batch
                    .payloads()
                    .iter()
                    .map(|payload| &payload.reference)
                    .eq(&saved.payloads)
                || batch.payloads().iter().any(|payload| {
                    context.original_body(&payload.reference) != Some(payload.bytes.as_slice())
                })
                || ack.stage_operation != saved.stage_operation
                || !Rc::ptr_eq(&batch.activation().authority, &activation.authority)
                || installed_inputs.contains_key(batch.batch())
            {
                return Err(failure(
                    "Tape2 original frozen input changed",
                    EffectKnowledge::None,
                ));
            }
            objects.insert(object.reference.clone(), object);
            installed_inputs.insert(batch.batch().clone(), (Rc::clone(batch), ack));
        }
        if objects.len() > MAXIMUM_OBJECTS {
            return Err(failure(
                "Tape2 installed ACK role credit exhausted",
                EffectKnowledge::None,
            ));
        }
        let mut observations = reserve(source.wire.observations.len())?;
        for saved in &source.wire.observations {
            if saved.node != source.wire.route.node || saved.owners != source.wire.route.owners {
                return Err(failure(
                    "Tape2 stopped observation scope changed",
                    EffectKnowledge::None,
                ));
            }
            let mut observation = saved.clone();
            observation.owners = self.route.owners.clone();
            observations.push((activation.clone(), observation));
        }

        // Commit the complete model replacement only after all comparisons.
        // The original source pin remains owned throughout refusals and unwind.
        self.operations = installed_operations;
        self.inputs = installed_inputs;
        self.observations = observations;
        self.custody_objects = objects;
        self.lineage_activation = Some(activation.clone());
        Ok(())
    }
}

fn charge(remaining: &mut usize, bytes: u64) -> Result<(), OperationFailure> {
    let bytes = usize::try_from(bytes)
        .map_err(|_| failure("Tape2 body extent overflows", EffectKnowledge::None))?;
    *remaining = remaining.checked_sub(bytes).ok_or_else(|| {
        failure(
            "Tape2 aggregate proof credit exhausted",
            EffectKnowledge::None,
        )
    })?;
    Ok(())
}

fn reserve<T>(count: usize) -> Result<Vec<T>, OperationFailure> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| failure("Tape2 finite allocation exhausted", EffectKnowledge::None))?;
    Ok(entries)
}

fn copy_roles(
    source: &super::super::PinnedTape2Continuation,
    references: &[ContentRef],
) -> Result<Vec<InputPayload>, OperationFailure> {
    let mut objects = reserve(references.len())?;
    for reference in references {
        let original = source
            .source
            .original_body(reference)
            .ok_or_else(|| failure("Tape2 original proof body absent", EffectKnowledge::None))?;
        let mut bytes = reserve(original.len())?;
        bytes.extend_from_slice(original);
        objects.push(InputPayload {
            reference: reference.clone(),
            bytes,
        });
    }
    Ok(objects)
}
