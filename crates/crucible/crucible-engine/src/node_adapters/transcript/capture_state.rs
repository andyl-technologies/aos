//! Unchanged replay-model capture with complete original runtime cache custody.

use super::*;

#[derive(serde::Serialize)]
struct ReplayOperationView<'a> {
    original: &'a SavedRuntimeOperation,
    evidence: &'a [InputPayload],
}

#[derive(serde::Serialize)]
struct ReplayCaptureView<'a> {
    schema_version: u16,
    runtime: &'a RuntimeSnapshot,
    route: &'a NodeRoute,
    binding: &'a NodeBinding,
    cursor: ReplayCursorSnapshot,
    boundary: Position,
    transcript: &'a ContentRef,
    qualification: &'a ContentRef,
    operations: Vec<ReplayOperationView<'a>>,
    inputs: Vec<&'a SavedRuntimeInput>,
    observations: Vec<&'a NativeSchedulingObservation>,
    custody_objects: Vec<&'a InputPayload>,
}

impl TranscriptReplayNode {
    pub(in super::super) fn capture_replay_state(
        &self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        self.same_world(activation)?;
        let cursor = self.cursor.as_ref().ok_or_else(|| {
            failure(
                "complete replay model is unavailable",
                EffectKnowledge::None,
            )
        })?;
        if !self.facets.contains(&FacetKind::Preservation)
            || self.route.owners.len() != 1
            || source.source_activation != SavedRuntimeActivation::from(activation.record())
            || limits.maximum_record_bytes == 0
            || limits.maximum_objects < 3
            || self.operations.len() > MAXIMUM_OBJECTS
            || self.inputs.len() > MAXIMUM_OBJECTS
            || self.observations.len() > MAXIMUM_OBJECTS
        {
            return Err(failure(
                "complete replay capture lacks original scope or finite credit",
                EffectKnowledge::None,
            ));
        }
        // Count all retained representations before copying any native buffers.
        // Capture performs no response replay, input staging or acknowledgement.
        for object in [
            (&cursor.source.reference, cursor.source.bytes()),
            (
                &cursor.qualification.proof.reference,
                cursor.qualification.proof.bytes.as_slice(),
            ),
        ] {
            if object.1.len() > limits.maximum_record_bytes {
                return Err(failure(
                    "original replay dependency exceeds record credit",
                    EffectKnowledge::None,
                ));
            }
            object
                .0
                .verify(object.1)
                .map_err(|error| failure(error, EffectKnowledge::None))?;
        }
        let mut operations = Vec::new();
        for original in source
            .operations
            .iter()
            .filter(|operation| operation.route.node == self.route.node)
        {
            let retained = self.operations.get(&original.operation).ok_or_else(|| {
                failure(
                    "replay original operation custody is absent",
                    EffectKnowledge::None,
                )
            })?;
            let expected = match &original.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => Some(outcome),
                SavedRuntimeResult::Pending | SavedRuntimeResult::Failed(_) => None,
            };
            if original.route != self.route
                || retained.admission.request() != &original.request
                || retained.admission.inputs().map(|input| input.batch())
                    != original.input_batch.as_ref()
                || retained.outcome.as_ref() != expected
                || retained.acknowledged
                    != matches!(original.result, SavedRuntimeResult::Acknowledged(_))
                || retained.close_submission != original.close_submission
                || !Rc::ptr_eq(
                    &retained.admission.activation.authority,
                    &activation.authority,
                )
            {
                return Err(failure(
                    "replay original operation or ACK cache changed",
                    EffectKnowledge::None,
                ));
            }
            operations.push(ReplayOperationView {
                original,
                evidence: &retained.evidence,
            });
        }
        if operations.len() != self.operations.len() {
            return Err(failure(
                "replay capture runtime omits retained native operations",
                EffectKnowledge::None,
            ));
        }
        let inputs: Vec<_> = source
            .inputs
            .iter()
            .filter(|input| input.node == self.route.node)
            .collect();
        if inputs.len() != self.inputs.len() {
            return Err(failure(
                "replay input custody inventory differs",
                EffectKnowledge::None,
            ));
        }
        for original in &inputs {
            let (batch, ack) = self.inputs.get(&original.batch).ok_or_else(|| {
                failure(
                    "replay staged original input is absent",
                    EffectKnowledge::None,
                )
            })?;
            if batch.stage_operation() != &original.stage_operation
                || batch.owners() != original.owners
                || batch.cutoff() != original.cutoff
                || batch.inventory() != &original.inventory
                || batch.deliveries() != original.deliveries
                || batch.payloads() != original.payloads
                || original.acknowledgement.as_ref() != Some(ack)
                || !Rc::ptr_eq(&batch.activation().authority, &activation.authority)
            {
                return Err(failure(
                    "replay staged input or original raw payload changed",
                    EffectKnowledge::None,
                ));
            }
        }
        let dependencies = native_dependencies::ReplayDependencies::prepare(
            &cursor.source,
            cursor.next,
            &cursor.qualification.proof,
            &inputs,
            self.custody_objects.values(),
            limits,
        )?;
        let remaining = limits
            .maximum_total_record_bytes
            .checked_sub(dependencies.bytes())
            .ok_or_else(|| {
                failure(
                    "complete replay dependencies exhaust state credit",
                    EffectKnowledge::None,
                )
            })?;
        let view = ReplayCaptureView {
            schema_version: 1,
            runtime: source,
            route: &self.route,
            binding: &self.binding,
            cursor: cursor.snapshot(),
            boundary: self.boundary,
            transcript: &cursor.source.reference,
            qualification: &cursor.qualification.proof.reference,
            operations,
            inputs,
            observations: self
                .observations
                .iter()
                .map(|(_, observation)| observation)
                .collect(),
            custody_objects: self.custody_objects.values().collect(),
        };
        // Count the exact complete envelope, including duplicated runtime/cache
        // representations and separators, before cloning any retained body.
        let mut count = CountWriter {
            remaining: remaining
                .min(limits.maximum_record_bytes)
                .min(MAXIMUM_STATE_BYTES),
        };
        count_encoding(&view, &mut count)?;

        let wire = ReplayContinuationWire {
            schema_version: view.schema_version,
            runtime: source.clone(),
            route: self.route.clone(),
            binding: self.binding.clone(),
            cursor: view.cursor,
            boundary: self.boundary,
            transcript: cursor.source.reference.clone(),
            qualification: cursor.qualification.proof.reference.clone(),
            operations: view
                .operations
                .into_iter()
                .map(|operation| SavedReplayOperation {
                    original: operation.original.clone(),
                    evidence: operation.evidence.to_vec(),
                })
                .collect(),
            inputs: view.inputs.into_iter().cloned().collect(),
            observations: view.observations.into_iter().cloned().collect(),
            custody_objects: view.custody_objects.into_iter().cloned().collect(),
        };
        validate_wire(&wire, &cursor.source)?;
        let bytes = bounded_canonical(&wire, limits.maximum_record_bytes)?;
        let total = bytes
            .len()
            .checked_add(dependencies.bytes())
            .filter(|total| *total <= limits.maximum_total_record_bytes)
            .ok_or_else(|| {
                failure(
                    "complete replay capture exceeds total record credit",
                    EffectKnowledge::None,
                )
            })?;
        if total == 0 {
            return Err(failure(
                "complete replay capture is empty",
                EffectKnowledge::None,
            ));
        }
        Ok(InstalledNativeCapture {
            owner: self.route.owners[0].owner.clone(),
            participants: vec![self.route.node.clone()],
            key: NativeStateKey {
                implementation: self
                    .binding
                    .compatibility
                    .implementation
                    .implementation_id
                    .clone(),
                profile: Id::new(TRANSCRIPT_REPLAY_PRESERVATION_PROFILE)
                    .map_err(|error| failure(error, EffectKnowledge::None))?,
                schema: transcript_replay_continuation_schema()?,
            },
            cut: source.capture_cut,
            state: InputPayload {
                reference: canonical::content_ref(&bytes, "application/json")
                    .map_err(|error| failure(error, EffectKnowledge::None))?,
                bytes,
            },
            evidence: dependencies.materialize(),
            artifacts: Vec::new(),
        })
    }
}
