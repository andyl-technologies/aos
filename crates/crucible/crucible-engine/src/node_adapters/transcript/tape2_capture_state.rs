//! Captures separately qualified Tape2 models using reference-only Runtime7 state.
//!
//! All native cache comparisons and complete body extents precede copies. The
//! full original tape stays authenticated data; only its consumed prefix may
//! explain original permissions, lineage, output and acknowledgement knowledge.

use super::super::{
    TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE, original_lineage_continuation_schema,
};
use super::continuation::{MAXIMUM_OBJECTS, bounded_canonical};
use super::*;
use std::collections::BTreeSet;

#[derive(serde::Serialize)]
struct OperationView<'a> {
    operation: &'a Id,
    objects: Vec<&'a ContentRef>,
}

#[derive(serde::Serialize)]
struct CaptureView<'a> {
    schema_version: u16,
    runtime: &'a ContentRef,
    route: &'a NodeRoute,
    binding: &'a NodeBinding,
    cursor: ReplayCursorSnapshot,
    boundary: Position,
    transcript: &'a ContentRef,
    qualification: &'a ContentRef,
    operation_evidence: Vec<OperationView<'a>>,
    observations: Vec<&'a NativeSchedulingObservation>,
    custody_objects: Vec<&'a ContentRef>,
}

impl TranscriptReplayNode {
    pub(super) fn qualify_tape2_capture(
        cursor: &ReplayCursor,
        graph: &AdmittedGraph,
        route: &NodeRoute,
        context: &[InputPayload],
        policy: &dyn InstalledReplayPolicy,
    ) -> Result<Option<(ReplayFacet, super::super::ReplayQualification)>, TranscriptError> {
        let binding = graph
            .binding(&route.node)
            .ok_or_else(|| invalid("Tape2 target binding absent"))?;
        let selection = binding
            .compatibility
            .operating_contract
            .facets
            .iter()
            .find(|facet| facet.id.as_str() == TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE);
        let Some(selection) = selection else {
            return Ok(None);
        };
        let schema =
            original_lineage_continuation_schema().map_err(|error| invalid(error.reason))?;
        if selection.version != 2
            || cursor.original_lineage.is_none()
            || route.owners.len() != 1
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
            return Err(invalid("complete Tape2 model selection differs"));
        }
        continuation::validate_preservation_trajectory(&cursor.source)?;
        let qualified =
            policy.qualify_original_lineage_continuation(&cursor.source, graph, route, context)?;
        qualified
            .proof
            .reference
            .verify(&qualified.proof.bytes)
            .map_err(invalid)?;
        if qualified.source_context != cursor.qualification.source_context
            || qualified.target_world != cursor.qualification.target_world
            || qualified.target_binding != cursor.qualification.target_binding
            || qualified.target_route != cursor.qualification.target_route
        {
            return Err(invalid("complete Tape2 model qualification differs"));
        }
        Ok(Some((
            ReplayFacet(
                Id::new(TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE).map_err(invalid)?,
            ),
            qualified,
        )))
    }

    pub(super) fn capture_tape2_state(
        &self,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        self.same_world(activation)?;
        let cursor = self
            .cursor
            .as_ref()
            .ok_or_else(|| refused("Tape2 cursor absent"))?;
        let (_, qualified) = self
            .lineage_continuation
            .as_ref()
            .ok_or_else(|| refused("complete Tape2 capture is not independently qualified"))?;
        if source.source_activation != SavedRuntimeActivation::from(activation.record())
            || !self.facets.contains(&FacetKind::Preservation)
            || self.route.owners.len() != 1
            || self.operations.len() > MAXIMUM_OBJECTS
            || self.inputs.len() > MAXIMUM_OBJECTS
            || self.observations.len() > MAXIMUM_OBJECTS
            || runtime_object
                .reference
                .verify(&runtime_object.bytes)
                .is_err()
            || bounded_canonical(source, limits.maximum_record_bytes)? != runtime_object.bytes
            || cursor.next > cursor.source.data.records.len()
        {
            return Err(refused("Tape2 source cut or model custody differs"));
        }
        continuation::validate_preservation_trajectory(&cursor.source)
            .map_err(|error| refused(error.to_string()))?;
        let saved_operations = source
            .operations
            .iter()
            .filter(|saved| saved.route.node == self.route.node);
        let saved_inputs = source
            .inputs
            .iter()
            .filter(|saved| saved.node == self.route.node);
        if saved_operations.clone().count() != self.operations.len()
            || saved_inputs.clone().count() != self.inputs.len()
        {
            return Err(refused("complete Tape2 cache roster differs"));
        }
        let references = self
            .operations
            .values()
            .try_fold(0usize, |total, cached| {
                total.checked_add(cached.evidence.len())
            })
            .filter(|total| *total <= limits.maximum_objects.min(MAXIMUM_OBJECTS))
            .ok_or_else(|| refused("Tape2 aggregate metadata role credit exhausted"))?;
        if references > limits.maximum_objects {
            return Err(refused("Tape2 operation metadata credit exhausted"));
        }
        let mut operations = reserved(saved_operations.clone().count())?;
        for saved in saved_operations {
            let cached = self
                .operations
                .get(&saved.operation)
                .ok_or_else(|| refused("Tape2 original permission absent"))?;
            let expected = match &saved.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => Some(outcome),
                SavedRuntimeResult::Pending => None,
                SavedRuntimeResult::Failed(_) => {
                    return Err(refused("Tape2 failed permission unsupported"));
                }
            };
            if saved.route != self.route
                || cached.admission.request() != &saved.request
                || cached.admission.inputs().map(|batch| batch.batch())
                    != saved.input_batch.as_ref()
                || cached.outcome.as_ref() != expected
                || cached.acknowledged
                    != matches!(saved.result, SavedRuntimeResult::Acknowledged(_))
                || cached.close_submission != saved.close_submission
                || !Rc::ptr_eq(
                    &cached.admission.activation.authority,
                    &activation.authority,
                )
                || cached.evidence.len() > MAXIMUM_OBJECTS
            {
                return Err(refused("Tape2 original outcome or ACK cache changed"));
            }
            let mut objects = reserved(cached.evidence.len())?;
            objects.extend(cached.evidence.iter().map(|object| &object.reference));
            operations.push(OperationView {
                operation: &saved.operation,
                objects,
            });
        }
        for saved in saved_inputs {
            let (batch, ack) = self
                .inputs
                .get(&saved.batch)
                .ok_or_else(|| refused("Tape2 accepted input absent"))?;
            if saved.owners != self.route.owners
                || saved.failure.is_some()
                || batch.stage_operation() != &saved.stage_operation
                || batch.cutoff() != saved.cutoff
                || batch.inventory() != &saved.inventory
                || batch.deliveries() != saved.deliveries
                || !batch
                    .payloads()
                    .iter()
                    .map(|payload| &payload.reference)
                    .eq(&saved.payloads)
                || saved.acknowledgement.as_ref() != Some(ack)
                || !Rc::ptr_eq(&batch.activation().authority, &activation.authority)
            {
                return Err(refused("Tape2 immutable input journal changed"));
            }
        }
        let mut registry = BTreeMap::new();
        insert(&mut registry, runtime_object, limits)?;
        insert_raw(
            &mut registry,
            &cursor.source.reference,
            cursor.source.bytes(),
            limits,
        )?;
        insert(&mut registry, &qualified.proof, limits)?;
        // Future records are deliberately absent from this body lookup. The
        // complete tape object is retained, while proof roles use consumed data.
        for record in &cursor.source.data.records[..cursor.next] {
            for object in &record.evidence {
                insert(&mut registry, object, limits)?;
            }
        }
        for cached in self.operations.values() {
            for object in &cached.evidence {
                insert(&mut registry, object, limits)?;
            }
        }
        for object in self.custody_objects.values() {
            insert(&mut registry, object, limits)?;
        }
        let mut required = BTreeSet::from([
            &runtime_object.reference,
            &cursor.source.reference,
            &qualified.proof.reference,
        ]);
        for view in &operations {
            required.extend(view.objects.iter().copied());
        }
        for record in &cursor.source.data.records[..cursor.next] {
            required.extend(record.evidence.iter().map(|object| &object.reference));
        }
        for input in source
            .inputs
            .iter()
            .filter(|input| input.node == self.route.node)
        {
            required.extend(input.payloads.iter());
            if let Some(proof) = &input.provenance {
                required.extend(proof.objects.iter());
            }
            if let Some(lineage) = &input.lineage {
                for publication in &lineage.publications {
                    required.extend(publication.objects.iter());
                }
            }
        }
        required.extend(self.custody_objects.keys());
        if required
            .len()
            .checked_add(1)
            .is_none_or(|count| count > limits.maximum_objects.min(MAXIMUM_OBJECTS))
        {
            return Err(refused("Tape2 aggregate role credit exhausted"));
        }
        let mut total = 0usize;
        for reference in &required {
            let bytes = registry
                .get(*reference)
                .ok_or_else(|| refused("Tape2 original body role absent from consumed custody"))?;
            reference
                .verify(bytes)
                .map_err(|error| refused(error.to_string()))?;
            total = total
                .checked_add(bytes.len())
                .filter(|total| *total <= limits.maximum_total_record_bytes)
                .ok_or_else(|| refused("Tape2 aggregate body credit exhausted"))?;
        }
        let remaining = limits
            .maximum_total_record_bytes
            .checked_sub(total)
            .ok_or_else(|| refused("Tape2 complete envelope credit exhausted"))?;
        let mut observations = reserved(self.observations.len())?;
        observations.extend(self.observations.iter().map(|(_, observation)| observation));
        let mut custody_objects = reserved(self.custody_objects.len())?;
        custody_objects.extend(self.custody_objects.keys());
        let bytes = bounded_canonical(
            &CaptureView {
                schema_version: 2,
                runtime: &runtime_object.reference,
                route: &self.route,
                binding: &self.binding,
                cursor: cursor.snapshot(),
                boundary: self.boundary,
                transcript: &cursor.source.reference,
                qualification: &qualified.proof.reference,
                operation_evidence: operations,
                observations,
                custody_objects,
            },
            remaining.min(limits.maximum_record_bytes),
        )?;
        let mut evidence = reserved(required.len())?;
        for reference in required {
            let original = registry
                .get(reference)
                .ok_or_else(|| refused("Tape2 body role disappeared"))?;
            let mut copy = reserved(original.len())?;
            copy.extend_from_slice(original);
            evidence.push(InputPayload {
                reference: reference.clone(),
                bytes: copy,
            });
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
                profile: Id::new(TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE)
                    .map_err(|error| refused(error.to_string()))?,
                schema: original_lineage_continuation_schema()?,
            },
            cut: source.capture_cut,
            state: InputPayload {
                reference: canonical::content_ref(&bytes, "application/json")
                    .map_err(|error| refused(error.to_string()))?,
                bytes,
            },
            evidence,
            artifacts: Vec::new(),
        })
    }
}

fn insert<'a>(
    registry: &mut BTreeMap<&'a ContentRef, &'a [u8]>,
    object: &'a InputPayload,
    limits: NativeCaptureLimits,
) -> Result<(), OperationFailure> {
    insert_raw(registry, &object.reference, &object.bytes, limits)
}

fn insert_raw<'a>(
    registry: &mut BTreeMap<&'a ContentRef, &'a [u8]>,
    reference: &'a ContentRef,
    bytes: &'a [u8],
    limits: NativeCaptureLimits,
) -> Result<(), OperationFailure> {
    if bytes.len() > limits.maximum_record_bytes
        || registry.len() >= limits.maximum_objects.min(MAXIMUM_OBJECTS)
            && !registry.contains_key(reference)
    {
        return Err(refused("Tape2 original body lookup credit exhausted"));
    }
    reference
        .verify(bytes)
        .map_err(|error| refused(error.to_string()))?;
    if registry
        .insert(reference, bytes)
        .is_some_and(|original| original != bytes)
    {
        return Err(refused("Tape2 typed role has conflicting body bytes"));
    }
    Ok(())
}

fn reserved<T>(count: usize) -> Result<Vec<T>, OperationFailure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| refused("Tape2 finite allocation exhausted"))?;
    Ok(values)
}

fn refused(reason: impl Into<String>) -> OperationFailure {
    failure(reason.into(), EffectKnowledge::None)
}
