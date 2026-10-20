//! Reconciles Tape2 source-capture custody against exactly the consumed prefix.
//!
//! Reference-only Runtime7 remains complete. Original operation identities,
//! request windows, input order, FIRST claims and original response bytes are
//! retained; only actual source-capture owner aliases are compared separately.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    node_contract::{OperationOutcome, OperationRequest, SavedRuntimeResult, Submission},
    node_scheduling::NativeInputAcknowledgement,
};

use super::*;
use crate::node_adapters::transcript::{
    control::{ControlRequest, ControlResponse, RecordedInput},
    node::continuation::ReplayInputCustody,
    tape2::{RecordedLineage, RecordedTape2},
    types::{TranscriptAction, TranscriptRecord},
};

#[derive(Default)]
struct OriginalOperation {
    request: Option<OperationRequest>,
    input: Option<Id>,
    outcome: Option<OperationOutcome>,
    evidence: Vec<ContentRef>,
    acknowledged: bool,
    close: Option<Submission>,
}

pub(super) fn validate(
    wire: &Tape2ContinuationWire,
    source: &AuthenticatedOriginalLineageSource<'_>,
    tape: &AuthenticatedTranscript,
) -> Result<(), OperationFailure> {
    let records = checked_records(wire, tape)?;
    let mut operations = BTreeMap::<Id, OriginalOperation>::new();
    let mut inputs = BTreeMap::<Id, (RecordedInput, NativeInputAcknowledgement)>::new();
    let mut first_inputs = BTreeMap::new();
    let mut observations = Vec::new();
    let mut expected = BTreeSet::from([
        wire.runtime.clone(),
        wire.transcript.clone(),
        wire.qualification.clone(),
    ]);
    let mut boundary = tape.data.origin.activation.boundary;
    for record in records {
        if record.request.boundary != boundary {
            return Err(refused("Tape2 original boundary sequence differs"));
        }
        for object in &record.evidence {
            if source.content().get(&object.reference) != Some(object.bytes.as_slice()) {
                return Err(refused("Tape2 consumed original proof body changed"));
            }
            expected.insert(object.reference.clone());
            if let Some(metadata) = RecordedTape2::decode(object, &tape.data.origin, record)
                .map_err(|error| refused(error.to_string()))?
                && let RecordedLineage::Input { input } = metadata.lineage
                && first_inputs
                    .insert(record.request.identity.clone(), *input)
                    .is_some()
            {
                return Err(refused("Tape2 original input metadata is ambiguous"));
            }
        }
        let request: ControlRequest = serde_json::from_slice(&record.request.bytes)
            .map_err(|error| refused(error.to_string()))?;
        validate_identity(record, &request, observations.len())?;
        let response: ControlResponse = serde_json::from_slice(&record.response_bytes)
            .map_err(|error| refused(error.to_string()))?;
        match (request, response) {
            (
                ControlRequest::Begin {
                    operation,
                    node,
                    request,
                    input,
                },
                ControlResponse::Submission(Submission::Accepted),
            ) => {
                if node != wire.route.node || operations.contains_key(&operation) {
                    return Err(refused(
                        "Tape2 original accepted Begin is foreign or duplicate",
                    ));
                }
                operations.insert(
                    operation,
                    OriginalOperation {
                        request: Some(request),
                        input: input.map(|input| input.batch),
                        ..Default::default()
                    },
                );
            }
            (ControlRequest::Complete { operation }, ControlResponse::Outcome(outcome)) => {
                // Authenticate FIRST observation scope before comparing its
                // separate SOURCE-CAPTURE owner association.
                super::super::tape2::validate_original_outcome_scope(&outcome, &tape.data.origin)
                    .map_err(|error| refused(error.to_string()))?;
                let original = operations
                    .get_mut(&operation)
                    .ok_or_else(|| refused("Tape2 original completion lacks its permission"))?;
                if original.outcome.is_some()
                    || outcome.operation != operation
                    || outcome.node != wire.route.node
                    || outcome.owners != tape.data.origin.route.owners
                {
                    return Err(refused("Tape2 original completion scope differs"));
                }
                // This comparison maps recorded physical owners to the already
                // authenticated SOURCE-CAPTURE route, not a new target authority.
                let mut outcome = *outcome;
                outcome.owners = wire.route.owners.clone();
                if let Some(observation) = &mut outcome.scheduling {
                    observation.owners = wire.route.owners.clone();
                }
                original.outcome = Some(outcome);
                original.evidence = record
                    .evidence
                    .iter()
                    .map(|object| object.reference.clone())
                    .collect();
            }
            (ControlRequest::Close { operation, .. }, ControlResponse::Submission(submission)) => {
                let original = operations
                    .get_mut(&operation)
                    .ok_or_else(|| refused("Tape2 original Close lacks its permission"))?;
                if original.close.replace(submission).is_some() {
                    return Err(refused("Tape2 original Close was consumed twice"));
                }
            }
            (ControlRequest::Acknowledge { operation, outputs }, ControlResponse::Acknowledged) => {
                let original = operations
                    .get_mut(&operation)
                    .ok_or_else(|| refused("Tape2 original ACK lacks its permission"))?;
                if original.acknowledged
                    || original
                        .outcome
                        .as_ref()
                        .is_none_or(|outcome| outcome.retained_outputs != outputs)
                {
                    return Err(refused("Tape2 original output ACK inventory differs"));
                }
                original.acknowledged = true;
                boundary = record
                    .assigned_positions
                    .first()
                    .copied()
                    .ok_or_else(|| refused("Tape2 original output ACK boundary absent"))?;
            }
            (ControlRequest::Stage { input }, ControlResponse::Input(ack)) => {
                if input.node != wire.route.node
                    || input.owners != tape.data.origin.route.owners
                    || ack.node != input.node
                    || ack.owners != input.owners
                    || ack.batch != input.batch
                    || ack.stage_operation != input.stage_operation
                    || ack.cutoff != input.cutoff
                    || ack.inventory != input.inventory
                    || inputs
                        .get(&input.batch)
                        .is_some_and(|prior| prior != &(input.clone(), (*ack).clone()))
                {
                    return Err(refused("Tape2 original staging/ACK scope differs"));
                }
                inputs.insert(input.batch.clone(), (input, *ack));
            }
            (ControlRequest::Observe, ControlResponse::Observation(observation)) => {
                let mut observation = *observation;
                if observation.node != wire.route.node
                    || observation.owners != tape.data.origin.route.owners
                {
                    return Err(refused("Tape2 original observation scope differs"));
                }
                observation.owners = wire.route.owners.clone();
                observations.push(observation);
            }
            _ => return Err(refused("Tape2 consumed control trajectory is unsupported")),
        }
    }
    let saved_operations = source
        .runtime()
        .operations
        .iter()
        .filter(|operation| operation.route.node == wire.route.node);
    let saved_inputs = source
        .runtime()
        .inputs
        .iter()
        .filter(|input| input.node == wire.route.node);
    if boundary != wire.boundary
        || observations != wire.observations
        || operations.len() != saved_operations.clone().count()
        || inputs.len() != saved_inputs.clone().count()
    {
        return Err(refused(
            "Tape2 consumed cutoff omits original cache custody",
        ));
    }
    for saved in saved_operations {
        let original = operations
            .get(&saved.operation)
            .ok_or_else(|| refused("Tape2 runtime introduces an unconsumed permission"))?;
        let outcome = match &saved.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                Some(outcome)
            }
            SavedRuntimeResult::Pending => None,
            SavedRuntimeResult::Failed(_) => {
                return Err(refused("Tape2 original failed operation is unsupported"));
            }
        };
        let evidence = wire
            .operation_evidence
            .iter()
            .find(|entry| entry.operation == saved.operation)
            .ok_or_else(|| refused("Tape2 original operation evidence omitted"))?;
        if original.request.as_ref() != Some(&saved.request)
            || original.input != saved.input_batch
            || original.outcome.as_ref() != outcome
            || original.evidence != evidence.objects
            || original.close != saved.close_submission
            || original.acknowledged != matches!(saved.result, SavedRuntimeResult::Acknowledged(_))
            || saved.submission_effects.is_some()
        {
            return Err(refused(
                "Tape2 original permission/window/outcome/cache differs",
            ));
        }
    }
    let mut used_custody = BTreeSet::new();
    for saved in saved_inputs {
        let (input, ack) = inputs
            .get(&saved.batch)
            .ok_or_else(|| refused("Tape2 runtime introduces unconsumed input"))?;
        let first = first_inputs.get(&saved.stage_operation);
        let lineage_matches = if input.deliveries.is_empty() {
            input.payloads.is_empty()
                && input.provenance.is_none()
                && first.is_none()
                && saved.lineage.is_none()
        } else {
            first.is_some() && saved.lineage.as_ref() == first
        };
        if saved.owners != wire.route.owners
            || saved.failure.is_some()
            || input.stage_operation != saved.stage_operation
            || input.cutoff != saved.cutoff
            || input.inventory != saved.inventory
            || input.deliveries != saved.deliveries
            || !input
                .payloads
                .iter()
                .map(|object| &object.reference)
                .eq(saved.payloads.iter())
            || !lineage_matches
            || !matches_provenance(input, saved)
        {
            return Err(refused("Tape2 FIRST/input/body/ACK custody differs"));
        }
        for reference in &saved.payloads {
            expected.insert(reference.clone());
        }
        if let Some(provenance) = &saved.provenance {
            expected.extend(provenance.objects.iter().cloned());
        }
        if let Some(first) = first {
            for publication in &first.publications {
                expected.extend(publication.objects.iter().cloned());
            }
        }
        let current = saved
            .acknowledgement
            .as_ref()
            .ok_or_else(|| refused("Tape2 source-capture input ACK absent"))?;
        if current.owners != saved.owners
            || !validate_ack_chain(current, ack, wire, source, &mut used_custody)?
        {
            return Err(refused(
                "Tape2 input ACK lacks original or selected model custody",
            ));
        }
    }
    if used_custody != wire.custody_objects.iter().cloned().collect() {
        return Err(refused(
            "Tape2 custody inventory includes unused/future objects",
        ));
    }
    expected.extend(used_custody);
    if expected != source.owner().evidence.iter().cloned().collect() {
        return Err(refused("Tape2 complete original dependency roster differs"));
    }
    Ok(())
}

fn matches_provenance(
    original: &RecordedInput,
    saved: &crate::node_contract::OriginalLineageInputRecord,
) -> bool {
    match (&original.provenance, &saved.provenance) {
        (None, None) => true,
        (Some(old), Some(current)) => {
            old.schema_version == current.schema_version
                && old.node == current.node
                && old.stage_operation == current.stage_operation
                && old.batch == current.batch
                && old.inventory == current.inventory
                && old.roots == current.roots
                && old
                    .objects
                    .iter()
                    .map(|object| &object.reference)
                    .eq(current.objects.iter())
        }
        _ => false,
    }
}

fn validate_ack_chain(
    saved: &NativeInputAcknowledgement,
    original: &NativeInputAcknowledgement,
    wire: &Tape2ContinuationWire,
    source: &AuthenticatedOriginalLineageSource<'_>,
    used: &mut BTreeSet<ContentRef>,
) -> Result<bool, OperationFailure> {
    let mut current = saved.clone();
    let mut visited = BTreeSet::new();
    while current != *original {
        if !visited.insert(current.proof_ref.clone())
            || visited.len() > wire.custody_objects.len()
            || !wire.custody_objects.contains(&current.proof_ref)
        {
            return Ok(false);
        }
        let mut scoped = current.clone();
        scoped.owners = original.owners.clone();
        scoped.proof_ref = original.proof_ref.clone();
        if scoped != *original {
            return Ok(false);
        }
        let bytes = source
            .content()
            .get(&current.proof_ref)
            .ok_or_else(|| refused("Tape2 original custody receipt absent"))?;
        current
            .proof_ref
            .verify(bytes)
            .map_err(|error| refused(error.to_string()))?;
        let value = canonical::parse_json(bytes, MAXIMUM_RECORD_BYTES)
            .map_err(|error| refused(error.to_string()))?;
        let receipt: ReplayInputCustody =
            serde_json::from_value(value).map_err(|error| refused(error.to_string()))?;
        if !matches!(
            receipt.schema.as_str(),
            "crucible.transcript-replay.input-custody.v1"
                | "crucible.transcript-replay.input-admission.v1"
        ) || receipt.owners != current.owners
            || receipt.node != current.node
            || receipt.batch != current.batch
            || receipt.stage_operation != current.stage_operation
            || receipt.inventory != current.inventory
            || receipt.cutoff != current.cutoff
            || !receipt
                .owners
                .iter()
                .all(|owner| receipt.target.owners.contains(owner))
            || receipt.target.world_binding_hash
                != source.runtime().source_activation.world_binding_hash
            || receipt.owners.len() != receipt.source_ack.owners.len()
            || receipt
                .owners
                .iter()
                .zip(&receipt.source_ack.owners)
                .any(|(fresh, old)| {
                    fresh.owner != old.owner
                        || fresh.incarnation == old.incarnation
                        || fresh.generation <= old.generation
                })
            || receipt.schema == "crucible.transcript-replay.input-admission.v1"
                && (receipt.source_state != wire.transcript || receipt.source_ack != *original)
        {
            return Ok(false);
        }
        used.insert(current.proof_ref);
        current = receipt.source_ack;
    }
    Ok(true)
}

fn validate_identity(
    record: &TranscriptRecord,
    request: &ControlRequest,
    observations: usize,
) -> Result<(), OperationFailure> {
    let (action, identity) = match request {
        ControlRequest::Observe => (
            TranscriptAction::Observe,
            Id::new(format!("transcript/observe-{observations}"))
                .map_err(|error| refused(error.to_string()))?,
        ),
        ControlRequest::Stage { input } => {
            (TranscriptAction::StageInput, input.stage_operation.clone())
        }
        ControlRequest::Begin { operation, .. } => (TranscriptAction::Begin, operation.clone()),
        ControlRequest::Complete { operation } => (TranscriptAction::Complete, operation.clone()),
        ControlRequest::Close { operation, .. } => {
            (TranscriptAction::CloseWindow, operation.clone())
        }
        ControlRequest::Acknowledge { operation, .. } => {
            (TranscriptAction::Acknowledge, operation.clone())
        }
        ControlRequest::Cancel { .. } => {
            return Err(refused("Tape2 original cancellation is unsupported"));
        }
    };
    if record.request.action != action || record.request.identity != identity {
        return Err(refused("Tape2 original typed request identity differs"));
    }
    Ok(())
}

fn checked_records<'a>(
    wire: &Tape2ContinuationWire,
    tape: &'a AuthenticatedTranscript,
) -> Result<&'a [TranscriptRecord], OperationFailure> {
    let count = usize::try_from(wire.cursor.next_record.get())
        .map_err(|error| refused(error.to_string()))?;
    let records = tape
        .data
        .records
        .get(..count)
        .ok_or_else(|| refused("Tape2 cursor exceeds original source"))?;
    if wire.transcript != *tape.reference()
        || wire.cursor.source_context
            != super::super::codec::context_commitment(&tape.data.origin)
                .map_err(|error| refused(error.to_string()))?
        || tape.data.origin.route.node != wire.route.node
    {
        return Err(refused("Tape2 cursor context or original node differs"));
    }
    Ok(records)
}

#[cfg(test)]
#[path = "tape2_continuation_tests.rs"]
mod tests;
