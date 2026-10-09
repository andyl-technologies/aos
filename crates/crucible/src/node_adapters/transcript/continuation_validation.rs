//! Exact cursor/cache reconciliation against the consumed original transcript.

use super::*;

#[derive(Default)]
struct OriginalOperation {
    request: Option<OperationRequest>,
    input: Option<Id>,
    outcome: Option<OperationOutcome>,
    evidence: Vec<InputPayload>,
    acknowledged: bool,
    close: Option<Submission>,
}

pub(super) fn validate_consumed_prefix(
    wire: &ReplayContinuationWire,
    source: &AuthenticatedTranscript,
) -> Result<(), OperationFailure> {
    let count = usize::try_from(wire.cursor.next_record.get())
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    let records = source.data.records.get(..count).ok_or_else(|| {
        failure(
            "replay cursor exceeds original transcript",
            EffectKnowledge::None,
        )
    })?;
    let mut boundary = source.data.origin.activation.boundary;
    let mut operations = BTreeMap::<Id, OriginalOperation>::new();
    let mut inputs = BTreeMap::<Id, (RecordedInput, NativeInputAcknowledgement)>::new();
    let mut observations = Vec::new();
    for record in records {
        if record.request.boundary != boundary {
            return Err(failure(
                "replay consumed request boundary is inconsistent",
                EffectKnowledge::None,
            ));
        }
        let request: ControlRequest = serde_json::from_slice(&record.request.bytes)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        validate_request_identity(record, &request, observations.len())?;
        let response: ControlResponse = serde_json::from_slice(&record.response_bytes)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
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
                    return Err(failure(
                        "original replay Begin is duplicated or foreign",
                        EffectKnowledge::None,
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
            (ControlRequest::Begin { .. }, ControlResponse::Submission(_)) => {}
            (ControlRequest::Complete { operation }, ControlResponse::Outcome(outcome)) => {
                let original = operations.get_mut(&operation).ok_or_else(|| {
                    failure(
                        "original completion has no accepted Begin",
                        EffectKnowledge::None,
                    )
                })?;
                if original.outcome.is_some()
                    || outcome.operation != operation
                    || outcome.node != wire.route.node
                    || outcome.owners != source.data.origin.route.owners
                {
                    return Err(failure(
                        "original replay completion is duplicated or foreign",
                        EffectKnowledge::None,
                    ));
                }
                let mut outcome = *outcome;
                outcome.owners = wire.route.owners.clone();
                if let Some(observation) = &mut outcome.scheduling {
                    observation.owners = wire.route.owners.clone();
                }
                original.outcome = Some(outcome);
                original.evidence = record.evidence.clone();
            }
            (ControlRequest::Close { operation, .. }, ControlResponse::Submission(submission)) => {
                let original = operations.get_mut(&operation).ok_or_else(|| {
                    failure(
                        "original Close has no accepted Begin",
                        EffectKnowledge::None,
                    )
                })?;
                if original.close.replace(submission).is_some() {
                    return Err(failure(
                        "original Close was replayed twice",
                        EffectKnowledge::None,
                    ));
                }
            }
            (ControlRequest::Acknowledge { operation, outputs }, ControlResponse::Acknowledged) => {
                let original = operations.get_mut(&operation).ok_or_else(|| {
                    failure("original ACK has no accepted Begin", EffectKnowledge::None)
                })?;
                if original
                    .outcome
                    .as_ref()
                    .is_none_or(|outcome| outcome.retained_outputs != outputs)
                    || original.acknowledged
                {
                    return Err(failure(
                        "original ACK inventory or identity differs",
                        EffectKnowledge::None,
                    ));
                }
                original.acknowledged = true;
                boundary = record.assigned_positions.first().copied().ok_or_else(|| {
                    failure("original ACK boundary is absent", EffectKnowledge::None)
                })?;
            }
            (ControlRequest::Stage { input }, ControlResponse::Input(ack)) => {
                let ack = *ack;
                if input.node != wire.route.node
                    || ack.node != wire.route.node
                    || input.owners != source.data.origin.route.owners
                    || ack.owners != source.data.origin.route.owners
                {
                    return Err(failure(
                        "original replay input belongs to another source",
                        EffectKnowledge::None,
                    ));
                }
                if inputs
                    .get(&input.batch)
                    .is_some_and(|original| original != &(input.clone(), ack.clone()))
                {
                    return Err(failure(
                        "original staged retry changed its input",
                        EffectKnowledge::None,
                    ));
                }
                inputs.insert(input.batch.clone(), (input, ack));
            }
            (ControlRequest::Observe, ControlResponse::Observation(observation)) => {
                let mut observation = *observation;
                if observation.node != wire.route.node
                    || observation.owners != source.data.origin.route.owners
                {
                    return Err(failure(
                        "original replay observation belongs to another source",
                        EffectKnowledge::None,
                    ));
                }
                observation.owners = wire.route.owners.clone();
                observations.push(observation);
            }
            _ => {
                return Err(failure(
                    "unsupported original replay state transition",
                    EffectKnowledge::None,
                ));
            }
        }
    }
    if boundary != wire.boundary
        || observations != wire.observations
        || operations.len() != wire.operations.len()
        || inputs.len() != wire.inputs.len()
    {
        return Err(failure(
            "replay cursor does not explain complete cache custody",
            EffectKnowledge::None,
        ));
    }
    for cached in &wire.operations {
        let original = operations.get(&cached.original.operation).ok_or_else(|| {
            failure(
                "replay cache introduces an unrecorded operation",
                EffectKnowledge::None,
            )
        })?;
        let outcome = match &cached.original.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                Some(outcome)
            }
            SavedRuntimeResult::Pending | SavedRuntimeResult::Failed(_) => None,
        };
        if original.request.as_ref() != Some(&cached.original.request)
            || original.input != cached.original.input_batch
            || original.outcome.as_ref() != outcome
            || original.evidence != cached.evidence
            || original.close != cached.original.close_submission
            || original.acknowledged
                != matches!(cached.original.result, SavedRuntimeResult::Acknowledged(_))
        {
            return Err(failure(
                "replay cached operation differs from original consumed prefix",
                EffectKnowledge::None,
            ));
        }
    }
    let mut used_custody = BTreeSet::new();
    for saved in &wire.inputs {
        let (input, ack) = inputs.get(&saved.batch).ok_or_else(|| {
            failure(
                "replay cache introduces an unrecorded input",
                EffectKnowledge::None,
            )
        })?;
        if input.stage_operation != saved.stage_operation
            || input.cutoff != saved.cutoff
            || input.inventory != saved.inventory
            || input.deliveries != saved.deliveries
            || input.payloads != saved.payloads
            || input.provenance != saved.provenance
        {
            return Err(failure(
                "replay frozen input differs from original consumed prefix",
                EffectKnowledge::None,
            ));
        }
        let saved_ack = saved
            .acknowledgement
            .as_ref()
            .ok_or_else(|| failure("preserved replay ACK is absent", EffectKnowledge::None))?;
        if saved_ack != ack
            && !validate_reminted_input_ack(
                saved_ack,
                ack,
                &wire.custody_objects,
                &mut used_custody,
                source.reference(),
            )?
        {
            return Err(failure(
                "replay input ACK has no original or restored model lineage",
                EffectKnowledge::None,
            ));
        }
    }
    if used_custody
        != wire
            .custody_objects
            .iter()
            .map(|object| object.reference.clone())
            .collect()
    {
        return Err(failure(
            "replay custody introduces an unrecorded or future evidence object",
            EffectKnowledge::None,
        ));
    }
    Ok(())
}

fn validate_reminted_input_ack(
    saved: &NativeInputAcknowledgement,
    original: &NativeInputAcknowledgement,
    objects: &[InputPayload],
    used: &mut BTreeSet<ContentRef>,
    source: &ContentRef,
) -> Result<bool, OperationFailure> {
    let mut current = saved.clone();
    let mut visited = BTreeSet::new();
    loop {
        if current == *original {
            return Ok(true);
        }
        if !visited.insert(current.proof_ref.clone()) || visited.len() > objects.len() {
            return Ok(false);
        }
        let mut normalized = current.clone();
        normalized.owners = original.owners.clone();
        normalized.proof_ref = original.proof_ref.clone();
        if normalized != *original {
            return Ok(false);
        }
        let Some(object) = objects
            .iter()
            .find(|object| object.reference == current.proof_ref)
        else {
            return Ok(false);
        };
        object
            .reference
            .verify(&object.bytes)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        used.insert(object.reference.clone());
        let value = canonical::parse_json(&object.bytes, MAXIMUM_STATE_BYTES)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let receipt: ReplayInputCustody =
            serde_json::from_value(value).map_err(|error| failure(error, EffectKnowledge::None))?;
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
        {
            return Ok(false);
        }
        if receipt.schema == "crucible.transcript-replay.input-admission.v1"
            && (receipt.source_state != *source || receipt.source_ack != *original)
        {
            return Ok(false);
        }
        current = receipt.source_ack;
    }
}

fn validate_request_identity(
    record: &TranscriptRecord,
    request: &ControlRequest,
    observation_sequence: usize,
) -> Result<(), OperationFailure> {
    let (action, identity) = match request {
        ControlRequest::Observe => (
            TranscriptAction::Observe,
            Id::new(format!("transcript/observe-{observation_sequence}"))
                .map_err(|error| failure(error, EffectKnowledge::None))?,
        ),
        ControlRequest::Stage { input } => {
            (TranscriptAction::StageInput, input.stage_operation.clone())
        }
        ControlRequest::Begin { operation, .. } => (TranscriptAction::Begin, operation.clone()),
        ControlRequest::Complete { operation } => (TranscriptAction::Complete, operation.clone()),
        ControlRequest::Close { operation, .. } => {
            (TranscriptAction::CloseWindow, operation.clone())
        }
        ControlRequest::Cancel { operation } => (TranscriptAction::Cancel, operation.clone()),
        ControlRequest::Acknowledge { operation, .. } => {
            (TranscriptAction::Acknowledge, operation.clone())
        }
    };
    if record.request.action != action || record.request.identity != identity {
        return Err(failure(
            "original request envelope differs from its exact typed interaction",
            EffectKnowledge::None,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "custody_chain_tests.rs"]
mod custody_chain_tests;
