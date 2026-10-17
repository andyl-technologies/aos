//! Canonical common-node requests and responses, with complete frozen input bytes.

use crucible_node_contract::{ContentRef, Id, Position};
use serde::{Deserialize, Serialize};

use crate::node_scheduling::event::Delivery;
use crate::{node_contract::*, node_scheduling::*};

use super::{
    codec::{TranscriptError, encode, invalid},
    types::*,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedInput {
    pub(super) node: Id,
    pub(super) stage_operation: Id,
    pub(super) batch: Id,
    pub(super) owners: Vec<OwnerIdentity>,
    pub(super) cutoff: Position,
    pub(super) inventory: ContentRef,
    pub(super) deliveries: Vec<Delivery>,
    pub(super) payloads: Vec<InputPayload>,
    pub(super) provenance: Option<SavedInputProvenance>,
}

impl RecordedInput {
    pub(super) fn from_batch(batch: &RuntimeInputBatch, source_owners: &[OwnerIdentity]) -> Self {
        Self {
            node: batch.node().clone(),
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            owners: source_owners.to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
            deliveries: batch.deliveries().to_vec(),
            payloads: batch.payloads().to_vec(),
            provenance: None,
        }
    }

    pub(super) fn with_provenance(
        batch: &RuntimeInputBatch,
        source_owners: &[OwnerIdentity],
        provenance: Option<&InputProvenanceClosure>,
    ) -> Result<Self, OperationFailure> {
        let mut input = Self::from_batch(batch, source_owners);
        if let Some(provenance) = provenance {
            if !std::rc::Rc::ptr_eq(
                &batch.activation().authority,
                &provenance.activation().authority,
            ) || batch.activation().record() != provenance.activation().record()
                || provenance.node() != batch.node()
                || provenance.stage_operation() != batch.stage_operation()
                || provenance.batch() != batch.batch()
                || provenance.inventory() != batch.inventory()
            {
                return Err(failure(
                    "recorded original input provenance scope differs",
                    EffectKnowledge::None,
                ));
            }
            // Preserve the exact selected codec, including additive dependency rows.
            input.provenance = Some(provenance.saved().clone());
        }
        Ok(input)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ControlRequest {
    Observe,
    Stage {
        input: RecordedInput,
    },
    Begin {
        operation: Id,
        node: Id,
        request: OperationRequest,
        input: Option<RecordedInput>,
    },
    Complete {
        operation: Id,
    },
    Close {
        operation: Id,
        request: OperationRequest,
    },
    Cancel {
        operation: Id,
    },
    Acknowledge {
        operation: Id,
        outputs: Vec<Id>,
    },
}

impl ControlRequest {
    pub(super) fn begin(admission: &OperationAdmission, source_owners: &[OwnerIdentity]) -> Self {
        Self::Begin {
            operation: admission.token().operation().clone(),
            node: admission.token().route().node.clone(),
            request: admission.request().clone(),
            input: admission
                .inputs()
                .map(|batch| RecordedInput::from_batch(batch, source_owners)),
        }
    }
}

impl TranscriptRequest {
    /// Reads original request IDs and bounds before coordinator admission.
    ///
    /// These are recorded data only. The coordinator must independently mint
    /// opaque permissions; this method cannot authorize a run or input transfer.
    ///
    /// # Errors
    /// Refuses changed request bytes or unsupported closed control encodings.
    pub fn request_metadata(&self) -> Result<ReplayRequestMetadata, TranscriptError> {
        self.content.verify(&self.bytes).map_err(invalid)?;
        let body: ControlRequest = serde_json::from_slice(&self.bytes).map_err(invalid)?;
        let (operation, input) = match &body {
            ControlRequest::Stage { input } => (None, Some(input)),
            ControlRequest::Begin { request, input, .. } => (Some(request.clone()), input.as_ref()),
            ControlRequest::Close { request, .. } => (Some(request.clone()), None),
            _ => (None, None),
        };
        Ok(ReplayRequestMetadata {
            action: self.action,
            identity: self.identity.clone(),
            operation,
            input_batch: input.map(|input| input.batch.clone()),
            input_stage: input.map(|input| input.stage_operation.clone()),
            input_cut: input.map(|input| input.cutoff),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum ControlResponse {
    Observation(Box<NativeSchedulingObservation>),
    Input(Box<NativeInputAcknowledgement>),
    Submission(Submission),
    Outcome(Box<OperationOutcome>),
    Failure(OperationFailure),
    Cancel(String),
    Acknowledged,
}

pub(super) fn request(
    action: TranscriptAction,
    identity: Id,
    boundary: Position,
    context: ContentRef,
    body: &ControlRequest,
) -> Result<TranscriptRequest, TranscriptError> {
    let bytes = encode(body)?;
    let content = crucible_node_contract::canonical::content_ref(&bytes, "application/json")
        .map_err(invalid)?;
    Ok(TranscriptRequest {
        action,
        identity,
        boundary,
        content,
        bytes,
        context,
    })
}

pub(super) fn outcome_references(outcome: &OperationOutcome) -> Vec<ContentRef> {
    let mut refs = Vec::new();
    let mut retain = |reference: &ContentRef| {
        if !refs.contains(reference) {
            refs.push(reference.clone());
        }
    };
    match &outcome.progress {
        ProgressEvidence::Quantized { closure, .. } => {
            retain(&closure.close_receipt);
            retain(&closure.output_inventory);
            retain(&closure.pending_inventory);
            retain(&closure.clock_evidence);
        }
        ProgressEvidence::Paused { stop_receipt, .. } => retain(stop_receipt),
        ProgressEvidence::AssertionsFinalized {
            barrier, report, ..
        } => {
            retain(barrier);
            retain(report);
        }
        _ => {}
    }
    if let Some(observation) = &outcome.scheduling {
        retain(&observation.proof_ref);
        for bound in &observation.bounds {
            retain(&bound.proof_ref);
        }
        for publication in &observation.publications {
            retain(&publication.payload);
        }
        if let Some(progress) = &observation.input_progress {
            retain(&progress.proof_ref);
        }
        for inventory in &observation.external_inputs {
            retain(&inventory.proof_ref);
            for input in &inventory.inputs {
                retain(&input.provenance_ref);
                retain(&input.payload);
            }
        }
    }
    refs
}

pub(super) fn observation_references(observation: &NativeSchedulingObservation) -> Vec<ContentRef> {
    let mut refs = observation_proof_references(observation);
    for reference in observation
        .publications
        .iter()
        .map(|output| &output.payload)
        .chain(
            observation
                .external_inputs
                .iter()
                .flat_map(|external| external.inputs.iter().map(|input| &input.payload)),
        )
    {
        if !refs.contains(reference) {
            refs.push(reference.clone());
        }
    }
    refs
}

pub(super) fn observation_proof_references(
    observation: &NativeSchedulingObservation,
) -> Vec<ContentRef> {
    let mut refs = vec![observation.proof_ref.clone()];
    let mut retain = |reference: &ContentRef| {
        if !refs.contains(reference) {
            refs.push(reference.clone());
        }
    };
    for bound in &observation.bounds {
        retain(&bound.proof_ref);
    }
    if let Some(progress) = &observation.input_progress {
        retain(&progress.proof_ref);
    }
    for external in &observation.external_inputs {
        retain(&external.proof_ref);
        for input in &external.inputs {
            retain(&input.provenance_ref);
        }
    }
    refs
}

pub(super) fn outcome_positions(outcome: &OperationOutcome) -> Vec<Position> {
    let mut positions = match &outcome.progress {
        ProgressEvidence::Exact { reached, .. }
        | ProgressEvidence::AssertionsFinalized { reached, .. }
        | ProgressEvidence::FaultMutationApplied { reached, .. }
        | ProgressEvidence::DebugConditionAppliedV1 { reached, .. } => vec![*reached],
        ProgressEvidence::Paused { reached, .. } => reached.iter().copied().collect(),
        ProgressEvidence::Quantized { publication, .. } => vec![*publication],
        ProgressEvidence::Administrative => Vec::new(),
    };
    if let Some(observation) = &outcome.scheduling {
        for output in &observation.publications {
            positions.push(output.publication);
        }
        for external in &observation.external_inputs {
            for input in &external.inputs {
                positions.push(input.publication);
            }
        }
    }
    positions
}

pub(super) fn failure(error: impl std::fmt::Display, effects: EffectKnowledge) -> OperationFailure {
    OperationFailure {
        effects,
        reason: error.to_string(),
    }
}
