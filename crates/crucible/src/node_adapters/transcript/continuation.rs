//! Complete replay cursor and original custody below an authenticated native archive.
//!
//! ```text
//! {"schema_version":1,"runtime":{...},"route":{...},"cursor":{...},
//!  "boundary":{...},"transcript":{...},"qualification":{...},
//!  "operations":[...],"inputs":[...],"observations":[...]}
//! ```
//!
//! This codec preserves the replay model, not the physical source process.
//! Original transcript bytes and receipts are immutable dependencies. Fresh
//! operation tokens are installed only through complete-world restoration.

use std::{
    collections::BTreeSet,
    io::{self, Write},
};

use crucible_node_contract::SchemaRef;
use serde::{Deserialize, Serialize};

use super::*;

#[path = "capture_state.rs"]
mod capture_state;
#[path = "native_dependencies.rs"]
mod native_dependencies;
#[path = "restoration.rs"]
mod restoration;
#[path = "continuation_validation.rs"]
mod validation;

/// Identifies complete preservation of the conditional replay model.
pub const TRANSCRIPT_REPLAY_PRESERVATION_PROFILE: &str =
    "transcript/complete-replay-continuation-v1";

const SPECIFICATION: &str = "crucible/transcript-replay-continuation-v1: complete original authenticated transcript and context, conditional source uncertainty and taint, exact sticky cursor, original local request boundary, whole source runtime ledger and capture cut, cached original operation permission/outcome/evidence/close/ACK knowledge, immutable staged deliveries/payloads/provenance/ACK, and consumed boundary observations. The complete model accepts only structurally typed positive Begin/Outcome/Input/Observation/ACK records and authentic subordinate Close Accepted/Refused records. Original Failure, Cancel, Unknown and unsupported control trajectories are refused before readiness even under a permissive installed qualifier. Source bytes and proofs retain original lineage. No serialized token, native process restoration claim, counterfactual resampling or caller-selected cursor. Fresh installed qualification and complete-world original-token reminting are mandatory.";
pub(in crate::node_adapters::transcript) const MAXIMUM_STATE_BYTES: usize = 64 * 1024 * 1024;
pub(in crate::node_adapters::transcript) const MAXIMUM_OBJECTS: usize = 8192;

/// Refuses unsupported original controls before complete-model readiness.
///
/// Recording preserves authentic negative responses, but this preservation
/// codec does not claim to reconstruct their native failure or uncertainty.
pub(in crate::node_adapters::transcript) fn validate_preservation_trajectory(
    source: &AuthenticatedTranscript,
) -> Result<(), TranscriptError> {
    for record in &source.data.records {
        let request: ControlRequest =
            serde_json::from_slice(&record.request.bytes).map_err(invalid)?;
        let response: ControlResponse =
            serde_json::from_slice(&record.response_bytes).map_err(invalid)?;
        let action = match (request, response) {
            (ControlRequest::Begin { .. }, ControlResponse::Submission(Submission::Accepted)) => {
                TranscriptAction::Begin
            }
            (ControlRequest::Complete { .. }, ControlResponse::Outcome(_)) => {
                TranscriptAction::Complete
            }
            (ControlRequest::Stage { .. }, ControlResponse::Input(_)) => {
                TranscriptAction::StageInput
            }
            (ControlRequest::Observe, ControlResponse::Observation(_)) => TranscriptAction::Observe,
            (ControlRequest::Acknowledge { .. }, ControlResponse::Acknowledged) => {
                TranscriptAction::Acknowledge
            }
            (
                ControlRequest::Close { .. },
                ControlResponse::Submission(Submission::Accepted | Submission::Refused(_)),
            ) => TranscriptAction::CloseWindow,
            _ => {
                return Err(invalid(
                    "complete replay preservation does not support the original negative or uncertain control trajectory",
                ));
            }
        };
        if record.request.action != action {
            return Err(invalid(
                "original preservation control action differs from its typed body",
            ));
        }
    }
    Ok(())
}

/// Returns the exact installed codec definition as immutable data.
pub fn transcript_replay_continuation_definition() -> &'static [u8] {
    SPECIFICATION.as_bytes()
}

/// Returns the installed complete conditional-replay continuation codec identity.
///
/// # Errors
/// Returns invalid portable identity or content construction errors.
pub fn transcript_replay_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("transcript/replay-continuation-v1")
            .map_err(|error| failure(error, EffectKnowledge::None))?,
        version: 1,
        definition: canonical::content_ref(SPECIFICATION.as_bytes(), "text/plain")
            .map_err(|error| failure(error, EffectKnowledge::None))?,
        extensions: Extensions::default(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedReplayOperation {
    pub original: SavedRuntimeOperation,
    pub evidence: Vec<InputPayload>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayContinuationWire {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    pub runtime: RuntimeSnapshot,
    pub route: NodeRoute,
    pub binding: NodeBinding,
    pub cursor: ReplayCursorSnapshot,
    pub boundary: Position,
    pub transcript: ContentRef,
    pub qualification: ContentRef,
    pub operations: Vec<SavedReplayOperation>,
    pub inputs: Vec<SavedRuntimeInput>,
    pub observations: Vec<NativeSchedulingObservation>,
    pub custody_objects: Vec<InputPayload>,
}

/// A closed replay-model custody receipt, distinct from physical-source proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::transcript) struct ReplayInputCustody {
    pub schema: String,
    pub source_state: ContentRef,
    pub source_ack: NativeInputAcknowledgement,
    pub target: SavedRuntimeActivation,
    pub node: Id,
    pub owners: Vec<OwnerIdentity>,
    pub batch: Id,
    pub stage_operation: Id,
    pub inventory: ContentRef,
    pub cutoff: Position,
}

/// Retains complete historical replay state admitted through a signed native archive.
///
/// This seal contains data only. It cannot arm a new world, authorize a run,
/// restore the physical source, or select an arbitrary unrecorded cursor.
pub struct AuthenticatedReplayContinuation {
    pub(super) wire: ReplayContinuationWire,
    pub(super) source: AuthenticatedTranscript,
    pub(super) reference: ContentRef,
    pub(super) qualification: InputPayload,
}

impl AuthenticatedReplayContinuation {
    /// Borrows the complete original common runtime custody.
    pub fn runtime(&self) -> &RuntimeSnapshot {
        &self.wire.runtime
    }

    /// Borrows the exact historical replay node and owner route as inert data.
    pub fn route(&self) -> &NodeRoute {
        &self.wire.route
    }

    /// Borrows the complete historical replay implementation and model binding.
    ///
    /// Its source incarnation is not live authority for the fresh target.
    pub fn binding(&self) -> &NodeBinding {
        &self.wire.binding
    }

    /// Borrows the exact original sticky replay cursor as inert state.
    pub fn cursor(&self) -> &ReplayCursorSnapshot {
        &self.wire.cursor
    }

    /// Borrows the authenticated physical-origin transcript without minting replay authority.
    pub fn transcript(&self) -> &AuthenticatedTranscript {
        &self.source
    }

    /// Borrows historical installed applicability evidence as immutable source data.
    ///
    /// This does not qualify the fresh target. Restoration independently invokes
    /// its installed policy against the actual target graph and full context.
    pub fn original_qualification(&self) -> &InputPayload {
        &self.qualification
    }
}

/// Authenticates complete conditional-replay state beneath a signed native source seal.
///
/// Installed applicability qualification is still mandatory on the fresh target.
/// This function never reads a source-host path or accepts an unsigned cursor.
///
/// # Errors
/// Refuses another backend/profile/schema, changed source runtime, incomplete
/// original evidence, invalid cursor/cache state, or finite metadata excess.
pub fn authenticate_replay_continuation(
    source: &crate::node_state::AuthenticatedNativeSource<'_>,
    node: &Id,
) -> Result<AuthenticatedReplayContinuation, OperationFailure> {
    let owner = source.owner();
    if owner.key.profile.as_str() != TRANSCRIPT_REPLAY_PRESERVATION_PROFILE
        || owner.key.schema != transcript_replay_continuation_schema()?
        || owner.participants.as_slice() != std::slice::from_ref(node)
        || !owner.artifacts.is_empty()
        || owner.evidence.len() > MAXIMUM_OBJECTS
    {
        return Err(failure(
            "unsupported authenticated replay continuation scope",
            EffectKnowledge::None,
        ));
    }
    let raw = source
        .native()
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    if raw.len() > MAXIMUM_STATE_BYTES {
        return Err(failure(
            "replay continuation exceeds finite state credit",
            EffectKnowledge::None,
        ));
    }
    let value = canonical::parse_json(raw, MAXIMUM_STATE_BYTES)
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    let wire: ReplayContinuationWire =
        serde_json::from_value(value).map_err(|error| failure(error, EffectKnowledge::None))?;
    if bounded_canonical(&wire, MAXIMUM_STATE_BYTES)? != raw
        || wire.runtime != *source.runtime()
        || wire.binding.compatibility.implementation.implementation_id != owner.key.implementation
        || wire.route.node != *node
        || wire.route.owners.len() != 1
        || wire.route.owners[0].owner != owner.owner
        || wire.runtime.capture_cut != owner.cut
    {
        return Err(failure(
            "authenticated replay source ledger differs",
            EffectKnowledge::None,
        ));
    }
    let transcript_bytes = source.content().get(&wire.transcript).ok_or_else(|| {
        failure(
            "original replay transcript bytes absent",
            EffectKnowledge::None,
        )
    })?;
    let qualification_bytes = source.content().get(&wire.qualification).ok_or_else(|| {
        failure(
            "original installed replay qualification absent",
            EffectKnowledge::None,
        )
    })?;
    wire.transcript
        .verify(transcript_bytes)
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    wire.qualification
        .verify(qualification_bytes)
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    let data = super::super::types::BoundaryTranscript::from_canonical_bytes(transcript_bytes)
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    let source_transcript = AuthenticatedTranscript {
        data: Rc::new(data),
        bytes: Rc::new(transcript_bytes.to_vec()),
        reference: wire.transcript.clone(),
    };
    validate_wire(&wire, &source_transcript)?;
    let qualification = InputPayload {
        reference: wire.qualification.clone(),
        bytes: qualification_bytes.to_vec(),
    };
    let inputs = wire.inputs.iter().collect::<Vec<_>>();
    let dependencies = native_dependencies::ReplayDependencies::prepare(
        &source_transcript,
        usize::try_from(wire.cursor.next_record.get())
            .map_err(|error| failure(error, EffectKnowledge::None))?,
        &qualification,
        &inputs,
        wire.custody_objects.iter(),
        NativeCaptureLimits {
            maximum_record_bytes: MAXIMUM_STATE_BYTES,
            maximum_total_record_bytes: MAXIMUM_STATE_BYTES,
            maximum_objects: MAXIMUM_OBJECTS,
            maximum_artifact_bytes: 0,
            maximum_total_artifact_bytes: 0,
        },
    )?;
    if owner.evidence.iter().cloned().collect::<BTreeSet<_>>() != dependencies.references() {
        return Err(failure(
            "complete replay native dependency inventory differs",
            EffectKnowledge::None,
        ));
    }
    dependencies.verify_registry(source.content())?;
    Ok(AuthenticatedReplayContinuation {
        qualification: InputPayload {
            reference: wire.qualification.clone(),
            bytes: qualification_bytes.to_vec(),
        },
        wire,
        source: source_transcript,
        reference: owner.state.clone(),
    })
}

pub(super) fn validate_wire(
    wire: &ReplayContinuationWire,
    source: &AuthenticatedTranscript,
) -> Result<(), OperationFailure> {
    if wire.schema_version != 1
        || wire.cursor.schema_version != 1
        || wire.transcript != *source.reference()
        || wire.cursor.transcript != wire.transcript
        || wire.cursor.source_context
            != super::super::codec::context_commitment(&source.data.origin)
                .map_err(|error| failure(error, EffectKnowledge::None))?
        || wire.cursor.next_record.get() > source.data.records.len() as u64
        || wire.route.node != source.data.origin.route.node
        || wire.operations.len() > MAXIMUM_OBJECTS
        || wire.inputs.len() > MAXIMUM_OBJECTS
        || wire.observations.len() > MAXIMUM_OBJECTS
        || wire.custody_objects.len() > MAXIMUM_OBJECTS
        || !wire
            .route
            .owners
            .iter()
            .all(|owner| wire.runtime.source_activation.owners.contains(owner))
    {
        return Err(failure(
            "invalid complete replay cursor or owner state",
            EffectKnowledge::None,
        ));
    }
    let originals: Vec<_> = wire
        .runtime
        .operations
        .iter()
        .filter(|operation| operation.route.node == wire.route.node)
        .collect();
    if originals.len() != wire.operations.len()
        || originals
            .iter()
            .zip(&wire.operations)
            .any(|(original, cached)| *original != &cached.original)
        || wire
            .runtime
            .inputs
            .iter()
            .filter(|input| input.node == wire.route.node)
            .ne(wire.inputs.iter())
    {
        return Err(failure(
            "replay custody inventory omits original runtime entries",
            EffectKnowledge::None,
        ));
    }
    for operation in &wire.operations {
        if operation.original.route != wire.route
            || operation.evidence.len() > MAXIMUM_OBJECTS
            || operation
                .evidence
                .iter()
                .any(|object| object.reference.verify(&object.bytes).is_err())
            || matches!(operation.original.result, SavedRuntimeResult::Failed(_))
                && !wire.cursor.diverged
        {
            return Err(failure(
                "replay original operation or raw evidence differs",
                EffectKnowledge::None,
            ));
        }
    }
    if wire.inputs.iter().any(|input| {
        input.owners != wire.route.owners
            || input.failure.is_some()
            || input.acknowledgement.as_ref().is_none_or(|ack| {
                ack.node != wire.route.node
                    || ack.owners != wire.route.owners
                    || ack.batch != input.batch
                    || ack.stage_operation != input.stage_operation
                    || ack.cutoff != input.cutoff
                    || ack.inventory != input.inventory
            })
    }) || wire.observations.iter().any(|observation| {
        observation.node != wire.route.node || observation.owners != wire.route.owners
    }) {
        return Err(failure(
            "replay preserved native input or observation custody differs",
            EffectKnowledge::None,
        ));
    }
    let mut unique = BTreeSet::new();
    if wire.custody_objects.iter().any(|object| {
        !unique.insert(&object.reference) || object.reference.verify(&object.bytes).is_err()
    }) {
        return Err(failure(
            "replay preserved custody proof bytes changed",
            EffectKnowledge::None,
        ));
    }
    validation::validate_consumed_prefix(wire, source)
}

pub(in crate::node_adapters::transcript) fn bounded_canonical(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, OperationFailure> {
    let mut writer = CountWriter {
        remaining: maximum.min(MAXIMUM_STATE_BYTES),
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    let value =
        serde_json::to_value(value).map_err(|error| failure(error, EffectKnowledge::None))?;
    let bytes =
        canonical::canonical_json(&value).map_err(|error| failure(error, EffectKnowledge::None))?;
    if bytes.len() > maximum.min(MAXIMUM_STATE_BYTES) {
        return Err(failure(
            "complete replay state exceeds preallocation credit",
            EffectKnowledge::None,
        ));
    }
    Ok(bytes)
}

struct CountWriter {
    remaining: usize,
}

fn count_encoding(
    value: &impl Serialize,
    writer: &mut CountWriter,
) -> Result<(), OperationFailure> {
    serde_json::to_writer(writer, value).map_err(|error| failure(error, EffectKnowledge::None))
}

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("replay state preallocation credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
