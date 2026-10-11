//! Retains explicit historical lineage roles inside original Tape2 interactions.
//!
//! The reference-only format keeps source capture and first producer scope
//! separate. Its raw bodies remain ordinary typed transcript evidence. Decoding
//! checks integrity; only an installed policy and owning native callbacks can
//! authenticate those historical facts or associate a fresh target.
//!
//! ```text
//! {"schema_version":2,"source_capture":{...},"node":"...",
//!  "interaction":"...","lineage":{"kind":"publication","publication":{...}}}
//! ```

use crucible_node_contract::{ContentRef, Event, Id, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::{
    node_contract::Submission,
    node_contract::{
        OriginalInputLineageLimits, SavedOriginalInputLineage, SavedOriginalPublication,
        SavedRuntimeActivation,
    },
    node_scheduling::InputPayload,
};

use super::{
    codec::{TranscriptError, encode, invalid},
    control::{ControlRequest, ControlResponse},
    types::{TranscriptAction, TranscriptOrigin, TranscriptRecord},
};

pub(super) const MEDIA_TYPE: &str =
    "application/vnd.crucible.transcript-original-lineage+json;version=2";

/// Selects the separately qualified historical original-lineage Tape2 reader.
///
/// Selecting this facet grants no physical preservation or native source class.
pub const TRANSCRIPT_ORIGINAL_LINEAGE_PROFILE: &str = "transcript/conditional-original-lineage-v2";

/// Borrows only authenticated historical evidence in the consumed Tape2 prefix.
///
/// This view carries no native or runtime input authority. It never searches a
/// future interaction, even when the same typed role also occurs in later data.
pub struct OriginalLineageTapePrefix<'a> {
    source: &'a super::archive::AuthenticatedTranscript,
    consumed: usize,
}

impl<'a> OriginalLineageTapePrefix<'a> {
    pub(super) fn from_cursor(
        cursor: &'a super::replay::ReplayCursor,
    ) -> Result<Self, TranscriptError> {
        if cursor.original_lineage.is_none() || cursor.next > cursor.source.data.records.len() {
            return Err(TranscriptError::Unqualified(
                "original lineage Tape2 reader is not independently qualified".into(),
            ));
        }
        Ok(Self {
            source: &cursor.source,
            consumed: cursor.next,
        })
    }

    /// Borrows the authenticated complete original tape identity.
    pub fn source(&self) -> &ContentRef {
        self.source.reference()
    }

    /// Borrows the source capture activation without relabeling it as a target.
    pub fn source_capture(&self) -> &SavedRuntimeActivation {
        &self.source.data.origin.activation
    }

    /// Reports the exclusive original interaction cutoff.
    pub fn consumed_records(&self) -> usize {
        self.consumed
    }

    /// Reads exact full typed body roles from the consumed original prefix.
    ///
    /// All requested extents are charged before the first returned body copy.
    /// A role absent from the prefix is refused even if it exists in the future.
    ///
    /// # Errors
    /// Refuses missing original roles, changed bodies or aggregate copy credit.
    pub fn read_original_bodies(
        &self,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, TranscriptError> {
        if references.len() > 4096 {
            return Err(TranscriptError::CaptureLimit);
        }
        let mut bytes = 0usize;
        for reference in references {
            let body = self
                .body(reference)
                .ok_or_else(|| invalid("original Tape2 body is beyond consumed cutoff"))?;
            reference.verify(body).map_err(invalid)?;
            bytes = bytes
                .checked_add(body.len())
                .filter(|bytes| *bytes <= maximum_bytes)
                .ok_or(TranscriptError::CaptureLimit)?;
        }
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(references.len())
            .map_err(|_| TranscriptError::CaptureLimit)?;
        for reference in references {
            let original = self
                .body(reference)
                .ok_or_else(|| invalid("original Tape2 body disappeared"))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(original.len())
                .map_err(|_| TranscriptError::CaptureLimit)?;
            bytes.extend_from_slice(original);
            objects.push(InputPayload {
                reference: reference.clone(),
                bytes,
            });
        }
        Ok(objects)
    }

    /// Reads an original producer claim beneath its consumed terminal record.
    ///
    /// The returned reference-only data remains historical. An installed source
    /// verifier must separately bind the actual native and current target scopes.
    ///
    /// # Errors
    /// Refuses unconsumed, missing, ambiguous or changed original publication data.
    pub fn publication(
        &self,
        operation: &Id,
        published: &ContentRef,
    ) -> Result<SavedOriginalPublication, TranscriptError> {
        let mut found = None;
        for record in &self.source.data.records[..self.consumed] {
            if record.request.identity != *operation
                || record.request.action != TranscriptAction::Complete
            {
                continue;
            }
            for object in &record.evidence {
                let Some(tape) = RecordedTape2::decode(object, &self.source.data.origin, record)?
                else {
                    continue;
                };
                if let RecordedLineage::Publication { publication } = tape.lineage
                    && publication.published == *published
                {
                    if found.is_some() {
                        return Err(invalid("original Tape2 terminal publication is ambiguous"));
                    }
                    found = Some(*publication);
                }
            }
        }
        found
            .ok_or_else(|| invalid("original Tape2 terminal publication is beyond consumed cutoff"))
    }

    /// Reads first-sealed input lineage only after its original Stage is consumed.
    ///
    /// # Errors
    /// Refuses unconsumed, missing or ambiguous staging evidence and changed roles.
    pub fn input(&self, stage: &Id) -> Result<SavedOriginalInputLineage, TranscriptError> {
        let mut found = None;
        for record in &self.source.data.records[..self.consumed] {
            if record.request.identity != *stage
                || record.request.action != TranscriptAction::StageInput
            {
                continue;
            }
            for object in &record.evidence {
                let Some(tape) = RecordedTape2::decode(object, &self.source.data.origin, record)?
                else {
                    continue;
                };
                if let RecordedLineage::Input { input } = tape.lineage {
                    if found.is_some() {
                        return Err(invalid("original Tape2 input Stage is ambiguous"));
                    }
                    found = Some(*input);
                }
            }
        }
        found.ok_or_else(|| invalid("original Tape2 input Stage is beyond consumed cutoff"))
    }

    pub(super) fn publication_matching(
        &self,
        operation: &Id,
        native: &crate::node_scheduling::NativePublication,
    ) -> Result<SavedOriginalPublication, TranscriptError> {
        let mut found = None;
        for record in &self.source.data.records[..self.consumed] {
            if record.request.identity != *operation
                || record.request.action != TranscriptAction::Complete
            {
                continue;
            }
            for object in &record.evidence {
                let Some(tape) = RecordedTape2::decode(object, &self.source.data.origin, record)?
                else {
                    continue;
                };
                let RecordedLineage::Publication { publication } = tape.lineage else {
                    continue;
                };
                let bytes = self
                    .body(&publication.published)
                    .ok_or_else(|| invalid("original Tape2 publication body is absent"))?;
                let event: Event = canonical::decode(bytes, bytes.len()).map_err(invalid)?;
                if event.id == native.publication_id
                    && event.source == native.endpoint
                    && event.source_sequence == native.native_sequence
                    && event.publication_position == native.publication
                    && event.payload == native.payload
                    && native.causal_parents.is_empty()
                {
                    if found.is_some() {
                        return Err(invalid("original Tape2 terminal tuple is ambiguous"));
                    }
                    found = Some(*publication);
                }
            }
        }
        found.ok_or_else(|| invalid("original terminal tuple is beyond the consumed cutoff"))
    }

    pub(super) fn validate_publication_limits(
        &self,
        publication: &SavedOriginalPublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<(), TranscriptError> {
        validate_publication(publication, limits, |reference| self.body(reference))?;
        Ok(())
    }

    pub(super) fn matches_original_bodies(
        &self,
        objects: &[InputPayload],
    ) -> Result<(), TranscriptError> {
        if objects.len() > 4096 {
            return Err(TranscriptError::CaptureLimit);
        }
        let mut total = 0usize;
        for object in objects {
            total = total
                .checked_add(object.bytes.len())
                .filter(|total| *total <= 64 * 1024 * 1024)
                .ok_or(TranscriptError::CaptureLimit)?;
            let original = self
                .body(&object.reference)
                .ok_or_else(|| invalid("original Tape2 typed role is beyond the cutoff"))?;
            if original != object.bytes {
                return Err(invalid("original Tape2 typed role body changed"));
            }
            object.reference.verify(original).map_err(invalid)?;
        }
        Ok(())
    }

    fn body(&self, reference: &ContentRef) -> Option<&[u8]> {
        self.source.data.records[..self.consumed]
            .iter()
            .flat_map(|record| &record.evidence)
            .find(|object| object.reference == *reference)
            .map(|object| object.bytes.as_slice())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedTape2 {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    source_capture: SavedRuntimeActivation,
    node: Id,
    interaction: Id,
    pub(super) lineage: RecordedLineage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RecordedLineage {
    Publication {
        publication: Box<SavedOriginalPublication>,
    },
    Input {
        input: Box<SavedOriginalInputLineage>,
    },
}

impl RecordedTape2 {
    pub(super) fn capture(
        origin: &TranscriptOrigin,
        interaction: Id,
        lineage: RecordedLineage,
        maximum_bytes: usize,
    ) -> Result<InputPayload, TranscriptError> {
        let record = Self {
            schema_version: 2,
            source_capture: origin.activation.clone(),
            node: origin.route.node.clone(),
            interaction,
            lineage,
        };
        bounded_metadata(&record, maximum_bytes)?;
        let bytes = encode(&record)?;
        let reference = canonical::content_ref(&bytes, MEDIA_TYPE).map_err(invalid)?;
        Ok(InputPayload { reference, bytes })
    }

    pub(super) fn decode(
        object: &InputPayload,
        origin: &TranscriptOrigin,
        record: &TranscriptRecord,
    ) -> Result<Option<Self>, TranscriptError> {
        if object.reference.media_type != MEDIA_TYPE {
            return Ok(None);
        }
        object.reference.verify(&object.bytes).map_err(invalid)?;
        let value = canonical::parse_json(&object.bytes, object.bytes.len()).map_err(invalid)?;
        let tape: Self = serde_json::from_value(value).map_err(invalid)?;
        if tape.schema_version != 2
            || tape.source_capture != origin.activation
            || tape.node != origin.route.node
            || tape.interaction != record.request.identity
            || encode(&tape)? != object.bytes
        {
            return Err(invalid(
                "original Tape2 source capture or interaction changed",
            ));
        }
        let body = |reference: &ContentRef| {
            record
                .evidence
                .iter()
                .find(|object| object.reference == *reference)
                .map(|object| object.bytes.as_slice())
        };
        match &tape.lineage {
            RecordedLineage::Publication { publication } => {
                if record.request.action != TranscriptAction::Complete
                    || publication.origin.operation_id != tape.interaction
                    || publication.origin.world_binding_hash != origin.activation.world_binding_hash
                    || publication.origin.activation_id != origin.activation.activation_id
                    || publication.origin.world_generation != origin.activation.generation
                    || !origin.route.owners.iter().any(|owner| {
                        owner.owner == publication.origin.execution_owner_id
                            && owner.incarnation == publication.origin.incarnation_id
                            && owner.generation == publication.origin.owner_generation
                    })
                {
                    return Err(invalid(
                        "Tape2 publication differs from original terminal scope",
                    ));
                }
                validate_publication(publication, OriginalInputLineageLimits::default(), body)?;
                let response: ControlResponse =
                    serde_json::from_slice(&record.response_bytes).map_err(invalid)?;
                let ControlResponse::Outcome(outcome) = response else {
                    return Err(invalid(
                        "Tape2 publication has no original terminal outcome",
                    ));
                };
                let event_bytes = body(&publication.published)
                    .ok_or_else(|| invalid("Tape2 Event body missing"))?;
                let event: Event =
                    canonical::decode(event_bytes, event_bytes.len()).map_err(invalid)?;
                let Some(observation) = &outcome.scheduling else {
                    return Err(invalid(
                        "Tape2 publication has no original scheduling observation",
                    ));
                };
                if outcome.operation != tape.interaction
                    || outcome.node != origin.route.node
                    || outcome.owners != origin.route.owners
                    || observation.proof_ref != publication.origin.measurement
                    || observation
                        .publications
                        .iter()
                        .filter(|native| {
                            native.publication_id == event.id
                                && native.endpoint == event.source
                                && native.native_sequence == event.source_sequence
                                && native.publication == event.publication_position
                                && native.payload == event.payload
                                && native.causal_parents.is_empty()
                        })
                        .count()
                        != 1
                {
                    return Err(invalid(
                        "Tape2 publication differs from original terminal inventory",
                    ));
                }
            }
            RecordedLineage::Input { input } => {
                if record.request.action != TranscriptAction::StageInput
                    || input.schema_version != 1
                    || input.source.source_activation != origin.activation
                    || input.source.node != tape.node
                    || input.source.stage_operation != tape.interaction
                    || input.source.owners != origin.route.owners
                {
                    return Err(invalid("Tape2 input differs from original staging scope"));
                }
                let request: ControlRequest =
                    serde_json::from_slice(&record.request.bytes).map_err(invalid)?;
                let ControlRequest::Stage { input: original } = request else {
                    return Err(invalid("Tape2 lineage has no original Stage request"));
                };
                if input.source.batch != original.batch
                    || input.source.cutoff != original.cutoff
                    || input.source.inventory != original.inventory
                    || input.publications.len() != original.deliveries.len()
                {
                    return Err(invalid(
                        "Tape2 input differs from original frozen ordered inventory",
                    ));
                }
                let response: ControlResponse =
                    serde_json::from_slice(&record.response_bytes).map_err(invalid)?;
                let ControlResponse::Input(acknowledgement) = response else {
                    return Err(invalid(
                        "Tape2 input has no original staging acknowledgement",
                    ));
                };
                if acknowledgement.node != original.node
                    || acknowledgement.stage_operation != original.stage_operation
                    || acknowledgement.batch != original.batch
                    || acknowledgement.owners != original.owners
                    || acknowledgement.cutoff != original.cutoff
                    || acknowledgement.inventory != original.inventory
                    || original.node != input.source.node
                    || original.stage_operation != input.source.stage_operation
                    || original.owners != input.source.owners
                {
                    return Err(invalid(
                        "Tape2 input acknowledgement changed original custody",
                    ));
                }
                let acknowledgement_body = body(&acknowledgement.proof_ref)
                    .ok_or_else(|| invalid("Tape2 input acknowledgement body is absent"))?;
                acknowledgement
                    .proof_ref
                    .verify(acknowledgement_body)
                    .map_err(invalid)?;
                let mut remaining = OriginalInputLineageLimits::default();
                for (publication, delivery) in input.publications.iter().zip(&original.deliveries) {
                    let edges = validate_publication(publication, remaining, body)?;
                    let event_bytes = body(&publication.published)
                        .ok_or_else(|| invalid("Tape2 input Event body missing"))?;
                    let event: Event =
                        canonical::decode(event_bytes, event_bytes.len()).map_err(invalid)?;
                    if event.id != delivery.publication_id
                        || event.source != delivery.producer_endpoint
                        || event.source_sequence != delivery.native_sequence
                        || event.payload != delivery.payload
                        || event.publication_position != delivery.publication
                        || event.provenance_ref != delivery.provenance_ref
                        || !delivery.causal_parents.is_empty()
                        || publication.origin.world_binding_hash
                            != input.source.source_activation.world_binding_hash
                        || publication.origin.activation_id
                            != input.source.source_activation.activation_id
                        || publication.origin.world_generation
                            != input.source.source_activation.generation
                        || !input.source.source_activation.owners.iter().any(|owner| {
                            owner.owner == publication.origin.execution_owner_id
                                && owner.incarnation == publication.origin.incarnation_id
                                && owner.generation == publication.origin.owner_generation
                        })
                    {
                        return Err(invalid(
                            "Tape2 input reordered or changed an original producer occurrence",
                        ));
                    }
                    remaining.maximum_objects = remaining
                        .maximum_objects
                        .checked_sub(publication.objects.len())
                        .ok_or(TranscriptError::CaptureLimit)?;
                    for reference in &publication.objects {
                        let bytes = usize::try_from(reference.length.get())
                            .map_err(|_| TranscriptError::CaptureLimit)?;
                        remaining.maximum_bytes = remaining
                            .maximum_bytes
                            .checked_sub(bytes)
                            .ok_or(TranscriptError::CaptureLimit)?;
                    }
                    remaining.maximum_edges = remaining
                        .maximum_edges
                        .checked_sub(edges)
                        .ok_or(TranscriptError::CaptureLimit)?;
                }
            }
        }
        Ok(Some(tape))
    }
}

fn validate_publication<'a>(
    publication: &SavedOriginalPublication,
    limits: OriginalInputLineageLimits,
    body: impl FnMut(&ContentRef) -> Option<&'a [u8]> + Copy,
) -> Result<usize, TranscriptError> {
    let derived = publication
        .validate_recorded_bodies(limits, body)
        .map_err(invalid)?;
    let direct = publication.rows.iter().try_fold(0usize, |total, row| {
        total
            .checked_add(row.dependencies.len())
            .ok_or(TranscriptError::CaptureLimit)
    })?;
    let mut body = body;
    let event_bytes = body(&publication.published)
        .ok_or_else(|| invalid("Tape2 original Event body is missing"))?;
    let event: Event = canonical::decode(event_bytes, event_bytes.len()).map_err(invalid)?;
    if publication.published.media_type != "application/json"
        || event.provenance_ref != publication.origin.measurement
        || event.stage != crucible_node_contract::EventStage::Publication
        || event.position != event.publication_position
        || event.delivery_position.is_some()
        || !event.causal_parent_ids.is_empty()
        || !event.extensions.is_empty()
        || event.validate().is_err()
    {
        return Err(invalid(
            "Tape2 original publication codec or proof root changed",
        ));
    }
    Ok(direct.max(derived))
}

/// Counts the whole borrowed metadata before allocating its canonical body.
pub(super) fn bounded_metadata(
    value: &impl Serialize,
    maximum_bytes: usize,
) -> Result<(), TranscriptError> {
    struct Counter {
        remaining: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.remaining = self
                .remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("original Tape2 metadata credit exhausted"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(
        Counter {
            remaining: maximum_bytes,
        },
        value,
    )
    .map_err(|_| TranscriptError::CaptureLimit)
}

/// Requires complete selected metadata independently of a permissive qualifier.
pub(super) fn validate_selected_source(
    source: &super::archive::AuthenticatedTranscript,
) -> Result<(), TranscriptError> {
    for record in &source.data.records {
        let request: ControlRequest =
            serde_json::from_slice(&record.request.bytes).map_err(invalid)?;
        let response: ControlResponse =
            serde_json::from_slice(&record.response_bytes).map_err(invalid)?;
        let expected_publications = match (&request, &response) {
            (ControlRequest::Stage { input }, ControlResponse::Input(_)) => {
                if input.deliveries.is_empty()
                    && (!input.payloads.is_empty() || input.provenance.is_some())
                {
                    return Err(invalid("Tape2 empty Stage retains unexpected input bodies"));
                }
                None
            }
            (ControlRequest::Complete { .. }, ControlResponse::Outcome(outcome)) => {
                validate_original_outcome_scope(outcome, &source.data.origin)?;
                Some(
                    outcome
                        .scheduling
                        .as_ref()
                        .ok_or_else(|| {
                            invalid("Tape2 source terminal has no original scheduling custody")
                        })?
                        .publications
                        .len(),
                )
            }
            (ControlRequest::Begin { .. }, ControlResponse::Submission(Submission::Accepted))
            | (
                ControlRequest::Close { .. },
                ControlResponse::Submission(Submission::Accepted | Submission::Refused(_)),
            )
            | (ControlRequest::Observe, ControlResponse::Observation(_))
            | (ControlRequest::Acknowledge { .. }, ControlResponse::Acknowledged) => continue,
            _ => return Err(invalid("Tape2 source control trajectory is unsupported")),
        };
        let mut inputs = 0usize;
        let mut publications = std::collections::BTreeSet::new();
        for object in &record.evidence {
            let Some(metadata) = RecordedTape2::decode(object, &source.data.origin, record)? else {
                continue;
            };
            match metadata.lineage {
                RecordedLineage::Input { .. } => inputs += 1,
                RecordedLineage::Publication { publication } => {
                    if !publications.insert(publication.published) {
                        return Err(invalid("Tape2 source publication metadata is ambiguous"));
                    }
                }
            }
        }
        // No event was consumed by an empty Stage. Its original request and ACK
        // remain recorded custody, without inventing a first-sealed ancestry.
        let expected_inputs = match &request {
            ControlRequest::Stage { input } => usize::from(!input.deliveries.is_empty()),
            _ => 0,
        };
        if expected_publications.map_or(
            inputs != expected_inputs || !publications.is_empty(),
            |expected| inputs != 0 || publications.len() != expected,
        ) {
            return Err(invalid(
                "Tape2 source interaction omits complete original lineage metadata",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_original_outcome_scope(
    outcome: &crate::node_contract::OperationOutcome,
    origin: &TranscriptOrigin,
) -> Result<(), TranscriptError> {
    let observation = outcome
        .scheduling
        .as_ref()
        .ok_or_else(|| invalid("Tape2 original scheduling custody absent"))?;
    if outcome.node != origin.route.node
        || outcome.owners != origin.route.owners
        || observation.node != origin.route.node
        || observation.owners != origin.route.owners
    {
        return Err(invalid(
            "Tape2 original outcome/observation owner scope differs",
        ));
    }
    Ok(())
}
