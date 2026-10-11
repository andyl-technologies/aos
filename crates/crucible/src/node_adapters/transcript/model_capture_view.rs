//! Closed data inspection of an explicitly selected conditional model capture.
//!
//! Original runtime, tape and per-operation roles retain full typed identities.
//! This view is not an authenticated source seal and cannot install permissions.

use crucible_node_contract::{ContentRef, Id, NodeBinding, Position, Validate, canonical};

use crate::{
    node_contract::NodeRoute,
    node_scheduling::{InputPayload, NativeSchedulingObservation},
};

use super::{
    ReplayCursorSnapshot, TranscriptError, codec::invalid,
    tape2_continuation::Tape2ContinuationWire,
};

const MAXIMUM_ROWS: usize = 8192;
const MAXIMUM_EDGES: usize = 65536;
const MAXIMUM_BYTES: usize = 64 * 1024 * 1024;

/// Borrows decoded capture data without granting historical or current authority.
///
/// The installed factory independently authenticates the actual owning model,
/// complete signed source and exact producer/consumer journals before acceptance.
pub struct OriginalLineageModelCapture(Tape2ContinuationWire);

impl OriginalLineageModelCapture {
    /// Borrows the complete SOURCE-CAPTURE Runtime7 reference.
    pub fn runtime(&self) -> &ContentRef {
        &self.0.runtime
    }

    /// Borrows the original model's exact node and owner roster.
    pub fn route(&self) -> &NodeRoute {
        &self.0.route
    }

    /// Borrows the source model's complete implementation and semantic binding.
    pub fn binding(&self) -> &NodeBinding {
        &self.0.binding
    }

    /// Borrows the exact consumed prefix and sticky divergence status.
    pub fn cursor(&self) -> &ReplayCursorSnapshot {
        &self.0.cursor
    }

    /// Returns the actual model-local boundary.
    pub fn boundary(&self) -> Position {
        self.0.boundary
    }

    /// Borrows the complete original physical transcript as data provenance.
    pub fn transcript(&self) -> &ContentRef {
        &self.0.transcript
    }

    /// Borrows the actual installed model qualification proof reference.
    pub fn qualification(&self) -> &ContentRef {
        &self.0.qualification
    }

    /// Enumerates exact original operation identifiers and retained body roles.
    pub fn operation_evidence(&self) -> impl Iterator<Item = (&Id, &[ContentRef])> {
        self.0
            .operation_evidence
            .iter()
            .map(|row| (&row.operation, row.objects.as_slice()))
    }

    /// Borrows all actually retained source scheduling observations.
    pub fn observations(&self) -> &[NativeSchedulingObservation] {
        &self.0.observations
    }

    /// Borrows administrative custody receipt roles without inferring leaves.
    pub fn custody_objects(&self) -> &[ContentRef] {
        &self.0.custody_objects
    }
}

/// Decodes the exact closed Tape2 model capture under finite role and byte credit.
///
/// The caller selects this reader for a known source-qualified model state role;
/// it does not classify generic JSON or authenticate an original native source.
/// Arrays and aggregate operation edges are checked before typed reconstruction.
///
/// # Errors
/// Refuses exceeded byte/row/edge credit, changed content, open or noncanonical
/// JSON, unsupported schema/runtime media, or duplicate operation identities.
pub fn decode_original_lineage_model_capture(
    object: &InputPayload,
    maximum_bytes: usize,
) -> Result<OriginalLineageModelCapture, TranscriptError> {
    let limit = maximum_bytes.min(MAXIMUM_BYTES);
    if object.bytes.len() > limit || object.reference.media_type != "application/json" {
        return Err(invalid(
            "Tape2 model inspection byte credit or media differs",
        ));
    }
    object.reference.verify(&object.bytes).map_err(invalid)?;
    let value = canonical::parse_json(&object.bytes, limit).map_err(invalid)?;
    let mut edges = 0usize;
    for field in ["operation_evidence", "observations", "custody_objects"] {
        let rows = value
            .get(field)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| invalid("Tape2 model inspection role array is absent"))?;
        if rows.len() > MAXIMUM_ROWS {
            return Err(invalid("Tape2 model inspection row credit exceeded"));
        }
        if field == "operation_evidence" {
            for row in rows {
                let count = row
                    .get("objects")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| invalid("Tape2 operation body row is absent"))?
                    .len();
                edges = edges
                    .checked_add(count)
                    .filter(|count| *count <= MAXIMUM_EDGES)
                    .ok_or_else(|| invalid("Tape2 model inspection edge credit exceeded"))?;
            }
        }
    }
    if canonical::canonical_json(&value).map_err(invalid)? != object.bytes {
        return Err(invalid("Tape2 model inspection bytes are not canonical"));
    }
    let wire: Tape2ContinuationWire = serde_json::from_value(value).map_err(invalid)?;
    if wire.schema_version != 2
        || wire.runtime.media_type != crate::node_state::ORIGINAL_LINEAGE_RUNTIME_MEDIA
        || wire.cursor.schema_version != 1
        || wire.cursor.transcript != wire.transcript
        || wire
            .operation_evidence
            .windows(2)
            .any(|pair| pair[0].operation >= pair[1].operation)
        || wire
            .custody_objects
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid(
            "Tape2 model inspection requires its exact Runtime7 edition",
        ));
    }
    let mut operations = std::collections::BTreeSet::new();
    for row in &wire.operation_evidence {
        row.operation.validate().map_err(invalid)?;
        if !operations.insert(&row.operation) {
            return Err(invalid("Tape2 model inspection operation identity repeats"));
        }
        for reference in &row.objects {
            reference.validate().map_err(invalid)?;
        }
    }
    for reference in [&wire.runtime, &wire.transcript, &wire.qualification]
        .into_iter()
        .chain(wire.custody_objects.iter())
    {
        reference.validate().map_err(invalid)?;
    }
    Ok(OriginalLineageModelCapture(wire))
}

#[cfg(test)]
#[path = "model_capture_view_tests.rs"]
mod tests;
