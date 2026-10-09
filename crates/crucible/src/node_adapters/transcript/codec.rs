//! Bounded canonical transcript integrity and original-context commitments.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, U64, Validate, canonical};

use super::types::*;

pub(super) const MAXIMUM_RECORDS: u64 = 4096;
pub(super) const MAXIMUM_RECORD_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAXIMUM_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Reports missing capture custody, invalid source data or replay divergence.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TranscriptError {
    /// A predeclared reservation or hard format ceiling would be exceeded.
    #[error("transcript capture reservation exhausted")]
    CaptureLimit,
    /// Retained bytes do not satisfy the closed canonical data format.
    #[error("invalid transcript: {0}")]
    Invalid(String),
    /// The original native source and its complete context were not authenticated.
    #[error("transcript source is not qualified: {0}")]
    Unqualified(String),
    /// The next original interaction does not match the actual requested branch.
    #[error("transcript diverged at record {record}: {reason}")]
    Divergence {
        /// Identifies the first unavailable or mismatched original interaction.
        record: U64,
        /// Retains a diagnostic without replacing or resampling the request.
        reason: String,
    },
}

impl TranscriptLimits {
    /// Validates finite reservations without permitting silent capture downgrade.
    ///
    /// # Errors
    /// Refuses zero, unrepresentable or unsupported capture reservations.
    pub fn validate(&self) -> Result<(), TranscriptError> {
        if self.maximum_records.get() == 0
            || self.maximum_records.get() > MAXIMUM_RECORDS
            || self.maximum_record_bytes.get() == 0
            || self.maximum_record_bytes.get() > MAXIMUM_RECORD_BYTES
            || self.maximum_total_bytes < self.maximum_record_bytes
            || self.maximum_total_bytes.get() > MAXIMUM_TOTAL_BYTES
        {
            return Err(TranscriptError::CaptureLimit);
        }
        Ok(())
    }
}

impl BoundaryTranscript {
    /// Encodes complete verified raw data without granting replay authority.
    ///
    /// # Errors
    /// Refuses malformed source scope, sequence gaps, changed bytes, incomplete
    /// evidence or capture reservations smaller than the complete envelope.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TranscriptError> {
        self.validate_integrity()?;
        let bytes = encode(self)?;
        if bytes.len() as u64 > self.limits.maximum_total_bytes.get() {
            return Err(TranscriptError::CaptureLimit);
        }
        Ok(bytes)
    }

    /// Decodes bounded canonical data without treating its source claims as proof.
    ///
    /// # Errors
    /// Refuses oversized, noncanonical, malformed or incomplete transcripts and
    /// corrupt payload, request, response or dependency evidence.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TranscriptError> {
        if bytes.len() as u64 > MAXIMUM_TOTAL_BYTES {
            return Err(TranscriptError::CaptureLimit);
        }
        let value = canonical::parse_json(bytes, MAXIMUM_TOTAL_BYTES as usize).map_err(invalid)?;
        let transcript: Self = serde_json::from_value(value).map_err(invalid)?;
        if transcript.canonical_bytes()? != bytes {
            return Err(TranscriptError::Invalid("noncanonical envelope".into()));
        }
        Ok(transcript)
    }

    pub(super) fn validate_integrity(&self) -> Result<(), TranscriptError> {
        self.limits.validate()?;
        if self.schema_version != 1
            || self.records.len() as u64 > self.limits.maximum_records.get()
            || self.origin.activation.generation.get() == 0
            || self.origin.route.owners.is_empty()
            || self.origin.context.is_empty()
            || self.origin.context.len() > MAXIMUM_RECORDS as usize
        {
            return Err(TranscriptError::Invalid("source scope or edition".into()));
        }
        self.origin.attempt.validate().map_err(invalid)?;
        self.origin.route.node.validate().map_err(invalid)?;
        self.origin
            .activation
            .world_binding_hash
            .validate()
            .map_err(invalid)?;
        self.origin
            .activation
            .activation_id
            .validate()
            .map_err(invalid)?;
        self.origin.source_binding.validate().map_err(invalid)?;
        let mut owners = BTreeSet::new();
        for owner in &self.origin.route.owners {
            owner.owner.validate().map_err(invalid)?;
            owner.incarnation.validate().map_err(invalid)?;
            if owner.generation.get() == 0
                || !owners.insert(owner)
                || !self.origin.activation.owners.contains(owner)
            {
                return Err(TranscriptError::Invalid(
                    "original owner realization".into(),
                ));
            }
        }
        let mut objects = BTreeMap::new();
        for object in &self.origin.context {
            retain_object(&mut objects, &object.reference, &object.bytes)?;
        }
        if !self
            .origin
            .context
            .iter()
            .any(|object| object.reference == self.origin.source_binding)
        {
            return Err(TranscriptError::Invalid(
                "missing raw source binding".into(),
            ));
        }
        let context = context_commitment(&self.origin)?;
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence.get() != index as u64
                || record.request.context != context
                || record.evidence.len() > MAXIMUM_RECORDS as usize
                || record.assigned_positions.len() > MAXIMUM_RECORDS as usize
            {
                return Err(TranscriptError::Invalid(
                    "missing sequence or context".into(),
                ));
            }
            record.request.identity.validate().map_err(invalid)?;
            record.request.boundary.validate().map_err(invalid)?;
            record
                .request
                .content
                .verify(&record.request.bytes)
                .map_err(invalid)?;
            record
                .response
                .verify(&record.response_bytes)
                .map_err(invalid)?;
            for position in &record.assigned_positions {
                position.validate().map_err(invalid)?;
            }
            for object in &record.evidence {
                retain_object(&mut objects, &object.reference, &object.bytes)?;
            }
            for object in &record.evidence {
                if let Some(closure) =
                    super::proof::RecordedProofClosure::decode(object, &self.origin)?
                {
                    let mut retained = std::collections::BTreeSet::new();
                    for reference in std::iter::once(&closure.root).chain(&closure.dependencies) {
                        if !retained.insert(reference.hash.clone())
                            || objects
                                .get(&reference.hash.digest)
                                .map(|(original, _)| *original)
                                != Some(reference)
                        {
                            return Err(TranscriptError::Invalid("original producer-proof inventory is duplicated or lacks raw dependency bytes".into()));
                        }
                    }
                }
            }
            if let PhysicalTimingUncertainty::ObservedInterval {
                earliest_ns,
                latest_ns,
                evidence,
            } = &record.physical_uncertainty
                && (earliest_ns > latest_ns
                    || objects
                        .get(&evidence.hash.digest)
                        .map(|(reference, _)| *reference)
                        != Some(evidence))
            {
                return Err(TranscriptError::Invalid(
                    "physical measurement custody".into(),
                ));
            }
            if encode(record)?.len() as u64 > self.limits.maximum_record_bytes.get() {
                return Err(TranscriptError::CaptureLimit);
            }
        }
        Ok(())
    }
}

/// Commits complete original context, including actual attempt and owner lineage.
///
/// # Errors
/// Refuses invalid serialization or an unsupported content representation.
pub fn context_commitment(origin: &TranscriptOrigin) -> Result<ContentRef, TranscriptError> {
    let bytes = encode(origin)?;
    canonical::content_ref(&bytes, "application/json").map_err(invalid)
}

fn retain_object<'a>(
    objects: &mut BTreeMap<String, (&'a ContentRef, &'a [u8])>,
    reference: &'a ContentRef,
    bytes: &'a [u8],
) -> Result<(), TranscriptError> {
    reference.verify(bytes).map_err(invalid)?;
    if objects
        .get(&reference.hash.digest)
        .is_some_and(|stored| stored.0 != reference || stored.1 != bytes)
    {
        return Err(TranscriptError::Invalid(
            "conflicting immutable object custody".into(),
        ));
    }
    objects.insert(reference.hash.digest.clone(), (reference, bytes));
    Ok(())
}

pub(super) fn invalid(error: impl std::fmt::Display) -> TranscriptError {
    TranscriptError::Invalid(error.to_string())
}

pub(super) fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, TranscriptError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(invalid)?).map_err(invalid)
}
