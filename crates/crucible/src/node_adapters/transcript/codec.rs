//! Bounded canonical transcript integrity and original-context commitments.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, HashRef, U64, Validate, canonical};

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
        let bytes = if self.schema_version == 2 {
            super::byte_wire::envelope(self)?
        } else {
            encode(self)?
        };
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
        let transcript: Self = if value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(2)
        {
            super::byte_wire::decode(value)?
        } else {
            serde_json::from_value(value).map_err(invalid)?
        };
        if transcript.canonical_bytes()? != bytes {
            return Err(TranscriptError::Invalid("noncanonical envelope".into()));
        }
        Ok(transcript)
    }

    pub(super) fn validate_integrity(&self) -> Result<(), TranscriptError> {
        self.limits.validate()?;
        if !matches!(self.schema_version, 1 | 2)
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
        let mut objects = OriginalObjects::default();
        for object in &self.origin.context {
            objects.retain(&object.reference, &object.bytes)?;
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
                objects.retain(&object.reference, &object.bytes)?;
            }
            for object in &record.evidence {
                // Tape2 roles remain data. Their complete bodies must be in this
                // interaction; future records cannot repair a missing source row.
                super::tape2::RecordedTape2::decode(object, &self.origin, record)?;
                if let Some(closure) =
                    super::proof::RecordedProofClosure::decode(object, &self.origin)?
                {
                    let mut retained = std::collections::BTreeSet::new();
                    for reference in std::iter::once(&closure.root).chain(&closure.dependencies) {
                        if !retained.insert(reference) || !objects.typed.contains_key(reference) {
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
                && (earliest_ns > latest_ns || !objects.typed.contains_key(evidence))
            {
                return Err(TranscriptError::Invalid(
                    "physical measurement custody".into(),
                ));
            }
            if record_bytes(
                record,
                self.schema_version,
                self.limits.maximum_record_bytes.get(),
            )?
            .len() as u64
                > self.limits.maximum_record_bytes.get()
            {
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

/// Retains each original content role without allowing a hash to name two bodies.
#[derive(Default)]
struct OriginalObjects<'a> {
    typed: BTreeMap<&'a ContentRef, &'a [u8]>,
    bodies: BTreeMap<&'a HashRef, &'a [u8]>,
}

impl<'a> OriginalObjects<'a> {
    fn retain(
        &mut self,
        reference: &'a ContentRef,
        bytes: &'a [u8],
    ) -> Result<(), TranscriptError> {
        reference.verify(bytes).map_err(invalid)?;
        if self
            .bodies
            .get(&reference.hash)
            .is_some_and(|original| *original != bytes)
        {
            return Err(TranscriptError::Invalid(
                "conflicting immutable object bytes".into(),
            ));
        }

        // Media roles are part of the original typed reference. The same bytes
        // can fill multiple authentic roles; dependency lookup must remain exact.
        self.bodies.insert(&reference.hash, bytes);
        self.typed.insert(reference, bytes);
        Ok(())
    }
}

pub(super) fn invalid(error: impl std::fmt::Display) -> TranscriptError {
    TranscriptError::Invalid(error.to_string())
}

pub(super) fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, TranscriptError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(invalid)?).map_err(invalid)
}

pub(super) fn record_bytes(
    record: &TranscriptRecord,
    edition: u16,
    maximum: u64,
) -> Result<Vec<u8>, TranscriptError> {
    if edition == 2 {
        super::byte_wire::record(record, maximum)
    } else {
        encode(record)
    }
}
