//! Canonical modeled outcomes and executor-produced evidence.
//!
//! Observation records bind one admitted semantic attempt to its exact child
//! configuration, stop outcome, measurements, property verdicts, coverage,
//! newly discovered choices, and selections produced while continuing through
//! those choices. Operational reservation, worker, retry, and host-timing data
//! is deliberately absent.

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    AttemptId, BranchPathId, CampaignCodecError, CampaignHash, ChoiceOpportunityId,
    ConfigurationArtifactId, ConfigurationId, CoverageProjectionId, MeasurementSetId,
    ObservationCondition, ObservationId, PropertyVerdictSetId, SelectionId, StopCondition,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const OBSERVATION_SCHEMA_VERSION: u32 = 13;
const MEASUREMENT_SET_SCHEMA_VERSION: u32 = 2;
const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;
const MAX_MEASUREMENT_EVALUATION_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_MEASUREMENT_SET_RECORD_BYTES: usize = 33 * 1024 * 1024;
const MAX_PROPERTIES: usize = 4096;
const MAX_SCENARIO_FAILURE_REASONS: usize = 4096;
const MAX_SCENARIO_FAILURE_REASON_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCENARIO_FAILURE_REASONS_BYTES: usize = MAX_RECORD_BYTES;
const MAX_EVIDENCE_OBJECTS: usize = 4096;
const MAX_COVERAGE_IDENTITIES: usize = 1_000_000;
// The generic content envelope permits 65,536 children. Observation reserves
// six roles for attempt, child, path, measurements, properties, and coverage.
const MAX_ENVELOPE_CHILDREN: usize = 65_536;
const OBSERVATION_FIXED_CHILDREN: usize = 6;
pub(crate) const MAX_DISCOVERED_CHOICES: usize = MAX_ENVELOPE_CHILDREN - OBSERVATION_FIXED_CHILDREN;

/// One execution-model-verified canonical measurement evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementEvaluationPayload {
    definitions: CampaignHash,
    payload_schema: u32,
    evaluation: CampaignHash,
    payload: Vec<u8>,
    evidence: BTreeSet<ContentId>,
}

impl MeasurementEvaluationPayload {
    /// Returns the exact scenario measurement-definition identity.
    #[must_use]
    pub const fn definitions(&self) -> CampaignHash {
        self.definitions
    }

    /// Returns the execution-model evaluation payload schema.
    #[must_use]
    pub const fn payload_schema(&self) -> u32 {
        self.payload_schema
    }

    /// Returns the execution-model-verified evaluation identity.
    #[must_use]
    pub const fn evaluation(&self) -> CampaignHash {
        self.evaluation
    }

    /// Returns the exact canonical evaluation bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns immutable evidence objects retained for replay or audit.
    #[must_use]
    pub const fn evidence(&self) -> &BTreeSet<ContentId> {
        &self.evidence
    }
}

/// Canonical exact measurement results for one observation.
///
/// Records retain one verified, versioned execution-model evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementSet {
    evaluation: MeasurementEvaluationPayload,
}

impl MeasurementSet {
    #[cfg(test)]
    pub(crate) fn test_evaluation(
        label: &[u8],
        evidence: BTreeSet<ContentId>,
    ) -> Result<Self, CampaignCodecError> {
        Self::from_evaluation(
            CampaignHash::derive("crucible.test-measurement-definitions.v1", label),
            1,
            CampaignHash::derive("crucible.test-measurement-evaluation.v1", label),
            label.to_vec(),
            evidence,
        )
    }

    /// Builds one bounded verified evaluation record.
    ///
    /// The owning execution-model adapter must derive and verify `definitions`,
    /// `evaluation`, and `payload` before construction. The campaign layer
    /// retains that exact binding without reinterpreting model-specific bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero payload schema, empty payload, excessive
    /// evidence, a payload above 32 MiB, or a record above 33 MiB.
    pub fn from_evaluation(
        definitions: CampaignHash,
        payload_schema: u32,
        evaluation: CampaignHash,
        payload: Vec<u8>,
        evidence: BTreeSet<ContentId>,
    ) -> Result<Self, CampaignCodecError> {
        if payload_schema == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "measurement evaluation payload schema is zero",
            });
        }
        if payload.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "measurement evaluation payload is empty",
            });
        }
        if payload.len() > MAX_MEASUREMENT_EVALUATION_PAYLOAD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "measurement-evaluation-payload-bytes",
            });
        }
        if evidence.len() > MAX_EVIDENCE_OBJECTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "measurement-evidence-count",
            });
        }
        let value = Self {
            evaluation: MeasurementEvaluationPayload {
                definitions,
                payload_schema,
                evaluation,
                payload,
                evidence,
            },
        };
        codec::ensure_encoded_size(
            &value,
            MAX_MEASUREMENT_SET_RECORD_BYTES,
            "measurement-set-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the retained body schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        MEASUREMENT_SET_SCHEMA_VERSION
    }

    /// Returns the verified evaluation payload.
    #[must_use]
    pub const fn evaluation(&self) -> &MeasurementEvaluationPayload {
        &self.evaluation
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_MEASUREMENT_SET_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "measurement-set-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the exact measurement-set identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<MeasurementSetId, CampaignCodecError> {
        MeasurementSetId::from_content_id(
            crate::ObjectEnvelope::for_measurement_set(self)?.content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        self.evaluation
            .evidence
            .iter()
            .enumerate()
            .map(|(index, id)| (format!("evaluation.evidence.{index:04x}"), *id))
            .collect()
    }
}

impl Canonical for MeasurementSet {
    fn encode(&self, encoder: &mut Encoder) {
        MEASUREMENT_SET_SCHEMA_VERSION.encode(encoder);
        self.evaluation.definitions.encode(encoder);
        self.evaluation.payload_schema.encode(encoder);
        self.evaluation.evaluation.encode(encoder);
        self.evaluation.payload.encode(encoder);
        self.evaluation.evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match u32::decode(decoder)? {
            MEASUREMENT_SET_SCHEMA_VERSION => Self::from_evaluation(
                CampaignHash::decode(decoder)?,
                u32::decode(decoder)?,
                CampaignHash::decode(decoder)?,
                decoder.sequence_bounded(
                    MAX_MEASUREMENT_EVALUATION_PAYLOAD_BYTES,
                    "measurement-evaluation-payload-bytes",
                    u8::decode,
                )?,
                decoder.set_bounded(MAX_EVIDENCE_OBJECTS, "measurement-evidence-count")?,
            ),
            _ => Err(CampaignCodecError::InvalidValue {
                reason: "unsupported measurement-set schema version",
            }),
        }
    }
}

/// Stable modeled property disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PropertyVerdict {
    /// The property held over its declared evaluation boundary.
    Passed,
    /// The property was violated canonically.
    Failed,
    /// The property could not be evaluated at this modeled boundary.
    Inconclusive,
}

impl Canonical for PropertyVerdict {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Passed => 0,
            Self::Failed => 1,
            Self::Inconclusive => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Passed),
            1 => Ok(Self::Failed),
            2 => Ok(Self::Inconclusive),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "property-verdict",
                tag,
            }),
        }
    }
}

/// One property verdict and its retained causal evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyEvidence {
    verdict: PropertyVerdict,
    evidence: BTreeSet<ContentId>,
}

impl PropertyEvidence {
    /// Builds one bounded property-evidence record.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence set exceeds its bound.
    pub fn new(
        verdict: PropertyVerdict,
        evidence: BTreeSet<ContentId>,
    ) -> Result<Self, CampaignCodecError> {
        if evidence.len() > MAX_EVIDENCE_OBJECTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "property-evidence-count",
            });
        }
        Ok(Self { verdict, evidence })
    }

    /// Returns the modeled verdict.
    #[must_use]
    pub const fn verdict(&self) -> PropertyVerdict {
        self.verdict
    }

    /// Returns retained causal evidence objects.
    #[must_use]
    pub const fn evidence(&self) -> &BTreeSet<ContentId> {
        &self.evidence
    }
}

impl Canonical for PropertyEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.verdict.encode(encoder);
        self.evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            PropertyVerdict::decode(decoder)?,
            decoder.set_bounded(MAX_EVIDENCE_OBJECTS, "property-evidence-count")?,
        )
    }
}

/// Canonical property verdicts keyed by scenario-declared property name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyVerdictSet {
    schema_version: u32,
    properties: BTreeMap<String, PropertyEvidence>,
}

impl PropertyVerdictSet {
    /// Builds a bounded canonical property-verdict set.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid names, count overflow, or oversized bytes.
    pub fn new(properties: BTreeMap<String, PropertyEvidence>) -> Result<Self, CampaignCodecError> {
        if properties.len() > MAX_PROPERTIES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "property-verdict-count",
            });
        }
        for name in properties.keys() {
            validate_identifier(name, "property name is invalid")?;
        }
        let evidence_children = properties.values().try_fold(0_usize, |total, evidence| {
            total
                .checked_add(evidence.evidence().len())
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "property-evidence-child-count",
                })
        })?;
        if evidence_children > MAX_ENVELOPE_CHILDREN {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "property-evidence-child-count",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            properties,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_RECORD_BYTES,
            "property-verdict-set-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns property evidence in canonical name order.
    #[must_use]
    pub const fn properties(&self) -> &BTreeMap<String, PropertyEvidence> {
        &self.properties
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_record(bytes, "property-verdict-set-encoded-bytes")
    }

    /// Returns the exact property-verdict-set identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<PropertyVerdictSetId, CampaignCodecError> {
        PropertyVerdictSetId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PropertyVerdictSet,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        self.properties
            .values()
            .enumerate()
            .flat_map(|(property, evidence)| {
                evidence
                    .evidence()
                    .iter()
                    .enumerate()
                    .map(move |(index, id)| {
                        (format!("property.{property:04x}.evidence.{index:04x}"), *id)
                    })
            })
            .collect()
    }
}

impl Canonical for PropertyVerdictSet {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.properties.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(decoder.map_bounded_by(
            MAX_PROPERTIES,
            "property-verdict-count",
            |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "property-name-bytes"),
            PropertyEvidence::decode,
        )?)
    }
}

/// Grow-only canonical coverage identities and their exact derivation evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageProjection {
    schema_version: u32,
    identities: BTreeSet<CampaignHash>,
    evidence: BTreeSet<ContentId>,
}

impl CoverageProjection {
    /// Builds a bounded coverage projection.
    ///
    /// # Errors
    ///
    /// Returns an error when identity/evidence counts or encoded bytes exceed bounds.
    pub fn new(
        identities: BTreeSet<CampaignHash>,
        evidence: BTreeSet<ContentId>,
    ) -> Result<Self, CampaignCodecError> {
        if identities.len() > MAX_COVERAGE_IDENTITIES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "coverage-identity-count",
            });
        }
        if evidence.len() > MAX_EVIDENCE_OBJECTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "coverage-evidence-count",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            identities,
            evidence,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_RECORD_BYTES,
            "coverage-projection-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns exact coverage identities.
    #[must_use]
    pub const fn identities(&self) -> &BTreeSet<CampaignHash> {
        &self.identities
    }

    /// Returns coverage derivation evidence objects.
    #[must_use]
    pub const fn evidence(&self) -> &BTreeSet<ContentId> {
        &self.evidence
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_record(bytes, "coverage-projection-encoded-bytes")
    }

    /// Returns the exact coverage-projection identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<CoverageProjectionId, CampaignCodecError> {
        CoverageProjectionId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::CoverageProjection,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        self.evidence
            .iter()
            .enumerate()
            .map(|(index, id)| (format!("evidence.{index:04x}"), *id))
            .collect()
    }
}

impl Canonical for CoverageProjection {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.identities.encode(encoder);
        self.evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            decoder.set_bounded(MAX_COVERAGE_IDENTITIES, "coverage-identity-count")?,
            decoder.set_bounded(MAX_EVIDENCE_OBJECTS, "coverage-evidence-count")?,
        )
    }
}

/// Exact authenticated event-log position at an observation stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationEventLogProof {
    prefix: CampaignHash,
    appended_segment: Option<CampaignHash>,
    bytes: u64,
    events: u64,
    digest: CampaignHash,
}

impl ObservationEventLogProof {
    /// Builds the exact scheduler offset and retained-prefix digest.
    #[must_use]
    pub const fn new(
        prefix: CampaignHash,
        appended_segment: Option<CampaignHash>,
        bytes: u64,
        events: u64,
        digest: CampaignHash,
    ) -> Self {
        Self {
            prefix,
            appended_segment,
            bytes,
            events,
            digest,
        }
    }

    /// Returns the shared prefix immediately before the appended segment.
    #[must_use]
    pub const fn prefix(self) -> CampaignHash {
        self.prefix
    }

    /// Returns the final segment appended after the parent checkpoint, if any.
    #[must_use]
    pub const fn appended_segment(self) -> Option<CampaignHash> {
        self.appended_segment
    }

    /// Returns the byte offset after the matching quantum.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Returns the event count after the matching quantum.
    #[must_use]
    pub const fn events(self) -> u64 {
        self.events
    }

    /// Returns the digest of each retained entry through this offset.
    #[must_use]
    pub const fn digest(self) -> CampaignHash {
        self.digest
    }
}

impl Canonical for ObservationEventLogProof {
    fn encode(&self, encoder: &mut Encoder) {
        self.prefix.encode(encoder);
        self.appended_segment.encode(encoder);
        self.bytes.encode(encoder);
        self.events.encode(encoder);
        self.digest.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            CampaignHash::decode(decoder)?,
            Option::<CampaignHash>::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            CampaignHash::decode(decoder)?,
        ))
    }
}

/// Exact assertion-state event that satisfied an observation condition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssertionViolationWitness {
    assertion: String,
    sequence: u64,
    entry: CampaignHash,
}

impl AssertionViolationWitness {
    /// Builds a witness from one named retained assertion-state event.
    ///
    /// # Errors
    ///
    /// Returns an error when the assertion identifier is invalid.
    pub fn new(
        assertion: impl Into<String>,
        sequence: u64,
        entry: CampaignHash,
    ) -> Result<Self, CampaignCodecError> {
        let assertion = assertion.into();
        validate_identifier(&assertion, "observation assertion witness is invalid")?;
        Ok(Self {
            assertion,
            sequence,
            entry,
        })
    }

    /// Returns the exact assertion identifier carried by the event.
    #[must_use]
    pub fn assertion(&self) -> &str {
        &self.assertion
    }

    /// Returns the exact scheduler event sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact event content hash.
    #[must_use]
    pub const fn entry(&self) -> CampaignHash {
        self.entry
    }
}

impl Canonical for AssertionViolationWitness {
    fn encode(&self, encoder: &mut Encoder) {
        self.assertion.encode(encoder);
        self.sequence.encode(encoder);
        self.entry.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "observation-assertion-bytes")?,
            u64::decode(decoder)?,
            CampaignHash::decode(decoder)?,
        )
    }
}

/// Exact coordinates before and after the quantum that satisfied a stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationQuantumBoundary {
    frontier_nanoseconds: u64,
    start_completed_quanta: u64,
    completed_quanta: u64,
    start_events: u64,
}

impl ObservationQuantumBoundary {
    /// Builds one strictly advancing quantum boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the completed coordinate is not
    /// exactly one greater than the coordinate recorded before the drive.
    pub fn new(
        frontier_nanoseconds: u64,
        start_completed_quanta: u64,
        completed_quanta: u64,
        start_events: u64,
    ) -> Result<Self, CampaignCodecError> {
        if start_completed_quanta.checked_add(1) != Some(completed_quanta) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation stop quantum coordinate did not advance exactly once",
            });
        }
        Ok(Self {
            frontier_nanoseconds,
            start_completed_quanta,
            completed_quanta,
            start_events,
        })
    }

    /// Returns the exact virtual-time frontier in nanoseconds.
    #[must_use]
    pub const fn frontier_nanoseconds(self) -> u64 {
        self.frontier_nanoseconds
    }

    /// Returns the absolute quantum coordinate immediately before the drive.
    #[must_use]
    pub const fn start_completed_quanta(self) -> u64 {
        self.start_completed_quanta
    }

    /// Returns the absolute completed-quantum coordinate after the drive.
    #[must_use]
    pub const fn completed_quanta(self) -> u64 {
        self.completed_quanta
    }

    /// Returns the event count immediately before the matching quantum.
    #[must_use]
    pub const fn start_events(self) -> u64 {
        self.start_events
    }
}

impl Canonical for ObservationQuantumBoundary {
    fn encode(&self, encoder: &mut Encoder) {
        self.frontier_nanoseconds.encode(encoder);
        self.start_completed_quanta.encode(encoder);
        self.completed_quanta.encode(encoder);
        self.start_events.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Authenticated clause that satisfied an observation stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservationStopSatisfaction {
    /// The matching quantum reported scheduler-owned quiescence.
    SchedulerQuiescent,
    /// The matching quantum emitted the requested assertion violation.
    AssertionViolationTransition,
    /// The matching quantum reached the authored absolute quantum bound.
    ExecutionQuanta,
}

impl Canonical for ObservationStopSatisfaction {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::SchedulerQuiescent => 0,
            Self::AssertionViolationTransition => 1,
            Self::ExecutionQuanta => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::SchedulerQuiescent),
            1 => Ok(Self::AssertionViolationTransition),
            2 => Ok(Self::ExecutionQuanta),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "observation-stop-satisfaction",
                tag,
            }),
        }
    }
}

/// Proof that one newly completed quantum satisfied an observation stop.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationStopProof {
    condition: ObservationCondition,
    satisfaction: ObservationStopSatisfaction,
    child: ConfigurationId,
    boundary: ObservationQuantumBoundary,
    event_log: ObservationEventLogProof,
    assertion_witness: Option<AssertionViolationWitness>,
}

impl ObservationStopProof {
    /// Builds one structurally valid observation-stop proof.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the condition is invalid or its
    /// assertion witness is absent, unexpected, or outside the matching quantum.
    pub fn new(
        condition: ObservationCondition,
        satisfaction: ObservationStopSatisfaction,
        child: ConfigurationId,
        boundary: ObservationQuantumBoundary,
        event_log: ObservationEventLogProof,
        assertion_witness: Option<AssertionViolationWitness>,
    ) -> Result<Self, CampaignCodecError> {
        condition.validate()?;
        let witness_is_valid = match (&condition, satisfaction, assertion_witness.as_ref()) {
            (
                ObservationCondition::SchedulerQuiescent,
                ObservationStopSatisfaction::SchedulerQuiescent,
                None,
            ) => true,
            (
                ObservationCondition::AssertionViolationTransition(_),
                ObservationStopSatisfaction::AssertionViolationTransition,
                Some(witness),
            ) => {
                matches!(
                    &condition,
                    ObservationCondition::AssertionViolationTransition(assertion)
                        if witness.assertion() == assertion
                ) && witness.sequence() >= boundary.start_events()
                    && witness.sequence() < event_log.events()
            }
            (
                ObservationCondition::AnyAssertionViolationTransition,
                ObservationStopSatisfaction::AssertionViolationTransition,
                Some(witness),
            ) => {
                witness.sequence() >= boundary.start_events()
                    && witness.sequence() < event_log.events()
            }
            (
                ObservationCondition::SchedulerQuiescentOrExecutionQuanta { .. },
                ObservationStopSatisfaction::SchedulerQuiescent,
                None,
            ) => true,
            (
                ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta },
                ObservationStopSatisfaction::ExecutionQuanta,
                None,
            ) => boundary.completed_quanta() >= *execution_quanta,
            _ => false,
        };
        if boundary.start_events() > event_log.events() || !witness_is_valid {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation stop has an invalid assertion witness",
            });
        }
        Ok(Self {
            condition,
            satisfaction,
            child,
            boundary,
            event_log,
            assertion_witness,
        })
    }

    /// Returns the requested observation condition.
    #[must_use]
    pub const fn condition(&self) -> &ObservationCondition {
        &self.condition
    }

    /// Returns the exact clause satisfied by the matching quantum.
    #[must_use]
    pub const fn satisfaction(&self) -> ObservationStopSatisfaction {
        self.satisfaction
    }

    /// Returns the exact child configuration reached by the quantum.
    #[must_use]
    pub const fn child(&self) -> ConfigurationId {
        self.child
    }

    /// Returns the exact pre-drive and post-drive quantum boundary.
    #[must_use]
    pub const fn boundary(&self) -> ObservationQuantumBoundary {
        self.boundary
    }

    /// Returns the exact event-log offset and retained-prefix digest.
    #[must_use]
    pub const fn event_log(&self) -> ObservationEventLogProof {
        self.event_log
    }

    /// Returns the matching assertion event, when the condition requires one.
    #[must_use]
    pub fn assertion_witness(&self) -> Option<&AssertionViolationWitness> {
        self.assertion_witness.as_ref()
    }

    /// Returns strict canonical proof bytes for portable boundary records.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical proof bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "observation-stop-proof-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }
}

impl Canonical for ObservationStopProof {
    fn encode(&self, encoder: &mut Encoder) {
        self.condition.encode(encoder);
        self.satisfaction.encode(encoder);
        self.child.encode(encoder);
        self.boundary.encode(encoder);
        self.event_log.encode(encoder);
        self.assertion_witness.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ObservationCondition::decode(decoder)?,
            ObservationStopSatisfaction::decode(decoder)?,
            ConfigurationId::decode(decoder)?,
            ObservationQuantumBoundary::decode(decoder)?,
            ObservationEventLogProof::decode(decoder)?,
            Option::<AssertionViolationWitness>::decode(decoder)?,
        )
    }
}

/// Executor-attested coordinates at one policy-bounded stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedStopProof {
    frontier_nanoseconds: u64,
    completed_quanta: u64,
}

impl BoundedStopProof {
    /// Records the exact scheduler frontier and absolute completed-quantum coordinate.
    #[must_use]
    pub const fn new(frontier_nanoseconds: u64, completed_quanta: u64) -> Self {
        Self {
            frontier_nanoseconds,
            completed_quanta,
        }
    }

    /// Returns the virtual-time frontier in nanoseconds.
    #[must_use]
    pub const fn frontier_nanoseconds(self) -> u64 {
        self.frontier_nanoseconds
    }

    /// Returns the absolute completed-quantum coordinate.
    #[must_use]
    pub const fn completed_quanta(self) -> u64 {
        self.completed_quanta
    }
}

impl Canonical for BoundedStopProof {
    fn encode(&self, encoder: &mut Encoder) {
        self.frontier_nanoseconds.encode(encoder);
        self.completed_quanta.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(u64::decode(decoder)?, u64::decode(decoder)?))
    }
}

/// Deterministic policy deadline that ended one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyTimeoutKind {
    /// The virtual-time deadline won, including a same-quantum tie.
    VirtualTime,
    /// The scheduler-quantum deadline won before virtual time.
    ExecutionQuanta,
}

impl Canonical for PolicyTimeoutKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::VirtualTime => 0,
            Self::ExecutionQuanta => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::VirtualTime),
            1 => Ok(Self::ExecutionQuanta),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "policy-timeout-kind",
                tag,
            }),
        }
    }
}

/// Canonical modeled reason that execution stopped.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StopOutcome {
    /// The attempt's exact requested semantic boundary was satisfied.
    Reached(StopCondition),
    /// The scenario reached a successful modeled terminal state.
    TerminalSuccess,
    /// A scenario-modeled timeout fired.
    ModeledTimeout(String),
    /// The guest reached a stable modeled crash class.
    GuestCrash(String),
    /// A named stable property assertion failed.
    AssertionFailure(String),
    /// Scenario actions declared failure with reasons in firing order.
    ScenarioFailure(Vec<String>),
    /// A newly completed quantum satisfied an authenticated observation condition.
    ObservationReached(Box<ObservationStopProof>),
    /// A primary boundary won before either campaign-policy deadline.
    BoundedPrimaryReached {
        /// Exact bounded attempt stop.
        stop: StopCondition,
        /// Executor-attested coordinates before both policy deadlines.
        proof: BoundedStopProof,
    },
    /// A campaign-policy deadline fired as a modeled, catchable timeout.
    PolicyTimeout {
        /// Exact bounded attempt stop.
        stop: StopCondition,
        /// Winning deterministic deadline.
        kind: PolicyTimeoutKind,
        /// Executor-attested coordinates at the deadline.
        proof: BoundedStopProof,
    },
}

impl StopOutcome {
    fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::Reached(StopCondition::Observation(_)) => Err(CampaignCodecError::InvalidValue {
                reason: "observation stop requires an authenticated reached proof",
            }),
            Self::Reached(StopCondition::Bounded { .. }) => Err(CampaignCodecError::InvalidValue {
                reason: "bounded stop requires a proof-bearing outcome",
            }),
            Self::Reached(stop) => stop.validate(),
            Self::BoundedPrimaryReached { stop, proof } => {
                if matches!(stop.primary(), StopCondition::Observation(_)) {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "bounded observation primary requires an authenticated proof",
                    });
                }
                if winning_policy_timeout(stop, *proof)?.is_some() {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "bounded primary reached at or after a policy deadline",
                    });
                }
                Ok(())
            }
            Self::PolicyTimeout { stop, kind, proof } => {
                if winning_policy_timeout(stop, *proof)? != Some(*kind) {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "policy timeout disagrees with bounded stop and precedence",
                    });
                }
                Ok(())
            }
            Self::ModeledTimeout(name) => validate_identifier(name, "timeout name is invalid"),
            Self::GuestCrash(class) => validate_identifier(class, "guest crash class is invalid"),
            Self::AssertionFailure(property) => {
                validate_identifier(property, "assertion property is invalid")
            }
            Self::ScenarioFailure(reasons) => validate_scenario_failure_reasons(reasons),
            Self::ObservationReached(proof) => proof.condition().validate(),
            Self::TerminalSuccess => Ok(()),
        }
    }

    /// Returns whether this outcome proves the attempt's requested stop.
    #[must_use]
    pub fn reaches(&self, requested: &StopCondition) -> bool {
        match (self, requested) {
            (Self::BoundedPrimaryReached { stop, proof }, requested) => {
                stop == requested && winning_policy_timeout(stop, *proof) == Ok(None)
            }
            (Self::Reached(actual), requested)
                if !matches!(
                    actual,
                    StopCondition::Observation(_) | StopCondition::Bounded { .. }
                ) =>
            {
                actual == requested
            }
            (Self::ObservationReached(proof), StopCondition::Observation(condition)) => {
                proof.condition() == condition
            }
            (Self::ObservationReached(proof), bounded @ StopCondition::Bounded { primary, .. }) => {
                matches!(primary.as_ref(), StopCondition::Observation(condition) if proof.condition() == condition)
                    && winning_policy_timeout(
                        bounded,
                        BoundedStopProof::new(
                            proof.boundary().frontier_nanoseconds(),
                            proof.boundary().completed_quanta(),
                        ),
                    ) == Ok(None)
            }
            _ => false,
        }
    }

    /// Returns whether this outcome is structurally valid for one exact stop.
    ///
    /// A policy timeout validates its deadline and precedence but does not
    /// count as reaching a statistical or choice-producing primary boundary.
    #[must_use]
    pub fn authenticates_requested_stop(&self, requested: &StopCondition) -> bool {
        match self {
            Self::PolicyTimeout { stop, .. } => stop == requested && self.validate().is_ok(),
            Self::Reached(_) | Self::ObservationReached(_) | Self::BoundedPrimaryReached { .. } => {
                self.reaches(requested)
            }
            _ => true,
        }
    }

    /// Returns whether a reached primary stop exposes a next-choice boundary.
    #[must_use]
    pub fn reached_next_choice(&self) -> bool {
        match self {
            Self::Reached(stop) | Self::BoundedPrimaryReached { stop, .. } => {
                stop.accepts_next_choice()
            }
            _ => false,
        }
    }
}

fn winning_policy_timeout(
    stop: &StopCondition,
    proof: BoundedStopProof,
) -> Result<Option<PolicyTimeoutKind>, CampaignCodecError> {
    let StopCondition::Bounded {
        virtual_time_nanoseconds,
        execution_quanta,
        ..
    } = stop
    else {
        return Err(CampaignCodecError::InvalidValue {
            reason: "policy outcome does not name a bounded stop",
        });
    };
    stop.validate()?;
    if virtual_time_nanoseconds.is_some_and(|bound| proof.frontier_nanoseconds() >= bound) {
        return Ok(Some(PolicyTimeoutKind::VirtualTime));
    }
    if execution_quanta.is_some_and(|bound| proof.completed_quanta() >= bound) {
        return Ok(Some(PolicyTimeoutKind::ExecutionQuanta));
    }
    Ok(None)
}

impl Canonical for StopOutcome {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Reached(stop) => {
                encoder.u8(0);
                stop.encode(encoder);
            }
            Self::TerminalSuccess => encoder.u8(1),
            Self::ModeledTimeout(name) => {
                encoder.u8(2);
                name.encode(encoder);
            }
            Self::GuestCrash(class) => {
                encoder.u8(3);
                class.encode(encoder);
            }
            Self::AssertionFailure(property) => {
                encoder.u8(4);
                property.encode(encoder);
            }
            Self::ScenarioFailure(reasons) => {
                encoder.u8(5);
                reasons.encode(encoder);
            }
            Self::ObservationReached(proof) => {
                encoder.u8(6);
                proof.encode(encoder);
            }
            Self::BoundedPrimaryReached { stop, proof } => {
                encoder.u8(7);
                stop.encode(encoder);
                proof.encode(encoder);
            }
            Self::PolicyTimeout { stop, kind, proof } => {
                encoder.u8(8);
                stop.encode(encoder);
                kind.encode(encoder);
                proof.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let outcome = match decoder.u8()? {
            0 => Self::Reached(StopCondition::decode(decoder)?),
            1 => Self::TerminalSuccess,
            2 => Self::ModeledTimeout(
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "timeout-name-bytes")?,
            ),
            3 => Self::GuestCrash(
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "guest-crash-class-bytes")?,
            ),
            4 => Self::AssertionFailure(
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "assertion-property-bytes")?,
            ),
            5 => Self::ScenarioFailure(decoder.sequence_bounded(
                MAX_SCENARIO_FAILURE_REASONS,
                "scenario-failure-reason-count",
                |decoder| {
                    decoder.string_bounded(
                        MAX_SCENARIO_FAILURE_REASON_BYTES,
                        "scenario-failure-reason-bytes",
                    )
                },
            )?),
            6 => Self::ObservationReached(Box::new(ObservationStopProof::decode(decoder)?)),
            7 => Self::BoundedPrimaryReached {
                stop: StopCondition::decode(decoder)?,
                proof: BoundedStopProof::decode(decoder)?,
            },
            8 => Self::PolicyTimeout {
                stop: StopCondition::decode(decoder)?,
                kind: PolicyTimeoutKind::decode(decoder)?,
                proof: BoundedStopProof::decode(decoder)?,
            },
            tag => {
                return Err(CampaignCodecError::UnknownTag {
                    kind: "stop-outcome",
                    tag,
                });
            }
        };
        outcome.validate()?;
        Ok(outcome)
    }
}

fn validate_scenario_failure_reasons(reasons: &[String]) -> Result<(), CampaignCodecError> {
    if reasons.is_empty() || reasons.len() > MAX_SCENARIO_FAILURE_REASONS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "scenario-failure-reason-count",
        });
    }
    let mut encoded_bytes = std::mem::size_of::<u64>();
    for reason in reasons {
        if reason.len() > MAX_SCENARIO_FAILURE_REASON_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "scenario-failure-reason-bytes",
            });
        }
        codec::validate_nfc(reason)?;
        encoded_bytes = encoded_bytes
            .checked_add(std::mem::size_of::<u64>())
            .and_then(|total| total.checked_add(reason.len()))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "scenario-failure-reasons-bytes",
            })?;
        if encoded_bytes > MAX_SCENARIO_FAILURE_REASONS_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "scenario-failure-reasons-bytes",
            });
        }
    }
    Ok(())
}

pub(crate) fn scenario_failure_hash(reasons: &[String]) -> CampaignHash {
    let mut encoder = Encoder::new();
    encoder.sequence(reasons, |encoder, reason| reason.encode(encoder));
    CampaignHash::derive(
        "crucible.campaign.scenario-failure-reasons.v1",
        &encoder.finish(),
    )
}

mod record;
pub use record::{Observation, ObservationOutcome};
use record::{decode_record, require_schema};
