//! Canonical modeled outcomes and executor-produced evidence.
//!
//! Observation records bind one admitted semantic attempt to its exact child
//! configuration, stop outcome, measurements, property verdicts, coverage,
//! and newly discovered choices. Operational reservation, worker, retry, and
//! host-timing data is deliberately absent.

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    AttemptId, BranchPathId, CampaignCodecError, CampaignHash, ChoiceOpportunityId,
    ConfigurationArtifactId, ConfigurationId, CoverageProjectionId, MeasurementSetId,
    ObservationId, PropertyVerdictSetId, StopCondition,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const SCENARIO_FAILURE_OBSERVATION_SCHEMA_VERSION: u32 = 2;
const MEASUREMENT_SET_SCHEMA_VERSION: u32 = 2;
const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;
const MAX_MEASUREMENT_EVALUATION_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_MEASUREMENT_SET_RECORD_BYTES: usize = 33 * 1024 * 1024;
const MAX_MEASUREMENTS: usize = 4096;
const MAX_SAMPLES_PER_MEASUREMENT: usize = 65_536;
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
const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// One exact typed measurement sample or aggregate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetricValue {
    /// Boolean value.
    Boolean(bool),
    /// Signed integer value.
    Signed(i64),
    /// Unsigned integer value.
    Unsigned(u64),
    /// Opaque bounded byte value for a scenario-declared metric type.
    Bytes(Vec<u8>),
    /// Bounded identifier-like text value.
    Text(String),
}

impl MetricValue {
    const fn kind_tag(&self) -> u8 {
        match self {
            Self::Boolean(_) => 0,
            Self::Signed(_) => 1,
            Self::Unsigned(_) => 2,
            Self::Bytes(_) => 3,
            Self::Text(_) => 4,
        }
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::Bytes(bytes) if bytes.len() > MAX_VALUE_BYTES => {
                Err(CampaignCodecError::LimitExceeded {
                    limit: "measurement-value-bytes",
                })
            }
            Self::Text(value) => validate_identifier(value, "measurement text value is invalid"),
            Self::Boolean(_) | Self::Signed(_) | Self::Unsigned(_) | Self::Bytes(_) => Ok(()),
        }
    }
}

impl Canonical for MetricValue {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Boolean(value) => {
                encoder.u8(0);
                value.encode(encoder);
            }
            Self::Signed(value) => {
                encoder.u8(1);
                value.encode(encoder);
            }
            Self::Unsigned(value) => {
                encoder.u8(2);
                value.encode(encoder);
            }
            Self::Bytes(value) => {
                encoder.u8(3);
                value.encode(encoder);
            }
            Self::Text(value) => {
                encoder.u8(4);
                value.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let value = match decoder.u8()? {
            0 => Self::Boolean(bool::decode(decoder)?),
            1 => Self::Signed(i64::decode(decoder)?),
            2 => Self::Unsigned(u64::decode(decoder)?),
            3 => Self::Bytes(decoder.sequence_bounded(
                MAX_VALUE_BYTES,
                "measurement-value-bytes",
                u8::decode,
            )?),
            4 => Self::Text(
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "measurement-text-value-bytes")?,
            ),
            tag => {
                return Err(CampaignCodecError::UnknownTag {
                    kind: "metric-value",
                    tag,
                });
            }
        };
        value.validate()?;
        Ok(value)
    }
}

/// Exact samples, aggregate, and retained evidence for one measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementSeries {
    samples: Vec<MetricValue>,
    aggregate: MetricValue,
    evidence: BTreeSet<ContentId>,
}

impl MeasurementSeries {
    /// Builds one bounded nonempty measurement series.
    ///
    /// # Errors
    ///
    /// Returns an error when samples or evidence exceed their bounds or a
    /// typed value is invalid.
    pub fn new(
        samples: Vec<MetricValue>,
        aggregate: MetricValue,
        evidence: BTreeSet<ContentId>,
    ) -> Result<Self, CampaignCodecError> {
        if samples.is_empty() || samples.len() > MAX_SAMPLES_PER_MEASUREMENT {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "measurement-sample-count",
            });
        }
        if evidence.len() > MAX_EVIDENCE_OBJECTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "measurement-evidence-count",
            });
        }
        for sample in &samples {
            sample.validate()?;
            if sample.kind_tag() != aggregate.kind_tag() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "measurement sample and aggregate types differ",
                });
            }
        }
        aggregate.validate()?;
        Ok(Self {
            samples,
            aggregate,
            evidence,
        })
    }

    /// Returns exact samples in modeled event order.
    #[must_use]
    pub fn samples(&self) -> &[MetricValue] {
        &self.samples
    }

    /// Returns the exact declared aggregate.
    #[must_use]
    pub const fn aggregate(&self) -> &MetricValue {
        &self.aggregate
    }

    /// Returns retained sample and aggregation evidence objects.
    #[must_use]
    pub const fn evidence(&self) -> &BTreeSet<ContentId> {
        &self.evidence
    }
}

impl Canonical for MeasurementSeries {
    fn encode(&self, encoder: &mut Encoder) {
        self.samples.encode(encoder);
        self.aggregate.encode(encoder);
        self.evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.sequence_bounded(
                MAX_SAMPLES_PER_MEASUREMENT,
                "measurement-sample-count",
                MetricValue::decode,
            )?,
            MetricValue::decode(decoder)?,
            decoder.set_bounded(MAX_EVIDENCE_OBJECTS, "measurement-evidence-count")?,
        )
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
enum MeasurementSetBody {
    Legacy(BTreeMap<String, MeasurementSeries>),
    Evaluation(MeasurementEvaluationPayload),
}

/// Canonical exact measurement results for one observation.
///
/// New records retain one verified, versioned execution-model evaluation.
/// Schema-v1 name/series maps remain readable with their original identity for
/// campaign compatibility, but are not independently verified aggregates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementSet {
    schema_version: u32,
    body: MeasurementSetBody,
}

impl MeasurementSet {
    /// Builds one legacy schema-v1 claimed measurement map.
    ///
    /// New execution paths should use [`Self::from_evaluation`]. This
    /// constructor remains available only so existing schema-v1 records retain
    /// their exact canonical identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, oversized set, or oversized record.
    pub fn new(
        measurements: BTreeMap<String, MeasurementSeries>,
    ) -> Result<Self, CampaignCodecError> {
        if measurements.len() > MAX_MEASUREMENTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "measurement-count",
            });
        }
        for name in measurements.keys() {
            validate_identifier(name, "measurement name is invalid")?;
        }
        let evidence_children = measurements.values().try_fold(0_usize, |total, series| {
            total
                .checked_add(series.evidence().len())
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "measurement-evidence-child-count",
                })
        })?;
        if evidence_children > MAX_ENVELOPE_CHILDREN {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "measurement-evidence-child-count",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            body: MeasurementSetBody::Legacy(measurements),
        };
        codec::ensure_encoded_size(&value, MAX_RECORD_BYTES, "measurement-set-encoded-bytes")?;
        Ok(value)
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
            schema_version: MEASUREMENT_SET_SCHEMA_VERSION,
            body: MeasurementSetBody::Evaluation(MeasurementEvaluationPayload {
                definitions,
                payload_schema,
                evaluation,
                payload,
                evidence,
            }),
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
        self.schema_version
    }

    /// Returns legacy measurements in canonical name order, when this is v1.
    #[must_use]
    pub fn legacy_measurements(&self) -> Option<&BTreeMap<String, MeasurementSeries>> {
        match &self.body {
            MeasurementSetBody::Legacy(measurements) => Some(measurements),
            MeasurementSetBody::Evaluation(_) => None,
        }
    }

    /// Returns the verified evaluation payload, when this is schema v2.
    #[must_use]
    pub const fn evaluation(&self) -> Option<&MeasurementEvaluationPayload> {
        match &self.body {
            MeasurementSetBody::Legacy(_) => None,
            MeasurementSetBody::Evaluation(evaluation) => Some(evaluation),
        }
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
        match &self.body {
            MeasurementSetBody::Legacy(measurements) => measurements
                .values()
                .enumerate()
                .flat_map(|(measurement, series)| {
                    series
                        .evidence()
                        .iter()
                        .enumerate()
                        .map(move |(index, id)| {
                            (
                                format!("measurement.{measurement:04x}.evidence.{index:04x}"),
                                *id,
                            )
                        })
                })
                .collect(),
            MeasurementSetBody::Evaluation(evaluation) => evaluation
                .evidence
                .iter()
                .enumerate()
                .map(|(index, id)| (format!("evaluation.evidence.{index:04x}"), *id))
                .collect(),
        }
    }
}

impl Canonical for MeasurementSet {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        match &self.body {
            MeasurementSetBody::Legacy(measurements) => measurements.encode(encoder),
            MeasurementSetBody::Evaluation(evaluation) => {
                evaluation.definitions.encode(encoder);
                evaluation.payload_schema.encode(encoder);
                evaluation.evaluation.encode(encoder);
                evaluation.payload.encode(encoder);
                evaluation.evidence.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match u32::decode(decoder)? {
            RECORD_SCHEMA_VERSION => Self::new(decoder.map_bounded_by(
                MAX_MEASUREMENTS,
                "measurement-count",
                |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "measurement-name-bytes"),
                MeasurementSeries::decode,
            )?),
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
}

impl StopOutcome {
    fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::Reached(stop) => stop.validate(),
            Self::ModeledTimeout(name) => validate_identifier(name, "timeout name is invalid"),
            Self::GuestCrash(class) => validate_identifier(class, "guest crash class is invalid"),
            Self::AssertionFailure(property) => {
                validate_identifier(property, "assertion property is invalid")
            }
            Self::ScenarioFailure(reasons) => validate_scenario_failure_reasons(reasons),
            Self::TerminalSuccess => Ok(()),
        }
    }
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

/// Canonical modeled result of one admitted attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    schema_version: u32,
    attempt: AttemptId,
    child: ConfigurationId,
    child_content: ConfigurationArtifactId,
    path: BranchPathId,
    stop: StopOutcome,
    measurements: MeasurementSetId,
    properties: PropertyVerdictSetId,
    coverage: CoverageProjectionId,
    discovered_choices: BTreeSet<ChoiceOpportunityId>,
}

impl Observation {
    /// Builds one bounded canonical attempt observation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid stop outcome, too many discovered
    /// choices, or an oversized encoded record.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attempt: AttemptId,
        child: ConfigurationId,
        child_content: ConfigurationArtifactId,
        path: BranchPathId,
        stop: StopOutcome,
        measurements: MeasurementSetId,
        properties: PropertyVerdictSetId,
        coverage: CoverageProjectionId,
        discovered_choices: BTreeSet<ChoiceOpportunityId>,
    ) -> Result<Self, CampaignCodecError> {
        let schema_version = if matches!(stop, StopOutcome::ScenarioFailure(_)) {
            SCENARIO_FAILURE_OBSERVATION_SCHEMA_VERSION
        } else {
            RECORD_SCHEMA_VERSION
        };
        Self::from_versioned(Self {
            schema_version,
            attempt,
            child,
            child_content,
            path,
            stop,
            measurements,
            properties,
            coverage,
            discovered_choices,
        })
    }

    fn from_versioned(value: Self) -> Result<Self, CampaignCodecError> {
        value.stop.validate()?;
        if value.discovered_choices.len() > MAX_DISCOVERED_CHOICES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "observation-discovered-choice-count",
            });
        }
        let compatible = match value.schema_version {
            RECORD_SCHEMA_VERSION => !matches!(&value.stop, StopOutcome::ScenarioFailure(_)),
            SCENARIO_FAILURE_OBSERVATION_SCHEMA_VERSION => {
                matches!(&value.stop, StopOutcome::ScenarioFailure(_))
            }
            _ => false,
        };
        if !compatible {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported observation schema or stop outcome",
            });
        }
        codec::ensure_encoded_size(&value, MAX_RECORD_BYTES, "observation-encoded-bytes")?;
        Ok(value)
    }

    /// Returns the admitted attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the child configuration semantic identity.
    #[must_use]
    pub const fn child(&self) -> ConfigurationId {
        self.child
    }

    /// Returns the exact retained child configuration artifact.
    #[must_use]
    pub const fn child_content(&self) -> ConfigurationArtifactId {
        self.child_content
    }

    /// Returns the exact admitted branch path.
    #[must_use]
    pub const fn path(&self) -> BranchPathId {
        self.path
    }

    /// Returns the modeled stop outcome.
    #[must_use]
    pub const fn stop(&self) -> &StopOutcome {
        &self.stop
    }

    /// Returns the exact measurement set.
    #[must_use]
    pub const fn measurements(&self) -> MeasurementSetId {
        self.measurements
    }

    /// Returns the exact property-verdict set.
    #[must_use]
    pub const fn properties(&self) -> PropertyVerdictSetId {
        self.properties
    }

    /// Returns the exact coverage projection.
    #[must_use]
    pub const fn coverage(&self) -> CoverageProjectionId {
        self.coverage
    }

    /// Returns discovered choice opportunities in canonical identity order.
    #[must_use]
    pub const fn discovered_choices(&self) -> &BTreeSet<ChoiceOpportunityId> {
        &self.discovered_choices
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
        decode_record(bytes, "observation-encoded-bytes")
    }

    /// Returns the exact observation identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<ObservationId, CampaignCodecError> {
        ObservationId::from_content_id(
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::Observation,
                self.schema_version,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("attempt".to_owned(), self.attempt.content_id()),
            ("child".to_owned(), self.child_content.content_id()),
            ("path".to_owned(), self.path.content_id()),
            ("measurements".to_owned(), self.measurements.content_id()),
            ("properties".to_owned(), self.properties.content_id()),
            ("coverage".to_owned(), self.coverage.content_id()),
        ];
        children.extend(
            self.discovered_choices
                .iter()
                .enumerate()
                .map(|(index, choice)| {
                    (
                        format!("discovered-choice.{index:04x}"),
                        choice.content_id(),
                    )
                }),
        );
        children
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Canonical for Observation {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.attempt.encode(encoder);
        self.child.encode(encoder);
        self.child_content.encode(encoder);
        self.path.encode(encoder);
        self.stop.encode(encoder);
        self.measurements.encode(encoder);
        self.properties.encode(encoder);
        self.coverage.encode(encoder);
        self.discovered_choices.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        Self::from_versioned(Self {
            schema_version,
            attempt: AttemptId::decode(decoder)?,
            child: ConfigurationId::decode(decoder)?,
            child_content: ConfigurationArtifactId::decode(decoder)?,
            path: BranchPathId::decode(decoder)?,
            stop: StopOutcome::decode(decoder)?,
            measurements: MeasurementSetId::decode(decoder)?,
            properties: PropertyVerdictSetId::decode(decoder)?,
            coverage: CoverageProjectionId::decode(decoder)?,
            discovered_choices: decoder.set_bounded(
                MAX_DISCOVERED_CHOICES,
                "observation-discovered-choice-count",
            )?,
        })
    }
}

fn require_schema(actual: u32) -> Result<(), CampaignCodecError> {
    if actual == RECORD_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported observation record schema version",
        })
    }
}

fn decode_record<T: Canonical>(bytes: &[u8], limit: &'static str) -> Result<T, CampaignCodecError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CampaignCodecError::LimitExceeded { limit });
    }
    codec::decode(bytes)
}
