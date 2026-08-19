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
const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;
const MAX_MEASUREMENTS: usize = 4096;
const MAX_SAMPLES_PER_MEASUREMENT: usize = 65_536;
const MAX_PROPERTIES: usize = 4096;
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

/// Canonical exact measurements keyed by scenario-declared measurement name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementSet {
    schema_version: u32,
    measurements: BTreeMap<String, MeasurementSeries>,
}

impl MeasurementSet {
    /// Builds a bounded canonical measurement set.
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
            measurements,
        };
        codec::ensure_encoded_size(&value, MAX_RECORD_BYTES, "measurement-set-encoded-bytes")?;
        Ok(value)
    }

    /// Returns measurements in canonical name order.
    #[must_use]
    pub const fn measurements(&self) -> &BTreeMap<String, MeasurementSeries> {
        &self.measurements
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
        decode_record(bytes, "measurement-set-encoded-bytes")
    }

    /// Returns the exact measurement-set identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<MeasurementSetId, CampaignCodecError> {
        MeasurementSetId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::MeasurementSet,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        self.measurements
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
            .collect()
    }
}

impl Canonical for MeasurementSet {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.measurements.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(decoder.map_bounded_by(
            MAX_MEASUREMENTS,
            "measurement-count",
            |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "measurement-name-bytes"),
            MeasurementSeries::decode,
        )?)
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
        stop.validate()?;
        if discovered_choices.len() > MAX_DISCOVERED_CHOICES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "observation-discovered-choice-count",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            attempt,
            child,
            child_content,
            path,
            stop,
            measurements,
            properties,
            coverage,
            discovered_choices,
        };
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
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::Observation,
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
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            AttemptId::decode(decoder)?,
            ConfigurationId::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            BranchPathId::decode(decoder)?,
            StopOutcome::decode(decoder)?,
            MeasurementSetId::decode(decoder)?,
            PropertyVerdictSetId::decode(decoder)?,
            CoverageProjectionId::decode(decoder)?,
            decoder.set_bounded(
                MAX_DISCOVERED_CHOICES,
                "observation-discovered-choice-count",
            )?,
        )
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
