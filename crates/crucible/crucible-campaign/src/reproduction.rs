//! Verifier-backed reproduction artifacts and their segmented payloads.
//!
//! A reproduction stores the execution model's self-contained replay input.
//! The input grows with the reproduced run, because it includes every recorded
//! schedule decision, so the record keeps only the payload's static part
//! inline and names the run-length part as ordered, content-addressed trace
//! leaves, the segment layout RFC-0020 section 15 uses for every run-length
//! log. The campaign layer treats both as opaque: an execution-model adapter
//! must replay and verify them before publication, and reassembles them when
//! reading.
//!
//! ```text
//! reproduction record v3:
//!   u32 schema-version = 3
//!   ScenarioDefId, ScenarioArtifactId, ConfigurationId,
//!   ConfigurationArtifactId, CampaignHash finding-fingerprint
//!   u32 payload-schema
//!   bytes payload                         // static part, at most 34 MiB
//!   sequence (ContentId segment, u64 segment-bytes)   // trace leaves, in order
//!   option FindingMinimizationEvidence
//!
//! children: scenario, configuration, [minimization.original],
//!           payload.segment.<index> for every segment
//! ```

use std::collections::BTreeSet;

use crucible_store::content_store::{ContentId, ObjectKind};
use crucible_store::segment_store::{MAX_MANIFEST_SEGMENTS, MAX_SEGMENT_BYTES};

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    CampaignCodecError, CampaignHash, CampaignRecordKind, ConfigurationArtifactId, ConfigurationId,
    FindingMinimizationEvidence, ObjectEnvelope, ReproductionArtifactId, ScenarioArtifactId,
    ScenarioDefId,
};

/// Record-body and envelope schema of a current reproduction record.
pub(crate) const REPRODUCTION_SCHEMA_VERSION: u32 = 3;

/// Largest static execution-model payload one reproduction record embeds.
///
/// The static part holds the scenario, itself bounded by the 32 MiB
/// execution-model artifact bound, and a manifest of at most 1 MiB naming the
/// payload segments. Run-length content lives in the segments.
const MAX_REPRODUCTION_PAYLOAD_BYTES: usize = 34 * 1024 * 1024;

/// Largest encoded reproduction record: the static payload plus the segment
/// list and bounded minimization evidence.
const MAX_REPRODUCTION_RECORD_BYTES: usize = 36 * 1024 * 1024;

/// Largest number of payload segments one reproduction may reference.
///
/// This is the segment bound of one manifest shared by every segmented log.
pub const MAX_REPRODUCTION_PAYLOAD_SEGMENTS: usize = MAX_MANIFEST_SEGMENTS;

/// One run-length payload segment retained as a trace leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReproductionPayloadSegment {
    content: ContentId,
    bytes: u64,
}

impl ReproductionPayloadSegment {
    /// Names one trace leaf and its exact length.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `content` is not a trace identity
    /// or `bytes` is zero or above the shared 16 MiB segment bound.
    pub fn new(content: ContentId, bytes: u64) -> Result<Self, CampaignCodecError> {
        if content.kind() != ObjectKind::Trace {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding reproduction payload segment is not a trace leaf",
            });
        }
        if bytes == 0 || bytes > MAX_SEGMENT_BYTES as u64 {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-reproduction-payload-segment-bytes",
            });
        }
        Ok(Self { content, bytes })
    }

    /// Returns the trace-leaf identity.
    #[must_use]
    pub const fn content(&self) -> ContentId {
        self.content
    }

    /// Returns the exact trace-leaf length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Canonical for ReproductionPayloadSegment {
    fn encode(&self, encoder: &mut Encoder) {
        Canonical::encode(&self.content, encoder);
        self.bytes.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            <ContentId as Canonical>::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Opaque execution-model payload: an inline static part plus ordered segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionPayload {
    schema: u32,
    bytes: Vec<u8>,
    segments: Vec<ReproductionPayloadSegment>,
}

impl ReproductionPayload {
    /// Builds a bounded payload description.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a zero schema, an empty static part,
    /// a static part above 34 MiB, more than
    /// [`MAX_REPRODUCTION_PAYLOAD_SEGMENTS`] segments, or a repeated segment.
    pub fn new(
        schema: u32,
        bytes: Vec<u8>,
        segments: Vec<ReproductionPayloadSegment>,
    ) -> Result<Self, CampaignCodecError> {
        if schema == 0 || bytes.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding reproduction payload is empty or has no schema",
            });
        }
        if bytes.len() > MAX_REPRODUCTION_PAYLOAD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-reproduction-payload-bytes",
            });
        }
        if segments.len() > MAX_REPRODUCTION_PAYLOAD_SEGMENTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-reproduction-payload-segments",
            });
        }
        // Every segment becomes its own envelope child, so identities must be
        // distinct; a segmented log never repeats one because each segment
        // records its own position.
        let distinct = segments
            .iter()
            .map(ReproductionPayloadSegment::content)
            .collect::<BTreeSet<_>>();
        if distinct.len() != segments.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding reproduction payload repeats a segment",
            });
        }
        Ok(Self {
            schema,
            bytes,
            segments,
        })
    }

    /// Returns the execution-model payload schema.
    #[must_use]
    pub const fn schema(&self) -> u32 {
        self.schema
    }

    /// Returns the inline static payload bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the run-length payload segments in payload order.
    #[must_use]
    pub fn segments(&self) -> &[ReproductionPayloadSegment] {
        &self.segments
    }

    /// Returns whether the payload names `segment` as one of its leaves.
    #[must_use]
    pub fn names_segment(&self, segment: ContentId) -> Option<ReproductionPayloadSegment> {
        self.segments
            .iter()
            .copied()
            .find(|candidate| candidate.content == segment)
    }
}

/// Authenticated identity basis shared by reproduction artifact constructors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReproductionArtifactBasis {
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    configuration: ConfigurationId,
    configuration_artifact: ConfigurationArtifactId,
    finding_fingerprint: CampaignHash,
}

impl ReproductionArtifactBasis {
    /// Builds an identity basis from its semantic and exact artifact identities.
    #[must_use]
    pub const fn new(
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        configuration_artifact: ConfigurationArtifactId,
        finding_fingerprint: CampaignHash,
    ) -> Self {
        Self {
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
        }
    }
}

/// Self-contained execution-model reproduction after adapter verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionArtifact {
    schema_version: u32,
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    configuration: ConfigurationId,
    configuration_artifact: ConfigurationArtifactId,
    finding_fingerprint: CampaignHash,
    payload: ReproductionPayload,
    minimization: Option<FindingMinimizationEvidence>,
}

impl ReproductionArtifact {
    /// Builds a bounded reproduction record after execution-model verification.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded record exceeds its
    /// bound.
    pub fn new(
        basis: ReproductionArtifactBasis,
        payload: ReproductionPayload,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_current(basis, payload, None)
    }

    /// Builds a verifier-backed minimized reproduction with its exact trace.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an inconsistent minimization target
    /// or an encoded record above its bound.
    pub fn new_minimized(
        basis: ReproductionArtifactBasis,
        payload: ReproductionPayload,
        minimization: FindingMinimizationEvidence,
    ) -> Result<Self, CampaignCodecError> {
        if minimization.attempts().iter().any(|attempt| {
            attempt.accepted() && attempt.observed_fingerprint() != Some(basis.finding_fingerprint)
        }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding minimization accepted a different fingerprint",
            });
        }
        Self::new_current(basis, payload, Some(minimization))
    }

    fn new_current(
        basis: ReproductionArtifactBasis,
        payload: ReproductionPayload,
        minimization: Option<FindingMinimizationEvidence>,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self {
            schema_version: REPRODUCTION_SCHEMA_VERSION,
            scenario: basis.scenario,
            scenario_artifact: basis.scenario_artifact,
            configuration: basis.configuration,
            configuration_artifact: basis.configuration_artifact,
            finding_fingerprint: basis.finding_fingerprint,
            payload,
            minimization,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_REPRODUCTION_RECORD_BYTES,
            "finding-reproduction-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the canonical record-body and envelope schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the semantic scenario identity.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the exact scenario artifact used by the reproduction.
    #[must_use]
    pub const fn scenario_artifact(&self) -> ScenarioArtifactId {
        self.scenario_artifact
    }

    /// Returns the semantic replay configuration identity.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the exact configuration artifact used by the reproduction.
    #[must_use]
    pub const fn configuration_artifact(&self) -> ConfigurationArtifactId {
        self.configuration_artifact
    }

    /// Returns the stable failure fingerprint verified during replay.
    #[must_use]
    pub const fn finding_fingerprint(&self) -> CampaignHash {
        self.finding_fingerprint
    }

    /// Returns the execution-model payload schema.
    #[must_use]
    pub const fn payload_schema(&self) -> u32 {
        self.payload.schema
    }

    /// Returns the inline static execution-model bytes.
    ///
    /// The run-length part of the payload is held by
    /// [`Self::payload_segments`]; readers reassemble the two through the
    /// execution-model adapter.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload.bytes
    }

    /// Returns the run-length payload segments in payload order.
    #[must_use]
    pub fn payload_segments(&self) -> &[ReproductionPayloadSegment] {
        &self.payload.segments
    }

    /// Returns the complete payload description.
    #[must_use]
    pub const fn reproduction_payload(&self) -> &ReproductionPayload {
        &self.payload
    }

    /// Returns retained deterministic minimization evidence, when present.
    #[must_use]
    pub const fn minimization(&self) -> Option<&FindingMinimizationEvidence> {
        self.minimization.as_ref()
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical record-body bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes, or a record body of any schema other than 3.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_REPRODUCTION_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-reproduction-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the exact stored reproduction identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ReproductionArtifactId, CampaignCodecError> {
        ReproductionArtifactId::from_content_id(
            ObjectEnvelope::for_record_versioned(
                CampaignRecordKind::ReproductionArtifact,
                self.schema_version,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("scenario".to_owned(), self.scenario_artifact.content_id()),
            (
                "configuration".to_owned(),
                self.configuration_artifact.content_id(),
            ),
        ];
        if let Some(minimization) = &self.minimization {
            children.push((
                "minimization.original".to_owned(),
                minimization.original().content_id(),
            ));
        }
        children.extend(
            self.payload
                .segments
                .iter()
                .enumerate()
                .map(|(index, segment)| (format!("payload.segment.{index}"), segment.content)),
        );
        children
    }
}

impl Canonical for ReproductionArtifact {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.scenario.encode(encoder);
        self.scenario_artifact.encode(encoder);
        self.configuration.encode(encoder);
        self.configuration_artifact.encode(encoder);
        self.finding_fingerprint.encode(encoder);
        self.payload.schema.encode(encoder);
        self.payload.bytes.encode(encoder);
        self.payload.segments.encode(encoder);
        self.minimization.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != REPRODUCTION_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding reproduction schema version",
            });
        }
        let scenario = ScenarioDefId::decode(decoder)?;
        let scenario_artifact = ScenarioArtifactId::decode(decoder)?;
        let configuration = ConfigurationId::decode(decoder)?;
        let configuration_artifact = ConfigurationArtifactId::decode(decoder)?;
        let finding_fingerprint = CampaignHash::decode(decoder)?;
        let payload_schema = u32::decode(decoder)?;
        let payload = decoder.sequence_bounded(
            MAX_REPRODUCTION_PAYLOAD_BYTES,
            "finding-reproduction-payload-bytes",
            u8::decode,
        )?;
        let segments = decoder.sequence_bounded(
            MAX_REPRODUCTION_PAYLOAD_SEGMENTS,
            "finding-reproduction-payload-segments",
            ReproductionPayloadSegment::decode,
        )?;
        let minimization = Option::<FindingMinimizationEvidence>::decode(decoder)?;
        Self::new_current(
            ReproductionArtifactBasis::new(
                scenario,
                scenario_artifact,
                configuration,
                configuration_artifact,
                finding_fingerprint,
            ),
            ReproductionPayload::new(payload_schema, payload, segments)?,
            minimization,
        )
    }
}
