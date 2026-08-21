//! Stable campaign findings and verifier-backed reproduction artifacts.
//!
//! The campaign layer stores a language-neutral failure signature and the
//! exact self-contained execution-model bytes that reproduce it. The bytes are
//! opaque here: an execution-model adapter must replay and verify them before
//! publication. Campaign ownership then validates their exact scenario,
//! configuration, fingerprint, observation, and retention relationships.

use std::collections::BTreeSet;

use crucible_cas::content_store::{ContentId, ObjectKind};

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    CampaignCodecError, CampaignHash, CampaignRecordKind, CampaignSnapshotId, ChoiceOpportunityId,
    ConfigurationArtifactId, ConfigurationId, ExactCheckpointId, FindingId, ObjectEnvelope,
    ObservationId, ReproductionArtifactId, ScenarioArtifactId, ScenarioDefId,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const MAX_REPRODUCTION_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_FINDING_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Maximum causal evidence objects retained by one signature.
pub const MAX_FINDING_CAUSAL_EVIDENCE: usize = 4_096;
/// Maximum observations clustered into one finding occurrence Merkle set.
pub const MAX_FINDING_OCCURRENCES: u32 = 1_000_000;
/// Maximum optional exact checkpoints retained by one finding.
pub const MAX_FINDING_EXACT_PINS: usize = 256;

/// Closed stable failure class represented by one campaign finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    /// A scenario-declared property or assertion failed.
    PropertyViolation,
    /// Deterministic replay diverged from its authenticated history.
    Divergence,
    /// A deterministic execution budget was exhausted.
    Timeout,
}

impl Canonical for FindingKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::PropertyViolation => 0,
            Self::Divergence => 1,
            Self::Timeout => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::PropertyViolation),
            1 => Ok(Self::Divergence),
            2 => Ok(Self::Timeout),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "finding-kind",
                tag,
            }),
        }
    }
}

/// Optional semantic target most directly associated with a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingTarget {
    /// The finding is associated with one exact modeled configuration.
    Configuration(ConfigurationArtifactId),
    /// The finding is associated with one declared runtime choice occurrence.
    ChoiceOpportunity(ChoiceOpportunityId),
}

impl FindingTarget {
    const fn content_id(self) -> ContentId {
        match self {
            Self::Configuration(id) => id.content_id(),
            Self::ChoiceOpportunity(id) => id.content_id(),
        }
    }
}

impl Canonical for FindingTarget {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Configuration(id) => {
                encoder.u8(0);
                id.encode(encoder);
            }
            Self::ChoiceOpportunity(id) => {
                encoder.u8(1);
                id.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => ConfigurationArtifactId::decode(decoder).map(Self::Configuration),
            1 => ChoiceOpportunityId::decode(decoder).map(Self::ChoiceOpportunity),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "finding-target",
                tag,
            }),
        }
    }
}

/// Stable, operational-data-free signature used to cluster finding occurrences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingSignature {
    kind: FindingKind,
    fingerprint: CampaignHash,
    property: Option<String>,
    failure_class: String,
    target: Option<FindingTarget>,
    causal_evidence: BTreeSet<ContentId>,
}

impl FindingSignature {
    /// Builds a bounded signature from execution-model-verified material.
    ///
    /// A property violation requires a property identity; other finding kinds
    /// reject one. Operational fields such as PID, executor, wall time, and
    /// materialization tier are intentionally not representable.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid identifier, inconsistent
    /// property basis, or too many causal evidence objects.
    pub fn new(
        kind: FindingKind,
        fingerprint: CampaignHash,
        property: Option<String>,
        failure_class: String,
        target: Option<FindingTarget>,
        causal_evidence: BTreeSet<ContentId>,
    ) -> Result<Self, CampaignCodecError> {
        if causal_evidence.len() > MAX_FINDING_CAUSAL_EVIDENCE {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-causal-evidence-count",
            });
        }
        if let Some(property) = &property {
            validate_identifier(property, "finding property identity is invalid")?;
        }
        validate_identifier(&failure_class, "finding failure class is invalid")?;
        if matches!(kind, FindingKind::PropertyViolation) != property.is_some() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding property identity disagrees with failure kind",
            });
        }
        Ok(Self {
            kind,
            fingerprint,
            property,
            failure_class,
            target,
            causal_evidence,
        })
    }

    /// Returns the closed failure kind.
    #[must_use]
    pub const fn kind(&self) -> FindingKind {
        self.kind
    }

    /// Returns the stable execution-model fingerprint reproduced by the artifact.
    #[must_use]
    pub const fn fingerprint(&self) -> CampaignHash {
        self.fingerprint
    }

    /// Returns the scenario-declared property identity, when applicable.
    #[must_use]
    pub fn property(&self) -> Option<&str> {
        self.property.as_deref()
    }

    /// Returns the normalized guest or QEMU failure class.
    #[must_use]
    pub fn failure_class(&self) -> &str {
        &self.failure_class
    }

    /// Returns the most relevant modeled target, when one is known.
    #[must_use]
    pub const fn target(&self) -> Option<FindingTarget> {
        self.target
    }

    /// Returns the exact retained causal evidence identities.
    #[must_use]
    pub const fn causal_evidence(&self) -> &BTreeSet<ContentId> {
        &self.causal_evidence
    }

    /// Returns the deterministic cluster key for this signature.
    #[must_use]
    pub fn cluster_key(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign.finding-signature.v1",
            &codec::encode(self),
        )
    }

    fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = self
            .causal_evidence
            .iter()
            .enumerate()
            .map(|(index, id)| (format!("signature.evidence.{index:04x}"), *id))
            .collect::<Vec<_>>();
        if let Some(target) = self.target {
            children.push(("signature.target".to_owned(), target.content_id()));
        }
        children
    }
}

impl Canonical for FindingSignature {
    fn encode(&self, encoder: &mut Encoder) {
        self.kind.encode(encoder);
        self.fingerprint.encode(encoder);
        self.property.encode(encoder);
        self.failure_class.encode(encoder);
        self.target.encode(encoder);
        self.causal_evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            FindingKind::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            decoder.option(|decoder| {
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "finding-property-identity-bytes")
            })?,
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "finding-failure-class-bytes")?,
            Option::<FindingTarget>::decode(decoder)?,
            decoder.set_bounded(MAX_FINDING_CAUSAL_EVIDENCE, "finding-causal-evidence-count")?,
        )
    }
}

/// Self-contained execution-model reproduction bytes after adapter verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionArtifact {
    schema_version: u32,
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    configuration: ConfigurationId,
    configuration_artifact: ConfigurationArtifactId,
    finding_fingerprint: CampaignHash,
    payload_schema: u32,
    payload: Vec<u8>,
}

impl ReproductionArtifact {
    /// Builds a bounded reproduction record after execution-model verification.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a zero payload schema, empty payload,
    /// or payload above 32 MiB.
    pub fn new(
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        configuration_artifact: ConfigurationArtifactId,
        finding_fingerprint: CampaignHash,
        payload_schema: u32,
        payload: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        if payload_schema == 0 || payload.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding reproduction payload is empty or has no schema",
            });
        }
        if payload.len() > MAX_REPRODUCTION_PAYLOAD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-reproduction-payload-bytes",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
            payload_schema,
            payload,
        })
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
        self.payload_schema
    }

    /// Returns the self-contained canonical execution-model bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
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
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_REPRODUCTION_PAYLOAD_BYTES + 2_048 {
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
            ObjectEnvelope::for_record(
                CampaignRecordKind::ReproductionArtifact,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> [(&'static str, ContentId); 2] {
        [
            ("scenario", self.scenario_artifact.content_id()),
            ("configuration", self.configuration_artifact.content_id()),
        ]
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
        self.payload_schema.encode(encoder);
        self.payload.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != RECORD_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding reproduction schema version",
            });
        }
        Self::new(
            ScenarioDefId::decode(decoder)?,
            ScenarioArtifactId::decode(decoder)?,
            ConfigurationId::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_REPRODUCTION_PAYLOAD_BYTES,
                "finding-reproduction-payload-bytes",
                u8::decode,
            )?,
        )
    }
}

/// Authenticated occurrence-set projection carried by one finding version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingOccurrenceSet {
    root: ContentId,
    count: u32,
    latest: ObservationId,
}

impl FindingOccurrenceSet {
    /// Builds a bounded occurrence-set projection.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `root` is not a Merkle node or
    /// `count` is zero or exceeds the one-million-occurrence bound.
    pub fn new(
        root: ContentId,
        count: u32,
        latest: ObservationId,
    ) -> Result<Self, CampaignCodecError> {
        if root.kind() != ObjectKind::MerkleNode {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding occurrence root is not a Merkle node",
            });
        }
        if count == 0 || count > MAX_FINDING_OCCURRENCES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-occurrence-count",
            });
        }
        Ok(Self {
            root,
            count,
            latest,
        })
    }

    /// Returns the authenticated Merkle-set root.
    #[must_use]
    pub const fn root(self) -> ContentId {
        self.root
    }

    /// Returns the authenticated set cardinality.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Returns the occurrence added or reaffirmed by this record version.
    #[must_use]
    pub const fn latest(self) -> ObservationId {
        self.latest
    }
}

impl Canonical for FindingOccurrenceSet {
    fn encode(&self, encoder: &mut Encoder) {
        Canonical::encode(&self.root, encoder);
        self.count.encode(encoder);
        self.latest.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ContentId::decode(decoder)?,
            u32::decode(decoder)?,
            ObservationId::decode(decoder)?,
        )
    }
}

/// Canonical cluster of one stable failure signature and its occurrences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    schema_version: u32,
    signature: FindingSignature,
    observation: ObservationId,
    reproduction: ReproductionArtifactId,
    first_seen_snapshot: CampaignSnapshotId,
    occurrences: FindingOccurrenceSet,
    minimized: Option<ReproductionArtifactId>,
    exact_pins: BTreeSet<ExactCheckpointId>,
}

impl Finding {
    /// Builds one bounded canonical finding cluster.
    ///
    /// `first_seen_snapshot` is the authenticated parent snapshot at which the
    /// first occurrence had already become observable. Naming the successor
    /// that publishes this record would create a content-address cycle.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the exact-pin set or encoded record
    /// exceeds its bound.
    pub fn new(
        signature: FindingSignature,
        observation: ObservationId,
        reproduction: ReproductionArtifactId,
        first_seen_snapshot: CampaignSnapshotId,
        occurrences: FindingOccurrenceSet,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: BTreeSet<ExactCheckpointId>,
    ) -> Result<Self, CampaignCodecError> {
        if exact_pins.len() > MAX_FINDING_EXACT_PINS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-exact-pin-count",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            signature,
            observation,
            reproduction,
            first_seen_snapshot,
            occurrences,
            minimized,
            exact_pins,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_FINDING_RECORD_BYTES,
            "finding-record-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the stable failure signature.
    #[must_use]
    pub const fn signature(&self) -> &FindingSignature {
        &self.signature
    }

    /// Returns the representative first observation.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the occurrence added or reaffirmed by this record version.
    #[must_use]
    pub const fn latest_occurrence(&self) -> ObservationId {
        self.occurrences.latest()
    }

    /// Returns the original verified reproduction artifact.
    #[must_use]
    pub const fn reproduction(&self) -> ReproductionArtifactId {
        self.reproduction
    }

    /// Returns the parent snapshot at which the finding was first observed.
    #[must_use]
    pub const fn first_seen_snapshot(&self) -> CampaignSnapshotId {
        self.first_seen_snapshot
    }

    /// Returns the authenticated Merkle-set root of clustered observations.
    #[must_use]
    pub const fn occurrences(&self) -> ContentId {
        self.occurrences.root()
    }

    /// Returns the authenticated number of clustered observations.
    #[must_use]
    pub const fn occurrence_count(&self) -> u32 {
        self.occurrences.count()
    }

    /// Returns the verified minimized reproduction, when one is retained.
    #[must_use]
    pub const fn minimized(&self) -> Option<ReproductionArtifactId> {
        self.minimized
    }

    /// Returns optional exact-checkpoint accelerators.
    #[must_use]
    pub const fn exact_pins(&self) -> &BTreeSet<ExactCheckpointId> {
        &self.exact_pins
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
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_FINDING_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-record-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the exact stored finding identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<FindingId, CampaignCodecError> {
        FindingId::from_content_id(
            ObjectEnvelope::for_record(
                CampaignRecordKind::Finding,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("observation".to_owned(), self.observation.content_id()),
            (
                "latest-occurrence".to_owned(),
                self.occurrences.latest().content_id(),
            ),
            ("reproduction".to_owned(), self.reproduction.content_id()),
            (
                "first-seen-snapshot".to_owned(),
                self.first_seen_snapshot.content_id(),
            ),
            ("occurrences".to_owned(), self.occurrences.root()),
        ];
        children.extend(self.signature.content_children());
        if let Some(minimized) = self.minimized {
            children.push(("minimized".to_owned(), minimized.content_id()));
        }
        children.extend(
            self.exact_pins
                .iter()
                .enumerate()
                .map(|(index, id)| (format!("exact-pin.{index:04x}"), id.content_id())),
        );
        children
    }
}

impl Canonical for Finding {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.signature.encode(encoder);
        self.observation.encode(encoder);
        self.reproduction.encode(encoder);
        self.first_seen_snapshot.encode(encoder);
        self.occurrences.encode(encoder);
        self.minimized.encode(encoder);
        self.exact_pins.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != RECORD_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding record schema version",
            });
        }
        Self::new(
            FindingSignature::decode(decoder)?,
            ObservationId::decode(decoder)?,
            ReproductionArtifactId::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            FindingOccurrenceSet::decode(decoder)?,
            Option::<ReproductionArtifactId>::decode(decoder)?,
            decoder.set_bounded(MAX_FINDING_EXACT_PINS, "finding-exact-pin-count")?,
        )
    }
}
