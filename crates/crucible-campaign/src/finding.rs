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
const RETENTION_SCHEMA_VERSION: u32 = 2;
const MAX_REPRODUCTION_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_REPRODUCTION_RECORD_BYTES: usize = 34 * 1024 * 1024;
const MAX_FINDING_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Maximum causal evidence objects retained by one signature.
pub const MAX_FINDING_CAUSAL_EVIDENCE: usize = 4_096;
/// Maximum observations clustered into one finding occurrence Merkle set.
pub const MAX_FINDING_OCCURRENCES: u32 = 1_000_000;
/// Guidance signal for one owner-verified property-violation occurrence.
pub const GUIDANCE_SIGNAL_FINDING_PROPERTY_VIOLATION: &str = "finding.property-violation";
/// Guidance signal for one owner-verified replay-divergence occurrence.
pub const GUIDANCE_SIGNAL_FINDING_DIVERGENCE: &str = "finding.divergence";
/// Guidance signal for one owner-verified timeout occurrence.
pub const GUIDANCE_SIGNAL_FINDING_TIMEOUT: &str = "finding.timeout";
/// Maximum optional exact checkpoints retained by one finding.
pub const MAX_FINDING_EXACT_PINS: usize = 256;
/// Maximum deterministic candidates retained by one minimization trace.
pub const MAX_FINDING_MINIMIZATION_ATTEMPTS: usize = 4_096;
/// Maximum execution-model policy bytes retained by one minimization trace.
pub const MAX_FINDING_MINIMIZATION_POLICY_BYTES: usize = 64 * 1024;

/// Role-tagged exact-checkpoint accelerators retained by one finding cluster.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FindingExactPins {
    pre_failure: BTreeSet<ExactCheckpointId>,
    measurement_boundary: BTreeSet<ExactCheckpointId>,
    post_failure: BTreeSet<ExactCheckpointId>,
    additional: BTreeSet<ExactCheckpointId>,
    all: BTreeSet<ExactCheckpointId>,
}

impl FindingExactPins {
    /// Builds a bounded role-tagged exact-checkpoint set.
    ///
    /// One checkpoint may legitimately serve more than one role. The 256-entry
    /// bound charges role associations, not only unique checkpoint identities.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::LimitExceeded`] when the aggregate number
    /// of role associations exceeds 256.
    pub fn new(
        pre_failure: BTreeSet<ExactCheckpointId>,
        measurement_boundary: BTreeSet<ExactCheckpointId>,
        post_failure: BTreeSet<ExactCheckpointId>,
        additional: BTreeSet<ExactCheckpointId>,
    ) -> Result<Self, CampaignCodecError> {
        let associations = pre_failure
            .len()
            .checked_add(measurement_boundary.len())
            .and_then(|count| count.checked_add(post_failure.len()))
            .and_then(|count| count.checked_add(additional.len()))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "finding-exact-pin-count",
            })?;
        if associations > MAX_FINDING_EXACT_PINS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-exact-pin-count",
            });
        }
        let all = pre_failure
            .iter()
            .chain(&measurement_boundary)
            .chain(&post_failure)
            .chain(&additional)
            .copied()
            .collect();
        Ok(Self {
            pre_failure,
            measurement_boundary,
            post_failure,
            additional,
            all,
        })
    }

    /// Converts a legacy untyped exact-checkpoint set into additional pins.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::LimitExceeded`] when `pins` exceeds 256.
    pub fn from_untyped(pins: BTreeSet<ExactCheckpointId>) -> Result<Self, CampaignCodecError> {
        Self::new(BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), pins)
    }

    /// Returns checkpoints immediately before causal failure evidence.
    #[must_use]
    pub const fn pre_failure(&self) -> &BTreeSet<ExactCheckpointId> {
        &self.pre_failure
    }

    /// Returns checkpoints at the last retained successful measurement boundary.
    #[must_use]
    pub const fn measurement_boundary(&self) -> &BTreeSet<ExactCheckpointId> {
        &self.measurement_boundary
    }

    /// Returns safely stopped checkpoints at or after the failure boundary.
    #[must_use]
    pub const fn post_failure(&self) -> &BTreeSet<ExactCheckpointId> {
        &self.post_failure
    }

    /// Returns explicitly retained exact checkpoints without a canonical role.
    #[must_use]
    pub const fn additional(&self) -> &BTreeSet<ExactCheckpointId> {
        &self.additional
    }

    /// Returns every unique exact-checkpoint identity across all roles.
    #[must_use]
    pub const fn all(&self) -> &BTreeSet<ExactCheckpointId> {
        &self.all
    }

    pub(crate) fn union(&self, other: &Self) -> Result<Self, CampaignCodecError> {
        Self::new(
            self.pre_failure
                .union(&other.pre_failure)
                .copied()
                .collect(),
            self.measurement_boundary
                .union(&other.measurement_boundary)
                .copied()
                .collect(),
            self.post_failure
                .union(&other.post_failure)
                .copied()
                .collect(),
            self.additional.union(&other.additional).copied().collect(),
        )
    }

    fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = Vec::new();
        children.extend(self.pre_failure.iter().enumerate().map(|(index, id)| {
            (
                format!("exact-pin.pre-failure.{index:04x}"),
                id.content_id(),
            )
        }));
        children.extend(
            self.measurement_boundary
                .iter()
                .enumerate()
                .map(|(index, id)| {
                    (
                        format!("exact-pin.measurement-boundary.{index:04x}"),
                        id.content_id(),
                    )
                }),
        );
        children.extend(self.post_failure.iter().enumerate().map(|(index, id)| {
            (
                format!("exact-pin.post-failure.{index:04x}"),
                id.content_id(),
            )
        }));
        children.extend(
            self.additional
                .iter()
                .enumerate()
                .map(|(index, id)| (format!("exact-pin.additional.{index:04x}"), id.content_id())),
        );
        children
    }
}

impl Canonical for FindingExactPins {
    fn encode(&self, encoder: &mut Encoder) {
        self.pre_failure.encode(encoder);
        self.measurement_boundary.encode(encoder);
        self.post_failure.encode(encoder);
        self.additional.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.set_bounded(MAX_FINDING_EXACT_PINS, "finding-exact-pin-count")?,
            decoder.set_bounded(MAX_FINDING_EXACT_PINS, "finding-exact-pin-count")?,
            decoder.set_bounded(MAX_FINDING_EXACT_PINS, "finding-exact-pin-count")?,
            decoder.set_bounded(MAX_FINDING_EXACT_PINS, "finding-exact-pin-count")?,
        )
    }
}

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

impl FindingKind {
    /// Returns the stable policy-guidance signal for this finding class.
    #[must_use]
    pub const fn guidance_signal(self) -> &'static str {
        match self {
            Self::PropertyViolation => GUIDANCE_SIGNAL_FINDING_PROPERTY_VIOLATION,
            Self::Divergence => GUIDANCE_SIGNAL_FINDING_DIVERGENCE,
            Self::Timeout => GUIDANCE_SIGNAL_FINDING_TIMEOUT,
        }
    }
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

/// One deterministic candidate retained by a finding minimization trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingMinimizationAttempt {
    sequence: u64,
    candidate_artifact: CampaignHash,
    candidate_schedule: CampaignHash,
    replayed_state: CampaignHash,
    observed_fingerprint: Option<CampaignHash>,
    accepted: bool,
}

impl FindingMinimizationAttempt {
    /// Builds one replayed minimization candidate result.
    #[must_use]
    pub const fn new(
        sequence: u64,
        candidate_artifact: CampaignHash,
        candidate_schedule: CampaignHash,
        replayed_state: CampaignHash,
        observed_fingerprint: Option<CampaignHash>,
        accepted: bool,
    ) -> Self {
        Self {
            sequence,
            candidate_artifact,
            candidate_schedule,
            replayed_state,
            observed_fingerprint,
            accepted,
        }
    }

    /// Returns the dense deterministic candidate sequence number.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the execution-model identity of the self-contained candidate.
    #[must_use]
    pub const fn candidate_artifact(self) -> CampaignHash {
        self.candidate_artifact
    }

    /// Returns the exact candidate schedule identity.
    #[must_use]
    pub const fn candidate_schedule(self) -> CampaignHash {
        self.candidate_schedule
    }

    /// Returns the state reached by independently replaying the candidate.
    #[must_use]
    pub const fn replayed_state(self) -> CampaignHash {
        self.replayed_state
    }

    /// Returns the failure fingerprint observed after candidate replay.
    #[must_use]
    pub const fn observed_fingerprint(self) -> Option<CampaignHash> {
        self.observed_fingerprint
    }

    /// Returns whether the candidate preserved the target signature and won.
    #[must_use]
    pub const fn accepted(self) -> bool {
        self.accepted
    }
}

impl Canonical for FindingMinimizationAttempt {
    fn encode(&self, encoder: &mut Encoder) {
        self.sequence.encode(encoder);
        self.candidate_artifact.encode(encoder);
        self.candidate_schedule.encode(encoder);
        self.replayed_state.encode(encoder);
        self.observed_fingerprint.encode(encoder);
        self.accepted.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            u64::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            Option::<CampaignHash>::decode(decoder)?,
            bool::decode(decoder)?,
        ))
    }
}

/// Verifier-produced policy, candidate history, and final replay proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingMinimizationEvidence {
    original: ReproductionArtifactId,
    policy_schema: u32,
    policy: Vec<u8>,
    attempts: Vec<FindingMinimizationAttempt>,
    final_replayed_state: CampaignHash,
}

impl FindingMinimizationEvidence {
    /// Builds one bounded deterministic minimization trace.
    ///
    /// Candidate sequence numbers must be dense from zero. At most one
    /// candidate may be accepted, and an accepted candidate must be the final
    /// attempted candidate whose replayed state is the retained final state.
    /// The minimized reproduction itself carries the verifier-checked target
    /// fingerprint and replay payload.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an empty/oversized policy, too many
    /// attempts, a non-dense sequence, or inconsistent accepted-candidate data.
    pub fn new(
        original: ReproductionArtifactId,
        policy_schema: u32,
        policy: Vec<u8>,
        attempts: Vec<FindingMinimizationAttempt>,
        final_replayed_state: CampaignHash,
    ) -> Result<Self, CampaignCodecError> {
        if original.content_id().schema_version() != RECORD_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding minimization original is not schema v1",
            });
        }
        if policy_schema == 0 || policy.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding minimization policy is empty or has no schema",
            });
        }
        if policy.len() > MAX_FINDING_MINIMIZATION_POLICY_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-minimization-policy-bytes",
            });
        }
        if attempts.len() > MAX_FINDING_MINIMIZATION_ATTEMPTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-minimization-attempt-count",
            });
        }
        let mut accepted = None;
        for (index, attempt) in attempts.iter().enumerate() {
            if attempt.sequence != index as u64 {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "finding minimization candidate sequence is not dense",
                });
            }
            if attempt.accepted
                && (accepted.replace(index).is_some()
                    || attempt.observed_fingerprint.is_none()
                    || attempt.replayed_state != final_replayed_state
                    || index + 1 != attempts.len())
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "finding minimization accepted candidate is inconsistent",
                });
            }
        }
        Ok(Self {
            original,
            policy_schema,
            policy,
            attempts,
            final_replayed_state,
        })
    }

    /// Returns the original unminimized campaign reproduction.
    #[must_use]
    pub const fn original(&self) -> ReproductionArtifactId {
        self.original
    }

    /// Returns the execution-model minimization-policy schema.
    #[must_use]
    pub const fn policy_schema(&self) -> u32 {
        self.policy_schema
    }

    /// Returns exact canonical execution-model minimization-policy bytes.
    #[must_use]
    pub fn policy(&self) -> &[u8] {
        &self.policy
    }

    /// Returns every replayed candidate in deterministic attempt order.
    #[must_use]
    pub fn attempts(&self) -> &[FindingMinimizationAttempt] {
        &self.attempts
    }

    /// Returns the state reached by replaying the retained minimized artifact.
    #[must_use]
    pub const fn final_replayed_state(&self) -> CampaignHash {
        self.final_replayed_state
    }
}

impl Canonical for FindingMinimizationEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.original.encode(encoder);
        self.policy_schema.encode(encoder);
        self.policy.encode(encoder);
        self.attempts.encode(encoder);
        self.final_replayed_state.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ReproductionArtifactId::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_FINDING_MINIMIZATION_POLICY_BYTES,
                "finding-minimization-policy-bytes",
                u8::decode,
            )?,
            decoder.sequence_bounded(
                MAX_FINDING_MINIMIZATION_ATTEMPTS,
                "finding-minimization-attempt-count",
                FindingMinimizationAttempt::decode,
            )?,
            CampaignHash::decode(decoder)?,
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
    minimization: Option<FindingMinimizationEvidence>,
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
        Self::new_versioned(
            RECORD_SCHEMA_VERSION,
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
            payload_schema,
            payload,
            None,
        )
    }

    /// Builds a verifier-backed minimized reproduction with its exact trace.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid payload, an inconsistent
    /// minimization target, or an encoded record above 34 MiB.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new_minimized(
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        configuration_artifact: ConfigurationArtifactId,
        finding_fingerprint: CampaignHash,
        payload_schema: u32,
        payload: Vec<u8>,
        minimization: FindingMinimizationEvidence,
    ) -> Result<Self, CampaignCodecError> {
        if minimization.attempts().iter().any(|attempt| {
            attempt.accepted() && attempt.observed_fingerprint() != Some(finding_fingerprint)
        }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding minimization accepted a different fingerprint",
            });
        }
        Self::new_versioned(
            RETENTION_SCHEMA_VERSION,
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
            payload_schema,
            payload,
            Some(minimization),
        )
    }

    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    fn new_versioned(
        schema_version: u32,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        configuration_artifact: ConfigurationArtifactId,
        finding_fingerprint: CampaignHash,
        payload_schema: u32,
        payload: Vec<u8>,
        minimization: Option<FindingMinimizationEvidence>,
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
        if matches!(schema_version, RECORD_SCHEMA_VERSION) != minimization.is_none() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding reproduction schema disagrees with minimization evidence",
            });
        }
        let value = Self {
            schema_version,
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
            payload_schema,
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
        self.payload_schema
    }

    /// Returns the self-contained canonical execution-model bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
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
    /// oversized bytes.
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
        self.payload_schema.encode(encoder);
        self.payload.encode(encoder);
        if self.schema_version == RETENTION_SCHEMA_VERSION {
            self.minimization.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(
            schema_version,
            RECORD_SCHEMA_VERSION | RETENTION_SCHEMA_VERSION
        ) {
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
        let minimization = if schema_version == RETENTION_SCHEMA_VERSION {
            Option::<FindingMinimizationEvidence>::decode(decoder)?
        } else {
            None
        };
        Self::new_versioned(
            schema_version,
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
            payload_schema,
            payload,
            minimization,
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
    exact_pins: FindingExactPins,
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
        Self::new_versioned(
            RECORD_SCHEMA_VERSION,
            signature,
            observation,
            reproduction,
            first_seen_snapshot,
            occurrences,
            minimized,
            FindingExactPins::from_untyped(exact_pins)?,
        )
    }

    /// Builds a schema-v2 finding with role-tagged exact-checkpoint retention.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the encoded record exceeds 4 MiB.
    // crucible-lint: allow rust-allow -- the stable constructor retains explicit schema arguments at this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_retention(
        signature: FindingSignature,
        observation: ObservationId,
        reproduction: ReproductionArtifactId,
        first_seen_snapshot: CampaignSnapshotId,
        occurrences: FindingOccurrenceSet,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: FindingExactPins,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_versioned(
            RETENTION_SCHEMA_VERSION,
            signature,
            observation,
            reproduction,
            first_seen_snapshot,
            occurrences,
            minimized,
            exact_pins,
        )
    }

    // crucible-lint: allow rust-allow -- the versioned constructor keeps every canonical field explicit.
    #[allow(clippy::too_many_arguments)]
    fn new_versioned(
        schema_version: u32,
        signature: FindingSignature,
        observation: ObservationId,
        reproduction: ReproductionArtifactId,
        first_seen_snapshot: CampaignSnapshotId,
        occurrences: FindingOccurrenceSet,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: FindingExactPins,
    ) -> Result<Self, CampaignCodecError> {
        let reproduction_version = reproduction.content_id().schema_version();
        let minimized_version = minimized.map(|id| id.content_id().schema_version());
        let reproduction_versions_match = match schema_version {
            RECORD_SCHEMA_VERSION => {
                reproduction_version == RECORD_SCHEMA_VERSION
                    && minimized_version.is_none_or(|version| version == RECORD_SCHEMA_VERSION)
            }
            RETENTION_SCHEMA_VERSION => {
                reproduction_version == RECORD_SCHEMA_VERSION
                    && minimized_version.is_none_or(|version| version == RETENTION_SCHEMA_VERSION)
            }
            _ => false,
        };
        if !reproduction_versions_match {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding schema disagrees with reproduction versions",
            });
        }
        let value = Self {
            schema_version,
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

    /// Returns the canonical record-body and envelope schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
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
        self.exact_pins.all()
    }

    /// Returns the role-tagged exact-checkpoint retention contract.
    #[must_use]
    pub const fn exact_pin_retention(&self) -> &FindingExactPins {
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
            ObjectEnvelope::for_record_versioned(
                CampaignRecordKind::Finding,
                self.schema_version,
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
        if self.schema_version == RECORD_SCHEMA_VERSION {
            children.extend(
                self.exact_pins
                    .all()
                    .iter()
                    .enumerate()
                    .map(|(index, id)| (format!("exact-pin.{index:04x}"), id.content_id())),
            );
        } else {
            children.extend(self.exact_pins.content_children());
        }
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
        if self.schema_version == RECORD_SCHEMA_VERSION {
            self.exact_pins.all().encode(encoder);
        } else {
            self.exact_pins.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(
            schema_version,
            RECORD_SCHEMA_VERSION | RETENTION_SCHEMA_VERSION
        ) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding record schema version",
            });
        }
        let signature = FindingSignature::decode(decoder)?;
        let observation = ObservationId::decode(decoder)?;
        let reproduction = ReproductionArtifactId::decode(decoder)?;
        let first_seen_snapshot = CampaignSnapshotId::decode(decoder)?;
        let occurrences = FindingOccurrenceSet::decode(decoder)?;
        let minimized = Option::<ReproductionArtifactId>::decode(decoder)?;
        let exact_pins = if schema_version == RECORD_SCHEMA_VERSION {
            FindingExactPins::from_untyped(
                decoder.set_bounded(MAX_FINDING_EXACT_PINS, "finding-exact-pin-count")?,
            )?
        } else {
            FindingExactPins::decode(decoder)?
        };
        Self::new_versioned(
            schema_version,
            signature,
            observation,
            reproduction,
            first_seen_snapshot,
            occurrences,
            minimized,
            exact_pins,
        )
    }
}
