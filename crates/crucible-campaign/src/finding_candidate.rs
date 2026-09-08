//! Durable executor handoff for one verified, minimized finding candidate.
//!
//! The bundle points from an executor-produced observation to its original and
//! minimized reproduction artifacts. The observation never points back to this
//! bundle, so the immutable object graph remains acyclic. A completion message
//! can name the bundle after every referenced object is durable; a coordinator
//! can then recover and validate the same handoff after restart.
//!
//! The canonical version-1 record body has this field order:
//!
//! ```text
//! u32 schema-version = 1
//! ObservationId observation
//! FindingSignature signature
//! ReproductionArtifactId original-reproduction
//! ReproductionArtifactId minimized-reproduction
//! FindingSignatureMinimizationEvidence signature-minimization
//! FindingExactPins exact-pins
//! ```
//!
//! `FindingSignatureMinimizationEvidence` stores the stable target-signature
//! hash followed by the bounded minimization and verification sequences. Each
//! sequence element is an optional complete `FindingSignature` observed by the
//! replay oracle.

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    CampaignCodecError, CampaignHash, CampaignRecordKind, FindingCandidateBundleId,
    FindingExactPins, FindingKind, FindingMinimizationEvidence, FindingSignature, FindingTarget,
    MAX_FINDING_MINIMIZATION_ATTEMPTS, ObjectEnvelope, ObservationId, ReproductionArtifactId,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const REPLAY_SIGNATURE_SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SIGNATURE_REPLAYS_PER_PASS: usize = MAX_FINDING_MINIMIZATION_ATTEMPTS + 1;

/// Stable category of the modeled target reported by a finding replay.
///
/// Exact target object identities are deliberately absent because minimizing a
/// reproduction can replace its configuration or choice-opportunity artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingReplayTargetKind {
    /// The replay associates the failure with a modeled configuration.
    Configuration,
    /// The replay associates the failure with a runtime choice opportunity.
    ChoiceOpportunity,
}

impl Canonical for FindingReplayTargetKind {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Configuration => 0,
            Self::ChoiceOpportunity => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Configuration),
            1 => Ok(Self::ChoiceOpportunity),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "finding-replay-target-kind",
                tag,
            }),
        }
    }
}

/// Failure identity independently derived from one execution-model replay.
///
/// This projection retains every stable semantic field that must match during
/// minimization. It omits exact target and causal-evidence object identities,
/// which legitimately change when a candidate shortens the reproduction. The
/// execution-model adapter derives it from the candidate's observed
/// [`FindingSignature`], rather than from the requested target signature. The
/// execution-model fingerprint identifies the reproduced failure payload;
/// failure class, property identity, and target category prevent that digest
/// from crossing semantic failure domains. Complete observed signatures remain
/// in [`FindingSignatureMinimizationEvidence`] as immutable provenance.
///
/// Schema v1 uses the
/// `crucible.campaign.finding-replay-signature.v1` hash domain. It is nested in
/// the finding-candidate-bundle schema and does not alter the canonical bytes or
/// cluster keys of the existing [`FindingSignature`] type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingReplaySignature {
    schema_version: u32,
    kind: FindingKind,
    fingerprint: CampaignHash,
    property: Option<String>,
    failure_class: String,
    target_kind: Option<FindingReplayTargetKind>,
}

impl FindingReplaySignature {
    /// Projects one independently observed finding into stable replay identity.
    #[must_use]
    pub fn from_observed(signature: &FindingSignature) -> Self {
        Self {
            schema_version: REPLAY_SIGNATURE_SCHEMA_VERSION,
            kind: signature.kind(),
            fingerprint: signature.fingerprint(),
            property: signature.property().map(ToOwned::to_owned),
            failure_class: signature.failure_class().to_owned(),
            target_kind: signature.target().map(|target| match target {
                FindingTarget::Configuration(_) => FindingReplayTargetKind::Configuration,
                FindingTarget::ChoiceOpportunity(_) => FindingReplayTargetKind::ChoiceOpportunity,
            }),
        }
    }

    /// Returns the canonical replay-signature schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the closed failure kind observed by the replay.
    #[must_use]
    pub const fn kind(&self) -> FindingKind {
        self.kind
    }

    /// Returns the execution-model fingerprint observed by the replay.
    #[must_use]
    pub const fn fingerprint(&self) -> CampaignHash {
        self.fingerprint
    }

    /// Returns the scenario property identity observed by the replay.
    #[must_use]
    pub fn property(&self) -> Option<&str> {
        self.property.as_deref()
    }

    /// Returns the normalized failure class observed by the replay.
    #[must_use]
    pub fn failure_class(&self) -> &str {
        &self.failure_class
    }

    /// Returns the stable target category observed by the replay.
    #[must_use]
    pub const fn target_kind(&self) -> Option<FindingReplayTargetKind> {
        self.target_kind
    }

    /// Returns the deterministic key compared across minimization replays.
    #[must_use]
    pub fn cluster_key(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign.finding-replay-signature.v1",
            &codec::encode(self),
        )
    }

    fn new(
        kind: FindingKind,
        fingerprint: CampaignHash,
        property: Option<String>,
        failure_class: String,
        target_kind: Option<FindingReplayTargetKind>,
    ) -> Result<Self, CampaignCodecError> {
        if let Some(property) = &property {
            validate_identifier(property, "finding replay property identity is invalid")?;
        }
        validate_identifier(&failure_class, "finding replay failure class is invalid")?;
        if matches!(kind, FindingKind::PropertyViolation) != property.is_some() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding replay property identity disagrees with failure kind",
            });
        }
        Ok(Self {
            schema_version: REPLAY_SIGNATURE_SCHEMA_VERSION,
            kind,
            fingerprint,
            property,
            failure_class,
            target_kind,
        })
    }
}

impl Canonical for FindingReplaySignature {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.kind.encode(encoder);
        self.fingerprint.encode(encoder);
        self.property.encode(encoder);
        self.failure_class.encode(encoder);
        self.target_kind.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != REPLAY_SIGNATURE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding replay signature schema version",
            });
        }
        Self::new(
            FindingKind::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            decoder.option(|decoder| {
                decoder.string_bounded(
                    MAX_IDENTIFIER_BYTES,
                    "finding-replay-property-identity-bytes",
                )
            })?,
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "finding-replay-failure-class-bytes")?,
            Option::<FindingReplayTargetKind>::decode(decoder)?,
        )
    }
}

/// Stable replay-signature results retained for both minimization passes.
///
/// Each entry retains the complete [`FindingSignature`] independently observed
/// by the replay oracle, or `None` when the candidate did not produce a finding.
/// Index zero is the original reproduction and subsequent entries map
/// one-to-one to [`FindingMinimizationEvidence::attempts`]. Repository loading
/// recomputes [`FindingReplaySignature`] from these complete observed values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingSignatureMinimizationEvidence {
    target_signature: CampaignHash,
    minimization_pass: Vec<Option<FindingSignature>>,
    verification_pass: Vec<Option<FindingSignature>>,
}

impl FindingSignatureMinimizationEvidence {
    /// Builds and validates two stable replay-signature passes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] unless both passes are identical, begin
    /// with the target signature, map exactly to the fingerprint minimization
    /// attempts, and select only a candidate whose stable replay signature
    /// equals the target.
    pub fn new(
        signature: &FindingSignature,
        minimization: &FindingMinimizationEvidence,
        minimization_pass: Vec<Option<FindingSignature>>,
        verification_pass: Vec<Option<FindingSignature>>,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self::new_structural(
            FindingReplaySignature::from_observed(signature).cluster_key(),
            minimization_pass,
            verification_pass,
        )?;
        value.validate_against(signature, minimization)?;
        Ok(value)
    }

    /// Returns the stable target replay-signature hash.
    #[must_use]
    pub const fn target_signature(&self) -> CampaignHash {
        self.target_signature
    }

    /// Returns the original and candidate signature results from minimization.
    #[must_use]
    pub fn minimization_pass(&self) -> &[Option<FindingSignature>] {
        &self.minimization_pass
    }

    /// Returns the independently repeated signature results from import verification.
    #[must_use]
    pub fn verification_pass(&self) -> &[Option<FindingSignature>] {
        &self.verification_pass
    }

    pub(crate) fn validate_against(
        &self,
        signature: &FindingSignature,
        minimization: &FindingMinimizationEvidence,
    ) -> Result<(), CampaignCodecError> {
        self.validate_signature_basis(signature)?;
        let target = FindingReplaySignature::from_observed(signature).cluster_key();
        let expected_len = minimization.attempts().len().checked_add(1).ok_or(
            CampaignCodecError::LimitExceeded {
                limit: "finding-signature-minimization-pass-count",
            },
        )?;
        if self.minimization_pass.len() != expected_len
            || self.verification_pass.len() != expected_len
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding signature minimization replay basis is inconsistent",
            });
        }

        for (attempt, observed_signature) in minimization
            .attempts()
            .iter()
            .zip(self.minimization_pass.iter().skip(1))
        {
            let preserves_signature = observed_signature
                .as_ref()
                .map(FindingReplaySignature::from_observed)
                .map(|signature| signature.cluster_key())
                == Some(target);
            let filtered_fingerprint = preserves_signature.then_some(signature.fingerprint());
            if attempt.accepted() && !preserves_signature
                || attempt.observed_fingerprint() != filtered_fingerprint
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "finding signature minimization attempt disagrees with replay evidence",
                });
            }
        }
        Ok(())
    }

    fn validate_signature_basis(
        &self,
        signature: &FindingSignature,
    ) -> Result<(), CampaignCodecError> {
        let target = FindingReplaySignature::from_observed(signature).cluster_key();
        if self.target_signature != target
            || self.minimization_pass.first() != Some(&Some(signature.clone()))
            || self.verification_pass.first() != Some(&Some(signature.clone()))
            || self.minimization_pass != self.verification_pass
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding signature minimization replay basis is inconsistent",
            });
        }
        Ok(())
    }

    fn new_structural(
        target_signature: CampaignHash,
        minimization_pass: Vec<Option<FindingSignature>>,
        verification_pass: Vec<Option<FindingSignature>>,
    ) -> Result<Self, CampaignCodecError> {
        if minimization_pass.is_empty()
            || minimization_pass.len() > MAX_SIGNATURE_REPLAYS_PER_PASS
            || verification_pass.is_empty()
            || verification_pass.len() > MAX_SIGNATURE_REPLAYS_PER_PASS
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-signature-minimization-pass-count",
            });
        }
        Ok(Self {
            target_signature,
            minimization_pass,
            verification_pass,
        })
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = Vec::new();
        for (pass_name, pass) in [
            ("minimization", &self.minimization_pass),
            ("verification", &self.verification_pass),
        ] {
            for (index, signature) in pass.iter().enumerate() {
                if let Some(signature) = signature {
                    children.extend(signature_children(
                        &format!("signature-minimization.{pass_name}.{index:04x}"),
                        signature,
                    ));
                }
            }
        }
        children
    }
}

impl Canonical for FindingSignatureMinimizationEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.target_signature.encode(encoder);
        self.minimization_pass.encode(encoder);
        self.verification_pass.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new_structural(
            CampaignHash::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_SIGNATURE_REPLAYS_PER_PASS,
                "finding-signature-minimization-pass-count",
                Option::<FindingSignature>::decode,
            )?,
            decoder.sequence_bounded(
                MAX_SIGNATURE_REPLAYS_PER_PASS,
                "finding-signature-minimization-pass-count",
                Option::<FindingSignature>::decode,
            )?,
        )
    }
}

/// Immutable worker-produced basis for one minimized finding publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingCandidateBundle {
    schema_version: u32,
    observation: ObservationId,
    signature: FindingSignature,
    reproduction: ReproductionArtifactId,
    minimized: ReproductionArtifactId,
    signature_minimization: FindingSignatureMinimizationEvidence,
    exact_pins: FindingExactPins,
}

impl FindingCandidateBundle {
    /// Builds one bounded, acyclic finding candidate handoff.
    ///
    /// The original reproduction must use schema v1 and the minimized
    /// reproduction must use schema v2, which retains the original identity and
    /// verifier-produced minimization trace.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when reproduction versions are invalid or
    /// the encoded bundle exceeds 4 MiB.
    pub fn new(
        observation: ObservationId,
        signature: FindingSignature,
        reproduction: ReproductionArtifactId,
        minimized: ReproductionArtifactId,
        signature_minimization: FindingSignatureMinimizationEvidence,
        exact_pins: FindingExactPins,
    ) -> Result<Self, CampaignCodecError> {
        if reproduction.content_id().schema_version() != 1
            || minimized.content_id().schema_version() != 2
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding candidate reproduction versions are invalid",
            });
        }
        signature_minimization.validate_signature_basis(&signature)?;

        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            observation,
            signature,
            reproduction,
            minimized,
            signature_minimization,
            exact_pins,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_RECORD_BYTES,
            "finding-candidate-bundle-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the observation that produced this finding candidate.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the complete stable finding signature.
    #[must_use]
    pub const fn signature(&self) -> &FindingSignature {
        &self.signature
    }

    /// Returns the original verified reproduction.
    #[must_use]
    pub const fn reproduction(&self) -> ReproductionArtifactId {
        self.reproduction
    }

    /// Returns the verified minimized reproduction and its retained trace.
    #[must_use]
    pub const fn minimized(&self) -> ReproductionArtifactId {
        self.minimized
    }

    /// Returns stable replay-signature results from both minimization passes.
    #[must_use]
    pub const fn signature_minimization(&self) -> &FindingSignatureMinimizationEvidence {
        &self.signature_minimization
    }

    /// Returns exact checkpoints retained as optional accelerators.
    #[must_use]
    pub const fn exact_pins(&self) -> &FindingExactPins {
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
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-candidate-bundle-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the exact stored bundle identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<FindingCandidateBundleId, CampaignCodecError> {
        FindingCandidateBundleId::from_content_id(
            ObjectEnvelope::for_record(
                CampaignRecordKind::FindingCandidateBundle,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("observation".to_owned(), self.observation.content_id()),
            ("reproduction".to_owned(), self.reproduction.content_id()),
            ("minimized".to_owned(), self.minimized.content_id()),
        ];
        children.extend(signature_children("signature", &self.signature));
        children.extend(self.signature_minimization.content_children());
        children.extend(exact_pin_children(&self.exact_pins));
        children
    }
}

impl Canonical for FindingCandidateBundle {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.observation.encode(encoder);
        self.signature.encode(encoder);
        self.reproduction.encode(encoder);
        self.minimized.encode(encoder);
        self.signature_minimization.encode(encoder);
        self.exact_pins.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != RECORD_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding candidate bundle schema version",
            });
        }
        Self::new(
            ObservationId::decode(decoder)?,
            FindingSignature::decode(decoder)?,
            ReproductionArtifactId::decode(decoder)?,
            ReproductionArtifactId::decode(decoder)?,
            FindingSignatureMinimizationEvidence::decode(decoder)?,
            FindingExactPins::decode(decoder)?,
        )
    }
}

fn signature_children(prefix: &str, signature: &FindingSignature) -> Vec<(String, ContentId)> {
    let mut children = signature
        .causal_evidence()
        .iter()
        .enumerate()
        .map(|(index, id)| (format!("{prefix}.evidence.{index:04x}"), *id))
        .collect::<Vec<_>>();
    if let Some(target) = signature.target() {
        let id = match target {
            FindingTarget::Configuration(id) => id.content_id(),
            FindingTarget::ChoiceOpportunity(id) => id.content_id(),
        };
        children.push((format!("{prefix}.target"), id));
    }
    children
}

fn exact_pin_children(pins: &FindingExactPins) -> Vec<(String, ContentId)> {
    let mut children = Vec::new();
    children.extend(pins.pre_failure().iter().enumerate().map(|(index, id)| {
        (
            format!("exact-pin.pre-failure.{index:04x}"),
            id.content_id(),
        )
    }));
    children.extend(
        pins.measurement_boundary()
            .iter()
            .enumerate()
            .map(|(index, id)| {
                (
                    format!("exact-pin.measurement-boundary.{index:04x}"),
                    id.content_id(),
                )
            }),
    );
    children.extend(pins.post_failure().iter().enumerate().map(|(index, id)| {
        (
            format!("exact-pin.post-failure.{index:04x}"),
            id.content_id(),
        )
    }));
    children.extend(
        pins.additional()
            .iter()
            .enumerate()
            .map(|(index, id)| (format!("exact-pin.additional.{index:04x}"), id.content_id())),
    );
    children
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{FindingKind, FindingMinimizationAttempt};
    use crucible_cas::content_store::ObjectKind;

    #[test]
    fn bundle_round_trip_preserves_an_acyclic_child_graph() {
        let observation = ObservationId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"finding-candidate-observation",
        ))
        .expect("observation ID");
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            1,
            b"finding-candidate-original",
        ))
        .expect("original reproduction ID");
        let minimized = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            2,
            b"finding-candidate-minimized",
        ))
        .expect("minimized reproduction ID");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::derive("test", b"finding-candidate-signature"),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("finding signature");
        let minimization = FindingMinimizationEvidence::new(
            original,
            1,
            b"test-policy".to_vec(),
            Vec::new(),
            CampaignHash::derive("test", b"finding-candidate-final-state"),
        )
        .expect("minimization evidence");
        let signature_minimization = FindingSignatureMinimizationEvidence::new(
            &signature,
            &minimization,
            vec![Some(signature.clone())],
            vec![Some(signature.clone())],
        )
        .expect("signature minimization evidence");
        let bundle = FindingCandidateBundle::new(
            observation,
            signature,
            original,
            minimized,
            signature_minimization,
            FindingExactPins::default(),
        )
        .expect("finding candidate bundle");

        let decoded = FindingCandidateBundle::from_canonical_bytes(&bundle.canonical_bytes())
            .expect("decode finding candidate bundle");
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.content_children().len(), 3);
        assert!(
            decoded
                .content_children()
                .iter()
                .all(|(_, child)| *child != decoded.id().expect("bundle ID").content_id())
        );
    }

    #[test]
    fn signature_evidence_rejects_equal_fingerprint_with_a_different_failure_class() {
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            1,
            b"signature-evidence-original",
        ))
        .expect("original reproduction ID");
        let fingerprint = CampaignHash::derive("test", b"shared-fingerprint");
        let target = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("target signature");
        let different_class = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            String::from("qemu.different-failure-class"),
            None,
            BTreeSet::new(),
        )
        .expect("different signature");
        let final_state = CampaignHash::derive("test", b"signature-evidence-final-state");
        let rejected_minimization = FindingMinimizationEvidence::new(
            original,
            1,
            b"test-policy".to_vec(),
            vec![FindingMinimizationAttempt::new(
                0,
                CampaignHash::derive("test", b"candidate-artifact"),
                CampaignHash::derive("test", b"candidate-schedule"),
                final_state,
                None,
                false,
            )],
            final_state,
        )
        .expect("minimization evidence");

        FindingSignatureMinimizationEvidence::new(
            &target,
            &rejected_minimization,
            vec![Some(target.clone()), Some(different_class.clone())],
            vec![Some(target.clone()), Some(different_class.clone())],
        )
        .expect("a different complete signature remains rejected");
        let selected_minimization = FindingMinimizationEvidence::new(
            original,
            1,
            b"test-policy".to_vec(),
            vec![FindingMinimizationAttempt::new(
                0,
                CampaignHash::derive("test", b"candidate-artifact"),
                CampaignHash::derive("test", b"candidate-schedule"),
                final_state,
                Some(fingerprint),
                true,
            )],
            final_state,
        )
        .expect("selected minimization evidence");
        assert!(
            FindingSignatureMinimizationEvidence::new(
                &target,
                &selected_minimization,
                vec![Some(target.clone()), Some(different_class.clone())],
                vec![Some(target.clone()), Some(different_class.clone())],
            )
            .is_err()
        );
    }

    #[test]
    fn signature_evidence_rejects_a_mismatched_verification_pass() {
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            1,
            b"verification-mismatch-original",
        ))
        .expect("original reproduction ID");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::derive("test", b"verification-mismatch-fingerprint"),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("finding signature");
        let minimization = FindingMinimizationEvidence::new(
            original,
            1,
            b"test-policy".to_vec(),
            Vec::new(),
            CampaignHash::derive("test", b"verification-mismatch-final-state"),
        )
        .expect("minimization evidence");

        assert!(
            FindingSignatureMinimizationEvidence::new(
                &signature,
                &minimization,
                vec![Some(signature.clone())],
                vec![None],
            )
            .is_err()
        );
    }

    #[test]
    fn signature_projection_accepts_constructed_shrink_evidence_with_new_artifact_identities() {
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            1,
            b"shrinking-winner-original",
        ))
        .expect("original reproduction ID");
        let original_configuration = crate::ConfigurationArtifactId::from_content_id(
            ContentId::for_bytes(ObjectKind::Configuration, 1, b"original-configuration"),
        )
        .expect("original configuration ID");
        let minimized_configuration = crate::ConfigurationArtifactId::from_content_id(
            ContentId::for_bytes(ObjectKind::Configuration, 1, b"minimized-configuration"),
        )
        .expect("minimized configuration ID");
        let fingerprint = CampaignHash::derive("test", b"shrinking-winner-fingerprint");
        let original_signature = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            String::from("qemu.replay-divergence"),
            Some(FindingTarget::Configuration(original_configuration)),
            BTreeSet::from([ContentId::for_bytes(
                ObjectKind::Observation,
                1,
                b"original-causal-evidence",
            )]),
        )
        .expect("original signature");
        let minimized_signature = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            String::from("qemu.replay-divergence"),
            Some(FindingTarget::Configuration(minimized_configuration)),
            BTreeSet::from([ContentId::for_bytes(
                ObjectKind::Observation,
                1,
                b"minimized-causal-evidence",
            )]),
        )
        .expect("minimized signature");
        assert_ne!(
            original_signature.cluster_key(),
            minimized_signature.cluster_key()
        );

        let final_state = CampaignHash::derive("test", b"shrinking-winner-final-state");
        let minimization = FindingMinimizationEvidence::new(
            original,
            1,
            b"test-policy".to_vec(),
            vec![FindingMinimizationAttempt::new(
                0,
                CampaignHash::derive("test", b"shorter-candidate-artifact"),
                CampaignHash::derive("test", b"shorter-candidate-schedule"),
                final_state,
                Some(fingerprint),
                true,
            )],
            final_state,
        )
        .expect("minimization evidence");
        let original_replay = FindingReplaySignature::from_observed(&original_signature);
        let minimized_replay = FindingReplaySignature::from_observed(&minimized_signature);
        assert_eq!(original_replay, minimized_replay);

        FindingSignatureMinimizationEvidence::new(
            &original_signature,
            &minimization,
            vec![
                Some(original_signature.clone()),
                Some(minimized_signature.clone()),
            ],
            vec![
                Some(original_signature.clone()),
                Some(minimized_signature.clone()),
            ],
        )
        .expect("shrinking candidate preserves stable replay signature");
    }

    #[test]
    fn replay_signature_separates_property_and_target_categories() {
        let fingerprint = CampaignHash::derive("test", b"semantic-domain-fingerprint");
        let configuration = crate::ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            b"semantic-domain-config",
        ))
        .expect("configuration ID");
        let opportunity = crate::ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"semantic-domain-opportunity",
        ))
        .expect("choice opportunity ID");
        let signature = |property: &str, target| {
            FindingSignature::new(
                FindingKind::PropertyViolation,
                fingerprint,
                Some(property.to_owned()),
                String::from("guest.assertion-failed"),
                Some(target),
                BTreeSet::new(),
            )
            .expect("property-violation signature")
        };
        let configuration_target = signature(
            "scenario.property-a",
            FindingTarget::Configuration(configuration),
        );
        let different_property = signature(
            "scenario.property-b",
            FindingTarget::Configuration(configuration),
        );
        let choice_target = signature(
            "scenario.property-a",
            FindingTarget::ChoiceOpportunity(opportunity),
        );

        assert_ne!(
            FindingReplaySignature::from_observed(&configuration_target),
            FindingReplaySignature::from_observed(&different_property)
        );
        assert_ne!(
            FindingReplaySignature::from_observed(&configuration_target),
            FindingReplaySignature::from_observed(&choice_target)
        );
    }
}
