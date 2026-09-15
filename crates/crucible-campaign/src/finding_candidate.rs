//! Durable executor handoff for one verified, minimized finding candidate.
//!
//! The bundle points from an executor-produced observation to its original and
//! minimized reproduction artifacts. The observation never points back to this
//! bundle, so the immutable object graph remains acyclic. A completion message
//! can name the bundle after every referenced object is durable; a coordinator
//! can then recover and validate the same handoff after restart.
//!
//! `FindingSignatureMinimizationEvidence` stores the stable target-signature
//! hash followed by the bounded minimization and verification sequences. Each
//! sequence element is an optional complete `FindingSignature` observed by the
//! replay oracle. The current bundle also retains the policy basis for automatic
//! exact retention and the authenticated checkpoint inventory and executor
//! attestation needed to verify a complete retention decision. The decoder
//! accepts only the current version-5 bundle schema; older schemas fail closed.

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    AttemptAdmissionId, CampaignCodecError, CampaignHash, CampaignPolicyId, CampaignRecordKind,
    CampaignSnapshotId, ExactCheckpointId, FindingCandidateBundleId, FindingExactPins, FindingKind,
    FindingMinimizationEvidence, FindingSignature, FindingTarget, FindingTriageReplayEvidenceId,
    MAX_FINDING_MINIMIZATION_ATTEMPTS, ObjectEnvelope, ObservationId, ReproductionArtifactId,
};

pub(crate) const FINDING_CANDIDATE_SCHEMA_VERSION: u32 = 5;
const REPLAY_SIGNATURE_SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SIGNATURE_REPLAYS_PER_PASS: usize = MAX_FINDING_MINIMIZATION_ATTEMPTS + 1;

mod exact_retention;
mod replay_signature;

pub use exact_retention::*;
pub use replay_signature::*;

/// Four native replay records required to reconstruct successful triage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingTriageEvidenceSet {
    minimization_original: FindingTriageReplayEvidenceId,
    minimization_selected: FindingTriageReplayEvidenceId,
    verification_original: FindingTriageReplayEvidenceId,
    verification_selected: FindingTriageReplayEvidenceId,
}

impl FindingTriageEvidenceSet {
    /// Builds the complete two-pass replay evidence set.
    #[must_use]
    pub const fn new(
        minimization_original: FindingTriageReplayEvidenceId,
        minimization_selected: FindingTriageReplayEvidenceId,
        verification_original: FindingTriageReplayEvidenceId,
        verification_selected: FindingTriageReplayEvidenceId,
    ) -> Self {
        Self {
            minimization_original,
            minimization_selected,
            verification_original,
            verification_selected,
        }
    }

    /// Returns the minimization pass replay of the original reproduction.
    #[must_use]
    pub const fn minimization_original(self) -> FindingTriageReplayEvidenceId {
        self.minimization_original
    }

    /// Returns the minimization pass replay of the selected reproduction.
    #[must_use]
    pub const fn minimization_selected(self) -> FindingTriageReplayEvidenceId {
        self.minimization_selected
    }

    /// Returns the verification pass replay of the original reproduction.
    #[must_use]
    pub const fn verification_original(self) -> FindingTriageReplayEvidenceId {
        self.verification_original
    }

    /// Returns the verification pass replay of the selected reproduction.
    #[must_use]
    pub const fn verification_selected(self) -> FindingTriageReplayEvidenceId {
        self.verification_selected
    }

    fn content_children(self) -> Vec<(String, ContentId)> {
        vec![
            (
                "triage-evidence.minimization.original".to_owned(),
                self.minimization_original.content_id(),
            ),
            (
                "triage-evidence.minimization.selected".to_owned(),
                self.minimization_selected.content_id(),
            ),
            (
                "triage-evidence.verification.original".to_owned(),
                self.verification_original.content_id(),
            ),
            (
                "triage-evidence.verification.selected".to_owned(),
                self.verification_selected.content_id(),
            ),
        ]
    }
}

impl Canonical for FindingTriageEvidenceSet {
    fn encode(&self, encoder: &mut Encoder) {
        self.minimization_original.encode(encoder);
        self.minimization_selected.encode(encoder);
        self.verification_original.encode(encoder);
        self.verification_selected.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            FindingTriageReplayEvidenceId::decode(decoder)?,
            FindingTriageReplayEvidenceId::decode(decoder)?,
            FindingTriageReplayEvidenceId::decode(decoder)?,
            FindingTriageReplayEvidenceId::decode(decoder)?,
        ))
    }
}

/// Immutable worker-produced basis for one minimized finding publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingCandidateCore {
    observation: ObservationId,
    signature: FindingSignature,
    reproduction: ReproductionArtifactId,
    minimized: ReproductionArtifactId,
    signature_minimization: FindingSignatureMinimizationEvidence,
    exact_pins: FindingExactPins,
}

impl FindingCandidateCore {
    /// Collects the immutable identities and evidence shared by every candidate form.
    #[must_use]
    pub const fn new(
        observation: ObservationId,
        signature: FindingSignature,
        reproduction: ReproductionArtifactId,
        minimized: ReproductionArtifactId,
        signature_minimization: FindingSignatureMinimizationEvidence,
        exact_pins: FindingExactPins,
    ) -> Self {
        Self {
            observation,
            signature,
            reproduction,
            minimized,
            signature_minimization,
            exact_pins,
        }
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
    triage_evidence: Option<FindingTriageEvidenceSet>,
    exact_retention: FindingExactRetention,
    exact_retention_evidence: Option<FindingExactRetentionEvidence>,
}

impl FindingCandidateBundle {
    /// Builds a candidate with policy-bound exact retention.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the evidence shape, retention
    /// disposition, or another candidate invariant is invalid.
    pub fn new_with_exact_retention(
        core: FindingCandidateCore,
        triage_evidence: Option<FindingTriageEvidenceSet>,
        exact_retention: FindingExactRetention,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_current(core, triage_evidence, exact_retention, None)
    }

    /// Builds a version-five candidate with independently verifiable selection evidence.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the complete retention disposition,
    /// candidate count, selected pins, or evidence shape disagree.
    pub fn new_with_authenticated_exact_retention(
        core: FindingCandidateCore,
        triage_evidence: Option<FindingTriageEvidenceSet>,
        exact_retention: FindingExactRetention,
        evidence: FindingExactRetentionEvidence,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_current(core, triage_evidence, exact_retention, Some(evidence))
    }

    pub(crate) fn new_current(
        core: FindingCandidateCore,
        triage_evidence: Option<FindingTriageEvidenceSet>,
        exact_retention: FindingExactRetention,
        exact_retention_evidence: Option<FindingExactRetentionEvidence>,
    ) -> Result<Self, CampaignCodecError> {
        let FindingCandidateCore {
            observation,
            signature,
            reproduction,
            minimized,
            signature_minimization,
            exact_pins,
        } = core;
        if reproduction.content_id().schema_version() != 2
            || minimized.content_id().schema_version() != 2
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding candidate reproduction versions are invalid",
            });
        }
        signature_minimization.validate_signature_basis(&signature)?;
        if exact_retention.disposition() == FindingExactRetentionDisposition::Complete
            && exact_retention_evidence.is_none()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "complete finding exact retention requires authenticated evidence",
            });
        }
        match exact_retention.disposition() {
            FindingExactRetentionDisposition::Disabled if !exact_pins.all().is_empty() => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "disabled finding exact retention has exact pins",
                });
            }
            FindingExactRetentionDisposition::Complete
                if exact_retention.authenticated_candidates() == 0
                    || exact_pins.all().is_empty()
                    || exact_pins.all().len()
                        > exact_retention.authenticated_candidates() as usize
                    || exact_pins.pre_failure().len() > 1
                    || exact_pins.measurement_boundary().len() > 1
                    || exact_pins.post_failure().len() != 1
                    || !exact_pins.additional().is_empty() =>
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "complete finding exact retention has invalid selected checkpoints",
                });
            }
            FindingExactRetentionDisposition::Incomplete(_)
                if exact_retention.authenticated_candidates() != 0
                    || !exact_pins.all().is_empty() =>
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "incomplete finding exact retention has selected checkpoints",
                });
            }
            _ => {}
        }
        if let Some(evidence) = &exact_retention_evidence
            && (exact_retention.disposition() != FindingExactRetentionDisposition::Complete
                || exact_retention.authenticated_candidates() as usize
                    != evidence.candidates().len()
                || &exact_pins != evidence.selected())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "authenticated finding exact retention evidence disagrees with outcome",
            });
        }

        let value = Self {
            schema_version: FINDING_CANDIDATE_SCHEMA_VERSION,
            observation,
            signature,
            reproduction,
            minimized,
            signature_minimization,
            exact_pins,
            triage_evidence,
            exact_retention,
            exact_retention_evidence,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_RECORD_BYTES,
            "finding-candidate-bundle-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the canonical record-body and envelope schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
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

    /// Returns native replay evidence for both passes, when retained.
    #[must_use]
    pub const fn triage_evidence(&self) -> Option<FindingTriageEvidenceSet> {
        self.triage_evidence
    }

    /// Returns the active-policy exact-retention outcome.
    #[must_use]
    pub const fn exact_retention(&self) -> FindingExactRetention {
        self.exact_retention
    }

    /// Returns independently verifiable selector evidence for a version-five bundle.
    #[must_use]
    pub const fn exact_retention_evidence(&self) -> Option<&FindingExactRetentionEvidence> {
        self.exact_retention_evidence.as_ref()
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
            ObjectEnvelope::for_record_versioned(
                CampaignRecordKind::FindingCandidateBundle,
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
            ("reproduction".to_owned(), self.reproduction.content_id()),
            ("minimized".to_owned(), self.minimized.content_id()),
        ];
        children.extend(signature_children("signature", &self.signature));
        children.extend(self.signature_minimization.content_children());
        children.extend(exact_pin_children(&self.exact_pins));
        if let Some(triage_evidence) = self.triage_evidence {
            children.extend(triage_evidence.content_children());
        }
        children.push((
            "exact-retention.snapshot".to_owned(),
            self.exact_retention.snapshot().content_id(),
        ));
        children.push((
            "exact-retention.policy".to_owned(),
            self.exact_retention.policy().content_id(),
        ));
        children.push((
            "exact-retention.admission".to_owned(),
            self.exact_retention.admission().content_id(),
        ));
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
        self.triage_evidence.encode(encoder);
        Some(self.exact_retention).encode(encoder);
        self.exact_retention_evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != FINDING_CANDIDATE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding candidate bundle schema version",
            });
        }
        Self::new_current(
            FindingCandidateCore::new(
                ObservationId::decode(decoder)?,
                FindingSignature::decode(decoder)?,
                ReproductionArtifactId::decode(decoder)?,
                ReproductionArtifactId::decode(decoder)?,
                FindingSignatureMinimizationEvidence::decode(decoder)?,
                FindingExactPins::decode(decoder)?,
            ),
            Option::<FindingTriageEvidenceSet>::decode(decoder)?,
            Option::<FindingExactRetention>::decode(decoder)?.ok_or(
                CampaignCodecError::InvalidValue {
                    reason: "current finding candidate bundle omits exact retention disposition",
                },
            )?,
            Option::<FindingExactRetentionEvidence>::decode(decoder)?,
        )
    }
}

pub(crate) fn signature_children(
    prefix: &str,
    signature: &FindingSignature,
) -> Vec<(String, ContentId)> {
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
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{FindingKind, FindingMinimizationAttempt};
    use crucible_cas::content_store::ObjectKind;

    fn disabled_exact_retention() -> Result<FindingExactRetention, CampaignCodecError> {
        FindingExactRetention::new(
            CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignSnapshot,
                3,
                b"disabled-finding-retention-snapshot",
            ))?,
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                4,
                b"disabled-finding-retention-policy",
            ))?,
            AttemptAdmissionId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                3,
                b"disabled-finding-retention-admission",
            ))?,
            0,
            FindingExactRetentionDisposition::Disabled,
        )
    }

    #[test]
    fn bundle_round_trip_preserves_an_acyclic_child_graph() -> Result<(), CampaignCodecError> {
        let observation = ObservationId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"finding-candidate-observation",
        ))?;
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            2,
            b"finding-candidate-original",
        ))?;
        let minimized = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            2,
            b"finding-candidate-minimized",
        ))?;
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::derive("test", b"finding-candidate-signature"),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )?;
        let minimization = FindingMinimizationEvidence::new(
            original,
            3,
            b"test-policy".to_vec(),
            Vec::new(),
            CampaignHash::derive("test", b"finding-candidate-final-state"),
        )?;
        let signature_minimization = FindingSignatureMinimizationEvidence::new(
            &signature,
            &minimization,
            vec![Some(signature.clone())],
            vec![Some(signature.clone())],
        )?;
        let bundle = FindingCandidateBundle::new_with_exact_retention(
            FindingCandidateCore::new(
                observation,
                signature,
                original,
                minimized,
                signature_minimization,
                FindingExactPins::default(),
            ),
            None,
            disabled_exact_retention()?,
        )?;

        let decoded = FindingCandidateBundle::from_canonical_bytes(&bundle.canonical_bytes())?;
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.content_children().len(), 6);
        let bundle_content = decoded.id()?.content_id();
        assert!(
            decoded
                .content_children()
                .iter()
                .all(|(_, child)| *child != bundle_content)
        );

        let triage_id = |label: &[u8]| {
            FindingTriageReplayEvidenceId::from_content_id(ContentId::for_bytes(
                ObjectKind::Finding,
                1,
                label,
            ))
        };
        let triage_evidence = FindingTriageEvidenceSet::new(
            triage_id(b"minimization-original")?,
            triage_id(b"minimization-selected")?,
            triage_id(b"verification-original")?,
            triage_id(b"verification-selected")?,
        );
        let rich_bundle = FindingCandidateBundle::new_with_exact_retention(
            FindingCandidateCore::new(
                bundle.observation(),
                bundle.signature().clone(),
                bundle.reproduction(),
                bundle.minimized(),
                bundle.signature_minimization().clone(),
                bundle.exact_pins().clone(),
            ),
            Some(triage_evidence),
            disabled_exact_retention()?,
        )?;

        let decoded_rich =
            FindingCandidateBundle::from_canonical_bytes(&rich_bundle.canonical_bytes())?;
        assert_eq!(decoded_rich, rich_bundle);
        assert_eq!(
            decoded_rich.schema_version(),
            FINDING_CANDIDATE_SCHEMA_VERSION
        );
        assert_eq!(decoded_rich.triage_evidence(), Some(triage_evidence));
        assert_eq!(decoded_rich.content_children().len(), 10);

        let policy = CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            4,
            b"finding-exact-retention-policy",
        ))?;
        let admission = AttemptAdmissionId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            3,
            b"finding-exact-retention-admission",
        ))?;
        let exact_retention = FindingExactRetention::new(
            CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignSnapshot,
                3,
                b"finding-exact-retention-snapshot",
            ))?,
            policy,
            admission,
            0,
            FindingExactRetentionDisposition::Incomplete(
                FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
            ),
        )?;
        let retained_bundle = FindingCandidateBundle::new_with_exact_retention(
            crate::FindingCandidateCore::new(
                bundle.observation(),
                bundle.signature().clone(),
                bundle.reproduction(),
                bundle.minimized(),
                bundle.signature_minimization().clone(),
                bundle.exact_pins().clone(),
            ),
            Some(triage_evidence),
            exact_retention,
        )?;

        let decoded_retained =
            FindingCandidateBundle::from_canonical_bytes(&retained_bundle.canonical_bytes())?;
        assert_eq!(decoded_retained, retained_bundle);
        assert_eq!(
            decoded_retained.schema_version(),
            FINDING_CANDIDATE_SCHEMA_VERSION
        );
        assert_eq!(decoded_retained.exact_retention(), exact_retention);
        assert_eq!(decoded_retained.content_children().len(), 10);

        for historical_schema in 1_u32..FINDING_CANDIDATE_SCHEMA_VERSION {
            let mut historical = bundle.canonical_bytes();
            historical[..4].copy_from_slice(&historical_schema.to_be_bytes());
            assert!(FindingCandidateBundle::from_canonical_bytes(&historical).is_err());
        }
        Ok(())
    }

    #[test]
    fn signature_evidence_rejects_equal_fingerprint_with_a_different_failure_class()
    -> Result<(), CampaignCodecError> {
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            2,
            b"signature-evidence-original",
        ))?;
        let fingerprint = CampaignHash::derive("test", b"shared-fingerprint");
        let target = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )?;
        let different_class = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            String::from("qemu.different-failure-class"),
            None,
            BTreeSet::new(),
        )?;
        let final_state = CampaignHash::derive("test", b"signature-evidence-final-state");
        let rejected_minimization = FindingMinimizationEvidence::new(
            original,
            3,
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
        )?;

        FindingSignatureMinimizationEvidence::new(
            &target,
            &rejected_minimization,
            vec![Some(target.clone()), Some(different_class.clone())],
            vec![Some(target.clone()), Some(different_class.clone())],
        )?;
        let selected_minimization = FindingMinimizationEvidence::new(
            original,
            3,
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
        )?;
        assert!(
            FindingSignatureMinimizationEvidence::new(
                &target,
                &selected_minimization,
                vec![Some(target.clone()), Some(different_class.clone())],
                vec![Some(target.clone()), Some(different_class.clone())],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn signature_evidence_rejects_a_mismatched_verification_pass() -> Result<(), CampaignCodecError>
    {
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            2,
            b"verification-mismatch-original",
        ))?;
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::derive("test", b"verification-mismatch-fingerprint"),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )?;
        let minimization = FindingMinimizationEvidence::new(
            original,
            3,
            b"test-policy".to_vec(),
            Vec::new(),
            CampaignHash::derive("test", b"verification-mismatch-final-state"),
        )?;

        assert!(
            FindingSignatureMinimizationEvidence::new(
                &signature,
                &minimization,
                vec![Some(signature.clone())],
                vec![None],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn signature_projection_accepts_constructed_shrink_evidence_with_new_artifact_identities()
    -> Result<(), CampaignCodecError> {
        let original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            2,
            b"shrinking-winner-original",
        ))?;
        let original_configuration = crate::ConfigurationArtifactId::from_content_id(
            ContentId::for_bytes(ObjectKind::Configuration, 1, b"original-configuration"),
        )?;
        let minimized_configuration = crate::ConfigurationArtifactId::from_content_id(
            ContentId::for_bytes(ObjectKind::Configuration, 1, b"minimized-configuration"),
        )?;
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
        )?;
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
        )?;
        assert_ne!(
            original_signature.cluster_key(),
            minimized_signature.cluster_key()
        );

        let final_state = CampaignHash::derive("test", b"shrinking-winner-final-state");
        let minimization = FindingMinimizationEvidence::new(
            original,
            3,
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
        )?;
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
        )?;
        Ok(())
    }

    #[test]
    fn replay_signature_separates_property_and_target_categories() -> Result<(), CampaignCodecError>
    {
        let fingerprint = CampaignHash::derive("test", b"semantic-domain-fingerprint");
        let configuration = crate::ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            b"semantic-domain-config",
        ))?;
        let opportunity = crate::ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"semantic-domain-opportunity",
        ))?;
        let signature = |property: &str, target| {
            FindingSignature::new(
                FindingKind::PropertyViolation,
                fingerprint,
                Some(property.to_owned()),
                String::from("guest.assertion-failed"),
                Some(target),
                BTreeSet::new(),
            )
        };
        let configuration_target = signature(
            "scenario.property-a",
            FindingTarget::Configuration(configuration),
        )?;
        let different_property = signature(
            "scenario.property-b",
            FindingTarget::Configuration(configuration),
        )?;
        let choice_target = signature(
            "scenario.property-a",
            FindingTarget::ChoiceOpportunity(opportunity),
        )?;

        assert_ne!(
            FindingReplaySignature::from_observed(&configuration_target),
            FindingReplaySignature::from_observed(&different_property)
        );
        assert_ne!(
            FindingReplaySignature::from_observed(&configuration_target),
            FindingReplaySignature::from_observed(&choice_target)
        );
        Ok(())
    }
}
