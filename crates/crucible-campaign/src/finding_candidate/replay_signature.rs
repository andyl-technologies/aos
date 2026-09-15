//! Stable replay signatures and two-pass minimization evidence.

use super::*;

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

    pub(super) fn validate_signature_basis(
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
