//! Record contracts.

use super::*;

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
    candidate_bundle: Option<FindingCandidateBundleId>,
    candidate_occurrences: Option<FindingCandidateOccurrenceSet>,
}

/// Stable signature and first-occurrence basis shared by finding record schemas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRecordBasis {
    signature: FindingSignature,
    observation: ObservationId,
    reproduction: ReproductionArtifactId,
    first_seen_snapshot: CampaignSnapshotId,
    occurrences: FindingOccurrenceSet,
}

impl FindingRecordBasis {
    /// Builds the common identity and occurrence portion of a finding record.
    #[must_use]
    pub const fn new(
        signature: FindingSignature,
        observation: ObservationId,
        reproduction: ReproductionArtifactId,
        first_seen_snapshot: CampaignSnapshotId,
        occurrences: FindingOccurrenceSet,
    ) -> Self {
        Self {
            signature,
            observation,
            reproduction,
            first_seen_snapshot,
            occurrences,
        }
    }
}

impl Finding {
    /// Builds the common record basis accepted by finding constructors.
    #[must_use]
    pub const fn basis(
        signature: FindingSignature,
        observation: ObservationId,
        reproduction: ReproductionArtifactId,
        first_seen_snapshot: CampaignSnapshotId,
        occurrences: FindingOccurrenceSet,
    ) -> FindingRecordBasis {
        FindingRecordBasis::new(
            signature,
            observation,
            reproduction,
            first_seen_snapshot,
            occurrences,
        )
    }

    /// Builds a finding that retains every verified candidate bundle.
    ///
    /// The representative observation and reproduction fields remain the first
    /// finding evidence. `candidate_bundle` is the first retained candidate
    /// bundle.
    /// `candidate_occurrences` authenticates every retained bundle.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when reproduction versions are invalid or
    /// the encoded record exceeds 4 MiB.
    pub fn new_with_candidate_occurrences(
        basis: FindingRecordBasis,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: FindingExactPins,
        candidate_bundle: FindingCandidateBundleId,
        candidate_occurrences: FindingCandidateOccurrenceSet,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_current(
            basis,
            minimized,
            exact_pins,
            candidate_bundle,
            candidate_occurrences,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_current_for_test(
        basis: FindingRecordBasis,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: FindingExactPins,
    ) -> Result<Self, CampaignCodecError> {
        let candidate_bundle = FindingCandidateBundleId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            5,
            b"unit-test finding candidate bundle",
        ))?;
        let candidate_occurrences = FindingCandidateOccurrenceSet::new(
            ContentId::for_bytes(
                ObjectKind::MerkleNode,
                1,
                b"unit-test candidate occurrences",
            ),
            1,
            candidate_bundle,
        )?;
        Self::new_current(
            basis,
            minimized,
            exact_pins,
            candidate_bundle,
            candidate_occurrences,
        )
    }

    fn new_current(
        basis: FindingRecordBasis,
        minimized: Option<ReproductionArtifactId>,
        exact_pins: FindingExactPins,
        candidate_bundle: FindingCandidateBundleId,
        candidate_occurrences: FindingCandidateOccurrenceSet,
    ) -> Result<Self, CampaignCodecError> {
        let reproduction_version = basis.reproduction.content_id().schema_version();
        let minimized_version = minimized.map(|id| id.content_id().schema_version());
        let reproduction_versions_match = reproduction_version == RETENTION_SCHEMA_VERSION
            && minimized_version.is_none_or(|version| version == RETENTION_SCHEMA_VERSION);
        if !reproduction_versions_match {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding schema disagrees with reproduction versions",
            });
        }
        let value = Self {
            schema_version: CANDIDATE_OCCURRENCES_SCHEMA_VERSION,
            signature: basis.signature,
            observation: basis.observation,
            reproduction: basis.reproduction,
            first_seen_snapshot: basis.first_seen_snapshot,
            occurrences: basis.occurrences,
            minimized,
            exact_pins,
            candidate_bundle: Some(candidate_bundle),
            candidate_occurrences: Some(candidate_occurrences),
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

    /// Returns the first retained candidate bundle.
    ///
    /// Schema v4 preserves the first bundle retained for the finding, while
    /// [`Self::candidate_occurrences`] is authoritative for all bundles.
    #[must_use]
    pub const fn candidate_bundle(&self) -> Option<FindingCandidateBundleId> {
        self.candidate_bundle
    }

    /// Returns the authenticated Merkle root of retained candidate bundles.
    #[must_use]
    pub const fn candidate_occurrences(&self) -> Option<ContentId> {
        match self.candidate_occurrences {
            Some(occurrences) => Some(occurrences.root()),
            None => None,
        }
    }

    /// Returns the number of retained candidate bundles.
    #[must_use]
    pub const fn candidate_occurrence_count(&self) -> u32 {
        match self.candidate_occurrences {
            Some(occurrences) => occurrences.count(),
            None if self.candidate_bundle.is_some() => 1,
            None => 0,
        }
    }

    /// Returns the candidate bundle added or reaffirmed by this record version.
    #[must_use]
    pub const fn latest_candidate_bundle(&self) -> Option<FindingCandidateBundleId> {
        match self.candidate_occurrences {
            Some(occurrences) => Some(occurrences.latest()),
            None => self.candidate_bundle,
        }
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
        if let Some(candidate_bundle) = self.candidate_bundle {
            children.push(("candidate-bundle".to_owned(), candidate_bundle.content_id()));
        }
        if let Some(candidate_occurrences) = self.candidate_occurrences {
            children.push((
                "candidate-occurrences".to_owned(),
                candidate_occurrences.root(),
            ));
            children.push((
                "latest-candidate-bundle".to_owned(),
                candidate_occurrences.latest().content_id(),
            ));
        }
        children.extend(self.exact_pins.content_children());
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
        self.candidate_bundle.encode(encoder);
        self.candidate_occurrences.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != CANDIDATE_OCCURRENCES_SCHEMA_VERSION {
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
        let exact_pins = FindingExactPins::decode(decoder)?;
        let candidate_bundle = Option::<FindingCandidateBundleId>::decode(decoder)?.ok_or(
            CampaignCodecError::InvalidValue {
                reason: "finding record has no authenticated candidate bundle",
            },
        )?;
        let candidate_occurrences = Option::<FindingCandidateOccurrenceSet>::decode(decoder)?
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "finding record has no authenticated candidate occurrences",
            })?;
        Self::new_current(
            Self::basis(
                signature,
                observation,
                reproduction,
                first_seen_snapshot,
                occurrences,
            ),
            minimized,
            exact_pins,
            candidate_bundle,
            candidate_occurrences,
        )
    }
}
