//! Authenticated earliest discovering observation for each parent choice.
//!
//! A branch request names its parent configuration artifact and the choice
//! opportunity it continues. Beam projection needs the canonical observation
//! that discovered that pair to find the request's producing cohort. Campaign
//! genesis anchors an empty nested index under the observation root, and every
//! canonical observation publication inserts or lowers one slot per discovered
//! choice. Determinism-conflict observations never touch it.
//!
//! ```text
//! observations[observation-choice-source-index.v1]
//!   -> H(parent_artifact || opportunity) -> earliest observation
//! ```
//!
//! "Earliest" is the ascending `(AdmissionOrdinal, ObservationId)` order.
//! Streaming completions may arrive out of admission order, so publication
//! compares against the current slot instead of keeping the first arrival.
//! Restart and import validation recompute the same read-compare-upsert from
//! the parent snapshot, so an omitted or raised slot is corrupt.

use super::*;

/// Returns the observation-root key that anchors the nested source index.
pub(super) fn choice_source_index_anchor_key() -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.observation-choice-source-index.v1",
        b"root",
    )
}

/// Returns the nested slot for one discovered `(parent, opportunity)` pair.
fn choice_source_key(
    parent: ConfigurationArtifactId,
    opportunity: ChoiceOpportunityId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(parent.content_id().encode().as_bytes());
    bytes.extend_from_slice(opportunity.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign.observation-choice-source.v1", &bytes)
}

impl CampaignRepository {
    /// Reads the nested source index anchored in one observation root.
    ///
    /// # Errors
    ///
    /// Returns an integrity error when the current-format anchor is absent, or
    /// a store error when the root cannot be read.
    pub(super) fn choice_source_index(
        &self,
        observations: ContentId,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.merkle
            .get(observations, choice_source_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-choice-source-index-is-missing"))
    }

    /// Returns the earliest canonical observation that discovered `opportunity`
    /// at the exact `parent` artifact, if any.
    ///
    /// # Errors
    ///
    /// Returns an integrity or store error when the anchor is missing or the
    /// indexed value is not an observation.
    pub(super) fn choice_source_observation(
        &self,
        observations: ContentId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let index = self.choice_source_index(observations)?;
        let source = self
            .merkle
            .get(index, choice_source_key(parent, opportunity))?;
        if source.is_some_and(|content| content.kind() != ObjectKind::Observation) {
            return Err(integrity("choice-source-index-value-kind"));
        }
        Ok(source)
    }

    /// Computes the nested-index upserts for one canonical observation.
    ///
    /// Each discovered choice claims its slot when the slot is empty or holds
    /// an observation later in `(AdmissionOrdinal, ObservationId)` order. The
    /// returned map is empty when every slot already names an earlier source.
    ///
    /// # Errors
    ///
    /// Returns an integrity or store error when a currently indexed source is
    /// missing, malformed, or lacks its authenticated execution basis.
    pub(super) fn choice_source_upserts(
        &self,
        accounting: ContentId,
        index: ContentId,
        observation_content: ContentId,
        observation: &Observation,
        ordinal: AdmissionOrdinal,
    ) -> Result<BTreeMap<CampaignHash, ContentId>, CampaignRepositoryError> {
        let candidate = (ordinal, observation_content);
        let mut upserts = BTreeMap::new();
        let mut incumbents = BTreeMap::<ContentId, AdmissionOrdinal>::new();
        self.for_each_discovered_choice(observation, |opportunity| {
            let key = choice_source_key(observation.child_content(), opportunity);
            let claims_slot = match self.merkle.get(index, key)? {
                None => true,
                Some(current) => {
                    let current_ordinal = match incumbents.get(&current) {
                        Some(ordinal) => *ordinal,
                        None => {
                            let ordinal = self.choice_source_ordinal(accounting, current)?;
                            incumbents.insert(current, ordinal);
                            ordinal
                        }
                    };
                    candidate < (current_ordinal, current)
                }
            };
            if claims_slot {
                upserts.insert(key, observation_content);
            }
            Ok(())
        })?;
        Ok(upserts)
    }

    /// Reads the admission ordinal of one indexed source observation.
    fn choice_source_ordinal(
        &self,
        accounting: ContentId,
        content: ContentId,
    ) -> Result<AdmissionOrdinal, CampaignRepositoryError> {
        if content.kind() != ObjectKind::Observation {
            return Err(integrity("choice-source-index-value-kind"));
        }
        let observation = self.decode_observation(content)?;
        let (_, ordinal) = self.observation_execution_basis(accounting, &observation)?;
        Ok(ordinal)
    }
}
