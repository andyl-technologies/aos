//! Closed campaign-mode derivation and completion-prefix reconstruction.
//!
//! A new strict campaign inherits every authenticated streaming completion.
//! Only its contiguous-prefix anchor changes; results beyond a hole remain
//! indexed and become part of the prefix after that hole is completed.

use super::*;
use crate::repository::closure::read::ClosureSemanticRead;

pub(super) fn derivation_modes_compatible(prior: CampaignMode, next: CampaignMode) -> bool {
    prior == next || (prior == CampaignMode::Streaming && next == CampaignMode::Strict)
}

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn validate_stored_creation_generator_closure(
        &mut self,
        policy: &CampaignPolicy,
    ) -> Result<(), CampaignRepositoryError> {
        let mut pending = Vec::new();
        for generator in policy
            .choice_policies()
            .values()
            .map(crate::ChoicePolicy::generator)
        {
            self.push(&mut pending, generator)?;
        }

        let mut visited = BTreeSet::new();
        let mut canonical_bytes = 0_usize;
        while let Some(id) = pending.pop() {
            if !self.insert_set(&mut visited, id)? {
                continue;
            }
            if visited.len() > crate::MAX_CREATE_CAMPAIGN_GENERATORS {
                return Err(integrity("campaign-generator-count-limit"));
            }
            let generator = self.read_generator(id.content_id())?;
            super::transactions::charge_creation_generator_bytes(
                &mut canonical_bytes,
                generator.canonical_bytes().len(),
            )?;
            for (_, child) in generator.content_children() {
                self.push(
                    &mut pending,
                    CandidateGeneratorSpecId::from_content_id(child)?,
                )?;
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn derivation_accounting_upserts(
        &mut self,
        accounting: ContentId,
        prior: CampaignMode,
        next: CampaignMode,
    ) -> Result<BTreeMap<CampaignHash, ContentId>, CampaignRepositoryError> {
        let mut upserts = BTreeMap::new();
        if prior == next {
            return Ok(upserts);
        }
        if !derivation_modes_compatible(prior, next) {
            return Err(integrity("unsupported-campaign-mode-derivation"));
        }

        // The caller authenticates the complete source history before this
        // projection. A later completion cannot bridge a genuine earlier hole.
        let admitted = self.accounted_attempts(accounting)?;
        let mut prefix = None;
        for value in 1..=admitted {
            let Some(completion) =
                self.derivation_completion_at_ordinal(accounting, AdmissionOrdinal::new(value))?
            else {
                break;
            };
            prefix = Some(completion);
        }
        if let Some(completion) = prefix {
            self.insert_map(&mut upserts, observation_sequence_key(), completion)?;
        }
        Ok(upserts)
    }

    fn derivation_completion_at_ordinal(
        &mut self,
        accounting: ContentId,
        ordinal: AdmissionOrdinal,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let observation = self.merkle_get(accounting, observation_ordinal_key(ordinal))?;
        let non_modeled = self.merkle_get(accounting, non_modeled_ordinal_key(ordinal))?;
        let completion = match (observation, non_modeled) {
            (None, None) => return Ok(None),
            (Some(_), Some(_)) => {
                return Err(integrity(
                    "completion-ordinal-has-modeled-and-non-modeled-results",
                ));
            }
            (Some(observation), None) => {
                let record = self.decode_observation(observation)?;
                if self.observation_execution_basis(accounting, &record)?.1 != ordinal {
                    return Err(integrity("observation-ordinal-index-mismatch"));
                }
                observation
            }
            (None, Some(non_modeled)) => {
                let CampaignFact::AttemptClosed {
                    ordinal: recorded, ..
                } = self.read_fact(non_modeled)?
                else {
                    return Err(integrity("attempt-closure-ordinal-index-type-mismatch"));
                };
                if recorded != ordinal {
                    return Err(integrity("attempt-closure-ordinal-index-mismatch"));
                }
                non_modeled
            }
        };
        Ok(Some(completion))
    }
}

impl CampaignRepository {
    pub(super) fn derivation_accounting_upserts(
        &self,
        accounting: ContentId,
        prior: CampaignMode,
        next: CampaignMode,
    ) -> Result<BTreeMap<CampaignHash, ContentId>, CampaignRepositoryError> {
        if prior == next {
            return Ok(BTreeMap::new());
        }
        if !derivation_modes_compatible(prior, next) {
            return Err(integrity("unsupported-campaign-mode-derivation"));
        }

        // The caller authenticates the complete source history before this
        // projection. Never infer a prefix from the largest completed ordinal:
        // streaming publication can contain genuine holes.
        let admitted = self.accounted_attempts(accounting)?;
        let mut prefix = None;
        for value in 1..=admitted {
            let Some(completion) =
                self.completion_at_ordinal(accounting, AdmissionOrdinal::new(value))?
            else {
                break;
            };
            prefix = Some(completion);
        }

        Ok(prefix
            .map(|completion| BTreeMap::from([(observation_sequence_key(), completion)]))
            .unwrap_or_default())
    }
}
