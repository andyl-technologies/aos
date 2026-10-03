//! Closed campaign-mode derivation and completion-prefix reconstruction.
//!
//! A new strict campaign inherits every authenticated streaming completion.
//! Only its contiguous-prefix anchor changes; results beyond a hole remain
//! indexed and become part of the prefix after that hole is completed.

use super::*;

pub(super) fn derivation_modes_compatible(prior: CampaignMode, next: CampaignMode) -> bool {
    prior == next || (prior == CampaignMode::Streaming && next == CampaignMode::Strict)
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
