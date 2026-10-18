//! Authenticated semantic completion ordinals and contiguous strict-order admission.

use super::*;

impl CampaignRepository {
    pub(in crate::repository) fn validate_strict_completion_order(
        &self,
        parent: &LoadedSnapshot,
        ordinal: AdmissionOrdinal,
    ) -> Result<(), CampaignRepositoryError> {
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if policy.mode() != CampaignMode::Strict {
            return Ok(());
        }
        let expected = self.next_strict_completion_ordinal(parent.snapshot.roots().accounting)?;
        if ordinal.value() != expected {
            return Err(integrity("strict-completion-order-gap"));
        }
        Ok(())
    }

    pub(in crate::repository) fn next_strict_completion_ordinal(
        &self,
        accounting: ContentId,
    ) -> Result<u64, CampaignRepositoryError> {
        let sequence = self.merkle.get(accounting, observation_sequence_key())?;
        let baseline = self.strict_sequence_anchor_ordinal(accounting, sequence)?;
        let admitted = self.accounted_attempts(accounting)?;
        if baseline > admitted {
            return Err(integrity("strict-completion-sequence-past-admission-head"));
        }

        let mut candidate = baseline
            .checked_add(1)
            .ok_or_else(|| integrity("strict-completion-sequence-overflow"))?;
        while candidate <= admitted
            && self
                .completion_at_ordinal(accounting, AdmissionOrdinal::new(candidate))?
                .is_some()
        {
            candidate = candidate
                .checked_add(1)
                .ok_or_else(|| integrity("strict-completion-sequence-overflow"))?;
        }
        Ok(candidate)
    }

    pub(in crate::repository::observation) fn strict_sequence_anchor_ordinal(
        &self,
        accounting: ContentId,
        sequence: Option<ContentId>,
    ) -> Result<u64, CampaignRepositoryError> {
        let Some(sequence) = sequence else {
            return Ok(0);
        };
        let envelope = self.read_envelope(sequence)?;
        let ordinal = match envelope.record_kind() {
            crate::CampaignRecordKind::Observation => {
                let observation = self.decode_observation(sequence)?;
                self.observation_execution_basis(accounting, &observation)?
                    .1
            }
            crate::CampaignRecordKind::Fact => match self.read_fact(sequence)? {
                CampaignFact::AttemptClosed { ordinal, .. } => ordinal,
                _ => {
                    return Err(integrity(
                        "strict-completion-sequence-fact-is-not-a-completion",
                    ));
                }
            },
            _ => {
                return Err(integrity(
                    "strict-completion-sequence-has-invalid-record-kind",
                ));
            }
        };
        if ordinal.value() == 0 {
            return Err(integrity("strict-completion-sequence-has-zero-ordinal"));
        }
        Ok(ordinal.value())
    }

    pub(in crate::repository) fn completion_at_ordinal(
        &self,
        accounting: ContentId,
        ordinal: AdmissionOrdinal,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        // Both terminal forms close the same semantic ordinal. Finding both is
        // an invalid owner projection rather than an arbitrary precedence.
        let observation = self
            .merkle
            .get(accounting, observation_ordinal_key(ordinal))?;
        let non_modeled = self
            .merkle
            .get(accounting, non_modeled_ordinal_key(ordinal))?;
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
