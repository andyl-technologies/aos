//! Candidate replay against the same checked proposal and observation view.

use super::*;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn candidate_at_with_feedback(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
        completed_visits: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let Some(profile) = self.candidate_source_profile(request, domain)? else {
            return Ok(None);
        };
        let Some(count) = profile.count() else {
            return Ok(None);
        };
        if ordinal == 0 || ordinal > count {
            return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
        }
        if ordinal > profile.available_count(completed_visits)? {
            return Err(integrity("progressive-generator-feedback-is-insufficient"));
        }
        if let Some(value) = self.static_candidate_at(request, domain, ordinal)? {
            return Ok(Some(value));
        }

        Ok(None)
    }

    pub(in crate::repository) fn expected_candidate_at_view(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
        basis: CandidateEnumerationBasis<'_>,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let CandidateEnumerationBasis {
            view,
            completed_visits,
            additional_previous,
            feedback_projection,
        } = basis;
        let Some(profile) = self.candidate_source_profile(request, domain)? else {
            return Ok(None);
        };
        if profile.scores_intervals() {
            let count = profile.count().unwrap_or_default();
            if ordinal == 0 || ordinal > count {
                return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
            }
            if ordinal > profile.available_count(completed_visits)? {
                return Err(integrity("progressive-generator-feedback-is-insufficient"));
            }
            let ChoiceDomain::Integer(integer) = domain else {
                return Err(integrity("candidate-generator-domain-family-mismatch"));
            };
            let generator = request
                .source()
                .generator()
                .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
            let spec = self.read_generator(generator.content_id())?;
            let CandidateGeneratorAlgorithm::ProgressiveInteger { initial_strata, .. } =
                spec.algorithm()
            else {
                return Err(integrity("progressive-generator-basis-mismatch"));
            };
            if spec.implementation_version()
                != crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            {
                return Err(integrity("progressive-generator-basis-mismatch"));
            }
            if ordinal <= u64::from(*initial_strata).min(count) {
                return stratified_integer_candidate(*initial_strata, integer, ordinal)
                    .map(ChoiceValue::Integer)
                    .map(Some);
            }
            let feedback = feedback_projection
                .ok_or_else(|| integrity("progressive-generator-feedback-projection-is-missing"))?;
            let additional_count = u64::try_from(additional_previous.len())
                .map_err(|_| integrity("progressive-generator-proposal-history-mismatch"))?;
            let base_ordinal = ordinal
                .checked_sub(additional_count)
                .ok_or_else(|| integrity("progressive-generator-proposal-history-mismatch"))?;
            let mut proposed =
                self.proposed_values_before(view.exploration, request.id()?, base_ordinal)?;
            for (index, proposal) in additional_previous.iter().enumerate() {
                self.poll()?;
                let expected_ordinal = base_ordinal
                    .checked_add(u64::try_from(index).map_err(|_| {
                        integrity("progressive-generator-proposal-history-mismatch")
                    })?)
                    .ok_or_else(|| integrity("progressive-generator-proposal-history-mismatch"))?;
                if proposal.request() != request.id()?
                    || proposal.ordinal() != expected_ordinal
                    || !self.insert_set(&mut proposed, proposal.value().clone_admitted()?)?
                {
                    return Err(integrity("progressive-generator-proposal-history-mismatch"));
                }
            }
            return feedback_progressive_integer_candidate(
                request,
                integer,
                domain.semantic_id(),
                &proposed,
                feedback,
                &mut || self.poll(),
            )
            .map(ChoiceValue::Integer)
            .map(Some);
        }
        if profile != CandidateSourceProfile::CorpusMutation {
            return self.candidate_at_with_feedback(request, domain, ordinal, completed_visits);
        }
        if ordinal == 0 || ordinal > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS {
            return Err(integrity("corpus-mutation-proposal-ordinal-limit"));
        }
        let additional_count = u64::try_from(additional_previous.len())
            .map_err(|_| integrity("corpus-mutation-proposal-ordinal-limit"))?;
        let base_ordinal = ordinal
            .checked_sub(additional_count)
            .ok_or_else(|| integrity("corpus-mutation-proposal-history-mismatch"))?;
        let mut proposed =
            self.proposed_values_before(view.exploration, request.id()?, base_ordinal)?;
        for (index, proposal) in additional_previous.iter().enumerate() {
            self.poll()?;
            let expected_ordinal = base_ordinal
                .checked_add(
                    u64::try_from(index)
                        .map_err(|_| integrity("corpus-mutation-proposal-ordinal-limit"))?,
                )
                .ok_or_else(|| integrity("corpus-mutation-proposal-ordinal-limit"))?;
            if proposal.request() != request.id()?
                || proposal.ordinal() != expected_ordinal
                || !self.insert_set(&mut proposed, proposal.value().clone_admitted()?)?
            {
                return Err(integrity("corpus-mutation-proposal-history-mismatch"));
            }
        }
        Ok(self
            .corpus_mutation_candidates_for_view(request, domain, view, None)?
            .into_iter()
            .find(|candidate| !proposed.contains(candidate)))
    }
}
