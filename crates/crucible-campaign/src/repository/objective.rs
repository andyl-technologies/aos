//! Immutable objective-evaluation and survivor-decision publication.

use super::*;

impl CampaignRepository {
    /// Publishes one complete deterministic survivor decision without advancing a campaign.
    ///
    /// The execution-model adapter must already have proven that every retained
    /// objective component came from its observation's verified measurement
    /// payload. This repository boundary authenticates observation/property/
    /// policy ownership, exact ranking replay, and the complete dependency
    /// closure before storing any new decision member.
    ///
    /// # Errors
    ///
    /// Returns an error without writing a decision member when a dependency is
    /// absent, corrupt, mismatched, or the retained selection differs from exact
    /// deterministic replay. A storage failure during final immutable writes may
    /// leave harmless content-addressed members for ordinary garbage collection.
    pub fn publish_survivor_selection(
        &self,
        bundle: &SurvivorSelectionBundle,
    ) -> Result<SurvivorSelectionId, CampaignRepositoryError> {
        let replayed = self.validate_survivor_selection_bundle(bundle)?;
        if &replayed != bundle {
            return Err(integrity("survivor-selection-bundle-replay-mismatch"));
        }

        for evaluation in bundle.evaluations().values() {
            self.put_objective_evaluation(evaluation)?;
        }
        for explanation in bundle.explanations().values() {
            self.put_ranking_explanation(explanation)?;
        }
        let content = self.put_survivor_selection(bundle.selection())?;
        if content != bundle.selection().id()?.content_id() {
            return Err(integrity("survivor-selection-publication-id-mismatch"));
        }
        self.verify_campaign_closure(content)?;
        SurvivorSelectionId::from_content_id(content).map_err(Into::into)
    }

    fn validate_survivor_selection_bundle(
        &self,
        bundle: &SurvivorSelectionBundle,
    ) -> Result<SurvivorSelectionBundle, CampaignRepositoryError> {
        let selection = bundle.selection();
        let policy = self.read_policy(selection.policy().content_id())?;
        if bundle.evaluations().len() != selection.considered().len()
            || bundle.explanations().len() != selection.explanations().len()
        {
            return Err(integrity("survivor-selection-bundle-member-count"));
        }

        let mut roots = BTreeSet::from([selection.policy().content_id()]);
        let mut candidates = Vec::with_capacity(bundle.evaluations().len());
        let mut evidence_bytes = 0;
        for (configuration, evaluation) in bundle.evaluations() {
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                evaluation.canonical_bytes().len(),
            )?;
            let evaluation_id = evaluation.id()?;
            if selection.considered().get(configuration) != Some(&evaluation_id) {
                return Err(integrity("survivor-selection-evaluation-map-mismatch"));
            }
            let observation = self.decode_observation(evaluation.observation().content_id())?;
            let properties =
                self.read_property_verdict_set(observation.properties().content_id())?;
            evaluation.validate_basis(&policy, &observation, &properties)?;
            roots.insert(evaluation.observation().content_id());

            let explanation = bundle
                .explanations()
                .get(configuration)
                .ok_or_else(|| integrity("survivor-selection-explanation-missing"))?;
            if explanation.evaluation() != evaluation_id
                || selection.explanations().get(configuration) != Some(&explanation.id()?)
            {
                return Err(integrity("survivor-selection-explanation-map-mismatch"));
            }
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                explanation.canonical_bytes().len(),
            )?;
            candidates.push(crate::RankingCandidate::new(
                evaluation.clone(),
                explanation.novelty_score(),
                explanation.breadth_ordinal(),
            ));
        }
        self.verify_campaign_closures_anchored_cached(
            roots,
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
        )?;
        crate::rank_survivors(&policy, selection.rule(), candidates).map_err(Into::into)
    }
}
