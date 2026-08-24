//! Immutable objective-evaluation and survivor-decision publication.

use super::*;

/// Stable result of publishing one policy-bound objective evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectiveEvaluationPublicationResult {
    /// Snapshot that owned the canonical observation and active policy.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot that first indexed the exact evaluation.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact immutable evaluation made authoritative.
    pub evaluation: ObjectiveEvaluationId,
    /// Whether this evaluation was already authoritative.
    pub replayed: bool,
}

impl CampaignRepository {
    /// Publishes one verified objective evaluation into a named campaign.
    ///
    /// The execution-model adapter must already have proven that every retained
    /// component came from the observation's verified measurement payload. This
    /// owner boundary validates the active policy, canonical observation,
    /// property filtering, deterministic scalar reward, and exact snapshot
    /// precondition before its first write.
    ///
    /// # Errors
    ///
    /// Returns an error without writing when the snapshot is stale, the
    /// evaluation is absent from the active policy/observation basis, another
    /// evaluation already owns the same basis, or repository validation fails.
    /// Storage failure after preflight may leave unreachable immutable objects
    /// before the final ref compare-and-swap.
    pub fn publish_objective_evaluation(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        evaluation: &ObjectiveEvaluation,
    ) -> Result<ObjectiveEvaluationPublicationResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;
        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        let evaluation_id = evaluation.id()?;
        if let Some(replayed) =
            self.find_objective_evaluation_result(current_content, evaluation_id)?
        {
            return Ok(replayed);
        }
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }

        self.validate_objective_evaluation_basis(&current, evaluation)?;
        let key = objective_evaluation_key(evaluation.policy(), evaluation.observation());
        match self
            .merkle
            .get(current.snapshot.roots().observations, key)?
        {
            Some(existing) if existing == evaluation_id.content_id() => {
                return Ok(ObjectiveEvaluationPublicationResult {
                    prior_snapshot: current_id,
                    new_snapshot: current_id,
                    evaluation: evaluation_id,
                    replayed: true,
                });
            }
            Some(_) => return Err(CampaignRepositoryError::AlreadyExists),
            None => {}
        }

        if self.put_objective_evaluation(evaluation)? != evaluation_id.content_id() {
            return Err(integrity("objective-evaluation-publication-id-mismatch"));
        }
        let mut roots = current.snapshot.roots();
        roots.observations = self
            .merkle
            .insert(roots.observations, key, evaluation_id.content_id())?
            .content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let transition =
            self.put_fact(&CampaignFact::ObjectiveEvaluationPublished(evaluation_id))?;
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(ObjectiveEvaluationPublicationResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    evaluation: evaluation_id,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    fn validate_objective_evaluation_basis(
        &self,
        snapshot: &LoadedSnapshot,
        evaluation: &ObjectiveEvaluation,
    ) -> Result<(), CampaignRepositoryError> {
        if evaluation.policy() != snapshot.snapshot.active_policy() {
            return Err(integrity("objective-evaluation-active-policy-mismatch"));
        }
        let policy = self.read_policy(evaluation.policy().content_id())?;
        let observation = self.read_observation(evaluation.observation().content_id())?;
        if self.merkle.get(
            snapshot.snapshot.roots().observations,
            attempt_observation_key(observation.attempt()),
        )? != Some(evaluation.observation().content_id())
        {
            return Err(integrity(
                "objective-evaluation-observation-is-not-canonical",
            ));
        }
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        evaluation.validate_basis(&policy, &observation, &properties)?;
        Ok(())
    }

    pub(super) fn validate_objective_evaluation_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        evaluation_id: ObjectiveEvaluationId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "objective-evaluation-transition-changed-campaign-basis",
            ));
        }
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
            || prior.accounting != next.accounting
        {
            return Err(integrity(
                "objective-evaluation-transition-changed-unrelated-root",
            ));
        }

        let evaluation =
            self.read_objective_evaluation_cached(evaluation_id.content_id(), choice_cache)?;
        self.validate_objective_evaluation_basis(parent, &evaluation)?;
        let key = objective_evaluation_key(evaluation.policy(), evaluation.observation());
        if self.merkle.get(prior.observations, key)?.is_some() {
            return Err(integrity(
                "objective-evaluation-transition-replaced-existing-basis",
            ));
        }
        let expected = self.merkle.root_after_upserts(
            prior.observations,
            &BTreeMap::from([(key, evaluation_id.content_id())]),
        )?;
        if next.observations != expected || next.observations == prior.observations {
            return Err(integrity(
                "objective-evaluation-transition-observation-root",
            ));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity(
                "objective-evaluation-transition-coordination-root",
            ));
        }
        Ok(())
    }

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
