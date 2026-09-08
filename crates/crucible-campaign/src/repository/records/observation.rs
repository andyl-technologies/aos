//! Observation evidence and attempt record authentication.

use super::*;

impl CampaignRepository {
    pub(in crate::repository) fn read_measurement_set(
        &self,
        id: ContentId,
    ) -> Result<MeasurementSet, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::MeasurementSet)?;
        let value = MeasurementSet::from_canonical_bytes(envelope.body())?;
        if value.id()?.content_id() != id {
            return Err(integrity("measurement-set-envelope-shape"));
        }
        Ok(value)
    }

    pub(in crate::repository) fn read_property_verdict_set(
        &self,
        id: ContentId,
    ) -> Result<PropertyVerdictSet, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::PropertyVerdictSet)?;
        let value = PropertyVerdictSet::from_canonical_bytes(envelope.body())?;
        if value.id()?.content_id() != id {
            return Err(integrity("property-verdict-set-envelope-shape"));
        }
        Ok(value)
    }

    pub(in crate::repository) fn read_coverage_projection(
        &self,
        id: ContentId,
    ) -> Result<CoverageProjection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::CoverageProjection)?;
        let value = CoverageProjection::from_canonical_bytes(envelope.body())?;
        if value.id()?.content_id() != id {
            return Err(integrity("coverage-projection-envelope-shape"));
        }
        Ok(value)
    }

    pub(crate) fn read_observation(
        &self,
        id: ContentId,
    ) -> Result<Observation, CampaignRepositoryError> {
        let observation = self.decode_observation(id)?;
        self.validate_observation_references(&observation)?;
        Ok(observation)
    }

    pub(in crate::repository) fn decode_observation(
        &self,
        id: ContentId,
    ) -> Result<Observation, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Observation)?;
        let observation = Observation::from_canonical_bytes(envelope.body())?;
        if observation.id()?.content_id() != id {
            return Err(integrity("observation-envelope-shape"));
        }
        Ok(observation)
    }

    pub(in crate::repository) fn read_objective_evaluation(
        &self,
        id: ContentId,
    ) -> Result<ObjectiveEvaluation, CampaignRepositoryError> {
        self.read_objective_evaluation_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(in crate::repository) fn read_objective_evaluation_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<ObjectiveEvaluation, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::ObjectiveEvaluation)?;
        let evaluation = ObjectiveEvaluation::from_canonical_bytes(envelope.body())?;
        if evaluation.id()?.content_id() != id {
            return Err(integrity("objective-evaluation-envelope-shape"));
        }
        let policy = evaluation.policy();
        let contract = if let Some(contract) = cache.objective_contract(policy) {
            contract
        } else {
            let value = self.read_policy(policy.content_id())?;
            let contract = value.objective_contract_hash();
            cache.insert_objective_contract(policy, contract);
            contract
        };
        let observation = self.decode_observation(evaluation.observation().content_id())?;
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        evaluation.validate_compact_basis(policy, contract, &observation, &properties)?;
        Ok(evaluation)
    }

    pub(in crate::repository) fn read_ranking_explanation(
        &self,
        id: ContentId,
    ) -> Result<RankingExplanation, CampaignRepositoryError> {
        self.read_ranking_explanation_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(in crate::repository) fn read_ranking_explanation_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<RankingExplanation, CampaignRepositoryError> {
        let explanation = self.decode_ranking_explanation(id)?;
        self.read_objective_evaluation_cached(explanation.evaluation().content_id(), cache)?;
        if let crate::RankingDisposition::ParetoDominated(dominator) = explanation.disposition() {
            self.read_objective_evaluation_cached(dominator.content_id(), cache)?;
        }
        Ok(explanation)
    }

    pub(in crate::repository) fn decode_ranking_explanation(
        &self,
        id: ContentId,
    ) -> Result<RankingExplanation, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::RankingExplanation)?;
        let explanation = RankingExplanation::from_canonical_bytes(envelope.body())?;
        if explanation.id()?.content_id() != id {
            return Err(integrity("ranking-explanation-envelope-shape"));
        }
        Ok(explanation)
    }

    pub(in crate::repository) fn read_survivor_selection_bundle(
        &self,
        id: ContentId,
    ) -> Result<SurvivorSelectionBundle, CampaignRepositoryError> {
        self.read_survivor_selection_bundle_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(in crate::repository) fn read_survivor_selection_bundle_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<SurvivorSelectionBundle, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::SurvivorSelection)?;
        let selection = SurvivorSelection::from_canonical_bytes(envelope.body())?;
        if selection.id()?.content_id() != id {
            return Err(integrity("survivor-selection-envelope-shape"));
        }
        let policy = self.read_policy(selection.policy().content_id())?;
        cache.insert_objective_contract(selection.policy(), policy.objective_contract_hash());
        let considered_evaluations = selection
            .considered()
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut candidates = Vec::with_capacity(selection.considered().len());
        let mut evidence_bytes = 0;
        for (configuration, evaluation_id) in selection.considered() {
            let evaluation =
                self.read_objective_evaluation_cached(evaluation_id.content_id(), cache)?;
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                evaluation.canonical_bytes().len(),
            )?;
            let explanation_id = selection
                .explanations()
                .get(configuration)
                .ok_or_else(|| integrity("survivor-selection-explanation-missing"))?;
            let explanation = self.decode_ranking_explanation(explanation_id.content_id())?;
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                explanation.canonical_bytes().len(),
            )?;
            if evaluation.configuration() != *configuration
                || explanation.evaluation() != *evaluation_id
            {
                return Err(integrity("survivor-selection-candidate-basis-mismatch"));
            }
            if let crate::RankingDisposition::ParetoDominated(dominator) = explanation.disposition()
                && !considered_evaluations.contains(dominator)
            {
                return Err(integrity("survivor-selection-dominator-is-not-considered"));
            }
            candidates.push(crate::RankingCandidate::new(
                evaluation,
                explanation.novelty_score(),
                explanation.breadth_ordinal(),
            ));
        }
        let replayed = crate::rank_survivors(&policy, selection.rule(), candidates)?;
        if replayed.selection() != &selection {
            return Err(integrity("survivor-selection-replay-mismatch"));
        }
        Ok(replayed)
    }

    pub(in crate::repository) fn validate_observation_references(
        &self,
        observation: &Observation,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_observation_references_cached(
            observation,
            &mut ChoiceValidationCache::default(),
        )
    }

    pub(in crate::repository) fn validate_observation_references_cached(
        &self,
        observation: &Observation,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let attempt = self.read_attempt_cached(observation.attempt().content_id(), choice_cache)?;
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        if child.configuration() != observation.child()
            || attempt.path() != observation.path()
            || matches!(observation.stop(), StopOutcome::Reached(stop) if stop != attempt.stop())
        {
            return Err(integrity("observation-attempt-or-child-mismatch"));
        }
        self.read_measurement_set(observation.measurements().content_id())?;
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        self.read_coverage_projection(observation.coverage().content_id())?;
        for choice in observation.discovered_choices() {
            let choice = self.read_opportunity_cached(choice.content_id(), choice_cache)?;
            if choice.scenario() != child.scenario() {
                return Err(integrity("observation-choice-scenario-mismatch"));
            }
        }
        self.validate_observation_produced_selections(observation, &child)?;
        if matches!(
            observation.stop(),
            StopOutcome::Reached(StopCondition::NextChoice)
        ) && observation.discovered_choices().is_empty()
        {
            return Err(integrity("next-choice-observation-has-no-choice"));
        }
        if let StopOutcome::AssertionFailure(property) = observation.stop()
            && properties
                .properties()
                .get(property)
                .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
        {
            return Err(integrity("assertion-outcome-has-no-failed-property"));
        }
        Ok(())
    }

    pub(in crate::repository) fn read_attempt(
        &self,
        id: ContentId,
    ) -> Result<Attempt, CampaignRepositoryError> {
        self.read_attempt_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(in crate::repository) fn read_attempt_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<Attempt, CampaignRepositoryError> {
        if let Some(validated) = cache.validated_attempts.get(&id) {
            return Ok(validated.attempt.clone());
        }

        let attempt = self.read_attempt_record(id)?;
        let path = self.read_branch_path(attempt.path().content_id())?;
        let mut current = Some(attempt.clone());
        let mut current_id = id;
        let mut visited = BTreeSet::new();
        let mut pending = Vec::new();

        loop {
            if !visited.insert(current_id) {
                return Err(integrity("attempt-continuation-origin-cycle"));
            }

            if let Some(validated) = cache.validated_attempts.get(&current_id).cloned() {
                if validated.path != attempt.path() {
                    return Err(integrity("attempt-continuation-path-mismatch"));
                }
                return cache_attempt_continuation_prefix(cache, id, pending, validated);
            }

            let current = match current.take() {
                Some(current) => current,
                None => self.read_attempt_record(current_id)?,
            };
            if current.path() != attempt.path() {
                return Err(integrity("attempt-continuation-path-mismatch"));
            }

            let validated = match current.start() {
                AttemptStart::Discover { configuration } => {
                    let configuration =
                        self.read_configuration_artifact(configuration.content_id())?;
                    ValidatedAttempt {
                        attempt: current,
                        path: attempt.path(),
                        lineage: (configuration.scenario(), configuration.scenario_artifact()),
                        origin_depth: 1,
                    }
                }
                AttemptStart::Branch {
                    edge,
                    parent,
                    selection,
                } => {
                    if path.edges().last() != Some(&edge) {
                        return Err(integrity("attempt-branch-path-terminal-edge-mismatch"));
                    }
                    let parent = self.read_configuration_artifact(parent.content_id())?;
                    let resolved = self.resolve_selection(selection)?;
                    let branch_point = resolved
                        .opportunity()
                        .branch_point_id(parent.configuration());
                    resolved.selection().validate_branch_replay(
                        resolved.opportunity(),
                        resolved.domain(),
                        branch_point,
                    )?;
                    if let crate::SelectionOrigin::CampaignBranch {
                        edge: selected_edge,
                        ..
                    } = resolved.selection().origin()
                        && selected_edge != edge
                    {
                        return Err(integrity("attempt-branch-edge-mismatch"));
                    }
                    if path.segments().is_some_and(|segments| {
                        segments.last().copied()
                            != Some(crate::BranchPathSegment::new(branch_point, edge))
                    }) {
                        return Err(integrity("attempt-branch-path-terminal-scope-mismatch"));
                    }
                    ValidatedAttempt {
                        attempt: current,
                        path: attempt.path(),
                        lineage: (parent.scenario(), parent.scenario_artifact()),
                        origin_depth: 1,
                    }
                }
                AttemptStart::AfterAttempt { origin, reached } => {
                    let reached = self.read_configuration_artifact(reached.content_id())?;
                    pending.push((
                        current_id,
                        current,
                        (reached.scenario(), reached.scenario_artifact()),
                    ));
                    if pending.len() >= MAX_AFTER_ATTEMPT_ORIGIN_DEPTH {
                        return Err(integrity("attempt-continuation-origin-depth-exceeded"));
                    }
                    current_id = origin.content_id();
                    continue;
                }
            };

            cache
                .validated_attempts
                .insert(current_id, validated.clone());
            return cache_attempt_continuation_prefix(cache, id, pending, validated);
        }
    }

    fn read_attempt_record(&self, id: ContentId) -> Result<Attempt, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Attempt)?;
        let attempt = Attempt::from_canonical_bytes(envelope.body())?;
        if attempt.id()?.content_id() != id {
            return Err(integrity("attempt-envelope-shape"));
        }
        Ok(attempt)
    }
}
