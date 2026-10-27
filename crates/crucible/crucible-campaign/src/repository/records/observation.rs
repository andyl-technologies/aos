//! Observation evidence and attempt record authentication.

use super::*;
use crate::ObservationCondition;

impl CampaignRepository {
    /// Reads one bounded slice of a retained trace leaf.
    ///
    /// Callers must first establish that an authenticated observation or
    /// measurement set owns `trace`. Only the requested range is read: the
    /// backend integrity-checks ranged reads, and the reader authenticates the
    /// assembled leaf against its content identity, so the cost of reading a
    /// leaf is linear in its length rather than in its length times its chunk
    /// count.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identity, a leaf longer than
    /// `max_bytes`, an offset beyond EOF, a chunk larger than one MiB, or a
    /// failed backend read.
    pub fn load_trace_chunk(
        &self,
        trace: ContentId,
        offset: u64,
        limit: u32,
        max_bytes: u64,
    ) -> Result<(u64, Vec<u8>), CampaignRepositoryError> {
        if trace.kind() != ObjectKind::Trace
            || trace.schema_version() == 0
            || limit == 0
            || limit > 1_048_576
        {
            return Err(integrity("campaign-trace-chunk-request-invalid"));
        }
        let total = self.blobs.read(trace, None)?.logical_length();
        if total > max_bytes {
            return Err(integrity("campaign-trace-leaf-oversized"));
        }
        if offset > total {
            return Err(integrity("campaign-trace-offset-out-of-range"));
        }

        let length = u64::from(limit).min(total - offset);
        let range = crucible_store::content_store::ByteRange::new(offset, length)
            .map_err(|_| integrity("campaign-trace-offset-overflow"))?;
        let chunk = self.blobs.read(trace, Some(range))?.read_all(length)?;
        Ok((total, chunk))
    }

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

    pub(in crate::repository) fn read_coverage_identity_frequency(
        &self,
        id: ContentId,
    ) -> Result<crate::CoverageIdentityFrequency, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::CoverageIdentityFrequency)?;
        let value = crate::CoverageIdentityFrequency::from_canonical_bytes(envelope.body())?;
        if value.content_id()? != id {
            return Err(integrity("coverage-identity-frequency-envelope-shape"));
        }
        Ok(value)
    }

    pub(in crate::repository) fn put_coverage_identity_frequency(
        &self,
        value: crate::CoverageIdentityFrequency,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CoverageIdentityFrequency,
            BTreeSet::new(),
            value.canonical_bytes(),
        )?)
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
            || !observation
                .stop()
                .authenticates_requested_stop(attempt.stop())
        {
            return Err(integrity("observation-attempt-or-child-mismatch"));
        }
        self.read_measurement_set(observation.measurements().content_id())?;
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        self.read_coverage_projection(observation.coverage().content_id())?;
        if let Some(trace) = observation.resolved_effect_trace() {
            self.validate_resolved_effect_trace_leaves(trace)?;
        }
        self.for_each_discovered_choice(observation, |choice| {
            let choice = self.read_opportunity_cached(choice.content_id(), choice_cache)?;
            if choice.scenario() != child.scenario() {
                return Err(integrity("observation-choice-scenario-mismatch"));
            }
            Ok(())
        })?;
        self.validate_observation_produced_selections(observation, &child)?;
        if observation.stop().reached_next_choice() && observation.discovered_choices().is_empty() {
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
        if let StopOutcome::ObservationReached(proof) = observation.stop()
            && let Some(property) = match proof.condition() {
                ObservationCondition::AssertionViolationTransition(property) => {
                    Some(property.as_str())
                }
                ObservationCondition::AnyAssertionViolationTransition => {
                    proof.assertion_witness().map(|witness| witness.assertion())
                }
                _ => None,
            }
            && properties
                .properties()
                .get(property)
                .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
        {
            return Err(integrity(
                "assertion-observation-stop-has-no-failed-property",
            ));
        }
        Ok(())
    }

    /// Requires every leaf of a segmented trace to be present within its
    /// bound, without reading the trace.
    ///
    /// Leaves were authenticated when they were stored; readers authenticate
    /// them again against the manifest before decoding.
    fn validate_resolved_effect_trace_leaves(
        &self,
        trace: &ResolvedEffectTraceRef,
    ) -> Result<(), CampaignRepositoryError> {
        let manifest = self.blobs.read(trace.manifest(), None)?.logical_length();
        if manifest > MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES as u64 {
            return Err(integrity("observation-trace-manifest-oversized"));
        }
        for &segment in trace.segments() {
            let length = self.blobs.read(segment, None)?.logical_length();
            if length > MAX_SEGMENT_BYTES as u64 {
                return Err(integrity("observation-trace-segment-oversized"));
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn read_attempt(
        &self,
        id: ContentId,
    ) -> Result<Attempt, CampaignRepositoryError> {
        self.read_attempt_cached(id, &mut ChoiceValidationCache::default())
    }

    /// Reads one attempt and validates its complete continuation chain.
    ///
    /// An `AfterAttempt` continuation must share its origin's branch path and
    /// reach a configuration of its origin's scenario lineage, back to a
    /// `Discover` or `Branch` root. Validation holds constant state: it walks
    /// origins until it reaches a cached validated attempt or the root, then
    /// caches a bounded prefix of the chain. Cycles cannot occur because each
    /// attempt's content ID commits to its origin's ID.
    pub(in crate::repository) fn read_attempt_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<Attempt, CampaignRepositoryError> {
        if let Some(validated) = cache.validated_attempts.get(&id).cloned() {
            self.cache_validated_attempt_origin(&validated, cache);
            return Ok(validated.attempt);
        }

        let attempt = self.read_attempt_record(id)?;
        let lineage = self.validate_attempt_chain(&attempt, cache)?;
        self.cache_validated_attempt_chain(id, attempt.clone(), lineage, cache)?;
        Ok(attempt)
    }

    /// Validates `attempt`'s chain and returns its scenario lineage.
    ///
    /// Each link's lineage must equal its origin's, so every link in a valid
    /// chain carries the requested attempt's lineage. Checking each link
    /// against that one expected value needs no per-link state.
    fn validate_attempt_chain(
        &self,
        attempt: &Attempt,
        cache: &ChoiceValidationCache,
    ) -> Result<AttemptLineage, CampaignRepositoryError> {
        let path_id = attempt.path();
        let path = self.read_branch_path(path_id.content_id())?;
        let mut expected = None;
        let mut start = attempt.start();

        loop {
            let (origin, reached) = match start {
                AttemptStart::AfterAttempt { origin, reached } => (origin, reached),
                AttemptStart::Discover { .. } | AttemptStart::Branch { .. } => {
                    let lineage = self.validate_attempt_root(start, &path)?;
                    return match_attempt_lineage(expected, lineage);
                }
            };

            let reached = self.read_configuration_artifact(reached.content_id())?;
            let lineage =
                match_attempt_lineage(expected, (reached.scenario(), reached.scenario_artifact()))?;
            expected = Some(lineage);

            if let Some(validated) = cache.validated_attempts.get(&origin.content_id()) {
                if validated.path != path_id {
                    return Err(integrity("attempt-continuation-path-mismatch"));
                }
                return match_attempt_lineage(expected, validated.lineage);
            }
            let origin = self.read_attempt_record(origin.content_id())?;
            if origin.path() != path_id {
                return Err(integrity("attempt-continuation-path-mismatch"));
            }
            start = origin.start();
        }
    }

    /// Validates a `Discover` or `Branch` chain root against the chain's path.
    fn validate_attempt_root(
        &self,
        start: AttemptStart,
        path: &BranchPath,
    ) -> Result<AttemptLineage, CampaignRepositoryError> {
        match start {
            AttemptStart::Discover { configuration } => {
                let configuration = self.read_configuration_artifact(configuration.content_id())?;
                Ok((configuration.scenario(), configuration.scenario_artifact()))
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
                if path.segments().last().copied()
                    != Some(crate::BranchPathSegment::new(branch_point, edge))
                {
                    return Err(integrity("attempt-branch-path-terminal-scope-mismatch"));
                }
                Ok((parent.scenario(), parent.scenario_artifact()))
            }
            AttemptStart::AfterAttempt { .. } => Err(integrity("attempt-continuation-root-shape")),
        }
    }

    /// Caches the validated attempt and a bounded prefix of its origins.
    ///
    /// Validation proved every link back to the anchor, so the prefix nearest
    /// the requested attempt is re-read and cached until the anchor, the root,
    /// or the fill bound. Reads that walk the same chain then stop early.
    fn cache_validated_attempt_chain(
        &self,
        id: ContentId,
        attempt: Attempt,
        lineage: AttemptLineage,
        cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let path = attempt.path();
        let mut current = (id, attempt);

        for _ in 0..MAX_ATTEMPT_CHAIN_CACHE_FILL {
            let (current_id, current_attempt) = current;
            let origin = match current_attempt.start() {
                AttemptStart::AfterAttempt { origin, .. } => Some(origin.content_id()),
                AttemptStart::Discover { .. } | AttemptStart::Branch { .. } => None,
            };
            cache.validated_attempts.insert(
                current_id,
                ValidatedAttempt {
                    attempt: current_attempt,
                    path,
                    lineage,
                },
            );

            let Some(origin) = origin.filter(|id| !cache.validated_attempts.contains_key(id))
            else {
                break;
            };
            current = (origin, self.read_attempt_record(origin)?);
        }
        Ok(())
    }

    /// Extends a cached validated continuation to its immediate origin.
    ///
    /// A validated chain vouches for every origin, so caching the next one on
    /// each hit lets a newest-to-oldest walk of an arbitrarily long chain, as
    /// closure traversal performs, validate each link with constant reads.
    /// This is best effort: a failed read only forgoes the cache entry, and
    /// reading that origin itself reports the failure.
    fn cache_validated_attempt_origin(
        &self,
        validated: &ValidatedAttempt,
        cache: &mut ChoiceValidationCache,
    ) {
        let AttemptStart::AfterAttempt { origin, .. } = validated.attempt.start() else {
            return;
        };
        let origin = origin.content_id();
        if cache.validated_attempts.contains_key(&origin) {
            return;
        }

        let Ok(attempt) = self.read_attempt_record(origin) else {
            return;
        };
        if attempt.path() == validated.path {
            cache.validated_attempts.insert(
                origin,
                ValidatedAttempt {
                    attempt,
                    path: validated.path,
                    lineage: validated.lineage,
                },
            );
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

/// Returns `lineage` when it matches the chain's expected lineage, if any.
fn match_attempt_lineage(
    expected: Option<AttemptLineage>,
    lineage: AttemptLineage,
) -> Result<AttemptLineage, CampaignRepositoryError> {
    if expected.is_some_and(|expected| expected != lineage) {
        return Err(integrity("attempt-continuation-lineage-mismatch"));
    }
    Ok(lineage)
}
