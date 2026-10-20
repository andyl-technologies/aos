//! Observation candidate evidence, exact index preflight, and bounded dependency closure.

use super::*;

impl CampaignRepository {
    pub(in crate::repository::observation) fn validate_compatible_upserts(
        &self,
        root: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        reason: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        for (key, value) in upserts {
            if self
                .merkle
                .get(root, *key)?
                .is_some_and(|prior| prior != *value)
            {
                return Err(integrity(reason));
            }
        }
        Ok(())
    }

    pub(in crate::repository::observation) fn validate_new_upserts(
        &self,
        root: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        reason: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        for key in upserts.keys() {
            if self.merkle.get(root, *key)?.is_some() && *key != observation_sequence_key() {
                return Err(integrity(reason));
            }
        }
        Ok(())
    }

    pub(in crate::repository::observation) fn insert_upserts(
        &self,
        mut root: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
    ) -> Result<ContentId, CampaignRepositoryError> {
        for (key, value) in upserts {
            root = self.merkle.insert(root, *key, *value)?.content_id();
        }
        Ok(root)
    }

    pub(in crate::repository::observation) fn preflight_evidence_children(
        &self,
        children: impl IntoIterator<Item = (String, ContentId)>,
    ) -> Result<(), CampaignRepositoryError> {
        self.verify_campaign_closures_anchored_cached(
            children.into_iter().map(|(_, id)| id),
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
        )?;
        Ok(())
    }

    pub(in crate::repository) fn validate_observation_produced_selections(
        &self,
        observation: &Observation,
        child: &ConfigurationArtifact,
    ) -> Result<(), CampaignRepositoryError> {
        let selection_ids = observation
            .produced_selections()
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut selected_opportunities = BTreeSet::new();
        for resolved in self.resolve_selections(&selection_ids)? {
            if !observation
                .discovered_choices()
                .contains(&resolved.selection().opportunity())
                || resolved.opportunity().scenario() != child.scenario()
            {
                return Err(integrity("observation-produced-selection-choice-mismatch"));
            }
            if !selected_opportunities.insert(resolved.selection().opportunity()) {
                return Err(integrity(
                    "observation-produced-selection-opportunity-duplicate",
                ));
            }
        }
        if observation.stop().reached_next_choice()
            && observation
                .discovered_choices()
                .iter()
                .all(|opportunity| selected_opportunities.contains(opportunity))
        {
            return Err(integrity(
                "next-choice-observation-has-no-unresolved-choice",
            ));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_observation_candidate(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_observation_candidate_with_owned_evidence(candidate, &BTreeSet::new())
    }

    pub(in crate::repository) fn validate_observation_candidate_with_owned_evidence(
        &self,
        candidate: &ObservationCandidate,
        owned_evidence: &BTreeSet<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = candidate.observation();
        if observation.resolved_effect_trace().is_some()
            != candidate.resolved_effect_trace().is_some()
        {
            return Err(integrity("observation-candidate-trace-missing"));
        }
        if let Some(bytes) = candidate.resolved_effect_trace()
            && (bytes.len() > 64 * 1024 * 1024
                || observation.resolved_effect_trace()
                    != Some(ContentId::for_bytes(ObjectKind::Trace, 1, bytes)))
        {
            return Err(integrity("observation-candidate-trace-mismatch"));
        }
        let child = candidate.child();
        let attempt = self.read_attempt(observation.attempt().content_id())?;

        let start = match attempt.start() {
            AttemptStart::Discover { configuration } => {
                self.read_configuration_artifact(configuration.content_id())?
            }
            AttemptStart::Branch {
                parent, selection, ..
            } => {
                let parent = self.read_configuration_artifact(parent.content_id())?;
                let selection = self.resolve_selection(selection)?;
                if selection.opportunity().scenario() != parent.scenario() {
                    return Err(integrity(
                        "observation-attempt-opportunity-scenario-mismatch",
                    ));
                }
                parent
            }
            AttemptStart::AfterAttempt { reached, .. } => {
                self.read_configuration_artifact(reached.content_id())?
            }
        };

        if child.id()? != observation.child_content()
            || child.configuration() != observation.child()
            || candidate.measurements().id()? != observation.measurements()
            || candidate.properties().id()? != observation.properties()
            || candidate.coverage().id()? != observation.coverage()
            || attempt.path() != observation.path()
            || child.scenario() != start.scenario()
            || child.scenario_artifact() != start.scenario_artifact()
            || !observation
                .stop()
                .authenticates_requested_stop(attempt.stop())
        {
            return Err(integrity("observation-candidate-bundle-mismatch"));
        }

        let scenario = self.read_scenario_artifact(child.scenario_artifact().content_id())?;
        if scenario.scenario() != child.scenario() {
            return Err(integrity("observation-candidate-scenario-mismatch"));
        }

        let mut choice_bodies = BTreeMap::new();
        for discovery in candidate.discovered_choices() {
            let choice = discovery.opportunity();
            if choice_bodies.insert(choice.id()?, discovery).is_some() {
                return Err(integrity("observation-candidate-choice-bundle-mismatch"));
            }
        }
        if choice_bodies.keys().copied().collect::<BTreeSet<_>>()
            != *observation.discovered_choices()
        {
            return Err(integrity("observation-candidate-choice-bundle-mismatch"));
        }
        let mut choice_cache = ChoiceValidationCache::default();
        let mut virtual_choice_records = BTreeSet::new();
        for discovery in choice_bodies.values() {
            let choice = discovery.opportunity();
            choice.validate_references(discovery.declaration(), discovery.domain())?;
            virtual_choice_records.insert(discovery.declaration().id()?.content_id());
            virtual_choice_records.insert(discovery.domain().id()?.content_id());
            virtual_choice_records.insert(choice.id()?.content_id());
            if choice.scenario() != child.scenario() {
                return Err(integrity("observation-choice-scenario-mismatch"));
            }
        }
        let mut produced_selection_ids = BTreeSet::new();
        let mut selected_opportunities = BTreeSet::new();
        for selection in candidate.produced_selections() {
            if !produced_selection_ids.insert(selection.id()?)
                || !selected_opportunities.insert(selection.opportunity())
            {
                return Err(integrity("observation-produced-selection-bundle-duplicate"));
            }
            let discovery = choice_bodies.get(&selection.opportunity()).ok_or_else(|| {
                integrity("observation-produced-selection-opportunity-is-not-discovered")
            })?;
            selection.validate_resolved_references(discovery.opportunity(), discovery.domain())?;
            virtual_choice_records.insert(selection.id()?.content_id());
        }
        if produced_selection_ids != *observation.produced_selections() {
            return Err(integrity("observation-produced-selection-bundle-mismatch"));
        }
        if observation.stop().reached_next_choice()
            && choice_bodies
                .keys()
                .all(|opportunity| selected_opportunities.contains(opportunity))
        {
            return Err(integrity(
                "next-choice-observation-has-no-unresolved-choice",
            ));
        }
        if observation.stop().reached_next_choice() && observation.discovered_choices().is_empty() {
            return Err(integrity("next-choice-observation-has-no-choice"));
        }
        if let StopOutcome::AssertionFailure(property) = observation.stop()
            && candidate
                .properties()
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
            && candidate
                .properties()
                .properties()
                .get(property)
                .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
        {
            return Err(integrity(
                "assertion-observation-stop-has-no-failed-property",
            ));
        }

        // The final observation closure contains five fixed not-yet-published
        // records plus every unique discovered declaration, domain, and
        // opportunity and produced selection. Traverse every already-published dependency in one
        // shared walk so independently valid evidence trees cannot exceed the
        // global closure bound only after writes begin.
        let roots = std::iter::once(observation.attempt().content_id())
            .chain(child.content_children().into_iter().map(|(_, id)| id))
            .chain(
                candidate
                    .measurements()
                    .content_children()
                    .into_iter()
                    .map(|(_, id)| id),
            )
            .chain(
                candidate
                    .properties()
                    .content_children()
                    .into_iter()
                    .map(|(_, id)| id),
            )
            .chain(
                candidate
                    .coverage()
                    .content_children()
                    .into_iter()
                    .map(|(_, id)| id),
            );
        let dependency_objects = self.verify_campaign_closures_anchored_cached(
            roots,
            owned_evidence,
            &mut choice_cache,
        )?;
        let virtual_records = virtual_choice_records
            .len()
            .checked_add(5)
            .and_then(|records| records.checked_add(owned_evidence.len()))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        if dependency_objects
            .checked_add(virtual_records)
            .is_none_or(|objects| objects > MAX_CAMPAIGN_CLOSURE_OBJECTS)
        {
            return Err(integrity("campaign-closure-object-limit"));
        }
        Ok(())
    }

    pub(in crate::repository::observation) fn preflight_observation_closure(
        &self,
        parent: &LoadedSnapshot,
        observation: &Observation,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let mut anchors = BTreeSet::from([
            parent.envelope.content_id(),
            parent.snapshot.lineage().content_id(),
            parent.snapshot.active_policy().content_id(),
            observation.attempt().content_id(),
            observation.path().content_id(),
        ]);
        anchors.extend(snapshot_roots(&parent.snapshot));

        let roots = std::iter::once(observation.child_content().content_id())
            .chain(std::iter::once(observation.measurements().content_id()))
            .chain(std::iter::once(observation.properties().content_id()))
            .chain(std::iter::once(observation.coverage().content_id()))
            .chain(
                observation
                    .discovered_choices()
                    .iter()
                    .map(|id| id.content_id()),
            );
        self.verify_campaign_closures_anchored_cached(roots, &anchors, choice_cache)?;
        Ok(())
    }
}
