//! Observation candidate evidence, exact index preflight, and bounded dependency closure.

use super::choice_sets::ChoiceSetCursor;
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

    /// Authenticates every produced selection against the discovered set.
    ///
    /// Both sets share one key order, so membership is one merge walk over
    /// their pages. Keys are unique per set, so a selection per opportunity is
    /// structural, and every discovery is resolved exactly when both sets have
    /// the same size.
    pub(in crate::repository) fn validate_observation_produced_selections(
        &self,
        observation: &Observation,
        child: &ConfigurationArtifact,
    ) -> Result<(), CampaignRepositoryError> {
        let mut discovered = ChoiceSetCursor::new(&self.merkle, observation.discovered_choices());
        let mut resolver = self.selection_resolver();
        self.for_each_produced_selection(observation, |key, selection| {
            loop {
                match discovered.next_entry()? {
                    Some((discovered_key, _)) if discovered_key < key => {}
                    Some((discovered_key, _)) if discovered_key == key => break,
                    _ => return Err(integrity("observation-produced-selection-choice-mismatch")),
                }
            }
            let resolved = resolver.resolve(selection)?;
            if choice_set_key(resolved.selection().opportunity()) != key
                || resolved.opportunity().scenario() != child.scenario()
            {
                return Err(integrity("observation-produced-selection-choice-mismatch"));
            }
            Ok(())
        })?;
        if observation.stop().reached_next_choice()
            && observation.produced_selections().entry_count()
                == observation.discovered_choices().entry_count()
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
            != candidate.resolved_effect_trace_manifest().is_some()
        {
            return Err(integrity("observation-candidate-trace-missing"));
        }
        // Segments are authenticated as publication streams them; the
        // candidate carries only the manifest bytes.
        if let Some(manifest) = candidate.resolved_effect_trace_manifest()
            && (manifest.len() > MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES
                || observation
                    .resolved_effect_trace()
                    .map(ResolvedEffectTraceRef::manifest)
                    != Some(ContentId::for_bytes(
                        ObjectKind::Trace,
                        crate::observation::RESOLVED_EFFECT_TRACE_MANIFEST_SCHEMA,
                        manifest,
                    )))
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

        // Re-derive both set roots from the carried bodies before any write.
        // Publication rebuilds the same roots in durable storage and compares
        // them again.
        let discovered_root = crate::observation::derive_choice_set_root(
            candidate
                .discovered_ids
                .iter()
                .map(|opportunity| (choice_set_key(*opportunity), opportunity.content_id())),
        )?;
        if discovered_root != observation.discovered_choices() {
            return Err(integrity("observation-candidate-choice-bundle-mismatch"));
        }
        let produced_entries = candidate
            .produced_selections()
            .iter()
            .map(|selection| {
                selection
                    .id()
                    .map(|id| (choice_set_key(selection.opportunity()), id.content_id()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if crate::observation::derive_choice_set_root(produced_entries)?
            != observation.produced_selections()
        {
            return Err(integrity("observation-produced-selection-bundle-mismatch"));
        }

        let mut validated_contracts = BTreeSet::new();
        let mut shared_choice_records = BTreeSet::new();
        for discovery in candidate.discovered_choices() {
            let choice = discovery.opportunity();
            if validated_contracts.insert((choice.declaration(), choice.domain())) {
                choice.validate_references(discovery.declaration(), discovery.domain())?;
                shared_choice_records.insert(choice.declaration().content_id());
                shared_choice_records.insert(choice.domain().content_id());
            }
            if choice.scenario() != child.scenario() {
                return Err(integrity("observation-choice-scenario-mismatch"));
            }
        }
        for selection in candidate.produced_selections() {
            let discovery = candidate
                .discovery(selection.opportunity())
                .ok_or_else(|| {
                    integrity("observation-produced-selection-opportunity-is-not-discovered")
                })?;
            selection.validate_resolved_references(discovery.opportunity(), discovery.domain())?;
        }
        if observation.stop().reached_next_choice()
            && candidate.produced_selections().len() == candidate.discovered_choices().len()
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
        // records, every unique discovered declaration and domain, every
        // opportunity and produced selection, and the nodes of both choice
        // sets. Digest keys keep the expected node count below one per entry
        // plus a root, which this preflight charges; the post-publication
        // closure walk charges the exact count. Traverse every
        // already-published dependency in one shared walk so independently
        // valid evidence trees cannot exceed the global closure bound only
        // after writes begin.
        let mut choice_cache = ChoiceValidationCache::default();
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
        let choice_entries = candidate
            .discovered_choices()
            .len()
            .checked_add(candidate.produced_selections().len())
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        let virtual_records = choice_entries
            .checked_mul(2)
            .and_then(|records| records.checked_add(2))
            .and_then(|records| records.checked_add(shared_choice_records.len()))
            .and_then(|records| records.checked_add(5))
            .and_then(|records| records.checked_add(owned_evidence.len()))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        if dependency_objects
            .checked_add(virtual_records)
            .is_none_or(|objects| objects > MAX_CANDIDATE_DEPENDENCY_OBJECTS)
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

        let roots = [
            observation.child_content().content_id(),
            observation.measurements().content_id(),
            observation.properties().content_id(),
            observation.coverage().content_id(),
            observation.discovered_choices().content_id(),
            observation.produced_selections().content_id(),
        ];
        self.verify_campaign_closures_anchored_cached(roots, &anchors, choice_cache)?;
        Ok(())
    }
}
