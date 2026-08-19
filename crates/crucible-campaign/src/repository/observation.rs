//! Exact observation publication and imported root-owner validation.

use super::*;

struct ObservationProjection {
    disposition: ObservationDisposition,
    graph: BTreeMap<CampaignHash, ContentId>,
    observations: BTreeMap<CampaignHash, ContentId>,
    corpus: BTreeMap<CampaignHash, ContentId>,
    coverage: BTreeMap<CampaignHash, ContentId>,
    accounting: BTreeMap<CampaignHash, ContentId>,
}

impl CampaignRepository {
    /// Publishes a canonical exact measurement set without advancing a campaign.
    ///
    /// # Errors
    ///
    /// Returns an error when referenced evidence is absent, corrupt, or cannot
    /// be stored and authenticated.
    pub fn publish_measurement_set(
        &self,
        value: &MeasurementSet,
    ) -> Result<MeasurementSetId, CampaignRepositoryError> {
        self.preflight_evidence_children(value.content_children())?;
        let content = self.put_measurement_set(value)?;
        MeasurementSetId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a canonical exact property-verdict set without advancing a campaign.
    ///
    /// # Errors
    ///
    /// Returns an error when referenced evidence is absent, corrupt, or cannot
    /// be stored and authenticated.
    pub fn publish_property_verdict_set(
        &self,
        value: &PropertyVerdictSet,
    ) -> Result<PropertyVerdictSetId, CampaignRepositoryError> {
        self.preflight_evidence_children(value.content_children())?;
        let content = self.put_property_verdict_set(value)?;
        PropertyVerdictSetId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a canonical exact coverage projection without advancing a campaign.
    ///
    /// # Errors
    ///
    /// Returns an error when referenced evidence is absent, corrupt, or cannot
    /// be stored and authenticated.
    pub fn publish_coverage_projection(
        &self,
        value: &CoverageProjection,
    ) -> Result<CoverageProjectionId, CampaignRepositoryError> {
        self.preflight_evidence_children(value.content_children())?;
        let content = self.put_coverage_projection(value)?;
        CoverageProjectionId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes one canonical or conflicting modeled observation atomically.
    ///
    /// The attempt must already have one authenticated execution-basis
    /// admission. Repeating the same observation returns its original
    /// transition. A different result for a completed attempt is retained in a
    /// conflict index without replacing the canonical graph child or evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale parent, unadmitted attempt, invalid evidence
    /// closure, strict-order gap, graph conflict, or failed final ref CAS.
    pub fn publish_observation(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        observation: &Observation,
    ) -> Result<ObservationResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;
        let mut choice_cache = ChoiceValidationCache::default();
        self.validate_observation_references_cached(observation, &mut choice_cache)?;

        let observation_id = observation.id()?;
        let attempt_key =
            map_key_content("observations.attempt", observation.attempt().content_id());
        let canonical = self
            .merkle
            .get(current.snapshot.roots().observations, attempt_key)?;
        if canonical == Some(observation_id.content_id())
            || (canonical.is_some()
                && self.merkle.get(
                    current.snapshot.roots().observations,
                    observation_conflict_key(observation.attempt(), observation_id),
                )? == Some(observation_id.content_id()))
        {
            return self
                .find_observation_result(current_content, observation_id)?
                .ok_or_else(|| integrity("observation-index-has-no-ancestry-transition"));
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }

        let projection = self.project_observation(
            &current,
            observation_id.content_id(),
            observation,
            &mut choice_cache,
        )?;
        self.preflight_observation_closure(&current, observation, &mut choice_cache)?;
        let observation_content = self.put_observation(observation)?;
        if observation_content != observation_id.content_id() {
            return Err(integrity("observation-publication-id-mismatch"));
        }

        let mut roots = current.snapshot.roots();
        roots.graph = self.insert_upserts(roots.graph, &projection.graph)?;
        roots.observations = self.insert_upserts(roots.observations, &projection.observations)?;
        roots.corpus = self.insert_upserts(roots.corpus, &projection.corpus)?;
        roots.coverage = self.insert_upserts(roots.coverage, &projection.coverage)?;
        roots.accounting = self.insert_upserts(roots.accounting, &projection.accounting)?;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;

        let fact = CampaignFact::ObservationPublished(observation_id);
        let transition_content = self.put_fact(&fact)?;
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let closure_growth_upper =
            observation_successor_growth(observation.discovered_choices().len())?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            closure_growth_upper,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(ObservationResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    observation: observation_id,
                    disposition: projection.disposition,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    pub(super) fn validate_observation_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        observation_id: ObservationId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("observation-transition-changed-campaign-basis"));
        }
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.exploration != next.exploration
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity("observation-transition-changed-unrelated-root"));
        }

        let observation = self.decode_observation(observation_id.content_id())?;
        let projection = self.project_observation(
            parent,
            observation_id.content_id(),
            &observation,
            choice_cache,
        )?;
        for (before, after, upserts, reason) in [
            (
                prior.graph,
                next.graph,
                &projection.graph,
                "observation-transition-graph-root",
            ),
            (
                prior.observations,
                next.observations,
                &projection.observations,
                "observation-transition-observations-root",
            ),
            (
                prior.corpus,
                next.corpus,
                &projection.corpus,
                "observation-transition-corpus-root",
            ),
            (
                prior.coverage,
                next.coverage,
                &projection.coverage,
                "observation-transition-coverage-root",
            ),
            (
                prior.accounting,
                next.accounting,
                &projection.accounting,
                "observation-transition-accounting-root",
            ),
        ] {
            if !self.merkle.equals_after_upserts(before, after, upserts)? {
                return Err(integrity(reason));
            }
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("observation-transition-coordination-root"));
        }
        Ok(())
    }

    fn project_observation(
        &self,
        parent: &LoadedSnapshot,
        observation_content: ContentId,
        observation: &Observation,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<ObservationProjection, CampaignRepositoryError> {
        self.validate_observation_references_cached(observation, choice_cache)?;
        let roots = parent.snapshot.roots();
        let lineage = self.read_lineage(required_child(&parent.envelope, "lineage")?)?;
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        if child.scenario() != lineage.scenario()
            || child.scenario_artifact() != lineage.scenario_content()
        {
            return Err(integrity("observation-child-lineage-mismatch"));
        }

        let observation_id = ObservationId::from_content_id(observation_content)?;
        let attempt_key =
            map_key_content("observations.attempt", observation.attempt().content_id());
        if let Some(canonical_content) = self.merkle.get(roots.observations, attempt_key)? {
            if canonical_content == observation_content
                || self
                    .merkle
                    .get(
                        roots.observations,
                        observation_conflict_key(observation.attempt(), observation_id),
                    )?
                    .is_some()
            {
                return Err(integrity("observation-transition-reuses-result"));
            }
            let canonical = ObservationId::from_content_id(canonical_content)?;
            return Ok(ObservationProjection {
                disposition: ObservationDisposition::DeterminismConflict { canonical },
                graph: BTreeMap::new(),
                observations: BTreeMap::from([(
                    observation_conflict_key(observation.attempt(), observation_id),
                    observation_content,
                )]),
                corpus: BTreeMap::new(),
                coverage: BTreeMap::new(),
                accounting: BTreeMap::new(),
            });
        }

        let (attempt, ordinal) = self.observation_execution_basis(roots.accounting, observation)?;
        self.validate_strict_observation_order(parent, ordinal)?;
        let mut graph = BTreeMap::from([(
            map_key_hash("graph.configuration", observation.child().as_hash()),
            observation.child_content().content_id(),
        )]);
        let corpus = BTreeMap::from([(
            map_key_hash("corpus.configuration", observation.child().as_hash()),
            observation.child_content().content_id(),
        )]);
        if let AttemptStart::Branch { edge, .. } = attempt.start() {
            graph.insert(
                map_key_hash("graph.branch-edge-child", edge.as_hash()),
                observation.child_content().content_id(),
            );
        }
        for choice_id in observation.discovered_choices() {
            let choice = self.read_opportunity_cached(choice_id.content_id(), choice_cache)?;
            graph.insert(
                map_key_content("graph.choice-opportunity", choice_id.content_id()),
                choice_id.content_id(),
            );
            graph.insert(
                branch_point_opportunity_key(
                    choice.branch_point_id(observation.child()),
                    *choice_id,
                ),
                choice_id.content_id(),
            );
        }
        self.validate_compatible_upserts(roots.graph, &graph, "observation-graph-conflict")?;
        self.validate_compatible_upserts(roots.corpus, &corpus, "observation-corpus-conflict")?;

        let mut observations = BTreeMap::from([
            (attempt_key, observation_content),
            (
                map_key_content("observations.observation", observation_content),
                observation_content,
            ),
            (
                map_key_content(
                    "observations.measurement-set",
                    observation.measurements().content_id(),
                ),
                observation.measurements().content_id(),
            ),
            (
                map_key_content(
                    "observations.property-verdict-set",
                    observation.properties().content_id(),
                ),
                observation.properties().content_id(),
            ),
            (
                map_key_content(
                    "observations.coverage-projection",
                    observation.coverage().content_id(),
                ),
                observation.coverage().content_id(),
            ),
        ]);
        observations.insert(
            map_key_content("observations.attempt-path", observation.path().content_id()),
            observation.path().content_id(),
        );
        let coverage = BTreeMap::from([(
            map_key_content("coverage.projection", observation.coverage().content_id()),
            observation.coverage().content_id(),
        )]);
        let mut accounting = BTreeMap::from([
            (
                map_key_content(
                    "accounting.attempt-observation",
                    observation.attempt().content_id(),
                ),
                observation_content,
            ),
            (
                map_key_hash("accounting.observation-ordinal", ordinal_hash(ordinal)),
                observation_content,
            ),
        ]);
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if policy.mode() == CampaignMode::Strict {
            accounting.insert(observation_sequence_key(), observation_content);
        }
        self.validate_compatible_upserts(
            roots.observations,
            &observations,
            "observation-index-conflict",
        )?;
        for key in [
            attempt_key,
            map_key_content("observations.observation", observation_content),
        ] {
            if self.merkle.get(roots.observations, key)?.is_some() {
                return Err(integrity("observation-index-reused"));
            }
        }
        self.validate_new_upserts(
            roots.accounting,
            &accounting,
            "observation-accounting-index-reused",
        )?;

        Ok(ObservationProjection {
            disposition: ObservationDisposition::Canonical,
            graph,
            observations,
            corpus,
            coverage,
            accounting,
        })
    }

    fn observation_execution_basis(
        &self,
        accounting: ContentId,
        observation: &Observation,
    ) -> Result<(Attempt, AdmissionOrdinal), CampaignRepositoryError> {
        let basis_content = self
            .merkle
            .get(
                accounting,
                map_key_content(
                    "accounting.attempt-execution-basis",
                    observation.attempt().content_id(),
                ),
            )?
            .ok_or_else(|| integrity("observation-attempt-is-not-admitted"))?;
        let basis = self.read_attempt_admission(basis_content)?;
        let AttemptAdmissionRole::ExecutionBasis {
            admission_ordinal, ..
        } = basis.role()
        else {
            return Err(integrity(
                "observation-attempt-basis-is-not-execution-basis",
            ));
        };
        if basis.attempt() != observation.attempt() {
            return Err(integrity("observation-attempt-basis-mismatch"));
        }
        Ok((
            self.read_attempt(observation.attempt().content_id())?,
            admission_ordinal,
        ))
    }

    fn validate_strict_observation_order(
        &self,
        parent: &LoadedSnapshot,
        ordinal: AdmissionOrdinal,
    ) -> Result<(), CampaignRepositoryError> {
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if policy.mode() != CampaignMode::Strict {
            return Ok(());
        }
        let expected = match self.merkle.get(
            parent.snapshot.roots().accounting,
            observation_sequence_key(),
        )? {
            None => 1,
            Some(previous) => {
                let previous = self.decode_observation(previous)?;
                let (_, previous_ordinal) = self
                    .observation_execution_basis(parent.snapshot.roots().accounting, &previous)?;
                previous_ordinal
                    .value()
                    .checked_add(1)
                    .ok_or_else(|| integrity("observation-sequence-overflow"))?
            }
        };
        if ordinal.value() != expected {
            return Err(integrity("strict-observation-order-gap"));
        }
        Ok(())
    }

    fn validate_compatible_upserts(
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

    fn validate_new_upserts(
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

    fn insert_upserts(
        &self,
        mut root: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
    ) -> Result<ContentId, CampaignRepositoryError> {
        for (key, value) in upserts {
            root = self.merkle.insert(root, *key, *value)?.content_id();
        }
        Ok(root)
    }

    fn preflight_evidence_children(
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

    fn preflight_observation_closure(
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

fn ordinal_hash(ordinal: AdmissionOrdinal) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-observation-ordinal.v1",
        &ordinal.value().to_be_bytes(),
    )
}
