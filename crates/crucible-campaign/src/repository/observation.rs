//! Exact observation publication and imported root-owner validation.

use super::*;

struct ObservationProjection {
    disposition: ObservationDisposition,
    credits: Vec<ExpansionCredit>,
    indexed_path: Option<(ConfigurationArtifactId, BranchPathId)>,
    graph: BTreeMap<CampaignHash, ContentId>,
    choice_index: BTreeMap<CampaignHash, ContentId>,
    observations: BTreeMap<CampaignHash, ContentId>,
    corpus: BTreeMap<CampaignHash, ContentId>,
    coverage: BTreeMap<CampaignHash, ContentId>,
    accounting: BTreeMap<CampaignHash, ContentId>,
}

#[derive(Clone, Copy)]
enum ObservationOwnerVersion {
    Legacy,
    Credits,
    ScopedPaths,
}

impl ObservationOwnerVersion {
    const fn credits(self) -> bool {
        !matches!(self, Self::Legacy)
    }

    const fn indexes_path(self) -> bool {
        matches!(self, Self::ScopedPaths)
    }
}

impl CampaignRepository {
    /// Publishes one fully validated immutable executor result without advancing a campaign.
    ///
    /// This is the executor-to-coordinator handoff. Validation authenticates
    /// the attempt, child scenario binding, modeled evidence, and discovered
    /// choices before the first bundle object is stored. The coordinator later
    /// incorporates the returned observation through [`Self::publish_observation`].
    ///
    /// # Errors
    ///
    /// Returns an error without writing a bundle member when the candidate or
    /// an already-published dependency is missing, corrupt, or inconsistent.
    /// Storage failure during publication may leave harmless content-addressed
    /// bundle members for ordinary garbage collection.
    pub fn publish_observation_candidate(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<ObservationId, CampaignRepositoryError> {
        self.validate_observation_candidate(candidate)?;

        let child = self.put_configuration_artifact(candidate.child())?;
        let measurements = self.put_measurement_set(candidate.measurements())?;
        let properties = self.put_property_verdict_set(candidate.properties())?;
        let coverage = self.put_coverage_projection(candidate.coverage())?;
        for choice in candidate.discovered_choices() {
            self.put_envelope(ObjectEnvelope::for_record(
                crate::CampaignRecordKind::ChoiceOpportunity,
                crate::object::content_children(choice.content_children())?,
                crate::codec::encode(choice),
            )?)?;
        }
        let observation = self.put_observation(candidate.observation())?;

        if child != candidate.observation().child_content().content_id()
            || measurements != candidate.observation().measurements().content_id()
            || properties != candidate.observation().properties().content_id()
            || coverage != candidate.observation().coverage().content_id()
            || observation != candidate.observation().id()?.content_id()
        {
            return Err(integrity("observation-candidate-publication-id-mismatch"));
        }
        self.verify_campaign_closure(observation)?;
        ObservationId::from_content_id(observation).map_err(Into::into)
    }

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

        let maintain_choice_index = self
            .merkle
            .get(current.snapshot.roots().graph, choice_index_anchor_key())?
            .is_some();
        let projection = self.project_observation(
            &current,
            observation_id.content_id(),
            observation,
            &mut choice_cache,
            maintain_choice_index,
            ObservationOwnerVersion::ScopedPaths,
        )?;
        self.preflight_observation_closure(&current, observation, &mut choice_cache)?;
        let observation_content = self.put_observation(observation)?;
        if observation_content != observation_id.content_id() {
            return Err(integrity("observation-publication-id-mismatch"));
        }
        for credit in &projection.credits {
            if self.put_expansion_credit(credit)? != credit.content_id()? {
                return Err(integrity("expansion-credit-publication-id-mismatch"));
            }
        }
        let mut roots = current.snapshot.roots();
        if let Some((configuration, path)) = projection.indexed_path {
            let anchor = configuration_path_index_key(configuration);
            let prior_path_index = self
                .merkle
                .get(roots.observations, anchor)?
                .unwrap_or(MerkleMap::empty_content_id()?);
            let published_path_index = self.insert_upserts(
                prior_path_index,
                &BTreeMap::from([(path_index_order_key(path), path.content_id())]),
            )?;
            if projection.observations.get(&anchor).copied() != Some(published_path_index) {
                return Err(integrity("configuration-path-index-publication-mismatch"));
            }
        }
        if !projection.choice_index.is_empty() {
            let prior_choice_index = self
                .merkle
                .get(roots.graph, choice_index_anchor_key())?
                .unwrap_or(MerkleMap::empty_content_id()?);
            let published_choice_index =
                self.insert_upserts(prior_choice_index, &projection.choice_index)?;
            if projection.graph.get(&choice_index_anchor_key()).copied()
                != Some(published_choice_index)
            {
                return Err(integrity("observation-choice-index-publication-mismatch"));
            }
        }
        for credit in &projection.credits {
            let anchor = branch_credit_index_key(credit.branch_point());
            let prior_credit_index = self
                .merkle
                .get(roots.observations, anchor)?
                .unwrap_or(MerkleMap::empty_content_id()?);
            let published_credit_index = self.insert_upserts(
                prior_credit_index,
                &BTreeMap::from([(credit.id().as_hash(), credit.content_id()?)]),
            )?;
            if projection.observations.get(&anchor).copied() != Some(published_credit_index) {
                return Err(integrity("expansion-credit-index-publication-mismatch"));
            }
        }
        roots.graph = self.insert_upserts(roots.graph, &projection.graph)?;
        roots.observations = self.insert_upserts(roots.observations, &projection.observations)?;
        roots.corpus = self.insert_upserts(roots.corpus, &projection.corpus)?;
        roots.coverage = self.insert_upserts(roots.coverage, &projection.coverage)?;
        roots.accounting = self.insert_upserts(roots.accounting, &projection.accounting)?;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;

        let fact = CampaignFact::ObservationCredited(observation_id);
        let transition_content = self.put_fact(&fact)?;
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let closure_growth_upper = observation_successor_growth(
            observation.discovered_choices().len(),
            projection.credits.len(),
            projection.indexed_path.is_some(),
        )?;
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
        if self
            .validate_observation_successor_version(
                parent,
                child,
                observation_id,
                choice_cache,
                ObservationOwnerVersion::Credits,
            )
            .is_ok()
        {
            return Ok(());
        }
        self.validate_observation_successor_version(
            parent,
            child,
            observation_id,
            choice_cache,
            ObservationOwnerVersion::Legacy,
        )
    }

    pub(super) fn validate_credited_observation_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        observation_id: ObservationId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_observation_successor_version(
            parent,
            child,
            observation_id,
            choice_cache,
            ObservationOwnerVersion::ScopedPaths,
        )
    }

    fn validate_observation_successor_version(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        observation_id: ObservationId,
        choice_cache: &mut ChoiceValidationCache,
        owner: ObservationOwnerVersion,
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
            self.merkle
                .get(prior.graph, choice_index_anchor_key())?
                .is_some(),
            owner,
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
        maintain_choice_index: bool,
        owner: ObservationOwnerVersion,
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
                credits: Vec::new(),
                indexed_path: None,
                graph: BTreeMap::new(),
                choice_index: BTreeMap::new(),
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
        let mut choice_index_upserts = BTreeMap::new();
        if maintain_choice_index && !observation.discovered_choices().is_empty() {
            let choice_index = self
                .merkle
                .get(roots.graph, choice_index_anchor_key())?
                .unwrap_or(MerkleMap::empty_content_id()?);
            for choice_id in observation.discovered_choices() {
                choice_index_upserts
                    .insert(choice_index_order_key(*choice_id), choice_id.content_id());
            }
            self.validate_compatible_upserts(
                choice_index,
                &choice_index_upserts,
                "observation-choice-index-conflict",
            )?;
            graph.insert(
                choice_index_anchor_key(),
                self.merkle
                    .root_after_upserts(choice_index, &choice_index_upserts)?,
            );
        }
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

        let credits = if owner.credits() {
            self.expansion_credits(observation_id, &attempt)?
        } else {
            Vec::new()
        };
        for credit in &credits {
            let anchor = branch_credit_index_key(credit.branch_point());
            let prior_credit_index = self
                .merkle
                .get(roots.observations, anchor)?
                .unwrap_or(MerkleMap::empty_content_id()?);
            if self
                .merkle
                .get(prior_credit_index, credit.id().as_hash())?
                .is_some()
            {
                return Err(integrity("expansion-credit-index-reused"));
            }
            observations.insert(
                anchor,
                self.merkle.root_after_upserts(
                    prior_credit_index,
                    &BTreeMap::from([(credit.id().as_hash(), credit.content_id()?)]),
                )?,
            );
        }
        let indexed_path = owner
            .indexes_path()
            .then_some((observation.child_content(), observation.path()));
        if let Some((configuration, path)) = indexed_path {
            let anchor = configuration_path_index_key(configuration);
            let prior_path_index = self
                .merkle
                .get(roots.observations, anchor)?
                .unwrap_or(MerkleMap::empty_content_id()?);
            if let Some(existing) = self
                .merkle
                .get(prior_path_index, path_index_order_key(path))?
                && existing != path.content_id()
            {
                return Err(integrity("configuration-path-index-conflict"));
            }
            observations.insert(
                anchor,
                self.merkle.root_after_upserts(
                    prior_path_index,
                    &BTreeMap::from([(path_index_order_key(path), path.content_id())]),
                )?,
            );
        }
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
        self.validate_new_upserts(
            roots.accounting,
            &accounting,
            "observation-accounting-index-reused",
        )?;

        Ok(ObservationProjection {
            disposition: ObservationDisposition::Canonical,
            credits,
            indexed_path,
            graph,
            choice_index: choice_index_upserts,
            observations,
            corpus,
            coverage,
            accounting,
        })
    }

    fn expansion_credits(
        &self,
        observation: ObservationId,
        attempt: &Attempt,
    ) -> Result<Vec<ExpansionCredit>, CampaignRepositoryError> {
        let path = self.read_branch_path(attempt.path().content_id())?;
        let mut branch_points = BTreeSet::new();
        if let Some(segments) = path.segments() {
            branch_points.extend(segments.iter().map(|segment| segment.branch_point()));
        } else if !path.edges().is_empty() {
            let AttemptStart::Branch {
                edge, selection, ..
            } = attempt.start()
            else {
                return Err(integrity("legacy-discovery-attempt-has-nonempty-path"));
            };
            let resolved = self.resolve_selection(selection)?;
            let crate::SelectionOrigin::CampaignBranch {
                branch_point,
                edge: selected_edge,
            } = resolved.selection().origin()
            else {
                return Err(integrity("legacy-branch-selection-origin-mismatch"));
            };
            if selected_edge != edge || path.edges().last() != Some(&edge) {
                return Err(integrity("legacy-branch-path-terminal-scope-mismatch"));
            }
            branch_points.insert(branch_point);
        }

        Ok(branch_points
            .into_iter()
            .map(|branch_point| ExpansionCredit::new(observation, branch_point))
            .collect())
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

    pub(super) fn validate_observation_candidate(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = candidate.observation();
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
        };

        if child.id()? != observation.child_content()
            || child.configuration() != observation.child()
            || candidate.measurements().id()? != observation.measurements()
            || candidate.properties().id()? != observation.properties()
            || candidate.coverage().id()? != observation.coverage()
            || attempt.path() != observation.path()
            || child.scenario() != start.scenario()
            || child.scenario_artifact() != start.scenario_artifact()
            || matches!(observation.stop(), StopOutcome::Reached(stop) if stop != attempt.stop())
        {
            return Err(integrity("observation-candidate-bundle-mismatch"));
        }

        let scenario = self.read_scenario_artifact(child.scenario_artifact().content_id())?;
        if scenario.scenario() != child.scenario() {
            return Err(integrity("observation-candidate-scenario-mismatch"));
        }

        let mut choice_bodies = BTreeMap::new();
        for choice in candidate.discovered_choices() {
            if choice_bodies.insert(choice.id()?, choice).is_some() {
                return Err(integrity("observation-candidate-choice-bundle-mismatch"));
            }
        }
        if choice_bodies.keys().copied().collect::<BTreeSet<_>>()
            != *observation.discovered_choices()
        {
            return Err(integrity("observation-candidate-choice-bundle-mismatch"));
        }
        let mut choice_cache = ChoiceValidationCache::default();
        for choice in choice_bodies.values() {
            let envelope = ObjectEnvelope::for_record(
                crate::CampaignRecordKind::ChoiceOpportunity,
                crate::object::content_children(choice.content_children())?,
                crate::codec::encode(*choice),
            )?;
            self.validate_opportunity_references_cached(&envelope, &mut choice_cache)?;
            if choice.scenario() != child.scenario() {
                return Err(integrity("observation-choice-scenario-mismatch"));
            }
        }
        if matches!(
            observation.stop(),
            StopOutcome::Reached(StopCondition::NextChoice)
        ) && observation.discovered_choices().is_empty()
        {
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

        // The final observation closure contains five fixed not-yet-published
        // records plus every newly discovered opportunity body.
        // records. Traverse every already-published dependency in one shared
        // walk so independently valid evidence trees cannot exceed the global
        // closure bound only after writes begin.
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
            )
            .chain(
                candidate
                    .discovered_choices()
                    .iter()
                    .flat_map(ChoiceOpportunity::content_children)
                    .map(|(_, id)| id),
            );
        let dependency_objects = self.verify_campaign_closures_anchored_cached(
            roots,
            &BTreeSet::new(),
            &mut choice_cache,
        )?;
        let virtual_records = candidate
            .discovered_choices()
            .len()
            .checked_add(5)
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        if dependency_objects
            .checked_add(virtual_records)
            .is_none_or(|objects| objects > MAX_CLOSURE_OBJECTS)
        {
            return Err(integrity("campaign-closure-object-limit"));
        }
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
