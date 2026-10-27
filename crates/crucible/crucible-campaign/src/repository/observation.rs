//! Exact observation publication and imported root-owner validation.

use super::*;
use crate::ObservationCondition;

struct ObservationProjection {
    disposition: ObservationDisposition,
    credits: Vec<ExpansionCredit>,
    direct_selection: Option<direct_selection::DirectSelectionIndexEntry>,
    indexed_path: Option<(ConfigurationArtifactId, BranchPathId)>,
    frontier_updates: Vec<(
        BranchRequestId,
        crate::BranchPointId,
        crate::ContinuationState,
    )>,
    graph: BTreeMap<CampaignHash, ContentId>,
    choice_index: BTreeMap<CampaignHash, ContentId>,
    choice_sources: BTreeMap<CampaignHash, ContentId>,
    exploration: BTreeMap<CampaignHash, ContentId>,
    observations: BTreeMap<CampaignHash, ContentId>,
    corpus: BTreeMap<CampaignHash, ContentId>,
    coverage: BTreeMap<CampaignHash, ContentId>,
    // Distinct frequency records named by the coverage upserts; publication
    // stores them before it advances the coverage root.
    coverage_frequencies: BTreeSet<crate::CoverageIdentityFrequency>,
    accounting: BTreeMap<CampaignHash, ContentId>,
}

mod candidate_validation;
mod choice_sets;

pub use choice_sets::{DiscoveredChoices, ProducedSelections};
mod direct_selection;
mod strict_order;

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

        for discovery in candidate.discovered_choices() {
            let domain = self.publish_choice_domain(discovery.domain())?;
            let declaration = self.publish_selectable(discovery.declaration())?;
            let opportunity = self.publish_choice_opportunity(discovery.opportunity())?;
            if domain != discovery.domain().id()?
                || declaration != discovery.declaration().id()?
                || opportunity != discovery.opportunity().id()?
            {
                return Err(integrity("observation-choice-publication-id-mismatch"));
            }
        }
        for selection in candidate.produced_selections() {
            if self.put_selection(selection)? != selection.id()?.content_id() {
                return Err(integrity("observation-selection-publication-id-mismatch"));
            }
        }
        self.publish_candidate_choice_sets(candidate)?;
        let child = self.put_configuration_artifact(candidate.child())?;
        let measurements = self.put_measurement_set(candidate.measurements())?;
        let properties = self.put_property_verdict_set(candidate.properties())?;
        let coverage = self.put_coverage_projection(candidate.coverage())?;
        if let (Some(manifest), Some(segments)) = (
            candidate.resolved_effect_trace_manifest(),
            candidate.resolved_effect_trace_segments(),
        ) {
            let trace = candidate
                .observation()
                .resolved_effect_trace()
                .ok_or_else(|| integrity("observation-trace-identity-missing"))?;
            self.publish_resolved_effect_trace(trace, manifest, segments)?;
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

    /// Publishes a segmented resolved-effect trace one segment at a time.
    ///
    /// Each segment is read from the producer's stores, authenticated against
    /// the identity the observation lists, and stored before the next one is
    /// read, so publication holds at most one segment in memory. The manifest
    /// leaf is stored last. A failure can leave earlier authenticated segments
    /// as unreferenced content-addressed leaves for ordinary collection.
    fn publish_resolved_effect_trace(
        &self,
        trace: &ResolvedEffectTraceRef,
        manifest_bytes: &[u8],
        sources: &SegmentSources,
    ) -> Result<(), CampaignRepositoryError> {
        for &segment in trace.segments() {
            if self.blobs.contains(segment)? {
                continue;
            }
            let bytes = sources
                .segment(segment)
                .map_err(|_| integrity("observation-trace-segment-unavailable"))?;
            if bytes.len() > MAX_SEGMENT_BYTES || !segment.authenticates(&bytes) {
                return Err(integrity("observation-trace-segment-mismatch"));
            }
            let receipt = self
                .blobs
                .put_if_absent(segment, &BlobHandle::from_bytes(bytes))?;
            if receipt.id != segment {
                return Err(integrity("observation-trace-publication-id-mismatch"));
            }
        }

        let manifest = trace.manifest();
        let receipt = self
            .blobs
            .put_if_absent(manifest, &BlobHandle::from_bytes(manifest_bytes.to_vec()))?;
        if receipt.id != manifest {
            return Err(integrity("observation-trace-publication-id-mismatch"));
        }
        Ok(())
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
        if self
            .merkle
            .get(
                current.snapshot.roots().accounting,
                non_modeled_attempt_key(observation.attempt()),
            )?
            .is_some()
        {
            return Err(CampaignRepositoryError::AlreadyExists);
        }
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
        if !projection.choice_sources.is_empty() {
            let prior_choice_sources = self.choice_source_index(roots.observations)?;
            let published_choice_sources =
                self.insert_upserts(prior_choice_sources, &projection.choice_sources)?;
            if projection
                .observations
                .get(&choice_source_index_anchor_key())
                .copied()
                != Some(published_choice_sources)
            {
                return Err(integrity(
                    "observation-choice-source-index-publication-mismatch",
                ));
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
        if let Some(entry) = &projection.direct_selection {
            let published = self.direct_selection_index_after(roots.observations, entry, true)?;
            if projection
                .observations
                .get(&direct_selection_index_anchor_key())
                .copied()
                != Some(published)
            {
                return Err(integrity("direct-selection-index-publication-mismatch"));
            }
        }
        if !projection.frontier_updates.is_empty() {
            let published =
                self.frontier_index_after(roots.exploration, &projection.frontier_updates, true)?;
            if projection
                .exploration
                .get(&frontier_index_anchor_key())
                .copied()
                != Some(published)
            {
                return Err(integrity("observation-frontier-index-publication-mismatch"));
            }
        }
        roots.graph = self.insert_upserts(roots.graph, &projection.graph)?;
        roots.exploration = self.insert_upserts(roots.exploration, &projection.exploration)?;
        roots.observations = self.insert_upserts(roots.observations, &projection.observations)?;
        roots.corpus = self.insert_upserts(roots.corpus, &projection.corpus)?;
        for frequency in &projection.coverage_frequencies {
            if self.put_coverage_identity_frequency(*frequency)? != frequency.content_id()? {
                return Err(integrity(
                    "coverage-identity-frequency-publication-id-mismatch",
                ));
            }
        }
        roots.coverage = self.insert_upserts(roots.coverage, &projection.coverage)?;
        roots.accounting = self.insert_upserts(roots.accounting, &projection.accounting)?;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;

        let fact = CampaignFact::ObservationCredited(observation_id);
        let transition_content = self.put_fact(&fact)?;
        let (next, budget_witness) = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let closure_growth_upper = observation_successor_growth(
            usize::try_from(observation.discovered_choices().entry_count())
                .map_err(|_| integrity("observation-successor-growth-overflow"))?,
            projection.credits.len(),
            projection.direct_selection.is_some(),
            projection.indexed_path.is_some(),
            projection.frontier_updates.len(),
            projection.coverage.len(),
        )?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            closure_growth_upper,
            &budget_witness,
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

    pub(super) fn validate_credited_observation_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        observation_id: ObservationId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_observation_successor_version(parent, child, observation_id, choice_cache)
    }

    fn validate_observation_successor_version(
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
        if prior.findings != next.findings || prior.pins != next.pins {
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
        )?;
        for (before, after, upserts, reason) in [
            (
                prior.exploration,
                next.exploration,
                &projection.exploration,
                "observation-transition-exploration-root",
            ),
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
                direct_selection: None,
                indexed_path: None,
                frontier_updates: Vec::new(),
                graph: BTreeMap::new(),
                choice_index: BTreeMap::new(),
                choice_sources: BTreeMap::new(),
                exploration: BTreeMap::new(),
                observations: BTreeMap::from([(
                    observation_conflict_key(observation.attempt(), observation_id),
                    observation_content,
                )]),
                corpus: BTreeMap::new(),
                coverage: BTreeMap::new(),
                coverage_frequencies: BTreeSet::new(),
                accounting: BTreeMap::new(),
            });
        }

        let (attempt, ordinal) = self.observation_execution_basis(roots.accounting, observation)?;
        self.validate_strict_completion_order(parent, ordinal)?;
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
        // The discovered set is read page by page. Its key order is also the
        // nested choice index's key order, so index upserts are its entries.
        let mut choice_index_upserts = BTreeMap::new();
        self.for_each_discovered_choice(observation, |choice_id| {
            let choice = self.read_opportunity_cached(choice_id.content_id(), choice_cache)?;
            graph.insert(
                map_key_content("graph.choice-opportunity", choice_id.content_id()),
                choice_id.content_id(),
            );
            graph.insert(
                branch_point_opportunity_key(
                    choice.branch_point_id(observation.child()),
                    choice_id,
                ),
                choice_id.content_id(),
            );
            if maintain_choice_index {
                choice_index_upserts
                    .insert(choice_index_order_key(choice_id), choice_id.content_id());
            }
            Ok(())
        })?;
        self.validate_compatible_upserts(roots.graph, &graph, "observation-graph-conflict")?;
        if !choice_index_upserts.is_empty() {
            let choice_index = self
                .merkle
                .get(roots.graph, choice_index_anchor_key())?
                .unwrap_or(MerkleMap::empty_content_id()?);
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

        let credits = self.expansion_credits(observation_id, &attempt)?;
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
        let direct_selection =
            self.direct_selection_index_entry(roots.observations, &attempt, observation_content)?;
        if let Some(entry) = &direct_selection {
            observations.insert(
                direct_selection_index_anchor_key(),
                self.direct_selection_index_after(roots.observations, entry, false)?,
            );
        }
        let indexed_path = Some((observation.child_content(), observation.path()));
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

        // The anchor is required for every current snapshot, even when this
        // observation discovers nothing, so a lineage cannot drop it silently.
        let choice_source_index = self.choice_source_index(roots.observations)?;
        let choice_source_upserts = self.choice_source_upserts(
            roots.accounting,
            choice_source_index,
            observation_content,
            observation,
            ordinal,
        )?;
        if !choice_source_upserts.is_empty() {
            observations.insert(
                choice_source_index_anchor_key(),
                self.merkle
                    .root_after_upserts(choice_source_index, &choice_source_upserts)?,
            );
        }

        let mut coverage = BTreeMap::from([(
            map_key_content("coverage.projection", observation.coverage().content_id()),
            observation.coverage().content_id(),
        )]);
        let coverage_frequencies =
            self.coverage_frequency_upserts(roots.coverage, observation.coverage(), &mut coverage)?;
        let mut accounting = BTreeMap::from([
            (
                map_key_content(
                    "accounting.attempt-observation",
                    observation.attempt().content_id(),
                ),
                observation_content,
            ),
            (observation_ordinal_key(ordinal), observation_content),
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

        let prior_candidate_view = super::projection::CandidateViewRoots::from_roots(roots)
            .with_request_admissions(self.parent_budget_ledger(parent)?.request_admissions());

        let mut remaining_updates = MAX_FEEDBACK_FRONTIER_UPDATES;
        let mut frontier_updates = Vec::new();
        for credit in &credits {
            for request_id in self.branch_point_requests(
                roots.exploration,
                credit.branch_point(),
                &mut remaining_updates,
            )? {
                let request = self.read_branch_request(request_id.content_id())?;
                if request.branch_point() != credit.branch_point() {
                    return Err(integrity("branch-request-point-index-scope-mismatch"));
                }
                let domain = self.read_choice_domain(request.domain().content_id())?;
                let Some(profile) = self.candidate_source_profile(&request, &domain)? else {
                    continue;
                };
                if !profile.requires_feedback_index() {
                    continue;
                }
                let frontier_index = self
                    .merkle
                    .get(roots.exploration, frontier_index_anchor_key())?
                    .ok_or_else(|| integrity("progressive-generator-frontier-index-is-missing"))?;
                let prior_state =
                    self.continuation_state(prior_candidate_view, request_id, &request)?;
                self.validate_frontier_projection(
                    frontier_index,
                    request_id,
                    request.branch_point(),
                    prior_state,
                )?;
                let completed_visits = self
                    .branch_completed_visits(roots.observations, request.branch_point())?
                    .checked_add(1)
                    .ok_or_else(|| integrity("expansion-completed-visit-count-overflow"))?;
                let next_state = self.continuation_state_after_observation(
                    prior_candidate_view,
                    request_id,
                    &request,
                    observation,
                    completed_visits,
                )?;
                frontier_updates.push((request_id, request.branch_point(), next_state));
            }
        }
        let mut exploration = BTreeMap::new();
        if !frontier_updates.is_empty() {
            let next_frontier =
                self.frontier_index_after(roots.exploration, &frontier_updates, false)?;
            exploration.insert(frontier_index_anchor_key(), next_frontier);
        }

        Ok(ObservationProjection {
            disposition: ObservationDisposition::Canonical,
            credits,
            direct_selection,
            indexed_path,
            frontier_updates,
            graph,
            choice_index: choice_index_upserts,
            choice_sources: choice_source_upserts,
            exploration,
            observations,
            corpus,
            coverage,
            coverage_frequencies,
            accounting,
        })
    }

    /// Adds one canonical observation's coverage to the global
    /// coverage-identity frequency index.
    ///
    /// Every identity of the coverage projection gains one count, except
    /// identities already at the saturation point, which add no upsert.
    /// Absent identities start at one. The returned records are the distinct
    /// values the upserts name.
    pub(super) fn coverage_frequency_upserts(
        &self,
        coverage_root: ContentId,
        coverage: crate::CoverageProjectionId,
        upserts: &mut BTreeMap<CampaignHash, ContentId>,
    ) -> Result<BTreeSet<crate::CoverageIdentityFrequency>, CampaignRepositoryError> {
        let projection = self.read_coverage_projection(coverage.content_id())?;
        let first = crate::CoverageIdentityFrequency::new(1)?;

        // Records are shared by value, so a campaign holds at most one per
        // count and this map stays small however many identities it serves.
        let mut decoded = BTreeMap::<ContentId, crate::CoverageIdentityFrequency>::new();
        let mut encoded = BTreeMap::<crate::CoverageIdentityFrequency, ContentId>::new();
        let mut records = BTreeSet::new();
        for identity in projection.identities() {
            let key = coverage_identity_frequency_key(*identity);
            let next = match self.merkle.get(coverage_root, key)? {
                None => first,
                Some(content) => {
                    let current = match decoded.get(&content) {
                        Some(current) => *current,
                        None => {
                            let current = self.read_coverage_identity_frequency(content)?;
                            decoded.insert(content, current);
                            current
                        }
                    };
                    if current.is_saturated() {
                        continue;
                    }
                    current.incremented()
                }
            };
            let content = match encoded.get(&next) {
                Some(content) => *content,
                None => {
                    let content = next.content_id()?;
                    encoded.insert(next, content);
                    content
                }
            };
            upserts.insert(key, content);
            records.insert(next);
        }
        Ok(records)
    }

    fn expansion_credits(
        &self,
        observation: ObservationId,
        attempt: &Attempt,
    ) -> Result<Vec<ExpansionCredit>, CampaignRepositoryError> {
        let path = self.read_branch_path(attempt.path().content_id())?;
        let mut branch_points = BTreeSet::new();
        branch_points.extend(path.segments().iter().map(|segment| segment.branch_point()));

        Ok(branch_points
            .into_iter()
            .map(|branch_point| ExpansionCredit::new(observation, branch_point))
            .collect())
    }

    pub(in crate::repository) fn observation_execution_basis(
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
}
