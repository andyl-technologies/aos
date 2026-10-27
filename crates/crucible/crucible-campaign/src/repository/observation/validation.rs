//! Checked replay of observation owner transitions and feedback indexes.

use super::*;
use crate::repository::closure::read::ClosureSemanticRead;
use crate::repository::projection::PROJECTION_SCAN_PAGE_ITEMS;

mod continuation;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn validate_credited_observation_successor(
        &mut self,
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
        let maintain_choice_index = self
            .merkle_get(prior.graph, choice_index_anchor_key())?
            .is_some();
        let projection = self.project_observation(
            parent,
            observation_id.content_id(),
            &observation,
            choice_cache,
            maintain_choice_index,
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
            if !self.merkle_equals_after_upserts(before, after, upserts)? {
                return Err(integrity(reason));
            }
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("observation-transition-coordination-root"));
        }
        Ok(())
    }

    fn project_observation(
        &mut self,
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
        if let Some(canonical_content) = self.merkle_get(roots.observations, attempt_key)? {
            if canonical_content == observation_content
                || self
                    .merkle_get(
                        roots.observations,
                        observation_conflict_key(observation.attempt(), observation_id),
                    )?
                    .is_some()
            {
                return Err(integrity("observation-transition-reuses-result"));
            }
            let canonical = ObservationId::from_content_id(canonical_content)?;
            let mut observations = BTreeMap::new();
            self.insert_map(
                &mut observations,
                observation_conflict_key(observation.attempt(), observation_id),
                observation_content,
            )?;
            return Ok(ObservationProjection {
                disposition: ObservationDisposition::DeterminismConflict { canonical },
                credits: Vec::new(),
                indexed_path: None,
                frontier_updates: Vec::new(),
                graph: BTreeMap::new(),
                choice_index: BTreeMap::new(),
                exploration: BTreeMap::new(),
                observations,
                corpus: BTreeMap::new(),
                coverage: BTreeMap::new(),
                accounting: BTreeMap::new(),
            });
        }

        let (attempt, ordinal) = self.observation_execution_basis(roots.accounting, observation)?;
        self.validate_strict_completion_order(parent, ordinal)?;
        let mut graph = BTreeMap::new();
        self.insert_map(
            &mut graph,
            map_key_hash("graph.configuration", observation.child().as_hash()),
            observation.child_content().content_id(),
        )?;
        let mut corpus = BTreeMap::new();
        self.insert_map(
            &mut corpus,
            map_key_hash("corpus.configuration", observation.child().as_hash()),
            observation.child_content().content_id(),
        )?;
        if let AttemptStart::Branch { edge, .. } = attempt.start() {
            self.insert_map(
                &mut graph,
                map_key_hash("graph.branch-edge-child", edge.as_hash()),
                observation.child_content().content_id(),
            )?;
        }
        for choice_id in observation.discovered_choices() {
            let choice = self.read_opportunity_cached(choice_id.content_id(), choice_cache)?;
            self.insert_map(
                &mut graph,
                map_key_content("graph.choice-opportunity", choice_id.content_id()),
                choice_id.content_id(),
            )?;
            self.insert_map(
                &mut graph,
                branch_point_opportunity_key(
                    choice.branch_point_id(observation.child()),
                    *choice_id,
                ),
                choice_id.content_id(),
            )?;
        }
        self.validate_compatible_upserts(roots.graph, &graph, "observation-graph-conflict")?;

        let mut choice_index_upserts = BTreeMap::new();
        if maintain_choice_index && !observation.discovered_choices().is_empty() {
            let choice_index = self
                .merkle_get(roots.graph, choice_index_anchor_key())?
                .unwrap_or(MerkleMap::empty_content_id()?);
            for choice_id in observation.discovered_choices() {
                self.insert_map(
                    &mut choice_index_upserts,
                    choice_index_order_key(*choice_id),
                    choice_id.content_id(),
                )?;
            }
            self.validate_compatible_upserts(
                choice_index,
                &choice_index_upserts,
                "observation-choice-index-conflict",
            )?;
            let next_choice_index =
                self.merkle_root_after_upserts(choice_index, &choice_index_upserts)?;
            self.insert_map(&mut graph, choice_index_anchor_key(), next_choice_index)?;
        }
        self.validate_compatible_upserts(roots.corpus, &corpus, "observation-corpus-conflict")?;

        let mut observations = BTreeMap::new();
        for (key, value) in [
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
            (
                map_key_content("observations.attempt-path", observation.path().content_id()),
                observation.path().content_id(),
            ),
        ] {
            self.insert_map(&mut observations, key, value)?;
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
            if self.merkle_get(roots.observations, key)?.is_some() {
                return Err(integrity("observation-index-reused"));
            }
        }

        let credits = self.expansion_credits(observation_id, &attempt)?;
        for credit in &credits {
            let anchor = branch_credit_index_key(credit.branch_point());
            let prior_credit_index = self
                .merkle_get(roots.observations, anchor)?
                .unwrap_or(MerkleMap::empty_content_id()?);
            if self
                .merkle_get(prior_credit_index, credit.id().as_hash())?
                .is_some()
            {
                return Err(integrity("expansion-credit-index-reused"));
            }
            let mut upserts = BTreeMap::new();
            self.insert_map(&mut upserts, credit.id().as_hash(), credit.content_id()?)?;
            let next_credit_index = self.merkle_root_after_upserts(prior_credit_index, &upserts)?;
            self.insert_map(&mut observations, anchor, next_credit_index)?;
        }

        let indexed_path = Some((observation.child_content(), observation.path()));
        if let Some((configuration, path)) = indexed_path {
            let anchor = configuration_path_index_key(configuration);
            let prior_path_index = self
                .merkle_get(roots.observations, anchor)?
                .unwrap_or(MerkleMap::empty_content_id()?);
            if let Some(existing) = self.merkle_get(prior_path_index, path_index_order_key(path))?
                && existing != path.content_id()
            {
                return Err(integrity("configuration-path-index-conflict"));
            }
            let mut upserts = BTreeMap::new();
            self.insert_map(&mut upserts, path_index_order_key(path), path.content_id())?;
            let next_path_index = self.merkle_root_after_upserts(prior_path_index, &upserts)?;
            self.insert_map(&mut observations, anchor, next_path_index)?;
        }

        let mut coverage = BTreeMap::new();
        self.insert_map(
            &mut coverage,
            map_key_content("coverage.projection", observation.coverage().content_id()),
            observation.coverage().content_id(),
        )?;
        let mut accounting = BTreeMap::new();
        self.insert_map(
            &mut accounting,
            map_key_content(
                "accounting.attempt-observation",
                observation.attempt().content_id(),
            ),
            observation_content,
        )?;
        self.insert_map(
            &mut accounting,
            observation_ordinal_key(ordinal),
            observation_content,
        )?;
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if policy.mode() == CampaignMode::Strict {
            self.insert_map(
                &mut accounting,
                observation_sequence_key(),
                observation_content,
            )?;
        }
        self.validate_new_upserts(
            roots.accounting,
            &accounting,
            "observation-accounting-index-reused",
        )?;

        let request_admissions = self.parent_budget_ledger(parent)?.request_admissions();
        let mut remaining_updates = MAX_FEEDBACK_FRONTIER_UPDATES;
        let mut frontier_updates = Vec::new();
        for credit in &credits {
            for request_id in self.branch_point_requests(
                roots.exploration,
                credit.branch_point(),
                &mut remaining_updates,
            )? {
                let request = self.read_branch_request(request_id)?;
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
                    .merkle_get(roots.exploration, frontier_index_anchor_key())?
                    .ok_or_else(|| integrity("progressive-generator-frontier-index-is-missing"))?;
                let prior_state = self.continuation_state_indexed(
                    roots,
                    request_admissions,
                    request_id,
                    &request,
                )?;
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
                let next_state = self.observation_continuation_state_after(
                    roots,
                    request_admissions,
                    request_id,
                    &request,
                    observation,
                    completed_visits,
                )?;
                self.push(
                    &mut frontier_updates,
                    (request_id, request.branch_point(), next_state),
                )?;
            }
        }
        let mut exploration = BTreeMap::new();
        if !frontier_updates.is_empty() {
            let next_frontier = self.frontier_index_after(roots.exploration, &frontier_updates)?;
            self.insert_map(&mut exploration, frontier_index_anchor_key(), next_frontier)?;
        }

        Ok(ObservationProjection {
            disposition: ObservationDisposition::Canonical,
            credits,
            indexed_path,
            frontier_updates,
            graph,
            choice_index: choice_index_upserts,
            exploration,
            observations,
            corpus,
            coverage,
            accounting,
        })
    }

    fn validate_compatible_upserts(
        &mut self,
        root: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        reason: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        for (key, value) in upserts {
            if self
                .merkle_get(root, *key)?
                .is_some_and(|prior| prior != *value)
            {
                return Err(integrity(reason));
            }
        }
        Ok(())
    }

    fn validate_new_upserts(
        &mut self,
        root: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        reason: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        for key in upserts.keys() {
            if self.merkle_get(root, *key)?.is_some() && *key != observation_sequence_key() {
                return Err(integrity(reason));
            }
        }
        Ok(())
    }

    fn expansion_credits(
        &mut self,
        observation: ObservationId,
        attempt: &Attempt,
    ) -> Result<Vec<ExpansionCredit>, CampaignRepositoryError> {
        let path = self.read_branch_path(attempt.path().content_id())?;
        let mut branch_points = BTreeSet::new();
        for segment in path.segments() {
            self.insert_set(&mut branch_points, segment.branch_point())?;
        }
        let mut credits = Vec::new();
        for branch_point in branch_points {
            self.push(
                &mut credits,
                ExpansionCredit::new(observation, branch_point),
            )?;
        }
        Ok(credits)
    }

    fn branch_point_requests(
        &mut self,
        exploration_root: ContentId,
        branch_point: crate::BranchPointId,
        remaining: &mut usize,
    ) -> Result<Vec<BranchRequestId>, CampaignRepositoryError> {
        let index = self
            .merkle_get(exploration_root, branch_request_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-branch-request-index-is-missing"))?;
        let index_entry_count = usize::try_from(self.merkle_inspect_shallow(index)?.entry_count())
            .map_err(|_| integrity("feedback-branch-request-index-limit"))?;
        if index_entry_count > MAX_FEEDBACK_FRONTIER_UPDATES {
            return Err(integrity("feedback-branch-request-index-limit"));
        }
        let Some(branch_root) =
            self.merkle_get(index, branch_request_index_branch_key(branch_point))?
        else {
            return Ok(Vec::new());
        };
        let entry_count = usize::try_from(self.merkle_inspect_shallow(branch_root)?.entry_count())
            .map_err(|_| integrity("feedback-frontier-update-limit"))?;
        *remaining = remaining
            .checked_sub(entry_count)
            .ok_or_else(|| integrity("feedback-frontier-update-limit"))?;

        let mut requests = Vec::new();
        let mut after = None;
        loop {
            let page = self.merkle_scan(branch_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                let request = BranchRequestId::from_content_id(*value)?;
                if *key != frontier_index_order_key(request) {
                    return Err(integrity("branch-request-point-index-mismatch"));
                }
                if self.merkle_get(index, branch_request_index_membership_key(request))?
                    != Some(request.content_id())
                {
                    return Err(integrity("feedback-branch-request-membership-mismatch"));
                }
                self.push(&mut requests, request)?;
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if requests.len() != entry_count {
            return Err(integrity("branch-request-point-index-count-mismatch"));
        }
        Ok(requests)
    }
}
