//! Complete snapshot ancestry and reachable-object closure validation.

use super::*;

impl CampaignRepository {
    pub(super) fn validate_complete_head(
        &self,
        head: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        self.load_validation_checkpoint(head).map(|_| ())
    }

    pub(super) fn load_validation_checkpoint(
        &self,
        head: ContentId,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        if let Some(checkpoint) = self.validation_checkpoints().get(&head).copied() {
            return Ok(checkpoint);
        }

        let mut choice_cache = ChoiceValidationCache::default();
        let (ancestry_depth, lifecycle, genesis, derived_branch) =
            self.validate_snapshot_ancestry(head, &mut choice_cache)?;
        let closure_objects = self.verify_campaign_closures_anchored_cached(
            [head],
            &BTreeSet::new(),
            &mut choice_cache,
        )?;
        let checkpoint = ValidationCheckpoint {
            ancestry_depth,
            closure_objects,
            lifecycle,
            genesis,
            derived_branch,
        };
        self.remember_validation_checkpoint(head, checkpoint);
        Ok(checkpoint)
    }

    pub(super) fn prepare_local_successor_checkpoint(
        &self,
        parent: ContentId,
        child: ContentId,
        action: Option<&CampaignControlAction>,
        closure_growth_upper: usize,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        // Transaction helpers have already authenticated their inputs and
        // constructed the exact owner delta. This final shape check prevents a
        // future caller from promoting an unrelated object while avoiding a
        // second walk over the immutable parent closure.
        let loaded = self.read_snapshot(child)?;
        if loaded.snapshot.parent().map(CampaignSnapshotId::content_id) != Some(parent)
            || optional_child(&loaded.envelope, "parent") != Some(parent)
            || loaded.snapshot.transition().is_none()
            || optional_child(&loaded.envelope, "transition").is_none()
        {
            return Err(integrity("local-successor-checkpoint-shape"));
        }
        let transition_content = optional_child(&loaded.envelope, "transition")
            .ok_or_else(|| integrity("local-successor-checkpoint-shape"))?;
        let parent_checkpoint = self.load_validation_checkpoint(parent)?;
        let derived_branch = match self.read_fact(transition_content)? {
            CampaignFact::CampaignDerived(derivation) => Some(DerivedBranchCheckpoint {
                snapshot: child,
                derivation,
            }),
            _ => parent_checkpoint.derived_branch,
        };
        let parent_snapshot = self.read_snapshot(parent)?;
        self.validate_budget_successor(
            &parent_snapshot,
            &loaded,
            &self.read_fact(transition_content)?,
        )?;
        let ancestry_depth = parent_checkpoint
            .ancestry_depth
            .checked_add(1)
            .ok_or_else(|| integrity("snapshot-ancestry-limit"))?;
        if ancestry_depth > MAX_SNAPSHOT_ANCESTRY {
            return Err(integrity("snapshot-ancestry-limit"));
        }
        let mut lifecycle = parent_checkpoint.lifecycle;
        if let Some(action) = action {
            lifecycle.apply(action)?;
        }
        // A transition may make a large, already-published object graph newly
        // reachable. Relative to exact parent-owned anchors, authenticate and
        // charge that complete new closure in addition to the conservative
        // bound for constructed snapshot and Merkle nodes, so a local
        // checkpoint never understates restart validation.
        let anchors = self.incremental_closure_anchors(&parent_snapshot, transition_content)?;
        let linked_objects = self.verify_campaign_closure_anchored(transition_content, &anchors)?;
        let closure_growth_upper = closure_growth_upper
            .checked_add(linked_objects)
            // The snapshot-owned ledger is childless and may be newly written.
            .and_then(|growth| growth.checked_add(1))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        let closure_objects = parent_checkpoint
            .closure_objects
            .checked_add(closure_growth_upper)
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        if closure_objects <= MAX_CAMPAIGN_CLOSURE_OBJECTS {
            return Ok(ValidationCheckpoint {
                ancestry_depth,
                closure_objects,
                lifecycle,
                genesis: parent_checkpoint.genesis,
                derived_branch,
            });
        }

        let mut choice_cache = ChoiceValidationCache::default();
        let (ancestry_depth, lifecycle, genesis, derived_branch) =
            self.validate_snapshot_ancestry(child, &mut choice_cache)?;
        let closure_objects = self.verify_campaign_closures_anchored_cached(
            [child],
            &BTreeSet::new(),
            &mut choice_cache,
        )?;
        Ok(ValidationCheckpoint {
            ancestry_depth,
            closure_objects,
            lifecycle,
            genesis,
            derived_branch,
        })
    }

    pub(super) fn promote_local_successor(
        &self,
        parent: ContentId,
        child: ContentId,
        checkpoint: ValidationCheckpoint,
    ) {
        let mut checkpoints = self.validation_checkpoints();
        checkpoints.remove(&parent);
        if checkpoints.len() >= MAX_VALIDATED_HEADS {
            checkpoints.clear();
        }
        checkpoints.insert(child, checkpoint);
    }

    pub(super) fn promote_local_branch(&self, child: ContentId, checkpoint: ValidationCheckpoint) {
        self.remember_validation_checkpoint(child, checkpoint);
    }

    pub(super) fn evict_local_checkpoint(&self, content: ContentId) {
        self.validation_checkpoints().remove(&content);
    }

    pub(super) fn current_lifecycle(
        &self,
        head: ContentId,
    ) -> Result<ProjectedState, CampaignRepositoryError> {
        Ok(self.load_validation_checkpoint(head)?.lifecycle)
    }

    fn remember_validation_checkpoint(&self, head: ContentId, checkpoint: ValidationCheckpoint) {
        let mut checkpoints = self.validation_checkpoints();
        if checkpoints.len() >= MAX_VALIDATED_HEADS {
            checkpoints.clear();
        }
        checkpoints.insert(head, checkpoint);
    }

    fn validation_checkpoints(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<ContentId, ValidationCheckpoint>> {
        match self.validated_heads.lock() {
            Ok(checkpoints) => checkpoints,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(super) fn validate_snapshot_ancestry(
        &self,
        mut content_id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<
        (
            usize,
            ProjectedState,
            ContentId,
            Option<DerivedBranchCheckpoint>,
        ),
        CampaignRepositoryError,
    > {
        let mut snapshots = BTreeSet::new();
        let mut verified_roots = BTreeSet::new();
        let mut seen_commands = BTreeSet::new();
        let mut expected_lineage = None;
        let mut actions = Vec::new();
        let mut derived_branch = None;
        let mut validated_generator_policies = BTreeSet::new();

        for depth in 1..=MAX_SNAPSHOT_ANCESTRY {
            if !snapshots.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            self.validate_snapshot_references_once(&loaded, &mut verified_roots)?;

            match expected_lineage {
                None => expected_lineage = Some(loaded.snapshot.lineage()),
                Some(lineage) if lineage != loaded.snapshot.lineage() => {
                    return Err(integrity("snapshot-ancestry-lineage-mismatch"));
                }
                Some(_) => {}
            }

            match (loaded.snapshot.parent(), loaded.snapshot.transition()) {
                (None, None) => {
                    self.validate_genesis_snapshot(&loaded)?;
                    actions.reverse();
                    let mut projected = ProjectedState::new();
                    for action in &actions {
                        projected.apply(action)?;
                    }
                    return Ok((depth, projected, content_id, derived_branch));
                }
                (Some(parent), Some(transition)) => {
                    let transition_fact = self.read_fact(transition.content_id())?;
                    let parent_snapshot = self.read_snapshot(parent.content_id())?;
                    let budget_fact = transition_fact.clone();
                    match transition_fact {
                        CampaignFact::CampaignDerived(derivation) => {
                            self.validate_derivation_successor(
                                &parent_snapshot,
                                &loaded,
                                derivation,
                                &mut validated_generator_policies,
                            )?;
                            if derived_branch.is_none() {
                                derived_branch = Some(DerivedBranchCheckpoint {
                                    snapshot: content_id,
                                    derivation,
                                });
                            }
                        }
                        CampaignFact::ChoiceOpportunityDiscovered {
                            parent,
                            branch_point,
                            opportunity,
                        } => {
                            self.validate_choice_discovery_successor(
                                &parent_snapshot,
                                &loaded,
                                parent,
                                branch_point,
                                opportunity,
                            )?;
                        }
                        CampaignFact::ControlRequested(request) => {
                            if !seen_commands.insert(request.command) {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_control_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &request,
                            )?;
                            actions.push(request.action);
                        }
                        CampaignFact::PinCommandAccepted(request) => {
                            if !seen_commands.insert(request.command) {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_pin_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &request,
                            )?;
                        }
                        CampaignFact::BranchRequestIssued(request) => {
                            let request_record = self.read_branch_request(request.content_id())?;
                            if let BranchRequestCause::Operator(command) = request_record.cause()
                                && !seen_commands.insert(command)
                            {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            self.validate_branch_request_successor(
                                &parent_snapshot,
                                &loaded,
                                request,
                                transition.content_id(),
                            )?;
                        }
                        CampaignFact::ProposalIssued(proposal) => {
                            self.validate_proposal_successor(&parent_snapshot, &loaded, proposal)?;
                        }
                        CampaignFact::AttemptAdmitted(admission) => {
                            self.validate_attempt_admission_successor(
                                &parent_snapshot,
                                &loaded,
                                admission,
                            )?;
                        }
                        CampaignFact::PlannerAdvanced(step) => {
                            self.validate_planner_step_successor(&parent_snapshot, &loaded, step)?;
                        }
                        CampaignFact::ObservationPublished(observation) => {
                            self.validate_observation_successor(
                                &parent_snapshot,
                                &loaded,
                                observation,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::ObservationCredited(observation) => {
                            self.validate_credited_observation_successor(
                                &parent_snapshot,
                                &loaded,
                                observation,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::FindingPublished(finding) => {
                            self.validate_finding_successor(
                                &parent_snapshot,
                                &loaded,
                                finding,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::ObjectiveEvaluationPublished(evaluation) => {
                            self.validate_objective_evaluation_successor(
                                &parent_snapshot,
                                &loaded,
                                evaluation,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::AttemptClosed {
                            attempt,
                            ordinal,
                            disposition,
                        } => {
                            self.validate_attempt_closed_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                attempt,
                                ordinal,
                                disposition,
                            )?;
                        }
                        _ => {
                            return Err(integrity("snapshot-transition-type-is-not-implemented"));
                        }
                    }
                    self.validate_budget_successor(&parent_snapshot, &loaded, &budget_fact)?;
                    content_id = parent.content_id();
                }
                _ => return Err(integrity("snapshot-parent-transition-shape")),
            }
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    pub(super) fn validate_genesis_snapshot(
        &self,
        loaded: &LoadedSnapshot,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_genesis_budget(&loaded.snapshot)?;
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        let roots = loaded.snapshot.roots();
        let expected_genesis = lineage.genesis_content().content_id();
        let corpus = self.merkle.inspect_shallow(roots.corpus)?;
        if corpus.entry_count() != 1
            || self.merkle.get(
                roots.corpus,
                map_key_hash("corpus.configuration", lineage.genesis().as_hash()),
            )? != Some(expected_genesis)
        {
            return Err(integrity("genesis-configuration-root-mismatch"));
        }
        let graph = self.merkle.inspect_shallow(roots.graph)?;
        let choice_index = self.merkle.get(roots.graph, choice_index_anchor_key())?;
        if !matches!(graph.entry_count(), 1 | 2)
            || self.merkle.get(
                roots.graph,
                map_key_hash("graph.configuration", lineage.genesis().as_hash()),
            )? != Some(expected_genesis)
        {
            return Err(integrity("genesis-configuration-root-mismatch"));
        }
        match choice_index {
            Some(index)
                if graph.entry_count() == 2
                    && self.merkle.inspect_shallow(index)?.entry_count() == 0 => {}
            None if graph.entry_count() == 1 => {}
            _ => return Err(integrity("genesis-choice-index-root-mismatch")),
        }

        let frontier_index = self
            .merkle
            .get(roots.exploration, frontier_index_anchor_key())?;
        let branch_request_index = self
            .merkle
            .get(roots.exploration, branch_request_index_anchor_key())?;
        let exploration = self.merkle.inspect_shallow(roots.exploration)?;
        match (frontier_index, branch_request_index) {
            (Some(index), None)
                if exploration.entry_count() == 1
                    && self.merkle.inspect_shallow(index)?.entry_count() == 0 => {}
            (Some(frontier), Some(requests))
                if exploration.entry_count() == 2
                    && self.merkle.inspect_shallow(frontier)?.entry_count() == 0
                    && self.merkle.inspect_shallow(requests)?.entry_count() == 0 => {}
            (None, None) if exploration.entry_count() == 0 => {}
            _ => return Err(integrity("genesis-frontier-index-root-mismatch")),
        }

        let empty_roots = [
            roots.observations,
            roots.coverage,
            roots.findings,
            roots.pins,
            roots.accounting,
            roots.coordination,
        ];
        for root in empty_roots {
            if self.merkle.inspect_shallow(root)?.entry_count() != 0 {
                return Err(integrity("genesis-nonconfiguration-root-is-not-empty"));
            }
        }
        if empty_roots.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(integrity("genesis-empty-roots-are-not-canonical"));
        }
        Ok(())
    }

    pub(super) fn validate_control_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        request: &ControlRequest,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage() {
            return Err(integrity("snapshot-transition-changed-lineage"));
        }

        let expected_policy = match request.action {
            CampaignControlAction::ActivatePolicy(policy) => policy,
            _ => parent.snapshot.active_policy(),
        };
        if let CampaignControlAction::ActivatePolicy(next) = request.action {
            let prior_policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
            let next_policy = self.read_policy(next.content_id())?;
            if prior_policy.mode() != next_policy.mode() {
                return Err(integrity("activated-policy-mode-mismatch"));
            }
        }
        if child.snapshot.active_policy() != expected_policy {
            return Err(integrity("snapshot-transition-active-policy-mismatch"));
        }

        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
        {
            return Err(integrity("control-transition-changed-nonaccounting-root"));
        }

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if self
            .merkle
            .get(prior_roots.accounting, command_key)?
            .is_some()
        {
            return Err(integrity("control-transition-reused-command"));
        }
        let mut upserts = BTreeMap::from([(command_key, transition_content)]);
        let auxiliary = match request.action {
            CampaignControlAction::ActivatePolicy(next) => Some(CampaignFact::PolicyActivated(
                PolicyActivation::new(parent.snapshot.active_policy(), next)?,
            )),
            CampaignControlAction::GrantBudget(grant) => Some(CampaignFact::BudgetGranted(grant)),
            _ => None,
        };
        if let Some(fact) = auxiliary {
            let content = fact.id()?.content_id();
            upserts.insert(map_key_content("accounting.fact", content), content);
        }
        if !self.merkle.equals_after_upserts(
            prior_roots.accounting,
            next_roots.accounting,
            &upserts,
        )? {
            return Err(integrity("control-transition-accounting-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next_roots.coordination)? {
            return Err(integrity("control-transition-coordination-root-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_pin_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        request: &PinRequest,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage() {
            return Err(integrity("snapshot-transition-changed-lineage"));
        }
        if child.snapshot.active_policy() != parent.snapshot.active_policy() {
            return Err(integrity("pin-transition-changed-active-policy"));
        }

        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
        {
            return Err(integrity("pin-transition-changed-unrelated-root"));
        }

        let configuration = request.change.configuration();
        let configuration_content = self
            .merkle
            .get(
                prior.graph,
                map_key_hash("graph.configuration", configuration.as_hash()),
            )?
            .ok_or_else(|| integrity("pin-configuration-is-not-in-campaign-graph"))?;
        let artifact = self.read_configuration_artifact(configuration_content)?;
        if artifact.configuration() != configuration {
            return Err(integrity("pin-configuration-index-mismatch"));
        }

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if self.merkle.get(prior.accounting, command_key)?.is_some() {
            return Err(integrity("pin-transition-reused-command"));
        }
        if !self.merkle.equals_after_upserts(
            prior.accounting,
            next.accounting,
            &BTreeMap::from([(command_key, transition_content)]),
        )? {
            return Err(integrity("pin-transition-accounting-root-mismatch"));
        }
        if !self.merkle.equals_after_upserts(
            prior.pins,
            next.pins,
            &BTreeMap::from([(pin_configuration_key(configuration), transition_content)]),
        )? {
            return Err(integrity("pin-transition-pins-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("pin-transition-coordination-root-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_derivation_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        derivation: CampaignDerivation,
        validated_generator_policies: &mut BTreeSet<CampaignPolicyId>,
    ) -> Result<(), CampaignRepositoryError> {
        let parent_id = CampaignSnapshotId::from_content_id(parent.envelope.content_id())?;
        if derivation.source() != parent_id {
            return Err(integrity("derivation-source-parent-mismatch"));
        }
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != derivation.active_policy()
        {
            return Err(integrity("derivation-transition-campaign-basis-mismatch"));
        }

        let lineage = self.read_lineage(parent.snapshot.lineage().content_id())?;
        let prior_policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        let next_policy = self.read_policy(derivation.active_policy().content_id())?;
        if next_policy.scenario() != lineage.scenario() || next_policy.mode() != prior_policy.mode()
        {
            return Err(integrity("derivation-policy-incompatible-with-source"));
        }
        if derivation.active_policy() != parent.snapshot.active_policy()
            && validated_generator_policies.insert(derivation.active_policy())
        {
            self.validate_stored_creation_generator_closure(&next_policy)?;
        }

        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
            || prior_roots.accounting != next_roots.accounting
        {
            return Err(integrity("derivation-transition-changed-semantic-root"));
        }
        if !self.coordination_matches_parent_result(parent, next_roots.coordination)? {
            return Err(integrity(
                "derivation-transition-coordination-root-mismatch",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_branch_request_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        request: BranchRequestId,
        transition_content: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "branch-request-transition-changed-campaign-basis",
            ));
        }

        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
        {
            return Err(integrity(
                "branch-request-transition-changed-unrelated-root",
            ));
        }

        let request_content = request.content_id();
        let request_record = self.read_branch_request(request_content)?;
        let parent_configuration =
            self.read_configuration_artifact(request_record.parent().content_id())?;
        self.validate_branch_request_campaign_scope(
            parent,
            &request_record,
            &parent_configuration,
        )?;
        let request_key = map_key_content("exploration.branch-request", request_content);
        if self
            .merkle
            .get(prior_roots.exploration, request_key)?
            .is_some()
        {
            return Err(integrity("branch-request-transition-reused-request"));
        }
        let mut upserts = BTreeMap::from([(request_key, request_content)]);
        let domain = self.read_choice_domain(request_record.domain().content_id())?;
        let feedback_indexed = self
            .candidate_source_profile(&request_record, &domain)?
            .is_some_and(super::projection::CandidateSourceProfile::requires_feedback_index);
        let frontier_index = self
            .merkle
            .get(prior_roots.exploration, frontier_index_anchor_key())?;
        if feedback_indexed && frontier_index.is_none() {
            return Err(integrity("progressive-generator-requires-frontier-index"));
        }
        let indexed_requests = feedback_indexed
            .then_some((request, request_record.branch_point()))
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(next_index) =
            self.branch_request_index_after(prior_roots.exploration, &indexed_requests, false)?
        {
            upserts.insert(branch_request_index_anchor_key(), next_index);
        }
        if let Some(frontier_index) = frontier_index {
            if self
                .merkle
                .get(frontier_index, frontier_index_order_key(request))?
                .is_some()
            {
                return Err(integrity("branch-request-transition-reused-frontier-slot"));
            }
            let next_frontier = self
                .frontier_index_after(
                    prior_roots.exploration,
                    &[(
                        request,
                        request_record.branch_point(),
                        self.initial_continuation_state_at(
                            &request_record,
                            super::projection::CandidateViewRoots::from_roots(prior_roots),
                        )?,
                    )],
                    false,
                )?
                .ok_or_else(|| integrity("branch-request-frontier-index-disappeared"))?;
            upserts.insert(frontier_index_anchor_key(), next_frontier);
        }
        if !self.merkle.equals_after_upserts(
            prior_roots.exploration,
            next_roots.exploration,
            &upserts,
        )? {
            return Err(integrity(
                "branch-request-transition-exploration-root-mismatch",
            ));
        }
        match request_record.cause() {
            BranchRequestCause::Operator(command) => {
                let command_key = map_key_hash("accounting.command", command.as_hash());
                if self
                    .merkle
                    .get(prior_roots.accounting, command_key)?
                    .is_some()
                {
                    return Err(integrity("branch-request-transition-reused-command"));
                }
                if !self.merkle.equals_after_upserts(
                    prior_roots.accounting,
                    next_roots.accounting,
                    &BTreeMap::from([(command_key, transition_content)]),
                )? {
                    return Err(integrity(
                        "branch-request-transition-accounting-root-mismatch",
                    ));
                }
            }
            BranchRequestCause::Planner(_)
            | BranchRequestCause::ExhaustivePolicy(_)
            | BranchRequestCause::Debugger(_)
                if prior_roots.accounting != next_roots.accounting =>
            {
                return Err(integrity(
                    "branch-request-transition-changed-accounting-root",
                ));
            }
            BranchRequestCause::Planner(_)
            | BranchRequestCause::ExhaustivePolicy(_)
            | BranchRequestCause::Debugger(_) => {}
        }
        if !self.coordination_matches_parent_result(parent, next_roots.coordination)? {
            return Err(integrity(
                "branch-request-transition-coordination-root-mismatch",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_choice_discovery_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        parent_artifact_id: ConfigurationArtifactId,
        branch_point: crate::BranchPointId,
        opportunity_id: ChoiceOpportunityId,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("choice-discovery-changed-campaign-basis"));
        }
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
            || prior.accounting != next.accounting
        {
            return Err(integrity("choice-discovery-changed-unrelated-root"));
        }

        let opportunity = self.read_opportunity(opportunity_id.content_id())?;
        let parent_artifact = self.read_configuration_artifact(parent_artifact_id.content_id())?;
        let lineage = self.read_lineage(required_child(&parent.envelope, "lineage")?)?;
        if opportunity.scenario() != lineage.scenario()
            || parent_artifact.scenario() != lineage.scenario()
        {
            return Err(integrity("choice-discovery-scenario-mismatch"));
        }
        if self.merkle.get(
            prior.graph,
            map_key_hash(
                "graph.configuration",
                parent_artifact.configuration().as_hash(),
            ),
        )? != Some(parent_artifact_id.content_id())
        {
            return Err(integrity(
                "choice-discovery-parent-is-not-in-campaign-graph",
            ));
        }
        if opportunity.branch_point_id(parent_artifact.configuration()) != branch_point {
            return Err(integrity("choice-discovery-branch-point-mismatch"));
        }
        let scoped_key = branch_point_opportunity_key(branch_point, opportunity_id);
        if self.merkle.get(prior.graph, scoped_key)?.is_some() {
            return Err(integrity("choice-discovery-reused-opportunity"));
        }
        let prior_choice_index = self.merkle.get(prior.graph, choice_index_anchor_key())?;
        let mut upserts = BTreeMap::from([
            (
                authoritative_choice_key(opportunity_id),
                opportunity_id.content_id(),
            ),
            (scoped_key, opportunity_id.content_id()),
        ]);
        if let Some(prior_choice_index) = prior_choice_index {
            let next_choice_index = self.merkle.root_after_upserts(
                prior_choice_index,
                &BTreeMap::from([(
                    choice_index_order_key(opportunity_id),
                    opportunity_id.content_id(),
                )]),
            )?;
            upserts.insert(choice_index_anchor_key(), next_choice_index);
        }
        if !self
            .merkle
            .equals_after_upserts(prior.graph, next.graph, &upserts)?
        {
            return Err(integrity("choice-discovery-graph-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("choice-discovery-coordination-root-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_proposal_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        proposal: ProposalId,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("proposal-transition-changed-campaign-basis"));
        }

        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
            || prior_roots.accounting != next_roots.accounting
        {
            return Err(integrity("proposal-transition-changed-unrelated-root"));
        }

        let proposal_content = proposal.content_id();
        let proposal_record = self.read_proposal(proposal_content)?;
        self.validate_proposal_campaign_scope(parent, &proposal_record)?;
        let proposal_key = map_key_content("exploration.proposal", proposal_content);
        let ordinal_key =
            proposal_ordinal_key(proposal_record.request(), proposal_record.ordinal());
        let value_key = proposal_value_key(proposal_record.request(), proposal_record.value());
        for key in [proposal_key, ordinal_key, value_key] {
            if self.merkle.get(prior_roots.exploration, key)?.is_some() {
                return Err(integrity("proposal-transition-reused-proposal-slot"));
            }
        }
        if proposal_record.ordinal() > 1 {
            let prior_key =
                proposal_ordinal_key(proposal_record.request(), proposal_record.ordinal() - 1);
            let prior_content = self
                .merkle
                .get(prior_roots.exploration, prior_key)?
                .ok_or_else(|| integrity("proposal-transition-skipped-request-ordinal"))?;
            let prior = self.read_proposal(prior_content)?;
            if prior.request() != proposal_record.request()
                || prior.ordinal().checked_add(1) != Some(proposal_record.ordinal())
            {
                return Err(integrity("proposal-predecessor-index-mismatch"));
            }
        }

        let mut upserts = BTreeMap::from([
            (proposal_key, proposal_content),
            (ordinal_key, proposal_content),
            (value_key, proposal_content),
        ]);
        if let Some(frontier_index) = self
            .merkle
            .get(prior_roots.exploration, frontier_index_anchor_key())?
        {
            let request = self.read_branch_request(proposal_record.request().content_id())?;
            let prior_state = self.continuation_state(
                super::projection::CandidateViewRoots::from_roots(prior_roots),
                proposal_record.request(),
                &request,
            )?;
            self.validate_frontier_projection(
                frontier_index,
                proposal_record.request(),
                proposal_record.branch_point(),
                prior_state,
            )?;
            let next_frontier = self
                .frontier_index_after(
                    prior_roots.exploration,
                    &[(
                        proposal_record.request(),
                        proposal_record.branch_point(),
                        crate::ContinuationState::Open,
                    )],
                    false,
                )?
                .ok_or_else(|| integrity("proposal-frontier-index-disappeared"))?;
            upserts.insert(frontier_index_anchor_key(), next_frontier);
        }
        if !self.merkle.equals_after_upserts(
            prior_roots.exploration,
            next_roots.exploration,
            &upserts,
        )? {
            return Err(integrity("proposal-transition-exploration-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next_roots.coordination)? {
            return Err(integrity("proposal-transition-coordination-root-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_attempt_admission_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        admission: AttemptAdmissionId,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "attempt-admission-transition-changed-campaign-basis",
            ));
        }
        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
        {
            return Err(integrity(
                "attempt-admission-transition-changed-unrelated-root",
            ));
        }

        let admission_content = admission.content_id();
        let admission_record = self.read_attempt_admission(admission_content)?;
        let proposal = match admission_record.role() {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                ..
            }
            | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
            AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                return self.validate_initial_discovery_successor(parent, child, admission_record);
            }
        };
        let expected =
            self.expected_proposal_admission(parent, proposal, admission_record.attempt())?;
        if admission_record != expected || expected.id()? != admission {
            return Err(integrity("attempt-admission-owner-recomputation-mismatch"));
        }

        let upserts = attempt_admission_upserts(admission_content, admission_record)?;
        for key in upserts
            .keys()
            .copied()
            .filter(|key| *key != admission_sequence_key())
        {
            if self.merkle.get(prior_roots.accounting, key)?.is_some() {
                return Err(integrity("attempt-admission-transition-reused-index"));
            }
        }
        if !self.merkle.equals_after_upserts(
            prior_roots.accounting,
            next_roots.accounting,
            &upserts,
        )? {
            return Err(integrity(
                "attempt-admission-transition-accounting-root-mismatch",
            ));
        }
        match self
            .merkle
            .get(prior_roots.exploration, frontier_index_anchor_key())?
        {
            Some(frontier_index) => {
                let proposal_record = self.read_proposal(proposal.content_id())?;
                let request = self.read_branch_request(proposal_record.request().content_id())?;
                let prior_state = self.continuation_state(
                    super::projection::CandidateViewRoots::from_roots(prior_roots),
                    proposal_record.request(),
                    &request,
                )?;
                self.validate_frontier_projection(
                    frontier_index,
                    proposal_record.request(),
                    proposal_record.branch_point(),
                    prior_state,
                )?;
                let next_state = self.continuation_state(
                    super::projection::CandidateViewRoots::new(
                        prior_roots.exploration,
                        next_roots.observations,
                        next_roots.corpus,
                        next_roots.accounting,
                    ),
                    proposal_record.request(),
                    &request,
                )?;
                let next_frontier = self
                    .frontier_index_after(
                        prior_roots.exploration,
                        &[(
                            proposal_record.request(),
                            proposal_record.branch_point(),
                            next_state,
                        )],
                        false,
                    )?
                    .ok_or_else(|| integrity("attempt-admission-frontier-index-disappeared"))?;
                if !self.merkle.equals_after_upserts(
                    prior_roots.exploration,
                    next_roots.exploration,
                    &BTreeMap::from([(frontier_index_anchor_key(), next_frontier)]),
                )? {
                    return Err(integrity(
                        "attempt-admission-transition-frontier-root-mismatch",
                    ));
                }
            }
            None if prior_roots.exploration != next_roots.exploration => {
                return Err(integrity(
                    "attempt-admission-transition-changed-exploration-root",
                ));
            }
            None => {}
        }
        if !self.coordination_matches_parent_result(parent, next_roots.coordination)? {
            return Err(integrity(
                "attempt-admission-transition-coordination-root-mismatch",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_planner_step_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        step_id: PlannerStepId,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("planner-step-transition-changed-campaign-basis"));
        }
        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
        {
            return Err(integrity("planner-step-transition-changed-unrelated-root"));
        }

        let step_content = step_id.content_id();
        let step = self.read_planner_step(step_content)?;
        let request = self.read_planner_request(step.request().content_id())?;
        self.validate_builtin_planner_step(&request, &step)?;
        if request.expected_snapshot()
            != CampaignSnapshotId::from_content_id(parent.envelope.content_id())?
        {
            return Err(integrity(
                "planner-step-transition-request-snapshot-mismatch",
            ));
        }
        let invocation = self.load_planner_invocation(step.invocation())?;
        let expected_view = parent.snapshot.planning_view();
        if expected_view.id()? != step.input_view()
            || invocation.input_view() != step.input_view()
            || step.policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("planner-step-transition-input-basis-mismatch"));
        }
        self.validate_planner_page(&expected_view, &invocation)?;
        self.validate_planner_cursor(parent, step.disposition())?;
        self.validate_planner_disposition_page(&invocation, step.disposition())?;
        self.validate_planner_selected_source(&expected_view, step.disposition())?;
        let expected_parent =
            self.validate_planner_invocation_start(prior_roots.coordination, &invocation)?;
        if step.parent() != expected_parent {
            return Err(integrity("planner-step-transition-parent-mismatch"));
        }

        let step_key = planner_step_key(step_id);
        let invocation_key = planner_invocation_result_key(step.invocation());
        for key in [step_key, invocation_key] {
            if self.merkle.get(prior_roots.coordination, key)?.is_some() {
                return Err(integrity("planner-step-transition-reused-index"));
            }
        }
        let mut upserts = BTreeMap::from([
            (step_key, step_content),
            (invocation_key, step_content),
            (planner_head_key(), step_content),
        ]);
        if let Some((key, value)) =
            self.parent_result_upsert(parent.envelope.content_id(), parent)?
        {
            if self.merkle.get(prior_roots.coordination, key)?.is_some() {
                return Err(integrity("planner-step-transition-reused-result-index"));
            }
            upserts.insert(key, value);
        }
        if !self.merkle.equals_after_upserts(
            prior_roots.coordination,
            next_roots.coordination,
            &upserts,
        )? {
            return Err(integrity(
                "planner-step-transition-coordination-root-mismatch",
            ));
        }
        if matches!(step.disposition(), PlannerDisposition::Issue { .. }) {
            self.validate_planner_issue_projection(parent, child, &step)?;
        } else if prior_roots.exploration != next_roots.exploration
            || prior_roots.accounting != next_roots.accounting
        {
            return Err(integrity("planner-step-transition-changed-semantic-root"));
        }
        Ok(())
    }

    pub(super) fn validate_snapshot_references_once(
        &self,
        loaded: &LoadedSnapshot,
        verified_roots: &mut BTreeSet<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        if lineage.id()? != loaded.snapshot.lineage() {
            return Err(integrity("snapshot-lineage-logical-id"));
        }
        let policy = self.read_policy(required_child(&loaded.envelope, "active-policy")?)?;
        if policy.id()? != loaded.snapshot.active_policy()
            || policy.scenario() != lineage.scenario()
        {
            return Err(integrity("snapshot-policy-logical-id-or-scenario"));
        }
        for root in snapshot_roots(&loaded.snapshot) {
            if verified_roots.insert(root) {
                self.merkle.inspect_shallow(root)?;
            }
        }
        Ok(())
    }

    pub(super) fn verify_campaign_closure(
        &self,
        root: ContentId,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_campaign_closure_anchored(root, &BTreeSet::new())
    }

    fn incremental_closure_anchors(
        &self,
        parent: &LoadedSnapshot,
        transition: ContentId,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        let mut anchors = BTreeSet::from([
            parent.envelope.content_id(),
            parent.snapshot.lineage().content_id(),
            parent.snapshot.active_policy().content_id(),
        ]);
        anchors.extend(snapshot_roots(&parent.snapshot));

        // These immutable basis records were authenticated with the parent.
        // Anchor their direct reusable roots as well because a new transition
        // can reference them without passing through the basis record itself.
        for basis in [
            parent.snapshot.lineage().content_id(),
            parent.snapshot.active_policy().content_id(),
        ] {
            let handle = self.blobs.read(basis, None)?;
            let envelope =
                ObjectEnvelope::from_canonical_bytes(&handle.read_all(MAX_ENVELOPE_BYTES)?)?;
            if envelope.content_id() != basis {
                return Err(integrity("incremental-closure-anchor-envelope-id"));
            }
            anchors.extend(envelope.children().iter().map(crate::ChildReference::id));
        }

        let roots = parent.snapshot.roots();
        if let Some(step) = self.merkle.get(roots.coordination, planner_head_key())? {
            anchors.insert(step);
            let envelope =
                self.require_record_kind(step, crate::CampaignRecordKind::PlannerStep)?;
            anchors.extend(envelope.children().iter().map(crate::ChildReference::id));
        }

        match self.read_fact(transition)? {
            CampaignFact::CampaignDerived(_) => {}
            CampaignFact::BranchRequestIssued(request_id) => {
                let request = self.decode_branch_request(request_id.content_id())?;
                if let BranchRequestCause::Planner(invocation) = request.cause()
                    && self
                        .merkle
                        .get(
                            roots.coordination,
                            planner_invocation_result_key(invocation),
                        )?
                        .is_some()
                {
                    anchors.insert(invocation.content_id());
                }
            }
            CampaignFact::ProposalIssued(proposal_id) => {
                let proposal = self.decode_proposal(proposal_id.content_id())?;
                let request = proposal.request().content_id();
                if self.merkle.get(
                    roots.exploration,
                    map_key_content("exploration.branch-request", request),
                )? == Some(request)
                {
                    anchors.insert(request);
                }
                if let Some(invocation) = proposal.planner_invocation()
                    && self
                        .merkle
                        .get(
                            roots.coordination,
                            planner_invocation_result_key(invocation),
                        )?
                        .is_some()
                {
                    anchors.insert(invocation.content_id());
                }
            }
            CampaignFact::AttemptAdmitted(admission_id) => {
                let admission = self.decode_attempt_admission(admission_id.content_id())?;
                let proposal = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    }
                    | AttemptAdmissionRole::AdditionalCause { proposal } => Some(proposal),
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => None,
                };
                if let Some(proposal) = proposal {
                    let proposal = proposal.content_id();
                    if self.merkle.get(
                        roots.exploration,
                        map_key_content("exploration.proposal", proposal),
                    )? == Some(proposal)
                    {
                        anchors.insert(proposal);
                    }
                }
            }
            CampaignFact::PlannerAdvanced(step_id) => {
                let envelope = self.require_record_kind(
                    step_id.content_id(),
                    crate::CampaignRecordKind::PlannerStep,
                )?;
                let step = PlannerStep::from_canonical_bytes(envelope.body())?;
                if step.id()? != step_id {
                    return Err(integrity("planner-step-envelope-shape"));
                }
                let (_, invocation) =
                    self.decode_planner_invocation(step.invocation().content_id())?;
                let mut sources = invocation
                    .scan_page()
                    .positions()
                    .iter()
                    .map(|position| position.source().content_id())
                    .collect::<BTreeSet<_>>();
                if let Some(after) = invocation.scan_page().after() {
                    sources.insert(after.source().content_id());
                }
                for source in sources {
                    if self.merkle.get(
                        roots.exploration,
                        map_key_content("exploration.branch-request", source),
                    )? == Some(source)
                    {
                        anchors.insert(source);
                    }
                }
            }
            CampaignFact::ObservationPublished(observation_id)
            | CampaignFact::ObservationCredited(observation_id) => {
                let observation = self.decode_observation(observation_id.content_id())?;
                let attempt = observation.attempt().content_id();
                if self.merkle.get(
                    roots.accounting,
                    map_key_content("accounting.attempt", attempt),
                )? == Some(attempt)
                {
                    anchors.insert(attempt);
                }
            }
            CampaignFact::ObjectiveEvaluationPublished(evaluation_id) => {
                let evaluation = self.read_objective_evaluation(evaluation_id.content_id())?;
                anchors.insert(evaluation.observation().content_id());
            }
            CampaignFact::ChoiceOpportunityDiscovered { .. }
            | CampaignFact::ControlRequested(_)
            | CampaignFact::FindingPublished(_)
            | CampaignFact::AttemptClosed { .. }
            | CampaignFact::PolicyActivated(_)
            | CampaignFact::BudgetGranted(_)
            | CampaignFact::PinChanged(_)
            | CampaignFact::PinCommandAccepted(_) => {}
        }
        Ok(anchors)
    }

    fn verify_campaign_closure_anchored(
        &self,
        root: ContentId,
        anchors: &BTreeSet<ContentId>,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_campaign_closures_anchored_cached(
            [root],
            anchors,
            &mut ChoiceValidationCache::default(),
        )
    }

    /// Authenticates and returns every unique object in the supplied closures.
    ///
    /// The returned set includes Merkle nodes, Merkle leaf values, generic
    /// content envelopes, campaign records, and opaque leaves. All roots are
    /// verified as one bounded union, so shared subgraphs are charged once.
    /// This operation performs no writes and does not trust child references
    /// until the enclosing object has authenticated under its exact content ID.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when any root or descendant is
    /// missing, corrupt, semantically invalid, or the complete union exceeds
    /// the campaign closure bound.
    pub fn authenticated_closure_ids(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        let mut objects = BTreeSet::new();
        self.verify_campaign_closures_anchored_cached_collect(
            roots,
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
            Some(&mut objects),
        )?;
        Ok(objects)
    }

    pub(super) fn verify_campaign_closures_anchored_cached(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        anchors: &BTreeSet<ContentId>,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_campaign_closures_anchored_cached_collect(roots, anchors, choice_cache, None)
    }

    fn verify_campaign_closures_anchored_cached_collect(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        anchors: &BTreeSet<ContentId>,
        choice_cache: &mut ChoiceValidationCache,
        mut collected: Option<&mut BTreeSet<ContentId>>,
    ) -> Result<usize, CampaignRepositoryError> {
        let mut stack = roots.into_iter().collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut verified_merkle_positions = BTreeSet::new();

        while let Some(id) = stack.pop() {
            if anchors.contains(&id) {
                continue;
            }
            if !visited.insert(id) {
                continue;
            }
            if let Some(objects) = collected.as_deref_mut() {
                objects.insert(id);
            }
            if visited
                .len()
                .checked_add(verified_merkle_positions.len())
                .is_none_or(|objects| objects > MAX_CAMPAIGN_CLOSURE_OBJECTS)
            {
                return Err(integrity("campaign-closure-object-limit"));
            }

            if id.kind() == ObjectKind::MerkleNode {
                let verified = self
                    .merkle
                    .verify_closure_objects_cached(id, &mut verified_merkle_positions)?;
                if let Some(objects) = collected.as_deref_mut() {
                    objects.extend(
                        verified_merkle_positions
                            .iter()
                            .map(|(node, _prefix)| *node),
                    );
                }
                if visited
                    .len()
                    .checked_add(verified_merkle_positions.len())
                    .is_none_or(|objects| objects > MAX_CAMPAIGN_CLOSURE_OBJECTS)
                {
                    return Err(integrity("campaign-closure-object-limit"));
                }
                stack.extend(verified.values);
                continue;
            }

            let handle = self.blobs.read(id, None)?;
            if is_opaque_campaign_leaf(id.kind()) {
                let mut sink = std::io::sink();
                handle.copy_to(&mut sink)?;
                continue;
            }
            let bytes = handle.read_all(MAX_ENVELOPE_BYTES)?;
            if !is_campaign_record_kind(id.kind()) {
                let envelope = ContentEnvelope::from_canonical_bytes(&bytes)
                    .map_err(CampaignCodecError::from)?;
                if envelope.content_id(id.kind()) != id {
                    return Err(integrity("campaign-closure-envelope-id-mismatch"));
                }
                stack.extend(envelope.children().iter().map(crate::ChildReference::id));
                continue;
            }
            let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
            if envelope.content_id() != id {
                return Err(integrity("campaign-closure-envelope-id-mismatch"));
            }

            match envelope.record_kind() {
                crate::CampaignRecordKind::Lineage => {
                    self.read_lineage(id)?;
                }
                crate::CampaignRecordKind::Policy => {
                    self.read_policy(id)?;
                }
                crate::CampaignRecordKind::Fact => {
                    self.read_fact(id)?;
                }
                crate::CampaignRecordKind::CandidateGeneratorSpec => {
                    self.read_generator(id)?;
                }
                crate::CampaignRecordKind::ScenarioArtifact => {
                    self.read_scenario_artifact(id)?;
                }
                crate::CampaignRecordKind::ConfigurationArtifact => {
                    self.read_configuration_artifact(id)?;
                }
                crate::CampaignRecordKind::ReproductionArtifact => {
                    self.read_reproduction_artifact(id)?;
                }
                crate::CampaignRecordKind::Finding => {
                    self.read_finding_cached(id, choice_cache)?;
                }
                crate::CampaignRecordKind::BranchRequest => {
                    let request = self.decode_branch_request(id)?;
                    self.validate_branch_request_references_shallow(&request)?;
                }
                crate::CampaignRecordKind::Proposal => {
                    let proposal = self.decode_proposal(id)?;
                    self.validate_proposal_references_shallow(&proposal)?;
                }
                crate::CampaignRecordKind::Attempt => {
                    self.read_attempt(id)?;
                }
                crate::CampaignRecordKind::AttemptAdmission => {
                    let admission = self.decode_attempt_admission(id)?;
                    self.validate_attempt_admission_references_shallow(&admission)?;
                }
                crate::CampaignRecordKind::PlannerStep => {
                    self.read_planner_step(id)?;
                }
                crate::CampaignRecordKind::RetainedPlannerRequest => {
                    self.read_planner_request(id)?;
                }
                crate::CampaignRecordKind::ExpansionState => {
                    self.read_expansion_state(id)?;
                }
                crate::CampaignRecordKind::ContinuationProjection => {
                    self.read_continuation_projection(id)?;
                }
                crate::CampaignRecordKind::ExpansionCredit => {
                    self.read_expansion_credit(id)?;
                }
                crate::CampaignRecordKind::MeasurementSet => {
                    self.read_measurement_set(id)?;
                }
                crate::CampaignRecordKind::PropertyVerdictSet => {
                    self.read_property_verdict_set(id)?;
                }
                crate::CampaignRecordKind::CoverageProjection => {
                    self.read_coverage_projection(id)?;
                }
                crate::CampaignRecordKind::Observation => {
                    let observation = self.decode_observation(id)?;
                    self.validate_observation_references_cached(&observation, choice_cache)?;
                }
                crate::CampaignRecordKind::ObjectiveEvaluation => {
                    self.read_objective_evaluation_cached(id, choice_cache)?;
                }
                crate::CampaignRecordKind::RankingExplanation => {
                    self.read_ranking_explanation_cached(id, choice_cache)?;
                }
                crate::CampaignRecordKind::SurvivorSelection => {
                    self.read_survivor_selection_bundle_cached(id, choice_cache)?;
                }
                crate::CampaignRecordKind::PolicyArtifact => {
                    self.validate_policy_artifact_references(&envelope)?;
                }
                crate::CampaignRecordKind::PlannerState => {
                    self.validate_planner_state_references(&envelope)?;
                }
                crate::CampaignRecordKind::PlannerInvocation => {
                    self.validate_planner_invocation_references(&envelope)?;
                }
                crate::CampaignRecordKind::ChoiceOpportunity => {
                    self.validate_opportunity_references_cached(&envelope, choice_cache)?;
                }
                crate::CampaignRecordKind::ChoiceGroup => {
                    self.validate_group_references(&envelope)?;
                }
                crate::CampaignRecordKind::Selection => {
                    self.validate_selection_references(&envelope)?;
                }
                _ => {}
            }
            stack.extend(envelope.children().iter().map(crate::ChildReference::id));
        }
        visited
            .len()
            .checked_add(verified_merkle_positions.len())
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }
}
