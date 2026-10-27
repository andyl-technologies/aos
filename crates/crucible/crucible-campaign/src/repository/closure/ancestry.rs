//! Checked complete-head ancestry replay.

use super::read::ClosureSemanticRead;
use super::*;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn validate_snapshot_ancestry(
        &mut self,
        mut content_id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
        maximum_depth: usize,
    ) -> Result<
        (
            usize,
            ProjectedState,
            ContentId,
            Option<DerivedBranchCheckpoint>,
        ),
        CampaignRepositoryError,
    > {
        enum LifecycleValidationAction {
            Control(CampaignControlAction),
            RequireRunning(&'static str),
        }

        let _operation = self.enter_operation();
        let mut snapshots = BTreeSet::new();
        let mut verified_roots = BTreeSet::new();
        let mut seen_commands = BTreeSet::new();
        let mut expected_lineage = None;
        let mut actions = Vec::new();
        let mut derived_branch = None;
        let mut validated_generator_policies = BTreeSet::new();

        for depth in 1..=maximum_depth.min(MAX_SNAPSHOT_ANCESTRY) {
            self.poll()?;
            if !self.insert_set(&mut snapshots, content_id)? {
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
                        match action {
                            LifecycleValidationAction::Control(action) => {
                                projected.apply(action)?;
                            }
                            LifecycleValidationAction::RequireRunning(reason) => {
                                if projected.visible != CampaignState::Running {
                                    return Err(integrity(reason));
                                }
                            }
                        }
                    }
                    return Ok((depth, projected, content_id, derived_branch));
                }
                (Some(parent), Some(transition)) => {
                    let (transition_fact, validated_planner_step) =
                        self.read_fact_with_planner_step(transition.content_id())?;
                    let parent_snapshot = self.read_snapshot(parent.content_id())?;
                    match &transition_fact {
                        CampaignFact::CampaignDerived(derivation) => {
                            self.validate_derivation_successor(
                                &parent_snapshot,
                                &loaded,
                                *derivation,
                                &mut validated_generator_policies,
                            )?;
                            if derived_branch.is_none() {
                                derived_branch = Some(DerivedBranchCheckpoint {
                                    snapshot: content_id,
                                    derivation: *derivation,
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
                                *parent,
                                *branch_point,
                                *opportunity,
                            )?;
                        }
                        CampaignFact::ControlRequested(request) => {
                            if !self.insert_set(&mut seen_commands, request.command)? {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_control_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                request,
                            )?;
                            self.push(
                                &mut actions,
                                LifecycleValidationAction::Control(request.action.clone()),
                            )?;
                        }
                        CampaignFact::PinCommandAccepted(request) => {
                            if !self.insert_set(&mut seen_commands, request.command)? {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_pin_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                request,
                            )?;
                        }
                        CampaignFact::DiscoveryRequested(request) => {
                            if !self.insert_set(&mut seen_commands, request.command)? {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_discovery_request_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                request,
                            )?;
                        }
                        CampaignFact::SavepointCaptureRequested(request) => {
                            if !self.insert_set(&mut seen_commands, request.command)? {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_savepoint_capture_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                request,
                                choice_cache,
                            )?;
                            self.push(
                                &mut actions,
                                LifecycleValidationAction::RequireRunning(
                                    "savepoint-capture-parent-is-not-running",
                                ),
                            )?;
                        }
                        CampaignFact::SavepointCaptureResolved(resolution) => {
                            if !self.insert_set(&mut seen_commands, resolution.command)? {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if resolution.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_savepoint_capture_resolution_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                resolution,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::SavepointContinuationSelected(selection) => {
                            if !self.insert_set(&mut seen_commands, selection.command)? {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            if selection.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_savepoint_continuation_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                selection,
                                choice_cache,
                            )?;
                            self.push(
                                &mut actions,
                                LifecycleValidationAction::RequireRunning(
                                    "savepoint-continuation-parent-is-not-running",
                                ),
                            )?;
                        }
                        CampaignFact::BranchRequestAccepted { request, summary } => {
                            let request_record = self.read_branch_request(*request)?;
                            if let BranchRequestCause::Operator(command) = request_record.cause()
                                && !self.insert_set(&mut seen_commands, command)?
                            {
                                return Err(integrity("snapshot-ancestry-reused-mutation-command"));
                            }
                            let expected_summary = self.branch_acceptance_summary(
                                parent_snapshot.snapshot.roots().graph,
                                &request_record,
                            )?;
                            if *summary != expected_summary {
                                return Err(integrity(
                                    "branch-request-acceptance-summary-mismatch",
                                ));
                            }
                            self.validate_branch_request_successor(
                                &parent_snapshot,
                                &loaded,
                                *request,
                                transition.content_id(),
                            )?;
                        }
                        CampaignFact::ProposalIssued(proposal) => {
                            self.validate_proposal_successor(&parent_snapshot, &loaded, *proposal)?;
                        }
                        CampaignFact::AttemptAdmitted(admission) => {
                            self.validate_attempt_admission_successor(
                                &parent_snapshot,
                                &loaded,
                                *admission,
                            )?;
                        }
                        CampaignFact::PlannerAdvanced(step) => {
                            let validated_step =
                                validated_planner_step.as_ref().ok_or_else(|| {
                                    integrity("planner-step-transition-fact-was-not-validated")
                                })?;
                            self.validate_planner_step_successor(
                                &parent_snapshot,
                                &loaded,
                                *step,
                                validated_step,
                            )?;
                        }
                        CampaignFact::ObservationCredited(observation) => {
                            self.validate_credited_observation_successor(
                                &parent_snapshot,
                                &loaded,
                                *observation,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::FindingPublished(finding) => {
                            self.validate_finding_successor(
                                &parent_snapshot,
                                &loaded,
                                *finding,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::ObjectiveEvaluationPublished(evaluation) => {
                            self.validate_objective_evaluation_successor(
                                &parent_snapshot,
                                &loaded,
                                *evaluation,
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
                                *attempt,
                                *ordinal,
                                *disposition,
                            )?;
                        }
                        _ => {
                            return Err(integrity("snapshot-transition-type-is-not-implemented"));
                        }
                    }
                    self.validate_budget_successor(&parent_snapshot, &loaded, &transition_fact)?;
                    content_id = parent.content_id();
                }
                _ => return Err(integrity("snapshot-parent-transition-shape")),
            }
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    fn validate_genesis_snapshot(
        &mut self,
        loaded: &LoadedSnapshot,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_genesis_budget(&loaded.snapshot)?;
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        let roots = loaded.snapshot.roots();
        let expected_genesis = lineage.genesis_content().content_id();
        let corpus = self.merkle_inspect_shallow(roots.corpus)?;
        if corpus.entry_count() != 1
            || self.merkle_get(
                roots.corpus,
                map_key_hash("corpus.configuration", lineage.genesis().as_hash()),
            )? != Some(expected_genesis)
        {
            return Err(integrity("genesis-configuration-root-mismatch"));
        }
        let graph = self.merkle_inspect_shallow(roots.graph)?;
        if graph.entry_count() != 2
            || self.merkle_get(
                roots.graph,
                map_key_hash("graph.configuration", lineage.genesis().as_hash()),
            )? != Some(expected_genesis)
        {
            return Err(integrity("genesis-configuration-root-mismatch"));
        }
        let choice_index = self
            .merkle_get(roots.graph, choice_index_anchor_key())?
            .ok_or_else(|| integrity("genesis-choice-index-root-mismatch"))?;
        if self.merkle_inspect_shallow(choice_index)?.entry_count() != 0 {
            return Err(integrity("genesis-choice-index-root-mismatch"));
        }

        let exploration = self.merkle_inspect_shallow(roots.exploration)?;
        if exploration.entry_count() != 3 {
            return Err(integrity("genesis-exploration-index-root-mismatch"));
        }
        for (anchor, reason) in [
            (
                frontier_index_anchor_key(),
                "genesis-frontier-index-root-mismatch",
            ),
            (
                branch_request_index_anchor_key(),
                "genesis-branch-request-index-root-mismatch",
            ),
            (
                planner_scan_index_anchor_key(),
                "genesis-planner-scan-index-root-mismatch",
            ),
        ] {
            let index = self
                .merkle_get(roots.exploration, anchor)?
                .ok_or_else(|| integrity(reason))?;
            if self.merkle_inspect_shallow(index)?.entry_count() != 0 {
                return Err(integrity(reason));
            }
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
            if self.merkle_inspect_shallow(root)?.entry_count() != 0 {
                return Err(integrity("genesis-nonconfiguration-root-is-not-empty"));
            }
        }
        if empty_roots.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(integrity("genesis-empty-roots-are-not-canonical"));
        }
        Ok(())
    }

    fn validate_snapshot_references_once(
        &mut self,
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
            if self.insert_set(verified_roots, root)? {
                self.merkle_inspect_shallow(root)?;
            }
        }
        let roots = loaded.snapshot.roots();
        for (root, key, reason) in [
            (
                roots.graph,
                choice_index_anchor_key(),
                "current-campaign-choice-index-is-missing",
            ),
            (
                roots.exploration,
                frontier_index_anchor_key(),
                "current-campaign-frontier-index-is-missing",
            ),
            (
                roots.exploration,
                branch_request_index_anchor_key(),
                "current-campaign-branch-request-index-is-missing",
            ),
            (
                roots.exploration,
                planner_scan_index_anchor_key(),
                "current-campaign-planner-scan-index-is-missing",
            ),
        ] {
            self.merkle_get(root, key)?
                .ok_or_else(|| integrity(reason))?;
        }
        Ok(())
    }

    pub(super) fn parent_result_upsert(
        &mut self,
        content_id: ContentId,
        loaded: &LoadedSnapshot,
    ) -> Result<Option<(CampaignHash, ContentId)>, CampaignRepositoryError> {
        let Some(transition_content) = optional_child(&loaded.envelope, "transition") else {
            return Ok(None);
        };
        let (fact, validated_planner_step) =
            self.read_fact_with_planner_step(transition_content)?;
        let key = if let Some((step, _)) = validated_planner_step {
            Some(mutation_result_content_key(
                "planner",
                step.invocation().content_id(),
            ))
        } else {
            self.mutation_result_key(&fact)?
        };
        Ok(key.map(|key| (key, content_id)))
    }

    fn mutation_result_key(
        &mut self,
        fact: &CampaignFact,
    ) -> Result<Option<CampaignHash>, CampaignRepositoryError> {
        let key = match fact {
            CampaignFact::CampaignDerived(derivation) => {
                mutation_result_hash_key("derivation", derivation.basis_digest())
            }
            CampaignFact::ControlRequested(request) => {
                mutation_result_hash_key("control", request.command.as_hash())
            }
            CampaignFact::PinCommandAccepted(request) => {
                mutation_result_hash_key("pin", request.command.as_hash())
            }
            CampaignFact::DiscoveryRequested(request) => {
                mutation_result_hash_key("discovery", request.command.as_hash())
            }
            CampaignFact::SavepointCaptureRequested(request) => {
                mutation_result_hash_key("savepoint-capture", request.command.as_hash())
            }
            CampaignFact::SavepointCaptureResolved(resolution) => mutation_result_hash_key(
                "savepoint-capture-resolution",
                resolution.command.as_hash(),
            ),
            CampaignFact::SavepointContinuationSelected(selection) => {
                mutation_result_hash_key("savepoint-continuation", selection.command.as_hash())
            }
            CampaignFact::BranchRequestAccepted { request, .. } => {
                mutation_result_content_key("branch-request", request.content_id())
            }
            CampaignFact::ProposalIssued(proposal) => {
                mutation_result_content_key("proposal", proposal.content_id())
            }
            CampaignFact::AttemptAdmitted(admission) => {
                let admission = self.read_attempt_admission(admission.content_id())?;
                let proposal = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    }
                    | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => return Ok(None),
                };
                mutation_result_content_key("admission", proposal.content_id())
            }
            CampaignFact::PlannerAdvanced(step) => {
                let (step, _) = self.read_planner_step_with_request(step.content_id())?;
                mutation_result_content_key("planner", step.invocation().content_id())
            }
            CampaignFact::ObservationCredited(observation) => {
                mutation_result_content_key("observation", observation.content_id())
            }
            CampaignFact::ObjectiveEvaluationPublished(evaluation) => {
                mutation_result_content_key("objective-evaluation", evaluation.content_id())
            }
            CampaignFact::AttemptClosed { attempt, .. } => {
                mutation_result_content_key("attempt-closure", attempt.content_id())
            }
            CampaignFact::ChoiceOpportunityDiscovered {
                parent,
                opportunity,
                ..
            } => choice_discovery_result_key(*parent, *opportunity),
            _ => return Ok(None),
        };
        Ok(Some(key))
    }

    pub(in crate::repository) fn coordination_matches_parent_result(
        &mut self,
        parent: &LoadedSnapshot,
        next: ContentId,
    ) -> Result<bool, CampaignRepositoryError> {
        let mut upserts = BTreeMap::new();
        if let Some((key, value)) =
            self.parent_result_upsert(parent.envelope.content_id(), parent)?
        {
            self.insert_map(&mut upserts, key, value)?;
        }
        self.merkle_equals_after_upserts(parent.snapshot.roots().coordination, next, &upserts)
    }
}
