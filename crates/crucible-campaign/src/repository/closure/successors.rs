//! Exact owner and Merkle-root validation for individual campaign successors.

use super::*;

impl CampaignRepository {
    pub(in crate::repository) fn validate_control_successor(
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
            if prior_policy.mode() == crate::CampaignMode::Statistical
                && next != parent.snapshot.active_policy()
            {
                return Err(integrity("statistical-policy-identity-is-immutable"));
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

    pub(in crate::repository) fn validate_pin_successor(
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

    pub(in crate::repository) fn validate_derivation_successor(
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
        if next_policy.scenario() != lineage.scenario()
            || !mode_derivation::derivation_modes_compatible(
                prior_policy.mode(),
                next_policy.mode(),
            )
            || (prior_policy.mode() == crate::CampaignMode::Statistical
                && derivation.active_policy() != parent.snapshot.active_policy())
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
        let accounting_upserts = self.derivation_accounting_upserts(
            prior_roots.accounting,
            prior_policy.mode(),
            next_policy.mode(),
        )?;
        let accounting_matches = self.merkle.equals_after_upserts(
            prior_roots.accounting,
            next_roots.accounting,
            &accounting_upserts,
        )?;
        if prior_roots.graph != next_roots.graph
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
            || !accounting_matches
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

    pub(in crate::repository) fn validate_branch_request_successor(
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
        let index = self.planner_scan_index_after(
            prior_roots.exploration,
            &[(request, request_record.branch_point())],
            None,
            false,
        )?;
        upserts.insert(planner_scan_index_anchor_key(), index);
        let domain = self.read_choice_domain(request_record.domain().content_id())?;
        let feedback_indexed = self
            .candidate_source_profile(&request_record, &domain)?
            .is_some_and(
                crate::repository::projection::CandidateSourceProfile::requires_feedback_index,
            );
        let frontier_index = self
            .merkle
            .get(prior_roots.exploration, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-frontier-index-is-missing"))?;
        let indexed_requests = feedback_indexed
            .then_some((request, request_record.branch_point()))
            .into_iter()
            .collect::<Vec<_>>();
        let next_index =
            self.branch_request_index_after(prior_roots.exploration, &indexed_requests, false)?;
        upserts.insert(branch_request_index_anchor_key(), next_index);
        if self
            .merkle
            .get(frontier_index, frontier_index_order_key(request))?
            .is_some()
        {
            return Err(integrity("branch-request-transition-reused-frontier-slot"));
        }
        let next_frontier = self.frontier_index_after(
            prior_roots.exploration,
            &[(
                request,
                request_record.branch_point(),
                self.initial_continuation_state_at(
                    &request_record,
                    crate::repository::projection::CandidateViewRoots::from_roots(prior_roots),
                )?,
            )],
            false,
        )?;
        upserts.insert(frontier_index_anchor_key(), next_frontier);
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
            | BranchRequestCause::ScenarioDefault(_)
            | BranchRequestCause::Debugger(_)
                if prior_roots.accounting != next_roots.accounting =>
            {
                return Err(integrity(
                    "branch-request-transition-changed-accounting-root",
                ));
            }
            BranchRequestCause::Planner(_)
            | BranchRequestCause::ExhaustivePolicy(_)
            | BranchRequestCause::ScenarioDefault(_)
            | BranchRequestCause::Debugger(_) => {}
        }
        if !self.coordination_matches_parent_result(parent, next_roots.coordination)? {
            return Err(integrity(
                "branch-request-transition-coordination-root-mismatch",
            ));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_choice_discovery_successor(
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
        let prior_choice_index = self
            .merkle
            .get(prior.graph, choice_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-choice-index-is-missing"))?;
        let mut upserts = BTreeMap::from([
            (
                authoritative_choice_key(opportunity_id),
                opportunity_id.content_id(),
            ),
            (scoped_key, opportunity_id.content_id()),
        ]);
        let next_choice_index = self.merkle.root_after_upserts(
            prior_choice_index,
            &BTreeMap::from([(
                choice_index_order_key(opportunity_id),
                opportunity_id.content_id(),
            )]),
        )?;
        upserts.insert(choice_index_anchor_key(), next_choice_index);
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

    pub(in crate::repository) fn validate_proposal_successor(
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
            (
                proposal_head_key(proposal_record.request()),
                proposal_content,
            ),
        ]);
        let frontier_index = self
            .merkle
            .get(prior_roots.exploration, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-frontier-index-is-missing"))?;
        let request = self.read_branch_request(proposal_record.request().content_id())?;
        let prior_state = self.continuation_state(
            crate::repository::projection::CandidateViewRoots::from_roots(prior_roots)
                .with_request_admissions(self.parent_budget_ledger(parent)?.request_admissions()),
            proposal_record.request(),
            &request,
        )?;
        self.validate_frontier_projection(
            frontier_index,
            proposal_record.request(),
            proposal_record.branch_point(),
            prior_state,
        )?;
        let next_frontier = self.frontier_index_after(
            prior_roots.exploration,
            &[(
                proposal_record.request(),
                proposal_record.branch_point(),
                crate::ContinuationState::Open,
            )],
            false,
        )?;
        upserts.insert(frontier_index_anchor_key(), next_frontier);
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

    pub(in crate::repository) fn validate_attempt_admission_successor(
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
            self.expected_stored_proposal_admission(parent, proposal, admission_record.attempt())?;
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
        let frontier_index = self
            .merkle
            .get(prior_roots.exploration, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-frontier-index-is-missing"))?;
        let proposal_record = self.read_proposal(proposal.content_id())?;
        let request = self.read_branch_request(proposal_record.request().content_id())?;
        let prior_state = self.continuation_state(
            crate::repository::projection::CandidateViewRoots::from_roots(prior_roots)
                .with_request_admissions(self.parent_budget_ledger(parent)?.request_admissions()),
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
            // The child ledger is not trusted until budget-successor replay.
            // Scan this accounting view before accepting its frontier delta.
            crate::repository::projection::CandidateViewRoots::new(
                prior_roots.exploration,
                next_roots.observations,
                next_roots.corpus,
                next_roots.accounting,
            )
            .with_unpublished_accounting(),
            proposal_record.request(),
            &request,
        )?;
        let next_frontier = self.frontier_index_after(
            prior_roots.exploration,
            &[(
                proposal_record.request(),
                proposal_record.branch_point(),
                next_state,
            )],
            false,
        )?;
        if !self.merkle.equals_after_upserts(
            prior_roots.exploration,
            next_roots.exploration,
            &BTreeMap::from([(frontier_index_anchor_key(), next_frontier)]),
        )? {
            return Err(integrity(
                "attempt-admission-transition-frontier-root-mismatch",
            ));
        }
        if !self.coordination_matches_parent_result(parent, next_roots.coordination)? {
            return Err(integrity(
                "attempt-admission-transition-coordination-root-mismatch",
            ));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_step_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        step_id: PlannerStepId,
        validated_step: &(PlannerStep, PlannerRequest),
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
        let (step, request) = validated_step;
        if step.id()?.content_id() != step_content
            || request.id()?.content_id() != step.request().content_id()
        {
            return Err(integrity(
                "planner-step-transition-validated-record-mismatch",
            ));
        }
        self.validate_builtin_planner_step(request, step)?;
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
        self.validate_planner_selected_source(&expected_view, step.disposition(), None)?;
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
            self.validate_planner_issue_projection(parent, child, step)?;
        } else if prior_roots.exploration != next_roots.exploration
            || prior_roots.accounting != next_roots.accounting
        {
            return Err(integrity("planner-step-transition-changed-semantic-root"));
        }
        Ok(())
    }
}
