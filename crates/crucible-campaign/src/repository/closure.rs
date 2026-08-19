//! Complete snapshot ancestry and reachable-object closure validation.

use super::*;

impl CampaignRepository {
    pub(super) fn validate_complete_head(
        &self,
        head: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_snapshot_ancestry(head)?;
        self.verify_campaign_closure(head)
    }

    pub(super) fn validate_snapshot_ancestry(
        &self,
        mut content_id: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        let mut snapshots = BTreeSet::new();
        let mut verified_roots = BTreeSet::new();
        let mut seen_commands = BTreeSet::new();
        let mut expected_lineage = None;
        let mut actions = Vec::new();

        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
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
                    return Ok(());
                }
                (Some(parent), Some(transition)) => {
                    let transition_fact = self.read_fact(transition.content_id())?;
                    let parent_snapshot = self.read_snapshot(parent.content_id())?;
                    match transition_fact {
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
                        _ => {
                            return Err(integrity("snapshot-transition-type-is-not-implemented"));
                        }
                    }
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
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        let roots = loaded.snapshot.roots();
        let expected_genesis = lineage.genesis_content().content_id();
        for (root, namespace) in [
            (roots.graph, "graph.configuration"),
            (roots.corpus, "corpus.configuration"),
        ] {
            let inspected = self.merkle.inspect_shallow(root)?;
            if inspected.entry_count() != 1
                || self
                    .merkle
                    .get(root, map_key_hash(namespace, lineage.genesis().as_hash()))?
                    != Some(expected_genesis)
            {
                return Err(integrity("genesis-configuration-root-mismatch"));
            }
        }

        let empty_roots = [
            roots.exploration,
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
        if child.snapshot.active_policy() != expected_policy {
            return Err(integrity("snapshot-transition-active-policy-mismatch"));
        }

        let prior_roots = parent.snapshot.roots();
        let next_roots = child.snapshot.roots();
        if prior_roots.graph != next_roots.graph
            || prior_roots.exploration != next_roots.exploration
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
            || prior_roots.coordination != next_roots.coordination
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
        Ok(())
    }

    pub(super) fn validate_branch_request_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        request: BranchRequestId,
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
            || prior_roots.accounting != next_roots.accounting
            || prior_roots.coordination != next_roots.coordination
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
        let upserts = BTreeMap::from([(request_key, request_content)]);
        if !self.merkle.equals_after_upserts(
            prior_roots.exploration,
            next_roots.exploration,
            &upserts,
        )? {
            return Err(integrity(
                "branch-request-transition-exploration-root-mismatch",
            ));
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
            || prior_roots.coordination != next_roots.coordination
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

        let upserts = BTreeMap::from([
            (proposal_key, proposal_content),
            (ordinal_key, proposal_content),
            (value_key, proposal_content),
        ]);
        if !self.merkle.equals_after_upserts(
            prior_roots.exploration,
            next_roots.exploration,
            &upserts,
        )? {
            return Err(integrity("proposal-transition-exploration-root-mismatch"));
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
            || prior_roots.exploration != next_roots.exploration
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
            || prior_roots.coordination != next_roots.coordination
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
                return Err(integrity("proposal-admission-is-discovery-basis"));
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
            || prior_roots.exploration != next_roots.exploration
            || prior_roots.observations != next_roots.observations
            || prior_roots.corpus != next_roots.corpus
            || prior_roots.coverage != next_roots.coverage
            || prior_roots.findings != next_roots.findings
            || prior_roots.pins != next_roots.pins
            || prior_roots.accounting != next_roots.accounting
        {
            return Err(integrity("planner-step-transition-changed-unrelated-root"));
        }

        let step_content = step_id.content_id();
        let step = self.read_planner_step(step_content)?;
        if matches!(step.disposition(), PlannerDisposition::Issue { .. }) {
            return Err(integrity("planner-step-issue-owner-is-not-implemented"));
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
        let upserts = BTreeMap::from([
            (step_key, step_content),
            (invocation_key, step_content),
            (planner_head_key(), step_content),
        ]);
        if !self.merkle.equals_after_upserts(
            prior_roots.coordination,
            next_roots.coordination,
            &upserts,
        )? {
            return Err(integrity(
                "planner-step-transition-coordination-root-mismatch",
            ));
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
                self.merkle.verify_closure(root)?;
            }
        }
        Ok(())
    }

    pub(super) fn verify_campaign_closure(
        &self,
        root: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        let mut stack = vec![root];
        let mut visited = BTreeSet::new();

        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue;
            }
            if visited.len() > MAX_CLOSURE_OBJECTS {
                return Err(integrity("campaign-closure-object-limit"));
            }

            if id.kind() == ObjectKind::MerkleNode {
                let verified = self.merkle.verify_closure_objects(id)?;
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
                crate::CampaignRecordKind::BranchRequest => {
                    self.read_branch_request(id)?;
                }
                crate::CampaignRecordKind::Proposal => {
                    self.read_proposal(id)?;
                }
                crate::CampaignRecordKind::Attempt => {
                    self.read_attempt(id)?;
                }
                crate::CampaignRecordKind::AttemptAdmission => {
                    self.read_attempt_admission(id)?;
                }
                crate::CampaignRecordKind::PlannerStep => {
                    self.read_planner_step(id)?;
                }
                crate::CampaignRecordKind::ExpansionState => {
                    self.read_expansion_state(id)?;
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
                    self.validate_opportunity_references(&envelope)?;
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
        Ok(())
    }
}
