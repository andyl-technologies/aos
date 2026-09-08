//! Proposal, control, and pin mutation transactions.

use super::*;

impl CampaignRepository {
    /// Issues one finite-source proposal under the current planning view.
    ///
    /// Acceptance writes canonical proposal, request-ordinal, and request-value
    /// indexes as one exact exploration-root delta. Generated-source proposal
    /// enumeration remains fail-closed until its deterministic owner lands.
    /// Repeating an accepted exact proposal returns its original transition.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale precondition, nonauthoritative request,
    /// noncanonical finite order, duplicate ordinal or value, invalid closure,
    /// exhausted aggregate proposal allowance, publication failure, or final
    /// authoritative-ref conflict.
    pub fn issue_proposal(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        proposal: &Proposal,
    ) -> Result<ProposalResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let proposal_id = proposal.id()?;
        let proposal_key = map_key_content("exploration.proposal", proposal_id.content_id());
        if self
            .merkle
            .get(current.snapshot.roots().exploration, proposal_key)?
            .is_some()
        {
            return self
                .find_proposal_result(current_content, proposal_id)?
                .ok_or_else(|| integrity("proposal-index-has-no-ancestry-transition"));
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }
        self.validate_proposal_campaign_scope(&current, proposal)?;
        self.ensure_budget_available(&current, 1, 0)?;

        let planning_view = current.snapshot.planning_view();
        let planning_view_content = self.put_planning_view(&planning_view)?;
        if planning_view_content != proposal.guidance_basis().content_id() {
            return Err(integrity("proposal-guidance-basis-publication-id-mismatch"));
        }

        let proposal_content = self.put_proposal(proposal)?;
        if proposal_content != proposal_id.content_id() {
            return Err(integrity("proposal-publication-id-mismatch"));
        }
        let ordinal_key = proposal_ordinal_key(proposal.request(), proposal.ordinal());
        let value_key = proposal_value_key(proposal.request(), proposal.value());
        for key in [proposal_key, ordinal_key, value_key] {
            if self
                .merkle
                .get(current.snapshot.roots().exploration, key)?
                .is_some()
            {
                return Err(integrity("proposal-index-has-no-ancestry-transition"));
            }
        }
        if proposal.ordinal() > 1 {
            let prior_key = proposal_ordinal_key(proposal.request(), proposal.ordinal() - 1);
            let prior_content = self
                .merkle
                .get(current.snapshot.roots().exploration, prior_key)?
                .ok_or_else(|| integrity("proposal-skipped-request-ordinal"))?;
            let prior = self.read_proposal(prior_content)?;
            if prior.request() != proposal.request()
                || prior.ordinal().checked_add(1) != Some(proposal.ordinal())
            {
                return Err(integrity("proposal-predecessor-index-mismatch"));
            }
        }

        let mut exploration = self.merkle.insert(
            current.snapshot.roots().exploration,
            proposal_key,
            proposal_content,
        )?;
        for key in [ordinal_key, value_key] {
            exploration = self
                .merkle
                .insert(exploration.content_id(), key, proposal_content)?;
        }
        if let Some(frontier_index) = self.merkle.get(
            current.snapshot.roots().exploration,
            frontier_index_anchor_key(),
        )? {
            let request = self.read_branch_request(proposal.request().content_id())?;
            let prior_state = self.continuation_state(
                super::projection::CandidateViewRoots::from_roots(current.snapshot.roots()),
                proposal.request(),
                &request,
            )?;
            self.validate_frontier_projection(
                frontier_index,
                proposal.request(),
                proposal.branch_point(),
                prior_state,
            )?;
            let next_frontier = self
                .frontier_index_after(
                    current.snapshot.roots().exploration,
                    &[(
                        proposal.request(),
                        proposal.branch_point(),
                        crate::ContinuationState::Open,
                    )],
                    true,
                )?
                .ok_or_else(|| integrity("proposal-frontier-index-disappeared"))?;
            exploration = self.merkle.insert(
                exploration.content_id(),
                frontier_index_anchor_key(),
                next_frontier,
            )?;
        }

        let fact = CampaignFact::ProposalIssued(proposal_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.exploration = exploration.content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(ProposalResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    proposal: proposal_id,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Admits or deduplicates one proposal-backed semantic attempt.
    ///
    /// The coordinator derives the immutable admission role from authoritative
    /// indexes: the first semantic attempt receives the next global ordinal and
    /// spends request attempt budget; a later convergent proposal becomes an
    /// additional cause and spends no attempt budget. Exact replay precedes stale
    /// precondition rejection.
    ///
    /// # Errors
    ///
    /// Returns an error for stale input, an unauthoritative or already-disposed
    /// proposal, invalid selection/path/attempt closure, exhausted attempt budget,
    /// inconsistent dedup indexes, publication failure, or final ref conflict.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_proposal(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        proposal: ProposalId,
        selection: &Selection,
        path: &BranchPath,
        attempt: &Attempt,
    ) -> Result<AttemptAdmissionResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let selection_id = selection.id()?;
        let path_id = path.id()?;
        let AttemptStart::Branch {
            selection: attempt_selection,
            ..
        } = attempt.start()
        else {
            return Err(integrity("proposal-admission-attempt-is-discovery"));
        };
        if attempt_selection != selection_id || attempt.path() != path_id {
            return Err(integrity("proposal-admission-input-closure-mismatch"));
        }
        let attempt_id = attempt.id()?;
        let proposal_admission_key =
            map_key_content("accounting.proposal-admission", proposal.content_id());
        if self
            .merkle
            .get(current.snapshot.roots().accounting, proposal_admission_key)?
            .is_some()
        {
            let result = self
                .find_attempt_admission_result(current_content, proposal)?
                .ok_or_else(|| integrity("proposal-admission-index-has-no-ancestry-transition"))?;
            if result.attempt != attempt_id {
                return Err(integrity("proposal-admission-replay-attempt-mismatch"));
            }
            return Ok(result);
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }

        let new_basis = self
            .merkle
            .get(
                current.snapshot.roots().accounting,
                map_key_content(
                    "accounting.attempt-execution-basis",
                    attempt_id.content_id(),
                ),
            )?
            .is_none();
        self.ensure_budget_available(&current, 0, u64::from(new_basis))?;

        let selection_content = self.put_selection(selection)?;
        if selection_content != selection_id.content_id() {
            return Err(integrity("selection-publication-id-mismatch"));
        }
        let path_content = self.put_branch_path(path)?;
        if path_content != path_id.content_id() {
            return Err(integrity("branch-path-publication-id-mismatch"));
        }
        let attempt_content = self.put_attempt(attempt)?;
        if attempt_content != attempt_id.content_id() {
            return Err(integrity("attempt-publication-id-mismatch"));
        }

        let admission = self.expected_proposal_admission(&current, proposal, attempt_id)?;
        let admission_id = admission.id()?;
        let admission_content = self.put_attempt_admission(&admission)?;
        if admission_content != admission_id.content_id() {
            return Err(integrity("attempt-admission-publication-id-mismatch"));
        }
        self.read_attempt_admission(admission_content)?;

        let upserts = attempt_admission_upserts(admission_content, admission)?;
        for key in upserts
            .keys()
            .copied()
            .filter(|key| *key != admission_sequence_key())
        {
            if self
                .merkle
                .get(current.snapshot.roots().accounting, key)?
                .is_some()
            {
                return Err(integrity(
                    "attempt-admission-index-has-no-ancestry-transition",
                ));
            }
        }
        let mut accounting = current.snapshot.roots().accounting;
        for (key, value) in &upserts {
            accounting = self.merkle.insert(accounting, *key, *value)?.content_id();
        }

        let mut exploration = current.snapshot.roots().exploration;
        if let Some(frontier_index) = self.merkle.get(exploration, frontier_index_anchor_key())? {
            let proposal_record = self.read_proposal(proposal.content_id())?;
            let request = self.read_branch_request(proposal_record.request().content_id())?;
            let prior_state = self.continuation_state(
                super::projection::CandidateViewRoots::new(
                    exploration,
                    current.snapshot.roots().observations,
                    current.snapshot.roots().corpus,
                    current.snapshot.roots().accounting,
                ),
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
                    exploration,
                    current.snapshot.roots().observations,
                    current.snapshot.roots().corpus,
                    accounting,
                ),
                proposal_record.request(),
                &request,
            )?;
            let next_frontier = self
                .frontier_index_after(
                    exploration,
                    &[(
                        proposal_record.request(),
                        proposal_record.branch_point(),
                        next_state,
                    )],
                    true,
                )?
                .ok_or_else(|| integrity("attempt-admission-frontier-index-disappeared"))?;
            exploration = self
                .merkle
                .insert(exploration, frontier_index_anchor_key(), next_frontier)?
                .content_id();
        }

        let fact = CampaignFact::AttemptAdmitted(admission_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.exploration = exploration;
        roots.accounting = accounting;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(AttemptAdmissionResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    proposal,
                    attempt: attempt_id,
                    admission: admission_id,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Applies one idempotent lifecycle, policy, or budget command.
    ///
    /// Command lookup happens before stale-precondition checking. Replaying the
    /// same command and payload therefore returns the original transition even
    /// after later snapshots; reusing an ID for another payload fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid closure/action, command-ID reuse, stale
    /// precondition, object publication failure, or final ref CAS conflict.
    pub fn apply_control(
        &self,
        name: &str,
        request: &ControlRequest,
    ) -> Result<CampaignCommandResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if let Some(fact_content) = self
            .merkle
            .get(current.snapshot.roots().accounting, command_key)?
        {
            let fact = self.read_fact(fact_content)?;
            match fact {
                CampaignFact::ControlRequested(prior_request) if prior_request == *request => {
                    return self.find_command_result(current_content, request, true);
                }
                CampaignFact::ControlRequested(_)
                | CampaignFact::BranchRequestIssued(_)
                | CampaignFact::BranchRequestAccepted { .. }
                | CampaignFact::PinCommandAccepted(_)
                | CampaignFact::DiscoveryRequested(_)
                | CampaignFact::SavepointCaptureRequested(_)
                | CampaignFact::SavepointCaptureResolved(_)
                | CampaignFact::SavepointContinuationSelected(_) => {
                    return Err(CampaignRepositoryError::CommandReuse);
                }
                _ => return Err(integrity("command-index-value-is-not-mutation-fact")),
            }
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if request.expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: request.expected_snapshot,
                current: current_id,
            });
        }
        let mut projected = self.current_lifecycle(current_content)?;
        projected.apply(&request.action)?;

        let policy_activation = match request.action {
            CampaignControlAction::ActivatePolicy(next) => {
                let policy = self.read_policy(next.content_id())?;
                let prior_policy =
                    self.read_policy(current.snapshot.active_policy().content_id())?;
                if policy.mode() != prior_policy.mode() {
                    return Err(integrity("activated-policy-mode-mismatch"));
                }
                let lineage_content = required_child(&current.envelope, "lineage")?;
                let lineage = self.read_lineage(lineage_content)?;
                if policy.scenario() != lineage.scenario() {
                    return Err(integrity("activated-policy-scenario-mismatch"));
                }
                Some(PolicyActivation::new(
                    current.snapshot.active_policy(),
                    next,
                )?)
            }
            _ => None,
        };

        let control_fact = CampaignFact::ControlRequested(request.clone());
        let control_content = self.put_fact(&control_fact)?;
        let mut accounting = self.merkle.insert(
            current.snapshot.roots().accounting,
            command_key,
            control_content,
        )?;

        let mut active_policy = current.snapshot.active_policy();
        match (request.action.clone(), policy_activation) {
            (CampaignControlAction::ActivatePolicy(_), Some(activation)) => {
                active_policy = activation.next();
                let activation = CampaignFact::PolicyActivated(activation);
                let activation_content = self.put_fact(&activation)?;
                accounting = self.insert_fact(accounting, &activation, activation_content)?;
            }
            (CampaignControlAction::GrantBudget(grant), None) => {
                let budget = CampaignFact::BudgetGranted(grant);
                let budget_content = self.put_fact(&budget)?;
                accounting = self.insert_fact(accounting, &budget, budget_content)?;
            }
            _ => {}
        }

        let mut roots = current.snapshot.roots();
        roots.accounting = accounting.content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            active_policy,
            roots,
            crate::CampaignFactId::from_content_id(control_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            Some(&request.action),
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(CampaignCommandResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Applies one idempotent semantic configuration-pin mutation.
    ///
    /// Command lookup precedes stale-precondition checking, so an exact replay
    /// returns the snapshot that first accepted the request even after later
    /// mutations. Removing a pin writes an authenticated tombstone into the
    /// pins projection rather than erasing campaign history.
    ///
    /// # Errors
    ///
    /// Returns an error for command-ID reuse, a stale precondition, a target
    /// outside the authoritative graph, object publication failure, or final
    /// ref CAS conflict.
    pub fn apply_pin(
        &self,
        name: &str,
        request: &PinRequest,
    ) -> Result<CampaignCommandResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if let Some(fact_content) = self
            .merkle
            .get(current.snapshot.roots().accounting, command_key)?
        {
            let fact = self.read_fact(fact_content)?;
            match fact {
                CampaignFact::PinCommandAccepted(prior_request) if prior_request == *request => {
                    return self.find_pin_result(current_content, request, true);
                }
                CampaignFact::ControlRequested(_)
                | CampaignFact::BranchRequestIssued(_)
                | CampaignFact::BranchRequestAccepted { .. }
                | CampaignFact::PinCommandAccepted(_)
                | CampaignFact::DiscoveryRequested(_)
                | CampaignFact::SavepointCaptureRequested(_)
                | CampaignFact::SavepointCaptureResolved(_)
                | CampaignFact::SavepointContinuationSelected(_) => {
                    return Err(CampaignRepositoryError::CommandReuse);
                }
                _ => return Err(integrity("command-index-value-is-not-mutation-fact")),
            }
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if request.expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: request.expected_snapshot,
                current: current_id,
            });
        }

        let configuration = request.change.configuration();
        let configuration_content = self
            .merkle
            .get(
                current.snapshot.roots().graph,
                map_key_hash("graph.configuration", configuration.as_hash()),
            )?
            .ok_or_else(|| integrity("pin-configuration-is-not-in-campaign-graph"))?;
        let artifact = self.read_configuration_artifact(configuration_content)?;
        if artifact.configuration() != configuration {
            return Err(integrity("pin-configuration-index-mismatch"));
        }

        let pin_fact = CampaignFact::PinCommandAccepted(request.clone());
        let pin_content = self.put_fact(&pin_fact)?;
        let accounting = self.merkle.insert(
            current.snapshot.roots().accounting,
            command_key,
            pin_content,
        )?;
        let pins = self.merkle.insert(
            current.snapshot.roots().pins,
            pin_configuration_key(configuration),
            pin_content,
        )?;

        let mut roots = current.snapshot.roots();
        roots.pins = pins.content_id();
        roots.accounting = accounting.content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(pin_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(CampaignCommandResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }
}
