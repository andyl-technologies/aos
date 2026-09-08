//! Authoritative choice discovery and branch-request transactions.

use super::*;

impl CampaignRepository {
    /// Makes an operator-supplied choice authoritative campaign knowledge.
    ///
    /// The direct adapter itself is the ambient authenticated operator
    /// boundary. RPC implementations must authenticate the principal before
    /// calling it and must use the same canonical IDs and owner transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying authoritative discovery
    /// transaction rejects the opportunity or snapshot precondition.
    pub fn discover_operator_choice_opportunity(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
    ) -> Result<ChoiceDiscoveryResult, CampaignRepositoryError> {
        self.discover_choice_opportunity(name, expected_snapshot, parent, opportunity)
    }

    /// Makes one validated choice opportunity authoritative campaign knowledge.
    ///
    /// Executors may publish immutable opportunity bodies, but only this
    /// coordinator transition or a canonical observation adds graph membership.
    /// Exact replay precedes snapshot staleness. If another owner already made
    /// the opportunity authoritative, the current snapshot is returned without
    /// mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or invalid opportunity closure, scenario
    /// mismatch, stale precondition, publication failure, or final ref conflict.
    pub(crate) fn discover_choice_opportunity(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
    ) -> Result<ChoiceDiscoveryResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;
        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        let choice = self.read_opportunity(opportunity.content_id())?;
        let parent_artifact = self.read_configuration_artifact(parent.content_id())?;
        let lineage = self.read_lineage(required_child(&current.envelope, "lineage")?)?;
        if choice.scenario() != lineage.scenario()
            || parent_artifact.scenario() != lineage.scenario()
        {
            return Err(integrity("choice-discovery-scenario-mismatch"));
        }
        if self.merkle.get(
            current.snapshot.roots().graph,
            map_key_hash(
                "graph.configuration",
                parent_artifact.configuration().as_hash(),
            ),
        )? != Some(parent.content_id())
        {
            return Err(integrity(
                "choice-discovery-parent-is-not-in-campaign-graph",
            ));
        }
        let branch_point = choice.branch_point_id(parent_artifact.configuration());
        let choice_key = branch_point_opportunity_key(branch_point, opportunity);
        if let Some(existing) = self
            .merkle
            .get(current.snapshot.roots().graph, choice_key)?
        {
            if existing != opportunity.content_id() {
                return Err(integrity("choice-discovery-graph-key-conflict"));
            }
            return Ok(self
                .find_choice_discovery_result(current_content, parent, opportunity)?
                .unwrap_or(ChoiceDiscoveryResult {
                    prior_snapshot: current_id,
                    new_snapshot: current_id,
                    parent,
                    branch_point,
                    opportunity,
                    replayed: true,
                }));
        }
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }

        let prior_graph = current.snapshot.roots().graph;
        let choice_index = self
            .merkle
            .get(prior_graph, choice_index_anchor_key())?
            .map(|choice_index| {
                self.merkle.insert(
                    choice_index,
                    choice_index_order_key(opportunity),
                    opportunity.content_id(),
                )
            })
            .transpose()?;
        let graph = self.merkle.insert(
            prior_graph,
            authoritative_choice_key(opportunity),
            opportunity.content_id(),
        )?;
        let graph = self
            .merkle
            .insert(graph.content_id(), choice_key, opportunity.content_id())?;
        let graph = match choice_index {
            Some(choice_index) => self.merkle.insert(
                graph.content_id(),
                choice_index_anchor_key(),
                choice_index.content_id(),
            )?,
            None => graph,
        };
        let fact = CampaignFact::ChoiceOpportunityDiscovered {
            parent,
            branch_point,
            opportunity,
        };
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.graph = graph.content_id();
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
                Ok(ChoiceDiscoveryResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    parent,
                    branch_point,
                    opportunity,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Submits one additive, lazily consumed branch request.
    ///
    /// Acceptance stores the request in the exploration root and records one
    /// transition fact. It does not enumerate candidates, create proposals, or
    /// admit attempts. Repeating an already accepted exact request returns its
    /// original transition even when later snapshots are current.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid request closure, a parent configuration
    /// outside the campaign graph, a stale precondition, publication failure,
    /// or final authoritative-ref conflict.
    pub(crate) fn submit_branch_request(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        request: &BranchRequest,
    ) -> Result<BranchRequestResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let request_id = request.id()?;
        let request_key = map_key_content("exploration.branch-request", request_id.content_id());
        if self
            .merkle
            .get(current.snapshot.roots().exploration, request_key)?
            .is_some()
        {
            return self
                .find_branch_request_result(current_content, request_id)?
                .ok_or_else(|| integrity("branch-request-index-has-no-ancestry-transition"));
        }
        let command_key = if let BranchRequestCause::Operator(command) = request.cause() {
            let key = map_key_hash("accounting.command", command.as_hash());
            if self
                .merkle
                .get(current.snapshot.roots().accounting, key)?
                .is_some()
            {
                return Err(CampaignRepositoryError::CommandReuse);
            }
            Some(key)
        } else {
            None
        };

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }
        let parent = self.validate_branch_request_references(request)?;
        self.validate_branch_request_campaign_scope(&current, request, &parent)?;
        let acceptance_summary =
            self.branch_acceptance_summary(current.snapshot.roots().graph, request)?;

        let frontier_index = self.merkle.get(
            current.snapshot.roots().exploration,
            frontier_index_anchor_key(),
        )?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let feedback_indexed = self
            .candidate_source_profile(request, &domain)?
            .is_some_and(super::projection::CandidateSourceProfile::requires_feedback_index);
        if feedback_indexed && frontier_index.is_none() {
            return Err(integrity("progressive-generator-requires-frontier-index"));
        }
        let indexed_requests = feedback_indexed
            .then_some((request_id, request.branch_point()))
            .into_iter()
            .collect::<Vec<_>>();
        let projected_branch_request_index = self.branch_request_index_after(
            current.snapshot.roots().exploration,
            &indexed_requests,
            false,
        )?;
        let scan_requests = [(request_id, request.branch_point())];
        let projected_scan_index = self.planner_scan_index_after(
            current.snapshot.roots().exploration,
            &scan_requests,
            false,
        )?;
        let initial_continuation = if let Some(index) = frontier_index {
            if self
                .merkle
                .get(index, frontier_index_order_key(request_id))?
                .is_some()
            {
                return Err(integrity("branch-request-frontier-slot-is-not-empty"));
            }
            Some(self.initial_continuation_state_at(
                request,
                super::projection::CandidateViewRoots::from_roots(current.snapshot.roots()),
            )?)
        } else {
            None
        };

        let request_content = self.put_branch_request(request)?;
        if request_content != request_id.content_id() {
            return Err(integrity("branch-request-publication-id-mismatch"));
        }
        let mut exploration = self.merkle.insert(
            current.snapshot.roots().exploration,
            request_key,
            request_content,
        )?;
        if let Some(projected) = projected_branch_request_index {
            let published = self
                .branch_request_index_after(
                    current.snapshot.roots().exploration,
                    &indexed_requests,
                    true,
                )?
                .ok_or_else(|| integrity("branch-request-index-disappeared"))?;
            if published != projected {
                return Err(integrity("branch-request-index-publication-mismatch"));
            }
            exploration = self.merkle.insert(
                exploration.content_id(),
                branch_request_index_anchor_key(),
                published,
            )?;
        }
        if let Some(initial_continuation) = initial_continuation {
            let next_frontier = self
                .frontier_index_after(
                    current.snapshot.roots().exploration,
                    &[(request_id, request.branch_point(), initial_continuation)],
                    true,
                )?
                .ok_or_else(|| integrity("branch-request-frontier-index-disappeared"))?;
            exploration = self.merkle.insert(
                exploration.content_id(),
                frontier_index_anchor_key(),
                next_frontier,
            )?;
        }

        if let Some(projected) = projected_scan_index {
            let published = self
                .planner_scan_index_after(
                    current.snapshot.roots().exploration,
                    &scan_requests,
                    true,
                )?
                .ok_or_else(|| integrity("planner-scan-index-disappeared"))?;
            if published != projected {
                return Err(integrity("planner-scan-index-publication-mismatch"));
            }
            exploration = self.merkle.insert(
                exploration.content_id(),
                planner_scan_index_anchor_key(),
                published,
            )?;
        }

        let fact = CampaignFact::BranchRequestAccepted {
            request: request_id,
            summary: acceptance_summary,
        };
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.exploration = exploration.content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        if let Some(command_key) = command_key {
            roots.accounting = self
                .merkle
                .insert(roots.accounting, command_key, transition_content)?
                .content_id();
        }
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
                Ok(BranchRequestResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    request: request_id,
                    summary: acceptance_summary,
                    snapshot: next,
                    acceptance_fact: fact,
                    summary_recorded: true,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Submits one operator-authorized additive branch request.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is not operator-caused or when the
    /// ordinary authoritative branch transaction rejects it.
    pub fn submit_operator_branch_request(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        request: &BranchRequest,
    ) -> Result<BranchRequestResult, CampaignRepositoryError> {
        if !matches!(request.cause(), BranchRequestCause::Operator(_)) {
            return Err(integrity(
                "branch-request-cause-requires-authority-specific-adapter",
            ));
        }
        self.submit_branch_request(name, expected_snapshot, request)
    }

    /// Submits one authenticated debugger-caused semantic branch request.
    ///
    /// # Errors
    ///
    /// Returns an error when component authority is not configured, the
    /// authenticator or session binding is invalid, or branch acceptance fails.
    pub fn submit_debugger_branch_request(
        &self,
        name: &str,
        submission: &DebuggerSubmission,
    ) -> Result<BranchRequestResult, CampaignRepositoryError> {
        let authority = self
            .debugger_authority
            .as_ref()
            .ok_or_else(|| integrity("debugger-authority-is-not-configured"))?;
        if !submission.verify(authority) {
            return Err(integrity("debugger-submission-authentication-failed"));
        }
        self.submit_branch_request(name, submission.expected_snapshot(), submission.request())
    }
}
