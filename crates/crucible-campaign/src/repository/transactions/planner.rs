//! Planner invocation, response, accounting, and scan transactions.

use super::*;

impl CampaignRepository {
    /// Publishes a complete immutable basis for one snapshot-bound planner call.
    ///
    /// The returned invocation names the current campaign policy and planning
    /// view. Publishing it does not advance the campaign ref; acceptance later
    /// rejects it if that snapshot is no longer current.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, an engine/artifact/state mismatch,
    /// a missing artifact dependency, or failed immutable publication.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_planner_invocation(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        engine: &PlannerEngine,
        artifact: &PolicyArtifact,
        state: &PlannerState,
        scan_after: Option<PlanningScanPosition>,
        scan_limit: u32,
        budget: PlanningBudget,
    ) -> Result<PlannerInvocation, CampaignRepositoryError> {
        let head = self.head(name)?;
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }

        let engine_content = self.put_planner_engine(engine)?;
        let engine_id = crate::PlannerEngineId::from_content_id(engine_content)?;
        if artifact.engine() != engine_id || state.engine() != engine_id {
            return Err(integrity("planner-basis-engine-mismatch"));
        }
        let artifact_content = self.put_policy_artifact(artifact)?;
        let artifact_id = crate::PolicyArtifactId::from_content_id(artifact_content)?;
        let state_content = self.put_planner_state(state)?;
        let state_id = crate::PlannerStateId::from_content_id(state_content)?;
        let view = head.snapshot().planning_view();
        let view_content = self.put_planning_view(&view)?;
        let view_id = crate::CampaignViewId::from_content_id(view_content)?;
        let scan_page = self.planner_scan_page(&view, scan_after, scan_limit)?;
        if scan_page.input_objects() > u64::from(budget.input_objects())
            || scan_page.input_bytes() > budget.input_bytes()
        {
            return Err(integrity("planner-scan-page-exceeds-input-budget"));
        }
        let invocation = PlannerInvocation::new(
            engine_id,
            artifact_id,
            head.snapshot().active_policy(),
            state_id,
            view_id,
            scan_page,
            budget,
        )?;
        self.validate_planner_invocation_start(head.snapshot().roots().coordination, &invocation)?;
        let invocation_content = self.put_planner_invocation(&invocation)?;
        // `head` authenticated this complete immutable history. Rewalking the
        // view roots on every scan page makes frontier selection history-wide;
        // only the new invocation/basis closure needs fresh authentication.
        let loaded = self.read_snapshot(head.snapshot_id().content_id())?;
        let anchors = self.authenticated_head_closure_anchors(&loaded)?;
        let added = self.verify_campaign_closure_anchored(invocation_content, &anchors)?;
        let prior = self.load_validation_checkpoint(head.snapshot_id().content_id())?;
        if prior
            .closure_objects
            .checked_add(added)
            .is_none_or(|upper| upper > MAX_CAMPAIGN_CLOSURE_OBJECTS)
        {
            // A conservative head bound can overcount this invocation's union.
            // Near the limit, retain the original exact closure admission rule.
            self.verify_campaign_closure(invocation_content)?;
        }
        Ok(invocation)
    }

    /// Accepts one coordinator-measured, pure planner result.
    ///
    /// `Issue` atomically composes request, proposal, derived attempt/admission,
    /// accounting, and planner-head ownership in the same snapshot transition.
    /// Exact invocation replay is resolved before snapshot staleness.
    ///
    /// # Errors
    ///
    /// Returns an error for stale or mismatched invocation input, an invalid
    /// scan cursor, output or resource-budget overflow, conflicting replay,
    /// issuing output, invalid state continuity, or failed ref advancement.
    fn accept_request_bound_planner_step(
        &self,
        name: &str,
        request: &PlannerRequest,
        proposal: &PlannerStepProposal,
        measured_usage: PlanningUsage,
    ) -> Result<PlannerStepResult, CampaignRepositoryError> {
        let expected_snapshot = request.expected_snapshot();
        let request_id = request.id()?;
        let request_digest = request.request_digest();
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let invocation = self.load_planner_invocation(proposal.invocation())?;
        if request.invocation_id()? != proposal.invocation() || *request.invocation() != invocation
        {
            return Err(integrity("planner-request-invocation-mismatch"));
        }
        self.preflight_planner_request_inputs(request)?;
        self.validate_builtin_planner_proposal(request, proposal)?;
        let next_state_id = proposal.next_state().id()?;
        let disposition = match proposal.disposition() {
            PlannerProposalDisposition::ContinueScan { cursor } => {
                PlannerDisposition::ContinueScan { cursor: *cursor }
            }
            PlannerProposalDisposition::NoWork => PlannerDisposition::NoWork,
            PlannerProposalDisposition::Issue {
                selected,
                branch_requests,
                proposals,
            } => PlannerDisposition::Issue {
                selected: *selected,
                issued_branch_requests: branch_requests
                    .iter()
                    .map(BranchRequest::id)
                    .collect::<Result<Vec<_>, _>>()?,
                issued_proposals: proposals
                    .iter()
                    .map(Proposal::id)
                    .collect::<Result<Vec<_>, _>>()?,
            },
        };
        self.validate_planner_usage(proposal, measured_usage, &invocation, &disposition)?;

        let invocation_key = planner_invocation_result_key(proposal.invocation());
        if let Some(existing_content) = self
            .merkle
            .get(current.snapshot.roots().coordination, invocation_key)?
        {
            let existing_id = PlannerStepId::from_content_id(existing_content)?;
            let existing = self.read_planner_step(existing_content)?;
            self.validate_replayed_planner_accounting(
                existing.accounting(),
                measured_usage,
                &disposition,
            )?;
            let expected = PlannerStep::new(
                existing.parent(),
                proposal.invocation(),
                request_id,
                request_digest,
                invocation.policy(),
                invocation.engine(),
                invocation.policy_artifact(),
                invocation.input_view(),
                disposition,
                next_state_id,
                proposal.usage_claim(),
                existing.accounting(),
                proposal.explanation().clone(),
            )?;
            if expected.id()? != existing_id {
                return Err(integrity("planner-invocation-result-conflict"));
            }
            return self
                .find_planner_step_result(current_content, proposal.invocation())?
                .ok_or_else(|| integrity("planner-step-index-has-no-ancestry-transition"));
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }
        let current_view = current.snapshot.planning_view();
        let current_view_content = self.put_planning_view(&current_view)?;
        if invocation.input_view().content_id() != current_view_content
            || invocation.policy() != current.snapshot.active_policy()
        {
            return Err(integrity(
                "planner-invocation-is-not-current-campaign-basis",
            ));
        }
        self.validate_planner_page(&current_view, &invocation)?;
        self.validate_planner_cursor(&current, &disposition)?;
        self.validate_planner_disposition_page(&invocation, &disposition)?;
        self.validate_planner_selected_source(&current_view, &disposition)?;
        let parent = self.validate_planner_invocation_start(
            current.snapshot.roots().coordination,
            &invocation,
        )?;

        let (accounting, issue_preflight) = match proposal.disposition() {
            PlannerProposalDisposition::Issue {
                branch_requests,
                proposals,
                ..
            } => {
                let PlannerDisposition::Issue { selected, .. } = &disposition else {
                    return Err(integrity("planner-issue-disposition-mismatch"));
                };
                let projected = self.preflight_planner_issue(
                    &current,
                    proposal.invocation(),
                    *selected,
                    branch_requests,
                    proposals,
                )?;
                if projected.branch_requests != disposition.issued_branch_requests()
                    || projected.proposals != disposition.issued_proposals()
                {
                    return Err(integrity("planner-issue-output-id-mismatch"));
                }
                let accounting = self.planner_accounting(
                    measured_usage,
                    &disposition,
                    projected.attempts,
                    projected.deduplicated,
                )?;
                (accounting, Some(projected))
            }
            PlannerProposalDisposition::ContinueScan { .. }
            | PlannerProposalDisposition::NoWork => (
                self.planner_accounting(measured_usage, &disposition, 0, 0)?,
                None,
            ),
        };

        if proposal.next_state().engine() != invocation.engine() {
            return Err(integrity("planner-step-next-state-engine-mismatch"));
        }
        let step = PlannerStep::new(
            parent,
            proposal.invocation(),
            request_id,
            request_digest,
            invocation.policy(),
            invocation.engine(),
            invocation.policy_artifact(),
            invocation.input_view(),
            disposition,
            next_state_id,
            proposal.usage_claim(),
            accounting,
            proposal.explanation().clone(),
        )?;
        let step_id = step.id()?;
        let step_key = planner_step_key(step_id);
        for key in [step_key, invocation_key] {
            if self
                .merkle
                .get(current.snapshot.roots().coordination, key)?
                .is_some()
            {
                return Err(integrity("planner-step-index-has-no-ancestry-transition"));
            }
        }

        let issue_projection = match (issue_preflight.as_ref(), proposal.disposition()) {
            (
                Some(prepared),
                PlannerProposalDisposition::Issue {
                    selected,
                    branch_requests,
                    proposals,
                },
            ) => Some(self.publish_planner_issue(
                &current,
                proposal.invocation(),
                *selected,
                branch_requests,
                proposals,
                prepared,
            )?),
            (None, PlannerProposalDisposition::ContinueScan { .. })
            | (None, PlannerProposalDisposition::NoWork) => None,
            _ => return Err(integrity("planner-issue-preflight-shape-mismatch")),
        };

        let next_state_content = self.put_planner_state(proposal.next_state())?;
        if next_state_content != next_state_id.content_id() {
            return Err(integrity("planner-next-state-publication-id-mismatch"));
        }
        for input in request
            .input_bundle()
            .candidate_inputs(request)?
            .into_values()
        {
            if let Some(offer) = input.offer {
                let offer_content = self.put_proposal(&offer)?;
                if offer_content != offer.id()?.content_id() {
                    return Err(integrity("planner-candidate-offer-publication-id-mismatch"));
                }
            }
            if let Some(guidance) = input.guidance {
                let guidance_content = self.put_planner_candidate_guidance(&guidance)?;
                if guidance_content != guidance.id()?.content_id() {
                    return Err(integrity(
                        "planner-candidate-guidance-publication-id-mismatch",
                    ));
                }
            }
            if let Some(budget) = input.budget {
                let content = self.put_envelope(ObjectEnvelope::for_candidate_budget(&budget)?)?;
                if content != budget.id()?.content_id() {
                    return Err(integrity(
                        "planner-candidate-budget-publication-id-mismatch",
                    ));
                }
            }
        }
        let request_content = self.put_planner_request(request)?;
        if request_content != request_id.content_id() {
            return Err(integrity("planner-request-publication-id-mismatch"));
        }
        let step_content = self.put_planner_step(&step)?;
        if step_content != step_id.content_id() {
            return Err(integrity("planner-step-publication-id-mismatch"));
        }

        let mut coordination = self.coordination_with_parent_result(current_content, &current)?;
        for key in [step_key, invocation_key, planner_head_key()] {
            coordination = self
                .merkle
                .insert(coordination, key, step_content)?
                .content_id();
        }

        let fact = CampaignFact::PlannerAdvanced(step_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        let issued = issue_projection.is_some();
        if let Some(projected) = issue_projection {
            roots.exploration = projected.exploration;
            roots.accounting = projected.accounting;
        }
        roots.coordination = coordination;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let closure_growth_upper = if issued {
            MAX_PLANNER_ISSUE_SUCCESSOR_GROWTH
        } else {
            MAX_SIMPLE_SUCCESSOR_GROWTH
        };
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
                Ok(PlannerStepResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    step: step_id,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Accepts one checked, exactly request-bound planner response.
    ///
    /// Authentication proves which supervised component produced the exact
    /// bytes; the coordinator still independently validates every semantic
    /// output and computes authoritative accounting.
    ///
    /// # Errors
    ///
    /// Returns an error when component authority is not configured, either
    /// authenticator is invalid, the response names another request, or
    /// ordinary planner acceptance fails.
    pub fn accept_planner_response(
        &self,
        name: &str,
        request: &crate::PlannerRequest,
        response: &crate::PlannerResponse,
    ) -> Result<PlannerStepResult, CampaignRepositoryError> {
        let authority = self
            .planner_authority
            .as_ref()
            .ok_or_else(|| integrity("planner-authority-is-not-configured"))?;
        if !response.verify(authority) || !response.submission().verify(authority) {
            return Err(integrity("planner-response-authentication-failed"));
        }
        response.validate_for(request)?;
        let submission = response.submission();
        self.accept_request_bound_planner_step(
            name,
            request,
            submission.proposal(),
            submission.measured_usage(),
        )
    }

    /// Builds the exact store-backed input for one prepared planner invocation.
    ///
    /// The returned request embeds the direct invocation basis by value and
    /// carries every served branch-request envelope. Engines advertising the
    /// canonical-frontier-offers capability additionally receive the exact
    /// snapshot-authenticated continuation projection and one owner-computed
    /// candidate offer for the least Ready source. This method performs no
    /// writes.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the expected snapshot,
    /// invocation basis, served source closure, or retained-request bounds are
    /// missing or invalid.
    pub fn build_planner_request(
        &self,
        expected_snapshot: CampaignSnapshotId,
        invocation_id: PlannerInvocationId,
    ) -> Result<PlannerRequest, CampaignRepositoryError> {
        let snapshot = self.read_snapshot(expected_snapshot.content_id())?;
        self.validate_complete_head(expected_snapshot.content_id())?;
        let invocation = self.load_planner_invocation(invocation_id)?;
        let expected_view = snapshot.snapshot.planning_view();
        if invocation.policy() != snapshot.snapshot.active_policy()
            || invocation.input_view() != expected_view.id()?
        {
            return Err(integrity("planner-request-basis-is-not-snapshot-current"));
        }
        self.validate_planner_page(&expected_view, &invocation)?;
        self.validate_planner_invocation_start(
            snapshot.snapshot.roots().coordination,
            &invocation,
        )?;

        let engine_envelope = self.require_record_kind(
            invocation.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        let artifact_envelope = self.require_record_kind(
            invocation.policy_artifact().content_id(),
            crate::CampaignRecordKind::PolicyArtifact,
        )?;
        let policy_envelope = self.require_record_kind(
            invocation.policy().content_id(),
            crate::CampaignRecordKind::Policy,
        )?;
        let state_envelope = self.require_record_kind(
            invocation.planner_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let view_envelope = self.require_record_kind(
            invocation.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;

        let engine: PlannerEngine = crate::codec::decode(engine_envelope.body())?;
        let mut retained = Vec::new();
        let mut retained_bytes = 0_usize;
        for position in invocation.scan_page().positions() {
            push_retained_planner_input(
                &mut retained,
                &mut retained_bytes,
                self.read_envelope(position.source().content_id())?,
            )?;
        }
        if engine
            .capabilities()
            .contains(crate::CANONICAL_FRONTIER_OFFERS_CAPABILITY)
        {
            let use_puct = engine
                .capabilities()
                .contains(crate::CANONICAL_FRONTIER_PUCT_CAPABILITY);
            let budget = engine
                .capabilities()
                .contains(crate::CANONICAL_FRONTIER_BUDGET_CAPABILITY)
                .then(|| self.parent_budget_ledger(&snapshot))
                .transpose()?;
            let mut request_budget_work = engine
                .capabilities()
                .contains(crate::CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY)
                .then_some(super::budget::MAX_PLANNER_REQUEST_BUDGET_PROPOSALS);
            let mut ready_positions = Vec::new();
            let mut candidate_cache = PlannerCandidateProjectionCache::default();
            for position in invocation.scan_page().positions() {
                let projection = self.planner_continuation_projection(&snapshot, *position)?;
                push_retained_planner_input(
                    &mut retained,
                    &mut retained_bytes,
                    self.read_envelope(projection.id()?.content_id())?,
                )?;
                if projection.state() != crate::ContinuationState::Ready
                    || (!use_puct && budget.is_none() && !ready_positions.is_empty())
                {
                    continue;
                }
                ready_positions.push(*position);
            }
            let mut projection_points = if use_puct {
                ready_positions
                    .iter()
                    .map(|position| position.branch_point())
                    .collect::<BTreeSet<_>>()
            } else {
                BTreeSet::new()
            };
            for position in &ready_positions {
                let request = self.read_branch_request(position.source().content_id())?;
                let domain = self.read_choice_domain(request.domain().content_id())?;
                if self.next_candidate_scores_intervals(
                    super::projection::CandidateViewRoots::from_roots(snapshot.snapshot.roots()),
                    position.source(),
                    &request,
                    &domain,
                )? {
                    projection_points.insert(position.branch_point());
                }
            }
            let puct_projections = if projection_points.is_empty() {
                BTreeMap::new()
            } else {
                self.project_branch_puct_batch_loaded(&snapshot, projection_points)?
            };
            let mut ready_offers = Vec::new();
            for position in ready_positions {
                let (_, offer) = self.planner_candidate_input(
                    &snapshot,
                    invocation_id,
                    position,
                    &mut candidate_cache,
                    puct_projections.get(&position.branch_point()),
                )?;
                let offer = offer.ok_or_else(|| integrity("planner-ready-candidate-is-missing"))?;
                ready_offers.push((position, offer));
            }
            for (position, offer) in ready_offers {
                if let Some(ledger) = budget {
                    let eligibility = self.planner_candidate_budget(
                        &snapshot,
                        &offer,
                        ledger,
                        request_budget_work.as_mut(),
                    )?;
                    push_retained_planner_input(
                        &mut retained,
                        &mut retained_bytes,
                        ObjectEnvelope::for_candidate_budget(&eligibility)?,
                    )?;
                }
                push_retained_planner_input(
                    &mut retained,
                    &mut retained_bytes,
                    ObjectEnvelope::for_record(
                        crate::CampaignRecordKind::Proposal,
                        crate::object::content_children(offer.content_children())?,
                        offer.canonical_bytes(),
                    )?,
                )?;
                if use_puct {
                    let guidance = self.planner_candidate_guidance(
                        &snapshot,
                        &puct_projections[&position.branch_point()],
                        &offer,
                        crate::PlannerCandidateGuidance::current_schema_version(),
                        &mut candidate_cache,
                    )?;
                    push_retained_planner_input(
                        &mut retained,
                        &mut retained_bytes,
                        ObjectEnvelope::for_record(
                            crate::CampaignRecordKind::PlannerCandidateGuidance,
                            crate::object::content_children(guidance.content_children())?,
                            guidance.canonical_bytes(),
                        )?,
                    )?;
                }
            }
        }

        let request = PlannerRequest::new(
            expected_snapshot,
            invocation,
            engine,
            crate::codec::decode(artifact_envelope.body())?,
            self.read_policy(policy_envelope.content_id())?,
            crate::codec::decode(state_envelope.body())?,
            crate::codec::decode(view_envelope.body())?,
            crate::CampaignPlanningBundle::new(retained)?,
        )?;
        request.id()?;
        Ok(request)
    }

    #[cfg(test)]
    pub(crate) fn accept_planner_step(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        proposal: &PlannerStepProposal,
        measured_usage: PlanningUsage,
    ) -> Result<PlannerStepResult, CampaignRepositoryError> {
        let request = self.build_planner_request(expected_snapshot, proposal.invocation())?;
        self.accept_request_bound_planner_step(name, &request, proposal, measured_usage)
    }

    fn validate_planner_usage(
        &self,
        proposal: &PlannerStepProposal,
        measured: PlanningUsage,
        invocation: &PlannerInvocation,
        disposition: &PlannerDisposition,
    ) -> Result<(), CampaignRepositoryError> {
        let budget = invocation.budget();
        let claimed = proposal.usage_claim();
        if claimed.branch_requests > u64::from(budget.branch_requests())
            || claimed.proposals > u64::from(budget.proposals())
            || claimed.input_objects > u64::from(budget.input_objects())
            || claimed.input_bytes > budget.input_bytes()
            || claimed.fuel > budget.fuel()
        {
            return Err(integrity("planner-step-usage-claim-exceeds-budget"));
        }
        let branch_requests = u64::try_from(disposition.issued_branch_requests().len())
            .map_err(|_| integrity("planner-measured-output-count-overflow"))?;
        let proposals = u64::try_from(disposition.issued_proposals().len())
            .map_err(|_| integrity("planner-measured-output-count-overflow"))?;
        if measured.branch_requests != branch_requests
            || measured.proposals != proposals
            || measured.branch_requests > u64::from(budget.branch_requests())
            || measured.proposals > u64::from(budget.proposals())
        {
            return Err(integrity("planner-measured-output-count-mismatch"));
        }
        if measured.input_objects != invocation.scan_page().input_objects()
            || measured.input_bytes != invocation.scan_page().input_bytes()
            || measured.fuel > budget.fuel()
        {
            return Err(integrity("planner-step-invocation-budget-exceeded"));
        }
        Ok(())
    }

    fn planner_accounting(
        &self,
        measured: PlanningUsage,
        disposition: &PlannerDisposition,
        attempts: u64,
        deduplicated: u64,
    ) -> Result<PlanningAccounting, CampaignRepositoryError> {
        let branch_requests = u64::try_from(disposition.issued_branch_requests().len())
            .map_err(|_| integrity("planner-accounting-output-count-overflow"))?;
        let proposals = u64::try_from(disposition.issued_proposals().len())
            .map_err(|_| integrity("planner-accounting-output-count-overflow"))?;
        if attempts.checked_add(deduplicated) != Some(proposals) {
            return Err(integrity("planner-accounting-admission-count-mismatch"));
        }
        Ok(PlanningAccounting {
            branch_requests,
            proposals,
            attempts,
            deduplicated,
            input_objects: measured.input_objects,
            input_bytes: measured.input_bytes,
            fuel: measured.fuel,
        })
    }

    fn validate_replayed_planner_accounting(
        &self,
        accounting: PlanningAccounting,
        measured: PlanningUsage,
        disposition: &PlannerDisposition,
    ) -> Result<(), CampaignRepositoryError> {
        let expected = self.planner_accounting(
            measured,
            disposition,
            accounting.attempts,
            accounting.deduplicated,
        )?;
        if expected != accounting {
            return Err(integrity("planner-invocation-result-conflict"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_cursor(
        &self,
        current: &LoadedSnapshot,
        disposition: &PlannerDisposition,
    ) -> Result<(), CampaignRepositoryError> {
        let PlannerDisposition::ContinueScan { cursor } = disposition else {
            return Ok(());
        };
        let Some(after) = cursor.after() else {
            return Ok(());
        };
        let request_content = after.source().content_id();
        if self.merkle.get(
            current.snapshot.roots().exploration,
            map_key_content("exploration.branch-request", request_content),
        )? != Some(request_content)
        {
            return Err(integrity("planner-step-scan-cursor-is-not-authoritative"));
        }
        let request = self.read_branch_request(request_content)?;
        if request.branch_point() != after.branch_point() {
            return Err(integrity("planner-step-scan-cursor-branch-point-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_page(
        &self,
        view: &CampaignPlanningView,
        invocation: &PlannerInvocation,
    ) -> Result<(), CampaignRepositoryError> {
        let expected = self.planner_scan_page(
            view,
            invocation.scan_page().after(),
            invocation.scan_page().limit(),
        )?;
        if expected != *invocation.scan_page() {
            return Err(integrity("planner-invocation-scan-page-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_invocation_start(
        &self,
        coordination: ContentId,
        invocation: &PlannerInvocation,
    ) -> Result<Option<PlannerStepId>, CampaignRepositoryError> {
        let parent = self
            .merkle
            .get(coordination, planner_head_key())?
            .map(PlannerStepId::from_content_id)
            .transpose()?;
        let Some(parent_id) = parent else {
            self.validate_planner_invocation_parent(None, invocation)?;
            return Ok(None);
        };

        let parent_step = self.read_planner_step(parent_id.content_id())?;
        self.validate_planner_invocation_parent(Some(&parent_step), invocation)?;
        Ok(Some(parent_id))
    }

    pub(in crate::repository) fn validate_planner_invocation_parent(
        &self,
        parent: Option<&PlannerStep>,
        invocation: &PlannerInvocation,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(parent_step) = parent else {
            if invocation.scan_page().after().is_some() {
                return Err(integrity("planner-invocation-scan-start-mismatch"));
            }
            let engine = self.require_record_kind(
                invocation.engine().content_id(),
                crate::CampaignRecordKind::PlannerEngine,
            )?;
            let engine: PlannerEngine = crate::codec::decode(engine.body())?;
            let initial = if CanonicalFrontierPlanner::supports_descriptor(&engine)? {
                Some(CanonicalFrontierPlanner::initial_state_for_engine(&engine)?)
            } else if CanonicalPuctPlanner::supports_descriptor(&engine)? {
                Some(CanonicalPuctPlanner::initial_state_for_engine(&engine)?)
            } else {
                None
            };
            if let Some(initial) = initial {
                let state = self.require_record_kind(
                    invocation.planner_state().content_id(),
                    crate::CampaignRecordKind::PlannerState,
                )?;
                if crate::codec::decode::<PlannerState>(state.body())? != initial {
                    return Err(integrity("builtin-planner-initial-state-mismatch"));
                }
            }
            return Ok(());
        };
        if parent_step.next_state() != invocation.planner_state() {
            return Err(integrity("planner-step-parent-state-discontinuity"));
        }
        let expected_after = if parent_step.input_view() != invocation.input_view() {
            None
        } else {
            match parent_step.disposition() {
                PlannerDisposition::ContinueScan { cursor } => cursor.after(),
                PlannerDisposition::NoWork => {
                    return Err(integrity("planner-invocation-reopens-complete-view"));
                }
                PlannerDisposition::Issue { .. } => {
                    return Err(integrity("planner-invocation-reopens-issued-view"));
                }
            }
        };
        if invocation.scan_page().after() != expected_after {
            return Err(integrity("planner-invocation-scan-start-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_disposition_page(
        &self,
        invocation: &PlannerInvocation,
        disposition: &PlannerDisposition,
    ) -> Result<(), CampaignRepositoryError> {
        match disposition {
            PlannerDisposition::ContinueScan { cursor }
                if !invocation.scan_page().complete()
                    && cursor.input_view() == invocation.input_view()
                    && cursor.after() == invocation.scan_page().last() =>
            {
                Ok(())
            }
            PlannerDisposition::NoWork if invocation.scan_page().complete() => Ok(()),
            PlannerDisposition::Issue { .. } if invocation.scan_page().complete() => Ok(()),
            PlannerDisposition::ContinueScan { .. }
            | PlannerDisposition::Issue { .. }
            | PlannerDisposition::NoWork => Err(integrity(
                "planner-step-disposition-does-not-match-served-page",
            )),
        }
    }

    pub(in crate::repository) fn validate_planner_selected_source(
        &self,
        view: &CampaignPlanningView,
        disposition: &PlannerDisposition,
    ) -> Result<(), CampaignRepositoryError> {
        let PlannerDisposition::Issue { selected, .. } = disposition else {
            return Ok(());
        };
        let content = selected.source().content_id();
        if self.merkle.get(
            view.exploration(),
            map_key_content("exploration.branch-request", content),
        )? != Some(content)
            || self.read_branch_request(content)?.branch_point() != selected.branch_point()
        {
            return Err(integrity(
                "planner-step-selected-source-is-not-authoritative",
            ));
        }
        Ok(())
    }

    pub(in crate::repository) fn planner_scan_page(
        &self,
        view: &CampaignPlanningView,
        after: Option<PlanningScanPosition>,
        limit: u32,
    ) -> Result<PlanningScanPage, CampaignRepositoryError> {
        let limit_usize =
            usize::try_from(limit).map_err(|_| integrity("planner-scan-page-limit-is-invalid"))?;
        if limit == 0 || limit > MAX_PLANNER_SCAN_PAGE_ITEMS {
            return Err(integrity("planner-scan-page-limit-is-invalid"));
        }
        if let Some(after) = after {
            let source_content = after.source().content_id();
            if self.merkle.get(
                view.exploration(),
                map_key_content("exploration.branch-request", source_content),
            )? != Some(source_content)
                || self.read_branch_request(source_content)?.branch_point() != after.branch_point()
            {
                return Err(integrity("planner-scan-page-after-is-not-authoritative"));
            }
        }

        let retained_limit = limit_usize
            .checked_add(1)
            .ok_or_else(|| integrity("planner-scan-page-limit-is-invalid"))?;
        let retained = if let Some(indexed) =
            self.indexed_planner_scan_positions(view.exploration(), after, retained_limit)?
        {
            indexed
        } else {
            self.legacy_planner_scan_positions(view, after, retained_limit)?
        };
        let mut retained = retained;
        let complete = retained.len() <= limit_usize;
        if !complete {
            retained.pop_last();
        }
        let input_bytes = retained.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(*bytes)
                .ok_or_else(|| integrity("planner-scan-page-input-byte-overflow"))
        })?;
        PlanningScanPage::new(
            after,
            limit,
            retained.into_keys().collect(),
            complete,
            input_bytes,
        )
        .map_err(Into::into)
    }

    pub(in crate::repository) fn legacy_planner_scan_positions(
        &self,
        view: &CampaignPlanningView,
        after: Option<PlanningScanPosition>,
        retained_limit: usize,
    ) -> Result<BTreeMap<PlanningScanPosition, u64>, CampaignRepositoryError> {
        let mut retained = BTreeMap::<PlanningScanPosition, u64>::new();
        let mut storage_after = None;
        loop {
            let page = self.merkle.scan(
                view.exploration(),
                storage_after,
                PLANNER_SCAN_STORAGE_PAGE_ITEMS,
            )?;
            for (key, value) in page.entries() {
                if *key != map_key_content("exploration.branch-request", *value) {
                    continue;
                }
                let request = self.read_branch_request(*value)?;
                let position = PlanningScanPosition::new(request.branch_point(), request.id()?);
                if after.is_some_and(|after| position <= after) {
                    continue;
                }
                let input_bytes = u64::try_from(request.canonical_bytes().len())
                    .map_err(|_| integrity("planner-scan-page-input-byte-overflow"))?;
                retained.insert(position, input_bytes);
                if retained.len() > retained_limit {
                    retained.pop_last();
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            storage_after = Some(next);
        }

        Ok(retained)
    }
}
