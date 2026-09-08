//! Planner record loading, validation, and immutable storage.

use super::*;

impl CampaignRepository {
    /// Loads a planner invocation after validating all engine and input links.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the invocation basis is
    /// missing, corrupt, or binds records from different planner engines.
    pub fn load_planner_invocation(
        &self,
        id: PlannerInvocationId,
    ) -> Result<PlannerInvocation, CampaignRepositoryError> {
        let (envelope, invocation) = self.decode_planner_invocation(id.content_id())?;
        self.validate_planner_invocation_references(&envelope)?;
        Ok(invocation)
    }

    /// Loads a retained planner request and authenticates every stored input.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the request envelope,
    /// direct invocation basis, expected snapshot, or bundled object differs
    /// from its content-addressed repository record.
    pub fn load_planner_request(
        &self,
        id: RetainedPlannerRequestId,
    ) -> Result<PlannerRequest, CampaignRepositoryError> {
        let request = self.read_planner_request(id.content_id())?;
        self.validate_complete_head(request.expected_snapshot().content_id())?;
        Ok(request)
    }

    pub(in crate::repository) fn read_planner_request(
        &self,
        id: ContentId,
    ) -> Result<PlannerRequest, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::RetainedPlannerRequest)?;
        let request = PlannerRequest::from_canonical_bytes(envelope.body())?;
        if request.id()?.content_id() != id {
            return Err(integrity("planner-request-envelope-shape"));
        }
        self.validate_planner_request_inputs(&request)?;
        Ok(request)
    }

    pub(in crate::repository) fn validate_planner_request_inputs(
        &self,
        request: &PlannerRequest,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_planner_request_inputs_with_mode(request, false)
    }

    pub(in crate::repository) fn preflight_planner_request_inputs(
        &self,
        request: &PlannerRequest,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_planner_request_inputs_with_mode(request, true)
    }

    fn validate_planner_request_inputs_with_mode(
        &self,
        request: &PlannerRequest,
        allow_unpublished_derived_inputs: bool,
    ) -> Result<(), CampaignRepositoryError> {
        self.require_record_kind(
            request.expected_snapshot().content_id(),
            crate::CampaignRecordKind::Snapshot,
        )?;
        if self.load_planner_invocation(request.invocation_id()?)? != *request.invocation() {
            return Err(integrity("planner-request-invocation-mismatch"));
        }

        let engine = self.require_record_kind(
            request.invocation().engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        let artifact = self.require_record_kind(
            request.invocation().policy_artifact().content_id(),
            crate::CampaignRecordKind::PolicyArtifact,
        )?;
        let state = self.require_record_kind(
            request.invocation().planner_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let view = self.require_record_kind(
            request.invocation().input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if crate::codec::decode::<PlannerEngine>(engine.body())? != *request.engine()
            || crate::codec::decode::<PolicyArtifact>(artifact.body())?
                != *request.policy_artifact()
            || self.read_policy(request.invocation().policy().content_id())? != *request.policy()
            || crate::codec::decode::<PlannerState>(state.body())? != *request.planner_state()
            || crate::codec::decode::<CampaignPlanningView>(view.body())? != *request.input_view()
        {
            return Err(integrity("planner-request-by-value-basis-mismatch"));
        }
        let candidate_inputs = request.input_bundle().candidate_inputs(request)?;
        let mut unpublished_derived_inputs = candidate_inputs
            .values()
            .filter_map(|input| input.offer.as_ref())
            .map(Proposal::id)
            .map(|result| result.map(|id| id.content_id()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        unpublished_derived_inputs.extend(
            candidate_inputs
                .values()
                .filter_map(|input| input.guidance.as_ref())
                .map(crate::PlannerCandidateGuidance::id)
                .map(|result| result.map(|id| id.content_id()))
                .collect::<Result<BTreeSet<_>, _>>()?,
        );
        unpublished_derived_inputs.extend(
            candidate_inputs
                .values()
                .filter_map(|input| input.budget.as_ref())
                .map(crate::PlannerCandidateBudget::id)
                .map(|result| result.map(|id| id.content_id()))
                .collect::<Result<BTreeSet<_>, _>>()?,
        );
        for object_id in request.input_bundle().object_ids() {
            match self.read_envelope(object_id) {
                Ok(stored) => {
                    if request.input_bundle().object(object_id)?.as_ref() != Some(&stored) {
                        return Err(integrity("planner-request-bundle-object-mismatch"));
                    }
                }
                Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
                    if allow_unpublished_derived_inputs
                        && unpublished_derived_inputs.contains(&object_id) => {}
                Err(error) => return Err(error),
            }
        }
        let snapshot = self.read_snapshot(request.expected_snapshot().content_id())?;
        let budget_ledger = request
            .engine()
            .capabilities()
            .contains(crate::CANONICAL_FRONTIER_BUDGET_CAPABILITY)
            .then(|| self.parent_budget_ledger(&snapshot))
            .transpose()?;
        let mut request_budget_work = request
            .engine()
            .capabilities()
            .contains(crate::CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY)
            .then_some(super::budget::MAX_PLANNER_REQUEST_BUDGET_PROPOSALS);
        let mut guidance_points = candidate_inputs
            .iter()
            .filter_map(|(position, input)| {
                input.guidance.as_ref().map(|_| position.branch_point())
            })
            .collect::<BTreeSet<_>>();
        for (position, input) in &candidate_inputs {
            if input.offer.is_none() {
                continue;
            }
            let request = self.read_branch_request(position.source().content_id())?;
            let domain = self.read_choice_domain(request.domain().content_id())?;
            if self
                .candidate_source_profile(&request, &domain)?
                .is_some_and(|profile| {
                    profile.scores_interval_at(input.offer.as_ref().map_or(0, Proposal::ordinal))
                })
            {
                guidance_points.insert(position.branch_point());
            }
        }
        let puct_projections = if guidance_points.is_empty() {
            BTreeMap::new()
        } else {
            self.project_branch_puct_batch_loaded(&snapshot, guidance_points)?
        };
        let mut candidate_cache = PlannerCandidateProjectionCache::default();
        for (position, input) in candidate_inputs {
            let expected_projection = self.planner_continuation_projection(&snapshot, position)?;
            if expected_projection != input.continuation {
                return Err(integrity("planner-request-candidate-projection-mismatch"));
            }
            if let Some(offer) = &input.offer {
                let expected = self.planner_candidate_input(
                    &snapshot,
                    request.invocation_id()?,
                    position,
                    &mut candidate_cache,
                    puct_projections.get(&position.branch_point()),
                )?;
                if expected != (input.continuation, Some(offer.clone())) {
                    return Err(integrity("planner-request-candidate-projection-mismatch"));
                }
                if let Some(ledger) = budget_ledger {
                    let expected = self.planner_candidate_budget(
                        &snapshot,
                        offer,
                        ledger,
                        request_budget_work.as_mut(),
                    )?;
                    if input.budget.as_ref() != Some(&expected) {
                        return Err(integrity("planner-request-candidate-budget-mismatch"));
                    }
                }
            }
            if let Some(guidance) = &input.guidance {
                let offer = input
                    .offer
                    .as_ref()
                    .ok_or_else(|| integrity("planner-candidate-guidance-offer-is-missing"))?;
                let expected = self.planner_candidate_guidance(
                    &snapshot,
                    &puct_projections[&position.branch_point()],
                    offer,
                    guidance.schema_version(),
                    &mut candidate_cache,
                )?;
                if &expected != guidance {
                    return Err(integrity("planner-request-candidate-guidance-mismatch"));
                }
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_builtin_planner_proposal(
        &self,
        request: &PlannerRequest,
        proposal: &PlannerStepProposal,
    ) -> Result<(), CampaignRepositoryError> {
        let expected = if CanonicalFrontierPlanner::supports_descriptor(request.engine())? {
            CanonicalFrontierPlanner
                .plan(request)
                .map_err(CampaignRepositoryError::Codec)?
        } else if CanonicalPuctPlanner::supports_descriptor(request.engine())? {
            CanonicalPuctPlanner
                .plan(request)
                .map_err(CampaignRepositoryError::Codec)?
        } else {
            return Ok(());
        };
        if expected.proposal() != proposal {
            return Err(integrity("builtin-planner-output-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_builtin_planner_step(
        &self,
        request: &PlannerRequest,
        step: &PlannerStep,
    ) -> Result<(), CampaignRepositoryError> {
        let expected = if CanonicalFrontierPlanner::supports_descriptor(request.engine())? {
            CanonicalFrontierPlanner
                .plan(request)
                .map_err(CampaignRepositoryError::Codec)?
        } else if CanonicalPuctPlanner::supports_descriptor(request.engine())? {
            CanonicalPuctPlanner
                .plan(request)
                .map_err(CampaignRepositoryError::Codec)?
        } else {
            return Ok(());
        };
        let expected = expected.proposal();
        let next_state = expected.next_state().id()?;
        let disposition = match expected.disposition() {
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
        if step.invocation() != expected.invocation()
            || step.next_state() != next_state
            || step.usage_claim() != expected.usage_claim()
            || step.evidence() != expected.explanation()
            || step.disposition() != &disposition
        {
            return Err(integrity("builtin-planner-step-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn decode_planner_invocation(
        &self,
        id: ContentId,
    ) -> Result<(ObjectEnvelope, PlannerInvocation), CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::PlannerInvocation)?;
        let invocation = crate::codec::decode::<PlannerInvocation>(envelope.body())?;
        if invocation.id()?.content_id() != id {
            return Err(integrity("planner-invocation-envelope-shape"));
        }
        Ok((envelope, invocation))
    }

    pub(in crate::repository) fn put_planning_view(
        &self,
        view: &CampaignPlanningView,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlanningView,
            crate::object::content_children(view.content_children())?,
            view.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_planner_engine(
        &self,
        engine: &PlannerEngine,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerEngine,
            BTreeSet::new(),
            crate::codec::encode(engine),
        )?)
    }

    pub(in crate::repository) fn put_policy_artifact(
        &self,
        artifact: &PolicyArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PolicyArtifact,
            crate::object::content_children(artifact.content_children())?,
            crate::codec::encode(artifact),
        )?)
    }

    pub(in crate::repository) fn put_planner_state(
        &self,
        state: &PlannerState,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerState,
            crate::object::content_children([("engine", state.engine().content_id())])?,
            crate::codec::encode(state),
        )?)
    }

    pub(in crate::repository) fn put_planner_invocation(
        &self,
        invocation: &PlannerInvocation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerInvocation,
            crate::object::content_children(invocation.content_children())?,
            crate::codec::encode(invocation),
        )?)
    }

    pub(in crate::repository) fn put_planner_request(
        &self,
        request: &PlannerRequest,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::RetainedPlannerRequest,
            crate::object::content_children(request.content_children()?)?,
            request.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_planner_step(
        &self,
        step: &PlannerStep,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerStep,
            crate::object::content_children(step.content_children())?,
            step.canonical_bytes(),
        )?)
    }
}
