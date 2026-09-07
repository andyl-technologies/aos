//! Strict campaign record publication, loading, and cross-record validation.

use super::projection::PlannerCandidateProjectionCache;
use super::*;
use crate::IntegerValue;

fn charge_selection_resolution_record(
    envelope: &ObjectEnvelope,
    charged: &mut BTreeSet<ContentId>,
    charged_bytes: &mut usize,
) -> Result<(), CampaignRepositoryError> {
    if !charged.insert(envelope.content_id()) {
        return Ok(());
    }
    *charged_bytes = charged_bytes.checked_add(envelope.body().len()).ok_or(
        CampaignCodecError::InvalidValue {
            reason: "selection resolution byte accounting overflow",
        },
    )?;
    if *charged_bytes > MAX_SELECTION_RESOLUTION_BYTES {
        return Err(CampaignCodecError::InvalidValue {
            reason: "selection resolution exceeds canonical record byte limit",
        }
        .into());
    }
    Ok(())
}

impl CampaignRepository {
    /// Loads an exact campaign lineage and authenticates its scenario/genesis closure.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// semantically inconsistent lineage.
    pub fn load_lineage(
        &self,
        id: CampaignLineageId,
    ) -> Result<CampaignLineage, CampaignRepositoryError> {
        self.read_lineage(id.content_id())
    }

    /// Loads an exact measurement set and verifies its complete evidence closure.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for missing, malformed, or
    /// incorrectly typed measurement/evidence objects.
    pub fn load_measurement_set(
        &self,
        id: MeasurementSetId,
    ) -> Result<MeasurementSet, CampaignRepositoryError> {
        let value = self.read_measurement_set(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        Ok(value)
    }

    /// Loads an exact property-verdict set and verifies its evidence closure.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for missing, malformed, or
    /// incorrectly typed property/evidence objects.
    pub fn load_property_verdict_set(
        &self,
        id: PropertyVerdictSetId,
    ) -> Result<PropertyVerdictSet, CampaignRepositoryError> {
        let value = self.read_property_verdict_set(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        Ok(value)
    }

    /// Loads an exact coverage projection and verifies its derivation closure.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for missing, malformed, or
    /// incorrectly typed coverage/evidence objects.
    pub fn load_coverage_projection(
        &self,
        id: CoverageProjectionId,
    ) -> Result<CoverageProjection, CampaignRepositoryError> {
        let value = self.read_coverage_projection(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        Ok(value)
    }

    /// Loads one exact observation and validates its complete semantic closure.
    ///
    /// Standalone loading proves record semantics, not membership in a campaign
    /// snapshot's canonical attempt-completion index.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, malformed, or
    /// semantically inconsistent observation closure.
    pub fn load_observation(
        &self,
        id: ObservationId,
    ) -> Result<Observation, CampaignRepositoryError> {
        let value = self.read_observation(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        Ok(value)
    }

    /// Loads one exact objective evaluation and validates its complete basis.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, malformed, or
    /// semantically inconsistent evaluation closure.
    pub fn load_objective_evaluation(
        &self,
        id: ObjectiveEvaluationId,
    ) -> Result<ObjectiveEvaluation, CampaignRepositoryError> {
        let value = self.read_objective_evaluation(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        Ok(value)
    }

    /// Loads one exact ranking explanation and validates its references.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, malformed, or
    /// incorrectly referenced explanation closure.
    pub fn load_ranking_explanation(
        &self,
        id: RankingExplanationId,
    ) -> Result<RankingExplanation, CampaignRepositoryError> {
        let value = self.read_ranking_explanation(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        Ok(value)
    }

    /// Loads and exactly replays one survivor-selection decision.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the complete selection
    /// closure is missing, malformed, or differs from deterministic replay.
    pub fn load_survivor_selection(
        &self,
        id: SurvivorSelectionId,
    ) -> Result<SurvivorSelectionBundle, CampaignRepositoryError> {
        let bundle = self.read_survivor_selection_bundle(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        Ok(bundle)
    }

    /// Loads an exact proposal and validates its request, domain, policy, and planner basis.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the proposal or any exact
    /// semantic reference is missing, corrupt, or inconsistent.
    pub fn load_proposal(&self, id: ProposalId) -> Result<Proposal, CampaignRepositoryError> {
        self.read_proposal(id.content_id())
    }

    /// Loads an exact branch path and authenticates its stored identity.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// wrongly typed record.
    pub fn load_branch_path(
        &self,
        id: BranchPathId,
    ) -> Result<BranchPath, CampaignRepositoryError> {
        self.read_branch_path(id.content_id())
    }

    /// Loads an attempt and validates its exact path and start references.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the attempt or any exact
    /// semantic reference is missing, corrupt, or inconsistent.
    pub fn load_attempt(&self, id: AttemptId) -> Result<Attempt, CampaignRepositoryError> {
        self.read_attempt(id.content_id())
    }

    /// Loads an attempt admission and validates its attempt and cause closure.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the admission or any
    /// exact semantic reference is missing, corrupt, or inconsistent.
    pub fn load_attempt_admission(
        &self,
        id: AttemptAdmissionId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        self.read_attempt_admission(id.content_id())
    }

    /// Rejects standalone planner-step loading without its owning snapshot.
    ///
    /// Every version-4 step commits to an exact request snapshot, while an
    /// `Issue` step additionally owns admissions and exact root deltas. Those
    /// invariants require [`Self::load_planner_step_at`]. This method still
    /// authenticates the standalone closure before failing closed so callers
    /// never mistake structural readability for coordinator acceptance.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for invalid closure, followed
    /// by an owner-required integrity error for a structurally valid step.
    pub fn load_planner_step(
        &self,
        id: PlannerStepId,
    ) -> Result<PlannerStep, CampaignRepositoryError> {
        let step = self.read_planner_step(id.content_id())?;
        self.verify_campaign_closure(id.content_id())?;
        self.validate_standalone_planner_ancestry(&step)?;
        Err(integrity("planner-step-requires-snapshot-owner"))
    }

    /// Loads a planner step through one authoritative snapshot's complete owner validation.
    ///
    /// Snapshot context is required for `Issue` because attempt admission,
    /// deduplication, and exact exploration/accounting roots are not properties
    /// of the standalone step object.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the snapshot ancestry is
    /// invalid or the step is not an authenticated member of its coordination root.
    pub fn load_planner_step_at(
        &self,
        snapshot: CampaignSnapshotId,
        id: PlannerStepId,
    ) -> Result<PlannerStep, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        if self
            .merkle
            .get(loaded.snapshot.roots().coordination, planner_step_key(id))?
            != Some(id.content_id())
        {
            return Err(integrity("planner-step-is-not-authoritative-at-snapshot"));
        }
        self.read_planner_step(id.content_id())
    }

    fn validate_standalone_planner_ancestry(
        &self,
        first: &PlannerStep,
    ) -> Result<(), CampaignRepositoryError> {
        let mut step = first.clone();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if matches!(step.disposition(), PlannerDisposition::Issue { .. }) {
                return Err(integrity("planner-issue-requires-snapshot-owner"));
            }
            let invocation = self.load_planner_invocation(step.invocation())?;
            let view_envelope = self.require_record_kind(
                invocation.input_view().content_id(),
                crate::CampaignRecordKind::PlanningView,
            )?;
            let view = crate::codec::decode::<CampaignPlanningView>(view_envelope.body())?;
            if view.id()? != invocation.input_view() {
                return Err(integrity("planner-invocation-planning-view-envelope-shape"));
            }
            self.validate_planner_page(&view, &invocation)?;
            self.validate_planner_selected_source(&view, step.disposition())?;

            let parent = step
                .parent()
                .map(|parent| self.read_planner_step(parent.content_id()))
                .transpose()?;
            self.validate_planner_invocation_parent(parent.as_ref(), &invocation)?;
            let Some(parent) = parent else {
                return Ok(());
            };
            step = parent;
        }
        Err(integrity("planner-step-ancestry-limit"))
    }

    /// Loads an expansion state through the fail-closed projector validator.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the source snapshot,
    /// planning view, homogeneous projection roots, cursor, statistics, or
    /// continuation page fails owner recomputation.
    pub fn load_expansion_state(
        &self,
        id: ExpansionStateId,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        self.read_expansion_state(id.content_id())
    }

    /// Loads an exact scenario artifact and authenticates its stored identity.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// wrongly typed record.
    pub fn load_scenario_artifact(
        &self,
        id: ScenarioArtifactId,
    ) -> Result<ScenarioArtifact, CampaignRepositoryError> {
        self.read_scenario_artifact(id.content_id())
    }

    /// Loads a configuration and validates its exact scenario-artifact binding.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for an invalid record or
    /// cross-record semantic mismatch.
    pub fn load_configuration_artifact(
        &self,
        id: ConfigurationArtifactId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        self.read_configuration_artifact(id.content_id())
    }

    /// Loads a reproduction and validates its exact scenario/configuration basis.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for an invalid record or
    /// cross-record semantic mismatch.
    pub fn load_reproduction_artifact(
        &self,
        id: ReproductionArtifactId,
    ) -> Result<ReproductionArtifact, CampaignRepositoryError> {
        self.read_reproduction_artifact(id.content_id())
    }

    /// Loads an exact selectable declaration.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// wrongly typed declaration.
    pub fn load_selectable(
        &self,
        id: SelectableId,
    ) -> Result<SelectableDeclaration, CampaignRepositoryError> {
        self.read_selectable(id.content_id())
    }

    /// Loads an exact choice domain.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for a missing, corrupt, or
    /// wrongly typed domain.
    pub fn load_choice_domain(
        &self,
        id: ChoiceDomainId,
    ) -> Result<ChoiceDomain, CampaignRepositoryError> {
        self.read_choice_domain(id.content_id())
    }

    /// Loads and resolves a choice opportunity against its declaration/domain.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the opportunity or any
    /// of its exact references is missing, corrupt, or inconsistent.
    pub fn load_choice_opportunity(
        &self,
        id: ChoiceOpportunityId,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        self.read_opportunity(id.content_id())
    }

    /// Loads a choice group and validates every exact member declaration.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the group closure is
    /// missing, corrupt, or semantically inconsistent.
    pub fn load_choice_group(
        &self,
        id: ChoiceGroupId,
    ) -> Result<ChoiceGroup, CampaignRepositoryError> {
        self.read_group(id.content_id())
    }

    /// Loads a selection with the opportunity and domain needed to trust it.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for missing/corrupt records,
    /// illegal values, or invalid self-contained provenance. Model samples
    /// still require their pure model verifier before execution.
    pub fn resolve_selection(
        &self,
        id: SelectionId,
    ) -> Result<ResolvedSelection, CampaignRepositoryError> {
        self.resolve_selections(&[id])?
            .pop()
            .ok_or_else(|| integrity("selection-resolution-empty"))
    }

    /// Resolves selections while decoding each unique dependency once.
    pub(super) fn resolve_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        if ids.len() > MAX_SELECTION_RESOLUTION_RECORDS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection resolution batch exceeds record limit",
            }
            .into());
        }

        let mut charged = BTreeSet::new();
        let mut charged_bytes = 0usize;
        let mut selections = BTreeMap::<SelectionId, ResolvedSelection>::new();
        let mut opportunities = BTreeMap::<ContentId, Arc<ChoiceOpportunity>>::new();
        let mut declarations = BTreeMap::<ContentId, Arc<SelectableDeclaration>>::new();
        let mut domains = BTreeMap::<ContentId, Arc<ChoiceDomain>>::new();
        let mut resolved = Vec::with_capacity(ids.len());

        for id in ids {
            if let Some(selection) = selections.get(id) {
                resolved.push(selection.clone());
                continue;
            }

            let selection_envelope =
                self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Selection)?;
            charge_selection_resolution_record(
                &selection_envelope,
                &mut charged,
                &mut charged_bytes,
            )?;
            let selection = Selection::from_canonical_bytes(selection_envelope.body())?;
            if selection.id()? != *id {
                return Err(integrity("selection-envelope-shape"));
            }

            let opportunity_id = required_child(&selection_envelope, "opportunity")?;
            let selection_domain_id = required_child(&selection_envelope, "domain")?;
            let opportunity = if let Some(opportunity) = opportunities.get(&opportunity_id) {
                Arc::clone(opportunity)
            } else {
                let envelope = self.require_record_kind(
                    opportunity_id,
                    crate::CampaignRecordKind::ChoiceOpportunity,
                )?;
                charge_selection_resolution_record(&envelope, &mut charged, &mut charged_bytes)?;
                let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
                if opportunity.id()?.content_id() != opportunity_id {
                    return Err(integrity("choice-opportunity-envelope-shape"));
                }
                Arc::new(opportunity)
            };

            let declaration_id = opportunity.declaration().content_id();
            let declaration = if let Some(declaration) = declarations.get(&declaration_id) {
                Arc::clone(declaration)
            } else {
                let envelope = self.require_record_kind(
                    declaration_id,
                    crate::CampaignRecordKind::SelectableDeclaration,
                )?;
                charge_selection_resolution_record(&envelope, &mut charged, &mut charged_bytes)?;
                let declaration = SelectableDeclaration::from_canonical_bytes(envelope.body())?;
                if declaration.id()?.content_id() != declaration_id {
                    return Err(integrity("selectable-envelope-shape"));
                }
                let declaration = Arc::new(declaration);
                declarations.insert(declaration_id, Arc::clone(&declaration));
                declaration
            };

            let domain_id = opportunity.domain().content_id();
            if domain_id != selection_domain_id {
                return Err(integrity("selection-envelope-domain-mismatch"));
            }
            let domain = if let Some(domain) = domains.get(&domain_id) {
                Arc::clone(domain)
            } else {
                let envelope =
                    self.require_record_kind(domain_id, crate::CampaignRecordKind::ChoiceDomain)?;
                charge_selection_resolution_record(&envelope, &mut charged, &mut charged_bytes)?;
                let domain = ChoiceDomain::from_canonical_bytes(envelope.body())?;
                if domain.id()?.content_id() != domain_id {
                    return Err(integrity("choice-domain-envelope-shape"));
                }
                let domain = Arc::new(domain);
                domains.insert(domain_id, Arc::clone(&domain));
                domain
            };

            opportunity.validate_references(&declaration, &domain)?;
            selection.validate_resolved_references(&opportunity, &domain)?;
            opportunities.insert(opportunity_id, Arc::clone(&opportunity));
            let selection = ResolvedSelection {
                selection,
                opportunity,
                declaration,
                domain,
            };
            selections.insert(*id, selection.clone());
            resolved.push(selection);
        }
        Ok(resolved)
    }

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

    pub(super) fn read_planner_request(
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

    pub(super) fn validate_planner_request_inputs(
        &self,
        request: &PlannerRequest,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_planner_request_inputs_with_mode(request, false)
    }

    pub(super) fn preflight_planner_request_inputs(
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

    pub(super) fn validate_builtin_planner_proposal(
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

    pub(super) fn validate_builtin_planner_step(
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

    pub(super) fn decode_planner_invocation(
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

    pub(super) fn put_planning_view(
        &self,
        view: &CampaignPlanningView,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlanningView,
            crate::object::content_children(view.content_children())?,
            view.canonical_bytes(),
        )?)
    }

    pub(super) fn put_planner_engine(
        &self,
        engine: &PlannerEngine,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerEngine,
            BTreeSet::new(),
            crate::codec::encode(engine),
        )?)
    }

    pub(super) fn put_policy_artifact(
        &self,
        artifact: &PolicyArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PolicyArtifact,
            crate::object::content_children(artifact.content_children())?,
            crate::codec::encode(artifact),
        )?)
    }

    pub(super) fn put_planner_state(
        &self,
        state: &PlannerState,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerState,
            crate::object::content_children([("engine", state.engine().content_id())])?,
            crate::codec::encode(state),
        )?)
    }

    pub(super) fn put_planner_invocation(
        &self,
        invocation: &PlannerInvocation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerInvocation,
            crate::object::content_children(invocation.content_children())?,
            crate::codec::encode(invocation),
        )?)
    }

    pub(super) fn put_planner_request(
        &self,
        request: &PlannerRequest,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::RetainedPlannerRequest,
            crate::object::content_children(request.content_children()?)?,
            request.canonical_bytes(),
        )?)
    }

    pub(super) fn put_planner_step(
        &self,
        step: &PlannerStep,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerStep,
            crate::object::content_children(step.content_children())?,
            step.canonical_bytes(),
        )?)
    }

    pub(super) fn put_lineage(
        &self,
        lineage: &CampaignLineage,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_lineage(lineage)?)
    }

    pub(super) fn put_policy(
        &self,
        policy: &CampaignPolicy,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_policy(policy)?)
    }

    pub(super) fn put_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(generator.content_children())?,
            generator.canonical_bytes(),
        )?)
    }

    pub(super) fn put_branch_request(
        &self,
        request: &BranchRequest,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::BranchRequest,
            request.schema_version(),
            crate::object::content_children(request.content_children())?,
            request.canonical_bytes(),
        )?)
    }

    pub(super) fn put_continuation_projection(
        &self,
        projection: &ContinuationProjection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ContinuationProjection,
            crate::object::content_children(projection.content_children())?,
            projection.canonical_bytes(),
        )?)
    }

    pub(super) fn put_expansion_credit(
        &self,
        credit: &ExpansionCredit,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ExpansionCredit,
            crate::object::content_children(credit.content_children())?,
            credit.canonical_bytes(),
        )?)
    }

    pub(super) fn put_proposal(
        &self,
        proposal: &Proposal,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Proposal,
            crate::object::content_children(proposal.content_children())?,
            proposal.canonical_bytes(),
        )?)
    }

    pub(super) fn put_selection(
        &self,
        selection: &Selection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Selection,
            crate::object::content_children(selection.content_children())?,
            selection.canonical_bytes(),
        )?)
    }

    pub(super) fn put_branch_path(
        &self,
        path: &BranchPath,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_branch_path(path)?)
    }

    pub(super) fn put_attempt(
        &self,
        attempt: &Attempt,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Attempt,
            crate::object::content_children(attempt.content_children())?,
            attempt.canonical_bytes(),
        )?)
    }

    pub(super) fn put_attempt_admission(
        &self,
        admission: &AttemptAdmission,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::AttemptAdmission,
            admission.schema_version(),
            crate::object::content_children(admission.content_children())?,
            admission.canonical_bytes(),
        )?)
    }

    pub(super) fn put_measurement_set(
        &self,
        value: &MeasurementSet,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_measurement_set(value)?)
    }

    pub(super) fn put_property_verdict_set(
        &self,
        value: &PropertyVerdictSet,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PropertyVerdictSet,
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_coverage_projection(
        &self,
        value: &CoverageProjection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CoverageProjection,
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_observation(
        &self,
        value: &Observation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::Observation,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_objective_evaluation(
        &self,
        value: &ObjectiveEvaluation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::ObjectiveEvaluation,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_ranking_explanation(
        &self,
        value: &RankingExplanation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::RankingExplanation,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_survivor_selection(
        &self,
        value: &SurvivorSelection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::SurvivorSelection,
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_reproduction_artifact(
        &self,
        value: &ReproductionArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::ReproductionArtifact,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_finding(
        &self,
        value: &Finding,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::Finding,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(super) fn put_scenario_artifact(
        &self,
        artifact: &ScenarioArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ScenarioArtifact,
            BTreeSet::new(),
            artifact.canonical_bytes(),
        )?)
    }

    pub(super) fn put_configuration_artifact(
        &self,
        artifact: &ConfigurationArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ConfigurationArtifact,
            crate::object::content_children(artifact.content_children())?,
            artifact.canonical_bytes(),
        )?)
    }

    pub(super) fn put_planner_candidate_guidance(
        &self,
        guidance: &crate::PlannerCandidateGuidance,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::PlannerCandidateGuidance,
            guidance.schema_version(),
            crate::object::content_children(guidance.content_children())?,
            guidance.canonical_bytes(),
        )?)
    }

    pub(super) fn put_fact(
        &self,
        fact: &CampaignFact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_fact(fact)?)
    }

    pub(super) fn put_snapshot(
        &self,
        snapshot: &CampaignSnapshot,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let envelope = ObjectEnvelope::for_snapshot(snapshot)?;
        self.put_envelope(envelope)
    }

    pub(super) fn put_envelope(
        &self,
        envelope: ObjectEnvelope,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let id = envelope.content_id();
        let receipt = self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(envelope.canonical_bytes()))?;
        if receipt.id != id {
            return Err(integrity("store-receipt-id-mismatch"));
        }
        Ok(id)
    }

    pub(super) fn read_envelope(
        &self,
        id: ContentId,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let bytes = self.blobs.read(id, None)?.read_all(MAX_ENVELOPE_BYTES)?;
        let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
        if envelope.content_id() != id {
            return Err(integrity("envelope-content-id-mismatch"));
        }
        Ok(envelope)
    }

    pub(super) fn read_snapshot(
        &self,
        id: ContentId,
    ) -> Result<LoadedSnapshot, CampaignRepositoryError> {
        if id.kind() != ObjectKind::CampaignSnapshot {
            return Err(integrity("snapshot-content-kind"));
        }
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Snapshot {
            return Err(integrity("snapshot-record-kind"));
        }
        let snapshot = CampaignSnapshot::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_snapshot(&snapshot)? != envelope || snapshot.id()?.content_id() != id
        {
            return Err(integrity("snapshot-child-table-mismatch"));
        }
        Ok(LoadedSnapshot { envelope, snapshot })
    }

    pub(super) fn read_lineage(
        &self,
        id: ContentId,
    ) -> Result<CampaignLineage, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Lineage {
            return Err(integrity("lineage-envelope-shape"));
        }
        let lineage = CampaignLineage::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_lineage(&lineage)? != envelope || lineage.id()?.content_id() != id {
            return Err(integrity("lineage-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(lineage.scenario_content().content_id())?;
        let genesis = self.read_configuration_artifact(lineage.genesis_content().content_id())?;
        if scenario.scenario() != lineage.scenario()
            || scenario.payload_schema() != lineage.scenario_schema()
            || genesis.scenario() != lineage.scenario()
            || genesis.scenario_artifact() != lineage.scenario_content()
            || genesis.configuration() != lineage.genesis()
        {
            return Err(integrity("lineage-execution-model-artifact-mismatch"));
        }
        Ok(lineage)
    }

    pub(super) fn read_scenario_artifact(
        &self,
        id: ContentId,
    ) -> Result<ScenarioArtifact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ScenarioArtifact {
            return Err(integrity("scenario-artifact-envelope-shape"));
        }
        let artifact = ScenarioArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("scenario-artifact-envelope-shape"));
        }
        Ok(artifact)
    }

    pub(super) fn read_configuration_artifact(
        &self,
        id: ContentId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ConfigurationArtifact {
            return Err(integrity("configuration-artifact-envelope-shape"));
        }
        let artifact = ConfigurationArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("configuration-artifact-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(artifact.scenario_artifact().content_id())?;
        if scenario.scenario() != artifact.scenario() {
            return Err(integrity("configuration-scenario-artifact-mismatch"));
        }
        Ok(artifact)
    }

    pub(crate) fn read_reproduction_artifact(
        &self,
        id: ContentId,
    ) -> Result<ReproductionArtifact, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::ReproductionArtifact)?;
        let artifact = ReproductionArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("finding-reproduction-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(artifact.scenario_artifact().content_id())?;
        let configuration =
            self.read_configuration_artifact(artifact.configuration_artifact().content_id())?;
        if scenario.scenario() != artifact.scenario()
            || configuration.scenario() != artifact.scenario()
            || configuration.scenario_artifact() != artifact.scenario_artifact()
            || configuration.configuration() != artifact.configuration()
        {
            return Err(integrity("finding-reproduction-artifact-basis-mismatch"));
        }
        Ok(artifact)
    }

    pub(crate) fn read_finding(&self, id: ContentId) -> Result<Finding, CampaignRepositoryError> {
        self.read_finding_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(super) fn decode_finding(&self, id: ContentId) -> Result<Finding, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Finding)?;
        let finding = Finding::from_canonical_bytes(envelope.body())?;
        if finding.id()?.content_id() != id {
            return Err(integrity("finding-envelope-shape"));
        }
        Ok(finding)
    }

    pub(super) fn read_finding_cached(
        &self,
        id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<Finding, CampaignRepositoryError> {
        let finding = self.decode_finding(id)?;
        self.validate_finding_references_cached(&finding, choice_cache)?;
        Ok(finding)
    }

    pub(super) fn validate_finding_references_cached(
        &self,
        finding: &Finding,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = self.decode_observation(finding.observation().content_id())?;
        self.validate_observation_references_cached(&observation, choice_cache)?;
        let observation_child =
            self.read_configuration_artifact(observation.child_content().content_id())?;
        let occurrences = self.merkle.inspect_shallow(finding.occurrences())?;
        if occurrences.entry_count() != u64::from(finding.occurrence_count())
            || self.merkle.get(
                finding.occurrences(),
                finding_occurrence_key(finding.observation()),
            )? != Some(finding.observation().content_id())
            || self.merkle.get(
                finding.occurrences(),
                finding_occurrence_key(finding.latest_occurrence()),
            )? != Some(finding.latest_occurrence().content_id())
        {
            return Err(integrity("finding-occurrence-root-mismatch"));
        }
        let reproduction = self.read_reproduction_artifact(finding.reproduction().content_id())?;
        self.read_snapshot(finding.first_seen_snapshot().content_id())?;
        if reproduction.finding_fingerprint() != finding.signature().fingerprint()
            || reproduction.scenario() != observation_child.scenario()
            || reproduction.configuration_artifact() != observation.child_content()
        {
            return Err(integrity("finding-reproduction-observation-basis-mismatch"));
        }
        if finding.latest_occurrence() != finding.observation() {
            let latest = self.decode_observation(finding.latest_occurrence().content_id())?;
            self.validate_observation_references_cached(&latest, choice_cache)?;
            let latest_child =
                self.read_configuration_artifact(latest.child_content().content_id())?;
            if latest_child.scenario() != observation_child.scenario() {
                return Err(integrity("finding-occurrence-scenario-mismatch"));
            }
        }
        if let Some(minimized) = finding.minimized() {
            let minimized = self.read_reproduction_artifact(minimized.content_id())?;
            if minimized.finding_fingerprint() != finding.signature().fingerprint()
                || minimized.scenario() != observation_child.scenario()
            {
                return Err(integrity("finding-minimized-reproduction-basis-mismatch"));
            }
            if finding.schema_version() >= 2 {
                let minimization = minimized
                    .minimization()
                    .ok_or_else(|| integrity("finding-minimized-reproduction-has-no-trace"))?;
                if minimization.original() != finding.reproduction() {
                    return Err(integrity("finding-minimization-original-mismatch"));
                }
            }
        }
        for pin in finding.exact_pins() {
            let handle = self.blobs.read(pin.content_id(), None)?;
            handle.copy_to(&mut std::io::sink())?;
        }
        Ok(())
    }

    pub(super) fn read_policy(
        &self,
        id: ContentId,
    ) -> Result<CampaignPolicy, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Policy {
            return Err(integrity("policy-envelope-shape"));
        }
        let policy = CampaignPolicy::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_policy(&policy)? != envelope || policy.id()?.content_id() != id {
            return Err(integrity("policy-envelope-shape"));
        }
        for (_, child) in policy.content_children() {
            self.require_record_kind(child, crate::CampaignRecordKind::CandidateGeneratorSpec)?;
        }
        Ok(policy)
    }

    pub(super) fn read_generator(
        &self,
        id: ContentId,
    ) -> Result<CandidateGeneratorSpec, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::CandidateGeneratorSpec {
            return Err(integrity("candidate-generator-envelope-shape"));
        }
        let generator = CandidateGeneratorSpec::from_canonical_bytes(envelope.body())?;
        let expected = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(generator.content_children())?,
            generator.canonical_bytes(),
        )?;
        if expected != envelope || generator.id()?.content_id() != id {
            return Err(integrity("candidate-generator-envelope-shape"));
        }
        for (_, child) in generator.content_children() {
            self.require_record_kind(child, crate::CampaignRecordKind::CandidateGeneratorSpec)?;
        }
        Ok(generator)
    }

    pub(super) fn read_fact(&self, id: ContentId) -> Result<CampaignFact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Fact {
            return Err(integrity("fact-envelope-shape"));
        }
        let fact = CampaignFact::from_canonical_bytes(envelope.body())?;
        self.validate_fact_references(&fact)?;
        Ok(fact)
    }

    pub(super) fn validate_fact_references(
        &self,
        fact: &CampaignFact,
    ) -> Result<(), CampaignRepositoryError> {
        match fact {
            CampaignFact::CampaignDerived(derivation) => {
                self.require_record_kind(
                    derivation.source().content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                self.require_record_kind(
                    derivation.active_policy().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
            }
            CampaignFact::ChoiceOpportunityDiscovered {
                parent,
                opportunity,
                ..
            } => {
                self.require_record_kind(
                    parent.content_id(),
                    crate::CampaignRecordKind::ConfigurationArtifact,
                )?;
                self.require_record_kind(
                    opportunity.content_id(),
                    crate::CampaignRecordKind::ChoiceOpportunity,
                )?;
            }
            CampaignFact::PolicyActivated(activation) => {
                self.require_record_kind(
                    activation.prior().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
                self.require_record_kind(
                    activation.next().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
            }
            CampaignFact::ControlRequested(_)
            | CampaignFact::PinCommandAccepted(_)
            | CampaignFact::DiscoveryRequested(_) => self.validate_command_fact_references(fact)?,
            CampaignFact::BranchRequestIssued(id)
            | CampaignFact::BranchRequestAccepted { request: id, .. } => {
                self.read_branch_request(id.content_id())?;
            }
            CampaignFact::PlannerAdvanced(id) => {
                self.read_planner_step(id.content_id())?;
            }
            CampaignFact::ProposalIssued(id) => {
                self.read_proposal(id.content_id())?;
            }
            CampaignFact::AttemptAdmitted(admission) => {
                self.read_attempt_admission(admission.content_id())?;
            }
            CampaignFact::AttemptClosed { attempt, .. } => {
                self.require_record_kind(attempt.content_id(), crate::CampaignRecordKind::Attempt)?;
            }
            CampaignFact::ObservationPublished(id) | CampaignFact::ObservationCredited(id) => {
                self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Observation)?;
            }
            CampaignFact::FindingPublished(id) => {
                self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Finding)?;
            }
            CampaignFact::ObjectiveEvaluationPublished(id) => {
                self.read_objective_evaluation(id.content_id())?;
            }
            CampaignFact::BudgetGranted(_) | CampaignFact::PinChanged(_) => {}
        }
        Ok(())
    }

    pub(crate) fn read_branch_request(
        &self,
        id: ContentId,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.decode_branch_request(id)?;
        self.validate_branch_request_references(&request)?;
        Ok(request)
    }

    pub(super) fn decode_branch_request(
        &self,
        id: ContentId,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::BranchRequest)?;
        let request = BranchRequest::from_canonical_bytes(envelope.body())?;
        if request.id()?.content_id() != id {
            return Err(integrity("branch-request-envelope-shape"));
        }
        Ok(request)
    }

    pub(super) fn validate_branch_request_references(
        &self,
        request: &BranchRequest,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        request.validate_resolved(&parent, &opportunity, &domain)?;
        let mut remaining = MAX_CAMPAIGN_CLOSURE_OBJECTS;
        self.validate_candidate_source_generator_with_budget(
            request.source(),
            &domain,
            &mut remaining,
        )?;
        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                self.load_planner_invocation(invocation)?;
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::ScenarioDefault(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
        }
        Ok(parent)
    }

    pub(super) fn validate_branch_request_references_shallow(
        &self,
        request: &BranchRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        request.validate_resolved(&parent, &opportunity, &domain)?;
        if let Some(generator) = request.source().generator() {
            self.require_record_kind(
                generator.content_id(),
                crate::CampaignRecordKind::CandidateGeneratorSpec,
            )?;
        }
        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                self.require_record_kind(
                    invocation.content_id(),
                    crate::CampaignRecordKind::PlannerInvocation,
                )?;
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::ScenarioDefault(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn validate_generator_for_domain(
        &self,
        root: CandidateGeneratorSpecId,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignRepositoryError> {
        let mut remaining = MAX_CAMPAIGN_CLOSURE_OBJECTS;
        self.validate_generator_for_domain_with_budget(root, domain, &mut remaining)
    }

    pub(super) fn validate_candidate_source_generator_with_budget(
        &self,
        source: &CandidateSource,
        domain: &ChoiceDomain,
        remaining: &mut usize,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(generator_id) = source.generator() else {
            return Ok(());
        };
        if let CandidateSource::ModeledGenerated(_) = source {
            let generator = self.read_generator(generator_id.content_id())?;
            let ChoiceDomain::Integer(integer) = domain else {
                return Err(integrity("modeled-uniform-integer-domain-family-mismatch"));
            };
            let cardinality = integer.cardinality();
            if generator.algorithm() != &CandidateGeneratorAlgorithm::PermutedInteger
                || generator.implementation_version()
                    != crate::MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                || cardinality == 0
                || !cardinality.is_power_of_two()
                || cardinality > u128::from(u64::MAX) + 1
            {
                return Err(integrity("modeled-generated-source-contract-mismatch"));
            }
        }
        self.validate_generator_for_domain_with_budget(generator_id, domain, remaining)
    }

    pub(super) fn validate_generator_for_domain_with_budget(
        &self,
        root: CandidateGeneratorSpecId,
        domain: &ChoiceDomain,
        remaining: &mut usize,
    ) -> Result<(), CampaignRepositoryError> {
        let mut stack = vec![(root, 0_usize)];
        let mut visited = BTreeSet::new();
        while let Some((id, depth)) = stack.pop() {
            if depth > 1024 {
                return Err(integrity("candidate-generator-validation-limit"));
            }
            if !visited.insert(id) {
                continue;
            }
            if *remaining == 0 {
                return Err(integrity("candidate-generator-validation-limit"));
            }
            *remaining -= 1;
            let generator = self.read_generator(id.content_id())?;
            match generator.algorithm() {
                CandidateGeneratorAlgorithm::All
                    if matches!(domain, ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_)) => {}
                CandidateGeneratorAlgorithm::WeightedCategorical { weights } => {
                    let ChoiceDomain::Discrete(discrete) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    if weights
                        .keys()
                        .any(|alternative| !discrete.alternatives().contains_key(alternative))
                    {
                        return Err(integrity(
                            "candidate-generator-discrete-alternative-mismatch",
                        ));
                    }
                    if generator.implementation_version()
                        == crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION
                        && weights.len() > crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES
                    {
                        return Err(integrity("weighted-generator-alternative-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::BoundaryInteger => {
                    let ChoiceDomain::Integer(integer) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    if generator.implementation_version()
                        == crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && integer.landmarks().len()
                            > crate::BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS
                    {
                        return Err(integrity("boundary-generator-landmark-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::StratifiedInteger { strata } => {
                    if !matches!(domain, ChoiceDomain::Integer(_)) {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    }
                    if generator.implementation_version()
                        == crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && *strata > crate::STRATIFIED_INTEGER_GENERATOR_MAX_STRATA
                    {
                        return Err(integrity("stratified-generator-strata-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::LogInteger { .. } => {
                    let ChoiceDomain::Integer(integer) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    let minimum_is_positive = match integer.minimum() {
                        IntegerValue::Signed(value) => value > 0,
                        IntegerValue::Unsigned(value) => value > 0,
                    };
                    if generator.implementation_version()
                        == crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && !minimum_is_positive
                    {
                        return Err(integrity("log-generator-domain-is-not-positive"));
                    }
                }
                CandidateGeneratorAlgorithm::PermutedInteger => {
                    let ChoiceDomain::Integer(integer) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    if generator.implementation_version()
                        == crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && integer.cardinality() > crate::PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY
                    {
                        return Err(integrity("permuted-generator-cardinality-limit"));
                    }
                    if generator.implementation_version()
                        == crate::MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && (integer.cardinality() == 0
                            || !integer.cardinality().is_power_of_two()
                            || integer.cardinality() > u128::from(u64::MAX) + 1)
                    {
                        return Err(integrity("modeled-uniform-integer-cardinality-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::ProgressiveInteger { initial_strata, .. }
                    if matches!(domain, ChoiceDomain::Integer(_)) =>
                {
                    if matches!(
                        generator.implementation_version(),
                        crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::FEEDBACK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    ) && *initial_strata
                        > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA
                    {
                        return Err(integrity("progressive-generator-initial-strata-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::MutateNearCorpus { maximum_distance }
                    if matches!(domain, ChoiceDomain::Integer(_)) =>
                {
                    if generator.implementation_version()
                        == crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION
                        && *maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE
                    {
                        return Err(integrity("corpus-mutation-generator-distance-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::OrderedMixture { components } => {
                    stack.extend(
                        components
                            .iter()
                            .rev()
                            .map(|component| (component.generator(), depth + 1)),
                    );
                }
                _ => return Err(integrity("candidate-generator-domain-family-mismatch")),
            }
        }
        Ok(())
    }

    pub(super) fn validate_branch_request_campaign_scope(
        &self,
        snapshot: &LoadedSnapshot,
        request: &BranchRequest,
        parent: &ConfigurationArtifact,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        if parent.scenario() != lineage.scenario() {
            return Err(integrity("branch-request-parent-scenario-mismatch"));
        }
        let expected_parent = self.merkle.get(
            snapshot.snapshot.roots().graph,
            map_key_hash("graph.configuration", parent.configuration().as_hash()),
        )?;
        if expected_parent != Some(request.parent().content_id()) {
            return Err(integrity("branch-request-parent-is-not-in-campaign-graph"));
        }
        if self.merkle.get(
            snapshot.snapshot.roots().graph,
            branch_point_opportunity_key(request.branch_point(), request.opportunity()),
        )? != Some(request.opportunity().content_id())
        {
            return Err(integrity(
                "branch-request-opportunity-is-not-authoritative-campaign-knowledge",
            ));
        }

        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                let invocation = self.load_planner_invocation(invocation)?;
                if invocation.policy() != snapshot.snapshot.active_policy() {
                    return Err(integrity("branch-request-planner-policy-is-not-active"));
                }
                if invocation.input_view() != snapshot.snapshot.planning_view().id()? {
                    return Err(integrity("branch-request-planner-view-is-not-current"));
                }
            }
            BranchRequestCause::ExhaustivePolicy(policy)
                if policy != snapshot.snapshot.active_policy() =>
            {
                return Err(integrity("branch-request-policy-is-not-active"));
            }
            BranchRequestCause::ScenarioDefault(policy)
                if policy != snapshot.snapshot.active_policy() =>
            {
                return Err(integrity("branch-request-policy-is-not-active"));
            }
            BranchRequestCause::ExhaustivePolicy(_)
            | BranchRequestCause::ScenarioDefault(_)
            | BranchRequestCause::Operator(_)
            | BranchRequestCause::Debugger(_) => {}
        }

        if let BranchRequestCause::ExhaustivePolicy(policy_id) = request.cause() {
            let policy = self.read_policy(policy_id.content_id())?;
            let crate::ExplorerPolicy::Exhaustive {
                maximum_cardinality,
            } = policy.explorer()
            else {
                return Err(integrity(
                    "exhaustive-branch-request-policy-is-not-exhaustive",
                ));
            };
            let CandidateSource::Generated(generator_id) = request.source() else {
                return Err(integrity(
                    "exhaustive-branch-request-source-is-not-generated",
                ));
            };
            let generator = self.read_generator(generator_id.content_id())?;
            if generator.implementation_version()
                != crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION
                || generator.algorithm() != &CandidateGeneratorAlgorithm::All
            {
                return Err(integrity("exhaustive-branch-request-generator-is-not-all"));
            }
            let domain = self.read_choice_domain(request.domain().content_id())?;
            let cardinality = domain.cardinality();
            if cardinality > u128::from(*maximum_cardinality) {
                return Err(integrity("exhaustive-branch-request-domain-exceeds-policy"));
            }
            if u128::from(request.budget().maximum_proposals()) != cardinality {
                return Err(integrity(
                    "exhaustive-branch-request-budget-is-not-domain-cardinality",
                ));
            }
        }

        if let BranchRequestCause::ScenarioDefault(policy_id) = request.cause() {
            let policy = self.read_policy(policy_id.content_id())?;
            if !policy.admits_scenario_defaults() {
                return Err(integrity(
                    "scenario-default-branch-request-is-disabled-by-policy",
                ));
            }
            let CandidateSource::Finite(source) = request.source() else {
                return Err(integrity(
                    "scenario-default-branch-request-source-is-not-finite",
                ));
            };
            let opportunity = self.read_opportunity(request.opportunity().content_id())?;
            if source.prior_weights().is_some()
                || source.values().len() != 1
                || !source.values().contains(opportunity.default())
            {
                return Err(integrity(
                    "scenario-default-branch-request-source-is-not-exact-default",
                ));
            }
            if request.budget().maximum_proposals() != 1 || request.budget().maximum_attempts() != 1
            {
                return Err(integrity(
                    "scenario-default-branch-request-budget-is-not-one",
                ));
            }
        }

        if let CandidateSource::Generated(generator) = request.source()
            && matches!(
                request.cause(),
                BranchRequestCause::Planner(_) | BranchRequestCause::ExhaustivePolicy(_)
            )
        {
            let opportunity = self.read_opportunity(request.opportunity().content_id())?;
            let declaration = self.read_selectable(opportunity.declaration().content_id())?;
            let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
            let selected = policy.choice_policies().get(declaration.name());
            if selected.map(crate::ChoicePolicy::generator) != Some(*generator) {
                return Err(integrity(
                    "branch-request-generator-is-not-selected-by-active-policy",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_proposal_campaign_scope(
        &self,
        snapshot: &LoadedSnapshot,
        proposal: &Proposal,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.read_branch_request(proposal.request().content_id())?;
        let request_key = map_key_content(
            "exploration.branch-request",
            proposal.request().content_id(),
        );
        if self
            .merkle
            .get(snapshot.snapshot.roots().exploration, request_key)?
            != Some(proposal.request().content_id())
        {
            return Err(integrity("proposal-request-is-not-authoritative"));
        }

        let domain = self.read_choice_domain(proposal.domain().content_id())?;
        proposal.validate_resolved(&request, &domain)?;
        if proposal.policy() != snapshot.snapshot.active_policy()
            || proposal.guidance_basis() != snapshot.snapshot.planning_view().id()?
        {
            return Err(integrity("proposal-campaign-basis-mismatch"));
        }
        if let Some(invocation) = proposal.planner_invocation() {
            let invocation = self.load_planner_invocation(invocation)?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }

        let completed_visits = self.branch_completed_visits(
            snapshot.snapshot.roots().observations,
            request.branch_point(),
        )?;
        let feedback_projection = if self
            .candidate_source_profile(&request, &domain)?
            .is_some_and(|profile| profile.scores_interval_at(proposal.ordinal()))
        {
            Some(self.project_branch_puct_loaded(snapshot, request.branch_point())?)
        } else {
            None
        };
        let expected = self
            .expected_candidate_at_view(
                &request,
                &domain,
                proposal.ordinal(),
                super::projection::CandidateEnumerationBasis::new(
                    super::projection::CandidateViewRoots::from_roots(snapshot.snapshot.roots()),
                    completed_visits,
                )
                .with_feedback(feedback_projection.as_ref().map(|projection| {
                    super::projection::CandidateFeedbackProjection::new(
                        snapshot.snapshot.active_policy(),
                        projection,
                    )
                })),
            )?
            .ok_or_else(|| integrity("generated-proposal-enumerator-is-not-implemented"))?;
        if &expected != proposal.value() {
            return Err(integrity("proposal-value-does-not-match-source-order"));
        }
        Ok(request)
    }

    pub(super) fn validate_proposal_references_shallow(
        &self,
        proposal: &Proposal,
    ) -> Result<(), CampaignRepositoryError> {
        let request = self.decode_branch_request(proposal.request().content_id())?;
        let domain = self.read_choice_domain(proposal.domain().content_id())?;
        proposal.validate_resolved(&request, &domain)?;
        self.read_policy(proposal.policy().content_id())?;
        self.require_record_kind(
            proposal.guidance_basis().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if let Some(invocation_id) = proposal.planner_invocation() {
            let (_, invocation) = self.decode_planner_invocation(invocation_id.content_id())?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }
        Ok(())
    }

    pub(super) fn read_proposal(&self, id: ContentId) -> Result<Proposal, CampaignRepositoryError> {
        let proposal = self.decode_proposal(id)?;
        let request = self.read_branch_request(proposal.request().content_id())?;
        let domain = self.read_choice_domain(proposal.domain().content_id())?;
        proposal.validate_resolved(&request, &domain)?;
        self.read_policy(proposal.policy().content_id())?;
        self.require_record_kind(
            proposal.guidance_basis().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if let Some(invocation) = proposal.planner_invocation() {
            let invocation = self.load_planner_invocation(invocation)?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }
        Ok(proposal)
    }

    pub(super) fn decode_proposal(
        &self,
        id: ContentId,
    ) -> Result<Proposal, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Proposal)?;
        let proposal = Proposal::from_canonical_bytes(envelope.body())?;
        if proposal.id()?.content_id() != id {
            return Err(integrity("proposal-envelope-shape"));
        }
        Ok(proposal)
    }

    pub(super) fn read_measurement_set(
        &self,
        id: ContentId,
    ) -> Result<MeasurementSet, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::MeasurementSet)?;
        let value = MeasurementSet::from_canonical_bytes(envelope.body())?;
        if value.id()?.content_id() != id {
            return Err(integrity("measurement-set-envelope-shape"));
        }
        Ok(value)
    }

    pub(super) fn read_property_verdict_set(
        &self,
        id: ContentId,
    ) -> Result<PropertyVerdictSet, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::PropertyVerdictSet)?;
        let value = PropertyVerdictSet::from_canonical_bytes(envelope.body())?;
        if value.id()?.content_id() != id {
            return Err(integrity("property-verdict-set-envelope-shape"));
        }
        Ok(value)
    }

    pub(super) fn read_coverage_projection(
        &self,
        id: ContentId,
    ) -> Result<CoverageProjection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::CoverageProjection)?;
        let value = CoverageProjection::from_canonical_bytes(envelope.body())?;
        if value.id()?.content_id() != id {
            return Err(integrity("coverage-projection-envelope-shape"));
        }
        Ok(value)
    }

    pub(crate) fn read_observation(
        &self,
        id: ContentId,
    ) -> Result<Observation, CampaignRepositoryError> {
        let observation = self.decode_observation(id)?;
        self.validate_observation_references(&observation)?;
        Ok(observation)
    }

    pub(super) fn decode_observation(
        &self,
        id: ContentId,
    ) -> Result<Observation, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Observation)?;
        let observation = Observation::from_canonical_bytes(envelope.body())?;
        if observation.id()?.content_id() != id {
            return Err(integrity("observation-envelope-shape"));
        }
        Ok(observation)
    }

    pub(super) fn read_objective_evaluation(
        &self,
        id: ContentId,
    ) -> Result<ObjectiveEvaluation, CampaignRepositoryError> {
        self.read_objective_evaluation_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(super) fn read_objective_evaluation_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<ObjectiveEvaluation, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::ObjectiveEvaluation)?;
        let evaluation = ObjectiveEvaluation::from_canonical_bytes(envelope.body())?;
        if evaluation.id()?.content_id() != id {
            return Err(integrity("objective-evaluation-envelope-shape"));
        }
        let policy = evaluation.policy();
        let contract = if let Some(contract) = cache.objective_contract(policy) {
            contract
        } else {
            let value = self.read_policy(policy.content_id())?;
            let contract = value.objective_contract_hash();
            cache.insert_objective_contract(policy, contract);
            contract
        };
        let observation = self.decode_observation(evaluation.observation().content_id())?;
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        evaluation.validate_compact_basis(policy, contract, &observation, &properties)?;
        Ok(evaluation)
    }

    pub(super) fn read_ranking_explanation(
        &self,
        id: ContentId,
    ) -> Result<RankingExplanation, CampaignRepositoryError> {
        self.read_ranking_explanation_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(super) fn read_ranking_explanation_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<RankingExplanation, CampaignRepositoryError> {
        let explanation = self.decode_ranking_explanation(id)?;
        self.read_objective_evaluation_cached(explanation.evaluation().content_id(), cache)?;
        if let crate::RankingDisposition::ParetoDominated(dominator) = explanation.disposition() {
            self.read_objective_evaluation_cached(dominator.content_id(), cache)?;
        }
        Ok(explanation)
    }

    pub(super) fn decode_ranking_explanation(
        &self,
        id: ContentId,
    ) -> Result<RankingExplanation, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::RankingExplanation)?;
        let explanation = RankingExplanation::from_canonical_bytes(envelope.body())?;
        if explanation.id()?.content_id() != id {
            return Err(integrity("ranking-explanation-envelope-shape"));
        }
        Ok(explanation)
    }

    pub(super) fn read_survivor_selection_bundle(
        &self,
        id: ContentId,
    ) -> Result<SurvivorSelectionBundle, CampaignRepositoryError> {
        self.read_survivor_selection_bundle_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(super) fn read_survivor_selection_bundle_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<SurvivorSelectionBundle, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::SurvivorSelection)?;
        let selection = SurvivorSelection::from_canonical_bytes(envelope.body())?;
        if selection.id()?.content_id() != id {
            return Err(integrity("survivor-selection-envelope-shape"));
        }
        let policy = self.read_policy(selection.policy().content_id())?;
        cache.insert_objective_contract(selection.policy(), policy.objective_contract_hash());
        let considered_evaluations = selection
            .considered()
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut candidates = Vec::with_capacity(selection.considered().len());
        let mut evidence_bytes = 0;
        for (configuration, evaluation_id) in selection.considered() {
            let evaluation =
                self.read_objective_evaluation_cached(evaluation_id.content_id(), cache)?;
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                evaluation.canonical_bytes().len(),
            )?;
            let explanation_id = selection
                .explanations()
                .get(configuration)
                .ok_or_else(|| integrity("survivor-selection-explanation-missing"))?;
            let explanation = self.decode_ranking_explanation(explanation_id.content_id())?;
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                explanation.canonical_bytes().len(),
            )?;
            if evaluation.configuration() != *configuration
                || explanation.evaluation() != *evaluation_id
            {
                return Err(integrity("survivor-selection-candidate-basis-mismatch"));
            }
            if let crate::RankingDisposition::ParetoDominated(dominator) = explanation.disposition()
                && !considered_evaluations.contains(dominator)
            {
                return Err(integrity("survivor-selection-dominator-is-not-considered"));
            }
            candidates.push(crate::RankingCandidate::new(
                evaluation,
                explanation.novelty_score(),
                explanation.breadth_ordinal(),
            ));
        }
        let replayed = crate::rank_survivors(&policy, selection.rule(), candidates)?;
        if replayed.selection() != &selection {
            return Err(integrity("survivor-selection-replay-mismatch"));
        }
        Ok(replayed)
    }

    pub(super) fn validate_observation_references(
        &self,
        observation: &Observation,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_observation_references_cached(
            observation,
            &mut ChoiceValidationCache::default(),
        )
    }

    pub(super) fn validate_observation_references_cached(
        &self,
        observation: &Observation,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let attempt = self.read_attempt(observation.attempt().content_id())?;
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        if child.configuration() != observation.child()
            || attempt.path() != observation.path()
            || matches!(observation.stop(), StopOutcome::Reached(stop) if stop != attempt.stop())
        {
            return Err(integrity("observation-attempt-or-child-mismatch"));
        }
        self.read_measurement_set(observation.measurements().content_id())?;
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        self.read_coverage_projection(observation.coverage().content_id())?;
        for choice in observation.discovered_choices() {
            let choice = self.read_opportunity_cached(choice.content_id(), choice_cache)?;
            if choice.scenario() != child.scenario() {
                return Err(integrity("observation-choice-scenario-mismatch"));
            }
        }
        self.validate_observation_produced_selections(observation, &child)?;
        if matches!(
            observation.stop(),
            StopOutcome::Reached(StopCondition::NextChoice)
        ) && observation.discovered_choices().is_empty()
        {
            return Err(integrity("next-choice-observation-has-no-choice"));
        }
        if let StopOutcome::AssertionFailure(property) = observation.stop()
            && properties
                .properties()
                .get(property)
                .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
        {
            return Err(integrity("assertion-outcome-has-no-failed-property"));
        }
        Ok(())
    }

    pub(super) fn read_attempt(&self, id: ContentId) -> Result<Attempt, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Attempt)?;
        let attempt = Attempt::from_canonical_bytes(envelope.body())?;
        if attempt.id()?.content_id() != id {
            return Err(integrity("attempt-envelope-shape"));
        }
        let path = self.read_branch_path(attempt.path().content_id())?;
        match attempt.start() {
            AttemptStart::Discover { configuration } => {
                self.read_configuration_artifact(configuration.content_id())?;
            }
            AttemptStart::Branch {
                edge,
                parent,
                selection,
            } => {
                if path.edges().last() != Some(&edge) {
                    return Err(integrity("attempt-branch-path-terminal-edge-mismatch"));
                }
                let parent = self.read_configuration_artifact(parent.content_id())?;
                let resolved = self.resolve_selection(selection)?;
                let branch_point = resolved
                    .opportunity()
                    .branch_point_id(parent.configuration());
                resolved.selection().validate_branch_replay(
                    resolved.opportunity(),
                    resolved.domain(),
                    branch_point,
                )?;
                if let crate::SelectionOrigin::CampaignBranch {
                    edge: selected_edge,
                    ..
                } = resolved.selection().origin()
                    && selected_edge != edge
                {
                    return Err(integrity("attempt-branch-edge-mismatch"));
                }
                if path.segments().is_some_and(|segments| {
                    segments.last().copied()
                        != Some(crate::BranchPathSegment::new(branch_point, edge))
                }) {
                    return Err(integrity("attempt-branch-path-terminal-scope-mismatch"));
                }
            }
        }
        Ok(attempt)
    }

    pub(super) fn read_branch_path(
        &self,
        id: ContentId,
    ) -> Result<BranchPath, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::BranchPath)?;
        let path = BranchPath::from_canonical_bytes(envelope.body())?;
        if path.id()?.content_id() != id {
            return Err(integrity("branch-path-envelope-shape"));
        }
        Ok(path)
    }

    pub(super) fn validate_proposal_attempt_equivalence(
        &self,
        proposal: &Proposal,
        attempt: &Attempt,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.read_branch_request(proposal.request().content_id())?;
        self.validate_proposal_attempt_equivalence_with_request(proposal, attempt, &request)?;
        Ok(request)
    }

    fn validate_proposal_attempt_equivalence_with_request(
        &self,
        proposal: &Proposal,
        attempt: &Attempt,
        request: &BranchRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let AttemptStart::Branch {
            edge: _,
            parent,
            selection,
        } = attempt.start()
        else {
            return Err(integrity("proposal-cannot-admit-discovery-attempt"));
        };
        let resolved = self.resolve_selection(selection)?;
        if parent != request.parent()
            || attempt.stop() != request.stop()
            || resolved.opportunity().id()? != request.opportunity()
            || resolved.domain().id()? != request.domain()
            || resolved.selection().value() != proposal.value()
        {
            return Err(integrity("proposal-attempt-semantic-mismatch"));
        }
        Ok(())
    }

    pub(super) fn read_attempt_admission(
        &self,
        id: ContentId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let admission = self.decode_attempt_admission(id)?;
        let attempt = self.read_attempt(admission.attempt().content_id())?;
        match admission.role() {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                cause,
                ..
            } => {
                let proposal = self.read_proposal(proposal.content_id())?;
                let request = self.validate_proposal_attempt_equivalence(&proposal, &attempt)?;
                if request.cause() != cause {
                    return Err(integrity("attempt-execution-basis-mismatch"));
                }
            }
            AttemptAdmissionRole::ExecutionBasis { proposal: None, .. }
                if !matches!(attempt.start(), AttemptStart::Discover { .. }) =>
            {
                return Err(integrity("branch-attempt-execution-basis-has-no-proposal"));
            }
            AttemptAdmissionRole::ExecutionBasis { .. } => {}
            AttemptAdmissionRole::AdditionalCause { proposal } => {
                let proposal = self.read_proposal(proposal.content_id())?;
                self.validate_proposal_attempt_equivalence(&proposal, &attempt)?;
            }
        }
        Ok(admission)
    }

    pub(super) fn decode_attempt_admission(
        &self,
        id: ContentId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::AttemptAdmission)?;
        let admission = AttemptAdmission::from_canonical_bytes(envelope.body())?;
        if admission.id()?.content_id() != id {
            return Err(integrity("attempt-admission-envelope-shape"));
        }
        Ok(admission)
    }

    pub(super) fn validate_attempt_admission_references_shallow(
        &self,
        admission: &AttemptAdmission,
    ) -> Result<(), CampaignRepositoryError> {
        let attempt = self.read_attempt(admission.attempt().content_id())?;
        match admission.role() {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                cause,
                ..
            } => {
                let proposal = self.decode_proposal(proposal.content_id())?;
                let request = self.decode_branch_request(proposal.request().content_id())?;
                self.validate_proposal_attempt_equivalence_with_request(
                    &proposal, &attempt, &request,
                )?;
                if request.cause() != cause {
                    return Err(integrity("attempt-execution-basis-mismatch"));
                }
            }
            AttemptAdmissionRole::ExecutionBasis { proposal: None, .. }
                if !matches!(attempt.start(), AttemptStart::Discover { .. }) =>
            {
                return Err(integrity("branch-attempt-execution-basis-has-no-proposal"));
            }
            AttemptAdmissionRole::ExecutionBasis { .. } => {}
            AttemptAdmissionRole::AdditionalCause { proposal } => {
                let proposal = self.decode_proposal(proposal.content_id())?;
                let request = self.decode_branch_request(proposal.request().content_id())?;
                self.validate_proposal_attempt_equivalence_with_request(
                    &proposal, &attempt, &request,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn count_request_execution_bases(
        &self,
        accounting_root: ContentId,
        request: BranchRequestId,
    ) -> Result<u64, CampaignRepositoryError> {
        let mut after = None;
        let mut count = 0_u64;
        loop {
            let page = self.merkle.scan(accounting_root, after, 10_000)?;
            for (key, value) in page.entries() {
                if *key != map_key_content("accounting.attempt-admission", *value) {
                    continue;
                }
                let admission = self.decode_attempt_admission(*value)?;
                let AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                } = admission.role()
                else {
                    continue;
                };
                if self.decode_proposal(proposal.content_id())?.request() == request {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| integrity("request-attempt-count-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                return Ok(count);
            };
            after = Some(next);
        }
    }

    pub(super) fn next_admission_ordinal(
        &self,
        accounting_root: ContentId,
    ) -> Result<AdmissionOrdinal, CampaignRepositoryError> {
        let Some(latest) = self.merkle.get(accounting_root, admission_sequence_key())? else {
            return Ok(AdmissionOrdinal::new(1));
        };
        let admission = self.decode_attempt_admission(latest)?;
        let AttemptAdmissionRole::ExecutionBasis {
            admission_ordinal, ..
        } = admission.role()
        else {
            return Err(integrity(
                "admission-sequence-does-not-name-execution-basis",
            ));
        };
        admission_ordinal
            .checked_next()
            .ok_or_else(|| integrity("admission-ordinal-overflow"))
    }

    pub(super) fn expected_proposal_admission(
        &self,
        snapshot: &LoadedSnapshot,
        proposal: ProposalId,
        attempt: AttemptId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        self.expected_proposal_admission_at(
            snapshot,
            roots.exploration,
            roots.accounting,
            proposal,
            attempt,
        )
    }

    pub(super) fn expected_proposal_admission_at(
        &self,
        snapshot: &LoadedSnapshot,
        exploration_root: ContentId,
        accounting_root: ContentId,
        proposal: ProposalId,
        attempt: AttemptId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let proposal_content = proposal.content_id();
        if self.merkle.get(
            exploration_root,
            map_key_content("exploration.proposal", proposal_content),
        )? != Some(proposal_content)
        {
            return Err(integrity("admission-proposal-is-not-authoritative"));
        }
        if self
            .merkle
            .get(
                accounting_root,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            .is_some()
        {
            return Err(integrity("proposal-already-has-admission"));
        }

        let proposal_record = self.read_proposal(proposal_content)?;
        let attempt_record = self.read_attempt(attempt.content_id())?;
        let request =
            self.validate_proposal_attempt_equivalence(&proposal_record, &attempt_record)?;
        let AttemptStart::Branch { edge, .. } = attempt_record.start() else {
            return Err(integrity("proposal-admission-attempt-is-discovery"));
        };
        let path = self.read_branch_path(attempt_record.path().content_id())?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        self.validate_attempt_path_owner(snapshot, &lineage, &request, &path, edge)?;
        let attempt_key = map_key_content("accounting.attempt", attempt.content_id());
        let basis_key = map_key_content("accounting.attempt-execution-basis", attempt.content_id());
        let indexed_attempt = self.merkle.get(accounting_root, attempt_key)?;
        let indexed_basis = self.merkle.get(accounting_root, basis_key)?;

        match (indexed_attempt, indexed_basis) {
            (None, None) => {
                if self.request_execution_bases_at(snapshot, proposal_record.request())?
                    >= request.budget().maximum_attempts()
                {
                    return Err(integrity("branch-request-attempt-budget-exhausted"));
                }
                Ok(AttemptAdmission::new(
                    attempt,
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        cause: request.cause(),
                        admission_ordinal: self.next_admission_ordinal(accounting_root)?,
                    },
                ))
            }
            (Some(indexed_attempt), Some(indexed_basis))
                if indexed_attempt == attempt.content_id() =>
            {
                let basis = self.read_attempt_admission(indexed_basis)?;
                if basis.attempt() != attempt
                    || !matches!(basis.role(), AttemptAdmissionRole::ExecutionBasis { .. })
                {
                    return Err(integrity("attempt-execution-basis-index-mismatch"));
                }
                Ok(AttemptAdmission::new(
                    attempt,
                    AttemptAdmissionRole::AdditionalCause { proposal },
                ))
            }
            _ => Err(integrity("attempt-admission-index-shape")),
        }
    }

    pub(super) fn validate_attempt_path_owner(
        &self,
        snapshot: &LoadedSnapshot,
        lineage: &CampaignLineage,
        request: &BranchRequest,
        path: &BranchPath,
        edge: crate::BranchEdgeId,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(segments) = path.segments() else {
            if request.parent() == lineage.genesis_content() && path.edges() == [edge] {
                return Ok(());
            }
            return Err(integrity("proposal-admission-requires-scoped-branch-path"));
        };
        let Some((terminal, prefix)) = segments.split_last() else {
            return Err(integrity("proposal-admission-branch-path-is-empty"));
        };
        if *terminal != crate::BranchPathSegment::new(request.branch_point(), edge) {
            return Err(integrity(
                "proposal-admission-branch-path-terminal-scope-mismatch",
            ));
        }

        let prefix = BranchPath::new(prefix.to_vec())?;
        if request.parent() == lineage.genesis_content() {
            if !prefix.edges().is_empty() {
                return Err(integrity(
                    "proposal-admission-genesis-path-prefix-is-not-empty",
                ));
            }
            return Ok(());
        }

        let path_index = self
            .merkle
            .get(
                snapshot.snapshot.roots().observations,
                configuration_path_index_key(request.parent()),
            )?
            .ok_or_else(|| integrity("proposal-admission-parent-path-index-is-missing"))?;
        let prefix_id = prefix.id()?;
        if self
            .merkle
            .get(path_index, path_index_order_key(prefix_id))?
            != Some(prefix_id.content_id())
        {
            return Err(integrity(
                "proposal-admission-path-prefix-is-not-authoritative",
            ));
        }
        Ok(())
    }

    pub(super) fn read_planner_step(
        &self,
        id: ContentId,
    ) -> Result<PlannerStep, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::PlannerStep)?;
        let step = PlannerStep::from_canonical_bytes(envelope.body())?;
        if step.id()?.content_id() != id {
            return Err(integrity("planner-step-envelope-shape"));
        }
        let request = self.read_planner_request(step.request().content_id())?;
        if request.invocation_id()? != step.invocation()
            || request.request_digest() != step.request_digest()
        {
            return Err(integrity("planner-step-request-mismatch"));
        }
        let invocation = self.load_planner_invocation(step.invocation())?;
        if invocation.engine() != step.engine()
            || invocation.policy_artifact() != step.policy_artifact()
            || invocation.policy() != step.policy()
            || invocation.input_view() != step.input_view()
        {
            return Err(integrity("planner-step-invocation-mismatch"));
        }
        self.validate_planner_disposition_page(&invocation, step.disposition())?;

        let next_state_envelope = self.require_record_kind(
            step.next_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let next_state = crate::codec::decode::<PlannerState>(next_state_envelope.body())?;
        if next_state.id()? != step.next_state() || next_state.engine() != step.engine() {
            return Err(integrity("planner-step-next-state-engine-mismatch"));
        }

        let accounting = step.accounting();
        let budget = invocation.budget();
        if accounting.branch_requests > u64::from(budget.branch_requests())
            || accounting.proposals > u64::from(budget.proposals())
            || accounting.input_objects != invocation.scan_page().input_objects()
            || accounting.input_bytes != invocation.scan_page().input_bytes()
            || accounting.input_objects > u64::from(budget.input_objects())
            || accounting.input_bytes > budget.input_bytes()
            || accounting.fuel > budget.fuel()
        {
            return Err(integrity("planner-step-invocation-budget-exceeded"));
        }
        let usage_claim = step.usage_claim();
        if usage_claim.branch_requests > u64::from(budget.branch_requests())
            || usage_claim.proposals > u64::from(budget.proposals())
            || usage_claim.input_objects > u64::from(budget.input_objects())
            || usage_claim.input_bytes > budget.input_bytes()
            || usage_claim.fuel > budget.fuel()
        {
            return Err(integrity("planner-step-usage-claim-exceeds-budget"));
        }

        if let Some(parent) = step.parent() {
            let parent_envelope = self
                .require_record_kind(parent.content_id(), crate::CampaignRecordKind::PlannerStep)?;
            let parent_step = PlannerStep::from_canonical_bytes(parent_envelope.body())?;
            if parent_step.id()? != parent || parent_step.next_state() != invocation.planner_state()
            {
                return Err(integrity("planner-step-parent-state-discontinuity"));
            }
        }
        Ok(step)
    }

    pub(super) fn read_expansion_state(
        &self,
        id: ContentId,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ExpansionState)?;
        let state = ExpansionState::from_canonical_bytes(envelope.body())?;
        if state.id()?.content_id() != id {
            return Err(integrity("expansion-state-envelope-shape"));
        }
        let view_envelope = self.require_record_kind(
            state.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        let stored_view = crate::codec::decode::<CampaignPlanningView>(view_envelope.body())?;
        if stored_view.id()? != state.input_view() {
            return Err(integrity("expansion-state-planning-view-envelope-shape"));
        }
        for root in [
            state.request_root(),
            state.proposal_root(),
            state.admission_root(),
            state.observation_root(),
        ] {
            self.merkle.verify_closure_streaming(root)?;
        }
        self.validate_complete_head(state.source_snapshot().content_id())?;
        let expected = self.recompute_finite_expansion(
            state.source_snapshot(),
            state.branch_point(),
            state.page_after(),
            state.page_size(),
        )?;
        if state != expected {
            return Err(integrity("expansion-state-owner-recomputation-mismatch"));
        }
        Ok(state)
    }

    pub(crate) fn read_continuation_projection(
        &self,
        id: ContentId,
    ) -> Result<ContinuationProjection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::ContinuationProjection)?;
        let projection = ContinuationProjection::from_canonical_bytes(envelope.body())?;
        if projection.id()?.content_id() != id {
            return Err(integrity("continuation-projection-envelope-shape"));
        }
        let request = self.read_branch_request(projection.request().content_id())?;
        if request.id()? != projection.request()
            || request.branch_point() != projection.branch_point()
        {
            return Err(integrity("continuation-projection-request-mismatch"));
        }
        Ok(projection)
    }

    pub(super) fn read_expansion_credit(
        &self,
        id: ContentId,
    ) -> Result<ExpansionCredit, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ExpansionCredit)?;
        let credit = ExpansionCredit::from_canonical_bytes(envelope.body())?;
        if credit.content_id()? != id {
            return Err(integrity("expansion-credit-envelope-shape"));
        }
        self.decode_observation(credit.observation().content_id())?;
        Ok(credit)
    }

    pub(super) fn require_record_kind(
        &self,
        id: ContentId,
        expected: crate::CampaignRecordKind,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != expected {
            return Err(integrity("campaign-child-record-kind-mismatch"));
        }
        Ok(envelope)
    }

    pub(super) fn validate_policy_artifact_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let artifact = crate::codec::decode::<PolicyArtifact>(envelope.body())?;
        self.require_record_kind(
            artifact.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        Ok(())
    }

    pub(super) fn validate_planner_state_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let state = crate::codec::decode::<PlannerState>(envelope.body())?;
        self.require_record_kind(
            state.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        Ok(())
    }

    pub(super) fn validate_planner_invocation_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let invocation = crate::codec::decode::<PlannerInvocation>(envelope.body())?;
        self.require_record_kind(
            invocation.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        let artifact_envelope = self.require_record_kind(
            invocation.policy_artifact().content_id(),
            crate::CampaignRecordKind::PolicyArtifact,
        )?;
        let artifact = crate::codec::decode::<PolicyArtifact>(artifact_envelope.body())?;
        self.require_record_kind(
            invocation.policy().content_id(),
            crate::CampaignRecordKind::Policy,
        )?;
        let state_envelope = self.require_record_kind(
            invocation.planner_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let state = crate::codec::decode::<PlannerState>(state_envelope.body())?;
        self.require_record_kind(
            invocation.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if artifact.engine() != invocation.engine() || state.engine() != invocation.engine() {
            return Err(integrity("planner-invocation-engine-mismatch"));
        }
        for position in invocation
            .scan_page()
            .after()
            .into_iter()
            .chain(invocation.scan_page().positions().iter().copied())
        {
            let request = self.decode_branch_request(position.source().content_id())?;
            if request.branch_point() != position.branch_point() {
                return Err(integrity(
                    "planner-invocation-scan-position-branch-point-mismatch",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn read_selectable(
        &self,
        id: ContentId,
    ) -> Result<SelectableDeclaration, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::SelectableDeclaration {
            return Err(integrity("selectable-envelope-shape"));
        }
        let selectable = SelectableDeclaration::from_canonical_bytes(envelope.body())?;
        if selectable.id()?.content_id() != id {
            return Err(integrity("selectable-envelope-shape"));
        }
        Ok(selectable)
    }

    pub(super) fn read_choice_domain(
        &self,
        id: ContentId,
    ) -> Result<ChoiceDomain, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceDomain {
            return Err(integrity("choice-domain-envelope-shape"));
        }
        let domain = ChoiceDomain::from_canonical_bytes(envelope.body())?;
        if domain.id()?.content_id() != id {
            return Err(integrity("choice-domain-envelope-shape"));
        }
        Ok(domain)
    }

    pub(super) fn validate_group_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let group = crate::codec::decode::<ChoiceGroup>(envelope.body())?;
        let mut declarations = BTreeMap::new();
        for id in group.members() {
            declarations.insert(*id, self.read_selectable(id.content_id())?);
        }
        group.validate_declarations(&declarations)?;
        Ok(())
    }

    pub(super) fn read_group(&self, id: ContentId) -> Result<ChoiceGroup, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ChoiceGroup)?;
        let group = crate::codec::decode::<ChoiceGroup>(envelope.body())?;
        if group.id()?.content_id() != id {
            return Err(integrity("choice-group-envelope-shape"));
        }
        self.validate_group_references(&envelope)?;
        Ok(group)
    }

    pub(super) fn read_opportunity(
        &self,
        id: ContentId,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        self.read_opportunity_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(super) fn read_opportunity_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceOpportunity {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        self.validate_opportunity_references_cached(&envelope, cache)
    }

    /// Loads one opportunity and each exact dependency once for a bounded read.
    pub(crate) fn load_choice_opportunity_dependencies(
        &self,
        id: ChoiceOpportunityId,
    ) -> Result<(ChoiceOpportunity, SelectableDeclaration, ChoiceDomain), CampaignRepositoryError>
    {
        let envelope = self.read_envelope(id.content_id())?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceOpportunity {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        if opportunity.id()? != id {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let declaration = self.read_selectable(opportunity.declaration().content_id())?;
        let domain = self.read_choice_domain(opportunity.domain().content_id())?;
        opportunity.validate_references(&declaration, &domain)?;
        Ok((opportunity, declaration, domain))
    }

    pub(super) fn validate_opportunity_references_cached(
        &self,
        envelope: &ObjectEnvelope,
        cache: &mut ChoiceValidationCache,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        if opportunity.id()?.content_id() != envelope.content_id() {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let key = (
            opportunity.declaration().content_id(),
            opportunity.domain().content_id(),
        );
        let contract = opportunity.reference_contract_hash();
        if let Some(validated) = cache.get(&key) {
            if validated != contract {
                return Err(integrity("choice-opportunity-cached-reference-mismatch"));
            }
            return Ok(opportunity);
        }

        let declaration = self.read_selectable(key.0)?;
        let domain = self.read_choice_domain(key.1)?;
        opportunity.validate_references(&declaration, &domain)?;
        cache.insert(key, contract);
        Ok(opportunity)
    }

    pub(super) fn validate_selection_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let selection = Selection::from_canonical_bytes(envelope.body())?;
        let opportunity = self.read_opportunity(required_child(envelope, "opportunity")?)?;
        let domain = self.read_choice_domain(required_child(envelope, "domain")?)?;
        selection.validate_resolved_references(&opportunity, &domain)?;
        Ok(())
    }

    pub(super) fn lock_mutation(
        &self,
    ) -> Result<RepositoryMutationGuard<'_>, CampaignRepositoryError> {
        let local = self
            .mutation_lock
            .lock()
            .map_err(|_| CampaignRepositoryError::Poisoned)?;
        let publication = self.refs.acquire_publication_guard()?;
        Ok(RepositoryMutationGuard {
            _local: local,
            _publication: publication,
        })
    }
}
