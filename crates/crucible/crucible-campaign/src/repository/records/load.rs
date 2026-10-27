//! Authenticated loading for public campaign records.

use super::*;

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

    /// Loads one attempt followed by its complete continuation ancestry.
    ///
    /// The returned vector is ordered from the requested attempt toward its
    /// oldest discovery or branch root. All entries are authenticated with one
    /// shared validation cache, so a continuation chain is read in linear time.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the attempt chain is
    /// missing, corrupt, or semantically inconsistent.
    pub fn load_attempt_origin_chain(
        &self,
        id: AttemptId,
    ) -> Result<Vec<Attempt>, CampaignRepositoryError> {
        let mut cache = ChoiceValidationCache::default();
        let mut chain = Vec::new();
        let mut current_id = id;

        loop {
            let attempt = self.read_attempt_cached(current_id.content_id(), &mut cache)?;
            let origin = match attempt.start() {
                AttemptStart::AfterAttempt { origin, .. } => Some(origin),
                AttemptStart::Discover { .. } | AttemptStart::Branch { .. } => None,
            };
            chain.push(attempt);

            let Some(origin) = origin else {
                return Ok(chain);
            };
            current_id = origin;
        }
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
        for _ in 0..MAX_CAMPAIGN_SNAPSHOT_ANCESTRY {
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
            self.validate_planner_selected_source(&view, step.disposition(), None)?;

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
}
