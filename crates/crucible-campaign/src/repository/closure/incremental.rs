//! Incremental campaign closure authentication.

use super::*;

impl CampaignRepository {
    pub(super) fn incremental_closure_anchors(
        &self,
        parent: &LoadedSnapshot,
        transition: ContentId,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        let mut anchors = self.authenticated_head_closure_anchors(parent)?;
        let roots = parent.snapshot.roots();
        match self.read_fact(transition)? {
            CampaignFact::CampaignDerived(_) => {}
            CampaignFact::BranchRequestAccepted {
                request: request_id,
                ..
            } => {
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
            CampaignFact::ObservationCredited(observation_id) => {
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
            | CampaignFact::PinCommandAccepted(_)
            | CampaignFact::DiscoveryRequested(_)
            | CampaignFact::SavepointCaptureRequested(_)
            | CampaignFact::SavepointCaptureResolved(_)
            | CampaignFact::SavepointContinuationSelected(_) => {}
        }
        Ok(anchors)
    }

    pub(in crate::repository) fn verify_campaign_closure_anchored(
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
            None,
        )?;
        Ok(objects)
    }

    // Only archive checkpoint selections may opt into raw production leaves.
    // The source resolver and destination exact store authenticate their semantics.
    pub(in crate::repository) fn authenticated_closure_with_exact_leaves(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
    ) -> Result<(BTreeSet<ContentId>, BTreeSet<ContentId>), CampaignRepositoryError> {
        let mut objects = BTreeSet::new();
        let mut exact_leaves = BTreeSet::new();
        self.verify_campaign_closures_anchored_cached_collect(
            roots,
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
            Some(&mut objects),
            Some(&mut exact_leaves),
        )?;
        Ok((objects, exact_leaves))
    }

    pub(in crate::repository) fn verify_campaign_closures_anchored_cached(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        anchors: &BTreeSet<ContentId>,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_campaign_closures_anchored_cached_collect(
            roots,
            anchors,
            choice_cache,
            None,
            None,
        )
    }

    pub(super) fn verify_campaign_closures_anchored_cached_collect(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        anchors: &BTreeSet<ContentId>,
        choice_cache: &mut ChoiceValidationCache,
        mut collected: Option<&mut BTreeSet<ContentId>>,
        mut collected_exact_leaves: Option<&mut BTreeSet<ContentId>>,
    ) -> Result<usize, CampaignRepositoryError> {
        let mut stack = roots.into_iter().map(|id| (id, false)).collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut verified_merkle_positions = BTreeSet::new();

        while let Some((id, exact_leaf)) = stack.pop() {
            if anchors.contains(&id) {
                continue;
            }
            if !visited.insert((id, exact_leaf)) {
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
                stack.extend(verified.values.into_iter().map(|id| (id, false)));
                continue;
            }

            let handle = self.blobs.read(id, None)?;
            if exact_leaf {
                // Exact-root choice and replay evidence use Observation identities
                // for raw protocol bytes. Their parent role, not their kind alone,
                // grants opaque traversal; the immutable digest remains checked.
                if id.kind() != ObjectKind::Observation
                    || id.schema_version() != 1
                    || ContentId::for_source(id.kind(), id.schema_version(), &handle)? != id
                {
                    return Err(integrity("campaign-exact-leaf-identity-mismatch"));
                }
                if let Some(leaves) = collected_exact_leaves.as_deref_mut() {
                    leaves.insert(id);
                }
                continue;
            }
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
                let exact_root = collected_exact_leaves.is_some()
                    && id.kind() == ObjectKind::ExactManifest
                    && envelope.schema_name() == "crucible.executor.exact-checkpoint-root"
                    && envelope.schema_version() == 5;
                stack.extend(envelope.children().iter().map(|child| {
                    let exact_leaf = exact_root
                        && matches!(
                            child.role(),
                            "checkpoint-choice-closure" | "replay-oracle-evidence"
                        );
                    (child.id(), exact_leaf)
                }));
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
                crate::CampaignRecordKind::FindingCandidateBundle => {
                    let bundle = self.decode_finding_candidate_bundle(id)?;
                    self.validate_finding_candidate_bundle(
                        &bundle,
                        super::finding_candidate::FindingCandidateValidation::Load,
                    )?;
                }
                crate::CampaignRecordKind::FindingTriageReplayEvidence => {
                    let evidence = self.decode_finding_triage_replay_evidence(id)?;
                    self.validate_finding_triage_replay_evidence(&evidence)?;
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
                    self.read_attempt_cached(id, choice_cache)?;
                }
                crate::CampaignRecordKind::AttemptAdmission => {
                    let admission = self.decode_attempt_admission(id)?;
                    self.validate_attempt_admission_references_shallow_cached(
                        &admission,
                        choice_cache,
                    )?;
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
            stack.extend(envelope.children().iter().map(|child| (child.id(), false)));
        }
        visited
            .len()
            .checked_add(verified_merkle_positions.len())
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }
}
