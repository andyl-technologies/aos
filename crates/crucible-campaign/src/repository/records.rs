//! Strict campaign record publication, loading, and cross-record validation.

use super::*;

impl CampaignRepository {
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

    /// Loads a planner step through the fail-closed coordinator validator.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for invalid closure. Planner
    /// steps remain inadmissible until coordinator recomputation is implemented.
    pub fn load_planner_step(
        &self,
        id: PlannerStepId,
    ) -> Result<PlannerStep, CampaignRepositoryError> {
        self.read_planner_step(id.content_id())
    }

    /// Loads an expansion state through the fail-closed projector validator.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for invalid closure. Expansion
    /// states remain inadmissible until projector recomputation is implemented.
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
        let envelope =
            self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Selection)?;
        let selection = Selection::from_canonical_bytes(envelope.body())?;
        if selection.id()? != id {
            return Err(integrity("selection-envelope-shape"));
        }
        let opportunity = self.read_opportunity(required_child(&envelope, "opportunity")?)?;
        let domain = self.read_choice_domain(required_child(&envelope, "domain")?)?;
        selection.validate_resolved_references(&opportunity, &domain)?;
        Ok(ResolvedSelection {
            selection,
            opportunity,
            domain,
        })
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
        let envelope = self.require_record_kind(
            id.content_id(),
            crate::CampaignRecordKind::PlannerInvocation,
        )?;
        let invocation = crate::codec::decode::<PlannerInvocation>(envelope.body())?;
        if invocation.id()? != id {
            return Err(integrity("planner-invocation-envelope-shape"));
        }
        self.validate_planner_invocation_references(&envelope)?;
        Ok(invocation)
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
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::BranchRequest,
            crate::object::content_children(request.content_children())?,
            request.canonical_bytes(),
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
        if ObjectEnvelope::for_fact(&fact)? != envelope || fact.id()?.content_id() != id {
            return Err(integrity("fact-envelope-shape"));
        }
        self.validate_fact_references(&fact)?;
        Ok(fact)
    }

    pub(super) fn validate_fact_references(
        &self,
        fact: &CampaignFact,
    ) -> Result<(), CampaignRepositoryError> {
        match fact {
            CampaignFact::ChoiceOpportunityDiscovered(id) => {
                self.require_record_kind(
                    id.content_id(),
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
            CampaignFact::ControlRequested(request) => {
                self.require_record_kind(
                    request.expected_snapshot.content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                if let CampaignControlAction::ActivatePolicy(policy) = request.action {
                    self.require_record_kind(
                        policy.content_id(),
                        crate::CampaignRecordKind::Policy,
                    )?;
                }
            }
            CampaignFact::BranchRequestIssued(id) => {
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
            CampaignFact::ObservationPublished(_) | CampaignFact::FindingPublished(_) => {
                return Err(integrity("campaign-fact-record-type-is-not-implemented"));
            }
            CampaignFact::BudgetGranted(_) | CampaignFact::PinChanged(_) => {}
        }
        Ok(())
    }

    pub(super) fn read_branch_request(
        &self,
        id: ContentId,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::BranchRequest)?;
        let request = BranchRequest::from_canonical_bytes(envelope.body())?;
        if request.id()?.content_id() != id {
            return Err(integrity("branch-request-envelope-shape"));
        }
        self.validate_branch_request_references(&request)?;
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
        match request.source() {
            CandidateSource::Finite(_) => {}
            CandidateSource::Generated(generator) => {
                self.validate_generator_for_domain(*generator, &domain)?;
            }
        }
        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                self.load_planner_invocation(invocation)?;
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
        }
        Ok(parent)
    }

    pub(super) fn validate_generator_for_domain(
        &self,
        root: CandidateGeneratorSpecId,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignRepositoryError> {
        let mut stack = vec![(root, 0_usize)];
        let mut visited = BTreeSet::new();
        while let Some((id, depth)) = stack.pop() {
            if depth > 1024 || visited.len() >= MAX_CLOSURE_OBJECTS {
                return Err(integrity("candidate-generator-validation-limit"));
            }
            if !visited.insert(id) {
                continue;
            }
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
                }
                CandidateGeneratorAlgorithm::StratifiedInteger { .. }
                | CandidateGeneratorAlgorithm::BoundaryInteger
                | CandidateGeneratorAlgorithm::LogInteger { .. }
                | CandidateGeneratorAlgorithm::PermutedInteger
                | CandidateGeneratorAlgorithm::ProgressiveInteger { .. }
                | CandidateGeneratorAlgorithm::MutateNearCorpus { .. }
                    if matches!(domain, ChoiceDomain::Integer(_)) => {}
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
            BranchRequestCause::ExhaustivePolicy(_)
            | BranchRequestCause::Operator(_)
            | BranchRequestCause::Debugger(_) => {}
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

    pub(super) fn read_proposal(&self, id: ContentId) -> Result<Proposal, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Proposal)?;
        let proposal = Proposal::from_canonical_bytes(envelope.body())?;
        if proposal.id()?.content_id() != id {
            return Err(integrity("proposal-envelope-shape"));
        }
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
        Ok(request)
    }

    pub(super) fn read_attempt_admission(
        &self,
        id: ContentId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::AttemptAdmission)?;
        let admission = AttemptAdmission::from_canonical_bytes(envelope.body())?;
        if admission.id()?.content_id() != id {
            return Err(integrity("attempt-admission-envelope-shape"));
        }
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

    pub(super) fn read_planner_step(
        &self,
        id: ContentId,
    ) -> Result<PlannerStep, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::PlannerStep)?;
        let step = PlannerStep::from_canonical_bytes(envelope.body())?;
        if step.id()?.content_id() != id {
            return Err(integrity("planner-step-envelope-shape"));
        }
        let invocation = self.load_planner_invocation(step.invocation())?;
        if invocation.engine() != step.engine()
            || invocation.policy_artifact() != step.policy_artifact()
            || invocation.policy() != step.policy()
            || invocation.input_view() != step.input_view()
        {
            return Err(integrity("planner-step-invocation-mismatch"));
        }
        let source = self.read_branch_request(step.selected_source().content_id())?;
        if source.branch_point() != step.selected_branch_point() {
            return Err(integrity("planner-step-source-branch-point-mismatch"));
        }
        for proposal in step.issued_proposals() {
            let proposal = self.read_proposal(proposal.content_id())?;
            if proposal.request() != step.selected_source()
                || proposal.planner_invocation() != Some(step.invocation())
            {
                return Err(integrity("planner-step-proposal-mismatch"));
            }
        }
        self.require_record_kind(
            step.next_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        if let Some(parent) = step.parent() {
            self.require_record_kind(parent.content_id(), crate::CampaignRecordKind::PlannerStep)?;
        }
        Err(integrity(
            "planner-step-coordinator-validation-is-not-implemented",
        ))
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
        for request in state.continuations().keys() {
            let request = self.read_branch_request(request.content_id())?;
            if request.branch_point() != state.branch_point() {
                return Err(integrity("expansion-state-request-branch-point-mismatch"));
            }
        }
        Err(integrity(
            "expansion-state-projector-validation-is-not-implemented",
        ))
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

    pub(super) fn validate_opportunity_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        let declaration = self.read_selectable(required_child(envelope, "declaration")?)?;
        let domain = self.read_choice_domain(required_child(envelope, "domain")?)?;
        opportunity.validate_references(&declaration, &domain)?;
        Ok(())
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
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceOpportunity {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        if opportunity.id()?.content_id() != id {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let declaration = self.read_selectable(opportunity.declaration().content_id())?;
        let domain = self.read_choice_domain(opportunity.domain().content_id())?;
        opportunity.validate_references(&declaration, &domain)?;
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

    pub(super) fn lock_mutation(&self) -> Result<MutexGuard<'_, ()>, CampaignRepositoryError> {
        self.mutation_lock
            .lock()
            .map_err(|_| CampaignRepositoryError::Poisoned)
    }
}
