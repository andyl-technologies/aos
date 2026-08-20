//! Campaign creation, mutation, publication, and authoritative-ref transactions.

use super::*;

impl CampaignRepository {
    /// Builds a repository over independently composable blob and ref backends.
    #[must_use]
    pub fn new(blobs: Arc<dyn ImmutableBlobBackend>, refs: Arc<dyn MutableRefBackend>) -> Self {
        let merkle = MerkleMap::new(blobs.clone());
        Self {
            blobs,
            refs,
            merkle,
            mutation_lock: Mutex::new(()),
            validated_heads: Mutex::new(BTreeMap::new()),
            planner_authority: None,
            debugger_authority: None,
        }
    }

    /// Builds a repository with distinct trusted planner and debugger authorities.
    ///
    /// Direct and RPC adapters authenticate the same canonical submission
    /// messages with operational keys. The keys never enter campaign state.
    ///
    /// # Errors
    ///
    /// Returns an integrity error if both roles are configured with identical
    /// key material.
    pub fn with_component_authorities(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        planner_authority: PlannerAuthorityKey,
        debugger_authority: DebuggerAuthorityKey,
    ) -> Result<Self, CampaignRepositoryError> {
        if planner_authority.has_same_material(&debugger_authority) {
            return Err(integrity("component-authority-keys-must-be-distinct"));
        }
        let mut repository = Self::new(blobs, refs);
        repository.planner_authority = Some(planner_authority);
        repository.debugger_authority = Some(debugger_authority);
        Ok(repository)
    }

    /// Creates a campaign with a canonical genesis snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, scenario/policy mismatch, existing
    /// ref, failed object publication, or failed authoritative ref creation.
    pub fn create(
        &self,
        name: &str,
        lineage: &CampaignLineage,
        policy: &CampaignPolicy,
        generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
    ) -> Result<CampaignHead, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        if self.refs.read_ref(&campaign_ref)?.is_some() {
            return Err(CampaignRepositoryError::AlreadyExists);
        }
        if lineage.scenario() != policy.scenario() {
            return Err(integrity("lineage-policy-scenario-mismatch"));
        }
        let scenario_artifact =
            self.read_scenario_artifact(lineage.scenario_content().content_id())?;
        let genesis_artifact =
            self.read_configuration_artifact(lineage.genesis_content().content_id())?;
        if scenario_artifact.scenario() != lineage.scenario()
            || scenario_artifact.payload_schema() != lineage.scenario_schema()
            || genesis_artifact.scenario() != lineage.scenario()
            || genesis_artifact.scenario_artifact() != lineage.scenario_content()
            || genesis_artifact.configuration() != lineage.genesis()
        {
            return Err(integrity("lineage-execution-model-artifact-mismatch"));
        }

        for (expected, generator) in generators {
            if generator.id()? != *expected {
                return Err(integrity("candidate-generator-map-key-mismatch"));
            }
            self.put_generator(generator)?;
        }
        for child in policy.content_children() {
            let generator = CandidateGeneratorSpecId::from_content_id(child.1)?;
            if !generators.contains_key(&generator) {
                return Err(integrity("campaign-policy-generator-was-not-supplied"));
            }
        }

        let lineage_content = self.put_lineage(lineage)?;
        let policy_content = self.put_policy(policy)?;
        let empty = self.merkle.empty()?.content_id();
        let graph = self.merkle.insert(
            empty,
            map_key_hash("graph.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )?;
        let corpus = self.merkle.insert(
            empty,
            map_key_hash("corpus.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )?;
        let snapshot = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(lineage_content)?,
            CampaignPolicyId::from_content_id(policy_content)?,
            crate::CampaignRoots {
                graph: graph.content_id(),
                exploration: empty,
                observations: empty,
                corpus: corpus.content_id(),
                coverage: empty,
                findings: empty,
                pins: empty,
                accounting: empty,
                coordination: empty,
            },
        )?;
        let content_id = self.put_snapshot(&snapshot)?;
        self.validate_complete_head(content_id)?;
        match self
            .refs
            .compare_exchange(&campaign_ref, None, content_id)?
        {
            RefCasOutcome::Advanced { .. } => Ok(CampaignHead {
                name: name.to_owned(),
                snapshot_id: CampaignSnapshotId::from_content_id(content_id)?,
                snapshot,
            }),
            RefCasOutcome::Conflict { .. } => Err(CampaignRepositoryError::AlreadyExists),
        }
    }

    /// Resolves and authenticates the current campaign head and its lineage and
    /// policy references.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable closure.
    pub fn head(&self, name: &str) -> Result<CampaignHead, CampaignRepositoryError> {
        let campaign_ref = campaign_ref(name)?;
        let content_id = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let loaded = self.read_snapshot(content_id)?;
        self.validate_complete_head(content_id)?;
        Ok(CampaignHead {
            name: name.to_owned(),
            snapshot_id: CampaignSnapshotId::from_content_id(content_id)?,
            snapshot: loaded.snapshot,
        })
    }

    /// Projects durable lifecycle intent from authenticated snapshot ancestry.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for a cycle, excessive ancestry, malformed
    /// transition, or invalid historical state transition.
    pub fn state(&self, name: &str) -> Result<CampaignState, CampaignRepositoryError> {
        self.head_with_state(name).map(|(_, state)| state)
    }

    /// Resolves one authenticated head and its lifecycle state from the same snapshot.
    ///
    /// Unlike independent [`Self::head`] and [`Self::state`] calls, this method
    /// cannot mix fields across a concurrent ref advance: lifecycle projection
    /// is anchored to the exact content ID returned in the head.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable closure or lifecycle.
    pub fn head_with_state(
        &self,
        name: &str,
    ) -> Result<(CampaignHead, CampaignState), CampaignRepositoryError> {
        let head = self.head(name)?;
        let state = self.state_at_snapshot(head.snapshot_id())?;
        Ok((head, state))
    }

    /// Projects lifecycle state from one exact authenticated snapshot.
    ///
    /// # Errors
    ///
    /// Returns an integrity/store error when the snapshot or its reachable
    /// ancestry is absent, malformed, excessive, or semantically invalid.
    pub fn state_at_snapshot(
        &self,
        snapshot: CampaignSnapshotId,
    ) -> Result<CampaignState, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        self.current_lifecycle(snapshot.content_id())
            .map(|state| state.visible)
    }

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

        let graph = self.merkle.insert(
            current.snapshot.roots().graph,
            authoritative_choice_key(opportunity),
            opportunity.content_id(),
        )?;
        let graph = self
            .merkle
            .insert(graph.content_id(), choice_key, opportunity.content_id())?;
        let fact = CampaignFact::ChoiceOpportunityDiscovered {
            parent,
            branch_point,
            opportunity,
        };
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.graph = graph.content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = CampaignSnapshot::successor(
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

        let request_content = self.put_branch_request(request)?;
        if request_content != request_id.content_id() {
            return Err(integrity("branch-request-publication-id-mismatch"));
        }
        let exploration = self.merkle.insert(
            current.snapshot.roots().exploration,
            request_key,
            request_content,
        )?;

        let fact = CampaignFact::BranchRequestIssued(request_id);
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
        let next = CampaignSnapshot::successor(
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
    /// publication failure, or final authoritative-ref conflict.
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

        let fact = CampaignFact::ProposalIssued(proposal_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.exploration = exploration.content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = CampaignSnapshot::successor(
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

        let fact = CampaignFact::AttemptAdmitted(admission_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.accounting = accounting;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = CampaignSnapshot::successor(
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
                CampaignFact::ControlRequested(_) | CampaignFact::BranchRequestIssued(_) => {
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
        let next = CampaignSnapshot::successor(
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
        self.verify_campaign_closure(invocation_content)?;
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
        self.validate_planner_request_inputs(request)?;
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
        let next = CampaignSnapshot::successor(
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
    /// carries every served branch-request envelope. Additional interpretation
    /// dependencies and Merkle proof guidance remain a later integration gate.
    /// This method performs no writes.
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

        let retained = invocation
            .scan_page()
            .positions()
            .iter()
            .map(|position| self.read_envelope(position.source().content_id()))
            .collect::<Result<Vec<_>, _>>()?;

        let request = PlannerRequest::new(
            expected_snapshot,
            invocation,
            crate::codec::decode(engine_envelope.body())?,
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

    pub(super) fn validate_planner_cursor(
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

    pub(super) fn validate_planner_page(
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

    pub(super) fn validate_planner_invocation_start(
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

    pub(super) fn validate_planner_invocation_parent(
        &self,
        parent: Option<&PlannerStep>,
        invocation: &PlannerInvocation,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(parent_step) = parent else {
            if invocation.scan_page().after().is_some() {
                return Err(integrity("planner-invocation-scan-start-mismatch"));
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

    pub(super) fn validate_planner_disposition_page(
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

    pub(super) fn validate_planner_selected_source(
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

    fn planner_scan_page(
        &self,
        view: &CampaignPlanningView,
        after: Option<PlanningScanPosition>,
        limit: u32,
    ) -> Result<PlanningScanPage, CampaignRepositoryError> {
        let limit_usize =
            usize::try_from(limit).map_err(|_| integrity("planner-scan-page-limit-is-invalid"))?;
        if limit_usize == 0 || limit_usize > 10_000 {
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

    /// Publishes a policy object so a later activation command can name it.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the policy cannot be placed.
    pub fn publish_policy(
        &self,
        policy: &CampaignPolicy,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let content = self.put_policy(policy)?;
        self.verify_campaign_closure(content)?;
        Ok(content)
    }

    /// Publishes a closed candidate-generator specification.
    ///
    /// Child specifications named by an ordered mixture must already exist;
    /// callers normally publish a dependency-ordered set before a policy.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or closure error if the specification cannot
    /// be authenticated and placed.
    pub fn publish_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, CampaignRepositoryError> {
        let content = self.put_generator(generator)?;
        self.verify_campaign_closure(content)?;
        CandidateGeneratorSpecId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes exact canonical scenario bytes for use by a lineage.
    ///
    /// The execution-model adapter remains responsible for proving that these
    /// bytes produce the lineage's semantic [`crate::ScenarioDefId`].
    ///
    /// # Errors
    ///
    /// Returns a store error if the artifact cannot be authenticated and placed.
    pub fn publish_scenario_artifact(
        &self,
        scenario: ScenarioDefId,
        payload_schema: u32,
        bytes: Vec<u8>,
    ) -> Result<ScenarioArtifactId, CampaignRepositoryError> {
        let artifact = ScenarioArtifact::new(scenario, payload_schema, bytes)?;
        let content = self.put_scenario_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ScenarioArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes exact canonical configuration bytes for use by a lineage.
    ///
    /// The execution-model adapter remains responsible for proving that these
    /// bytes produce the lineage's semantic [`crate::ConfigurationId`].
    ///
    /// # Errors
    ///
    /// Returns a store error if the artifact cannot be authenticated and placed.
    pub fn publish_configuration_artifact(
        &self,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        payload_schema: u32,
        bytes: Vec<u8>,
    ) -> Result<ConfigurationArtifactId, CampaignRepositoryError> {
        let artifact = ConfigurationArtifact::new(
            scenario,
            scenario_artifact,
            configuration,
            payload_schema,
            bytes,
        )?;
        let content = self.put_configuration_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ConfigurationArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes an exact choice domain.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the domain cannot be placed and
    /// authenticated.
    pub fn publish_choice_domain(
        &self,
        domain: &ChoiceDomain,
    ) -> Result<ChoiceDomainId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceDomain,
            BTreeSet::new(),
            domain.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceDomainId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes an exact selectable declaration.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the declaration cannot be placed
    /// and authenticated.
    pub fn publish_selectable(
        &self,
        selectable: &SelectableDeclaration,
    ) -> Result<SelectableId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::SelectableDeclaration,
            BTreeSet::new(),
            selectable.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        SelectableId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a choice opportunity after resolving its declaration/domain.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error if either dependency is
    /// absent or the opportunity's copied semantic fields disagree.
    pub fn publish_choice_opportunity(
        &self,
        opportunity: &ChoiceOpportunity,
    ) -> Result<ChoiceOpportunityId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceOpportunity,
            crate::object::content_children(opportunity.content_children())?,
            crate::codec::encode(opportunity),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceOpportunityId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a simultaneous choice group after resolving every declaration.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error if a declaration is
    /// absent or disagrees with the group's effective domain.
    pub fn publish_choice_group(
        &self,
        group: &ChoiceGroup,
    ) -> Result<ChoiceGroupId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceGroup,
            crate::object::content_children(group.content_children())?,
            crate::codec::encode(group),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceGroupId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a selection after validating its opportunity and legal domain.
    ///
    /// Model-sampled selections remain subject to their pure model verifier at
    /// execution time; their self-contained model identity is checked here.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error for an absent dependency,
    /// illegal value, or invalid origin evidence.
    pub fn publish_selection(
        &self,
        selection: &Selection,
    ) -> Result<SelectionId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Selection,
            crate::object::content_children(selection.content_children())?,
            selection.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        SelectionId::from_content_id(content).map_err(Into::into)
    }
}
