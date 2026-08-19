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
        }
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
        let head = self.head(name)?;
        self.project_state(head.content_id())
            .map(|state| state.visible)
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
    pub fn submit_branch_request(
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
        if let Some(result) = self.find_branch_request_result(current_content, request_id)? {
            return Ok(result);
        }
        if let BranchRequestCause::Operator(command) = request.cause()
            && self.mutation_command_exists(current_content, command)?
        {
            return Err(CampaignRepositoryError::CommandReuse);
        }

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
        let request_key = map_key_content("exploration.branch-request", request_content);
        if self
            .merkle
            .get(current.snapshot.roots().exploration, request_key)?
            .is_some()
        {
            return Err(integrity("branch-request-index-has-no-ancestry-transition"));
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
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        self.validate_complete_head(next_content)?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => Ok(BranchRequestResult {
                prior_snapshot: current_id,
                new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                request: request_id,
                replayed: false,
            }),
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
            let CampaignFact::ControlRequested(prior_request) = fact else {
                return Err(integrity("command-index-value-is-not-control-fact"));
            };
            if prior_request != *request {
                return Err(CampaignRepositoryError::CommandReuse);
            }
            return self.find_command_result(current_content, request, true);
        }
        if self.mutation_command_exists(current_content, request.command)? {
            return Err(CampaignRepositoryError::CommandReuse);
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if request.expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: request.expected_snapshot,
                current: current_id,
            });
        }
        let mut projected = self.project_state(current_content)?;
        projected.apply(&request.action)?;

        let control_fact = CampaignFact::ControlRequested(request.clone());
        let control_content = self.put_fact(&control_fact)?;
        let mut accounting = self.merkle.insert(
            current.snapshot.roots().accounting,
            command_key,
            control_content,
        )?;

        let mut active_policy = current.snapshot.active_policy();
        match request.action {
            CampaignControlAction::ActivatePolicy(next) => {
                let next_content = next.content_id();
                let policy = self.read_policy(next_content)?;
                let lineage_content = required_child(&current.envelope, "lineage")?;
                let lineage = self.read_lineage(lineage_content)?;
                if policy.scenario() != lineage.scenario() {
                    return Err(integrity("activated-policy-scenario-mismatch"));
                }
                let activation =
                    CampaignFact::PolicyActivated(PolicyActivation::new(active_policy, next)?);
                let activation_content = self.put_fact(&activation)?;
                accounting = self.insert_fact(accounting, &activation, activation_content)?;
                active_policy = next;
            }
            CampaignControlAction::GrantBudget(grant) => {
                let budget = CampaignFact::BudgetGranted(grant);
                let budget_content = self.put_fact(&budget)?;
                accounting = self.insert_fact(accounting, &budget, budget_content)?;
            }
            _ => {}
        }

        let mut roots = current.snapshot.roots();
        roots.accounting = accounting.content_id();
        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            active_policy,
            roots,
            crate::CampaignFactId::from_content_id(control_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        self.validate_complete_head(next_content)?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => Ok(CampaignCommandResult {
                prior_snapshot: current_id,
                new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                replayed: false,
            }),
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
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
