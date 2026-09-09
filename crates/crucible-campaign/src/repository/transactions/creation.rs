//! Repository construction and campaign creation or derivation.

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
            beam_projection_cache: Mutex::new(None),
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

    /// Publishes and authenticates the deterministic built-in planner basis.
    ///
    /// The opaque dependency-lock leaf is placed before the policy artifact
    /// that names it. Every object has one fixed content identity, so retrying
    /// after an interrupted immutable publication is idempotent and cannot
    /// create an unbounded family of debris.
    ///
    /// # Errors
    ///
    /// Returns a codec, store, or integrity error if the closed basis cannot be
    /// derived, placed, or authenticated as one complete repository closure.
    pub fn publish_canonical_frontier_planner_basis(
        &self,
    ) -> Result<crate::CanonicalFrontierPlannerBasis, CampaignRepositoryError> {
        let basis = CanonicalFrontierPlanner::basis()?;
        let dependency = CanonicalFrontierPlanner::dependency_lock_id();
        self.blobs.put_if_absent(
            dependency,
            &BlobHandle::from_bytes(CanonicalFrontierPlanner::dependency_lock_bytes().to_vec()),
        )?;

        let engine = self.put_planner_engine(basis.engine())?;
        let artifact = self.put_policy_artifact(basis.artifact())?;
        let state = self.put_planner_state(basis.initial_state())?;
        if engine != basis.engine().id()?.content_id()
            || artifact != basis.artifact().id()?.content_id()
            || state != basis.initial_state().id()?.content_id()
        {
            return Err(integrity("canonical-planner-basis-publication-mismatch"));
        }
        self.verify_campaign_closures_anchored_cached(
            [artifact, state],
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
        )?;
        Ok(basis)
    }

    /// Publishes and authenticates the deterministic PUCT planner basis.
    ///
    /// The version-2 basis has distinct engine, state, artifact, and dependency
    /// identities from the version-1 fairness bootstrap. Publication is
    /// idempotent and does not mutate a campaign ref.
    ///
    /// # Errors
    ///
    /// Returns a codec, store, or integrity error if the closed basis cannot be
    /// derived, placed, or authenticated as one complete repository closure.
    pub fn publish_canonical_puct_planner_basis(
        &self,
    ) -> Result<crate::CanonicalPuctPlannerBasis, CampaignRepositoryError> {
        let basis = CanonicalPuctPlanner::basis()?;
        let dependency = CanonicalPuctPlanner::dependency_lock_id();
        self.blobs.put_if_absent(
            dependency,
            &BlobHandle::from_bytes(CanonicalPuctPlanner::dependency_lock_bytes().to_vec()),
        )?;

        let engine = self.put_planner_engine(basis.engine())?;
        let artifact = self.put_policy_artifact(basis.artifact())?;
        let state = self.put_planner_state(basis.initial_state())?;
        if engine != basis.engine().id()?.content_id()
            || artifact != basis.artifact().id()?.content_id()
            || state != basis.initial_state().id()?.content_id()
        {
            return Err(integrity(
                "canonical-PUCT-planner-basis-publication-mismatch",
            ));
        }
        self.verify_campaign_closures_anchored_cached(
            [artifact, state],
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
        )?;
        Ok(basis)
    }

    /// Publishes and authenticates the deterministic Beam planner basis.
    ///
    /// Publication is idempotent and does not mutate a campaign ref.
    ///
    /// # Errors
    ///
    /// Returns a codec, store, or integrity error if the closed basis cannot be
    /// derived, placed, or authenticated as one complete repository closure.
    pub fn publish_canonical_beam_planner_basis(
        &self,
    ) -> Result<crate::CanonicalBeamPlannerBasis, CampaignRepositoryError> {
        let basis = CanonicalBeamPlanner::basis()?;
        let dependency = CanonicalBeamPlanner::dependency_lock_id();
        self.blobs.put_if_absent(
            dependency,
            &BlobHandle::from_bytes(CanonicalBeamPlanner::dependency_lock_bytes().to_vec()),
        )?;

        let engine = self.put_planner_engine(basis.engine())?;
        let artifact = self.put_policy_artifact(basis.artifact())?;
        let state = self.put_planner_state(basis.initial_state())?;
        if engine != basis.engine().id()?.content_id()
            || artifact != basis.artifact().id()?.content_id()
            || state != basis.initial_state().id()?.content_id()
        {
            return Err(integrity(
                "canonical-Beam-planner-basis-publication-mismatch",
            ));
        }
        self.verify_campaign_closures_anchored_cached(
            [artifact, state],
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
        )?;
        Ok(basis)
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
        validate_creation_artifact_basis(lineage, &scenario_artifact, &genesis_artifact)?;
        validate_creation_generator_closure(policy, generators)?;
        self.publish_genesis_after_preflight(name, campaign_ref, lineage, policy, generators)
    }

    /// Creates a campaign from an already imported immutable creation closure.
    ///
    /// Large execution-model artifacts and generator records are loaded by
    /// their authenticated content IDs. The complete closure is validated
    /// before any new lineage, policy, Merkle, or snapshot object is written.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name or semantic basis, missing imported
    /// input, an existing ref, failed publication, or failed ref creation.
    pub fn create_from_stored(
        &self,
        name: &str,
        lineage: &CampaignLineage,
        policy: &CampaignPolicy,
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
        validate_creation_artifact_basis(lineage, &scenario_artifact, &genesis_artifact)?;
        self.validate_stored_creation_generator_closure(policy)?;
        self.publish_genesis_after_preflight(name, campaign_ref, lineage, policy, &BTreeMap::new())
    }

    /// Derives one new named campaign history from an authenticated source snapshot.
    ///
    /// The source ref is never mutated. The derived ref begins with one audited
    /// derivation transition whose parent is the exact requested source
    /// snapshot. A compatible supplied policy becomes active atomically with
    /// ref creation. Strict and streaming policies may migrate between those
    /// modes; statistical policies remain in their original mode. Omitting a
    /// policy preserves the source policy. Exact retries are resolved from the
    /// derived history even after later mutations.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent source, a snapshot outside the named
    /// source ancestry, an existing target with another semantic basis, an
    /// incompatible or incomplete policy, failed publication, or ref conflict.
    pub fn derive_campaign(
        &self,
        source_name: &str,
        source_snapshot: CampaignSnapshotId,
        target_name: &str,
        policy: Option<&CampaignPolicy>,
    ) -> Result<CampaignDerivationResult, CampaignRepositoryError> {
        if source_name == target_name {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "derived campaign name must differ from its source",
            });
        }

        let source_ref = campaign_ref(source_name)?;
        let source_head = self
            .refs
            .read_ref(&source_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        self.validate_complete_head(source_head)?;
        let source = self.load_named_ancestor_snapshot(source_head, source_snapshot)?;
        let source_content = source_snapshot.content_id();

        let lineage = self.read_lineage(source.snapshot.lineage().content_id())?;
        let prior_policy = self.read_policy(source.snapshot.active_policy().content_id())?;
        let prior_mode = prior_policy.mode();
        let active_policy = match policy {
            Some(next) => {
                if next.scenario() != lineage.scenario()
                    || !derivation_modes_are_compatible(prior_mode, next.mode())
                {
                    return Err(CampaignRepositoryError::InvalidRequest {
                        reason: "derived policy is incompatible with the source campaign",
                    });
                }
                next.id()?
            }
            None => source.snapshot.active_policy(),
        };
        let derivation = CampaignDerivation::new(source_snapshot, active_policy);
        let target_ref = campaign_ref(target_name)?;
        if let Some(current) = self.refs.read_ref(&target_ref)? {
            self.validate_complete_head(current)?;
            return self
                .find_derivation_result(current, derivation)?
                .ok_or(CampaignRepositoryError::AlreadyExists);
        }

        if let Some(next) = policy
            && active_policy != source.snapshot.active_policy()
        {
            self.validate_stored_creation_generator_closure(next)?;
        }

        let _guard = self.lock_mutation()?;
        if let Some(current) = self.refs.read_ref(&target_ref)? {
            self.validate_complete_head(current)?;
            return self
                .find_derivation_result(current, derivation)?
                .ok_or(CampaignRepositoryError::AlreadyExists);
        }

        if let Some(next) = policy
            && active_policy != source.snapshot.active_policy()
        {
            let content = self.put_policy(next)?;
            if content != active_policy.content_id() {
                return Err(integrity("derived-policy-publication-id-mismatch"));
            }
        }

        let fact = CampaignFact::CampaignDerived(derivation);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = source.snapshot.roots();
        let active_mode = policy.map_or(prior_mode, CampaignPolicy::mode);
        if is_streaming_to_strict_migration(prior_mode, active_mode) {
            let anchor =
                self.strict_migration_sequence_anchor(roots.accounting, transition_content)?;
            roots.accounting = self
                .merkle
                .insert(roots.accounting, observation_sequence_key(), anchor)?
                .content_id();
        }
        roots.coordination = self.coordination_with_parent_result(source_content, &source)?;
        let next = self.budgeted_successor(
            source_snapshot,
            source.snapshot.lineage(),
            active_policy,
            roots,
            crate::CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            source_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&target_ref, None, next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_branch(next_content, checkpoint);
                Ok(CampaignDerivationResult {
                    source_snapshot,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    active_policy,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                self.evict_local_checkpoint(next_content);
                let Some(current) = current else {
                    return Err(CampaignRepositoryError::RefConflict { current });
                };
                self.validate_complete_head(current)?;
                self.find_derivation_result(current, derivation)?
                    .ok_or(CampaignRepositoryError::AlreadyExists)
            }
        }
    }

    pub(super) fn load_named_ancestor_snapshot(
        &self,
        mut current: ContentId,
        requested: CampaignSnapshotId,
    ) -> Result<LoadedSnapshot, CampaignRepositoryError> {
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            let loaded = self.read_snapshot(current)?;
            if current == requested.content_id() {
                return Ok(loaded);
            }
            let Some(parent) = loaded.snapshot.parent() else {
                break;
            };
            current = parent.content_id();
        }
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "campaign snapshot is not in the named history",
        })
    }

    pub(in crate::repository) fn validate_stored_creation_generator_closure(
        &self,
        policy: &CampaignPolicy,
    ) -> Result<(), CampaignRepositoryError> {
        let mut pending: Vec<_> = policy
            .content_children()
            .into_iter()
            .map(|(_, child)| CandidateGeneratorSpecId::from_content_id(child))
            .collect::<Result<_, _>>()?;
        let mut visited = BTreeSet::new();
        let mut canonical_bytes = 0_usize;
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            if visited.len() > crate::MAX_CREATE_CAMPAIGN_GENERATORS {
                return Err(integrity("campaign-generator-count-limit"));
            }
            let generator = self.read_generator(id.content_id())?;
            charge_creation_generator_bytes(
                &mut canonical_bytes,
                generator.canonical_bytes().len(),
            )?;
            for (_, child) in generator.content_children() {
                pending.push(CandidateGeneratorSpecId::from_content_id(child)?);
            }
        }
        Ok(())
    }

    fn publish_genesis_after_preflight(
        &self,
        name: &str,
        campaign_ref: RefName,
        lineage: &CampaignLineage,
        policy: &CampaignPolicy,
        generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
    ) -> Result<CampaignHead, CampaignRepositoryError> {
        for generator in generators.values() {
            self.put_generator(generator)?;
        }

        let lineage_content = self.put_lineage(lineage)?;
        let policy_content = self.put_policy(policy)?;
        let empty = self.merkle.empty()?.content_id();
        let choice_index = self.merkle.empty()?.content_id();
        let frontier_index = self.merkle.empty()?.content_id();
        let branch_request_index = self.merkle.empty()?.content_id();
        let graph = self.merkle.insert(
            empty,
            map_key_hash("graph.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )?;
        let graph =
            self.merkle
                .insert(graph.content_id(), choice_index_anchor_key(), choice_index)?;
        let corpus = self.merkle.insert(
            empty,
            map_key_hash("corpus.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )?;
        let exploration = self
            .merkle
            .insert(empty, frontier_index_anchor_key(), frontier_index)?;
        let exploration = self.merkle.insert(
            exploration.content_id(),
            branch_request_index_anchor_key(),
            branch_request_index,
        )?;
        let exploration = self.merkle.insert(
            exploration.content_id(),
            planner_scan_index_anchor_key(),
            empty,
        )?;
        let snapshot = CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(lineage_content)?,
            CampaignPolicyId::from_content_id(policy_content)?,
            crate::CampaignRoots {
                graph: graph.content_id(),
                exploration: exploration.content_id(),
                observations: empty,
                corpus: corpus.content_id(),
                coverage: empty,
                findings: empty,
                pins: empty,
                accounting: empty,
                coordination: empty,
            },
        )?
        .with_budget_ledger(
            self.put_budget_ledger(
                crate::CampaignBudgetLedger::empty()
                    .with_request_spending(MerkleMap::empty_content_id()?)?,
            )?,
        );
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
            RefCasOutcome::Conflict { .. } => {
                self.validated_heads
                    .lock()
                    .map_err(|_| CampaignRepositoryError::Poisoned)?
                    .remove(&content_id);
                Err(CampaignRepositoryError::AlreadyExists)
            }
        }
    }
}
