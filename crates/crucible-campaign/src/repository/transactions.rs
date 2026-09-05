//! Campaign creation, mutation, publication, and authoritative-ref transactions.

use super::projection::PlannerCandidateProjectionCache;
use super::*;

mod publication;

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
    /// ref creation; omitting it preserves the source policy. Exact retries are
    /// resolved from the derived history even after later mutations.
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
        let active_policy = match policy {
            Some(next) => {
                if next.scenario() != lineage.scenario() || next.mode() != prior_policy.mode() {
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

    fn load_named_ancestor_snapshot(
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

    pub(super) fn validate_stored_creation_generator_closure(
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
        .with_budget_ledger(self.put_budget_ledger(crate::CampaignBudgetLedger::empty())?);
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

    /// Returns one bounded ordered page of authenticated named campaign heads.
    ///
    /// The mutable-ref backend holds its ordinary shared namespace fence for
    /// the scan, so every returned binding comes from one stable ref view. Head
    /// bodies remain immutable after that fence is released and are completely
    /// authenticated before this method returns.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid cursor or limit, excessive ref scan,
    /// malformed campaign ref, invalid snapshot target, or incomplete head.
    pub fn list_heads(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<CampaignHeadPage, CampaignRepositoryError> {
        let namespace = RefName::new("campaigns")?;
        let after_ref = after.map(campaign_ref).transpose()?;
        let page = self.refs.scan_refs(&namespace, after_ref.as_ref(), limit)?;
        let mut heads = Vec::with_capacity(page.entries().len());
        for entry in page.entries() {
            let name = entry
                .name()
                .as_str()
                .strip_prefix("campaigns/")
                .ok_or_else(|| integrity("campaign-ref-scan-namespace-mismatch"))?
                .to_owned();
            if campaign_ref(&name)?.as_str() != entry.name().as_str() {
                return Err(integrity("campaign-ref-scan-name-is-not-canonical"));
            }
            let snapshot_id = CampaignSnapshotId::from_content_id(entry.target())?;
            let loaded = self.read_snapshot(entry.target())?;
            self.validate_complete_head(entry.target())?;
            heads.push(CampaignHead {
                name,
                snapshot_id,
                snapshot: loaded.snapshot,
            });
        }
        let next_after = page
            .next_after()
            .map(|cursor| {
                cursor
                    .as_str()
                    .strip_prefix("campaigns/")
                    .ok_or_else(|| integrity("campaign-ref-scan-cursor-namespace-mismatch"))
                    .map(str::to_owned)
            })
            .transpose()?;
        Ok(CampaignHeadPage {
            heads,
            next_after,
            visited_refs: page.visited(),
        })
    }

    /// Loads one exact snapshot from the authenticated history of `name`.
    ///
    /// The lookup validates the named current head before walking immutable
    /// parent links. A snapshot from another campaign is rejected even when its
    /// object is present in the same store.
    ///
    /// # Errors
    ///
    /// Returns an error when the campaign is absent, its head is invalid, the
    /// snapshot is not in that history, the ancestry bound is exceeded, or an
    /// immutable object cannot be read.
    pub fn snapshot_in_campaign(
        &self,
        name: &str,
        snapshot: CampaignSnapshotId,
    ) -> Result<CampaignSnapshot, CampaignRepositoryError> {
        let head = self.head(name)?;
        self.load_named_ancestor_snapshot(head.snapshot_id().content_id(), snapshot)
            .map(|loaded| loaded.snapshot)
    }

    pub(crate) fn scan_graph_page(
        &self,
        root: ContentId,
        after: Option<CampaignHash>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapPageProof), CampaignRepositoryError> {
        self.merkle
            .scan_with_proof(root, after, limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-query-cursor-is-not-in-graph",
                },
                error => error.into(),
            })
    }

    pub(crate) fn scan_findings_page(
        &self,
        root: ContentId,
        after: Option<CampaignHash>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapPageProof), CampaignRepositoryError> {
        self.merkle
            .scan_with_proof(root, after, limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-finding-query-cursor-is-not-in-index",
                },
                error => error.into(),
            })
    }

    pub(crate) fn finding_with_proof(
        &self,
        root: ContentId,
        finding: FindingId,
    ) -> Result<(Finding, MerkleMapLookupProof), CampaignRepositoryError> {
        let value = self.read_finding(finding.content_id())?;
        let key = finding_signature_key(value.signature().cluster_key());
        let (indexed, proof) = self.merkle.get_with_proof(root, key)?;
        if indexed != Some(finding.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-finding-is-not-in-snapshot",
            });
        }
        Ok((value, proof))
    }

    pub(crate) fn attempt_with_proof(
        &self,
        root: ContentId,
        attempt: AttemptId,
    ) -> Result<(Attempt, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, attempt_index_key(attempt))?;
        if indexed != Some(attempt.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-attempt-is-not-in-snapshot",
            });
        }
        Ok((self.load_attempt(attempt)?, proof))
    }

    pub(crate) fn attempt_execution_basis_with_proof(
        &self,
        root: ContentId,
        attempt: AttemptId,
    ) -> Result<(AttemptAdmission, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, attempt_execution_basis_key(attempt))?;
        let admission = AttemptAdmissionId::from_content_id(indexed.ok_or(
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-attempt-execution-basis-is-not-in-snapshot",
            },
        )?)?;
        Ok((self.load_attempt_admission(admission)?, proof))
    }

    pub(crate) fn proposal_with_proof(
        &self,
        root: ContentId,
        proposal: ProposalId,
    ) -> Result<(Proposal, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, proposal_index_key(proposal))?;
        if indexed != Some(proposal.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-proposal-is-not-in-snapshot",
            });
        }
        Ok((self.load_proposal(proposal)?, proof))
    }

    pub(crate) fn planner_step_for_invocation_with_proof(
        &self,
        root: ContentId,
        invocation: PlannerInvocationId,
    ) -> Result<(PlannerStep, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, planner_invocation_result_key(invocation))?;
        let step = PlannerStepId::from_content_id(indexed.ok_or(
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-planner-invocation-is-not-in-snapshot",
            },
        )?)?;
        let step = self.read_planner_step(step.content_id())?;
        if step.invocation() != invocation {
            return Err(integrity(
                "campaign-planner-invocation-result-step-mismatch",
            ));
        }
        Ok((step, proof))
    }

    pub(crate) fn planner_step_with_proof(
        &self,
        root: ContentId,
        step: PlannerStepId,
    ) -> Result<(PlannerStep, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self.merkle.get_with_proof(root, planner_step_key(step))?;
        if indexed != Some(step.content_id()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-planner-step-is-not-in-snapshot",
            });
        }
        Ok((self.read_planner_step(step.content_id())?, proof))
    }

    pub(crate) fn attempt_observation_with_proof(
        &self,
        root: ContentId,
        attempt: AttemptId,
    ) -> Result<(Option<Observation>, MerkleMapLookupProof), CampaignRepositoryError> {
        let (indexed, proof) = self
            .merkle
            .get_with_proof(root, attempt_observation_key(attempt))?;
        let observation = indexed
            .map(ObservationId::from_content_id)
            .transpose()?
            .map(|id| self.load_observation(id))
            .transpose()?;
        Ok((observation, proof))
    }

    pub(crate) fn graph_object_with_proof(
        &self,
        root: ContentId,
        key: CampaignHash,
    ) -> Result<(ObjectEnvelope, MerkleMapLookupProof), CampaignRepositoryError> {
        let (object, proof) = self.merkle.get_with_proof(root, key)?;
        let object = object.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-graph-object-key-is-not-present",
        })?;
        Ok((self.read_envelope(object)?, proof))
    }

    pub(crate) fn scan_choice_page(
        &self,
        graph_root: ContentId,
        after: Option<ChoiceOpportunityId>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapLookupProof, MerkleMapPageProof), CampaignRepositoryError>
    {
        let (choice_index, index_proof) = self
            .merkle
            .get_with_proof(graph_root, choice_index_anchor_key())?;
        let choice_index = choice_index.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-choice-index",
        })?;
        let (page, page_proof) = self
            .merkle
            .scan_with_proof(choice_index, after.map(choice_index_order_key), limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-choice-query-cursor-is-not-in-index",
                },
                error => error.into(),
            })?;
        Ok((page, index_proof, page_proof))
    }

    pub(crate) fn scan_frontier_page(
        &self,
        exploration_root: ContentId,
        after: Option<BranchRequestId>,
        limit: usize,
    ) -> Result<(MerkleMapPage, MerkleMapLookupProof, MerkleMapPageProof), CampaignRepositoryError>
    {
        let (frontier_index, index_proof) = self
            .merkle
            .get_with_proof(exploration_root, frontier_index_anchor_key())?;
        let frontier_index = frontier_index.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-frontier-index",
        })?;
        let (page, page_proof) = self
            .merkle
            .scan_with_proof(frontier_index, after.map(frontier_index_order_key), limit)
            .map_err(|error| match error {
                CampaignStoreError::InvalidMerkle {
                    reason: "page-cursor-not-in-root",
                } => CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-frontier-query-cursor-is-not-in-index",
                },
                error => error.into(),
            })?;
        Ok((page, index_proof, page_proof))
    }

    pub(crate) fn lookup_frontier_projection(
        &self,
        exploration_root: ContentId,
        request: BranchRequestId,
    ) -> Result<(ContentId, MerkleMapLookupProof, MerkleMapLookupProof), CampaignRepositoryError>
    {
        let (frontier_index, index_proof) = self
            .merkle
            .get_with_proof(exploration_root, frontier_index_anchor_key())?;
        let frontier_index = frontier_index.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-frontier-index",
        })?;
        let (projection, object_proof) = self
            .merkle
            .get_with_proof(frontier_index, frontier_index_order_key(request))?;
        let projection = projection.ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-branch-request-is-not-in-frontier-index",
        })?;
        Ok((projection, index_proof, object_proof))
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
        self.head_with_lifecycle(name)
            .map(|(head, lifecycle)| (head, lifecycle.state()))
    }

    /// Resolves one authenticated head and its complete lifecycle intent.
    ///
    /// The state and active-attempt policy are projected from the same exact
    /// content ID returned in the head, so a concurrent ref advance cannot mix
    /// lifecycle fields from different snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent name or an
    /// integrity/store error for an invalid reachable closure or lifecycle.
    pub fn head_with_lifecycle(
        &self,
        name: &str,
    ) -> Result<(CampaignHead, CampaignLifecycle), CampaignRepositoryError> {
        let head = self.head(name)?;
        let lifecycle = self.lifecycle_at_snapshot(head.snapshot_id())?;
        Ok((head, lifecycle))
    }

    /// Resolves the authenticated genesis snapshot of one named campaign.
    ///
    /// The validated-head checkpoint retains the exact genesis content ID, so
    /// repeated creation replay remains constant-time after ordinary head
    /// validation instead of walking the complete campaign history again.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::NotFound`] for an absent campaign or
    /// an integrity/store error for an invalid current head or genesis record.
    pub fn genesis(&self, name: &str) -> Result<CampaignHead, CampaignRepositoryError> {
        let current = self.head(name)?;
        let checkpoint = self.load_validation_checkpoint(current.content_id())?;
        let loaded = self.read_snapshot(checkpoint.genesis)?;
        Ok(CampaignHead {
            name: name.to_owned(),
            snapshot_id: CampaignSnapshotId::from_content_id(checkpoint.genesis)?,
            snapshot: loaded.snapshot,
        })
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
        self.lifecycle_at_snapshot(snapshot)
            .map(CampaignLifecycle::state)
    }

    /// Projects complete lifecycle intent from one exact authenticated snapshot.
    ///
    /// # Errors
    ///
    /// Returns an integrity/store error when the snapshot or its reachable
    /// ancestry is absent, malformed, excessive, or semantically invalid.
    pub fn lifecycle_at_snapshot(
        &self,
        snapshot: CampaignSnapshotId,
    ) -> Result<CampaignLifecycle, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        self.current_lifecycle(snapshot.content_id())
            .map(|state| CampaignLifecycle {
                state: state.visible,
                active_attempt_policy: state.active_attempt_policy,
            })
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
    /// exhausted aggregate proposal allowance, publication failure, or final
    /// authoritative-ref conflict.
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
        self.ensure_budget_available(&current, 1, 0)?;

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
        if let Some(frontier_index) = self.merkle.get(
            current.snapshot.roots().exploration,
            frontier_index_anchor_key(),
        )? {
            let request = self.read_branch_request(proposal.request().content_id())?;
            let prior_state = self.continuation_state(
                super::projection::CandidateViewRoots::from_roots(current.snapshot.roots()),
                proposal.request(),
                &request,
            )?;
            self.validate_frontier_projection(
                frontier_index,
                proposal.request(),
                proposal.branch_point(),
                prior_state,
            )?;
            let next_frontier = self
                .frontier_index_after(
                    current.snapshot.roots().exploration,
                    &[(
                        proposal.request(),
                        proposal.branch_point(),
                        crate::ContinuationState::Open,
                    )],
                    true,
                )?
                .ok_or_else(|| integrity("proposal-frontier-index-disappeared"))?;
            exploration = self.merkle.insert(
                exploration.content_id(),
                frontier_index_anchor_key(),
                next_frontier,
            )?;
        }

        let fact = CampaignFact::ProposalIssued(proposal_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.exploration = exploration.content_id();
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
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
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

        let new_basis = self
            .merkle
            .get(
                current.snapshot.roots().accounting,
                map_key_content(
                    "accounting.attempt-execution-basis",
                    attempt_id.content_id(),
                ),
            )?
            .is_none();
        self.ensure_budget_available(&current, 0, u64::from(new_basis))?;

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

        let mut exploration = current.snapshot.roots().exploration;
        if let Some(frontier_index) = self.merkle.get(exploration, frontier_index_anchor_key())? {
            let proposal_record = self.read_proposal(proposal.content_id())?;
            let request = self.read_branch_request(proposal_record.request().content_id())?;
            let prior_state = self.continuation_state(
                super::projection::CandidateViewRoots::new(
                    exploration,
                    current.snapshot.roots().observations,
                    current.snapshot.roots().corpus,
                    current.snapshot.roots().accounting,
                ),
                proposal_record.request(),
                &request,
            )?;
            self.validate_frontier_projection(
                frontier_index,
                proposal_record.request(),
                proposal_record.branch_point(),
                prior_state,
            )?;
            let next_state = self.continuation_state(
                super::projection::CandidateViewRoots::new(
                    exploration,
                    current.snapshot.roots().observations,
                    current.snapshot.roots().corpus,
                    accounting,
                ),
                proposal_record.request(),
                &request,
            )?;
            let next_frontier = self
                .frontier_index_after(
                    exploration,
                    &[(
                        proposal_record.request(),
                        proposal_record.branch_point(),
                        next_state,
                    )],
                    true,
                )?
                .ok_or_else(|| integrity("attempt-admission-frontier-index-disappeared"))?;
            exploration = self
                .merkle
                .insert(exploration, frontier_index_anchor_key(), next_frontier)?
                .content_id();
        }

        let fact = CampaignFact::AttemptAdmitted(admission_id);
        let transition_content = self.put_fact(&fact)?;
        let mut roots = current.snapshot.roots();
        roots.exploration = exploration;
        roots.accounting = accounting;
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
                CampaignFact::ControlRequested(_)
                | CampaignFact::BranchRequestIssued(_)
                | CampaignFact::PinCommandAccepted(_) => {
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
        let next = self.budgeted_successor(
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

    /// Applies one idempotent semantic configuration-pin mutation.
    ///
    /// Command lookup precedes stale-precondition checking, so an exact replay
    /// returns the snapshot that first accepted the request even after later
    /// mutations. Removing a pin writes an authenticated tombstone into the
    /// pins projection rather than erasing campaign history.
    ///
    /// # Errors
    ///
    /// Returns an error for command-ID reuse, a stale precondition, a target
    /// outside the authoritative graph, object publication failure, or final
    /// ref CAS conflict.
    pub fn apply_pin(
        &self,
        name: &str,
        request: &PinRequest,
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
                CampaignFact::PinCommandAccepted(prior_request) if prior_request == *request => {
                    return self.find_pin_result(current_content, request, true);
                }
                CampaignFact::ControlRequested(_)
                | CampaignFact::BranchRequestIssued(_)
                | CampaignFact::PinCommandAccepted(_) => {
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

        let configuration = request.change.configuration();
        let configuration_content = self
            .merkle
            .get(
                current.snapshot.roots().graph,
                map_key_hash("graph.configuration", configuration.as_hash()),
            )?
            .ok_or_else(|| integrity("pin-configuration-is-not-in-campaign-graph"))?;
        let artifact = self.read_configuration_artifact(configuration_content)?;
        if artifact.configuration() != configuration {
            return Err(integrity("pin-configuration-index-mismatch"));
        }

        let pin_fact = CampaignFact::PinCommandAccepted(request.clone());
        let pin_content = self.put_fact(&pin_fact)?;
        let accounting = self.merkle.insert(
            current.snapshot.roots().accounting,
            command_key,
            pin_content,
        )?;
        let pins = self.merkle.insert(
            current.snapshot.roots().pins,
            pin_configuration_key(configuration),
            pin_content,
        )?;

        let mut roots = current.snapshot.roots();
        roots.pins = pins.content_id();
        roots.accounting = accounting.content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(pin_content)?,
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
                let content = self.put_envelope(ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::PlannerCandidateBudget,
                    crate::object::content_children(budget.content_children())?,
                    budget.canonical_bytes(),
                )?)?;
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
                    let eligibility = self.planner_candidate_budget(&snapshot, &offer, ledger)?;
                    push_retained_planner_input(
                        &mut retained,
                        &mut retained_bytes,
                        ObjectEnvelope::for_record(
                            crate::CampaignRecordKind::PlannerCandidateBudget,
                            crate::object::content_children(eligibility.content_children())?,
                            eligibility.canonical_bytes(),
                        )?,
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
}

fn validate_creation_artifact_basis(
    lineage: &CampaignLineage,
    scenario: &ScenarioArtifact,
    genesis: &ConfigurationArtifact,
) -> Result<(), CampaignRepositoryError> {
    // The genesis ID authenticates its complete configuration payload,
    // including that payload's version. `exact_closure_schema` instead names
    // executor checkpoint closures; the two formats evolve independently.
    if scenario.id()? != lineage.scenario_content()
        || scenario.scenario() != lineage.scenario()
        || scenario.payload_schema() != lineage.scenario_schema()
        || genesis.id()? != lineage.genesis_content()
        || genesis.scenario() != lineage.scenario()
        || genesis.scenario_artifact() != lineage.scenario_content()
        || genesis.configuration() != lineage.genesis()
    {
        return Err(integrity("lineage-execution-model-artifact-mismatch"));
    }
    Ok(())
}

fn push_retained_planner_input(
    retained: &mut Vec<ObjectEnvelope>,
    retained_bytes: &mut usize,
    envelope: ObjectEnvelope,
) -> Result<(), CampaignRepositoryError> {
    if retained.len() >= crate::MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS {
        return Err(integrity("retained-planner-request-bundle-object-count"));
    }
    *retained_bytes = retained_bytes
        .checked_add(envelope.canonical_bytes().len())
        .filter(|bytes| *bytes <= crate::MAX_RETAINED_PLANNER_REQUEST_BYTES)
        .ok_or_else(|| integrity("retained-planner-request-encoded-bytes"))?;
    retained.push(envelope);
    Ok(())
}

pub(super) fn charge_creation_generator_bytes(
    total: &mut usize,
    next: usize,
) -> Result<(), CampaignRepositoryError> {
    *total = (*total)
        .checked_add(next)
        .filter(|bytes| *bytes <= crate::MAX_CREATE_CAMPAIGN_GENERATOR_BYTES)
        .ok_or_else(|| integrity("campaign-generator-byte-limit"))?;
    Ok(())
}

fn validate_creation_generator_closure(
    policy: &CampaignPolicy,
    generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
) -> Result<(), CampaignRepositoryError> {
    if generators.len() > crate::MAX_CREATE_CAMPAIGN_GENERATORS {
        return Err(integrity("campaign-generator-count-limit"));
    }
    let mut canonical_bytes = 0_usize;
    for (expected, generator) in generators {
        charge_creation_generator_bytes(&mut canonical_bytes, generator.canonical_bytes().len())?;
        if generator.id()? != *expected {
            return Err(integrity("candidate-generator-map-key-mismatch"));
        }
    }

    let mut pending: Vec<_> = policy
        .content_children()
        .into_iter()
        .map(|(_, child)| CandidateGeneratorSpecId::from_content_id(child))
        .collect::<Result<_, _>>()?;
    let mut reachable = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let generator = generators
            .get(&id)
            .ok_or_else(|| integrity("campaign-policy-generator-was-not-supplied"))?;
        for (_, child) in generator.content_children() {
            pending.push(CandidateGeneratorSpecId::from_content_id(child)?);
        }
    }
    if reachable.len() != generators.len() {
        return Err(integrity("campaign-generator-map-has-unreachable-record"));
    }
    Ok(())
}
