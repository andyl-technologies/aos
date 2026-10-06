//! Incremental campaign closure authentication.

use super::*;

/// Authenticated campaign metadata with a separate bounded RAM frontier.
///
/// Generic objects include complete RAM root records. RAM descendants are not
/// flattened into this set; destructive inventory must authenticate and mark
/// every descendant through the CAS RAM inventory walker before deletion.
pub struct CampaignStorageClosure {
    pub(in crate::repository) objects: BTreeSet<ContentId>,
    pub(in crate::repository) exact_leaves: BTreeSet<ContentId>,
    pub(in crate::repository) ram_roots: Vec<ContentId>,
    pub(in crate::repository) ram_bindings: Vec<(crate::ExactCheckpointId, ContentId)>,
}

impl CampaignStorageClosure {
    /// Returns fully authenticated generic objects, including RAM roots.
    #[must_use]
    pub fn objects(&self) -> &BTreeSet<ContentId> {
        &self.objects
    }

    /// Returns complete RAM roots in canonical storage identity order.
    #[must_use]
    pub fn ram_roots(&self) -> &[ContentId] {
        &self.ram_roots
    }
}

/// Optional inventories produced by one authenticated generic traversal.
#[derive(Default)]
pub(in crate::repository) struct ClosureCollection<'a> {
    pub(in crate::repository) objects: Option<&'a mut BTreeSet<ContentId>>,
    pub(in crate::repository) exact_leaves: Option<&'a mut BTreeSet<ContentId>>,
    pub(in crate::repository) ram: Option<&'a mut ArchiveRamInventory>,
}

pub(in crate::repository) struct ArchiveRamInventory {
    roots: BTreeSet<ContentId>,
    bindings: BTreeSet<(crate::ExactCheckpointId, ContentId)>,
    verify_contents: bool,
}

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

    /// Authenticates generic storage closure under destructive inventory ownership.
    ///
    /// RAM roots are returned separately after bounded metadata authentication.
    /// The caller must visit and mark their complete graphs under `inventory`
    /// before authorizing any deletion. No lazy reader or retention lease is
    /// created, and this method never reacquires a shared publication fence.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable, corrupt, invalid, or excessive generic
    /// objects or RAM root metadata.
    pub fn authenticated_storage_closure(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        _inventory: &dyn crucible_cas::content_store::RefInventoryFence,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        self.authenticated_archive_closure(roots, false, &mut || Ok(()))
    }

    pub(in crate::repository) fn authenticated_archive_closure(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        verify_contents: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        let mut objects = BTreeSet::new();
        let mut exact_leaves = BTreeSet::new();
        let mut ram = ArchiveRamInventory {
            roots: BTreeSet::new(),
            bindings: BTreeSet::new(),
            verify_contents,
        };
        self.verify_campaign_closures_anchored_cached_collect(
            roots,
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
            ClosureCollection {
                objects: Some(&mut objects),
                exact_leaves: Some(&mut exact_leaves),
                ram: Some(&mut ram),
            },
            boundary,
        )?;
        if ram
            .bindings
            .iter()
            .any(|(_, root)| !ram.roots.contains(root))
        {
            return Err(integrity("campaign-exact-ram-root-is-untyped"));
        }
        Ok(CampaignStorageClosure {
            objects,
            exact_leaves,
            ram_roots: ram.roots.into_iter().collect(),
            ram_bindings: ram.bindings.into_iter().collect(),
        })
    }

    pub(in crate::repository) fn authenticate_ram_root(
        &self,
        id: ContentId,
        verify_contents: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        use crucible_cas::ram::{RamRetention, RamStore, RamStoreLimits};
        let map_error = CampaignRepositoryError::Ram;
        let store = RamStore::new(
            Arc::clone(&self.blobs),
            crucible_cas::content_store::DurabilityRequirement::new(1, false)?,
            RamStoreLimits::default(),
        )
        .map_err(map_error)?;
        if verify_contents {
            let retention = self
                .ram_retention_authority()
                .acquire()
                .map_err(map_error)?;
            let lease = retention.retain_root(id).map_err(map_error)?;
            let root = store
                .open_with_metadata_resources(lease, boundary)
                .map_err(map_error)?;
            if root.record().scope() != crucible_ram::Scope::Exact {
                return Err(integrity("campaign-ram-root-wrong-scope"));
            }
            store.verify(&root, boundary).map_err(map_error)?;
        } else {
            let metadata = store
                .inspect_root_with_metadata_resources(id, boundary)
                .map_err(map_error)?;
            if metadata.record().scope() != crucible_ram::Scope::Exact {
                return Err(integrity("campaign-ram-root-wrong-scope"));
            }
        }
        Ok(())
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
            ClosureCollection {
                objects: Some(&mut objects),
                ..ClosureCollection::default()
            },
            &mut || Ok(()),
        )?;
        Ok(objects)
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
            ClosureCollection::default(),
            &mut || Ok(()),
        )
    }

    pub(super) fn verify_campaign_closures_anchored_cached_collect(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        anchors: &BTreeSet<ContentId>,
        choice_cache: &mut ChoiceValidationCache,
        mut collection: ClosureCollection<'_>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_cas::ram::RamStoreError>,
    ) -> Result<usize, CampaignRepositoryError> {
        let mut stack = roots.into_iter().map(|id| (id, false)).collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut verified_merkle_positions = BTreeSet::new();

        while let Some((id, exact_leaf)) = stack.pop() {
            boundary().map_err(CampaignRepositoryError::Ram)?;
            if anchors.contains(&id) {
                continue;
            }
            if !visited.insert((id, exact_leaf)) {
                continue;
            }
            if let Some(objects) = collection.objects.as_deref_mut() {
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
                // A full cold walk reads every yielded leaf below. Anchored
                // incremental walks may skip known parent leaves, so they
                // still check leaf presence during Merkle verification.
                let verified = if anchors.is_empty() {
                    self.merkle
                        .verify_closure_structure_cached(id, &mut verified_merkle_positions)?
                } else {
                    self.merkle
                        .verify_closure_objects_cached(id, &mut verified_merkle_positions)?
                };
                if let Some(objects) = collection.objects.as_deref_mut() {
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
                if let Some(leaves) = collection.exact_leaves.as_deref_mut() {
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
                if envelope.schema_name() == "crucible.executor.exact-checkpoint-root"
                    && (id.kind() != ObjectKind::ExactManifest || envelope.schema_version() != 6)
                {
                    return Err(integrity("campaign-exact-root-unsupported-edition"));
                }
                if envelope.schema_name() == "crucible.ram.root"
                    && (id.kind() != ObjectKind::ExactManifest || envelope.schema_version() != 1)
                {
                    return Err(integrity("campaign-ram-root-unsupported-edition"));
                }
                let exact_root = id.kind() == ObjectKind::ExactManifest
                    && envelope.schema_name() == "crucible.executor.exact-checkpoint-root"
                    && envelope.schema_version() == 6;
                let ram_root = id.kind() == ObjectKind::ExactManifest
                    && envelope.schema_name() == "crucible.ram.root"
                    && envelope.schema_version() == 1;
                if ram_root {
                    let verify = collection
                        .ram
                        .as_ref()
                        .is_none_or(|ram| ram.verify_contents);
                    self.authenticate_ram_root(id, verify, boundary)?;
                    if let Some(ram) = collection.ram.as_deref_mut() {
                        ram.roots.insert(id);
                    }
                    if collection.ram.is_some() || collection.objects.is_none() {
                        continue;
                    }
                }
                if exact_root {
                    let owner = crate::ExactCheckpointId::from_content_id(id)?;
                    let mut ordinal = 0_u32;
                    for child in envelope
                        .children()
                        .iter()
                        .filter(|child| child.role().starts_with("ram-root-"))
                    {
                        if child.role() != format!("ram-root-{ordinal:08x}")
                            || child.id().kind() != ObjectKind::ExactManifest
                            || child.id().schema_version() != 1
                        {
                            return Err(integrity("campaign-exact-ram-root-role-mismatch"));
                        }
                        if let Some(ram) = collection.ram.as_deref_mut() {
                            ram.bindings.insert((owner, child.id()));
                        }
                        ordinal = ordinal
                            .checked_add(1)
                            .ok_or_else(|| integrity("campaign-exact-ram-root-limit"))?;
                    }
                }
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
