//! Incremental campaign closure authentication.

use super::read::ClosureRead;
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
    // Checked collection allocations close before their operation custody.
    _custody: Option<crucible_store::owned_decode::DecodeCustody>,
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
    // None selects saved repository admission. Some(None) explicitly denies
    // RAM for an archive operation whose validated closure must contain none.
    pub(in crate::repository) ram_original:
        Option<Option<&'a crucible_store::owned_decode::DecodeBudget>>,
    pub(in crate::repository) checked_original:
        Option<&'a crucible_store::owned_decode::DecodeBudget>,
    pub(in crate::repository) checked_operation:
        Option<&'a crucible_store::owned_decode::DecodeBudget>,
    pub(in crate::repository) operation:
        Option<&'a mut Option<crucible_store::owned_decode::DecodeBudget>>,
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
        _inventory: &dyn crucible_store::content_store::RefInventoryFence,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        self.authenticated_storage_closure_with_boundary(roots, _inventory, &mut || Ok(()))
    }

    /// Authenticates storage metadata under the caller's original inventory operation.
    ///
    /// RAM graphs remain a separate bounded inventory traversal under the same
    /// exclusive fence. The callback is polled throughout generic closure reads.
    ///
    /// # Errors
    /// Refuses expired supervision, invalid metadata, missing objects, and
    /// incomplete or excessive closures before permitting any deletion.
    pub fn authenticated_storage_closure_with_boundary(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        _inventory: &dyn crucible_store::content_store::RefInventoryFence,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        self.authenticated_archive_closure(roots, false, boundary)
    }

    pub(in crate::repository) fn authenticated_archive_closure(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        verify_contents: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        self.authenticated_archive_closure_under(roots, verify_contents, None, boundary)
    }

    pub(in crate::repository) fn authenticated_archive_closure_under(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        verify_contents: bool,
        ram_original: Option<Option<&crucible_store::owned_decode::DecodeBudget>>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        self.authenticated_archive_closure_under_resources(
            roots,
            verify_contents,
            ram_original,
            None,
            boundary,
        )
    }

    pub(in crate::repository) fn authenticated_archive_closure_with_operation(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        verify_contents: bool,
        saved: &crucible_store::owned_decode::DecodeBudget,
        operation: &crucible_store::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        self.authenticated_archive_closure_under_resources(
            roots,
            verify_contents,
            None,
            Some((saved, operation)),
            boundary,
        )
    }

    fn authenticated_archive_closure_under_resources(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        verify_contents: bool,
        ram_original: Option<Option<&crucible_store::owned_decode::DecodeBudget>>,
        checked: Option<(
            &crucible_store::owned_decode::DecodeBudget,
            &crucible_store::owned_decode::DecodeBudget,
        )>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignStorageClosure, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        let mut objects = BTreeSet::new();
        let mut exact_leaves = BTreeSet::new();
        let mut ram = ArchiveRamInventory {
            roots: BTreeSet::new(),
            bindings: BTreeSet::new(),
            verify_contents,
        };
        let mut operation = None;
        let (checked_original, checked_operation) = checked.unzip();
        self.verify_campaign_closures_anchored_cached_collect(
            roots,
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
            ClosureCollection {
                objects: Some(&mut objects),
                exact_leaves: Some(&mut exact_leaves),
                ram: Some(&mut ram),
                ram_original,
                checked_original,
                checked_operation,
                operation: Some(&mut operation),
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
        let ram_roots = collect_checked_vec(operation.as_ref(), ram.roots)?;
        let ram_bindings = collect_checked_vec(operation.as_ref(), ram.bindings)?;
        let custody = operation.map(|operation| operation.custody());
        Ok(CampaignStorageClosure {
            objects,
            exact_leaves,
            ram_roots,
            ram_bindings,
            _custody: custody,
        })
    }

    pub(in crate::repository) fn authenticate_ram_root(
        &self,
        id: ContentId,
        verify_contents: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let original = self.ram_operation_account()?;
        self.authenticate_ram_root_under(id, verify_contents, &original, boundary)
    }

    pub(in crate::repository) fn authenticate_ram_root_under(
        &self,
        id: ContentId,
        verify_contents: bool,
        original: &crucible_store::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        use crucible_store::ram::{RamRetention, RamStore, RamStoreLimits};
        let map_error = CampaignRepositoryError::Ram;
        original.verify_live().map_err(|source| {
            map_error(crucible_store::ram::RamStoreError::from_admission(
                original, source,
            ))
        })?;
        let store = RamStore::new(
            Arc::clone(&self.blobs),
            crucible_store::content_store::DurabilityRequirement::new(1, false)?,
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
                .open_with_metadata_resources(lease, original, boundary)
                .map_err(map_error)?;
            if root.record().scope() != crucible_ram::Scope::Exact {
                return Err(integrity("campaign-ram-root-wrong-scope"));
            }
            store.verify(&root, original, boundary).map_err(map_error)?;
        } else {
            let metadata = store
                .inspect_root_with_metadata_resources(id, original, boundary)
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
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        let reader = match (collection.checked_original, collection.checked_operation) {
            (Some(saved), Some(operation)) => ClosureRead::from_operation(self, saved, operation),
            (saved, None) => ClosureRead::new(self, saved)?,
            (None, Some(_)) => {
                return Err(integrity(
                    "campaign-closure-checked-operation-has-no-original",
                ));
            }
        };
        let _operation_scope = reader.enter_operation();
        let mut stack = Vec::new();
        for id in roots {
            reader.push(&mut stack, (id, false))?;
        }
        let mut visited = BTreeSet::new();
        let mut verified_merkle_positions = BTreeSet::new();

        while let Some((id, exact_leaf)) = stack.pop() {
            reader.poll(boundary)?;
            if anchors.contains(&id) {
                continue;
            }
            if visited.contains(&(id, exact_leaf)) {
                continue;
            }
            reader.charge_btree_entry::<(ContentId, bool), ()>()?;
            visited.insert((id, exact_leaf));
            if let Some(objects) = collection.objects.as_deref_mut() {
                if !objects.contains(&id) {
                    reader.charge_btree_entry::<ContentId, ()>()?;
                }
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
                let verified = reader.verify_merkle_closure(
                    id,
                    &mut verified_merkle_positions,
                    !anchors.is_empty(),
                    boundary,
                )?;
                if let Some(objects) = collection.objects.as_deref_mut() {
                    for (node, _prefix) in &verified_merkle_positions {
                        if !objects.contains(node) {
                            reader.charge_btree_entry::<ContentId, ()>()?;
                        }
                        objects.insert(*node);
                    }
                }
                if visited
                    .len()
                    .checked_add(verified_merkle_positions.len())
                    .is_none_or(|objects| objects > MAX_CAMPAIGN_CLOSURE_OBJECTS)
                {
                    return Err(integrity("campaign-closure-object-limit"));
                }
                for id in verified.values {
                    reader.push(&mut stack, (id, false))?;
                }
                continue;
            }

            if exact_leaf {
                // Exact-root choice and replay evidence use Observation identities
                // for raw protocol bytes. Their parent role, not their kind alone,
                // grants opaque traversal; the immutable digest remains checked.
                reader.authenticate_exact_leaf(id, boundary)?;
                if let Some(leaves) = collection.exact_leaves.as_deref_mut() {
                    if !leaves.contains(&id) {
                        reader.charge_btree_entry::<ContentId, ()>()?;
                    }
                    leaves.insert(id);
                }
                continue;
            }
            if is_opaque_campaign_leaf(id.kind()) {
                reader.authenticate_opaque(id, boundary)?;
                continue;
            }
            let bytes = reader.read_envelope_bytes(id, boundary)?;
            if !is_campaign_record_kind(id.kind()) {
                let envelope = ContentEnvelope::from_canonical_bytes(bytes.as_ref())
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
                    reader.authenticate_ram_root(id, verify, collection.ram_original, boundary)?;
                    if let Some(ram) = collection.ram.as_deref_mut() {
                        if !ram.roots.contains(&id) {
                            reader.charge_btree_entry::<ContentId, ()>()?;
                        }
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
                            if !ram.bindings.contains(&(owner, child.id())) {
                                reader.charge_btree_entry::<
                                    (crate::ExactCheckpointId, ContentId),
                                    (),
                                >()?;
                            }
                            ram.bindings.insert((owner, child.id()));
                        }
                        ordinal = ordinal
                            .checked_add(1)
                            .ok_or_else(|| integrity("campaign-exact-ram-root-limit"))?;
                    }
                }
                for child in envelope.children() {
                    let exact_leaf = exact_root
                        && matches!(
                            child.role(),
                            "checkpoint-choice-closure" | "replay-oracle-evidence"
                        );
                    reader.push(&mut stack, (child.id(), exact_leaf))?;
                }
                continue;
            }
            let envelope = ObjectEnvelope::from_canonical_bytes(bytes.as_ref())?;
            if envelope.content_id() != id {
                return Err(integrity("campaign-closure-envelope-id-mismatch"));
            }

            match envelope.record_kind() {
                crate::CampaignRecordKind::Lineage => {
                    if reader.is_checked() {
                        reader.semantic(boundary).read_lineage(id)?;
                    } else {
                        self.read_lineage(id)?;
                    }
                }
                crate::CampaignRecordKind::Policy => {
                    if reader.is_checked() {
                        let policy = self.decode_policy_envelope(id, &envelope)?;
                        let mut semantic = reader.semantic(boundary);
                        for (role, child) in policy.content_children() {
                            let kind = Self::policy_child_kind(&role)?;
                            semantic.require_record_kind(child, kind)?;
                        }
                    } else {
                        self.read_policy(id)?;
                    }
                }
                crate::CampaignRecordKind::Fact => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .validate_fact_references(&envelope)?;
                    } else {
                        self.read_fact(id)?;
                    }
                }
                crate::CampaignRecordKind::CandidateGeneratorSpec => {
                    if reader.is_checked() {
                        reader.semantic(boundary).read_generator(id)?;
                    } else {
                        self.read_generator(id)?;
                    }
                }
                crate::CampaignRecordKind::ScenarioArtifact => {
                    if reader.is_checked() {
                        self.decode_scenario_artifact_envelope(id, &envelope)?;
                    } else {
                        self.read_scenario_artifact(id)?;
                    }
                }
                crate::CampaignRecordKind::ConfigurationArtifact => {
                    if reader.is_checked() {
                        let artifact =
                            self.decode_configuration_artifact_envelope(id, &envelope)?;
                        let mut semantic = reader.semantic(boundary);
                        let scenario = semantic
                            .read_scenario_artifact(artifact.scenario_artifact().content_id())?;
                        self.validate_configuration_artifact_scenario(&artifact, &scenario)?;
                    } else {
                        self.read_configuration_artifact(id)?;
                    }
                }
                crate::CampaignRecordKind::ReproductionArtifact => {
                    if reader.is_checked() {
                        let artifact = self.decode_reproduction_artifact_envelope(id, &envelope)?;
                        let mut semantic = reader.semantic(boundary);
                        let scenario = semantic
                            .read_scenario_artifact(artifact.scenario_artifact().content_id())?;
                        let configuration = semantic.read_configuration_artifact(
                            artifact.configuration_artifact().content_id(),
                        )?;
                        self.validate_reproduction_artifact_basis(
                            &artifact,
                            &scenario,
                            &configuration,
                        )?;
                    } else {
                        self.read_reproduction_artifact(id)?;
                    }
                }
                crate::CampaignRecordKind::Finding => {
                    if reader.is_checked() {
                        let finding = self.decode_finding_envelope(id, &envelope)?;
                        reader
                            .semantic(boundary)
                            .validate_finding_references_cached(&finding, choice_cache)?;
                    } else {
                        self.read_finding_cached(id, choice_cache)?;
                    }
                }
                crate::CampaignRecordKind::FindingCandidateBundle => {
                    if reader.is_checked() {
                        let bundle = FindingCandidateBundle::from_canonical_bytes(envelope.body())?;
                        if bundle.id()?.content_id() != id {
                            return Err(integrity("finding-candidate-bundle-envelope-shape"));
                        }
                        reader
                            .semantic(boundary)
                            .validate_finding_candidate_bundle(&bundle, choice_cache)?;
                    } else {
                        let bundle = self.decode_finding_candidate_bundle(id)?;
                        self.validate_finding_candidate_bundle(
                            &bundle,
                            super::finding_candidate::FindingCandidateValidation::Load,
                        )?;
                    }
                }
                crate::CampaignRecordKind::FindingTriageReplayEvidence => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .decode_finding_triage_replay_evidence(id)?;
                    } else {
                        let evidence = self.decode_finding_triage_replay_evidence(id)?;
                        self.validate_finding_triage_replay_evidence(&evidence)?;
                    }
                }
                crate::CampaignRecordKind::BranchRequest => {
                    if reader.is_checked() {
                        let mut semantic = reader.semantic(boundary);
                        let request = semantic.decode_branch_request(id)?;
                        semantic
                            .validate_branch_request_references_shallow(&request, choice_cache)?;
                    } else {
                        let request = self.decode_branch_request(id)?;
                        self.validate_branch_request_references_shallow(&request)?;
                    }
                }
                crate::CampaignRecordKind::Proposal => {
                    if reader.is_checked() {
                        let mut semantic = reader.semantic(boundary);
                        let proposal = semantic.decode_proposal(id)?;
                        semantic.validate_proposal_references_shallow(&proposal)?;
                    } else {
                        let proposal = self.decode_proposal(id)?;
                        self.validate_proposal_references_shallow(&proposal)?;
                    }
                }
                crate::CampaignRecordKind::Attempt => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .read_attempt_cached(id, choice_cache)?;
                    } else {
                        self.read_attempt_cached(id, choice_cache)?;
                    }
                }
                crate::CampaignRecordKind::AttemptAdmission => {
                    if reader.is_checked() {
                        let mut semantic = reader.semantic(boundary);
                        let admission = semantic.decode_attempt_admission(id)?;
                        semantic.validate_attempt_admission_references_shallow_cached(
                            &admission,
                            choice_cache,
                        )?;
                    } else {
                        let admission = self.decode_attempt_admission(id)?;
                        self.validate_attempt_admission_references_shallow_cached(
                            &admission,
                            choice_cache,
                        )?;
                    }
                }
                crate::CampaignRecordKind::PlannerStep => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .read_planner_step_with_request(id)?;
                    } else {
                        self.read_planner_step(id)?;
                    }
                }
                crate::CampaignRecordKind::RetainedPlannerRequest => {
                    if reader.is_checked() {
                        reader.semantic(boundary).read_planner_request(id)?;
                    } else {
                        self.read_planner_request(id)?;
                    }
                }
                crate::CampaignRecordKind::ExpansionState => {
                    if reader.is_checked() {
                        reader.semantic(boundary).read_expansion_state(id)?;
                    } else {
                        self.read_expansion_state(id)?;
                    }
                }
                crate::CampaignRecordKind::ContinuationProjection => {
                    if reader.is_checked() {
                        reader.semantic(boundary).read_continuation_projection(id)?;
                    } else {
                        self.read_continuation_projection(id)?;
                    }
                }
                crate::CampaignRecordKind::ExpansionCredit => {
                    if reader.is_checked() {
                        reader.semantic(boundary).read_expansion_credit(id)?;
                    } else {
                        self.read_expansion_credit(id)?;
                    }
                }
                crate::CampaignRecordKind::MeasurementSet => {
                    if reader.is_checked() {
                        self.decode_measurement_set_envelope(id, &envelope)?;
                    } else {
                        self.read_measurement_set(id)?;
                    }
                }
                crate::CampaignRecordKind::PropertyVerdictSet => {
                    if reader.is_checked() {
                        self.decode_property_verdict_set_envelope(id, &envelope)?;
                    } else {
                        self.read_property_verdict_set(id)?;
                    }
                }
                crate::CampaignRecordKind::CoverageProjection => {
                    if reader.is_checked() {
                        self.decode_coverage_projection_envelope(id, &envelope)?;
                    } else {
                        self.read_coverage_projection(id)?;
                    }
                }
                crate::CampaignRecordKind::Observation => {
                    if reader.is_checked() {
                        let mut semantic = reader.semantic(boundary);
                        let observation = semantic.decode_observation(id)?;
                        semantic
                            .validate_observation_references_cached(&observation, choice_cache)?;
                    } else {
                        let observation = self.decode_observation(id)?;
                        self.validate_observation_references_cached(&observation, choice_cache)?;
                    }
                }
                crate::CampaignRecordKind::ObjectiveEvaluation => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .read_objective_evaluation_cached(id, choice_cache)?;
                    } else {
                        self.read_objective_evaluation_cached(id, choice_cache)?;
                    }
                }
                crate::CampaignRecordKind::RankingExplanation => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .read_ranking_explanation_cached(id, choice_cache)?;
                    } else {
                        self.read_ranking_explanation_cached(id, choice_cache)?;
                    }
                }
                crate::CampaignRecordKind::SurvivorSelection => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .read_survivor_selection_bundle_cached(id, choice_cache)?;
                    } else {
                        self.read_survivor_selection_bundle_cached(id, choice_cache)?;
                    }
                }
                crate::CampaignRecordKind::PolicyArtifact => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .validate_policy_artifact_references(&envelope)?;
                    } else {
                        self.validate_policy_artifact_references(&envelope)?;
                    }
                }
                crate::CampaignRecordKind::PlannerState => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .validate_planner_state_references(&envelope)?;
                    } else {
                        self.validate_planner_state_references(&envelope)?;
                    }
                }
                crate::CampaignRecordKind::PlannerInvocation => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .validate_planner_invocation_references(&envelope)?;
                    } else {
                        self.validate_planner_invocation_references(&envelope)?;
                    }
                }
                crate::CampaignRecordKind::ChoiceOpportunity => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .validate_opportunity_references_cached(&envelope, choice_cache)?;
                    } else {
                        self.validate_opportunity_references_cached(&envelope, choice_cache)?;
                    }
                }
                crate::CampaignRecordKind::ChoiceGroup => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .validate_group_references(&envelope)?;
                    } else {
                        self.validate_group_references(&envelope)?;
                    }
                }
                crate::CampaignRecordKind::Selection => {
                    if reader.is_checked() {
                        reader
                            .semantic(boundary)
                            .validate_selection_references(&envelope, choice_cache)?;
                    } else {
                        self.validate_selection_references(&envelope)?;
                    }
                }
                _ => {}
            }
            for child in envelope.children() {
                reader.push(&mut stack, (child.id(), false))?;
            }
        }
        let objects = visited
            .len()
            .checked_add(verified_merkle_positions.len())
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        if let Some(operation) = collection.operation.as_deref_mut() {
            *operation = reader.retained_operation();
        }
        Ok(objects)
    }
}

fn collect_checked_vec<T: Ord>(
    operation: Option<&crucible_store::owned_decode::DecodeBudget>,
    values: BTreeSet<T>,
) -> Result<Vec<T>, CampaignRepositoryError> {
    let Some(operation) = operation else {
        return Ok(values.into_iter().collect());
    };
    operation
        .charge_array::<T>(values.len())
        .map_err(CampaignCodecError::from)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(values.len())
        .map_err(|source| StoreError::Allocation {
            source,
            custody: Some(operation.custody()),
        })?;
    if output.capacity() > values.len() {
        return Err(StoreError::Quota.into());
    }
    output.extend(values);
    Ok(output)
}
