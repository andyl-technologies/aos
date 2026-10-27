//! Checked semantic validation for retained planner records.

use super::read::ClosureSemanticRead;
use super::*;

mod index;
mod lifecycle;
mod request;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn read_planner_invocation(
        &mut self,
        id: PlannerInvocationId,
    ) -> Result<PlannerInvocation, CampaignRepositoryError> {
        let (envelope, invocation) = self.decode_planner_invocation(id)?;
        self.validate_planner_invocation_references(&envelope)?;
        Ok(invocation)
    }

    pub(in crate::repository) fn read_planner_request(
        &mut self,
        id: ContentId,
    ) -> Result<PlannerRequest, CampaignRepositoryError> {
        // Bundle validation builds bounded temporary maps and sets. Keep the
        // checked operation's prepaid account current through decoding and
        // validation so those allocations cannot escape its custody.
        let _operation = self.enter_operation();
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::RetainedPlannerRequest)?;
        let request = PlannerRequest::from_canonical_bytes(envelope.body())?;
        if request.id()?.content_id() != id {
            return Err(integrity("planner-request-envelope-shape"));
        }
        self.validate_planner_request_inputs(&request)?;
        Ok(request)
    }

    fn validate_planner_request_inputs(
        &mut self,
        request: &PlannerRequest,
    ) -> Result<(), CampaignRepositoryError> {
        self.require_record_kind(
            request.expected_snapshot().content_id(),
            crate::CampaignRecordKind::Snapshot,
        )?;
        let invocation = self.read_planner_invocation(request.invocation_id()?)?;
        if invocation != *request.invocation() {
            return Err(integrity("planner-request-invocation-mismatch"));
        }

        let engine = self.require_record_kind(
            invocation.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        let artifact = self.require_record_kind(
            invocation.policy_artifact().content_id(),
            crate::CampaignRecordKind::PolicyArtifact,
        )?;
        let state = self.require_record_kind(
            invocation.planner_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let view = self.require_record_kind(
            invocation.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if crate::codec::decode::<PlannerEngine>(engine.body())? != *request.engine()
            || crate::codec::decode::<PolicyArtifact>(artifact.body())?
                != *request.policy_artifact()
            || self.read_policy(invocation.policy().content_id())? != *request.policy()
            || crate::codec::decode::<PlannerState>(state.body())? != *request.planner_state()
            || crate::codec::decode::<CampaignPlanningView>(view.body())? != *request.input_view()
        {
            return Err(integrity("planner-request-by-value-basis-mismatch"));
        }
        let candidate_inputs = request.input_bundle().candidate_inputs(request)?;
        for input in candidate_inputs.values() {
            if let Some(offer) = &input.offer {
                offer.id()?;
            }
            if let Some(guidance) = &input.guidance {
                guidance.id()?;
            }
            if let Some(beam) = &input.beam {
                beam.id()?;
            }
            if let Some(search) = &input.search {
                search.id()?;
            }
            if let Some(budget) = &input.budget {
                budget.id()?;
            }
        }
        for object_id in request.input_bundle().object_ids() {
            if request.input_bundle().object(object_id)?.as_ref()
                != Some(&self.read_envelope(object_id)?)
            {
                return Err(integrity("planner-request-bundle-object-mismatch"));
            }
        }

        let snapshot = self.read_snapshot(request.expected_snapshot().content_id())?;
        if self.statistical_request_basis(&snapshot, request.policy())?
            != request.statistical_request_basis()
        {
            return Err(integrity("planner-request-statistical-basis-mismatch"));
        }
        if self
            .smc_request_basis(&snapshot, request.policy())?
            .as_ref()
            != request.smc_request_basis()
        {
            return Err(integrity("planner-request-SMC-basis-mismatch"));
        }
        let beam_projection = request
            .engine()
            .capabilities()
            .contains(crate::CANONICAL_BEAM_SURVIVORS_CAPABILITY)
            .then(|| self.project_beam_planner(&snapshot, request.policy()))
            .transpose()?;
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
            .then_some(crate::repository::budget::MAX_PLANNER_REQUEST_BUDGET_PROPOSALS);

        let mut guidance_points = BTreeSet::new();
        for (position, input) in &candidate_inputs {
            if input.guidance.is_some() {
                self.insert_set(&mut guidance_points, position.branch_point())?;
            }
            let Some(offer) = &input.offer else {
                continue;
            };
            let source = self.read_branch_request(position.source())?;
            let domain = self.read_choice_domain(source.domain().content_id())?;
            if self
                .candidate_source_profile(&source, &domain)?
                .is_some_and(|profile| profile.scores_interval_at(offer.ordinal()))
            {
                self.insert_set(&mut guidance_points, position.branch_point())?;
            }
        }
        let mut puct_projections = BTreeMap::new();
        for branch_point in guidance_points {
            let projection = self.project_branch_puct_loaded(&snapshot, branch_point)?;
            self.insert_map(&mut puct_projections, branch_point, projection)?;
        }

        let mut candidate_cache =
            crate::repository::projection::PlannerCandidateProjectionCache::default();
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
                    puct_projections.get(&position.branch_point()),
                )?;
                if expected.0 != input.continuation || expected.1.as_ref() != Some(offer) {
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
                if let Some(search) = &input.search {
                    let (expected, parent_path, path) =
                        self.planner_search_candidate(&snapshot, offer)?;
                    if search != &expected {
                        return Err(integrity("planner-request-search-candidate-mismatch"));
                    }
                    for (expected_envelope, mismatch_reason) in [
                        (
                            ObjectEnvelope::for_branch_path(&parent_path)?,
                            "planner-request-search-parent-path-mismatch",
                        ),
                        (
                            ObjectEnvelope::for_branch_path(&path)?,
                            "planner-request-search-path-mismatch",
                        ),
                    ] {
                        let bundled = request
                            .input_bundle()
                            .object(expected_envelope.content_id())?
                            .ok_or_else(|| integrity(mismatch_reason))?;
                        if bundled != expected_envelope {
                            return Err(integrity(mismatch_reason));
                        }
                    }
                }
            }
            if let Some(guidance) = &input.guidance {
                let offer = input
                    .offer
                    .as_ref()
                    .ok_or_else(|| integrity("planner-candidate-guidance-offer-is-missing"))?;
                let projection = puct_projections
                    .get(&position.branch_point())
                    .ok_or_else(|| integrity("planner-candidate-guidance-projection-is-missing"))?;
                let expected = self.planner_candidate_guidance(
                    &snapshot,
                    projection,
                    offer,
                    &mut candidate_cache,
                )?;
                if &expected != guidance {
                    return Err(integrity("planner-request-candidate-guidance-mismatch"));
                }
            }
            if let Some(beam) = &input.beam {
                let expected = beam_projection
                    .as_ref()
                    .and_then(|projection| projection.candidates.get(&position))
                    .ok_or_else(|| integrity("planner-request-Beam-projection-is-missing"))?;
                if expected != beam {
                    return Err(integrity("planner-request-Beam-projection-mismatch"));
                }
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn decode_planner_invocation(
        &mut self,
        id: PlannerInvocationId,
    ) -> Result<(ObjectEnvelope, PlannerInvocation), CampaignRepositoryError> {
        let envelope = self.require_record_kind(
            id.content_id(),
            crate::CampaignRecordKind::PlannerInvocation,
        )?;
        let invocation = crate::codec::decode::<PlannerInvocation>(envelope.body())?;
        if invocation.id()? != id {
            return Err(integrity("planner-invocation-envelope-shape"));
        }
        Ok((envelope, invocation))
    }

    pub(in crate::repository) fn planner_scan_page(
        &mut self,
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
            let source = after.source().content_id();
            if self.merkle_get(
                view.exploration(),
                map_key_content("exploration.branch-request", source),
            )? != Some(source)
            {
                return Err(integrity("planner-scan-page-after-is-not-authoritative"));
            }
            let request = self.read_branch_request(after.source())?;
            if request.branch_point() != after.branch_point() {
                return Err(integrity("planner-scan-page-after-is-not-authoritative"));
            }
        }

        let retained_limit = limit_usize
            .checked_add(1)
            .ok_or_else(|| integrity("planner-scan-page-limit-is-invalid"))?;
        let mut retained =
            self.indexed_planner_scan_positions(view.exploration(), after, retained_limit)?;
        let complete = retained.len() <= limit_usize;
        if !complete {
            retained.pop_last();
        }
        let input_bytes = retained.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(*bytes)
                .ok_or_else(|| integrity("planner-scan-page-input-byte-overflow"))
        })?;
        let mut positions = Vec::new();
        for position in retained.into_keys() {
            self.push(&mut positions, position)?;
        }
        PlanningScanPage::new(after, limit, positions, complete, input_bytes).map_err(Into::into)
    }

    fn indexed_planner_scan_positions(
        &mut self,
        exploration: ContentId,
        after: Option<PlanningScanPosition>,
        limit: usize,
    ) -> Result<BTreeMap<PlanningScanPosition, u64>, CampaignRepositoryError> {
        let index = self
            .merkle_get(exploration, planner_scan_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-planner-scan-index-is-missing"))?;
        let mut positions = BTreeMap::new();
        let mut branch_after = after.map(|position| position.branch_point().as_hash());
        if let Some(after) = after {
            let root = self
                .merkle_get(index, after.branch_point().as_hash())?
                .ok_or_else(|| integrity("planner-scan-index-cursor-branch-missing"))?;
            self.append_planner_scan_branch(
                root,
                after.branch_point(),
                Some(after.source()),
                limit,
                &mut positions,
            )?;
        }
        while positions.len() < limit {
            let page = self.merkle_scan(index, branch_after, limit - positions.len())?;
            for (key, root) in page.entries() {
                self.append_planner_scan_branch(
                    *root,
                    crate::BranchPointId::from_hash(*key),
                    None,
                    limit,
                    &mut positions,
                )?;
                if positions.len() == limit {
                    return Ok(positions);
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            branch_after = Some(next);
        }
        Ok(positions)
    }

    fn append_planner_scan_branch(
        &mut self,
        root: ContentId,
        branch: crate::BranchPointId,
        after: Option<BranchRequestId>,
        limit: usize,
        positions: &mut BTreeMap<PlanningScanPosition, u64>,
    ) -> Result<(), CampaignRepositoryError> {
        if self.merkle_inspect_shallow(root)?.entry_count() == 0 {
            return Err(integrity("planner-scan-index-empty-branch"));
        }
        let cursor = after.map(|request| CampaignHash::from_bytes(request.content_id().digest()));
        if let Some(after) = after {
            let content = after.content_id();
            let cursor_key = CampaignHash::from_bytes(content.digest());
            if self.merkle_get(root, cursor_key)? != Some(content) {
                return Err(integrity("planner-scan-index-cursor-request-missing"));
            }
            let request = self.read_branch_request(after)?;
            if request.branch_point() != branch || request.id()? != after {
                return Err(integrity("planner-scan-index-cursor-request-mismatch"));
            }
        }

        let page = self.merkle_scan(root, cursor, limit - positions.len())?;
        for (key, content) in page.entries() {
            let request = self.read_branch_request(BranchRequestId::from_content_id(*content)?)?;
            if *key != CampaignHash::from_bytes(content.digest())
                || request.branch_point() != branch
                || request.id()?.content_id() != *content
            {
                return Err(integrity("planner-scan-index-position-mismatch"));
            }
            let position = PlanningScanPosition::new(branch, request.id()?);
            let bytes = u64::try_from(request.canonical_bytes().len())
                .map_err(|_| integrity("planner-scan-index-input-byte-overflow"))?;
            if !positions.contains_key(&position) {
                self.charge_btree_entry::<PlanningScanPosition, u64>()?;
            }
            positions.insert(position, bytes);
            if positions.len() == limit {
                break;
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn read_branch_request(
        &mut self,
        id: BranchRequestId,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.decode_branch_request(id.content_id())?;
        self.validate_branch_request_references(&request, &mut ChoiceValidationCache::default())?;
        Ok(request)
    }
}
