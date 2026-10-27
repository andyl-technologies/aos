//! Checked owner replay for retained finite-expansion state.

use std::ops::Bound::{Excluded, Unbounded};

use super::*;

struct CheckedFiniteExpansionInputs {
    requests: ContentId,
    proposals: ContentId,
    admissions: ContentId,
    request_entries: BTreeMap<CampaignHash, ContentId>,
    admitted_children: u64,
}

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn read_expansion_state(
        &mut self,
        id: ContentId,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ExpansionState)?;
        let state = ExpansionState::from_canonical_bytes(envelope.body())?;
        let state_id = state.id()?;
        self.poll()?;
        if state_id.content_id() != id {
            return Err(integrity("expansion-state-envelope-shape"));
        }
        let view_envelope = self.require_record_kind(
            state.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        let stored_view = crate::codec::decode::<CampaignPlanningView>(view_envelope.body())?;
        let stored_view_id = stored_view.id()?;
        self.poll()?;
        if stored_view_id != state.input_view() {
            return Err(integrity("expansion-state-planning-view-envelope-shape"));
        }
        for root in [
            state.request_root(),
            state.proposal_root(),
            state.admission_root(),
            state.observation_root(),
        ] {
            self.verify_merkle_closure(root)?;
        }
        self.validate_complete_head(state.source_snapshot().content_id())?;
        let expected = self.recompute_finite_expansion(
            state.source_snapshot(),
            state.branch_point(),
            state.page_after(),
            state.page_size(),
        )?;
        self.poll()?;
        if state != expected {
            return Err(integrity("expansion-state-owner-recomputation-mismatch"));
        }
        Ok(state)
    }

    fn recompute_finite_expansion(
        &mut self,
        source_snapshot: CampaignSnapshotId,
        branch_point: crate::BranchPointId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let loaded = self.read_snapshot(source_snapshot.content_id())?;
        let view = loaded.snapshot.planning_view();
        let view_id = view.id()?;
        self.poll()?;
        let inputs = self.derive_finite_expansion_inputs(&view, branch_point)?;
        let request_admissions = self.parent_budget_ledger(&loaded)?.request_admissions();
        let (continuations, next_after) = self.finite_continuation_page(
            loaded.snapshot.roots(),
            request_admissions,
            &inputs.request_entries,
            page_after,
            page_size,
        )?;
        ExpansionState::new(
            source_snapshot,
            view_id,
            branch_point,
            inputs.requests,
            inputs.proposals,
            inputs.admissions,
            view.observations(),
            crate::ExpansionStatistics {
                admitted_children: inputs.admitted_children,
                completed_visits: self
                    .branch_completed_visits(view.observations(), branch_point)?,
                ..crate::ExpansionStatistics::default()
            },
            page_after,
            page_size,
            next_after,
            continuations,
        )
        .map_err(Into::into)
    }

    fn derive_finite_expansion_inputs(
        &mut self,
        view: &CampaignPlanningView,
        branch_point: crate::BranchPointId,
    ) -> Result<CheckedFiniteExpansionInputs, CampaignRepositoryError> {
        let mut request_entries = BTreeMap::new();
        let mut proposal_entries = BTreeMap::new();
        let mut admission_entries = BTreeMap::new();

        let mut after = None;
        loop {
            let page = self.merkle_scan(
                view.exploration(),
                after,
                crate::repository::projection::PROJECTION_SCAN_PAGE_ITEMS,
            )?;
            for (key, value) in page.entries() {
                self.poll()?;
                if *key == map_key_content("exploration.branch-request", *value) {
                    let request =
                        self.read_branch_request(BranchRequestId::from_content_id(*value)?)?;
                    if request.branch_point() == branch_point {
                        let domain = self.read_choice_domain(request.domain().content_id())?;
                        if self.candidate_source_profile(&request, &domain)?.is_none() {
                            return Err(integrity(
                                "generated-expansion-projector-is-not-implemented",
                            ));
                        }
                        self.insert_map(
                            &mut request_entries,
                            crate::repository::projection::projection_order_key(*value),
                            *value,
                        )?;
                    }
                } else if *key == map_key_content("exploration.proposal", *value) {
                    let proposal = self.read_proposal(*value)?;
                    if proposal.branch_point() == branch_point {
                        self.insert_map(
                            &mut proposal_entries,
                            crate::repository::projection::projection_order_key(*value),
                            *value,
                        )?;
                    }
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }

        let mut admitted_children = 0_u64;
        after = None;
        loop {
            let page = self.merkle_scan(
                view.accounting(),
                after,
                crate::repository::projection::PROJECTION_SCAN_PAGE_ITEMS,
            )?;
            for (key, value) in page.entries() {
                self.poll()?;
                if *key != map_key_content("accounting.attempt-admission", *value) {
                    continue;
                }
                let admission = self.read_attempt_admission(*value)?;
                let (proposal, is_execution_basis) = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    } => (proposal, true),
                    AttemptAdmissionRole::AdditionalCause { proposal } => (proposal, false),
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => continue,
                };
                if self.read_proposal(proposal.content_id())?.branch_point() != branch_point {
                    continue;
                }
                self.insert_map(
                    &mut admission_entries,
                    crate::repository::projection::projection_order_key(*value),
                    *value,
                )?;
                if is_execution_basis {
                    admitted_children = admitted_children
                        .checked_add(1)
                        .ok_or_else(|| integrity("expansion-admitted-child-count-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }

        let empty = MerkleMap::empty_content_id()?;
        Ok(CheckedFiniteExpansionInputs {
            requests: self.merkle_root_after_upserts(empty, &request_entries)?,
            proposals: self.merkle_root_after_upserts(empty, &proposal_entries)?,
            admissions: self.merkle_root_after_upserts(empty, &admission_entries)?,
            request_entries,
            admitted_children,
        })
    }

    fn finite_continuation_page(
        &mut self,
        roots: crate::CampaignRoots,
        request_admissions: ContentId,
        request_entries: &BTreeMap<CampaignHash, ContentId>,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<
        (
            BTreeMap<BranchRequestId, crate::ContinuationState>,
            Option<BranchRequestId>,
        ),
        CampaignRepositoryError,
    > {
        let limit =
            usize::try_from(page_size).map_err(|_| integrity("expansion-page-size-is-invalid"))?;
        let after_key = page_after.map(|request| {
            crate::repository::projection::projection_order_key(request.content_id())
        });
        if let Some(request) = page_after
            && request_entries.get(&crate::repository::projection::projection_order_key(
                request.content_id(),
            )) != Some(&request.content_id())
        {
            return Err(integrity("expansion-page-cursor-is-not-in-request-root"));
        }
        if limit == 0 || limit > crate::repository::projection::PROJECTION_SCAN_PAGE_ITEMS {
            return Err(crate::CampaignStoreError::InvalidPageSize.into());
        }

        let mut entries = match after_key {
            Some(after) => request_entries.range((Excluded(after), Unbounded)),
            None => request_entries.range::<CampaignHash, _>(..),
        };
        let mut continuations = BTreeMap::new();
        for _ in 0..limit {
            self.poll()?;
            let Some((key, value)) = entries.next() else {
                break;
            };
            if *key != crate::repository::projection::projection_order_key(*value) {
                return Err(integrity("expansion-request-order-index-mismatch"));
            }
            let request_id = BranchRequestId::from_content_id(*value)?;
            let request = self.read_branch_request(request_id)?;
            let state =
                self.continuation_state_indexed(roots, request_admissions, request_id, &request)?;
            self.insert_map(&mut continuations, request_id, state)?;
        }
        let next_after = if entries.next().is_some() {
            continuations.last_key_value().map(|entry| *entry.0)
        } else {
            None
        };
        Ok((continuations, next_after))
    }
}
