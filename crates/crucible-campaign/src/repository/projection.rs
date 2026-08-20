//! Owner-recomputed, snapshot-bound campaign projection pages.

use super::*;
use crate::ChoiceValue;

const PROJECTION_SCAN_PAGE_ITEMS: usize = 10_000;

struct FiniteExpansionInputs {
    requests: ContentId,
    proposals: ContentId,
    admissions: ContentId,
    admitted_children: u64,
}

impl CampaignRepository {
    pub(super) fn initial_continuation_state(
        &self,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        Ok(
            if self.static_candidate_count(request, &domain)?.is_some() {
                crate::ContinuationState::Ready
            } else {
                crate::ContinuationState::Open
            },
        )
    }

    /// Resolves the exact cardinality of a history-independent source.
    ///
    /// `None` means that the source requires a generator owner with cursor or
    /// feedback semantics that this repository checkpoint does not implement.
    pub(super) fn static_candidate_count(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<Option<u64>, CampaignRepositoryError> {
        if let Some(values) = request.source().finite_values() {
            return u64::try_from(values.len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow"));
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        if spec.implementation_version() != crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION {
            return Ok(None);
        }
        match (spec.algorithm(), domain) {
            (CandidateGeneratorAlgorithm::All, ChoiceDomain::Boolean(_)) => Ok(Some(2)),
            (CandidateGeneratorAlgorithm::All, ChoiceDomain::Discrete(discrete)) => {
                u64::try_from(discrete.alternatives().len())
                    .map(Some)
                    .map_err(|_| integrity("candidate-source-cardinality-overflow"))
            }
            (CandidateGeneratorAlgorithm::All, ChoiceDomain::Integer(_)) => {
                Err(integrity("candidate-generator-domain-family-mismatch"))
            }
            _ => Ok(None),
        }
    }

    /// Resolves one one-based candidate ordinal from a history-independent source.
    pub(super) fn static_candidate_at(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        if ordinal == 0 {
            return Err(integrity("proposal-ordinal-is-not-canonical"));
        }
        let index = usize::try_from(ordinal - 1)
            .map_err(|_| integrity("proposal-ordinal-is-not-canonical"))?;
        if let Some(values) = request.source().finite_values() {
            return values
                .iter()
                .nth(index)
                .cloned()
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality"));
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        if spec.implementation_version() != crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION {
            return Ok(None);
        }
        match (spec.algorithm(), domain) {
            (CandidateGeneratorAlgorithm::All, ChoiceDomain::Boolean(_)) => match index {
                0 => Ok(Some(ChoiceValue::Boolean(false))),
                1 => Ok(Some(ChoiceValue::Boolean(true))),
                _ => Err(integrity("proposal-ordinal-exceeds-source-cardinality")),
            },
            (CandidateGeneratorAlgorithm::All, ChoiceDomain::Discrete(discrete)) => discrete
                .alternatives()
                .keys()
                .nth(index)
                .copied()
                .map(ChoiceValue::Discrete)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (CandidateGeneratorAlgorithm::All, ChoiceDomain::Integer(_)) => {
                Err(integrity("candidate-generator-domain-family-mismatch"))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn frontier_index_after(
        &self,
        exploration_root: ContentId,
        projections: &[(
            BranchRequestId,
            crate::BranchPointId,
            crate::ContinuationState,
        )],
        publish: bool,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let Some(frontier_index) = self
            .merkle
            .get(exploration_root, frontier_index_anchor_key())?
        else {
            return Ok(None);
        };
        let mut upserts = BTreeMap::new();
        for (request, branch_point, state) in projections {
            let projection = ContinuationProjection::new(*request, *branch_point, *state);
            let projection_id = projection.id()?;
            if publish {
                let content = self.put_continuation_projection(&projection)?;
                if content != projection_id.content_id() {
                    return Err(integrity("continuation-projection-publication-id-mismatch"));
                }
            }
            upserts.insert(
                frontier_index_order_key(*request),
                projection_id.content_id(),
            );
        }
        if publish {
            let mut root = frontier_index;
            for (key, value) in upserts {
                root = self.merkle.insert(root, key, value)?.content_id();
            }
            Ok(Some(root))
        } else {
            self.merkle
                .root_after_upserts(frontier_index, &upserts)
                .map(Some)
                .map_err(Into::into)
        }
    }

    pub(super) fn validate_frontier_projection(
        &self,
        frontier_index: ContentId,
        request: BranchRequestId,
        branch_point: crate::BranchPointId,
        state: crate::ContinuationState,
    ) -> Result<(), CampaignRepositoryError> {
        let content = self
            .merkle
            .get(frontier_index, frontier_index_order_key(request))?
            .ok_or_else(|| integrity("frontier-index-request-is-missing"))?;
        let projection = self.read_continuation_projection(content)?;
        if projection != ContinuationProjection::new(request, branch_point, state) {
            return Err(integrity("frontier-index-projection-mismatch"));
        }
        Ok(())
    }

    /// Projects and publishes one bounded static-continuation page.
    ///
    /// The page is derived from one authenticated historical or current
    /// snapshot. Its cursor is meaningful only for that immutable snapshot and
    /// branch point. Implementation-version 2 `all` generators over Boolean and discrete
    /// domains share the finite-source path. History-dependent generators and
    /// observation-bearing views remain fail-closed until their semantic owners
    /// are implemented.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid snapshot closure, fabricated or
    /// cross-branch cursor, invalid page size, unsupported generated request or
    /// observation input, inconsistent proposal/admission indexes, or store
    /// failure.
    pub fn project_finite_expansion(
        &self,
        source_snapshot: CampaignSnapshotId,
        branch_point: crate::BranchPointId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<ExpansionStateId, CampaignRepositoryError> {
        self.validate_complete_head(source_snapshot.content_id())?;
        let state =
            self.recompute_finite_expansion(source_snapshot, branch_point, page_after, page_size)?;
        let state_id = state.id()?;
        let content = self.put_expansion_state(&state)?;
        if content != state_id.content_id() {
            return Err(integrity("expansion-state-publication-id-mismatch"));
        }
        self.read_expansion_state(content)?;
        Ok(state_id)
    }

    pub(super) fn recompute_finite_expansion(
        &self,
        source_snapshot: CampaignSnapshotId,
        branch_point: crate::BranchPointId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let loaded = self.read_snapshot(source_snapshot.content_id())?;
        let view = loaded.snapshot.planning_view();
        let view_id = view.id()?;
        let view_content = self.put_planning_view(&view)?;
        if view_content != view_id.content_id() {
            return Err(integrity("expansion-state-planning-view-id-mismatch"));
        }
        if self
            .merkle
            .inspect_shallow(view.observations())?
            .entry_count()
            != 0
        {
            return Err(integrity(
                "finite-expansion-observation-owner-is-not-implemented",
            ));
        }

        let inputs = self.derive_finite_expansion_inputs(&view, branch_point)?;
        let (continuations, next_after) = self.finite_continuation_page(
            view.exploration(),
            view.accounting(),
            inputs.requests,
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
        &self,
        view: &CampaignPlanningView,
        branch_point: crate::BranchPointId,
    ) -> Result<FiniteExpansionInputs, CampaignRepositoryError> {
        let mut requests = self.merkle.empty()?.content_id();
        let mut proposals = self.merkle.empty()?.content_id();
        let mut admissions = self.merkle.empty()?.content_id();

        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(view.exploration(), after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                if *key == map_key_content("exploration.branch-request", *value) {
                    let request = self.read_branch_request(*value)?;
                    if request.branch_point() == branch_point {
                        let domain = self.read_choice_domain(request.domain().content_id())?;
                        if self.static_candidate_count(&request, &domain)?.is_none() {
                            return Err(integrity(
                                "generated-expansion-projector-is-not-implemented",
                            ));
                        }
                        requests = self
                            .merkle
                            .insert(requests, projection_order_key(*value), *value)?
                            .content_id();
                    }
                } else if *key == map_key_content("exploration.proposal", *value) {
                    let proposal = self.read_proposal(*value)?;
                    if proposal.branch_point() == branch_point {
                        proposals = self
                            .merkle
                            .insert(proposals, projection_order_key(*value), *value)?
                            .content_id();
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
            let page = self
                .merkle
                .scan(view.accounting(), after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
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
                admissions = self
                    .merkle
                    .insert(admissions, projection_order_key(*value), *value)?
                    .content_id();
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

        Ok(FiniteExpansionInputs {
            requests,
            proposals,
            admissions,
            admitted_children,
        })
    }

    fn finite_continuation_page(
        &self,
        exploration_root: ContentId,
        accounting_root: ContentId,
        request_root: ContentId,
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
        let after_key = page_after.map(|request| projection_order_key(request.content_id()));
        if let Some(request) = page_after
            && self
                .merkle
                .get(request_root, projection_order_key(request.content_id()))?
                != Some(request.content_id())
        {
            return Err(integrity("expansion-page-cursor-is-not-in-request-root"));
        }

        let page = self.merkle.scan(request_root, after_key, limit)?;
        let mut continuations = BTreeMap::new();
        for (key, value) in page.entries() {
            if *key != projection_order_key(*value) {
                return Err(integrity("expansion-request-order-index-mismatch"));
            }
            let request_id = BranchRequestId::from_content_id(*value)?;
            let request = self.read_branch_request(*value)?;
            let state =
                self.continuation_state(exploration_root, accounting_root, request_id, &request)?;
            continuations.insert(request_id, state);
        }
        let next_after = if page.next_after().is_some() {
            continuations.last_key_value().map(|entry| *entry.0)
        } else {
            None
        };
        Ok((continuations, next_after))
    }

    pub(super) fn continuation_state(
        &self,
        exploration_root: ContentId,
        accounting_root: ContentId,
        request_id: BranchRequestId,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let value_count = self
            .static_candidate_count(request, &domain)?
            .ok_or_else(|| integrity("generated-expansion-projector-is-not-implemented"))?;
        let maximum_proposals = request.budget().maximum_proposals();
        let check_count = value_count.min(maximum_proposals);
        let mut proposed = 0_u64;
        let mut pending = false;

        for ordinal in 1..=check_count {
            let Some(proposal_content) = self
                .merkle
                .get(exploration_root, proposal_ordinal_key(request_id, ordinal))?
            else {
                break;
            };
            let proposal = self.read_proposal(proposal_content)?;
            if proposal.request() != request_id
                || proposal.ordinal() != ordinal
                || self.merkle.get(
                    exploration_root,
                    map_key_content("exploration.proposal", proposal_content),
                )? != Some(proposal_content)
            {
                return Err(integrity("finite-expansion-proposal-index-mismatch"));
            }
            proposed = ordinal;

            let Some(admission_content) = self.merkle.get(
                accounting_root,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            else {
                pending = true;
                continue;
            };
            if self.merkle.get(
                accounting_root,
                map_key_content("accounting.attempt-admission", admission_content),
            )? != Some(admission_content)
            {
                return Err(integrity("finite-expansion-admission-index-mismatch"));
            }
            let admission = self.read_attempt_admission(admission_content)?;
            let admitted_proposal = match admission.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                }
                | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                    return Err(integrity("finite-expansion-discovery-admission"));
                }
            };
            if admitted_proposal.content_id() != proposal_content {
                return Err(integrity("finite-expansion-proposal-admission-mismatch"));
            }
        }

        if pending {
            Ok(crate::ContinuationState::Open)
        } else if proposed == value_count {
            Ok(crate::ContinuationState::Exhausted)
        } else if proposed >= maximum_proposals {
            Ok(crate::ContinuationState::Closed)
        } else {
            Ok(crate::ContinuationState::Ready)
        }
    }

    pub(super) fn put_expansion_state(
        &self,
        state: &ExpansionState,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ExpansionState,
            crate::object::content_children(state.content_children())?,
            state.canonical_bytes(),
        )?)
    }
}

fn projection_order_key(id: ContentId) -> CampaignHash {
    CampaignHash::from_bytes(id.digest())
}
