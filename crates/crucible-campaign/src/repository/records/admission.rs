//! Attempt admission, paths, planner steps, and continuation records.

use super::*;

impl CampaignRepository {
    pub(in crate::repository) fn read_branch_path(
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

    pub(in crate::repository) fn validate_proposal_attempt_equivalence(
        &self,
        proposal: &Proposal,
        attempt: &Attempt,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.read_branch_request(proposal.request().content_id())?;
        self.validate_proposal_attempt_equivalence_with_request(proposal, attempt, &request)?;
        Ok(request)
    }

    fn validate_proposal_attempt_equivalence_with_request(
        &self,
        proposal: &Proposal,
        attempt: &Attempt,
        request: &BranchRequest,
    ) -> Result<(), CampaignRepositoryError> {
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
        Ok(())
    }

    pub(in crate::repository) fn read_attempt_admission(
        &self,
        id: ContentId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        self.read_attempt_admission_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(in crate::repository) fn read_attempt_admission_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let admission = self.decode_attempt_admission(id)?;
        let attempt = self.read_attempt_cached(admission.attempt().content_id(), cache)?;
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
                if !matches!(
                    attempt.start(),
                    AttemptStart::Discover { .. } | AttemptStart::AfterAttempt { .. }
                ) =>
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

    pub(in crate::repository) fn decode_attempt_admission(
        &self,
        id: ContentId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::AttemptAdmission)?;
        let admission = AttemptAdmission::from_canonical_bytes(envelope.body())?;
        if admission.id()?.content_id() != id {
            return Err(integrity("attempt-admission-envelope-shape"));
        }
        Ok(admission)
    }

    pub(in crate::repository) fn validate_attempt_admission_references_shallow_cached(
        &self,
        admission: &AttemptAdmission,
        cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let attempt = self.read_attempt_cached(admission.attempt().content_id(), cache)?;
        match admission.role() {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                cause,
                ..
            } => {
                let proposal = self.decode_proposal(proposal.content_id())?;
                let request = self.decode_branch_request(proposal.request().content_id())?;
                self.validate_proposal_attempt_equivalence_with_request(
                    &proposal, &attempt, &request,
                )?;
                if request.cause() != cause {
                    return Err(integrity("attempt-execution-basis-mismatch"));
                }
            }
            AttemptAdmissionRole::ExecutionBasis { proposal: None, .. }
                if !matches!(
                    attempt.start(),
                    AttemptStart::Discover { .. } | AttemptStart::AfterAttempt { .. }
                ) =>
            {
                return Err(integrity("branch-attempt-execution-basis-has-no-proposal"));
            }
            AttemptAdmissionRole::ExecutionBasis { .. } => {}
            AttemptAdmissionRole::AdditionalCause { proposal } => {
                let proposal = self.decode_proposal(proposal.content_id())?;
                let request = self.decode_branch_request(proposal.request().content_id())?;
                self.validate_proposal_attempt_equivalence_with_request(
                    &proposal, &attempt, &request,
                )?;
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn count_request_execution_bases(
        &self,
        accounting_root: ContentId,
        request: BranchRequestId,
    ) -> Result<u64, CampaignRepositoryError> {
        let mut after = None;
        let mut count = 0_u64;
        loop {
            let page = self.merkle.scan(accounting_root, after, 10_000)?;
            for (key, value) in page.entries() {
                if *key != map_key_content("accounting.attempt-admission", *value) {
                    continue;
                }
                let admission = self.decode_attempt_admission(*value)?;
                let AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                } = admission.role()
                else {
                    continue;
                };
                if self.decode_proposal(proposal.content_id())?.request() == request {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| integrity("request-attempt-count-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                return Ok(count);
            };
            after = Some(next);
        }
    }

    pub(in crate::repository) fn next_admission_ordinal(
        &self,
        accounting_root: ContentId,
    ) -> Result<AdmissionOrdinal, CampaignRepositoryError> {
        let Some(latest) = self.merkle.get(accounting_root, admission_sequence_key())? else {
            return Ok(AdmissionOrdinal::new(1));
        };
        let admission = self.decode_attempt_admission(latest)?;
        let AttemptAdmissionRole::ExecutionBasis {
            admission_ordinal, ..
        } = admission.role()
        else {
            return Err(integrity(
                "admission-sequence-does-not-name-execution-basis",
            ));
        };
        admission_ordinal
            .checked_next()
            .ok_or_else(|| integrity("admission-ordinal-overflow"))
    }

    pub(in crate::repository) fn expected_proposal_admission(
        &self,
        snapshot: &LoadedSnapshot,
        proposal: ProposalId,
        attempt: AttemptId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        self.expected_proposal_admission_at(
            snapshot,
            roots.exploration,
            roots.accounting,
            proposal,
            attempt,
        )
    }

    pub(in crate::repository) fn expected_proposal_admission_at(
        &self,
        snapshot: &LoadedSnapshot,
        exploration_root: ContentId,
        accounting_root: ContentId,
        proposal: ProposalId,
        attempt: AttemptId,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        let proposal_content = proposal.content_id();
        if self.merkle.get(
            exploration_root,
            map_key_content("exploration.proposal", proposal_content),
        )? != Some(proposal_content)
        {
            return Err(integrity("admission-proposal-is-not-authoritative"));
        }
        if self
            .merkle
            .get(
                accounting_root,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            .is_some()
        {
            return Err(integrity("proposal-already-has-admission"));
        }

        let proposal_record = self.read_proposal(proposal_content)?;
        let attempt_record = self.read_attempt(attempt.content_id())?;
        let request =
            self.validate_proposal_attempt_equivalence(&proposal_record, &attempt_record)?;
        let AttemptStart::Branch { edge, .. } = attempt_record.start() else {
            return Err(integrity("proposal-admission-attempt-is-discovery"));
        };
        let path = self.read_branch_path(attempt_record.path().content_id())?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        self.validate_attempt_path_owner(snapshot, &lineage, &request, &path, edge)?;
        let attempt_key = map_key_content("accounting.attempt", attempt.content_id());
        let basis_key = map_key_content("accounting.attempt-execution-basis", attempt.content_id());
        let indexed_attempt = self.merkle.get(accounting_root, attempt_key)?;
        let indexed_basis = self.merkle.get(accounting_root, basis_key)?;

        match (indexed_attempt, indexed_basis) {
            (None, None) => {
                if self.request_execution_bases_at(snapshot, proposal_record.request())?
                    >= request.budget().maximum_attempts()
                {
                    return Err(integrity("branch-request-attempt-budget-exhausted"));
                }
                Ok(AttemptAdmission::new(
                    attempt,
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        cause: request.cause(),
                        admission_ordinal: self.next_admission_ordinal(accounting_root)?,
                    },
                ))
            }
            (Some(indexed_attempt), Some(indexed_basis))
                if indexed_attempt == attempt.content_id() =>
            {
                let basis = self.read_attempt_admission(indexed_basis)?;
                if basis.attempt() != attempt
                    || !matches!(basis.role(), AttemptAdmissionRole::ExecutionBasis { .. })
                {
                    return Err(integrity("attempt-execution-basis-index-mismatch"));
                }
                Ok(AttemptAdmission::new(
                    attempt,
                    AttemptAdmissionRole::AdditionalCause { proposal },
                ))
            }
            _ => Err(integrity("attempt-admission-index-shape")),
        }
    }

    pub(in crate::repository) fn validate_attempt_path_owner(
        &self,
        snapshot: &LoadedSnapshot,
        lineage: &CampaignLineage,
        request: &BranchRequest,
        path: &BranchPath,
        edge: crate::BranchEdgeId,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(segments) = path.segments() else {
            if request.parent() == lineage.genesis_content() && path.edges() == [edge] {
                return Ok(());
            }
            return Err(integrity("proposal-admission-requires-scoped-branch-path"));
        };
        let Some((terminal, prefix)) = segments.split_last() else {
            return Err(integrity("proposal-admission-branch-path-is-empty"));
        };
        if *terminal != crate::BranchPathSegment::new(request.branch_point(), edge) {
            return Err(integrity(
                "proposal-admission-branch-path-terminal-scope-mismatch",
            ));
        }

        let prefix = BranchPath::new(prefix.to_vec())?;
        if request.parent() == lineage.genesis_content() {
            if !prefix.edges().is_empty() {
                return Err(integrity(
                    "proposal-admission-genesis-path-prefix-is-not-empty",
                ));
            }
            return Ok(());
        }

        let path_index = self
            .merkle
            .get(
                snapshot.snapshot.roots().observations,
                configuration_path_index_key(request.parent()),
            )?
            .ok_or_else(|| integrity("proposal-admission-parent-path-index-is-missing"))?;
        let prefix_id = prefix.id()?;
        if self
            .merkle
            .get(path_index, path_index_order_key(prefix_id))?
            != Some(prefix_id.content_id())
        {
            return Err(integrity(
                "proposal-admission-path-prefix-is-not-authoritative",
            ));
        }
        Ok(())
    }

    pub(in crate::repository) fn read_planner_step(
        &self,
        id: ContentId,
    ) -> Result<PlannerStep, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::PlannerStep)?;
        let step = PlannerStep::from_canonical_bytes(envelope.body())?;
        if step.id()?.content_id() != id {
            return Err(integrity("planner-step-envelope-shape"));
        }
        let request = self.read_planner_request(step.request().content_id())?;
        if request.invocation_id()? != step.invocation()
            || request.request_digest() != step.request_digest()
        {
            return Err(integrity("planner-step-request-mismatch"));
        }
        let invocation = self.load_planner_invocation(step.invocation())?;
        if invocation.engine() != step.engine()
            || invocation.policy_artifact() != step.policy_artifact()
            || invocation.policy() != step.policy()
            || invocation.input_view() != step.input_view()
        {
            return Err(integrity("planner-step-invocation-mismatch"));
        }
        self.validate_planner_disposition_page(&invocation, step.disposition())?;

        let next_state_envelope = self.require_record_kind(
            step.next_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let next_state = crate::codec::decode::<PlannerState>(next_state_envelope.body())?;
        if next_state.id()? != step.next_state() || next_state.engine() != step.engine() {
            return Err(integrity("planner-step-next-state-engine-mismatch"));
        }

        let accounting = step.accounting();
        let budget = invocation.budget();
        if accounting.branch_requests > u64::from(budget.branch_requests())
            || accounting.proposals > u64::from(budget.proposals())
            || accounting.input_objects != invocation.scan_page().input_objects()
            || accounting.input_bytes != invocation.scan_page().input_bytes()
            || accounting.input_objects > u64::from(budget.input_objects())
            || accounting.input_bytes > budget.input_bytes()
            || accounting.fuel > budget.fuel()
        {
            return Err(integrity("planner-step-invocation-budget-exceeded"));
        }
        let usage_claim = step.usage_claim();
        if usage_claim.branch_requests > u64::from(budget.branch_requests())
            || usage_claim.proposals > u64::from(budget.proposals())
            || usage_claim.input_objects > u64::from(budget.input_objects())
            || usage_claim.input_bytes > budget.input_bytes()
            || usage_claim.fuel > budget.fuel()
        {
            return Err(integrity("planner-step-usage-claim-exceeds-budget"));
        }

        if let Some(parent) = step.parent() {
            let parent_envelope = self
                .require_record_kind(parent.content_id(), crate::CampaignRecordKind::PlannerStep)?;
            let parent_step = PlannerStep::from_canonical_bytes(parent_envelope.body())?;
            if parent_step.id()? != parent || parent_step.next_state() != invocation.planner_state()
            {
                return Err(integrity("planner-step-parent-state-discontinuity"));
            }
        }
        Ok(step)
    }

    pub(in crate::repository) fn read_expansion_state(
        &self,
        id: ContentId,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ExpansionState)?;
        let state = ExpansionState::from_canonical_bytes(envelope.body())?;
        if state.id()?.content_id() != id {
            return Err(integrity("expansion-state-envelope-shape"));
        }
        let view_envelope = self.require_record_kind(
            state.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        let stored_view = crate::codec::decode::<CampaignPlanningView>(view_envelope.body())?;
        if stored_view.id()? != state.input_view() {
            return Err(integrity("expansion-state-planning-view-envelope-shape"));
        }
        for root in [
            state.request_root(),
            state.proposal_root(),
            state.admission_root(),
            state.observation_root(),
        ] {
            self.merkle.verify_closure_streaming(root)?;
        }
        self.validate_complete_head(state.source_snapshot().content_id())?;
        let expected = self.recompute_finite_expansion(
            state.source_snapshot(),
            state.branch_point(),
            state.page_after(),
            state.page_size(),
        )?;
        if state != expected {
            return Err(integrity("expansion-state-owner-recomputation-mismatch"));
        }
        Ok(state)
    }

    pub(crate) fn read_continuation_projection(
        &self,
        id: ContentId,
    ) -> Result<ContinuationProjection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::ContinuationProjection)?;
        let projection = ContinuationProjection::from_canonical_bytes(envelope.body())?;
        if projection.id()?.content_id() != id {
            return Err(integrity("continuation-projection-envelope-shape"));
        }
        let request = self.read_branch_request(projection.request().content_id())?;
        if request.id()? != projection.request()
            || request.branch_point() != projection.branch_point()
        {
            return Err(integrity("continuation-projection-request-mismatch"));
        }
        Ok(projection)
    }

    pub(in crate::repository) fn read_expansion_credit(
        &self,
        id: ContentId,
    ) -> Result<ExpansionCredit, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ExpansionCredit)?;
        let credit = ExpansionCredit::from_canonical_bytes(envelope.body())?;
        if credit.content_id()? != id {
            return Err(integrity("expansion-credit-envelope-shape"));
        }
        self.decode_observation(credit.observation().content_id())?;
        Ok(credit)
    }
}
