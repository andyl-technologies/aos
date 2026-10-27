//! Planner scan and invocation lifecycle replay over explicit readers.

use super::*;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn validate_planner_cursor(
        &mut self,
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
        if self.merkle_get(
            current.snapshot.roots().exploration,
            map_key_content("exploration.branch-request", request_content),
        )? != Some(request_content)
        {
            return Err(integrity("planner-step-scan-cursor-is-not-authoritative"));
        }
        let request =
            self.read_branch_request(BranchRequestId::from_content_id(request_content)?)?;
        if request.branch_point() != after.branch_point() {
            return Err(integrity("planner-step-scan-cursor-branch-point-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_page(
        &mut self,
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

    pub(in crate::repository) fn validate_planner_invocation_start(
        &mut self,
        coordination: ContentId,
        invocation: &PlannerInvocation,
    ) -> Result<Option<PlannerStepId>, CampaignRepositoryError> {
        let parent = self
            .merkle_get(coordination, planner_head_key())?
            .map(PlannerStepId::from_content_id)
            .transpose()?;
        let Some(parent_id) = parent else {
            self.validate_planner_invocation_parent(None, invocation)?;
            return Ok(None);
        };

        let parent_step = self
            .read_planner_step_with_request(parent_id.content_id())?
            .0;
        self.validate_planner_invocation_parent(Some(&parent_step), invocation)?;
        Ok(Some(parent_id))
    }

    pub(in crate::repository) fn validate_planner_invocation_parent(
        &mut self,
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
            } else if CanonicalBeamPlanner::supports_descriptor(&engine)? {
                Some(CanonicalBeamPlanner::initial_state_for_engine(&engine)?)
            } else if crate::CanonicalSearchPlanner::supports_descriptor(&engine)? {
                Some(crate::CanonicalSearchPlanner::initial_state_for_engine(
                    &engine,
                )?)
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

    pub(in crate::repository) fn validate_planner_selected_source(
        &mut self,
        view: &CampaignPlanningView,
        disposition: &PlannerDisposition,
        proposed_requests: Option<&[BranchRequest]>,
    ) -> Result<(), CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let PlannerDisposition::Issue { selected, .. } = disposition else {
            return Ok(());
        };
        let content = selected.source().content_id();
        let authoritative = self.merkle_get(
            view.exploration(),
            map_key_content("exploration.branch-request", content),
        )? == Some(content);
        let selected_request = if authoritative {
            self.read_branch_request(BranchRequestId::from_content_id(content)?)?
        } else if let Some(request) = proposed_requests.and_then(|requests| {
            requests
                .iter()
                .find(|request| request.id().ok() == Some(selected.source()))
        }) {
            crate::codec::admitted_clone(request)?
        } else {
            self.read_branch_request(BranchRequestId::from_content_id(content)?)?
        };
        let newly_issued_statistical = !authoritative
            && disposition.issued_proposals().is_empty()
            && disposition
                .issued_branch_requests()
                .contains(&selected.source())
            && matches!(
                selected_request.source(),
                CandidateSource::StatisticalFinite(_) | CandidateSource::StatisticalSmc(_)
            );
        if (!authoritative && !newly_issued_statistical)
            || selected_request.branch_point() != selected.branch_point()
        {
            return Err(integrity(
                "planner-step-selected-source-is-not-authoritative",
            ));
        }
        Ok(())
    }
}
