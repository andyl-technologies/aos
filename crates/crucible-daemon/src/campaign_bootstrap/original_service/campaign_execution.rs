//! Drives an explicit campaign through the same prepared service and factory.
//!
//! The coordinator's fixed body is reserved before Box or planner publication.
//! It retains the actual drivers and last command until semantic drainage;
//! alias or original refusal retains that body and its same-budget custody.
//! Campaign commands use the existing principal authorizer, never repository
//! control bypasses. This module does not certify native or actor retirement.

use super::*;
use crate::packaged_qemu_executor::original_campaign::{
    OriginalCampaignExecutorError, OriginalCampaignExecutorService,
};
use crate::qemu_campaign_lifecycle::{
    ConfiguredCampaignPlannerError, LocalCampaignPlannerKind, LocalCampaignPlannerService,
    LocalCampaignPlannerServiceError, configured_campaign_planner,
};
use crucible::owned_decode::json_profiles::workflow::{
    CampaignExecution, CampaignExecutionPlanner, CampaignExecutionRetention,
    CampaignExecutionSearch,
};
use crucible_campaign::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, CampaignCommandId,
    CampaignControlAction, CampaignHash, CampaignPlannerStepOutcome, CampaignSupervisor,
    CampaignSupervisorConfigError, CampaignSupervisorError, CampaignSupervisorStepOutcome,
    CanonicalSearchStrategy, ControlRequest, CreateCampaignRequest, ExecutionRetentionIntent,
    ExplorerPolicy, PlannerDisposition, PlanningBudget,
};

type ActualCoordinator =
    CampaignSupervisor<LocalCampaignPlannerService, OriginalCampaignExecutorService>;
type ActualCoordinatorFailure = CampaignSupervisorError<
    LocalCampaignPlannerServiceError,
    crate::LocalExecutorPoolServiceError<crate::AssignmentLedgerError>,
>;

/// Preserves actual coordinator construction, planning and execution refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OriginalCampaignCoordinatorError {
    /// The required planner family differs from the actual campaign policy.
    #[error("required planner family differs from campaign policy")]
    Policy,
    /// The retained service or coordinator is unavailable or already entered.
    #[error("original campaign coordinator custody is unavailable")]
    Custody,
    /// Actual canonical planner attachment refused.
    #[error("original campaign planner refused: {0}")]
    Planner(#[from] ConfiguredCampaignPlannerError),
    /// The already-owned executor refused attachment.
    #[error("original campaign executor refused: {0}")]
    Executor(#[from] OriginalCampaignExecutorError),
    /// Actual shared repository or slot bounds refused.
    #[error("original campaign supervisor refused: {0}")]
    Configuration(#[from] CampaignSupervisorConfigError),
    /// The actual repository refused head observation.
    #[error("original campaign head refused: {0}")]
    Repository(#[from] crucible_campaign::CampaignRepositoryError),
    /// The actual driver transition returned its typed cause.
    #[error("original campaign transition refused: {0}")]
    Transition(#[from] ActualCoordinatorFailure),
    /// Original semantically granted work cannot settle under the current grant.
    #[error("campaign planning remains blocked by the explicit semantic grant")]
    BudgetBlocked,
}

/// Retains the paid fixed coordinator body outside its own credit receipt.
pub(crate) struct OriginalCampaignCoordinator {
    body: Option<Box<CoordinatorBody>>,
    credit: Option<DecodeScratch>,
    custody: Option<DecodeCustody>,
}

struct CoordinatorBody {
    supervisor: Option<ActualCoordinator>,
    command: Option<ApplyCampaignCommandRequest>,
    response: Option<ApplyCampaignCommandResponse>,
    complete: bool,
}

impl OriginalCampaignCoordinator {
    /// Reserves the exact target body before allocation or campaign effects.
    ///
    /// # Errors
    /// Refuses the same original budget before a coordinator can be born.
    pub(crate) fn prepare(budget: &DecodeBudget) -> Result<Self, DecodeAdmissionError> {
        let credit = budget.reserve_scratch_array::<CoordinatorBody>(1)?;
        Ok(Self {
            body: Some(Box::new(CoordinatorBody {
                supervisor: None,
                command: None,
                response: None,
                complete: false,
            })),
            credit: Some(credit),
            custody: Some(budget.custody()),
        })
    }

    /// Executes explicit grant, resume and semantic completion against one head.
    ///
    /// # Errors
    /// Retains the actual coordinator and command on typed service, driver,
    /// original or grant refusal. A native prebirth refusal remains an error.
    pub(crate) fn execute(
        &mut self,
        service: &OriginalPreparedCampaignServiceOwner,
        executor: &crate::private_measurement_runtime::OriginalPreparedPackagedExecutor<'_>,
        creation: &CreateCampaignRequest,
        input: CampaignExecution,
        budget: &DecodeBudget,
    ) -> Result<(), OriginalPreparedServiceError> {
        service.artifact_operation(|actual| {
            let body = self
                .body
                .as_mut()
                .ok_or(OriginalCampaignCoordinatorError::Custody)?;
            if body.supervisor.is_some() || body.command.is_some() || body.complete {
                return Err(OriginalCampaignCoordinatorError::Custody.into());
            }
            validate_policy(creation, input.planner)?;
            let grant =
                crucible_campaign::BudgetGrant::new(input.grant.proposals, input.grant.attempts)?;
            apply_command(
                body,
                actual,
                creation,
                CampaignControlAction::GrantBudget(grant),
                0,
                budget,
            )?;
            service.original.verify()?;
            apply_command(
                body,
                actual,
                creation,
                CampaignControlAction::Resume,
                1,
                budget,
            )?;
            service.original.verify()?;
            body.supervisor = Some(prepare_coordinator(
                actual, executor, creation, input, budget,
            )?);
            loop {
                service.original.verify()?;
                budget.verify_live()?;
                let supervisor = body
                    .supervisor
                    .as_mut()
                    .ok_or(OriginalCampaignCoordinatorError::Custody)?;
                let outcome = supervisor
                    .step()
                    .map_err(OriginalCampaignCoordinatorError::from)?;
                // Publish driver state before this independent boundary. A
                // late refusal retains the real reservation and service alias.
                service.original.verify()?;
                budget.verify_live()?;
                let terminal = matches!(
                    outcome,
                    CampaignSupervisorStepOutcome::Planner(CampaignPlannerStepOutcome::Advanced {
                        disposition: PlannerDisposition::NoWork,
                        ..
                    }) | CampaignSupervisorStepOutcome::Planner(
                        CampaignPlannerStepOutcome::Settled {
                            disposition: PlannerDisposition::NoWork,
                            ..
                        }
                    )
                );
                if matches!(
                    outcome,
                    CampaignSupervisorStepOutcome::Planner(
                        CampaignPlannerStepOutcome::BudgetBlocked { .. }
                    )
                ) {
                    return Err(OriginalCampaignCoordinatorError::BudgetBlocked.into());
                }
                if terminal && supervisor.reservation_count() == 0 {
                    break;
                }
                executor.wait_for_campaign_progress()?;
            }
            apply_command(
                body,
                actual,
                creation,
                CampaignControlAction::Complete,
                2,
                budget,
            )?;
            service.original.verify()?;
            body.complete = true;
            drop(body.supervisor.take());
            Ok(())
        })
    }

    /// Frees a semantically drained body before releasing its original credit.
    ///
    /// # Errors
    /// Refuses a still-active coordinator; uncertainty retains all three owners.
    pub(crate) fn try_close(&mut self) -> Result<(), OriginalCampaignCoordinatorError> {
        if self
            .body
            .as_ref()
            .is_some_and(|body| !body.complete || body.supervisor.is_some())
        {
            return Err(OriginalCampaignCoordinatorError::Custody);
        }
        drop(self.body.take());
        drop(self.credit.take());
        drop(self.custody.take());
        Ok(())
    }
}

impl Drop for OriginalCampaignCoordinator {
    fn drop(&mut self) {
        if self.body.is_some() {
            std::mem::forget(self.body.take());
            std::mem::forget(self.credit.take());
            std::mem::forget(self.custody.take());
        }
    }
}

fn apply_command(
    body: &mut CoordinatorBody,
    actual: &PreparedCampaignLocalService,
    creation: &CreateCampaignRequest,
    action: CampaignControlAction,
    ordinal: u8,
    budget: &DecodeBudget,
) -> Result<(), PreparedCause> {
    budget.verify_live()?;
    let _scope = budget.enter();
    // Both exact clone extents are admitted before owning request birth.
    budget.charge_bytes(creation.principal().as_str().len() as u64)?;
    budget.charge_bytes(creation.campaign().as_str().len() as u64)?;
    let head = actual
        .repository
        .head(creation.campaign().as_str())
        .map_err(OriginalCampaignCoordinatorError::from)?;
    let mut identity = [0_u8; 33];
    identity[..32].copy_from_slice(&creation.request_digest().as_bytes());
    identity[32] = ordinal;
    body.command = Some(ApplyCampaignCommandRequest::new(
        creation.principal().clone(),
        creation.campaign().clone(),
        ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "crucible.original-campaign-command.v1",
                &identity,
            )),
            expected_snapshot: head.snapshot_id(),
            action,
        },
    )?);
    body.response = None;
    let command = body
        .command
        .as_ref()
        .ok_or(OriginalCampaignCoordinatorError::Custody)?;
    let response = artifacts::apply_authorized_command(actual, command)?;
    body.response = Some(response);
    Ok(())
}

fn validate_policy(
    creation: &CreateCampaignRequest,
    planner: CampaignExecutionPlanner,
) -> Result<(), OriginalCampaignCoordinatorError> {
    if matches!(
        (planner, creation.policy().explorer()),
        (
            CampaignExecutionPlanner::Exhaustive { .. },
            ExplorerPolicy::Exhaustive { .. }
        ) | (
            CampaignExecutionPlanner::TreeSearch,
            ExplorerPolicy::TreeSearch { .. }
        ) | (CampaignExecutionPlanner::Beam, ExplorerPolicy::Beam { .. })
    ) {
        Ok(())
    } else {
        Err(OriginalCampaignCoordinatorError::Policy)
    }
}

fn prepare_coordinator(
    service: &PreparedCampaignLocalService,
    executor: &crate::private_measurement_runtime::OriginalPreparedPackagedExecutor<'_>,
    creation: &CreateCampaignRequest,
    input: CampaignExecution,
    allocation_budget: &DecodeBudget,
) -> Result<ActualCoordinator, PreparedCause> {
    let authority = service
        .planner_authority
        .as_ref()
        .ok_or(OriginalCampaignCoordinatorError::Custody)?;
    let kind = match input.planner {
        CampaignExecutionPlanner::Exhaustive { search } => {
            LocalCampaignPlannerKind::Search(match search {
                CampaignExecutionSearch::BreadthFirst => CanonicalSearchStrategy::BreadthFirst,
                CampaignExecutionSearch::DepthFirst => CanonicalSearchStrategy::DepthFirst,
                CampaignExecutionSearch::Priority { seed } => {
                    CanonicalSearchStrategy::Priority { seed }
                }
            })
        }
        CampaignExecutionPlanner::TreeSearch => LocalCampaignPlannerKind::Puct,
        CampaignExecutionPlanner::Beam => LocalCampaignPlannerKind::Beam,
    };
    let limits = input.planning_budget;
    let budget = PlanningBudget::new(
        limits.branch_requests,
        limits.proposals,
        limits.input_objects,
        limits.input_bytes,
        limits.fuel,
    )?;
    let planner = configured_campaign_planner(
        &service.repository,
        authority.clone(),
        kind,
        input.planner_scan_limit,
        budget,
    )
    .map_err(OriginalCampaignCoordinatorError::from)?;
    let retention = match input.retention {
        CampaignExecutionRetention::Discard => ExecutionRetentionIntent::Discard,
        CampaignExecutionRetention::RetainOnFailure => ExecutionRetentionIntent::RetainOnFailure,
        CampaignExecutionRetention::RetainAlways => ExecutionRetentionIntent::RetainAlways,
    };
    let (driver, slots) = executor
        .prepare_campaign_driver(&service.repository, retention, input.executor_scan_limit)
        .map_err(OriginalCampaignCoordinatorError::from)?;
    allocation_budget.charge_bytes(creation.campaign().as_str().len() as u64)?;
    Ok(CampaignSupervisor::new(
        Arc::clone(&service.repository),
        creation.campaign().clone(),
        planner,
        driver,
        slots,
    )
    .map_err(OriginalCampaignCoordinatorError::from)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_measurement_runtime::catalog::tests::fixture;

    #[test]
    fn original_coordinator_body_and_custody_prevent_parent_close_until_free() {
        let (_original, decoder, catalog) = fixture();
        let mut coordinator =
            OriginalCampaignCoordinator::prepare(decoder.budget().expect("budget"))
                .expect("paid body");
        catalog.try_close().expect("fixture catalog close");
        assert!(coordinator.try_close().is_err());
        assert!(coordinator.body.is_some());
        assert!(coordinator.credit.is_some());
        // Consuming fixture close refusal stays terminal; no retry is donated.
        let retained = match decoder.try_close() {
            Ok(()) => panic!("actual coordinator custody permitted decoder close"),
            Err(retained) => retained,
        };
        drop(retained);
        // This empty fixture never installed a driver or executed semantic work.
        coordinator.body.as_mut().expect("same body").complete = true;
        coordinator.try_close().expect("actual body before receipt");
    }

    #[test]
    fn original_coordinator_fresh_empty_body_frees_before_first_parent_close() {
        let (_original, decoder, catalog) = fixture();
        let mut coordinator =
            OriginalCampaignCoordinator::prepare(decoder.budget().expect("budget"))
                .expect("paid body");
        coordinator
            .body
            .as_mut()
            .expect("empty fixture body")
            .complete = true;
        coordinator.try_close().expect("body before same receipt");
        catalog.try_close().expect("fixture catalog close");
        assert!(decoder.try_close().is_ok());
        eprintln!(
            "original coordinator target body={}",
            std::mem::size_of::<CoordinatorBody>()
        );
    }

    #[test]
    fn original_coordinator_canceled_credit_refuses_before_box_birth() {
        let (original, decoder, catalog) = fixture();
        let budget = decoder.budget().expect("saved original budget").clone();
        original.cancel().expect("cancel actual original");
        assert!(OriginalCampaignCoordinator::prepare(&budget).is_err());
        drop(budget);
        drop(catalog);
        drop(decoder);
    }
}
