//! Prepays the shared three-row planner on the actual current-C Root purpose.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ObjectDigest, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2;

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootExecutionNoApplyStageReceivingV2};
use crate::policy_compiler::continuation_policy::RootExecutionNoApplyPolicyOriginalV2;
use crate::policy_compiler::provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1;
use aos_sandbox_protocol::domain_ledger::create_failure::ClosedCreateFailurePlanDataV2;

use super::RootExecutionNoApplyModelsErrorV2;

/// Keeps funding, original causes and exact planned rows in one finite owner.
pub(crate) struct RootExecutionNoApplyModelsOriginalV2 {
    geometry: Option<Result<ResourceVector, RootExecutionNoApplyModelsErrorV2>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    plan: Option<Result<ClosedCreateFailurePlanDataV2, RootExecutionNoApplyModelsErrorV2>>,
    reentry: Option<JournalError>,
}

impl RootExecutionNoApplyModelsOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            plan: None,
            reentry: None,
        }
    }

    /// Pays actual complete model geometry before the existing reducer executes.
    ///
    /// # Errors
    /// Rejects repeat entry, failed native-reader/policy access, unpaid model
    /// reception or a noncanonical accepted Create/Requested row relation.
    pub(crate) fn observe_once_v2(
        &mut self,
        stage: &mut RootExecutionNoApplyStageReceivingV2<'_, '_>,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        marker: ClosedBeforeArgumentNoApplyRecordV2,
        terminal_archive: ObjectDigest,
        signed_terminal: ObjectDigest,
        wall_seconds: i64,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| {
            if policy.verified_v1().is_none() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let demand = readonly
                .execution_no_apply_current_data_v2()?
                .planning_demand_v2()?;
            let carriers = size_of::<Self>()
                .checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            Ok(demand
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carriers))
                .map_err(JournalError::ReceivingAccounting)?)
        })());
        let demand = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.funding = Some(stage.admit_execution_no_apply_models_once_v2(
            RootContinuationDemandV1::from_demand_v1(demand),
        ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.plan = Some((|| {
            readonly
                .execution_no_apply_current_data_v2()?
                .plan_rows_data_v2(marker, terminal_archive, signed_terminal, wall_seconds)
        })());
        self.plan_data_v2().map(|_| ())
    }

    pub(crate) fn plan_data_v2(&self) -> Result<&ClosedCreateFailurePlanDataV2, JournalError> {
        if self.reentry.is_some() || !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.plan
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.plan.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}
