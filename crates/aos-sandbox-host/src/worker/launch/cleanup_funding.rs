//! Lends either actual original to the same finite worker and Stop program.
//!
//! This closed union supplies financial/native receiving only. Fresh cleanup
//! effect permission still requires its signed current subject, protected exact
//! parent and new native ownership at the Host receiver. It cannot start a unit
//! or turn a readonly preparation into an ordinary consumed Launch owner.

use super::*;
use crate::plan::HostControlPreparationReceivingV5;

pub(super) enum WorkerReceivingOriginalV5<'call, 'original> {
    Launch(&'call mut HostExecutionReceivingLoanV2<'original>),
    Cleanup(&'call mut HostControlPreparationReceivingV5<'original>),
}

impl WorkerReceivingOriginalV5<'_, '_> {
    pub(super) fn require_stop_method_v1(
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if request.method()
            != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || request.authorization().is_none()
        {
            return Err(closed(
                "cleanup worker requires its signed Host Stop request",
            ));
        }
        Ok(())
    }

    pub(super) fn require_launch_request_v2(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        match self {
            Self::Launch(original) => original.require_launch_request_v2(request),
            Self::Cleanup(original) => {
                Self::require_stop_method_v1(request)?;
                original.require_cleanup_request_v1(request)
            }
        }
    }

    pub(super) fn require_launch_readonly_post_request_v2(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        match self {
            Self::Launch(original) => original.require_launch_readonly_post_request_v2(request),
            Self::Cleanup(original) => {
                Self::require_stop_method_v1(request)?;
                original.require_cleanup_owed_request_v1(request)
            }
        }
    }

    pub(super) fn require_complete_v2(
        &mut self,
        complete: aos_sandbox_core::ResourceVector,
    ) -> Result<()> {
        match self {
            Self::Launch(original) => original.require_complete_v2(complete),
            Self::Cleanup(original) => original.raise_complete_v1(complete),
        }
    }

    pub(super) fn remaining_launch_capacity_v2(
        &self,
        complete: aos_sandbox_core::ResourceVector,
    ) -> Result<aos_sandbox_core::ResourceVector> {
        match self {
            Self::Launch(original) => original.remaining_launch_capacity_v2(complete),
            Self::Cleanup(original) => original.remaining_cleanup_capacity_v1(),
        }
    }

    pub(super) fn enter_launch_worker_phase_v4(
        &mut self,
        phase: &HostLaunchWorkerPhaseV4,
    ) -> Result<()> {
        match self {
            Self::Launch(original) => original.enter_launch_worker_phase_v4(phase),
            Self::Cleanup(original) => original.enter_cleanup_worker_phase_v1(phase),
        }
    }

    pub(super) fn require_launch_compensation_phase_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        phase: &HostLaunchWorkerPhaseV4,
    ) -> Result<()> {
        match self {
            Self::Launch(original) => original.require_launch_compensation_phase_v1(request, phase),
            Self::Cleanup(_) => Err(closed("fresh Stop cannot borrow Launch compensation")),
        }
    }

    pub(super) fn component_report_original_failure_entered_v2(&self) -> bool {
        match self {
            Self::Launch(original) => original.component_report_original_failure_entered_v2(),
            Self::Cleanup(original) => original.original_failure_entered_v5(),
        }
    }
}
