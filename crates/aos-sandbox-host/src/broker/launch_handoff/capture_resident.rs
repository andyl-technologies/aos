//! Retains the same admitted execution from before its first Guest issue.
//!
//! The Launch owns the whole accepted Stage before issue; first Observe Sent
//! advances that existing association. Its four runtime journals, fifth59
//! journal, Storage channel, operations and native failures remain resident.
//! Uncertain Continue executions wait for the original Guardian backstop; this
//! module grants no cancellation, kill, thaw or physical-completion permission.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use aos_sandbox_core::ExecutionId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};

use crate::plan::{HostCatalog, HostComponentControlStartupV2, HostExecutionRequestBindingV2};
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};

use super::super::argument_handoff::ArgumentStageOriginalV2;
use super::super::HostBroker;

pub(super) struct HostCaptureResidentV3 {
    // Moving this Arc retains the original OFDs. There is no reopening,
    // capsule copying, healthy reset or purpose20 completion at this frontier.
    stage: Arc<Mutex<ArgumentStageOriginalV2>>,
    accept: HostExecutionRequestBindingV2,
    observe: Option<HostExecutionRequestBindingV2>,
    unknown: Arc<AtomicBool>,
    execution: ExecutionId,
    cutoff: u64,
}

/// Retains uncertainty without acquiring a cancellation or cleanup permission.
///
/// The Launch owns the whole Stage before the first Guest issue. Backreferences
/// are weak, so custody contains no Arc cycle. Neither expiry nor a channel Ack
/// disposes this plan: the original Guardian/BindsTo backstop remains unchanged.
pub(in crate::broker) enum HostCaptureNegativeDispositionV3 {
    HoldOriginalUntilGuardianExpiry {
        launch: Weak<Mutex<super::HostLaunchOriginalV2>>,
        stage: Weak<Mutex<ArgumentStageOriginalV2>>,
        source: aos_sandbox_core::ObjectDigest,
        execution: ExecutionId,
        unknown: Arc<AtomicBool>,
        _financial: crate::plan::HostCaptureNegativeControlV3,
    },
}

impl HostCaptureNegativeDispositionV3 {
    fn receiving_demand_v3() -> Result<aos_sandbox_core::ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<HostCaptureResidentV3>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<AtomicBool>()))
            .ok_or(HostError::ResourceExhausted)?;
        Ok(aos_sandbox_core::ResourceVector::ZERO.with(
            aos_sandbox_core::ResourceDimension::MemoryBytes,
            u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?,
        ))
    }

    pub(in crate::broker) fn require_prearmed_v3(
        &self,
        actual_stage: &Arc<Mutex<ArgumentStageOriginalV2>>,
        ongoing: &super::super::accepted_execution::ongoing::HostExecutionOngoingOriginalV5,
    ) -> Result<()> {
        match self {
            Self::HoldOriginalUntilGuardianExpiry {
                launch, stage, source, execution, unknown, ..
            } => {
                if !stage.ptr_eq(&Arc::downgrade(actual_stage)) || launch.upgrade().is_none()
                    || *source != ongoing.source_digest_v5()
                    || *execution != ongoing.lifetime_v5().execution_v2()
                    || unknown.load(Ordering::Acquire)
                {
                    return Err(refused());
                }
                Ok(())
            }
        }
    }

    pub(in crate::broker) fn enter_stop_financial_once_v4(
        &mut self,
        failed: &super::capture_stop::HostCaptureFailedStageV4,
        admitted: &aos_sandbox_broker::VerifiedBrokerAdmission,
        source: &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
        actual: &Arc<Mutex<HostComponentControlStartupV2>>,
        original: &mut HostComponentControlStartupV2,
    ) -> Result<crate::plan::HostCaptureNegativeLoanV3> {
        failed.require_failed_resident_v4()?;
        if admitted.intersection.verb() != aos_sandbox_core::BrokerVerb::HostStop
            || admitted.fence.assignment() != source.original_source_v1().assignment()
        {
            return Err(refused());
        }
        match self {
            Self::HoldOriginalUntilGuardianExpiry {
                launch, source: original_source, execution, unknown, _financial, ..
            } => {
                if launch.upgrade().is_none() || !unknown.load(Ordering::Acquire)
                    || *original_source != source.source_digest_v2()
                    || *execution != failed.execution_v4()
                {
                    return Err(refused());
                }
                _financial.enter_from_same_control_v4(actual, original)
            }
        }
    }

    // This changes no operation, authority, cleanup result or native owner.
    // The actual original error stays on AcceptedTurn and is never replaced.
    pub(in crate::broker) fn retain_unknown_v3(&self) {
        match self {
            Self::HoldOriginalUntilGuardianExpiry { unknown, .. } => {
                unknown.store(true, Ordering::Release);
            }
        }
    }
}

fn refused() -> HostError {
    HostError::Fence("Host execution resident association is incomplete")
}

impl HostCaptureResidentV3 {
    pub(super) fn failed_stop_binding_v4(&self)
        -> Result<super::capture_stop::HostCaptureFailedStageV4> {
        if !self.unknown.load(Ordering::Acquire) {
            return Err(refused());
        }
        // Both references come from the actual original installed before the
        // first Guest issue. They supply identity and retained failure only;
        // a fresh signed Stop supplies the separate disabling permission.
        super::capture_stop::HostCaptureFailedStageV4::from_resident_v4(
            &self.stage, &self.unknown, self.accept, self.execution,
        )
    }

    pub(super) fn failed_stop_stage_v4(&self) -> Result<(
        Arc<Mutex<ArgumentStageOriginalV2>>, super::capture_stop::HostCaptureFailedStageV4,
    )> {
        Ok((Arc::clone(&self.stage), self.failed_stop_binding_v4()?))
    }

    pub(super) fn stage_for_terminal_disposal_v3(&self) -> &Arc<Mutex<ArgumentStageOriginalV2>> {
        &self.stage
    }

    pub(super) fn terminal_bindings_v3(&self)
        -> Result<(HostExecutionRequestBindingV2, HostExecutionRequestBindingV2)> {
        if self.unknown.load(Ordering::Acquire) { return Err(refused()); }
        Ok((self.accept, self.observe.ok_or_else(refused)?))
    }

    pub(super) fn dispose_unique_terminal_stage_v3(self) -> std::result::Result<(), Self> {
        match Arc::try_unwrap(self.stage) {
            Ok(original) => {
                // All native/post checks ran under the same Launch and Stage
                // locks. Atomic Arc consumption excludes every surviving
                // strong alias; old Weak callbacks can no longer enter.
                drop(original);
                Ok(())
            }
            Err(stage) => Err(Self { stage, ..self }),
        }
    }

    fn require_same_stage_v3(&self, stage: &Arc<Mutex<ArgumentStageOriginalV2>>) -> Result<()> {
        if !Arc::ptr_eq(&self.stage, stage) {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn monitor_association_v5(&self) -> Result<(
        Arc<Mutex<ArgumentStageOriginalV2>>, HostExecutionRequestBindingV2,
        HostExecutionRequestBindingV2, Arc<AtomicBool>, ExecutionId,
    )> {
        if self.unknown.load(Ordering::Acquire) { return Err(refused()); }
        Ok((Arc::clone(&self.stage), self.accept, self.observe.ok_or_else(refused)?,
            Arc::clone(&self.unknown), self.execution))
    }

    pub(super) fn query_association_v3(&self) -> Result<(
        Arc<Mutex<ArgumentStageOriginalV2>>, HostExecutionRequestBindingV2,
        HostExecutionRequestBindingV2, ExecutionId, Arc<AtomicBool>,
    )> {
        // Custody DATA only. Fresh Query admission supplies read permission;
        // an old sticky unknown is preserved and never cleared by this borrow.
        Ok((Arc::clone(&self.stage), self.accept, self.observe.ok_or_else(refused)?, self.execution, Arc::clone(&self.unknown)))
    }

    pub(super) fn retain_monitor_unknown_v5(&self) {
        self.unknown.store(true, Ordering::Release);
    }

    pub(super) fn monitor_failed_data_v5(&self) -> bool {
        self.unknown.load(Ordering::Acquire)
    }

    pub(super) fn format_monitor_failure_v5(&self,
        component: &HostComponentControlStartupV2, formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let held = self.stage.lock().map_err(|_| std::fmt::Error)?;
        if let Some(cause) = held.accepted.as_ref().and_then(|accepted|
            accepted.capture_terminal_failure_v3(component)) {
            return std::fmt::Display::fmt(cause, formatter);
        }
        let original = held.accepted.as_ref().and_then(|accepted| accepted.monitor_original_v5());
        if let Some(cause) = original.and_then(|original|
            original.first_failure_v5(held.owner.as_ref()?, component)) {
            std::fmt::Display::fmt(cause, formatter)
        } else if let Some(query) = held.accepted.as_ref().and_then(|accepted| accepted.query_original_v3()) {
            query.format_failure_v3(component, formatter)
        } else {
            formatter.write_str("execution resident retains unresolved original custody")
        }
    }

    pub(super) fn cutoff_v3(&self) -> u64 {
        self.cutoff
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(in crate::broker) fn prearm_execution_hold_v5(
        &self,
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>,
        receiving: &mut crate::plan::HostExecutionReceivingLoanV2<'_>,
        original: &Arc<Mutex<HostComponentControlStartupV2>>,
        accept: HostExecutionRequestBindingV2,
        agent: &crate::live_agent::HostAgentLiveSessionV1,
        logical: &crate::storage_existing_output::StorageExistingOutputOriginalV2,
        pipes: Option<&crate::storage_existing_output::capture::StorageCapturePipeLoanV2<'_>>,
        cutoff: u64,
        ongoing: &super::super::accepted_execution::ongoing::HostExecutionOngoingOriginalV5,
    ) -> Result<HostCaptureNegativeDispositionV3> {
        ongoing.require_same_v5(stage, accept, logical, pipes)?;
        if ongoing.deadline_v5()? != cutoff { return Err(refused()); }
        let launch_arc = self.launch_original.as_ref().ok_or_else(refused)?;
        let mut launch = launch_arc.lock().map_err(|_| refused())?;
        if !launch.authenticated_sent || launch.first.is_some() || launch.capture.is_some()
            || launch.lease.is_none() || launch.intersection.is_none()
            || launch.agent_binding != Some(agent.session_binding()) || cutoff == 0
            || self.component_control.as_ref().is_none_or(|actual| !Arc::ptr_eq(actual, original))
            || self.argument_stages[1].as_ref().is_none_or(|actual| !Arc::ptr_eq(actual, stage))
        {
            return Err(refused());
        }
        let lifetime = ongoing.lifetime_v5();
        let verified = launch.lease.as_ref().ok_or_else(refused)?;
        let lease = verified.lease();
        lifetime.require_original_lease_data_v2(
            verified.lease_digest(), lease.lease_generation(),
            lease.authority_expires_seconds(), lease.maximum_clock_skew_seconds(),
        )?;
        if lifetime.assignment_v2().sandbox() != lease.assignment().sandbox()
            || lifetime.assignment_v2().incarnation() != lease.assignment().incarnation()
            || lifetime.assignment_v2().epoch() != lease.assignment().epoch()
            || lifetime.assignment_v2().digest() != lease.assignment().digest()
        { return Err(refused()); }
        let launch_binding = HostExecutionRequestBindingV2 {
            id: launch.request.0, session: launch.request.1, signed: launch.request.2,
        };
        let financial = receiving.prearm_execution_resident_negative_v5(
            original, launch_binding, ongoing.source_digest_v5(), lifetime.execution_v2(),
            HostCaptureNegativeDispositionV3::receiving_demand_v3()?,
        )?;
        let execution = lifetime.execution_v2();
        let unknown = Arc::new(AtomicBool::new(false));
        let plan = HostCaptureNegativeDispositionV3::HoldOriginalUntilGuardianExpiry {
            launch: Arc::downgrade(launch_arc), stage: Arc::downgrade(stage),
            source: ongoing.source_digest_v5(), execution, unknown: Arc::clone(&unknown),
            _financial: financial,
        };
        // Own the SAME entire Stage before exposing the Guest issue. Any later
        // refusal leaves both operations, pipe aliases and all native prefixes
        // resident; an Abort/Ack supplies no permission to remove them.
        launch.capture = Some(HostCaptureResidentV3 {
            stage: Arc::clone(stage), accept, observe: None, unknown, execution,
            cutoff,
        });
        Ok(plan)
    }

    pub(in crate::broker) fn park_capture_after_observe_v3(
        &self,
        original: &mut HostComponentControlStartupV2,
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>,
        request: &AuthenticatedBrokerMethodRequestV1,
        accept: HostExecutionRequestBindingV2,
        execution: ExecutionId,
        cutoff: u64,
    ) -> Result<()> {
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive {
            return Err(refused());
        }
        let launch = self.launch_original.as_ref().ok_or_else(refused)?;
        let mut launch = launch.lock().map_err(|_| refused())?;
        if !launch.authenticated_sent || launch.first.is_some()
            || launch.lease.is_none() || launch.intersection.is_none()
            || launch.agent_binding.is_none() || launch.capture.is_none()
        {
            return Err(refused());
        }
        let held = stage.lock().map_err(|_| refused())?;
        if !held.authenticated || held.owner.is_none() || held.argument.is_none()
            || accept != (HostExecutionRequestBindingV2 {
                id: held.request.1, session: held.request.2, signed: held.request.3,
            })
        {
            return Err(refused());
        }
        let completed = held.accepted.as_ref().ok_or_else(refused)?
            .require_capture_residency_v3()?;
        if completed != (execution, cutoff) || cutoff == 0 {
            return Err(refused());
        }
        let completed_permission = held.accepted.as_ref().ok_or_else(refused)?
            .ongoing_permission_v5().ok_or_else(refused)?;
        completed_permission.require_same_stage_v5(stage, accept)?;
        let permission_deadline = completed_permission.deadline_v5()?;
        let observe = HostExecutionRequestBindingV2 {
            id: request.request_id(), session: request.session_binding(),
            signed: request.signed_request_digest(),
        };
        let launch_binding = HostExecutionRequestBindingV2 {
            id: launch.request.0, session: launch.request.1, signed: launch.request.2,
        };
        // Both exact consumed flights are checked while this same intrinsic
        // original is exclusively borrowed. No vector becomes an authority.
        original.retain_capture_after_observe_v3(launch_binding, accept, observe)?;
        drop(held);
        if cutoff != permission_deadline { return Err(refused()); }
        let bounded_cutoff = cutoff;
        let resident = launch.capture.as_mut().ok_or_else(refused)?;
        resident.require_same_stage_v3(stage)?;
        if resident.accept != accept || resident.execution != execution
            || resident.cutoff != bounded_cutoff || resident.observe.is_some()
            || resident.unknown.load(Ordering::Acquire)
        {
            return Err(refused());
        }
        resident.observe = Some(observe);
        Ok(())
    }
}
