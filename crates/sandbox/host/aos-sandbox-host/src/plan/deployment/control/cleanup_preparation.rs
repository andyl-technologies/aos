//! Lends the existing current-Control observer to finite fresh cleanup.
//!
//! Caller native/model demand is cumulative across the whole flight. Each
//! real exchange independently pays its Source pair and concrete loan before
//! allocation. All samples and the initial readonly interval remain held until
//! the typed native terminal disposer drops the final actual writer owner.

use super::*;
use super::execution_receiving::{ControlCleanupPurposeV1, HostControlCleanupTokenV1, Request};
use super::terminal_inventory::{ControlPreparationPurposeV5, HostControlPreparationReceivingV5};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerRequestDirectionV1,
};

pub(super) struct CleanupPreparationV1 {
    token: HostControlCleanupTokenV1,
    purpose: ControlCleanupPurposeV1,
    request: Request,
    pub(super) resumed: bool,
}

fn request_binding(request: &AuthenticatedBrokerMethodRequestV1) -> Request {
    Request { id: request.request_id(), session: request.session_binding(),
        signed: request.signed_request_digest() }
}

fn cleanup_refused() -> HostError {
    HostError::Fence("fresh cleanup differs from its actual paid current-Control flight")
}

impl HostComponentControlStartupV2 {
    pub(crate) fn prepare_stop_cleanup_disposal_v1<'original>(
        &'original mut self,
        token: &HostControlCleanupTokenV1,
        posts: &crate::broker::HostStopCleanupTerminalPositiveV1<'_>,
    ) -> Result<HostControlCleanupDisposalV1<'original>> {
        self.require_admitted_original()?;
        posts.require_control_original_v1(token)?;
        let owner = self
            .execution_receiving
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(cleanup_refused)?;
        let destinations = owner
            .cleanup_destinations_v1(token)
            .map_err(|_| cleanup_refused())?;
        owner
            .require_cleanup_resident_binding_v1(token, posts.resident_launch_binding_v1())
            .map_err(|_| cleanup_refused())?;
        let Some((round, _)) = destinations[0] else {
            return Err(cleanup_refused());
        };
        if round != posts.observation_round_v1() || destinations[1..].iter().any(Option::is_some) {
            return Err(cleanup_refused());
        }
        for sample in round..round + 2 {
            self.attempts[sample].require_positive_leaf_v2()?;
        }
        self.execution_receiving
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?
            .prepare_cleanup_disposal_v1(token, ControlCleanupPurposeV1::Stop)
            .map_err(|_| cleanup_refused())?;
        Ok(HostControlCleanupDisposalV1 {
            original: self,
            token: token.borrow_original_v1(),
            completed: false,
        })
    }

    /// Lends current Control to the exact freshly authenticated Stop cleanup.
    ///
    /// This checks request/boot/cutoff correspondence only. The broker must
    /// independently join current Root authorization and fresh native ownership.
    ///
    /// # Errors
    /// Refuses an ordinary Stop, mismatched signed subject or closed Control.
    pub(crate) fn begin_stop_cleanup_receiving_v1<'original>(
        &'original mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        runtime: &aos_sandbox_protocol::ValidatedRuntimeRequest,
        admitted: &aos_sandbox_broker::VerifiedBrokerAdmission,
        complete: ResourceVector,
        resident: Option<&crate::broker::HostLiveCleanupParentV1<'_>>,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        let subject = runtime.host_stop_cleanup_v1().ok_or_else(cleanup_refused)?;
        if runtime.header().request_id() != &request.request_id()
            || runtime.header().deadline_boottime_nanoseconds()
                != request.deadline_boottime_nanoseconds()
            || admitted.effect.request_id() != &request.request_id()
            || admitted.effect.host_boot_id() != subject.current_boot_v1()
            || request.deadline_boottime_nanoseconds() > subject.original_cutoff_v1()
        {
            return Err(cleanup_refused());
        }
        self.require_argument_boot_v2(*subject.current_boot_v1())?;
        subject.require_request_data_v1(
            runtime.header().request_id(),
            runtime.fence(),
            request.deadline_boottime_nanoseconds(),
        )?;
        if let Some(parent) = resident {
            if parent.namespace_scope_v1()? != subject.historical_scope_v1().launch_scope_v1() {
                return Err(cleanup_refused());
            }
        }
        self.begin_control_cleanup_engine_v2(
            ControlCleanupPurposeV1::Stop,
            request,
            complete,
            resident,
        )
    }

    // This is a financial/native lender, not a Source or effect authorization
    // factory. The finite Host entry separately verifies its current signed
    // cleanup subject and exact protected target before any effect.
    pub(super) fn begin_control_cleanup_engine_v1<'original>(
        &'original mut self,
        purpose: ControlCleanupPurposeV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        complete: ResourceVector,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        self.begin_control_cleanup_engine_v2(purpose, request, complete, None)
    }

    fn begin_control_cleanup_engine_v2<'original>(
        &'original mut self,
        purpose: ControlCleanupPurposeV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        complete: ResourceVector,
        resident: Option<&crate::broker::HostLiveCleanupParentV1<'_>>,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        self.require_admitted_original()?;
        require_authenticated_method(purpose, request)?;
        let owner = self
            .execution_receiving
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?;
        let funded = match resident {
            Some(parent) if purpose == ControlCleanupPurposeV1::Stop => owner
                .begin_live_stop_cleanup_v1(
                    request_binding(request),
                    request.deadline_boottime_nanoseconds(),
                    complete,
                    parent,
                ),
            Some(_) => return Err(cleanup_refused()),
            None => owner.begin_control_cleanup_v1(
                purpose,
                request_binding(request),
                request.deadline_boottime_nanoseconds(),
                complete,
            ),
        };
        let token = self.select_cleanup_financial_result_v1(funded)?;
        self.cleanup_turn_engine_v1(token, purpose, request_binding(request), false)
    }

    pub(crate) fn begin_no_apply_cleanup_receiving_v1<'original>(
        &'original mut self, request: &AuthenticatedBrokerMethodRequestV1,
        complete: ResourceVector,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
        use aos_sandbox_protocol::host_execution_no_apply::held_settlement_transport::HostNoApplyHeldCommandV2;
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            || !matches!(request.host_held_no_apply_settlement_data_v2().map(|body| body.command_v2()),
                Some(HostNoApplyHeldCommandV2::RecoveryPreliminary { .. }))
        {
            return Err(cleanup_refused());
        }
        self.begin_control_cleanup_engine_v1(ControlCleanupPurposeV1::NoApply, request, complete)
    }

    pub(crate) fn resume_no_apply_cleanup_receiving_v1<'original>(
        &'original mut self, token: &HostControlCleanupTokenV1,
        request: &AuthenticatedBrokerMethodRequestV1, complete: ResourceVector,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        self.require_admitted_original()?;
        require_authenticated_method(ControlCleanupPurposeV1::NoApply, request)?;
        let owner = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?;
        let used = owner.cleanup_destinations_v1(token).map_err(|_| cleanup_refused())?
            .into_iter().flatten().count();
        require_no_apply_resume_phase(used, request)?;
        owner.resume_control_cleanup_v1(token, ControlCleanupPurposeV1::NoApply,
            request_binding(request), request.deadline_boottime_nanoseconds())
            .map_err(|_| cleanup_refused())?;
        let raised = owner.raise_cleanup_complete_v1(token, ControlCleanupPurposeV1::NoApply,
            request_binding(request), complete);
        self.select_cleanup_financial_result_v1(raised)?;
        self.cleanup_turn_engine_v1(token.borrow_original_v1(), ControlCleanupPurposeV1::NoApply,
            request_binding(request), true)
    }

    fn cleanup_turn_engine_v1<'original>(&'original mut self,
        token: HostControlCleanupTokenV1, purpose: ControlCleanupPurposeV1,
        request: Request, resumed: bool,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        let result: Result<super::recurring_observation::RecurringObservationDestinationsV4> = (|| {
            let (native, maximum) = self.recurring_observation_demand_v4()?;
            let headers = std::mem::size_of::<HostControlPreparationReceivingV5<'_>>()
                .checked_mul(3).and_then(|bytes| bytes.checked_add(
                    std::mem::size_of::<HostControlCleanupDisposalV1<'_>>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(HostError::ResourceExhausted)?;
            let complete = native.checked_add(ResourceVector::ZERO.with(
                aos_sandbox_model::ResourceDimension::MemoryBytes, headers))
                .map_err(|_| HostError::ResourceExhausted)?;
            self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or_else(cleanup_refused)?
                .admit_cleanup_observation_v1(&token, purpose, request, complete)
                .map_err(|_| cleanup_refused())?;
            let destinations = self.append_recurring_observation_destinations_v4(maximum)?;
            self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or_else(cleanup_refused)?
                .register_cleanup_destinations_v1(&token, destinations.round_start, destinations.manager_slot)
                .map_err(|_| cleanup_refused())?;
            Ok(destinations)
        })();
        if result.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            self.armed = true;
            if let Some(Ok(owner)) = self.execution_receiving.as_mut() { owner.close(); }
        }
        let destinations = result?;
        let preparation_purpose = match purpose {
            ControlCleanupPurposeV1::Stop => ControlPreparationPurposeV5::StopCleanup,
            ControlCleanupPurposeV1::NoApply => ControlPreparationPurposeV5::NoApplyCleanup,
        };
        Ok(HostControlPreparationReceivingV5 { original: self, purpose: preparation_purpose,
            destinations, before: false, after: false, completed: false, extension: false,
            cleanup: Some(CleanupPreparationV1 { token, purpose, request, resumed }) })
    }

    pub(crate) fn mark_cleanup_authenticated_sent_v1(&mut self,
        token: &HostControlCleanupTokenV1, outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<()> {
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.mark_cleanup_authenticated_sent_v1(token, outcome)
            .map_err(|_| cleanup_refused())
    }

    fn select_cleanup_financial_result_v1<T>(&mut self, result: std::result::Result<T, execution_receiving::Closed>)
        -> Result<T> {
        if result.is_err() && self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .is_some_and(|owner| owner.control_preparation_failure_v2().is_some())
        {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            self.armed = true;
        }
        result.map_err(|_| cleanup_refused())
    }

    pub(crate) fn require_cleanup_authenticated_response_v1(&self,
        token: &HostControlCleanupTokenV1, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive {
            return Err(cleanup_refused());
        }
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(cleanup_refused)?.require_cleanup_authenticated_response_v1(token,
                request_binding(request)).map_err(|_| cleanup_refused())
    }
}

fn require_authenticated_method(purpose: ControlCleanupPurposeV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<()> {
    use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod as Method;
    let purpose_matches = match purpose {
        ControlCleanupPurposeV1::Stop => request.method() == Method::BROKER_METHOD_HOST_APPLY_RUNTIME
            && request.authorization().is_some(),
        ControlCleanupPurposeV1::NoApply => request.authorization().is_none() && match request.method() {
            Method::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 =>
                request.host_held_no_apply_settlement_data_v2().is_some(),
            Method::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 =>
                request.host_no_apply_current_lease_query_data_v2().is_some(),
            _ => false,
        },
    };
    if !purpose_matches || request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
        || request.deadline_boottime_nanoseconds() == 0
    { return Err(cleanup_refused()); }
    Ok(())
}

fn require_no_apply_resume_phase(used: usize, request: &AuthenticatedBrokerMethodRequestV1)
    -> Result<()> {
    use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod as Method;
    use aos_sandbox_protocol::host_execution_no_apply::held_settlement_transport::HostNoApplyHeldCommandV2;
    let command = request.host_held_no_apply_settlement_data_v2().map(|body| body.command_v2());
    let matches = match used {
        1 => request.method() == Method::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
            && request.host_no_apply_current_lease_query_data_v2().is_some(),
        2 => matches!(command, Some(HostNoApplyHeldCommandV2::FloorSeal { .. })),
        3 => matches!(command, Some(HostNoApplyHeldCommandV2::Acknowledge { .. })),
        _ => false,
    };
    if !matches { return Err(cleanup_refused()); }
    Ok(())
}

impl HostControlPreparationReceivingV5<'_> {
    pub(crate) fn raise_complete_v1(&mut self, complete: ResourceVector) -> Result<()> {
        let cleanup = self.cleanup.as_ref().ok_or_else(cleanup_refused)?;
        let result = self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed).and_then(|owner| owner.raise_cleanup_complete_v1(
                &cleanup.token, cleanup.purpose, cleanup.request, complete));
        if result.is_err() {
            self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(cleanup_refused());
        }
        Ok(())
    }

    pub(crate) fn require_cleanup_request_v1(&self, request: &AuthenticatedBrokerMethodRequestV1)
        -> Result<()> {
        self.original.require_admitted_original()?;
        let cleanup = self.cleanup.as_ref().ok_or_else(cleanup_refused)?;
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(cleanup_refused)?.require_cleanup_current_v1(&cleanup.token,
                cleanup.purpose, request_binding(request)).map_err(|_| cleanup_refused())
    }

    pub(crate) fn require_cleanup_owed_request_v1(&self, request: &AuthenticatedBrokerMethodRequestV1)
        -> Result<()> {
        let cleanup = self.cleanup.as_ref().ok_or_else(cleanup_refused)?;
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(cleanup_refused)?.require_cleanup_owed_v1(&cleanup.token,
                request_binding(request)).map_err(|_| cleanup_refused())
    }

    pub(crate) fn remaining_cleanup_capacity_v1(&self) -> Result<ResourceVector> {
        let cleanup = self.cleanup.as_ref().ok_or_else(cleanup_refused)?;
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(cleanup_refused)?.cleanup_remaining_capacity_v1(&cleanup.token,
                cleanup.purpose, cleanup.request).map_err(|_| cleanup_refused())
    }

    pub(crate) fn observation_round_start_data_v1(&self) -> usize {
        self.destinations.round_start
    }

    pub(crate) fn enter_cleanup_worker_phase_v1(&mut self,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<()> {
        let cleanup = self.cleanup.as_ref().ok_or_else(cleanup_refused)?;
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.enter_cleanup_worker_phase_v1(&cleanup.token,
                cleanup.request, phase).map_err(|_| cleanup_refused())
    }

    pub(super) fn cleanup_before_entered_v1(&mut self) -> Result<()> {
        let Some(cleanup) = self.cleanup.as_ref() else { return Ok(()); };
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.cleanup_before_entered_v1(&cleanup.token)
            .map_err(|_| cleanup_refused())
    }

    pub(super) fn cleanup_after_entered_v1(&mut self) -> Result<()> {
        let Some(cleanup) = self.cleanup.as_ref() else { return Ok(()); };
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.cleanup_after_entered_v1(&cleanup.token)
            .map_err(|_| cleanup_refused())
    }

    pub(crate) fn finish_cleanup_native_once_v1(&mut self) -> Result<()> {
        if !self.before || !self.after { return Err(cleanup_refused()); }
        let cleanup = self.cleanup.as_ref().ok_or_else(cleanup_refused)?;
        for round in self.destinations.round_start .. self.destinations.round_start + 2 {
            self.original.attempts[round].require_positive_leaf_v2()?;
        }
        self.original.require_admitted_original()?;
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.cleanup_native_finished_v1(&cleanup.token)
            .map_err(|_| cleanup_refused())
    }

    pub(crate) fn retain_pending_authenticated_v1(mut self) -> Result<HostControlCleanupTokenV1> {
        let cleanup = self.cleanup.as_ref().ok_or_else(cleanup_refused)?;
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.cleanup_retain_pending_v1(&cleanup.token)
            .map_err(|_| cleanup_refused())?;
        let cleanup = self.cleanup.take().ok_or_else(cleanup_refused)?;
        self.completed = true;
        Ok(cleanup.token)
    }
}

/// Retains the same Control until its native terminal owner has really dropped.
///
/// The constructor checks a concrete native positive proof; completing this
/// disposer never refunds previously consumed Control or operation traffic.
pub(crate) struct HostControlCleanupDisposalV1<'original> {
    original: &'original mut HostComponentControlStartupV2,
    token: HostControlCleanupTokenV1,
    completed: bool,
}

impl HostComponentControlStartupV2 {
    pub(crate) fn prepare_no_apply_cleanup_disposal_v1<'original>(
        &'original mut self, token: &HostControlCleanupTokenV1,
        posts: &crate::broker::HostNoApplyTerminalPositiveV2<'_>,
    ) -> Result<HostControlCleanupDisposalV1<'original>> {
        self.require_admitted_original()?;
        posts.require_cleanup_control_original_v1(token)?;
        let owner = self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(cleanup_refused)?;
        let destinations = owner.cleanup_destinations_v1(token).map_err(|_| cleanup_refused())?;
        if !destinations.into_iter().flatten().map(|(round, _)| round)
            .eq(posts.observation_rounds_v2())
        { return Err(cleanup_refused()); }
        for (round, _) in destinations.into_iter().flatten() {
            for sample in round .. round + 2 { self.attempts[sample].require_positive_leaf_v2()?; }
        }
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.prepare_cleanup_disposal_v1(token, ControlCleanupPurposeV1::NoApply)
            .map_err(|_| cleanup_refused())?;
        Ok(HostControlCleanupDisposalV1 { original: self,
            token: token.borrow_original_v1(), completed: false })
    }
}

impl HostControlCleanupDisposalV1<'_> {
    /// Retires the actual Source samples after the final native owner drops.
    ///
    /// # Errors
    /// Refuses remaining token owners, missing native samples or manager posts.
    pub(crate) fn complete_after_native_drop_v1(mut self) -> Result<()> {
        self.original.execution_receiving.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or_else(cleanup_refused)?
            .require_cleanup_native_dropped_v1(&self.token).map_err(|_| cleanup_refused())?;
        let destinations = self.original.execution_receiving.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or_else(cleanup_refused)?
            .cleanup_destinations_v1(&self.token).map_err(|_| cleanup_refused())?;
        let (first, manager_slot) = destinations[0].ok_or_else(cleanup_refused)?;
        for (round, _) in destinations.into_iter().flatten() {
            for sample in round .. round + 2 { self.original.attempts[sample].require_positive_leaf_v2()?; }
        }
        // One actual readonly interval was opened on the initial turn. Retire
        // later positive samples only after the last native stage has dropped,
        // then the initial pair closes that same manager interval exactly once.
        for (round, _) in destinations.into_iter().skip(1).flatten() {
            for sample in round .. round + 2 { self.original.attempts[sample].dispose_positive_leaf_v2()?; }
        }
        self.original.retire_execution_samples_v2(first, 2, manager_slot)?;
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(cleanup_refused)?.complete_cleanup_after_native_drop_v1(&self.token)
            .map_err(|_| cleanup_refused())?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for HostControlCleanupDisposalV1<'_> {
    fn drop(&mut self) {
        if self.completed { return; }
        self.original.armed = true;
        self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
        if let Some(Ok(owner)) = self.original.execution_receiving.as_mut() { owner.close(); }
    }
}
