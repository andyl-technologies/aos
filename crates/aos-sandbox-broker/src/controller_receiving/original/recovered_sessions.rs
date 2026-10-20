//! Keeps the four recovered Session latches on the original shared B ledger.
//!
//! Only the completed-enrollment native factory enters this private schedule.
//! These transitions issue no account, initial claim, cold receiver or Ready.

use super::*;

pub(super) fn recovered_session_is_current_v2(state: &BaselineOriginalState,
    role: crate::controller_receiving::initial_session::ControllerInitialBrokerSessionRoleV1,
) -> bool {
    state.recovered_sessions_entered && state.recovered_session_claimed[role.index()]
        && state.original.is_some_and(|original| is_recovered_range_recipient_v2(original))
        && !matches!(state.continuation_purpose,
            Some(ContinuationReceivingPurposeV1::OperatorRecover | ContinuationReceivingPurposeV1::RecoveredEnrollment))
        && (state.recovered_session_completed[role.index()]
            || state.continuation_purpose == Some(ContinuationReceivingPurposeV1::RecoveredOrdinarySession(role)))
}

impl ControllerReceivingOriginalV1 {
    pub(in crate::controller_receiving) fn begin_recovered_sessions_context_v2(&self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || state.continuation_base.is_some() || state.recovered_sessions_entered
            || state.original.is_none_or(|original| !is_recovered_range_recipient_v2(original))
            || state.startup.as_ref().is_none_or(|startup| startup.is_unfinished())
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        // Once is spent before arithmetic/debit. No prior Session owner,
        // predecessor carry, reconciliation traffic or highwater is reset.
        state.recovered_sessions_entered = true;
        let result = (|| {
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            state.demand.begin()?;
            state.demand.raise(BaselineOwner::RecoveredOrdinarySessionContext, complete, provision)
        })();
        if result.is_err() { state.closed = true; }
        result
    }

    pub(in crate::controller_receiving) fn require_recovered_sessions_context_current_v2(&self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || !state.recovered_sessions_entered
            || state.original.is_none_or(|original| !is_recovered_range_recipient_v2(original))
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn require_recovered_session_current_v2(&self,
        role: crate::controller_receiving::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || !recovered_session_is_current_v2(&state, role)
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn complete_recovered_session_native_v2(&self,
        role: crate::controller_receiving::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope
            || state.continuation_base.is_some() || !state.recovered_sessions_entered
            || !state.recovered_session_claimed[role.index()] || state.recovered_session_completed[role.index()]
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        state.recovered_session_completed[role.index()] = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn raise_recovered_session_complete_v2(&self,
        role: crate::controller_receiving::initial_session::ControllerInitialBrokerSessionRoleV1, complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.require_recovered_session_current_v2(role)?;
        let mut state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || !recovered_session_is_current_v2(&state, role) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let result = (|| {
            let provision = state.baseline.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            state.demand.begin()?;
            state.demand.raise(role.recovered_owner_v2(), complete, provision)
        })();
        if result.is_err() { state.closed = true; }
        result
    }

    pub(in crate::controller_receiving) fn prepare_recovered_session_physical_v2(&self,
        role: crate::controller_receiving::initial_session::ControllerInitialBrokerSessionRoleV1,
        required: ResourceVector,
        destination: &mut Option<ComponentReceivingOwnedOperationV1>,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !matches!(role, crate::controller_receiving::initial_session::ControllerInitialBrokerSessionRoleV1::Storage
            | crate::controller_receiving::initial_session::ControllerInitialBrokerSessionRoleV1::Mount) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.prepare_storage_physical_with_context_v1(
            PhysicalSessionFundingV3::RecoveredOrdinary(role), required, destination,
        )
    }
}
