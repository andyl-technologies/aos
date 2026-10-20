//! Rejoins the permanent ordinary Session schedule on the same baseline ledger.
//!
//! The typed upper context additionally proves all four actual cold Sessions.
//! These comparisons issue no Session, semantic append or effect authority.

use super::*;

pub(super) fn require_ordinary_session_context_v2(state: &BaselineOriginalState)
    -> Result<(), ControllerReceivingErrorV1>
{
    let original = state.original.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
    let available = match original.controller_generation_v1 {
        Some(0) => state.initial_session_claimed.iter().all(|claimed| *claimed),
        Some(ordinal) if ordinal > 0 && is_recovered_range_recipient_v2(original) => state.recovered_sessions_entered
            && state.recovered_session_completed.iter().all(|completed| *completed),
        _ => false,
    };
    if !available { return Err(ControllerReceivingErrorV1::Conflict); }
    Ok(())
}

impl ControllerReceivingOriginalV1 {
    pub(in crate::controller_receiving) fn require_catalog_maintenance_context_v2(&self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        require_ordinary_session_context_v2(&state)
    }

    pub(in crate::controller_receiving) fn require_catalog_maintenance_active_v2(&self,
        base: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let state = self.usage.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if state.closed || state.demand.is_closed() || state.active_scope || !state.runtime_entered
            || state.continuation_purpose != Some(ContinuationReceivingPurposeV1::CatalogMaintenance)
            || state.continuation_base != Some(base) || self.process != std::process::id()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        require_ordinary_session_context_v2(&state)
    }
}
