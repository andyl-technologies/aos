//! Holds cursor8's same Root/C turn around the fresh post-Network Host query.
//!
//! The query temporarily owns the actual entered Controller turn. Its final
//! post returns that original before the existing Root interval finishes. Only
//! joint native and upper disposal advances the retained cursor to Mount Reap.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerDeletePreacceptTurnOriginalV1;

impl<'profile> RootDeleteClientOriginalV1<'profile> {
    pub(crate) fn begin_host_confirmation_once_v4(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.require_network_resource_approval_v4()
            .map_err(|_| self.closed)?;
        self.require_resource_flight_pending_v3(fence, controller, launch, Some(accepted))
            .map_err(|_| self.closed)?;
        fence
            .require_source_controller_committed_v3()
            .map_err(|_| self.closed)?;
        self.begin_admission_interval_once_v3(
            fence,
            controller,
            launch,
            RootNativeAdmissionPhaseV3::HostConfirmation(accepted),
        )
    }

    pub(crate) fn host_confirmation_bound_v4(
        &mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        self.require_accepted_pending_v3(fence, controller, launch, accepted)?;
        self.require_network_resource_approval_v4()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 8
            || state.before.is_none()
            || state.after.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut bound = state
            .binding
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?
            .clock_bound_data_v3();
        let signed = self.resource_signing_complete
            [resource_slot_v3(DeleteResourcePurposeV3::Network9)]
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)?;
        bound.expires = bound
            .expires
            .min(signed.signed.plan().expires_seconds())
            .min(signed.lease.authority_expires_seconds());
        bound.require_sample_v3(bound.after)?;
        self.require_admission_native_frontier_v3()?;
        Ok(bound)
    }

    pub(crate) fn take_host_confirmation_turn_v4(
        &mut self,
    ) -> Option<ControllerDeletePreacceptTurnOriginalV1<'profile>> {
        if self.source_admission.as_ref()?.cursor != 8 {
            return None;
        }
        self.turn.take()
    }

    pub(crate) fn require_host_confirmation_post_v4(
        &self,
        bound: DeleteSourceClockBoundDataV3,
        query_after: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        bound.require_sample_v3(query_after)?;
        let after = self
            .source_admission
            .as_ref()
            .and_then(|state| state.after)
            .ok_or(JournalError::ProtectedBoundary)?;
        query_after
            .validate_later_sample(after)
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        // The independent Root/C post also stays inside the original signed9
        // lease and policy, rather than only its broader authorization cutoff.
        bound.require_sample_v3(after)
    }

    pub(crate) fn return_host_confirmation_turn_v4(
        &mut self,
        turn: ControllerDeletePreacceptTurnOriginalV1<'profile>,
    ) {
        if self.turn.is_some() {
            std::process::abort();
        }
        self.turn = Some(turn);
    }

    pub(crate) fn host_confirmation_turn_mut_v4(
        &mut self,
    ) -> Result<&mut ControllerDeletePreacceptTurnOriginalV1<'profile>, JournalError> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 8
            || !matches!(state.after_time, Some(Ok(())))
            || state
                .interval
                .as_ref()
                .is_none_or(|interval| !interval.completed_interval_v2())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn take_completed_host_confirmation_turn_v4(
        &mut self,
    ) -> Result<ControllerDeletePreacceptTurnOriginalV1<'profile>, JournalError> {
        self.host_confirmation_turn_mut_v4()?;
        let state = self
            .source_admission
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        // Wholly compared Root scratch may retire before the shared C token.
        // The query still retains that actual turn and its full upper owners.
        drop(state.interval.take());
        self.turn.take().ok_or(JournalError::ProtectedBoundary)
    }

    // Called solely by the same query's Drop after its native disposal token
    // completed. Dropping an incomplete actual turn aborts in that turn's Drop.
    pub(crate) fn complete_host_confirmation_disposal_v4(&mut self) {
        let Some(state) = self.source_admission.as_mut() else {
            std::process::abort();
        };
        let Some(binding) = state.binding.as_mut().and_then(|value| value.as_mut().ok()) else {
            std::process::abort();
        };
        let Some(after) = state.after else {
            std::process::abort();
        };
        if state.cursor != 8 || state.first.is_some() || self.first.is_some() {
            std::process::abort();
        }
        if self.turn.is_some() || state.interval.is_some() {
            std::process::abort();
        }
        binding.after = after;
        state.disposal = Some(Ok(()));
        state.cursor = 9;
    }
}
