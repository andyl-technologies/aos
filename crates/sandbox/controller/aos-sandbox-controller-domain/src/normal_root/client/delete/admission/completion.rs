//! Bookends final Source successors with the same actual Root/C17 interval.
//!
//! These finite phases preserve the original absolute Root and authorization
//! horizons. A new Source frontier replaces only current-EOF comparison; the
//! original accepted Batch2 and Controller witnesses remain independently held.

use super::*;
use crate::lifecycle::delete_pending::{
    DeleteSourceCompletionPhaseV4 as Phase, SourceDeleteCompletionPlanV4 as Plan,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    cleanup_current::DeleteRootCleanupTerminalDataV4,
    completion::{DeleteRootPhysicalCompletionDataV4, completion_approval_commitment_data_v4},
};

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn require_completion_network_v4(
        &self,
        native: &[u8; 64],
        identity: ([u8; 32], [u8; 32]),
    ) -> Result<(), JournalError> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (frame, _) = state.cleanup.completed_frame_v4(state)?;
        if frame.network.native != *native
            || (frame.network.request, frame.network.outcome) != identity
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn physical_completion_data_v4(
        &self,
        mount: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
        storage: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<DeleteRootPhysicalCompletionDataV4, Cause> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 11
            || !state.mount_retired
            || !matches!(state.disposal, Some(Ok(())))
            || self.turn.is_some()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let (cleanup, _) = state.cleanup.completed_frame_v4(state)?;
        let receipt = |value: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1)| {
            DeleteRootCleanupTerminalDataV4 {
                native: *value.0,
                request: value.1.request().signed_request_digest(),
                outcome: *blake3::hash(value.1.canonical_packet()).as_bytes(),
            }
        };
        let approval = |purpose| {
            self.preparatory_approval_complete[resource_slot_v3(purpose)]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .map(|value| value.approval)
                .ok_or(JournalError::ProtectedBoundary)
        };
        let physical = DeleteRootPhysicalCompletionDataV4 {
            challenge: cleanup.challenge,
            opening: cleanup.opening,
            cleanup: cleanup.commitment_v4()?,
            approved_mount: completion_approval_commitment_data_v4(
                approval(DeleteResourcePurposeV3::MountReap62)?,
                DeleteResourcePurposeV3::MountReap62,
            )?,
            approved_storage: completion_approval_commitment_data_v4(
                approval(DeleteResourcePurposeV3::Apply7)?,
                DeleteResourcePurposeV3::Apply7,
            )?,
            mount: receipt(mount),
            storage: receipt(storage),
        };
        physical.encode_v4()?;
        Ok(physical)
    }

    pub(crate) fn begin_source_completion_interval_once_v4(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
        phase: Phase,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if phase == Phase::Reserve {
            fence.require_source_controller_committed_v3()
        } else {
            fence.require_source_completion_phase_v4(Phase::Reserve)
        }
        .map_err(|_| self.closed)?;
        self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::MountReap62)
            .and_then(|()| {
                self.require_cleanup_resource_approval_v4(DeleteResourcePurposeV3::Apply7)
            })
            .map_err(|_| self.closed)?;
        let state = self.source_admission.as_ref().ok_or(self.closed)?;
        if !state.mount_retired
            || state.cursor != 11 + phase.index_v4() as u8
            || !matches!(state.disposal, Some(Ok(())))
        {
            return Err(self.closed);
        }
        self.begin_admission_interval_once_v3(
            fence,
            controller,
            launch,
            RootNativeAdmissionPhaseV3::SourceCompletion(phase, accepted),
        )
    }

    pub(crate) fn require_source_completion_before_v4(
        &mut self,
        phase: Phase,
    ) -> Result<DeleteSourceClockBoundDataV3, JournalError> {
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 11 + phase.index_v4() as u8
            || state.before.is_none()
            || state.after.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let bound = state
            .binding
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?
            .clock_bound_data_v3();
        self.require_admission_native_frontier_v3()?;
        Ok(bound)
    }

    pub(crate) fn require_source_completion_after_v4(
        &self,
        plan: &Plan,
        controller: &Journal,
    ) -> Result<(), JournalError> {
        controller.ensure_healthy()?;
        plan.require_controller_v4(controller.snapshot_sequence())?;
        let state = self
            .source_admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let binding = state
            .binding
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let bound = plan.clock_bound_v4();
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 11 + plan.phase_v4().index_v4() as u8
            || bound.cutoff != binding.cutoff
            || bound.expires != binding.expires
            || state.after.is_none()
            || !matches!(state.after_time, Some(Ok(())))
            || state
                .interval
                .as_ref()
                .is_none_or(|interval| !interval.completed_interval_v2())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        bound.require_sample_v3(state.after.ok_or(JournalError::ProtectedBoundary)?)
    }

    pub(crate) fn retire_source_completion_interval_once_v4(
        &mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        phase: Phase,
    ) -> Result<(), RootDeleteClientClosedV1> {
        fence
            .require_source_completion_phase_v4(phase)
            .map_err(|_| self.closed)?;
        let state = self.source_admission.as_mut().ok_or(self.closed)?;
        if self.first.is_some()
            || state.first.is_some()
            || state.cursor != 11 + phase.index_v4() as u8
            || state.after.is_none()
        {
            return Err(self.closed);
        }
        state.disposal = Some((|| {
            let token = self
                .turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(state.interval.take());
            token.complete_after_upper_disposal_v1();
            Ok(())
        })());
        if !matches!(state.disposal, Some(Ok(()))) {
            state.first = Some(RootAdmissionFirst::Disposal);
            self.first = Some(First::SourceAdmission);
            return Err(self.closed);
        }
        drop(self.turn.take());
        state
            .binding
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .ok_or(self.closed)?
            .after = state.after.ok_or(self.closed)?;
        state.cursor += 1;
        Ok(())
    }
}
