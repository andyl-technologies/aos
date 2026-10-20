//! Joins a separate final C reader to the completed initial original.
//!
//! The same native/full-fold engine runs again. Held initial writers prohibit
//! replacement or compaction while the fresh signed Inventory requests advance
//! their Session journals. A changed Controller or any native name refuses;
//! equivalent decoded data does not authorize adopting another original.

use super::*;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

pub(super) struct FreshControllerPredecessorV2 {
    frame: DeleteRootControllerCutDataV3,
    names: ProtectedJournalNamesV1,
}

impl FreshControllerPredecessorV2 {
    fn from_initial_v2(initial: &RootDeleteControllerCurrentOriginalV1) -> Result<Self, JournalError> {
        initial.retained_receiving_demand_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        initial.initial_session_cuts_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        initial.broker_manifests_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let actual = initial.readback_v2()?;
        let frame = *positive(&initial.frame)?;
        if (frame.next, frame.end) != (actual.next, actual.end) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(Self { frame, names: actual.names })
    }

    pub(super) fn require_same_controller_v2(
        &self,
        frame: DeleteRootControllerCutDataV3,
        actual: &RootFixedNativeReadbackV1<'_>,
    ) -> Result<(), JournalError> {
        if frame != self.frame || actual.names != self.names
            || (actual.next, actual.end) != (self.frame.next, self.frame.end)
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

impl RootDeleteControllerCurrentOriginalV1 {
    pub(in crate::policy_compiler::delete_root) fn observe_fresh_controller_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
        initial: &Self,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.fresh_predecessor.is_some() || self.first.is_some() {
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        }
        self.fresh_predecessor = Some(FreshControllerPredecessorV2::from_initial_v2(initial));
        if !matches!(self.fresh_predecessor, Some(Ok(_))) {
            self.first = Some(First::Compare);
            return Err(RootDeleteErrorV1::Original);
        }
        self.observe_once_v1(flight, original, challenge)
    }

    pub(in crate::policy_compiler::delete_root) fn require_fresh_controller_v2(&self, initial: &Self) -> Result<(), RootDeleteErrorV1> {
        self.verified_named_cut_data_v2()?;
        let expected = FreshControllerPredecessorV2::from_initial_v2(initial)
            .map_err(|_| RootDeleteErrorV1::Original)?;
        let actual = self.readback_v2().map_err(|_| RootDeleteErrorV1::Original)?;
        let frame = *positive(&self.frame).map_err(|_| RootDeleteErrorV1::Original)?;
        expected.require_same_controller_v2(frame, &actual)
            .map_err(|_| RootDeleteErrorV1::Original)?;
        if !matches!(self.fresh_predecessor, Some(Ok(_))) {
            return Err(RootDeleteErrorV1::Original);
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn current_frame_data_v2(&self)
        -> Result<DeleteRootControllerCutDataV3, RootDeleteErrorV1>
    {
        self.verified_named_cut_data_v2()?;
        positive(&self.frame).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(crate) fn fresh_admission_phase_v2(
        &self,
    ) -> Result<RootDeleteControllerAdmissionPhaseV1, ResourceReservationErrorV1> {
        self.receiving_demand_v1()?;
        if !matches!(self.fresh_predecessor, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(self.phase)
    }
}
