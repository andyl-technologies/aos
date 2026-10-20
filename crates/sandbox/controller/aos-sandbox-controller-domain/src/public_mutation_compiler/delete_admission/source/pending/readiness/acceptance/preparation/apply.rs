//! Constructs signed7's genuine upper from actual completed26 owner borrows.

use super::*;

impl<'source, 'original> ControllerDeletePendingOriginalV2<'source, 'original> {
    pub(crate) fn borrow_storage_apply_once_v3<'held, 'root>(
        &'held mut self,
        root: &'held mut RootDeleteClientOriginalV1<'root>,
        controller: &'held mut Journal,
        launch: &'held ControllerBankLaunchOriginalV1,
        profile: &'held ControllerSelfProfileOriginalV1,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<OriginalDeleteStorageApplyLoanV3<'held>, JournalError> {
        let accepted = &mut self.readiness.acceptance;
        let preparation = &accepted.preparation;
        if self.outer_after.is_some() || accepted.first.is_some()
            || !matches!(accepted.complete, Some(Ok(())))
            || preparation.first.is_some()
            || !matches!(preparation.complete, Some(Ok(())))
            || !matches!(preparation.after, Some(Ok(())))
            || !matches!(preparation.retirement, Some(Ok(())))
            || !matches!(preparation.current_send, Some(Ok(())))
            || accepted.mount.first.is_some()
            || !matches!(accepted.mount.after, Some(Ok(())))
            || !matches!(accepted.mount.retirement, Some(Ok(())))
            || !matches!(accepted.mount.complete, Some(Ok(())))
            || accepted.apply.started {
            accepted.apply.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        let state = &mut accepted.apply;
        state.started = true;
        let plan = self.plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let fence = self.source.borrow_controller_committed_fence_v3(plan)?;
        state.contract = Some((|| {
            accepted.controller.completed_native_v3(controller, &fence)?;
            preparation.io.completed_native_v3()?;
            accepted.mount.io.completed_native_v3()?;
            Ok(())
        })());
        if !matches!(state.contract, Some(Ok(()))) {
            state.first.get_or_insert(First::Contract);
            return Err(JournalError::ProtectedBoundary);
        }
        let inner = OriginalDeleteStorageFlightLoanV3::begin_once_v3(fence, state,
            &accepted.controller, root, controller, launch, profile, None,
            Some(&preparation.io), shape, Purpose::Apply7)?;
        Ok(OriginalDeleteStorageApplyLoanV3 { inner })
    }

    /// Identifies the actual7 financial/native cause while the originals live.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_apply_root_failure_is_selected_v3(&self) -> bool {
        let state = &self.readiness.acceptance.apply;
        state.funding_selected || state.root_selected
            || matches!(state.first, Some(First::Entry | First::After | First::Complete))
    }
}
