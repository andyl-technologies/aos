//! Selects the genuine Mount62 upper after actual9 and fresh Host3 completed.

use super::*;

impl<'source, 'original> ControllerDeletePendingOriginalV2<'source, 'original> {
    pub(crate) fn borrow_mount_reap_once_v4<'held, 'root>(
        &'held mut self,
        root: &'held mut RootDeleteClientOriginalV1<'root>,
        controller: &'held mut Journal,
        launch: &'held ControllerBankLaunchOriginalV1,
        profile: &'held ControllerSelfProfileOriginalV1,
        inventory: DeleteSessionInventoryCutDataV2<'_>,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<OriginalDeleteMountReapLoanV4<'held>, JournalError> {
        let accepted = &mut self.readiness.acceptance;
        if self.outer_after.is_some()
            || accepted.first.is_some()
            || !matches!(accepted.complete, Some(Ok(())))
            || !matches!(accepted.host_confirmation_contract, Some(Ok(())))
            || accepted.network.first.is_some()
            || !matches!(accepted.network.after, Some(Ok(())))
            || !matches!(accepted.network.retirement, Some(Ok(())))
            || !matches!(accepted.network.complete, Some(Ok(())))
            || accepted.mount.started
        {
            accepted.mount.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        let state = &mut accepted.mount;
        state.started = true;
        let plan = match self.plan.as_ref().and_then(|value| value.as_ref().ok()) {
            Some(plan) => plan,
            None => {
                state.construction = Some(Err(JournalError::ProtectedBoundary));
                state.first = Some(First::Construction);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        let fence = match self.source.borrow_controller_committed_fence_v3(plan) {
            Ok(fence) => fence,
            Err(cause) => {
                state.entry = Some(Err(cause));
                state.first = Some(First::Entry);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        state.contract = Some((|| {
            accepted
                .controller
                .completed_native_v3(controller, &fence)?;
            // Actual original completion, not supplied native64, selects62.
            accepted.network.io.completed_native_v3()?;
            Ok(())
        })());
        if !matches!(state.contract, Some(Ok(()))) {
            state.first = Some(First::Contract);
            return Err(JournalError::ProtectedBoundary);
        }
        let inner = OriginalDeleteStorageFlightLoanV3::begin_once_v3(
            fence,
            state,
            &accepted.controller,
            root,
            controller,
            launch,
            profile,
            Some(inventory),
            None,
            shape,
            Purpose::MountReap62,
        )?;
        Ok(OriginalDeleteMountReapLoanV4 { inner })
    }

    /// Identifies this Mount upper's selected Root/financial/native refusal.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_mount_root_failure_is_selected_v4(&self) -> bool {
        let state = &self.readiness.acceptance.mount;
        state.funding_selected
            || state.root_selected
            || matches!(
                state.first,
                Some(First::Entry | First::After | First::Complete)
            )
    }
}
