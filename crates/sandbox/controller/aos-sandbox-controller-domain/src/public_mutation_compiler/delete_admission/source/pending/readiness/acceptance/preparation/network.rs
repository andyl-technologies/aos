//! Lends real Root9 beside the accepted Source/C owners and fresh Network19.

use super::*;

impl<'source, 'original> ControllerDeletePendingOriginalV2<'source, 'original> {
    pub(crate) fn send_cleanup_current_once_v4(
        &mut self,
        root: &mut RootDeleteClientOriginalV1<'_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        network: (&[u8; 64], &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1),
        host: (&[u8; 64], &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<(), JournalError> {
        let accepted = &self.readiness.acceptance;
        if self.outer_after.is_some() || accepted.first.is_some()
            || !matches!(accepted.complete, Some(Ok(())))
            || !matches!(accepted.host_confirmation_contract, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        require_completed_network_for_host_v4(&accepted.network, network.0)?;
        let plan = self.plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let mut fence = self.source.borrow_controller_committed_fence_v3(plan)?;
        accepted.controller.completed_native_v3(controller, &fence)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        root.send_cleanup_current_once_v4(&mut fence, controller, launch,
            &accepted.controller, network, host).map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn borrow_host_confirmation_once_v4<'turn, 'profile>(
        &'turn mut self,
        root: &'turn mut RootDeleteClientOriginalV1<'profile>,
        controller: &'turn mut Journal,
        launch: &'turn ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: crate::DeleteInventorySecurityShapeDataV1,
        completed_network: &[u8; 64],
        upper_bytes: usize,
    ) -> Result<
        crate::DeleteInventorySessionAppendOriginalV1<
            'turn,
            'turn,
            'source,
            'original,
            'source,
            'profile,
        >,
        JournalError,
    > {
        let accepted = &mut self.readiness.acceptance;
        let network = &accepted.network;
        if self.outer_after.is_some()
            || accepted.first.is_some()
            || accepted.host_confirmation_contract.is_some()
            || !matches!(accepted.complete, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        // Supplied SDK coordinates only compare to this genuine entered native
        // original; no DATA can create the completion checked above or below.
        require_completed_network_for_host_v4(network, completed_network)?;
        let plan = self
            .plan
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let fence = self.source.borrow_controller_committed_fence_v3(plan)?;
        fence.into_host_confirmation_once_v4(
            &accepted.controller,
            &mut accepted.host_confirmation_contract,
            root,
            controller,
            launch,
            profile,
            transcript,
            shape,
            upper_bytes,
        )
    }

    pub(crate) fn borrow_network_apply_once_v4<'held, 'root>(
        &'held mut self,
        root: &'held mut RootDeleteClientOriginalV1<'root>,
        controller: &'held mut Journal,
        launch: &'held ControllerBankLaunchOriginalV1,
        profile: &'held ControllerSelfProfileOriginalV1,
        inventory: DeleteSessionInventoryCutDataV2<'_>,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<OriginalDeleteNetworkApplyLoanV4<'held>, JournalError> {
        let accepted = &mut self.readiness.acceptance;
        let preparation = &accepted.preparation;
        if self.outer_after.is_some() || accepted.first.is_some()
            || !matches!(accepted.complete, Some(Ok(())))
            || preparation.first.is_some()
            || !matches!(preparation.complete, Some(Ok(())))
            || !matches!(preparation.after, Some(Ok(())))
            || !matches!(preparation.retirement, Some(Ok(())))
            || !matches!(preparation.current_send, Some(Ok(())))
            || accepted.network.started {
            accepted.network.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        let state = &mut accepted.network;
        state.started = true;
        let plan = match self.plan.as_ref().and_then(|result| result.as_ref().ok()) {
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
            accepted.controller.completed_native_v3(controller, &fence)?;
            preparation.io.completed_native_v3()?;
            Ok(())
        })());
        if !matches!(state.contract, Some(Ok(()))) {
            state.first.get_or_insert(First::Contract);
            return Err(JournalError::ProtectedBoundary);
        }
        let inner = OriginalDeleteStorageFlightLoanV3::begin_once_v3(fence, state,
            &accepted.controller, root, controller, launch, profile,
            Some(inventory), None, shape, Purpose::Network9)?;
        Ok(OriginalDeleteNetworkApplyLoanV4 { inner })
    }

    /// Identifies the same actual Network9 upper's retained Root/F/native cause.
    #[doc(hidden)]
    #[must_use]
    pub fn delete_network_root_failure_is_selected_v4(&self) -> bool {
        let state = &self.readiness.acceptance.network;
        state.funding_selected || state.root_selected
            || matches!(state.first, Some(First::Entry | First::After | First::Complete))
    }
}

fn require_completed_network_for_host_v4(
    network: &ControllerDeleteNetworkOriginalV4,
    sdk: &[u8; 64],
) -> Result<(), JournalError> {
    if network.first.is_some()
        || !network.started
        || !matches!(network.after, Some(Ok(())))
        || !matches!(network.retirement, Some(Ok(())))
        || !matches!(network.complete, Some(Ok(())))
    {
        return Err(JournalError::ProtectedBoundary);
    }
    if network
        .io
        .completed_native_v3()
        .map_err(|_| JournalError::ProtectedBoundary)?
        != sdk
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_network_markers_and_supplied_position_do_not_create_host_query_loan() {
        let mut network = ControllerDeleteNetworkOriginalV4::default();
        network.started = true;
        network.after = Some(Ok(()));
        network.retirement = Some(Ok(()));
        network.complete = Some(Ok(()));

        let result = require_completed_network_for_host_v4(&network, &[7; 64]);

        assert!(result.is_err());
        assert!(network.io.completed_native_v3().is_err());
    }
}
