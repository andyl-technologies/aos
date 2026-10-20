//! Rejoins the continuously held Create Session for fresh Storage31/18.
//!
//! The genuine Start loan supplies new funding/currentness. These closed
//! adapters invoke the same provisioning IO kernel and retire only the new
//! operation owners after actual Root completion; the held Session survives.

use super::*;

impl StartResourceProvisioningSessionIoOriginalV4 {
    /// Creates only inert destinations for current31 and fresh18 on the held Session.
    #[must_use]
    pub fn storage_guest_root_v2() -> Self {
        Self { inner: StorageProvisioningSessionIoOriginalV1::new_kind_v4(ProvisioningKindV4::StartStorage), completed_models: None }
    }

    /// Rechecks the same held Storage originals in the fresh Start Root opening turn.
    ///
    /// # Errors
    /// Retains the actual new Start debit and passive/native Session association.
    pub fn rejoin_storage_session_once_v2(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::OriginalStartHostRootLoanV1<'_, '_>,
        root: &aos_sandbox_controller_domain::normal_root::RootStartResourceCurrentTurnV2<'_>,
        previous: &aos_sandbox_controller_domain::CreateProvisioningOriginalsV1,
        controller: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        session.rejoin_storage_session_once_v2(self, original, root, previous, controller)
    }

    pub(crate) fn rejoin_storage_inner_once_v2(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::OriginalStartHostRootLoanV1<'_, '_>,
        root: &aos_sandbox_controller_domain::normal_root::RootStartResourceCurrentTurnV2<'_>,
        previous: &aos_sandbox_controller_domain::CreateProvisioningOriginalsV1,
        controller: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.inner.apply.kind, ProvisioningKindV4::StartStorage) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let journal = session.owner.retained_storage_client_journal_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        original.observe_retained_storage_session_once_v2(root, previous, controller,
            journal, &session.socket, &session.transcript)
    }

    /// Runs current31 on the continuously held Create Storage Session.
    ///
    /// # Errors
    /// Retains changed genuine Start/Root/Create association and all IO/post refusals.
    pub fn prepare_storage_once_v2(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox_controller_domain::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        session.prepare_storage_once_v2(self, original, prepared)
    }

    pub(crate) fn prepare_storage_inner_once_v2(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox_controller_domain::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.inner.apply.kind, ProvisioningKindV4::StartStorage) {
            return Err(OutputPreparationClosedV1);
        }
        self.inner.run_member_once_v4(session, original, prepared, false)
    }

    /// Runs fresh18 after the same owner's actual current31 terminal.
    ///
    /// # Errors
    /// Refuses another purpose, unfinished current31, native or currentness failure.
    pub fn inventory_storage_once_v2(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox_controller_domain::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        session.inventory_storage_once_v2(self, original, prepared)
    }

    pub(crate) fn inventory_storage_inner_once_v2(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox_controller_domain::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.inner.inventory.kind, ProvisioningKindV4::StartStorage) {
            return Err(OutputPreparationClosedV1);
        }
        self.inner.run_member_once_v4(session, original, prepared, true)
    }

    /// Retires only fresh31/18 operation owners after genuine Root completion.
    ///
    /// The continuously held Create Session is neither replaced nor dropped.
    /// Its descriptors and history stay in the same global Start invoice.
    ///
    /// # Errors
    /// Refuses changed packets/native boundary, unfinished posts or foreign completion.
    pub fn dispose_completed_storage_once_v2(
        &mut self,
        prepared: &mut aos_sandbox_controller_domain::PreparedStartResourceRequestOriginalV2,
        completed: &aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
        entry: &mut aos_sandbox_controller_domain::AcceptedStartEntryOriginalV1,
        controller: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.inner.apply.kind, ProvisioningKindV4::StartStorage) {
            return Err(OutputPreparationClosedV1);
        }
        let actual = self.completed_exchange_data_v2()?;
        let recorded = completed.comparison_data_v2();
        if actual.resource_request != recorded.resource_request
            || actual.resource_outcome != recorded.resource_outcome
            || actual.inventory_request != recorded.inventory_request
            || actual.inventory_outcome != recorded.inventory_outcome
            || actual.session_native != recorded.session_native {
            return Err(OutputPreparationClosedV1);
        }
        let retained_model_bytes = self.retain_completed_models_once_v2(completed)?;
        let disposition = entry.prepare_completed_storage_upper_disposal_v2(
            prepared, completed, controller, retained_model_bytes).map_err(|_| OutputPreparationClosedV1)?;
        // Dispose the actual two completed flights before releasing their same
        // Domain stages. No part of the independently held Session is touched.
        self.retire_completed_flights_v2();
        disposition.complete_after_sdk_disposal_v2().map_err(|_| OutputPreparationClosedV1)
    }

    /// Borrows the actual sole-decoded current304 and immutable physical proof.
    #[must_use]
    pub fn completed_storage_guest_root_result_v2(&self)
        -> Option<&aos_sandbox_protocol::semantics::storage_guest_root::StorageGuestRootResponseDataV2> {
        if !matches!(self.inner.apply.kind, ProvisioningKindV4::StartStorage)
            || self.failure().is_some() { return None; }
        self.completed_prepare_outcome_v4()?;
        self.inner.apply.outcome.as_ref()?.retained_storage_guest_root_response_data_v2()
    }

    /// Borrows the same sole decoder's complete fresh18 semantic and raw inventory.
    #[must_use]
    pub fn completed_storage_inventory_model_v2(&self)
        -> Option<&(ValidatedStorageInventory, InventoryStorageResourcesResponse)> {
        if !matches!(self.inner.inventory.kind, ProvisioningKindV4::StartStorage)
            || self.failure().is_some() { return None; }
        self.completed_inventory_outcome_v4()?;
        self.inner.inventory.outcome.as_ref()?.retained_storage_inventory_response_data_v1()
    }

}
