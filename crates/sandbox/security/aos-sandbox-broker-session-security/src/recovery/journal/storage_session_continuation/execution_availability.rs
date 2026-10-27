//! Lends actual required StorageBroker floor owners to the retained Session.
//!
//! These private operations use the same parked main, sidecar and authenticated
//! physical backend. A returned checkpoint is comparison DATA; the service
//! capsule must retain the whole Session and original financial loan.

use super::*;

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn reserve_storage_execution_availability_v3(&mut self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        let operation = BrokerFloorOperationV1::begin(&mut self.journal);
        let result = operation.floor.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?
            .reserve_storage_availability_receiving_v3(operation.owner, receiving, complete)
            .map_err(floor_revalidation::security_error);
        operation.finish(result)
    }

    pub(crate) fn observe_storage_execution_availability_v3(&mut self,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(tpm_floor::FloorProfileV1, crate::tpm_nv_custody::FloorCheckpointV1), BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        let mut operation = BrokerFloorOperationV1::begin(&mut self.journal);
        let result = operation.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .observe_storage_availability_receiving_v3(operation.owner, receiving)
            .map_err(floor_revalidation::security_error);
        operation.finish(result)
    }
}
