//! Borrows actual remote Session, financial and floor originals for method65.

use super::*;

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn reserve_storage_execution_availability_v3(&mut self,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>, complete: ResourceVector,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_storage_lifecycle_current_v1(receiving)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.owner.reserve_storage_execution_availability_v3(receiving, complete)
    }

    pub(crate) fn observe_storage_execution_availability_v3(&mut self,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(crate::tpm_nv_custody::FloorProfileV1, crate::tpm_nv_custody::FloorCheckpointV1), BrokerSessionSecurityError> {
        self.require_storage_lifecycle_current_v1(receiving)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.owner.observe_storage_execution_availability_v3(receiving)
    }
}
