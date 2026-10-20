//! Lends the continuously held Storage Session to closed Create and Start IO.

use super::*;
use aos_sandbox::CreateProvisioningStorageIoLoanV1;
use aos_sandbox_broker_session_security::controller_composition::{
    OutputPreparationClosedV1 as StorageProvisioningSessionIoClosedV1,
    StorageProvisioningSessionIoOriginalV1, StartResourceProvisioningSessionIoOriginalV4,
};

impl DormantStorageLifecycleInventoryOwnerV1 {
    pub(in crate::controller_service) fn apply_original_provisioning_once_v1(
        &mut self,
        destination: &mut StorageProvisioningSessionIoOriginalV1,
        original: &mut CreateProvisioningStorageIoLoanV1<'_>,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<(), StorageProvisioningSessionIoClosedV1> {
        destination.apply_once_v1(&mut self.0.session, original, prepared)
    }

    pub(in crate::controller_service) fn inventory_original_provisioning_once_v1(
        &mut self,
        destination: &mut StorageProvisioningSessionIoOriginalV1,
        original: &mut CreateProvisioningStorageIoLoanV1<'_>,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<(), StorageProvisioningSessionIoClosedV1> {
        destination.inventory_once_v1(&mut self.0.session, original, prepared)
    }
}

impl DormantStorageLifecycleInventoryOwnerV1 {
    pub(in crate::controller_service) fn borrow_source_workspace_original_v1<'models>(
        &'models self,
        flights: &'models StorageProvisioningSessionIoOriginalV1,
        context: &mut aos_sandbox::CreateProvisioningSourceWorkspaceContextV1<'_>,
    ) -> Result<aos_sandbox::StorageProvisioningWorkspaceOriginalV1<'models>,
        aos_sandbox::ResourceReservationErrorV1> {
        flights.borrow_source_workspace_original_v1(&self.0.session, context)
    }
}

impl DormantStorageLifecycleInventoryOwnerV1 {
    pub(in crate::controller_service) fn rejoin_original_start_storage_once_v2(
        &mut self,
        destination: &mut StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::OriginalStartHostRootLoanV1<'_, '_>,
        root: &aos_sandbox::normal_root::RootStartResourceCurrentTurnV2<'_>,
        previous: &aos_sandbox::CreateProvisioningOriginalsV1,
        controller: &aos_sandbox::Journal,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        destination.rejoin_storage_session_once_v2(
            &mut self.0.session, original, root, previous, controller,
        )
    }

    pub(in crate::controller_service) fn populate_original_start_storage_once_v2(
        &mut self,
        destination: &mut StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), StorageProvisioningSessionIoClosedV1> {
        destination.prepare_storage_once_v2(&mut self.0.session, original, prepared)
    }

    pub(in crate::controller_service) fn inventory_original_start_storage_once_v2(
        &mut self,
        destination: &mut StartResourceProvisioningSessionIoOriginalV4,
        original: &mut aos_sandbox::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), StorageProvisioningSessionIoClosedV1> {
        destination.inventory_storage_once_v2(&mut self.0.session, original, prepared)
    }
}
