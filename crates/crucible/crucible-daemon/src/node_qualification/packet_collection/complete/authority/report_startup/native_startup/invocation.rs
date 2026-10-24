//! Lends genuine original or archive-ticketed purpose to the Core startup issuer.
//!
//! The private holder variant supplies the choice. No caller enum, decoded
//! receipt, missing Query owner or resettable endpoint flag can select it.

use super::*;
use crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData;

impl InstalledPacketCompleteCollectionAuthority {
    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_native_invocation_data(
        &self,
        scope: &OriginalNativeStartupScope<'_>,
    ) -> Result<[PacketNativeInvocationPurposeData; 3], RuntimeError> {
        let original = self.original_native_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_scope_data(self, scope)?;
        let launch = scope.launches();
        let result = match &held.purpose {
            StartupHolderPurpose::OriginalScene => {
                self.host.authenticate_original_report_startup_data()?;
                [
                    PacketNativeInvocationPurposeData::original_execution_data(&launch[0])
                        .map_err(|_| RuntimeError::ForeignAuthority)?,
                    PacketNativeInvocationPurposeData::original_execution_data(&launch[1])
                        .map_err(|_| RuntimeError::ForeignAuthority)?,
                    PacketNativeInvocationPurposeData::original_execution_data(&launch[2])
                        .map_err(|_| RuntimeError::ForeignAuthority)?,
                ]
            }
            StartupHolderPurpose::FreshRestoration(capsule) => {
                let capsule = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
                capsule.original_native_invocation_data(self, &held.plan, launch)?
            }
        };
        held.authenticate_native_scope_data(self, scope)?;
        Ok(result)
    }
}
