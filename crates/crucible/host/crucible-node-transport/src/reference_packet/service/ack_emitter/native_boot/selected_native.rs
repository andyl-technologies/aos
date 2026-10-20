//! Selects a cold native grammar only from the actual Source-MAC-verified Prepare.
//!
//! The enum is data, not a capability. The installed input custody and its
//! genuine verified token remain mandatory at the only live dispatcher. Full
//! schema definitions and the immutable decoded native class are both checked;
//! FreshSome, a prefix string or a requested byte limit cannot select a reader.

use super::*;
use crate::protocol_snapshot::{
    RestorationMappingClass, owned11::outer::OwnedProtocol11DataLimits,
};

impl VerifiedCompleteRestorePrepare {
    pub(crate) fn original_selected_native_class_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<Option<RestorationMappingClass>, ProviderError> {
        self.authenticate_installation(connection)?;
        let class = {
            let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
            flight.authenticate_verified_metadata_data()?;
            let schema = &flight
                .request
                .as_ref()
                .ok_or_else(refused)?
                .restoration
                .backend_schema;
            match schema.id.as_str() {
                "source-owned.packet-native-continuation/13" => {
                    crate::reference_packet::service::native_snapshot::authenticate_native_owned13_snapshot_schema_data(schema)?;
                    Some(RestorationMappingClass::StartupCapture14)
                }
                "source-owned.packet-native-continuation/14" => {
                    crate::reference_packet::service::native_snapshot::authenticate_native_owned14_snapshot_schema_data(schema)?;
                    Some(RestorationMappingClass::InvocationCapture15)
                }
                // The old reader remains on its existing path. Unknown new
                // classes are never treated as one of these selected readers.
                _ => None,
            }
        };
        if let Some(class) = class {
            if self.policy.complete_restore_selection()
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || self.policy.fresh_restore_allocation_selection()
                    != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
                || self.policy.capture_allocation_selection()
                    != Some(crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12) {
                return Err(refused());
            }
            let boot = self.boot.try_borrow().map_err(|_| borrowed())?;
            boot.ensure_origin()?;
            if !boot.verified || boot.startup.is_none() {
                return Err(refused());
            }
            if class == RestorationMappingClass::InvocationCapture15 {
                boot.authenticate_original_invocation_prepare_target_data()?;
            }
        }
        self.authenticate_installation(connection)?;
        Ok(class)
    }

    pub(crate) fn original_selected_native_counter_scratch_data() -> usize {
        crate::reference_packet::service::native_snapshot::native_owned13_snapshot_schema_counter_scratch_data()
            + crate::reference_packet::service::native_snapshot::native_owned14_snapshot_schema_counter_scratch_data()
            + std::mem::size_of::<std::cell::Ref<'static, NativeCompleteRestorePrepareAttempt>>()
            + std::mem::size_of::<std::cell::Ref<'static, NativeAckBoot>>()
            + std::mem::size_of::<std::cell::Ref<'static, PacketCompleteRestorePrepareRequest>>()
            + 2 * std::mem::size_of::<OwnedProtocol11DataLimits>()
            + std::mem::size_of::<Option<OwnedProtocol11DataLimits>>()
            + std::mem::size_of::<(Option<RestorationMappingClass>, Option<OwnedProtocol11DataLimits>)>()
            + std::mem::size_of::<Option<RestorationMappingClass>>()
            + std::mem::size_of::<Result<Option<RestorationMappingClass>, ProviderError>>()
            + std::mem::size_of::<Result<OwnedProtocol11DataLimits, ProviderError>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
            + std::mem::size_of::<[usize; 4]>()
    }
}
