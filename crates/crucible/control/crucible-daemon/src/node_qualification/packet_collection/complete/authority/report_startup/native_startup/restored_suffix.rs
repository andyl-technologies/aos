//! Lends the same ticket-derived suffix geometry under the registered holder.
//!
//! The scenario's actual maximum_operations supplies the finite count. The
//! controller request ceiling and carrier limit only refuse unsupported counts;
//! neither can enlarge or truncate the single global operation allowance.

use super::*;
use crucible_node_transport::reference_packet::service::native_startup::PacketNativeRestoredSuffixStartupStorageData;
use std::mem::size_of;

impl PacketCompleteReportStartupHolder {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn restored_suffix_startup_selected_data(
        &self,
    ) -> Result<bool, RuntimeError> {
        self.authenticate_native_origin_data()?;
        let fixed = Self::restored_suffix_selection_counter_scratch_data();
        let maximum = usize::try_from(self.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if fixed > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut selected = 0usize;
        for source in &self.authority.roster.sources {
            if source.is_original_restored_suffix_declaration_data()? {
                selected = selected.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        match selected {
            0 => Ok(false),
            3 => Ok(true),
            _ => Err(RuntimeError::ForeignAuthority),
        }
    }

    pub(super) fn restored_suffix_selection_counter_scratch_data() -> usize {
        crate::node_qualification::packet_collection::complete::InstalledCompleteRestoration::counter_scratch_data()
            + crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource::original_restored_suffix_declaration_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<std::slice::Iter<'static, Rc<crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource>>>()
            + size_of::<&Rc<crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<Option<usize>>()
            + 2 * size_of::<usize>()
    }

    pub(super) fn restored_suffix_holder_counter_scratch_data() -> usize {
        Self::restored_suffix_selection_counter_scratch_data()
            + PacketCompleteRestorationPrebirth::restored_suffix_startup_counter_scratch_data()
            + size_of::<Rc<RefCell<Self>>>()
            + size_of::<std::cell::Ref<'static, Self>>()
            + size_of::<Result<std::cell::Ref<'static, Self>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'static, Self>, RuntimeError>>()
            + size_of::<std::cell::Ref<'static, PacketCompleteRestorationPrebirth>>()
            + size_of::<
                Result<
                    std::cell::Ref<'static, PacketCompleteRestorationPrebirth>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<std::cell::Ref<'static, PacketCompleteRestorationPrebirth>, RuntimeError>,
            >()
            + size_of::<[PacketNativeRestoredSuffixStartupStorageData; 3]>()
            + size_of::<Result<[PacketNativeRestoredSuffixStartupStorageData; 3], RuntimeError>>()
            + size_of::<OriginalNativeStartupPolicy>()
            + size_of::<Result<OriginalNativeStartupPolicy, RuntimeError>>()
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_restored_suffix_startup_data(
        &self,
        scope: &OriginalNativeStartupScope<'_>,
    ) -> Result<[PacketNativeRestoredSuffixStartupStorageData; 3], RuntimeError> {
        let original = self.original_native_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_scope_data(self, scope)?;
        if !held.restored_suffix_startup_selected_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        let count = usize::try_from(held.resources.maximum_operations.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let maximum = held.native_policy_data()?.maximum_requested_bytes;
        let result = match &held.purpose {
            StartupHolderPurpose::FreshRestoration(capsule) => {
                let capsule = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
                capsule.original_restored_suffix_startup_data(
                    self,
                    &held.plan,
                    scope.launches(),
                    scope.encoded_launches(),
                    count,
                    maximum,
                )?
            }
            StartupHolderPurpose::OriginalScene => return Err(RuntimeError::ForeignAuthority),
        };
        held.authenticate_native_scope_data(self, scope)?;
        Ok(result)
    }
}
