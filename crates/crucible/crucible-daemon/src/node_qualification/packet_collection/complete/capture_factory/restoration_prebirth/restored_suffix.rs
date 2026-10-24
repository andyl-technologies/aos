//! Quotes same-ticket immutable geometry without decoding historical owners.

use super::*;
use crucible_engine::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::service::{
    PacketNative5SourceLaunch,
    native_startup::{
        PacketNativeRestoredSuffixStartupStorageData,
        original_native_restored_suffix_startup_storage_data,
    },
};
use std::mem::size_of;

// This explicit borrowed view makes the complete callback layout countable.
// The outer method retains the same whole-capsule checks before and after all
// three ticket loans; this view cannot issue or retain a ticket.
struct OriginalSuffixTicketQuoteInputs<'a> {
    capsule: &'a PacketCompleteRestorationPrebirth,
    authority: &'a InstalledPacketCompleteCollectionAuthority,
    launches: &'a [PacketNative5SourceLaunch; 3],
    canonical_launches: &'a [Vec<u8>; 3],
    count: usize,
    maximum: usize,
}

impl OriginalSuffixTicketQuoteInputs<'_> {
    fn member(
        &self,
        index: usize,
    ) -> Result<PacketNativeRestoredSuffixStartupStorageData, RuntimeError> {
        let ticket = self.capsule.native[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let owner = ticket.owner()?;
        let source = &self.authority.roster().sources[index];
        let installed = source.installation();
        if owner.owner != installed.owner.owner.id
            || owner.participants != installed.owner.owner.participant_ids
            || !source.is_original_restored_suffix_declaration_data()?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let historical = ticket.native_restoration_construction_data()?;
        let geometry = historical
            .selected_owner_construction_data()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let result = original_native_restored_suffix_startup_storage_data(
            &self.launches[index],
            &self.canonical_launches[index],
            geometry,
            self.count,
            self.maximum,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        ticket.owner()?;
        Ok(result)
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn original_restored_suffix_startup_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launches: &[Vec<u8>; 3],
        count: usize,
        maximum: usize,
    ) -> Result<[PacketNativeRestoredSuffixStartupStorageData; 3], RuntimeError> {
        self.authenticate_native_startup_target_precredit_data(authority, plan)?;
        let inputs = OriginalSuffixTicketQuoteInputs {
            capsule: self,
            authority,
            launches,
            canonical_launches,
            count,
            maximum,
        };
        let result = [inputs.member(0)?, inputs.member(1)?, inputs.member(2)?];
        self.authenticate_native_startup_target_precredit_data(authority, plan)?;
        Ok(result)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn restored_suffix_startup_counter_scratch_data()
    -> usize {
        use crucible_engine::node_state::{
            CompleteOriginalNativeRestorationData, NativeOwnerState,
        };
        use crucible_node_transport::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage;
        size_of::<OriginalSuffixTicketQuoteInputs<'static>>()
            + size_of::<&OriginalSuffixTicketQuoteInputs<'static>>()
            + size_of::<&InstalledPacketCompleteCollectionAuthority>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<&Self>()
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<Option<&CompleteOriginalNativeTicket>>()
            + size_of::<&NativeOwnerState>()
            + size_of::<Result<&NativeOwnerState, RuntimeError>>()
            + size_of::<&CompleteOriginalNativeRestorationData>()
            + size_of::<Result<&CompleteOriginalNativeRestorationData, RuntimeError>>()
            + size_of::<&PacketCompleteRestoreOwnerValidationStorage>()
            + size_of::<Option<&PacketCompleteRestoreOwnerValidationStorage>>()
            + size_of::<Result<&PacketCompleteRestoreOwnerValidationStorage, RuntimeError>>()
            + size_of::<&[PacketNative5SourceLaunch; 3]>()
            + size_of::<&[Vec<u8>; 3]>()
            + size_of::<&[u8]>()
            + size_of::<[PacketNativeRestoredSuffixStartupStorageData; 3]>()
            + size_of::<PacketNativeRestoredSuffixStartupStorageData>()
            + size_of::<Result<PacketNativeRestoredSuffixStartupStorageData, RuntimeError>>()
            + size_of::<
                Result<
                    PacketNativeRestoredSuffixStartupStorageData,
                    crucible_node_transport::ProviderError,
                >,
            >()
            + size_of::<Result<[PacketNativeRestoredSuffixStartupStorageData; 3], RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + 3 * size_of::<usize>()
    }
}
