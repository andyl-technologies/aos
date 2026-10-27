//! Retains the closed workflow's authentic original park caller for its executor.
//!
//! The issuer passes its actual Preparation and workflow decoder before factory
//! construction. The precreated body and its external credit survive executor
//! clones; no ordinary attempt supervisor or configuration scalar can mint it.

use std::alloc::Layout;
use std::sync::Arc;

use crucible_engine::owned_decode::DecodeScratch;
use crucible_host_resources::host_supervision::HostSupervisionError;
use crucible_qemu_host::{
    OriginalActorAccountError, OriginalActorDecodeOwner, OriginalActorParkCallerLease,
};
use crucible_ram::ResourceLoan;

use super::OriginalPreparation;

struct ParkCallerState {
    original: OriginalPreparation,
    decoder: OriginalActorParkCallerLease,
}

/// Keeps the same actor Preparation and decoder loan outside executor effects.
#[derive(Clone)]
pub(crate) struct OriginalPackagedParkCaller {
    state: Arc<ParkCallerState>,
    // The last actual state/control closes before this shared credit refunds.
    _credit: ResourceLoan,
}

impl std::fmt::Debug for OriginalPackagedParkCaller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalPackagedParkCaller")
            .finish_non_exhaustive()
    }
}

impl OriginalPreparation {
    pub(crate) fn retain_packaged_park_caller(
        &self,
        decoder: &OriginalActorDecodeOwner,
    ) -> Result<OriginalPackagedParkCaller, OriginalActorAccountError> {
        decoder.verify_parent_park_preparation(&self.original)?;
        let loan = decoder.retain_parent_park_caller(&self.original)?;
        let budget = loan.caller().budget()?;
        let (layout, _) = Layout::new::<(usize, usize)>()
            .extend(Layout::new::<ParkCallerState>())
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let bytes = layout
            .pad_to_align()
            .size()
            .checked_add(2 * std::mem::size_of::<Self>())
            .and_then(|bytes| {
                bytes.checked_add(2 * std::mem::size_of::<OriginalPackagedParkCaller>())
            })
            .and_then(|bytes| {
                bytes.checked_add(ResourceLoan::allocation_bytes::<DecodeScratch>() as usize)
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let credit = budget
            .reserve_scratch_array::<u8>(bytes)
            .map_err(OriginalActorAccountError::Decode)?;
        let caller = OriginalPackagedParkCaller {
            state: Arc::new(ParkCallerState {
                original: self.clone(),
                decoder: loan,
            }),
            _credit: ResourceLoan::new(credit),
        };
        caller.verify_original()?;
        Ok(caller)
    }
}

impl OriginalPackagedParkCaller {
    pub(crate) fn verify_original(&self) -> Result<(), OriginalActorAccountError> {
        self.state
            .decoder
            .caller()
            .verify_parent_park_preparation(&self.state.original.original)
    }

    pub(crate) fn original_after(&self) -> Option<HostSupervisionError> {
        self.state.original.boundary().err()
    }

    pub(crate) fn reserve_session_storage(
        &self,
        bytes: usize,
    ) -> Result<DecodeScratch, OriginalActorAccountError> {
        self.verify_original()?;
        self.state
            .decoder
            .caller()
            .budget()?
            .reserve_scratch_array::<u8>(bytes)
            .map_err(OriginalActorAccountError::Decode)
    }

    pub(crate) fn begin_retained_world(
        &self,
        world: &mut crate::ProductionVmHotForkSourceWorld,
        node: &crucible_engine::NodeId,
        correlation: u64,
    ) -> Result<crucible_qemu_host::QmpParentParkResult, crate::ProductionVmParentParkDrainRefusal> {
        self.verify_original()?;
        world.begin_parent_park_retained(
            node,
            &self.state.original.original,
            self.state.decoder.caller(),
            correlation,
        )
    }
}

/// Creates only controlled host originals for negative pool-custody tests.
///
/// This fixture has no admitted process, native slot or stage grant. The used
/// launcher must therefore refuse acquisition; the pool still retains its real
/// paid caller and original credits after that refusal.
#[cfg(test)]
pub(crate) fn controlled_park_caller_for_test() -> (
    OriginalPackagedParkCaller,
    OriginalActorDecodeOwner,
    crucible_host_resources::host_services::HostServiceAllocator,
    crucible_host_resources::host_services::HostServiceAllocator,
) {
    let crucible_qemu_host::ControlledOriginalActorParkFixture {
        original,
        supervisor,
        decoder,
        resident,
        metadata,
    } = crucible_qemu_host::ControlledOriginalActorParkFixture::prepare().unwrap();
    let preparation = OriginalPreparation {
        original,
        owner: supervisor,
    };
    let caller = preparation.retain_packaged_park_caller(&decoder).unwrap();
    (caller, decoder, resident, metadata)
}
