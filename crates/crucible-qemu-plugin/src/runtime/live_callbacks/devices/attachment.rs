//! Registration-time construction of the live device callback aggregate.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use crate::{PluginBlockIo, PluginDeviceIoFreeze, PluginNinePIo, PluginStorageHistoryLimits};

use super::{LiveDeviceCallbackError, LiveDeviceCallbackState, LiveDirectedRingPair};
use crate::runtime::live_callbacks::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};

impl LiveDeviceCallbackState {
    #[cfg(test)]
    pub(super) fn new(
        vm_slot: u32,
        block_rings: LiveDirectedRingPair,
        ninep_rings: LiveDirectedRingPair,
        accelerator_generation: u64,
        accelerator_rings: crucible_shmem::DetachedPluginAcceleratorRings,
    ) -> Result<Self, LiveDeviceCallbackError> {
        Self::new_with_history_limits(
            vm_slot,
            block_rings,
            ninep_rings,
            PluginStorageHistoryLimits::compiled_maximum(),
            accelerator_generation,
            accelerator_rings,
        )
    }

    pub(super) fn new_with_history_limits(
        vm_slot: u32,
        block_rings: LiveDirectedRingPair,
        ninep_rings: LiveDirectedRingPair,
        storage_history_limits: PluginStorageHistoryLimits,
        accelerator_generation: u64,
        accelerator_rings: crucible_shmem::DetachedPluginAcceleratorRings,
    ) -> Result<Self, LiveDeviceCallbackError> {
        let block = PluginBlockIo::from_directed_rings_with_history_limits(
            vm_slot,
            block_rings.outbound.descriptor,
            block_rings.inbound.descriptor,
            storage_history_limits,
        )
        .map_err(|source| LiveDeviceCallbackError::Block { source })?;
        let ninep = PluginNinePIo::from_directed_rings(
            vm_slot,
            ninep_rings.outbound.descriptor,
            ninep_rings.inbound.descriptor,
        )
        .map_err(|source| LiveDeviceCallbackError::NineP { source })?;
        Ok(Self {
            freeze: PluginDeviceIoFreeze::new(),
            block,
            block_rings,
            block_tokens: BTreeMap::new(),
            block_reissue_preserve: BTreeSet::new(),
            pending_block_event: None,
            ninep,
            ninep_rings,
            ninep_tokens: BTreeMap::new(),
            accelerator_generation,
            accelerator_rings,
            accelerator_pending: BTreeMap::new(),
            accelerator_completed: BTreeMap::new(),
            accelerator_cancelled: BTreeMap::new(),
            accelerator_restore_staging: None,
        })
    }
}

impl LiveVcpuTimeCallbackState {
    #[cfg(test)]
    pub(super) fn attach_devices(
        mut self,
        vm_slot: u32,
        block: LiveDirectedRingPair,
        ninep: LiveDirectedRingPair,
        accelerator_generation: u64,
        accelerator_rings: crucible_shmem::DetachedPluginAcceleratorRings,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        self = self.attach_devices_with_history_limits(
            vm_slot,
            block,
            ninep,
            PluginStorageHistoryLimits::compiled_maximum(),
            accelerator_generation,
            accelerator_rings,
        )?;
        Ok(self)
    }

    pub(in crate::runtime) fn attach_devices_with_history_limits(
        mut self,
        vm_slot: u32,
        block: LiveDirectedRingPair,
        ninep: LiveDirectedRingPair,
        storage_history_limits: PluginStorageHistoryLimits,
        accelerator_generation: u64,
        accelerator_rings: crucible_shmem::DetachedPluginAcceleratorRings,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        self.devices = Some(Mutex::new(
            LiveDeviceCallbackState::new_with_history_limits(
                vm_slot,
                block,
                ninep,
                storage_history_limits,
                accelerator_generation,
                accelerator_rings,
            )
            .map_err(LiveVcpuTimeCallbackError::live_device)?,
        ));
        Ok(self)
    }
}
