//! Host-side access to one VM's lossless QEMU fault transport.

use crucible_shmem::{
    DequeuedFaultEvent, DequeuedFaultResult, FaultCommandHeaderV1, dequeue_fault_event,
    dequeue_fault_result, enqueue_fault_command, fault_event_count, fault_event_pending,
    snapshot_fault_events,
};

use super::{QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError};

impl QemuMappedQuantumShmemHotPath {
    /// Publishes one authenticated command to this VM's plugin bridge.
    ///
    /// The command and payload become visible atomically through the dedicated
    /// host-producer/plugin-consumer ring. The plugin copies them before calling
    /// QEMU, so callers may release `payload` after this method returns.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the VM transport is
    /// absent, full, corrupt, or the command envelope violates the public ABI.
    pub fn enqueue_fault_command(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuMappedQuantumShmemHotPathError> {
        let transport = self
            .region
            .fault_command_transport_mut(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
        enqueue_fault_command(
            transport.ring,
            transport.slots,
            transport.arena_header,
            transport.arena,
            transport.arena_region_offset,
            header,
            payload,
        )
        .map_err(|source| QemuMappedQuantumShmemHotPathError::FaultTransport { source })
    }

    /// Removes one completed QEMU fault result from this VM's plugin bridge.
    ///
    /// An ABI-invalid result is returned as [`DequeuedFaultResult::Invalid`]
    /// after its sound transport reservation is released. Production callers
    /// must fail the run rather than treating that variant as a guest outcome.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the VM transport is
    /// absent or its ring/arena framing is corrupt.
    pub fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<DequeuedFaultResult>, QemuMappedQuantumShmemHotPathError> {
        let transport = self
            .region
            .fault_result_transport_mut(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
        dequeue_fault_result(
            transport.ring,
            transport.slots,
            transport.arena_header,
            transport.arena,
            transport.arena_region_offset,
        )
        .map_err(|source| QemuMappedQuantumShmemHotPathError::FaultTransport { source })
    }

    /// Removes one authenticated QEMU fault-rule event from this VM's bridge.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the VM transport is
    /// absent or event framing, sequencing metadata, or evidence authentication
    /// is invalid.
    pub fn dequeue_fault_event(
        &mut self,
    ) -> Result<Option<DequeuedFaultEvent>, QemuMappedQuantumShmemHotPathError> {
        let transport = self
            .region
            .fault_event_transport_mut(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
        dequeue_fault_event(
            transport.ring,
            transport.slots,
            transport.arena_header,
            transport.arena,
            transport.arena_region_offset,
        )
        .map_err(|source| QemuMappedQuantumShmemHotPathError::FaultEvent { source })
    }

    /// Reports whether an event is waiting without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] for absent or corrupt
    /// event transport geometry.
    pub fn fault_event_pending(&mut self) -> Result<bool, QemuMappedQuantumShmemHotPathError> {
        let transport = self
            .region
            .fault_event_transport_mut(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
        fault_event_pending(transport.ring, transport.slots)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::FaultTransport { source })
    }

    /// Returns the number of published events without consuming them.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] for absent or corrupt
    /// event transport geometry.
    pub fn fault_event_count(&mut self) -> Result<usize, QemuMappedQuantumShmemHotPathError> {
        let transport = self
            .region
            .fault_event_transport_mut(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
        fault_event_count(transport.ring, transport.slots)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::FaultTransport { source })
    }

    /// Authenticates and copies published events without releasing transport ownership.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the transport is
    /// absent or corrupt, destination storage is insufficient, or event
    /// evidence does not authenticate.
    pub fn snapshot_fault_events(
        &mut self,
        destination: &mut Vec<DequeuedFaultEvent>,
        canonical_payload_bytes: &mut usize,
        configured_payload_bytes: usize,
        configured_inline_payload_bytes: usize,
    ) -> Result<(), QemuMappedQuantumShmemHotPathError> {
        let transport = self
            .region
            .fault_event_transport_mut(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
        snapshot_fault_events(
            transport.ring,
            transport.slots,
            transport.arena_header,
            transport.arena,
            transport.arena_region_offset,
            destination,
            canonical_payload_bytes,
            configured_payload_bytes,
            configured_inline_payload_bytes,
        )
        .map_err(|source| QemuMappedQuantumShmemHotPathError::FaultEvent { source })
    }
}
