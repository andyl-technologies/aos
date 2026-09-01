//! Mapped fault command, result, and event transports.

use super::*;

impl MappedSetupRegion {
    /// Borrows one VM's host-to-plugin fault command transport.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` is not a logical VM, or any transport segment is out
    /// of bounds or misaligned.
    pub fn fault_command_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultCommandTransportMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        validate_fault_vm_slot(layout, vm_slot, "fault command transport")?;
        let ring_offset = mapped_fault_ring_header_offset(
            layout.fault_command_ring_hdr_off,
            layout.fault_command_ring_count,
            self.len,
            vm_slot,
            "fault command ring header",
        )?;
        let slots_offset = mapped_fault_slot_offset(
            layout.fault_command_slot_off,
            layout.fault_command_ring_count,
            layout.fault_command_queue_capacity,
            FAULT_COMMAND_SLOT_V1_BYTES,
            self.len,
            vm_slot,
            "fault command slot",
        )?;
        let arena_header_offset = mapped_fault_arena_header_offset(
            layout.fault_command_arena_hdr_off,
            layout.fault_command_ring_count,
            self.len,
            vm_slot,
            "fault command arena header",
        )?;
        let arena_offset = mapped_fault_arena_offset(
            layout.fault_command_arena_off,
            layout.fault_command_arena_stride,
            layout.fault_command_ring_count,
            self.len,
            vm_slot,
            "fault command arena",
        )?;
        let slot_count = usize::try_from(layout.fault_command_queue_capacity).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault command slot",
                index: vm_slot,
            }
        })?;
        let arena_len = usize::try_from(layout.fault_command_arena_stride).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault command arena",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: the helpers validate complete, pairwise-disjoint aligned
        // ranges for this VM. The exclusive mapping borrow prevents another
        // safe mutable transport view while these slices are live.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                &*base.add(ring_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(slots_offset).cast::<FaultCommandSlotV1>(),
                    slot_count,
                ),
                &*base
                    .add(arena_header_offset)
                    .cast::<FaultPayloadArenaHeader>(),
                core::slice::from_raw_parts_mut(base.add(arena_offset), arena_len),
            )
        };
        Ok(MappedFaultCommandTransportMut {
            vm_slot,
            ring,
            slots,
            arena_header,
            arena,
            arena_region_offset: layout.fault_command_arena_off
                + u64::from(vm_slot) * layout.fault_command_arena_stride,
        })
    }

    /// Borrows one VM's plugin-to-host fault result transport.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` is not a logical VM, or any transport segment is out
    /// of bounds or misaligned.
    pub fn fault_result_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultResultTransportMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        validate_fault_vm_slot(layout, vm_slot, "fault result transport")?;
        let ring_offset = mapped_fault_ring_header_offset(
            layout.fault_result_ring_hdr_off,
            layout.fault_result_ring_count,
            self.len,
            vm_slot,
            "fault result ring header",
        )?;
        let slots_offset = mapped_fault_slot_offset(
            layout.fault_result_slot_off,
            layout.fault_result_ring_count,
            layout.fault_result_queue_capacity,
            FAULT_RESULT_SLOT_V1_BYTES,
            self.len,
            vm_slot,
            "fault result slot",
        )?;
        let arena_header_offset = mapped_fault_arena_header_offset(
            layout.fault_result_arena_hdr_off,
            layout.fault_result_ring_count,
            self.len,
            vm_slot,
            "fault result arena header",
        )?;
        let arena_offset = mapped_fault_arena_offset(
            layout.fault_result_arena_off,
            layout.fault_result_arena_stride,
            layout.fault_result_ring_count,
            self.len,
            vm_slot,
            "fault result arena",
        )?;
        let slot_count = usize::try_from(layout.fault_result_queue_capacity).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault result slot",
                index: vm_slot,
            }
        })?;
        let arena_len = usize::try_from(layout.fault_result_arena_stride).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault result arena",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: the helpers validate complete, pairwise-disjoint aligned
        // ranges for this VM. The exclusive mapping borrow prevents another
        // safe mutable transport view while these slices are live.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                &*base.add(ring_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(slots_offset).cast::<FaultResultSlotV1>(),
                    slot_count,
                ),
                &*base
                    .add(arena_header_offset)
                    .cast::<FaultPayloadArenaHeader>(),
                core::slice::from_raw_parts_mut(base.add(arena_offset), arena_len),
            )
        };
        Ok(MappedFaultResultTransportMut {
            vm_slot,
            ring,
            slots,
            arena_header,
            arena,
            arena_region_offset: layout.fault_result_arena_off
                + u64::from(vm_slot) * layout.fault_result_arena_stride,
        })
    }

    /// Borrows one VM's plugin-to-host fault rule-event transport.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` is not a logical VM, or any event transport segment
    /// is out of bounds or misaligned.
    pub fn fault_event_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultEventTransportMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        validate_fault_vm_slot(layout, vm_slot, "fault event transport")?;
        let ring_offset = mapped_fault_ring_header_offset(
            layout.fault_event_ring_hdr_off,
            layout.fault_event_ring_count,
            self.len,
            vm_slot,
            "fault event ring header",
        )?;
        let slots_offset = mapped_fault_slot_offset(
            layout.fault_event_slot_off,
            layout.fault_event_ring_count,
            layout.fault_event_queue_capacity,
            FAULT_EVENT_SLOT_V1_BYTES,
            self.len,
            vm_slot,
            "fault event slot",
        )?;
        let arena_header_offset = mapped_fault_arena_header_offset(
            layout.fault_event_arena_hdr_off,
            layout.fault_event_ring_count,
            self.len,
            vm_slot,
            "fault event arena header",
        )?;
        let arena_offset = mapped_fault_arena_offset(
            layout.fault_event_arena_off,
            layout.fault_event_arena_stride,
            layout.fault_event_ring_count,
            self.len,
            vm_slot,
            "fault event arena",
        )?;
        let slot_count = usize::try_from(layout.fault_event_queue_capacity).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault event slot",
                index: vm_slot,
            }
        })?;
        let arena_len = usize::try_from(layout.fault_event_arena_stride).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault event arena",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: all event transport ranges are validated, aligned, and
        // disjoint; the exclusive mapping borrow prevents another mutable view.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                &*base.add(ring_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(slots_offset).cast::<FaultEventSlotV1>(),
                    slot_count,
                ),
                &*base
                    .add(arena_header_offset)
                    .cast::<FaultPayloadArenaHeader>(),
                core::slice::from_raw_parts_mut(base.add(arena_offset), arena_len),
            )
        };
        Ok(MappedFaultEventTransportMut {
            vm_slot,
            ring,
            slots,
            arena_header,
            arena,
            arena_region_offset: layout.fault_event_arena_off
                + u64::from(vm_slot) * layout.fault_event_arena_stride,
        })
    }
}
