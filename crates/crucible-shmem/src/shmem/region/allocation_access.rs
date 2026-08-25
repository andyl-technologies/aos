//! Region construction and typed allocation accessors.

use super::*;

impl RegionAllocation {
    /// Allocates and initializes a typed shared-memory region model.
    ///
    /// # Errors
    ///
    /// Returns [`RegionLayoutError`] if the compiled target is not the pinned
    /// ABI layout target, the requested layout is invalid, or a computed count
    /// cannot fit in memory indexes on this host.
    pub fn new(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        validate_layout_target()?;
        Self::new_model(config)
    }

    /// Allocates and initializes a typed shared-memory model without target validation.
    ///
    /// This constructor is for in-process harnesses that need the canonical
    /// slot, ring, and frame-entry topology on developer hosts that are not the
    /// pinned ABI target. Use [`Self::new`] when the allocation is evidence for
    /// the mapped shared-memory ABI on the pinned target.
    ///
    /// # Errors
    ///
    /// Returns [`RegionLayoutError`] if the requested layout is invalid or a
    /// computed count cannot fit in memory indexes on this host.
    pub fn new_model(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        let layout = RegionLayout::for_config(config)?;
        let header = RegionHeader::new(layout);
        let slots = (0..MAX_NODES)
            .map(|slot| node_slot_for_physical_index(layout.vm_node_count, slot))
            .collect::<Vec<_>>();
        let ring_headers = (0..layout.ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let entry_count = usize::try_from(layout.frame_entry_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let frame_entries = (0..entry_count)
            .map(|_| FrameEntry::default())
            .collect::<Vec<_>>();
        let rings = directed_rings(layout.vm_node_count)?;
        let coverage_ring_headers = (0..layout.coverage_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let coverage_entry_count = usize::try_from(layout.coverage_entry_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let coverage_entries = (0..coverage_entry_count)
            .map(|_| CoverageEntry::default())
            .collect::<Vec<_>>();
        let whitebox_marker_ring_headers = (0..layout.whitebox_marker_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let whitebox_marker_entry_count = usize::try_from(layout.whitebox_marker_entry_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let whitebox_marker_entries = (0..whitebox_marker_entry_count)
            .map(|_| WhiteboxMarkerEntry::default())
            .collect::<Vec<_>>();
        let fault_command_ring_headers = (0..layout.fault_command_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let fault_command_slot_count = usize::try_from(layout.fault_command_slot_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let fault_command_slots = vec![FaultCommandSlotV1::new(); fault_command_slot_count];
        let fault_command_arena_headers = (0..layout.fault_command_ring_count)
            .map(|_| FaultPayloadArenaHeader::new())
            .collect::<Vec<_>>();
        let fault_command_arena_len = usize::try_from(
            u64::from(layout.fault_command_ring_count)
                .checked_mul(layout.fault_command_arena_stride)
                .ok_or(RegionLayoutError::GeometryOverflow)?,
        )
        .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let fault_command_arena_bytes = vec![0; fault_command_arena_len];
        let fault_result_ring_headers = (0..layout.fault_result_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let fault_result_slot_count = usize::try_from(layout.fault_result_slot_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let fault_result_slots = vec![FaultResultSlotV1::new(); fault_result_slot_count];
        let fault_result_arena_headers = (0..layout.fault_result_ring_count)
            .map(|_| FaultPayloadArenaHeader::new())
            .collect::<Vec<_>>();
        let fault_result_arena_len = usize::try_from(
            u64::from(layout.fault_result_ring_count)
                .checked_mul(layout.fault_result_arena_stride)
                .ok_or(RegionLayoutError::GeometryOverflow)?,
        )
        .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let fault_result_arena_bytes = vec![0; fault_result_arena_len];
        let fault_event_ring_headers = (0..layout.fault_event_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let fault_event_slot_count = usize::try_from(layout.fault_event_slot_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let fault_event_slots = vec![FaultEventSlotV1::new(); fault_event_slot_count];
        let fault_event_arena_headers = (0..layout.fault_event_ring_count)
            .map(|_| FaultPayloadArenaHeader::new())
            .collect::<Vec<_>>();
        let fault_event_arena_len = usize::try_from(
            u64::from(layout.fault_event_ring_count)
                .checked_mul(layout.fault_event_arena_stride)
                .ok_or(RegionLayoutError::GeometryOverflow)?,
        )
        .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let fault_event_arena_bytes = vec![0; fault_event_arena_len];
        let guest_introspection_ring_headers = (0..layout.guest_introspection_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let guest_introspection_entry_count =
            usize::try_from(layout.guest_introspection_entry_count())
                .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let guest_introspection_entries = (0..guest_introspection_entry_count)
            .map(|_| GuestIntrospectionEntry::default())
            .collect::<Vec<_>>();
        let accelerator_ring_headers = (0..layout.accelerator_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let accelerator_entry_count = usize::try_from(layout.accelerator_entry_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let accelerator_entries = (0..accelerator_entry_count)
            .map(|_| AcceleratorEntry::default())
            .collect::<Vec<_>>();
        let selectable_reply_ring_headers = (0..layout.selectable_reply_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let selectable_reply_entry_count = usize::try_from(layout.selectable_reply_entry_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let selectable_reply_entries = (0..selectable_reply_entry_count)
            .map(|_| WhiteboxMarkerEntry::default())
            .collect::<Vec<_>>();

        Ok(Self {
            header,
            slots,
            ring_headers,
            frame_entries,
            coverage_ring_headers,
            coverage_entries,
            whitebox_marker_ring_headers,
            whitebox_marker_entries,
            fault_command_ring_headers,
            fault_command_slots,
            fault_command_arena_headers,
            fault_command_arena_bytes,
            fault_result_ring_headers,
            fault_result_slots,
            fault_result_arena_headers,
            fault_result_arena_bytes,
            fault_event_ring_headers,
            fault_event_slots,
            fault_event_arena_headers,
            fault_event_arena_bytes,
            guest_introspection_ring_headers,
            guest_introspection_entries,
            accelerator_ring_headers,
            accelerator_entries,
            selectable_reply_ring_headers,
            selectable_reply_entries,
            rings,
            layout,
        })
    }

    /// Returns the initialized region header.
    #[must_use]
    pub fn header(&self) -> &RegionHeader {
        &self.header
    }

    /// Returns the fixed physical node slot array.
    #[must_use]
    pub fn slots(&self) -> &[NodeSlot] {
        &self.slots
    }

    /// Returns the directed ring headers.
    #[must_use]
    pub fn ring_headers(&self) -> &[RingHeader] {
        &self.ring_headers
    }

    /// Returns the frame-entry backing storage.
    #[must_use]
    pub fn frame_entries(&self) -> &[FrameEntry] {
        &self.frame_entries
    }

    /// Returns the plugin-to-host coverage ring headers.
    #[must_use]
    pub fn coverage_ring_headers(&self) -> &[RingHeader] {
        &self.coverage_ring_headers
    }

    /// Returns the plugin-to-host coverage-entry backing storage.
    #[must_use]
    pub fn coverage_entries(&self) -> &[CoverageEntry] {
        &self.coverage_entries
    }

    /// Returns the plugin-to-host white-box marker ring headers.
    #[must_use]
    pub fn whitebox_marker_ring_headers(&self) -> &[RingHeader] {
        &self.whitebox_marker_ring_headers
    }

    /// Returns the plugin-to-host white-box marker-entry backing storage.
    #[must_use]
    pub fn whitebox_marker_entries(&self) -> &[WhiteboxMarkerEntry] {
        &self.whitebox_marker_entries
    }

    /// Returns the host-to-plugin selectable-reply ring headers.
    #[must_use]
    pub fn selectable_reply_ring_headers(&self) -> &[RingHeader] {
        &self.selectable_reply_ring_headers
    }

    /// Returns the host-to-plugin selectable-reply entry storage.
    #[must_use]
    pub fn selectable_reply_entries(&self) -> &[WhiteboxMarkerEntry] {
        &self.selectable_reply_entries
    }

    /// Returns the host-to-plugin fault command ring headers.
    #[must_use]
    pub fn fault_command_ring_headers(&self) -> &[RingHeader] {
        &self.fault_command_ring_headers
    }

    /// Returns the fault command slot backing storage.
    #[must_use]
    pub fn fault_command_slots(&self) -> &[FaultCommandSlotV1] {
        &self.fault_command_slots
    }

    /// Returns the command payload-arena headers.
    #[must_use]
    pub fn fault_command_arena_headers(&self) -> &[FaultPayloadArenaHeader] {
        &self.fault_command_arena_headers
    }

    /// Returns the command payload-arena backing bytes.
    #[must_use]
    pub fn fault_command_arena_bytes(&self) -> &[u8] {
        &self.fault_command_arena_bytes
    }

    /// Returns the plugin-to-host fault result ring headers.
    #[must_use]
    pub fn fault_result_ring_headers(&self) -> &[RingHeader] {
        &self.fault_result_ring_headers
    }

    /// Returns the fault result slot backing storage.
    #[must_use]
    pub fn fault_result_slots(&self) -> &[FaultResultSlotV1] {
        &self.fault_result_slots
    }

    /// Returns the result payload-arena headers.
    #[must_use]
    pub fn fault_result_arena_headers(&self) -> &[FaultPayloadArenaHeader] {
        &self.fault_result_arena_headers
    }

    /// Returns the result payload-arena backing bytes.
    #[must_use]
    pub fn fault_result_arena_bytes(&self) -> &[u8] {
        &self.fault_result_arena_bytes
    }

    /// Returns the plugin-to-host fault event ring headers.
    #[must_use]
    pub fn fault_event_ring_headers(&self) -> &[RingHeader] {
        &self.fault_event_ring_headers
    }

    /// Returns the fault event slot backing storage.
    #[must_use]
    pub fn fault_event_slots(&self) -> &[FaultEventSlotV1] {
        &self.fault_event_slots
    }

    /// Returns the event payload-arena headers.
    #[must_use]
    pub fn fault_event_arena_headers(&self) -> &[FaultPayloadArenaHeader] {
        &self.fault_event_arena_headers
    }

    /// Returns the event payload-arena backing bytes.
    #[must_use]
    pub fn fault_event_arena_bytes(&self) -> &[u8] {
        &self.fault_event_arena_bytes
    }

    /// Returns the bidirectional guest-introspection ring headers.
    #[must_use]
    pub fn guest_introspection_ring_headers(&self) -> &[RingHeader] {
        &self.guest_introspection_ring_headers
    }

    /// Returns the guest-introspection entry backing storage.
    #[must_use]
    pub fn guest_introspection_entries(&self) -> &[GuestIntrospectionEntry] {
        &self.guest_introspection_entries
    }

    /// Returns the deterministic directed-ring map.
    #[must_use]
    pub fn rings(&self) -> &[DirectedRing] {
        &self.rings
    }

    /// Returns the computed region layout.
    #[must_use]
    pub fn layout(&self) -> RegionLayout {
        self.layout
    }

    /// Returns a node slot by physical slot index.
    #[must_use]
    pub fn node_slot(&self, slot_index: u32) -> Option<&NodeSlot> {
        usize::try_from(slot_index)
            .ok()
            .and_then(|index| self.slots.get(index))
    }
}
