//! Model-side directed-frame and device-ring operations.

use super::*;

impl RegionAllocation {
    /// Enqueues a frame into the directed ring from `src_slot` to `dst_slot`.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC
    /// enqueue operation rejects the frame.
    pub fn enqueue_directed_frame(
        &mut self,
        src_slot: u32,
        dst_slot: u32,
        frame: &FrameEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        self.ring_headers[ring_index].enqueue(&mut self.frame_entries[entry_range], frame)?;
        Ok(())
    }

    /// Enqueues one plugin-produced coverage entry for `vm_slot`.
    ///
    /// This model helper uses the same SPSC publication primitive as the mapped
    /// plugin path and exists for cross-process transport tests.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the VM slot is absent, its
    /// fixed backing range cannot be represented, or the coverage ring rejects
    /// the entry.
    pub fn enqueue_coverage_entry(
        &mut self,
        vm_slot: u32,
        entry: CoverageEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        if vm_slot >= self.layout.coverage_ring_count {
            return Err(RegionAllocationAccessError::UnknownCoverageRing {
                vm_slot,
                vm_node_count: self.layout.vm_node_count,
            });
        }
        let ring_index = usize::try_from(vm_slot).map_err(|_error| {
            RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot }
        })?;
        let capacity = usize::try_from(self.layout.coverage_queue_capacity).map_err(|_error| {
            RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot }
        })?;
        let start = ring_index
            .checked_mul(capacity)
            .ok_or(RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot })?;
        let end = start
            .checked_add(capacity)
            .ok_or(RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot })?;
        if end > self.coverage_entries.len() {
            return Err(RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot });
        }
        self.coverage_ring_headers[ring_index]
            .enqueue_coverage(&mut self.coverage_entries[start..end], entry)?;
        Ok(())
    }

    /// Enqueues one plugin-produced white-box marker entry for `vm_slot`.
    ///
    /// This model helper uses the same observational SPSC publication primitive
    /// as the mapped plugin path.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the VM slot is absent, its
    /// fixed backing range cannot be represented, or the marker ring rejects
    /// the entry.
    pub fn enqueue_whitebox_marker_entry(
        &mut self,
        vm_slot: u32,
        entry: WhiteboxMarkerEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        if vm_slot >= self.layout.whitebox_marker_ring_count {
            return Err(RegionAllocationAccessError::UnknownWhiteboxMarkerRing {
                vm_slot,
                vm_node_count: self.layout.vm_node_count,
            });
        }
        let ring_index = usize::try_from(vm_slot).map_err(|_error| {
            RegionAllocationAccessError::WhiteboxMarkerEntryRangeOverflow { vm_slot }
        })?;
        let capacity =
            usize::try_from(self.layout.whitebox_marker_queue_capacity).map_err(|_error| {
                RegionAllocationAccessError::WhiteboxMarkerEntryRangeOverflow { vm_slot }
            })?;
        let start = ring_index
            .checked_mul(capacity)
            .ok_or(RegionAllocationAccessError::WhiteboxMarkerEntryRangeOverflow { vm_slot })?;
        let end = start
            .checked_add(capacity)
            .ok_or(RegionAllocationAccessError::WhiteboxMarkerEntryRangeOverflow { vm_slot })?;
        if end > self.whitebox_marker_entries.len() {
            return Err(RegionAllocationAccessError::WhiteboxMarkerEntryRangeOverflow { vm_slot });
        }
        self.whitebox_marker_ring_headers[ring_index]
            .enqueue_whitebox_marker(&mut self.whitebox_marker_entries[start..end], entry)?;
        Ok(())
    }

    /// Enqueues one host-produced guest-introspection request.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the VM slot is absent, the
    /// directional backing range overflows, or the SPSC queue rejects the entry.
    pub fn enqueue_guest_introspection_request(
        &mut self,
        vm_slot: u32,
        entry: GuestIntrospectionEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        self.enqueue_guest_introspection_entry(
            vm_slot,
            GuestIntrospectionRingDirection::Request,
            entry,
        )
    }

    /// Enqueues one plugin-produced guest-introspection response.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the VM slot is absent, the
    /// response backing range overflows, or the SPSC queue rejects the entry.
    pub fn enqueue_guest_introspection_response(
        &mut self,
        vm_slot: u32,
        entry: GuestIntrospectionEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        self.enqueue_guest_introspection_entry(
            vm_slot,
            GuestIntrospectionRingDirection::Response,
            entry,
        )
    }

    fn enqueue_guest_introspection_entry(
        &mut self,
        vm_slot: u32,
        direction: GuestIntrospectionRingDirection,
        entry: GuestIntrospectionEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        let (ring_index, range) = self.guest_introspection_entry_range(vm_slot, direction)?;
        self.guest_introspection_ring_headers[ring_index]
            .enqueue_guest_introspection(&mut self.guest_introspection_entries[range], entry)?;
        Ok(())
    }

    /// Dequeues one host-produced guest-introspection request for the plugin.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the VM slot is absent, the
    /// directional backing range overflows, or the SPSC queue is corrupt.
    pub fn dequeue_guest_introspection_request(
        &self,
        vm_slot: u32,
    ) -> Result<Option<GuestIntrospectionEntry>, RegionAllocationAccessError> {
        self.dequeue_guest_introspection_entry(vm_slot, GuestIntrospectionRingDirection::Request)
    }

    /// Dequeues one plugin-produced guest-introspection response for the host.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the VM slot is absent, the
    /// response backing range overflows, or the SPSC queue is corrupt.
    pub fn dequeue_guest_introspection_response(
        &self,
        vm_slot: u32,
    ) -> Result<Option<GuestIntrospectionEntry>, RegionAllocationAccessError> {
        self.dequeue_guest_introspection_entry(vm_slot, GuestIntrospectionRingDirection::Response)
    }

    fn dequeue_guest_introspection_entry(
        &self,
        vm_slot: u32,
        direction: GuestIntrospectionRingDirection,
    ) -> Result<Option<GuestIntrospectionEntry>, RegionAllocationAccessError> {
        let (ring_index, range) = self.guest_introspection_entry_range(vm_slot, direction)?;
        Ok(self.guest_introspection_ring_headers[ring_index]
            .dequeue_guest_introspection(&self.guest_introspection_entries[range])?)
    }
}
