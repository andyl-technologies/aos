//! Mapped guest-introspection, accelerator, and fingerprint views.

use super::*;

impl MappedSetupRegion {
    /// Borrows one VM's host-side guest-introspection role view.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when `vm_slot` is absent or the
    /// request or response segment is invalid.
    pub fn host_guest_introspection_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedHostGuestIntrospectionRingsMut<'_>, MappedSetupRegionAccessError> {
        let GuestIntrospectionRingPairMut { request, response } =
            self.guest_introspection_ring_pair_mut(vm_slot)?;
        Ok(MappedHostGuestIntrospectionRingsMut {
            requests: MappedGuestIntrospectionProducerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Request,
                header: request.header,
                entries: request.entries,
            },
            responses: MappedGuestIntrospectionConsumerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Response,
                header: response.header,
                entries: response.entries,
            },
        })
    }

    /// Borrows one VM's plugin-side guest-introspection role view.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when `vm_slot` is absent or the
    /// request or response segment is invalid.
    pub fn plugin_guest_introspection_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedPluginGuestIntrospectionRingsMut<'_>, MappedSetupRegionAccessError> {
        let GuestIntrospectionRingPairMut { request, response } =
            self.guest_introspection_ring_pair_mut(vm_slot)?;
        Ok(MappedPluginGuestIntrospectionRingsMut {
            requests: MappedGuestIntrospectionConsumerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Request,
                header: request.header,
                entries: request.entries,
            },
            responses: MappedGuestIntrospectionProducerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Response,
                header: response.header,
                entries: response.entries,
            },
        })
    }

    /// Borrows one VM's QEMU/plugin-side accelerator role pair.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the VM or either fixed
    /// shared-memory segment is invalid.
    pub fn plugin_accelerator_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedPluginAcceleratorRingsMut<'_>, MappedSetupRegionAccessError> {
        let (request_header, request_entries, completion_header, completion_entries) =
            self.accelerator_ring_pair_mut(vm_slot)?;
        Ok(MappedPluginAcceleratorRingsMut {
            requests: MappedAcceleratorProducerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Request,
                header: request_header,
                entries: request_entries,
            },
            completions: MappedAcceleratorConsumerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Completion,
                header: completion_header,
                entries: completion_entries,
            },
        })
    }

    /// Borrows one VM's host-side accelerator adapter role pair.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the VM or either fixed
    /// shared-memory segment is invalid.
    pub fn host_accelerator_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedHostAcceleratorRingsMut<'_>, MappedSetupRegionAccessError> {
        let (request_header, request_entries, completion_header, completion_entries) =
            self.accelerator_ring_pair_mut(vm_slot)?;
        Ok(MappedHostAcceleratorRingsMut {
            requests: MappedAcceleratorConsumerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Request,
                header: request_header,
                entries: request_entries,
            },
            completions: MappedAcceleratorProducerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Completion,
                header: completion_header,
                entries: completion_entries,
            },
        })
    }

    fn accelerator_ring_pair_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<AcceleratorRingPairMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        if vm_slot >= layout.vm_node_count {
            return Err(
                MappedSetupRegionAccessError::UnknownGuestIntrospectionRing {
                    vm_slot,
                    vm_node_count: layout.vm_node_count,
                },
            );
        }
        let request_index = AcceleratorRingDirection::Request
            .ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "accelerator ring",
                index: vm_slot,
            })?;
        let completion_index = AcceleratorRingDirection::Completion
            .ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "accelerator ring",
                index: vm_slot,
            })?;
        let request_header_offset =
            mapped_accelerator_ring_header_offset(layout, self.len, request_index)?;
        let completion_header_offset =
            mapped_accelerator_ring_header_offset(layout, self.len, completion_index)?;
        let request_entries_offset =
            mapped_accelerator_ring_entries_offset(layout, self.len, request_index)?;
        let completion_entries_offset =
            mapped_accelerator_ring_entries_offset(layout, self.len, completion_index)?;
        let count = usize::try_from(layout.accelerator_queue_capacity).map_err(|_error| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "accelerator entry",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: both offset helpers validate complete aligned ranges. The
        // request and completion indices are distinct and their fixed strides
        // cannot overlap; the exclusive mapping borrow prevents aliasing.
        Ok(unsafe {
            (
                &*base.add(request_header_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(request_entries_offset).cast::<AcceleratorEntry>(),
                    count,
                ),
                &*base.add(completion_header_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(completion_entries_offset)
                        .cast::<AcceleratorEntry>(),
                    count,
                ),
            )
        })
    }

    fn guest_introspection_ring_pair_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<GuestIntrospectionRingPairMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        if vm_slot >= layout.vm_node_count {
            return Err(
                MappedSetupRegionAccessError::UnknownGuestIntrospectionRing {
                    vm_slot,
                    vm_node_count: layout.vm_node_count,
                },
            );
        }
        let request_index = GuestIntrospectionRingDirection::Request
            .ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "guest-introspection ring",
                index: vm_slot,
            })?;
        let response_index = GuestIntrospectionRingDirection::Response
            .ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "guest-introspection ring",
                index: vm_slot,
            })?;
        let request_header_offset =
            mapped_guest_introspection_ring_header_offset(layout, self.len, request_index)?;
        let response_header_offset =
            mapped_guest_introspection_ring_header_offset(layout, self.len, response_index)?;
        let request_entries_offset =
            mapped_guest_introspection_ring_entries_offset(layout, self.len, request_index)?;
        let response_entries_offset =
            mapped_guest_introspection_ring_entries_offset(layout, self.len, response_index)?;
        let entry_count =
            usize::try_from(layout.guest_introspection_queue_capacity).map_err(|_error| {
                MappedSetupRegionAccessError::SegmentOffsetOverflow {
                    segment: "guest-introspection entry",
                    index: request_index,
                }
            })?;
        if request_header_offset == response_header_offset
            || request_entries_offset == response_entries_offset
        {
            return Err(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "guest-introspection ring",
                index: vm_slot,
            });
        }
        let base = self.base_ptr();
        // SAFETY: the offset helpers validate every complete aligned range in
        // this owned mapping. Request and response indices are distinct and
        // each fixed-size segment uses its ring index as a non-overlapping
        // stride. The exclusive mapping borrow prevents any other safe mutable
        // view for the lifetime of the returned role pair.
        let pair = unsafe {
            GuestIntrospectionRingPairMut {
                request: GuestIntrospectionRawRingMut {
                    header: &*base.add(request_header_offset).cast::<RingHeader>(),
                    entries: core::slice::from_raw_parts_mut(
                        base.add(request_entries_offset)
                            .cast::<GuestIntrospectionEntry>(),
                        entry_count,
                    ),
                },
                response: GuestIntrospectionRawRingMut {
                    header: &*base.add(response_header_offset).cast::<RingHeader>(),
                    entries: core::slice::from_raw_parts_mut(
                        base.add(response_entries_offset)
                            .cast::<GuestIntrospectionEntry>(),
                        entry_count,
                    ),
                },
            }
        };
        Ok(pair)
    }

    /// Borrows one VM's dedicated plugin-to-host fingerprint sample slot.
    ///
    /// The VM slot is also the fingerprint-slot index. The interior atomic
    /// fields support the plugin's boundary publication and the host's post-
    /// `finish_quantum` read without a mutable mapping borrow.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` does not name a logical VM, or the computed
    /// fingerprint segment is out of bounds or misaligned.
    pub fn fingerprint_sample(
        &self,
        vm_slot: u32,
    ) -> Result<&FingerprintSampleSlot, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        if vm_slot >= layout.fingerprint_sample_count {
            return Err(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fingerprint sample",
                index: vm_slot,
            });
        }
        let offset = mapped_fingerprint_sample_offset(layout, self.len, vm_slot)?;
        let base = self.base_ptr();
        // SAFETY: `mapped_fingerprint_sample_offset` validated the slot index,
        // byte range, and ABI alignment against this live owned mapping.
        Ok(unsafe { &*base.add(offset).cast::<FingerprintSampleSlot>() })
    }
}
