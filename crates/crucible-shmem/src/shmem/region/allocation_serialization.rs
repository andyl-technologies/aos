//! Canonical serialization of typed shared-memory region allocations.

use super::*;

impl RegionAllocation {
    /// Serializes the allocation into setup-region bytes for a host memfd.
    ///
    /// The returned byte vector has length [`RegionLayout::region_size`] and
    /// uses the exact `#[repr(C)]` offsets exported by this crate. It exists for
    /// host setup paths that must initialize a shared-memory descriptor before
    /// handing it to the QEMU plugin through the control protocol.
    ///
    /// # Errors
    ///
    /// Returns [`RegionSerializationError`] when the region size or a computed
    /// segment offset cannot be represented on this host.
    pub fn setup_region_bytes(&self) -> Result<Vec<u8>, RegionSerializationError> {
        let region_len = usize::try_from(self.layout.region_size).map_err(|_error| {
            RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            }
        })?;
        let mut bytes = vec![0; region_len];

        write_region_header_bytes(&mut bytes, self.header.snapshot())?;
        for (index, slot) in self.slots.iter().enumerate() {
            let base = checked_segment_offset(
                "node slot",
                index,
                self.layout.node_slots_off,
                NODE_SLOT_SIZE,
                region_len,
            )?;
            write_node_slot_bytes(&mut bytes[base..base + NODE_SLOT_SIZE], slot.snapshot());
        }
        for (index, ring_header) in self.ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "ring header",
                index,
                self.layout.ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, frame_entry) in self.frame_entries.iter().enumerate() {
            let base = checked_segment_offset(
                "frame entry",
                index,
                self.layout.ring_data_off,
                FRAME_ENTRY_SIZE,
                region_len,
            )?;
            write_frame_entry_bytes(&mut bytes[base..base + FRAME_ENTRY_SIZE], frame_entry);
        }
        for (index, ring_header) in self.coverage_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "coverage ring header",
                index,
                self.layout.coverage_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, coverage_entry) in self.coverage_entries.iter().enumerate() {
            let base = checked_segment_offset(
                "coverage entry",
                index,
                self.layout.coverage_ring_data_off,
                COVERAGE_ENTRY_SIZE,
                region_len,
            )?;
            write_coverage_entry_bytes(
                &mut bytes[base..base + COVERAGE_ENTRY_SIZE],
                coverage_entry,
            );
        }
        for (index, ring_header) in self.whitebox_marker_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "white-box marker ring header",
                index,
                self.layout.whitebox_marker_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, marker_entry) in self.whitebox_marker_entries.iter().enumerate() {
            let base = checked_segment_offset(
                "white-box marker entry",
                index,
                self.layout.whitebox_marker_ring_data_off,
                WHITEBOX_MARKER_ENTRY_SIZE,
                region_len,
            )?;
            write_whitebox_marker_entry_bytes(
                &mut bytes[base..base + WHITEBOX_MARKER_ENTRY_SIZE],
                marker_entry,
            );
        }
        for (index, ring_header) in self.fault_command_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "fault command ring header",
                index,
                self.layout.fault_command_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, slot) in self.fault_command_slots.iter().enumerate() {
            let base = checked_segment_offset(
                "fault command slot",
                index,
                self.layout.fault_command_slot_off,
                FAULT_COMMAND_SLOT_V1_BYTES,
                region_len,
            )?;
            slot.write_bytes(&mut bytes[base..base + FAULT_COMMAND_SLOT_V1_BYTES]);
        }
        for (index, header) in self.fault_command_arena_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "fault command payload arena header",
                index,
                self.layout.fault_command_arena_hdr_off,
                FAULT_PAYLOAD_ARENA_HEADER_BYTES,
                region_len,
            )?;
            header.write_bytes(&mut bytes[base..base + FAULT_PAYLOAD_ARENA_HEADER_BYTES]);
        }
        let command_arena_base =
            usize::try_from(self.layout.fault_command_arena_off).map_err(|_| {
                RegionSerializationError::RegionSizeTooLarge {
                    region_size: self.layout.region_size,
                }
            })?;
        let command_arena_end = command_arena_base
            .checked_add(self.fault_command_arena_bytes.len())
            .ok_or(RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            })?;
        bytes
            .get_mut(command_arena_base..command_arena_end)
            .ok_or(RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            })?
            .copy_from_slice(&self.fault_command_arena_bytes);

        for (index, ring_header) in self.fault_result_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "fault result ring header",
                index,
                self.layout.fault_result_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, slot) in self.fault_result_slots.iter().enumerate() {
            let base = checked_segment_offset(
                "fault result slot",
                index,
                self.layout.fault_result_slot_off,
                FAULT_RESULT_SLOT_V1_BYTES,
                region_len,
            )?;
            slot.write_bytes(&mut bytes[base..base + FAULT_RESULT_SLOT_V1_BYTES]);
        }
        for (index, header) in self.fault_result_arena_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "fault result payload arena header",
                index,
                self.layout.fault_result_arena_hdr_off,
                FAULT_PAYLOAD_ARENA_HEADER_BYTES,
                region_len,
            )?;
            header.write_bytes(&mut bytes[base..base + FAULT_PAYLOAD_ARENA_HEADER_BYTES]);
        }
        let result_arena_base =
            usize::try_from(self.layout.fault_result_arena_off).map_err(|_| {
                RegionSerializationError::RegionSizeTooLarge {
                    region_size: self.layout.region_size,
                }
            })?;
        let result_arena_end = result_arena_base
            .checked_add(self.fault_result_arena_bytes.len())
            .ok_or(RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            })?;
        bytes
            .get_mut(result_arena_base..result_arena_end)
            .ok_or(RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            })?
            .copy_from_slice(&self.fault_result_arena_bytes);

        for (index, ring_header) in self.fault_event_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "fault event ring header",
                index,
                self.layout.fault_event_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, slot) in self.fault_event_slots.iter().enumerate() {
            let base = checked_segment_offset(
                "fault event slot",
                index,
                self.layout.fault_event_slot_off,
                FAULT_EVENT_SLOT_V1_BYTES,
                region_len,
            )?;
            slot.write_bytes(&mut bytes[base..base + FAULT_EVENT_SLOT_V1_BYTES]);
        }
        for (index, header) in self.fault_event_arena_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "fault event payload arena header",
                index,
                self.layout.fault_event_arena_hdr_off,
                FAULT_PAYLOAD_ARENA_HEADER_BYTES,
                region_len,
            )?;
            header.write_bytes(&mut bytes[base..base + FAULT_PAYLOAD_ARENA_HEADER_BYTES]);
        }
        let event_arena_base =
            usize::try_from(self.layout.fault_event_arena_off).map_err(|_| {
                RegionSerializationError::RegionSizeTooLarge {
                    region_size: self.layout.region_size,
                }
            })?;
        let event_arena_end = event_arena_base
            .checked_add(self.fault_event_arena_bytes.len())
            .ok_or(RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            })?;
        bytes
            .get_mut(event_arena_base..event_arena_end)
            .ok_or(RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            })?
            .copy_from_slice(&self.fault_event_arena_bytes);

        for (index, ring_header) in self.guest_introspection_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "guest-introspection ring header",
                index,
                self.layout.guest_introspection_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, entry) in self.guest_introspection_entries.iter().enumerate() {
            let base = checked_segment_offset(
                "guest-introspection entry",
                index,
                self.layout.guest_introspection_ring_data_off,
                GUEST_INTROSPECTION_ENTRY_SIZE,
                region_len,
            )?;
            write_guest_introspection_entry_bytes(
                &mut bytes[base..base + GUEST_INTROSPECTION_ENTRY_SIZE],
                entry,
            );
        }

        for (index, ring_header) in self.selectable_reply_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "selectable reply ring header",
                index,
                self.layout.selectable_reply_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, entry) in self.selectable_reply_entries.iter().enumerate() {
            let base = checked_segment_offset(
                "selectable reply entry",
                index,
                self.layout.selectable_reply_ring_data_off,
                WHITEBOX_MARKER_ENTRY_SIZE,
                region_len,
            )?;
            write_whitebox_marker_entry_bytes(
                &mut bytes[base..base + WHITEBOX_MARKER_ENTRY_SIZE],
                entry,
            );
        }

        Ok(bytes)
    }
}
