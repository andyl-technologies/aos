//! Requested and computed shared-memory region geometry.

use super::*;

/// A requested shared-memory region shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionConfig {
    /// Number of logical VM nodes to allocate into physical VM slots.
    pub vm_node_count: u32,
    /// Capacity of every directed SPSC ring in frame entries.
    pub queue_capacity: u32,
    /// Fixed icount shift used to derive virtual nanoseconds.
    pub icount_shift: u32,
    /// Bytes in each per-node, per-direction fault payload arena.
    pub fault_payload_arena_bytes: u32,
}

impl RegionConfig {
    /// Builds a region configuration.
    #[must_use]
    pub const fn new(vm_node_count: u32, queue_capacity: u32, icount_shift: u32) -> Self {
        Self {
            vm_node_count,
            queue_capacity,
            icount_shift,
            fault_payload_arena_bytes: DEFAULT_FAULT_PAYLOAD_ARENA_BYTES,
        }
    }

    /// Returns a configuration with an explicit fault payload-arena size.
    #[must_use]
    pub const fn with_fault_payload_arena_bytes(mut self, bytes: u32) -> Self {
        self.fault_payload_arena_bytes = bytes;
        self
    }
}

/// Computed offsets and counts for a shared-memory region allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionLayout {
    /// Number of logical VM nodes represented in physical VM slots.
    pub vm_node_count: u32,
    /// Number of physical node slots present in the fixed slot array.
    pub node_count: u32,
    /// Capacity of every directed SPSC ring in frame entries.
    pub queue_capacity: u32,
    /// Number of directed rings allocated for VM-to-executor traffic.
    pub ring_count: u32,
    /// Byte offset from region base to the fixed node slot array.
    pub node_slots_off: u64,
    /// Byte offset from region base to the first ring header.
    pub ring_hdr_off: u64,
    /// Byte offset from region base to the first frame-entry slot.
    pub ring_data_off: u64,
    /// Byte stride between frame-entry slots.
    pub entry_stride: u64,
    /// Number of plugin-to-host coverage rings, one per logical VM.
    pub coverage_ring_count: u32,
    /// Fixed entry capacity of every coverage ring.
    pub coverage_queue_capacity: u32,
    /// Byte offset from region base to the first coverage ring header.
    pub coverage_ring_hdr_off: u64,
    /// Byte offset from region base to the first coverage entry.
    pub coverage_ring_data_off: u64,
    /// Byte stride between coverage entries.
    pub coverage_entry_stride: u64,
    /// Number of per-node fingerprint sample slots, one per logical VM.
    pub fingerprint_sample_count: u32,
    /// Byte offset from region base to the first fingerprint sample slot.
    pub fingerprint_sample_off: u64,
    /// Byte stride between fingerprint sample slots.
    pub fingerprint_sample_stride: u64,
    /// Number of plugin-to-host white-box marker rings, one per logical VM.
    pub whitebox_marker_ring_count: u32,
    /// Fixed entry capacity of every white-box marker ring.
    pub whitebox_marker_queue_capacity: u32,
    /// Byte offset from region base to the first white-box marker ring header.
    pub whitebox_marker_ring_hdr_off: u64,
    /// Byte offset from region base to the first white-box marker entry.
    pub whitebox_marker_ring_data_off: u64,
    /// Byte stride between white-box marker entries.
    pub whitebox_marker_entry_stride: u64,
    /// Number of host-to-plugin fault command rings, one per logical VM.
    pub fault_command_ring_count: u32,
    /// Fixed entry capacity of every fault command ring.
    pub fault_command_queue_capacity: u32,
    /// Byte offset to the first fault command ring header.
    pub fault_command_ring_hdr_off: u64,
    /// Byte offset to the first fault command slot.
    pub fault_command_slot_off: u64,
    /// Byte stride between fault command slots.
    pub fault_command_slot_stride: u64,
    /// Byte offset to the first command payload-arena header.
    pub fault_command_arena_hdr_off: u64,
    /// Byte offset to the first command payload arena.
    pub fault_command_arena_off: u64,
    /// Byte stride between command payload arenas.
    pub fault_command_arena_stride: u64,
    /// Number of plugin-to-host fault result rings, one per logical VM.
    pub fault_result_ring_count: u32,
    /// Fixed entry capacity of every fault result ring.
    pub fault_result_queue_capacity: u32,
    /// Byte offset to the first fault result ring header.
    pub fault_result_ring_hdr_off: u64,
    /// Byte offset to the first fault result slot.
    pub fault_result_slot_off: u64,
    /// Byte stride between fault result slots.
    pub fault_result_slot_stride: u64,
    /// Byte offset to the first result payload-arena header.
    pub fault_result_arena_hdr_off: u64,
    /// Byte offset to the first result payload arena.
    pub fault_result_arena_off: u64,
    /// Byte stride between result payload arenas.
    pub fault_result_arena_stride: u64,
    /// Number of plugin-to-host fault event rings, one per logical VM.
    pub fault_event_ring_count: u32,
    /// Fixed entry capacity of every fault event ring.
    pub fault_event_queue_capacity: u32,
    /// Byte offset to the first fault event ring header.
    pub fault_event_ring_hdr_off: u64,
    /// Byte offset to the first fault event slot.
    pub fault_event_slot_off: u64,
    /// Byte stride between fault event slots.
    pub fault_event_slot_stride: u64,
    /// Byte offset to the first event payload-arena header.
    pub fault_event_arena_hdr_off: u64,
    /// Byte offset to the first event payload arena.
    pub fault_event_arena_off: u64,
    /// Byte stride between event payload arenas.
    pub fault_event_arena_stride: u64,
    /// Number of guest-introspection rings, two per logical VM.
    pub guest_introspection_ring_count: u32,
    /// Fixed entry capacity of every guest-introspection ring.
    pub guest_introspection_queue_capacity: u32,
    /// Byte offset to the first guest-introspection ring header.
    pub guest_introspection_ring_hdr_off: u64,
    /// Byte offset to the first guest-introspection entry.
    pub guest_introspection_ring_data_off: u64,
    /// Byte stride between guest-introspection entries.
    pub guest_introspection_entry_stride: u64,
    /// Number of accelerator rings, two per logical VM.
    pub accelerator_ring_count: u32,
    /// Fixed entry capacity of every accelerator ring.
    pub accelerator_queue_capacity: u32,
    /// Byte offset to the first accelerator ring header.
    pub accelerator_ring_hdr_off: u64,
    /// Byte offset to the first accelerator entry.
    pub accelerator_ring_data_off: u64,
    /// Byte stride between accelerator entries.
    pub accelerator_entry_stride: u64,
    /// Number of host-to-plugin selectable-reply rings, one per logical VM.
    pub selectable_reply_ring_count: u32,
    /// Fixed entry capacity of every selectable-reply ring.
    pub selectable_reply_queue_capacity: u32,
    /// Byte offset from region base to the first selectable-reply ring header.
    pub selectable_reply_ring_hdr_off: u64,
    /// Byte offset from region base to the first selectable-reply entry.
    pub selectable_reply_ring_data_off: u64,
    /// Byte stride between selectable-reply entries.
    pub selectable_reply_entry_stride: u64,
    /// Total mapped region size in bytes.
    pub region_size: u64,
    /// Fixed icount shift used to derive virtual nanoseconds.
    pub icount_shift: u32,
    /// Bytes in each per-node, per-direction fault payload arena.
    pub fault_payload_arena_bytes: u32,
}

impl RegionLayout {
    /// Computes the region geometry for `config`.
    ///
    /// # Errors
    ///
    /// Returns [`RegionLayoutError`] when the VM count, queue capacity, icount
    /// shift, or computed byte geometry is outside the ABI-supported range.
    pub fn for_config(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        if config.vm_node_count > MAX_VM_NODES as u32 {
            return Err(RegionLayoutError::TooManyVmNodes {
                requested: config.vm_node_count,
                max: MAX_VM_NODES as u32,
            });
        }
        if config.queue_capacity == 0 || !config.queue_capacity.is_power_of_two() {
            return Err(RegionLayoutError::InvalidQueueCapacity {
                capacity: config.queue_capacity,
            });
        }
        if config.icount_shift >= 64 {
            return Err(RegionLayoutError::InvalidIcountShift {
                shift_bits: config.icount_shift,
            });
        }
        if config.fault_payload_arena_bytes < DEFAULT_FAULT_PAYLOAD_BYTES
            || config.fault_payload_arena_bytes > HARD_FAULT_PAYLOAD_ARENA_BYTES
        {
            return Err(RegionLayoutError::InvalidFaultPayloadArenaBytes {
                bytes: config.fault_payload_arena_bytes,
                minimum: DEFAULT_FAULT_PAYLOAD_BYTES,
                maximum: HARD_FAULT_PAYLOAD_ARENA_BYTES,
            });
        }

        let ring_count = config
            .vm_node_count
            .checked_mul(RESERVED_SLOTS as u32)
            .and_then(|count| count.checked_mul(2))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let node_slots_off = usize_to_u64(REGION_HEADER_SIZE)?;
        let ring_hdr_off = usize_to_u64(REGION_HEADER_SIZE)?
            .checked_add(usize_to_u64(MAX_NODES)? * usize_to_u64(NODE_SLOT_SIZE)?)
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let ring_data_off = ring_hdr_off
            .checked_add(u64::from(ring_count) * usize_to_u64(RING_HEADER_SIZE)?)
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let entry_stride = usize_to_u64(FRAME_ENTRY_SIZE)?;
        let entry_count = u64::from(ring_count)
            .checked_mul(u64::from(config.queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let frame_data_end = ring_data_off
            .checked_add(
                entry_count
                    .checked_mul(entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let coverage_ring_count = config.vm_node_count;
        let coverage_queue_capacity = COVERAGE_QUEUE_CAPACITY;
        let coverage_ring_hdr_off =
            checked_align_up(frame_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let coverage_ring_data_off = coverage_ring_hdr_off
            .checked_add(
                u64::from(coverage_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let coverage_entry_stride = usize_to_u64(COVERAGE_ENTRY_SIZE)?;
        let coverage_entry_count = u64::from(coverage_ring_count)
            .checked_mul(u64::from(coverage_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let coverage_data_end = coverage_ring_data_off
            .checked_add(
                coverage_entry_count
                    .checked_mul(coverage_entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // Additive ABI v3 section: one fingerprint sample slot per logical VM,
        // appended after the coverage data with the slot's own alignment.
        let fingerprint_sample_count = config.vm_node_count;
        let fingerprint_sample_stride = usize_to_u64(FINGERPRINT_SAMPLE_SLOT_SIZE)?;
        let fingerprint_sample_off = checked_align_up(
            coverage_data_end,
            usize_to_u64(FINGERPRINT_SAMPLE_SLOT_ALIGN)?,
        )?;
        let fingerprint_data_end = fingerprint_sample_off
            .checked_add(
                u64::from(fingerprint_sample_count)
                    .checked_mul(fingerprint_sample_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // Additive ABI v4 section: one observational marker ring per logical
        // VM, appended after the v3 fingerprint slots.
        let whitebox_marker_ring_count = config.vm_node_count;
        let whitebox_marker_queue_capacity = WHITEBOX_MARKER_QUEUE_CAPACITY;
        let whitebox_marker_ring_hdr_off =
            checked_align_up(fingerprint_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let whitebox_marker_ring_data_off = whitebox_marker_ring_hdr_off
            .checked_add(
                u64::from(whitebox_marker_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let whitebox_marker_entry_stride = usize_to_u64(WHITEBOX_MARKER_ENTRY_SIZE)?;
        let whitebox_marker_entry_count = u64::from(whitebox_marker_ring_count)
            .checked_mul(u64::from(whitebox_marker_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let whitebox_data_end = whitebox_marker_ring_data_off
            .checked_add(
                whitebox_marker_entry_count
                    .checked_mul(whitebox_marker_entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // ABI v7 sections: one host-to-plugin command transport and one
        // plugin-to-host result transport per logical VM. Each direction has
        // an independent SPSC ring and explicitly sized circular byte arena.
        let fault_command_ring_count = config.vm_node_count;
        let fault_command_queue_capacity = DEFAULT_FAULT_COMMAND_CAPACITY;
        let fault_command_ring_hdr_off =
            checked_align_up(whitebox_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let fault_command_slot_off = fault_command_ring_hdr_off
            .checked_add(
                u64::from(fault_command_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_command_slot_stride = usize_to_u64(FAULT_COMMAND_SLOT_V1_BYTES)?;
        let fault_command_slot_count = u64::from(fault_command_ring_count)
            .checked_mul(u64::from(fault_command_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_command_slot_end = fault_command_slot_off
            .checked_add(
                fault_command_slot_count
                    .checked_mul(fault_command_slot_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_command_arena_hdr_off = checked_align_up(
            fault_command_slot_end,
            usize_to_u64(FAULT_PAYLOAD_ARENA_HEADER_BYTES)?,
        )?;
        let fault_command_arena_off = fault_command_arena_hdr_off
            .checked_add(
                u64::from(fault_command_ring_count)
                    .checked_mul(usize_to_u64(FAULT_PAYLOAD_ARENA_HEADER_BYTES)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_command_arena_stride = u64::from(config.fault_payload_arena_bytes);
        let fault_command_data_end = fault_command_arena_off
            .checked_add(
                u64::from(fault_command_ring_count)
                    .checked_mul(fault_command_arena_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        let fault_result_ring_count = config.vm_node_count;
        let fault_result_queue_capacity = DEFAULT_FAULT_COMMAND_CAPACITY;
        let fault_result_ring_hdr_off =
            checked_align_up(fault_command_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let fault_result_slot_off = fault_result_ring_hdr_off
            .checked_add(
                u64::from(fault_result_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_result_slot_stride = usize_to_u64(FAULT_RESULT_SLOT_V1_BYTES)?;
        let fault_result_slot_count = u64::from(fault_result_ring_count)
            .checked_mul(u64::from(fault_result_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_result_slot_end = fault_result_slot_off
            .checked_add(
                fault_result_slot_count
                    .checked_mul(fault_result_slot_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_result_arena_hdr_off = checked_align_up(
            fault_result_slot_end,
            usize_to_u64(FAULT_PAYLOAD_ARENA_HEADER_BYTES)?,
        )?;
        let fault_result_arena_off = fault_result_arena_hdr_off
            .checked_add(
                u64::from(fault_result_ring_count)
                    .checked_mul(usize_to_u64(FAULT_PAYLOAD_ARENA_HEADER_BYTES)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_result_arena_stride = u64::from(config.fault_payload_arena_bytes);
        let fault_result_data_end = fault_result_arena_off
            .checked_add(
                u64::from(fault_result_ring_count)
                    .checked_mul(fault_result_arena_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // ABI v9 section: one independent, lossless QEMU rule-event stream per
        // logical VM. Command results remain strictly request/response shaped.
        let fault_event_ring_count = config.vm_node_count;
        let fault_event_queue_capacity = DEFAULT_FAULT_EVENT_CAPACITY;
        let fault_event_ring_hdr_off =
            checked_align_up(fault_result_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let fault_event_slot_off = fault_event_ring_hdr_off
            .checked_add(
                u64::from(fault_event_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_event_slot_stride = usize_to_u64(FAULT_EVENT_SLOT_V1_BYTES)?;
        let fault_event_slot_count = u64::from(fault_event_ring_count)
            .checked_mul(u64::from(fault_event_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_event_slot_end = fault_event_slot_off
            .checked_add(
                fault_event_slot_count
                    .checked_mul(fault_event_slot_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_event_arena_hdr_off = checked_align_up(
            fault_event_slot_end,
            usize_to_u64(FAULT_PAYLOAD_ARENA_HEADER_BYTES)?,
        )?;
        let fault_event_arena_off = fault_event_arena_hdr_off
            .checked_add(
                u64::from(fault_event_ring_count)
                    .checked_mul(usize_to_u64(FAULT_PAYLOAD_ARENA_HEADER_BYTES)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let fault_event_arena_stride = u64::from(config.fault_payload_arena_bytes);
        let fault_event_data_end = fault_event_arena_off
            .checked_add(
                u64::from(fault_event_ring_count)
                    .checked_mul(fault_event_arena_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // ABI v10 appends the two bounded guest-introspection directions after
        // the fault transports, preserving all ABI v9 fault offsets.
        let guest_introspection_ring_count = config
            .vm_node_count
            .checked_mul(GUEST_INTROSPECTION_RINGS_PER_VM)
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let guest_introspection_queue_capacity = GUEST_INTROSPECTION_QUEUE_CAPACITY;
        let guest_introspection_ring_hdr_off =
            checked_align_up(fault_event_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let guest_introspection_ring_data_off = guest_introspection_ring_hdr_off
            .checked_add(
                u64::from(guest_introspection_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let guest_introspection_entry_stride = usize_to_u64(GUEST_INTROSPECTION_ENTRY_SIZE)?;
        let guest_introspection_entry_count = u64::from(guest_introspection_ring_count)
            .checked_mul(u64::from(guest_introspection_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let guest_introspection_data_end = guest_introspection_ring_data_off
            .checked_add(
                guest_introspection_entry_count
                    .checked_mul(guest_introspection_entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // ABI v11 appends accelerator request/completion rings, preserving all
        // prior section offsets.
        let accelerator_ring_count = config
            .vm_node_count
            .checked_mul(ACCELERATOR_RINGS_PER_VM)
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let accelerator_queue_capacity = ACCELERATOR_QUEUE_CAPACITY;
        let accelerator_ring_hdr_off = checked_align_up(
            guest_introspection_data_end,
            usize_to_u64(RING_HEADER_ALIGN)?,
        )?;
        let accelerator_ring_data_off = accelerator_ring_hdr_off
            .checked_add(
                u64::from(accelerator_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let accelerator_entry_stride = usize_to_u64(ACCELERATOR_ENTRY_SIZE)?;
        let accelerator_entry_count = u64::from(accelerator_ring_count)
            .checked_mul(u64::from(accelerator_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let accelerator_data_end = accelerator_ring_data_off
            .checked_add(
                accelerator_entry_count
                    .checked_mul(accelerator_entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // ABI v18 appends one single-entry host-to-plugin selectable reply
        // ring per logical VM. A catalog owns at most one pending request, so
        // additional queue capacity would permit only invalid pipelining.
        let selectable_reply_ring_count = config.vm_node_count;
        let selectable_reply_queue_capacity = SELECTABLE_REPLY_QUEUE_CAPACITY;
        let selectable_reply_ring_hdr_off =
            checked_align_up(accelerator_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let selectable_reply_ring_data_off = selectable_reply_ring_hdr_off
            .checked_add(
                u64::from(selectable_reply_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let selectable_reply_entry_stride = usize_to_u64(WHITEBOX_MARKER_ENTRY_SIZE)?;
        let selectable_reply_entry_count = u64::from(selectable_reply_ring_count)
            .checked_mul(u64::from(selectable_reply_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let region_size = selectable_reply_ring_data_off
            .checked_add(
                selectable_reply_entry_count
                    .checked_mul(selectable_reply_entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        Ok(Self {
            vm_node_count: config.vm_node_count,
            node_count: MAX_NODES as u32,
            queue_capacity: config.queue_capacity,
            ring_count,
            node_slots_off,
            ring_hdr_off,
            ring_data_off,
            entry_stride,
            coverage_ring_count,
            coverage_queue_capacity,
            coverage_ring_hdr_off,
            coverage_ring_data_off,
            coverage_entry_stride,
            fingerprint_sample_count,
            fingerprint_sample_off,
            fingerprint_sample_stride,
            whitebox_marker_ring_count,
            whitebox_marker_queue_capacity,
            whitebox_marker_ring_hdr_off,
            whitebox_marker_ring_data_off,
            whitebox_marker_entry_stride,
            fault_command_ring_count,
            fault_command_queue_capacity,
            fault_command_ring_hdr_off,
            fault_command_slot_off,
            fault_command_slot_stride,
            fault_command_arena_hdr_off,
            fault_command_arena_off,
            fault_command_arena_stride,
            fault_result_ring_count,
            fault_result_queue_capacity,
            fault_result_ring_hdr_off,
            fault_result_slot_off,
            fault_result_slot_stride,
            fault_result_arena_hdr_off,
            fault_result_arena_off,
            fault_result_arena_stride,
            fault_event_ring_count,
            fault_event_queue_capacity,
            fault_event_ring_hdr_off,
            fault_event_slot_off,
            fault_event_slot_stride,
            fault_event_arena_hdr_off,
            fault_event_arena_off,
            fault_event_arena_stride,
            guest_introspection_ring_count,
            guest_introspection_queue_capacity,
            guest_introspection_ring_hdr_off,
            guest_introspection_ring_data_off,
            guest_introspection_entry_stride,
            accelerator_ring_count,
            accelerator_queue_capacity,
            accelerator_ring_hdr_off,
            accelerator_ring_data_off,
            accelerator_entry_stride,
            selectable_reply_ring_count,
            selectable_reply_queue_capacity,
            selectable_reply_ring_hdr_off,
            selectable_reply_ring_data_off,
            selectable_reply_entry_stride,
            region_size,
            icount_shift: config.icount_shift,
            fault_payload_arena_bytes: config.fault_payload_arena_bytes,
        })
    }

    /// Returns the number of frame-entry slots in the backing storage.
    #[must_use]
    pub fn frame_entry_count(&self) -> u64 {
        u64::from(self.ring_count) * u64::from(self.queue_capacity)
    }

    /// Returns the number of coverage-entry slots in the backing storage.
    #[must_use]
    pub fn coverage_entry_count(&self) -> u64 {
        u64::from(self.coverage_ring_count) * u64::from(self.coverage_queue_capacity)
    }

    /// Returns the number of white-box marker-entry slots in the allocation.
    #[must_use]
    pub fn whitebox_marker_entry_count(&self) -> u64 {
        u64::from(self.whitebox_marker_ring_count) * u64::from(self.whitebox_marker_queue_capacity)
    }

    /// Returns the number of fault command slots in the allocation.
    #[must_use]
    pub fn fault_command_slot_count(&self) -> u64 {
        u64::from(self.fault_command_ring_count) * u64::from(self.fault_command_queue_capacity)
    }

    /// Returns the number of fault result slots in the allocation.
    #[must_use]
    pub fn fault_result_slot_count(&self) -> u64 {
        u64::from(self.fault_result_ring_count) * u64::from(self.fault_result_queue_capacity)
    }

    /// Returns the number of fault event slots in the allocation.
    #[must_use]
    pub fn fault_event_slot_count(&self) -> u64 {
        u64::from(self.fault_event_ring_count) * u64::from(self.fault_event_queue_capacity)
    }

    /// Returns the number of guest-introspection entries in both directions.
    #[must_use]
    pub fn guest_introspection_entry_count(&self) -> u64 {
        u64::from(self.guest_introspection_ring_count)
            * u64::from(self.guest_introspection_queue_capacity)
    }

    /// Returns the number of accelerator entry slots.
    #[must_use]
    pub fn accelerator_entry_count(&self) -> u64 {
        u64::from(self.accelerator_ring_count) * u64::from(self.accelerator_queue_capacity)
    }

    /// Returns the number of selectable-reply entries in the allocation.
    #[must_use]
    pub fn selectable_reply_entry_count(&self) -> u64 {
        u64::from(self.selectable_reply_ring_count)
            * u64::from(self.selectable_reply_queue_capacity)
    }
}
