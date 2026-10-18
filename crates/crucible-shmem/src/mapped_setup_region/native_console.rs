//! Per-VM console views derived exclusively from validated ABI-31 geometry.

use super::*;
use crate::native_console::{MappedNativeConsoleSegment, NativeConsoleSegmentLayout};
use crucible_protocol::native_console::{
    NATIVE_CONSOLE_CAPACITY, NATIVE_CONSOLE_REQUIRED_SHMEM_ABI, NativeConsoleError,
};

impl MappedSetupRegion {
    /// Copies paired custody only for the exact visible original request.
    ///
    /// This is a bounded framing/ordering check, not a native closed-control
    /// receipt. A native adapter must still authenticate its installed owner,
    /// full-body custody, settled fault boundary, and actual RR closure before
    /// committing a frontier. No raw or logical origin is read from this table.
    ///
    /// # Errors
    ///
    /// Refuses an invalid mapping, absent/in-progress publication, odd request,
    /// mismatched control/advance fields, or a changing original publication.
    pub fn native_console_clamp_for_request(
        &self,
        vm_slot: u32,
    ) -> Result<crucible_protocol::native_console::NativeConsoleClamp, NativeConsoleError> {
        let slot = self
            .node_slot(vm_slot)
            .map_err(|_| NativeConsoleError::Binding)?;
        let before = slot.try_snapshot().ok_or(NativeConsoleError::Sequence)?;
        if before.control_boundary_ack & 1 != 0 {
            return Err(NativeConsoleError::Sequence);
        }
        let paired = self.native_console_segment(vm_slot)?.clamp.snapshot()?;
        if paired.request != before.control_boundary_ack
            || paired.advance != before.advance_publication_sequence
            || paired.fault_frontier != before.control_boundary_fault_command_frontier
            || paired.capture != before.control_boundary_capture_request
            || paired.ceiling != before.max_advance_icount
            || paired.stop != before.advance_stop_condition
        {
            return Err(NativeConsoleError::Binding);
        }
        let after = slot.try_snapshot().ok_or(NativeConsoleError::Sequence)?;
        if after.control_boundary_ack != before.control_boundary_ack
            || after.advance_publication_sequence != before.advance_publication_sequence
            || after.control_boundary_fault_command_frontier
                != before.control_boundary_fault_command_frontier
            || after.control_boundary_capture_request != before.control_boundary_capture_request
        {
            return Err(NativeConsoleError::Sequence);
        }
        Ok(paired)
    }

    /// Borrows one console segment in the original owned setup mapping.
    ///
    /// Offsets are recomputed from the validated region header and physical VM
    /// slot. Callers cannot select arbitrary storage or reinterpret an ABI-30
    /// mapping. This view grants neither a phase nor a native capability.
    ///
    /// # Errors
    ///
    /// Refuses an old/invalid header, an absent VM slot, overflow, or a segment
    /// outside the mapping. Its returned borrows cannot outlive this owner.
    pub fn native_console_segment(
        &self,
        vm_slot: u32,
    ) -> Result<MappedNativeConsoleSegment<'_>, NativeConsoleError> {
        if self.header_snapshot().abi_version != NATIVE_CONSOLE_REQUIRED_SHMEM_ABI {
            return Err(NativeConsoleError::Binding);
        }
        let region = self.layout().map_err(|_| NativeConsoleError::Binding)?;
        if vm_slot >= region.vm_node_count {
            return Err(NativeConsoleError::Binding);
        }
        let offset = region
            .native_console_off
            .checked_add(
                u64::from(vm_slot)
                    .checked_mul(region.native_console_stride)
                    .ok_or(NativeConsoleError::Length)?,
            )
            .ok_or(NativeConsoleError::Length)?;
        let base_offset = usize::try_from(offset).map_err(|_| NativeConsoleError::Length)?;
        let segment = NativeConsoleSegmentLayout::new(base_offset, self.len)?;
        let base = self.base_ptr();

        // SAFETY: the original mapping is live in this process. The validated
        // ABI layout gives each VM a disjoint segment; the checked local layout
        // bounds and aligns every fixed scalar atomic table and record. Zero
        // initialization is valid, and all borrows remain tied to this mapping.
        Ok(unsafe {
            MappedNativeConsoleSegment {
                capability: &*base.add(segment.capability).cast(),
                authorization: &*base.add(segment.authorization).cast(),
                ring: &*base.add(segment.ring_header).cast(),
                records: core::slice::from_raw_parts(
                    base.add(segment.records).cast(),
                    NATIVE_CONSOLE_CAPACITY as usize,
                ),
                frontier: &*base.add(segment.frontier).cast(),
                clamp: &*base.add(segment.clamp).cast(),
                operation_stop: &*base.add(segment.operation_stop).cast(),
            }
        })
    }
}
