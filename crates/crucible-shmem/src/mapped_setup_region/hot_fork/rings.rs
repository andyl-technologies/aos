//! Enumerates the actual held ring endpoints, including per-node console storage.
//!
//! One descriptor set owns aggregate admission and canonical image validation.
//! Console headers use the checked per-node segment stride; physical capability,
//! authorization and completion tables are not ring contents or phase authority.

use super::*;

pub(super) struct RingHeaderSegment {
    pub(super) name: &'static str,
    pub(super) count: u32,
    pub(super) base: u64,
    pub(super) stride: u64,
    pub(super) capacity: u32,
}

impl RingHeaderSegment {
    fn offset(&self, index: u32, region_len: usize) -> Result<usize, MappedSetupRegionAccessError> {
        let segment = self.name;
        let offset = u64::from(index)
            .checked_mul(self.stride)
            .and_then(|relative| self.base.checked_add(relative))
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow { segment, index })?;
        let end = offset
            .checked_add(RING_HEADER_SIZE)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow { segment, index })?;
        if end > region_len {
            return Err(MappedSetupRegionAccessError::SegmentOutOfBounds {
                segment,
                index,
                offset,
                len: RING_HEADER_SIZE,
                region_len,
            });
        }
        if !offset.is_multiple_of(RING_HEADER_ALIGN) {
            return Err(MappedSetupRegionAccessError::SegmentUnaligned {
                segment,
                index,
                offset,
                alignment: RING_HEADER_ALIGN,
            });
        }
        Ok(offset)
    }
}

pub(super) fn ring_header_segments(
    layout: RegionLayout,
) -> Result<[RingHeaderSegment; 10], MappedSetupRegionAccessError> {
    // Both fixed atomic tables precede the existing RingHeader in the ABI-31
    // segment. Their exact sizes are independently asserted by their modules.
    let prefix = core::mem::size_of::<crate::native_console::NativeConsoleCapabilityTable>()
        + core::mem::size_of::<crate::native_console::NativeConsoleAuthorizationTable>();
    let console_base = layout.native_console_off.checked_add(prefix as u64).ok_or(
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "native console ring header",
            index: 0,
        },
    )?;
    Ok([
        RingHeaderSegment {
            name: "directed ring header",
            count: layout.ring_count,
            base: layout.ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.queue_capacity,
        },
        RingHeaderSegment {
            name: "coverage ring header",
            count: layout.coverage_ring_count,
            base: layout.coverage_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.coverage_queue_capacity,
        },
        RingHeaderSegment {
            name: "white-box marker ring header",
            count: layout.whitebox_marker_ring_count,
            base: layout.whitebox_marker_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.whitebox_marker_queue_capacity,
        },
        RingHeaderSegment {
            name: "fault command ring header",
            count: layout.fault_command_ring_count,
            base: layout.fault_command_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.fault_command_queue_capacity,
        },
        RingHeaderSegment {
            name: "fault result ring header",
            count: layout.fault_result_ring_count,
            base: layout.fault_result_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.fault_result_queue_capacity,
        },
        RingHeaderSegment {
            name: "fault event ring header",
            count: layout.fault_event_ring_count,
            base: layout.fault_event_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.fault_event_queue_capacity,
        },
        RingHeaderSegment {
            name: "guest introspection ring header",
            count: layout.guest_introspection_ring_count,
            base: layout.guest_introspection_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.guest_introspection_queue_capacity,
        },
        RingHeaderSegment {
            name: "accelerator ring header",
            count: layout.accelerator_ring_count,
            base: layout.accelerator_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.accelerator_queue_capacity,
        },
        RingHeaderSegment {
            name: "selectable reply ring header",
            count: layout.selectable_reply_ring_count,
            base: layout.selectable_reply_ring_hdr_off,
            stride: RING_HEADER_SIZE as u64,
            capacity: layout.selectable_reply_queue_capacity,
        },
        RingHeaderSegment {
            name: "native console ring header",
            count: layout.vm_node_count,
            base: console_base,
            stride: layout.native_console_stride,
            capacity: crucible_protocol::native_console::NATIVE_CONSOLE_CAPACITY,
        },
    ])
}

impl MappedSetupRegion {
    pub(super) fn apply_ring_io_barrier(
        &self,
        action: BarrierAction,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        let segments = ring_header_segments(layout)?;

        // Validate the complete geometry before mutating the first barrier so
        // malformed shared header bytes cannot leave a partially held region.
        for segment in &segments {
            if segment.count != 0 {
                segment.offset(segment.count - 1, self.len)?;
            }
        }

        let mut ring_count = 0_u64;
        let mut held_rings = 0_u64;
        let mut producers_in_flight = 0_u64;
        let mut consumers_in_flight = 0_u64;
        for segment in &segments {
            for index in 0..segment.count {
                let offset = segment.offset(index, self.len)?;
                // SAFETY: the complete segment geometry was validated before
                // any mutation and this immutable borrow uses only atomics.
                let ring = unsafe { &*self.base_ptr().add(offset).cast::<RingHeader>() };
                let (producer, consumer) = match action {
                    BarrierAction::Hold => (
                        ring.hold_hot_fork_producers(),
                        ring.hold_hot_fork_consumers(),
                    ),
                    BarrierAction::Query => (
                        ring.producer_barrier_snapshot(),
                        ring.consumer_barrier_snapshot(),
                    ),
                    BarrierAction::Release => {
                        // Reopen consumers first so already-queued content can
                        // drain before producers publish new entries.
                        let consumer = ring.release_hot_fork_consumers();
                        let producer = ring.release_hot_fork_producers();
                        (producer, consumer)
                    }
                };
                ring_count += 1;
                held_rings += u64::from(producer.held() && consumer.held());
                producers_in_flight = producers_in_flight
                    .checked_add(producer.in_flight())
                    .unwrap_or_else(|| std::process::abort());
                consumers_in_flight = consumers_in_flight
                    .checked_add(consumer.in_flight())
                    .unwrap_or_else(|| std::process::abort());
            }
        }

        Ok(MappedRingIoBarrierSnapshot {
            ring_count,
            held_rings,
            producers_in_flight,
            consumers_in_flight,
        })
    }
}
