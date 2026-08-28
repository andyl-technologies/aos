//! Aggregate hot-fork producer and consumer admission for mapped rings.

use super::*;

/// Exact aggregate state of every ring I/O barrier in one setup region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedRingIoBarrierSnapshot {
    ring_count: u64,
    held_rings: u64,
    producers_in_flight: u64,
    consumers_in_flight: u64,
}

impl MappedRingIoBarrierSnapshot {
    /// Returns the exact number of ring headers in the validated region layout.
    #[must_use]
    pub const fn ring_count(self) -> u64 {
        self.ring_count
    }

    /// Returns the number of rings whose producer and consumer barriers are held.
    #[must_use]
    pub const fn held_rings(self) -> u64 {
        self.held_rings
    }

    /// Returns the checked aggregate of already-admitted producer operations.
    #[must_use]
    pub const fn producers_in_flight(self) -> u64 {
        self.producers_in_flight
    }

    /// Returns the checked aggregate of already-admitted consumer operations.
    #[must_use]
    pub const fn consumers_in_flight(self) -> u64 {
        self.consumers_in_flight
    }

    /// Returns whether every ring is held and every admitted I/O operation returned.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.ring_count != 0
            && self.held_rings == self.ring_count
            && self.producers_in_flight == 0
            && self.consumers_in_flight == 0
    }
}

#[derive(Clone, Copy)]
enum BarrierAction {
    Hold,
    Query,
    Release,
}

impl MappedSetupRegion {
    /// Holds producer and consumer admission for every validated ring.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the live header or a ring
    /// segment no longer matches the mapped region's validated ABI geometry.
    pub fn hold_hot_fork_ring_io(
        &self,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        self.apply_ring_io_barrier(BarrierAction::Hold)
    }

    /// Observes producer and consumer admission for every validated ring.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the live header or a ring
    /// segment no longer matches the mapped region's validated ABI geometry.
    pub fn hot_fork_ring_io_snapshot(
        &self,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        self.apply_ring_io_barrier(BarrierAction::Query)
    }

    /// Releases consumer and producer admission for every validated ring.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the live header or a ring
    /// segment no longer matches the mapped region's validated ABI geometry.
    pub fn release_hot_fork_ring_io(
        &self,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        self.apply_ring_io_barrier(BarrierAction::Release)
    }

    fn apply_ring_io_barrier(
        &self,
        action: BarrierAction,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        let segments = ring_header_segments(layout);

        // Validate the complete geometry before mutating the first barrier so
        // malformed shared header bytes cannot leave a partially held region.
        for &(segment, count, base) in &segments {
            if count != 0 {
                mapped_segment_offset(
                    segment,
                    count - 1,
                    base,
                    RING_HEADER_SIZE,
                    RING_HEADER_ALIGN,
                    self.len,
                )?;
            }
        }

        let mut ring_count = 0_u64;
        let mut held_rings = 0_u64;
        let mut producers_in_flight = 0_u64;
        let mut consumers_in_flight = 0_u64;
        for &(segment, count, base) in &segments {
            for index in 0..count {
                let offset = mapped_segment_offset(
                    segment,
                    index,
                    base,
                    RING_HEADER_SIZE,
                    RING_HEADER_ALIGN,
                    self.len,
                )?;
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

type RingHeaderSegment = (&'static str, u32, u64);

const fn ring_header_segments(layout: RegionLayout) -> [RingHeaderSegment; 9] {
    [
        (
            "directed ring header",
            layout.ring_count,
            layout.ring_hdr_off,
        ),
        (
            "coverage ring header",
            layout.coverage_ring_count,
            layout.coverage_ring_hdr_off,
        ),
        (
            "white-box marker ring header",
            layout.whitebox_marker_ring_count,
            layout.whitebox_marker_ring_hdr_off,
        ),
        (
            "fault command ring header",
            layout.fault_command_ring_count,
            layout.fault_command_ring_hdr_off,
        ),
        (
            "fault result ring header",
            layout.fault_result_ring_count,
            layout.fault_result_ring_hdr_off,
        ),
        (
            "fault event ring header",
            layout.fault_event_ring_count,
            layout.fault_event_ring_hdr_off,
        ),
        (
            "guest introspection ring header",
            layout.guest_introspection_ring_count,
            layout.guest_introspection_ring_hdr_off,
        ),
        (
            "accelerator ring header",
            layout.accelerator_ring_count,
            layout.accelerator_ring_hdr_off,
        ),
        (
            "selectable reply ring header",
            layout.selectable_reply_ring_count,
            layout.selectable_reply_ring_hdr_off,
        ),
    ]
}
