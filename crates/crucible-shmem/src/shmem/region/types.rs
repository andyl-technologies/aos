//! Owned region allocation records and scheduler publication DTOs.

use super::*;

/// A directed SPSC ring allocation between two physical slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectedRing {
    /// Ring index in the header and backing-storage arrays.
    pub index: u32,
    /// Physical producer slot.
    pub src_slot: u32,
    /// Physical consumer slot.
    pub dst_slot: u32,
}

/// A reserved executor endpoint in the physical slot array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedExecutorSlot {
    /// Deterministic network router endpoint.
    NetRouter,
    /// Block-device I/O endpoint.
    BlockIo,
    /// 9p filesystem I/O endpoint.
    NineP,
}

impl ReservedExecutorSlot {
    /// Returns every reserved executor endpoint in deterministic ring order.
    #[must_use]
    pub const fn all() -> [Self; RESERVED_SLOTS] {
        [Self::NetRouter, Self::BlockIo, Self::NineP]
    }

    /// Returns the physical slot occupied by this executor.
    #[must_use]
    pub const fn slot(self) -> usize {
        match self {
            Self::NetRouter => SLOT_NET_ROUTER,
            Self::BlockIo => SLOT_BLK_IO,
            Self::NineP => SLOT_9P_IO,
        }
    }

    /// Returns the [`NodeSlot`] kind value used for this executor.
    #[must_use]
    pub const fn kind(self) -> u8 {
        match self {
            Self::NetRouter => KIND_NET,
            Self::BlockIo => KIND_BLK,
            Self::NineP => KIND_9P,
        }
    }
}

/// An owned, typed shared-memory region allocation for layout tests and builders.
pub struct RegionAllocation {
    pub(super) header: RegionHeader,
    pub(super) slots: Vec<NodeSlot>,
    pub(super) ring_headers: Vec<RingHeader>,
    pub(super) frame_entries: Vec<FrameEntry>,
    pub(super) coverage_ring_headers: Vec<RingHeader>,
    pub(super) coverage_entries: Vec<CoverageEntry>,
    pub(super) whitebox_marker_ring_headers: Vec<RingHeader>,
    pub(super) whitebox_marker_entries: Vec<WhiteboxMarkerEntry>,
    pub(super) fault_command_ring_headers: Vec<RingHeader>,
    pub(super) fault_command_slots: Vec<FaultCommandSlotV1>,
    pub(super) fault_command_arena_headers: Vec<FaultPayloadArenaHeader>,
    pub(super) fault_command_arena_bytes: Vec<u8>,
    pub(super) fault_result_ring_headers: Vec<RingHeader>,
    pub(super) fault_result_slots: Vec<FaultResultSlotV1>,
    pub(super) fault_result_arena_headers: Vec<FaultPayloadArenaHeader>,
    pub(super) fault_result_arena_bytes: Vec<u8>,
    pub(super) fault_event_ring_headers: Vec<RingHeader>,
    pub(super) fault_event_slots: Vec<FaultEventSlotV1>,
    pub(super) fault_event_arena_headers: Vec<FaultPayloadArenaHeader>,
    pub(super) fault_event_arena_bytes: Vec<u8>,
    pub(super) guest_introspection_ring_headers: Vec<RingHeader>,
    pub(super) guest_introspection_entries: Vec<GuestIntrospectionEntry>,
    pub(super) accelerator_ring_headers: Vec<RingHeader>,
    pub(super) accelerator_entries: Vec<AcceleratorEntry>,
    pub(super) selectable_reply_ring_headers: Vec<RingHeader>,
    pub(super) selectable_reply_entries: Vec<WhiteboxMarkerEntry>,
    pub(super) rings: Vec<DirectedRing>,
    pub(super) layout: RegionLayout,
}

impl Clone for RegionAllocation {
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            slots: self.slots.clone(),
            ring_headers: self.ring_headers.clone(),
            frame_entries: self.frame_entries.clone(),
            coverage_ring_headers: self.coverage_ring_headers.clone(),
            coverage_entries: self.coverage_entries.clone(),
            whitebox_marker_ring_headers: self.whitebox_marker_ring_headers.clone(),
            whitebox_marker_entries: self.whitebox_marker_entries.clone(),
            fault_command_ring_headers: self.fault_command_ring_headers.clone(),
            fault_command_slots: self.fault_command_slots.clone(),
            fault_command_arena_headers: self.fault_command_arena_headers.clone(),
            fault_command_arena_bytes: self.fault_command_arena_bytes.clone(),
            fault_result_ring_headers: self.fault_result_ring_headers.clone(),
            fault_result_slots: self.fault_result_slots.clone(),
            fault_result_arena_headers: self.fault_result_arena_headers.clone(),
            fault_result_arena_bytes: self.fault_result_arena_bytes.clone(),
            fault_event_ring_headers: self.fault_event_ring_headers.clone(),
            fault_event_slots: self.fault_event_slots.clone(),
            fault_event_arena_headers: self.fault_event_arena_headers.clone(),
            fault_event_arena_bytes: self.fault_event_arena_bytes.clone(),
            guest_introspection_ring_headers: self.guest_introspection_ring_headers.clone(),
            guest_introspection_entries: self.guest_introspection_entries.clone(),
            accelerator_ring_headers: self.accelerator_ring_headers.clone(),
            accelerator_entries: self.accelerator_entries.clone(),
            selectable_reply_ring_headers: self.selectable_reply_ring_headers.clone(),
            selectable_reply_entries: self.selectable_reply_entries.clone(),
            rings: self.rings.clone(),
            layout: self.layout,
        }
    }
}

/// A scheduler-owned input frame to publish into one consumer's inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInputPublication {
    /// Physical slot that produces this frame.
    pub src_slot: u32,
    /// Frame to append to the directed inbox from `src_slot` to the consumer.
    pub frame: FrameEntry,
}

impl PendingInputPublication {
    /// Builds a pending input publication.
    #[must_use]
    pub const fn new(src_slot: u32, frame: FrameEntry) -> Self {
        Self { src_slot, frame }
    }
}

/// Result of publishing scheduler inputs, ceiling, and wake for one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerWakePublication {
    /// Physical slot that consumed the published inputs and ceiling.
    pub dst_slot: u32,
    /// Number of input frames enqueued before the wake signal was incremented.
    pub pending_input_count: usize,
    /// The max-advance icount published before the wake signal was incremented.
    pub max_advance_icount: u64,
    /// The wake action returned by the node slot.
    pub wake: WakeAction,
}

#[derive(Clone, Debug)]
pub(super) struct SchedulerWakeEnqueuePlan {
    pub(super) ring_index: usize,
    pub(super) entry_range: std::ops::Range<usize>,
    pub(super) input_index: usize,
}
