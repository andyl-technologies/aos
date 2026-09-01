//! Typed region-access and scheduler-publication errors.

use super::*;

/// An error produced while accessing a typed region allocation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionAllocationAccessError {
    /// A directed shared-memory ring does not exist.
    #[error("region allocation has no directed ring from slot {src_slot} to slot {dst_slot}")]
    UnknownDirectedRing {
        /// Producer slot.
        src_slot: u32,
        /// Consumer slot.
        dst_slot: u32,
    },
    /// A VM slot was outside the guest-introspection ring table.
    #[error(
        "region allocation has no guest-introspection ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownGuestIntrospectionRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots.
        vm_node_count: u32,
    },
    /// A guest-introspection entry range overflowed local indexing.
    #[error("guest-introspection ring {ring_index} entry range overflowed")]
    GuestIntrospectionEntryRangeOverflow {
        /// Rejected directional ring index.
        ring_index: u32,
    },
    /// A VM slot does not have a plugin-to-host coverage ring.
    #[error(
        "region allocation has no coverage ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownCoverageRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Logical VM count.
        vm_node_count: u32,
    },
    /// A VM slot does not have a plugin-to-host white-box marker ring.
    #[error(
        "region allocation has no white-box marker ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownWhiteboxMarkerRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Logical VM count.
        vm_node_count: u32,
    },
    /// A ring index could not be represented as a local vector index.
    #[error("region allocation ring index {ring_index} is outside the local ring table")]
    RingIndexOutOfRange {
        /// Rejected ring index.
        ring_index: u32,
    },
    /// A ring's backing frame-entry range overflowed.
    #[error("region allocation frame-entry range overflowed for ring {ring_index}")]
    RingEntryRangeOverflow {
        /// Rejected ring index.
        ring_index: u32,
    },
    /// A VM's compact coverage-entry range overflowed.
    #[error("region allocation coverage-entry range overflowed for VM slot {vm_slot}")]
    CoverageEntryRangeOverflow {
        /// Rejected VM slot.
        vm_slot: u32,
    },
    /// A VM's white-box marker-entry range overflowed.
    #[error("region allocation white-box marker-entry range overflowed for VM slot {vm_slot}")]
    WhiteboxMarkerEntryRangeOverflow {
        /// Rejected VM slot.
        vm_slot: u32,
    },
    /// The shared-memory SPSC ring operation failed.
    #[error("region allocation SPSC ring operation failed")]
    SpscRing {
        /// Underlying SPSC ring error.
        #[from]
        source: SpscRingError,
    },
}

/// An error produced while publishing scheduler inputs, ceiling, and wake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SchedulerWakePublicationError {
    /// The consumer physical slot does not exist in the region.
    #[error("region allocation has no node slot {slot}")]
    UnknownNodeSlot {
        /// Rejected physical slot index.
        slot: u32,
    },
    /// The directed inbox publication failed.
    #[error("scheduler wake inbox publication failed")]
    RegionAccess {
        /// Underlying region access error.
        #[from]
        source: RegionAllocationAccessError,
    },
    /// The consumer node slot rejected the ceiling or wake.
    #[error("scheduler wake node-slot publication failed")]
    NodeSlot {
        /// Underlying node-slot error.
        #[from]
        source: NodeSlotError,
    },
    /// A pending input's embedded source did not match its directed ring source.
    #[error(
        "scheduler wake pending input {input_index} frame source {frame_src_node} does not match ring source {expected_src_slot}"
    )]
    FrameSourceMismatch {
        /// Index in the pending-input batch.
        input_index: usize,
        /// Source slot selected for the directed ring.
        expected_src_slot: u32,
        /// Source node stamped into the frame entry.
        frame_src_node: u32,
    },
}
