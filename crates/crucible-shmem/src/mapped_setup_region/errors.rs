//! Mapping and typed-access errors for setup regions.

use super::*;

/// An error produced while borrowing typed objects from a mapped setup region.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MappedSetupRegionAccessError {
    /// The mapped region header failed ABI or geometry validation.
    #[error("mapped setup region header validation failed")]
    Header {
        /// Underlying header validation error.
        source: RegionSetupValidationError,
    },
    /// A node slot index was outside the validated physical slot table.
    #[error("mapped setup region has no node slot {slot}")]
    UnknownNodeSlot {
        /// Rejected physical node slot.
        slot: u32,
    },
    /// A directed ring was absent from the validated topology.
    #[error("mapped setup region has no directed ring from slot {src_slot} to slot {dst_slot}")]
    UnknownDirectedRing {
        /// Producer slot.
        src_slot: u32,
        /// Consumer slot.
        dst_slot: u32,
    },
    /// A VM slot was outside the dedicated coverage-ring table.
    #[error(
        "mapped setup region has no coverage ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownCoverageRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
    },
    /// A VM slot was outside the dedicated white-box marker-ring table.
    #[error(
        "mapped setup region has no white-box marker ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownWhiteboxMarkerRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
    },
    /// A VM slot was outside a per-VM fault command/result transport table.
    #[error(
        "mapped setup region has no {segment} for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownFaultTransport {
        /// Transport segment being requested.
        segment: &'static str,
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
    },

    /// A VM slot was outside the guest-introspection ring table.
    #[error(
        "mapped setup region has no guest-introspection ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownGuestIntrospectionRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
    },
    /// The validated ring topology could not be enumerated.
    #[error("mapped setup region directed-ring topology is invalid")]
    RingTopology {
        /// Underlying layout error.
        source: RegionLayoutError,
    },
    /// The same directed ring was requested for both mutable views.
    #[error("mapped setup region directed ring {ring_index} was requested twice")]
    DuplicateDirectedRing {
        /// Duplicated directed-ring index.
        ring_index: u32,
    },
    /// A typed segment offset overflowed local address arithmetic.
    #[error("mapped setup region {segment} index {index} offset overflowed")]
    SegmentOffsetOverflow {
        /// Segment kind being borrowed.
        segment: &'static str,
        /// Segment index within its array.
        index: u32,
    },
    /// A typed segment would extend beyond the mapping.
    #[error(
        "mapped setup region {segment} index {index} at byte {offset} with length {len} extends past mapping length {region_len}"
    )]
    SegmentOutOfBounds {
        /// Segment kind being borrowed.
        segment: &'static str,
        /// Segment index within its array.
        index: u32,
        /// Computed byte offset.
        offset: usize,
        /// Segment length in bytes.
        len: usize,
        /// Total mapped length in bytes.
        region_len: usize,
    },
    /// A typed segment offset did not satisfy the ABI alignment.
    #[error(
        "mapped setup region {segment} index {index} at byte {offset} is not aligned to {alignment}"
    )]
    SegmentUnaligned {
        /// Segment kind being borrowed.
        segment: &'static str,
        /// Segment index within its array.
        index: u32,
        /// Computed byte offset.
        offset: usize,
        /// Required byte alignment.
        alignment: usize,
    },
}

/// An error produced while mapping a setup shared-memory descriptor.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SetupRegionMapError {
    /// The `Setup.region_len` cannot be represented as a process-local mapping length.
    #[error("setup region length {region_len} cannot fit in usize")]
    RegionLenTooLarge {
        /// The rejected `Setup.region_len`.
        region_len: u64,
    },
    /// The `Setup.region_len` is too small to contain a shared-memory header.
    #[error("setup region length {region_len} is smaller than header size {minimum_len}")]
    RegionTooSmall {
        /// The rejected `Setup.region_len`.
        region_len: u64,
        /// The minimum mappable length required for the header.
        minimum_len: u64,
    },
    /// The descriptor's current backing length could not be inspected.
    #[error("setup region fstat failed with errno {errno}")]
    FstatFailed {
        /// Raw OS errno value.
        errno: i32,
    },
    /// The descriptor reported a negative backing length.
    #[error("setup region backing length {backing_len} is negative")]
    NegativeBackingLength {
        /// Rejected signed backing length reported by `fstat`.
        backing_len: i64,
    },
    /// The descriptor backing is shorter than the advertised setup region.
    #[error(
        "setup region backing length {backing_len} is smaller than advertised length {region_len}"
    )]
    BackingTooShort {
        /// Current descriptor backing length.
        backing_len: u64,
        /// Length advertised by the control-protocol `Setup` frame.
        region_len: u64,
    },
    /// A seal-capable Linux memfd could still be shrunk after validation.
    #[error("setup memfd is missing F_SEAL_SHRINK (reported seals {seals:#x})")]
    MissingShrinkSeal {
        /// Seal mask returned by `fcntl(F_GET_SEALS)`.
        seals: i32,
    },
    /// Inspecting Linux memfd seals failed unexpectedly.
    #[error("setup region seal query failed with errno {errno}")]
    SealQueryFailed {
        /// Raw operating-system error number.
        errno: i32,
    },
    /// The OS rejected the shared-memory `mmap`.
    #[error("setup region mmap failed with errno {errno}")]
    MmapFailed {
        /// Raw OS errno value.
        errno: i32,
    },
    /// The OS returned a null mapping address.
    #[error("setup region mmap returned a null address")]
    NullMapping,
    /// The mapping base is not aligned for [`RegionHeader`].
    #[error("setup region mmap base is not aligned to {alignment} bytes")]
    UnalignedMapping {
        /// Required ABI alignment.
        alignment: usize,
    },
}
