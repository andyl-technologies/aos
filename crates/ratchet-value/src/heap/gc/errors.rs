//! The generational-GC error type: one exhaustive [`GenerationalGcError`]
//! enum for every planning and commit refusal.
//!
//! Moved verbatim from `heap/gc.rs` under the RFC-0007 §2 file-size cap; the
//! parent re-exports every public path.

use super::*;

/// A failed generational-GC policy or remembered-set operation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenerationalGcError {
    /// A heap address decoded to zero.
    #[error("GC heap address is null")]
    NullAddress,
    /// A heap address still carried low pointer-tag bits.
    #[error("GC heap address still has low pointer-tag bits set: 0x{address_bits:x}")]
    LowTagBitsPresent {
        /// The rejected address bits.
        address_bits: usize,
    },
    /// The remembered-set edge count overflowed.
    #[error("remembered-set edge count overflow")]
    RememberedSetLengthOverflow,
    /// The remembered set could not reserve storage.
    #[error("failed to reserve {edges} remembered-set edges")]
    RememberedSetAllocationFailed {
        /// The requested remembered-set capacity.
        edges: usize,
    },
    /// A card table was created with an invalid card size.
    #[error("invalid GC card size {card_size_bytes}")]
    InvalidGcCardSize {
        /// The rejected card size in bytes.
        card_size_bytes: usize,
    },
    /// The card-table dirty-card count overflowed.
    #[error("GC card-table dirty-card count overflow")]
    GcCardTableLengthOverflow,
    /// The card table could not reserve storage.
    #[error("failed to reserve {cards} GC dirty-card entries")]
    GcCardTableAllocationFailed {
        /// The requested dirty-card capacity.
        cards: usize,
    },
    /// A remembered-set snapshot did not belong to the requested collection
    /// epoch.
    #[error("remembered-set snapshot epoch {actual} does not match collection epoch {expected}")]
    RememberedSetEpochMismatch {
        /// The minor-GC collection epoch being planned.
        expected: RememberedSetEpoch,
        /// The epoch attached to the remembered-set snapshot.
        actual: RememberedSetEpoch,
    },
    /// The remembered-set epoch counter overflowed.
    #[error("remembered-set epoch overflow")]
    RememberedSetEpochOverflow,
    /// The minor-GC frontier length overflowed.
    #[error("minor-GC frontier length overflow")]
    MinorGcFrontierLengthOverflow,
    /// The minor-GC frontier could not reserve storage.
    #[error("failed to reserve {objects} minor-GC frontier objects")]
    MinorGcFrontierAllocationFailed {
        /// The requested frontier capacity.
        objects: usize,
    },
    /// The minor-GC survivor plan length overflowed.
    #[error("minor-GC survivor length overflow")]
    MinorGcSurvivorLengthOverflow,
    /// The minor-GC survivor plan could not reserve storage.
    #[error("failed to reserve {survivors} minor-GC survivors")]
    MinorGcSurvivorAllocationFailed {
        /// The requested survivor-plan capacity.
        survivors: usize,
    },
    /// The minor-GC destination allocation plan length overflowed.
    #[error("minor-GC destination allocation length overflow")]
    MinorGcDestinationAllocationLengthOverflow,
    /// The minor-GC destination allocation plan could not reserve storage.
    #[error("failed to reserve {allocations} minor-GC destination allocations")]
    MinorGcDestinationAllocationFailed {
        /// The requested destination-allocation capacity.
        allocations: usize,
    },
    /// Minor-GC destination allocation bytes overflowed for one generation.
    #[error("minor-GC destination bytes overflowed for {generation:?}")]
    MinorGcDestinationBytesOverflow {
        /// The destination generation whose byte total overflowed.
        generation: HeapGeneration,
    },
    /// Minor-GC destination allocation bytes overflowed in aggregate.
    #[error("minor-GC total destination bytes overflowed")]
    MinorGcDestinationTotalBytesOverflow,
    /// The minor-GC destination placement plan length overflowed.
    #[error("minor-GC destination placement length overflow")]
    MinorGcDestinationPlacementLengthOverflow,
    /// The minor-GC destination placement plan could not reserve storage.
    #[error("failed to reserve {placements} minor-GC destination placements")]
    MinorGcDestinationPlacementAllocationFailed {
        /// The requested destination-placement capacity.
        placements: usize,
    },
    /// A destination placement carried invalid alignment metadata.
    #[error("invalid minor-GC destination placement alignment {align} for {generation:?}")]
    InvalidMinorGcDestinationPlacementAlignment {
        /// The destination generation being placed.
        generation: HeapGeneration,
        /// The rejected alignment in bytes.
        align: usize,
    },
    /// Minor-GC destination placement reserved bytes overflowed.
    #[error("minor-GC destination placement bytes overflowed for {generation:?}")]
    MinorGcDestinationPlacementBytesOverflow {
        /// The destination generation whose reserved byte total overflowed.
        generation: HeapGeneration,
    },
    /// Minor-GC destination placement reserved bytes overflowed in aggregate.
    #[error("minor-GC total destination placement bytes overflowed")]
    MinorGcDestinationPlacementTotalBytesOverflow,
    /// Owned minor-GC destination storage bytes overflowed.
    #[error("minor-GC destination storage bytes overflowed for {generation:?}")]
    MinorGcDestinationStorageBytesOverflow {
        /// The destination generation whose owned storage length overflowed.
        generation: HeapGeneration,
    },
    /// Owned minor-GC destination storage could not be reserved.
    #[error("failed to reserve {bytes} bytes of minor-GC destination storage for {generation:?}")]
    MinorGcDestinationStorageAllocationFailed {
        /// The destination generation being reserved.
        generation: HeapGeneration,
        /// The byte capacity requested for the owned storage buffer.
        bytes: usize,
    },
    /// Aligning an owned minor-GC destination storage base overflowed.
    #[error(
        "minor-GC destination storage base address overflowed for {generation:?} address 0x{address_bits:x} align {align}"
    )]
    MinorGcDestinationStorageBaseAddressOverflow {
        /// The destination generation whose base address overflowed.
        generation: HeapGeneration,
        /// The raw allocation address being aligned.
        address_bits: usize,
        /// The required base alignment in bytes.
        align: usize,
    },
    /// Owned minor-GC destination storage could not reserve validation metadata.
    #[error("failed to reserve {copies} minor-GC destination storage copy records")]
    MinorGcDestinationStorageCopyPlanAllocationFailed {
        /// The object-copy count being validated.
        copies: usize,
    },
    /// The object-copy plan did not match the owned destination placement count.
    #[error(
        "minor-GC destination storage copy count {copies} does not match placement count {placements}"
    )]
    MinorGcDestinationStorageCopyPlanLengthMismatch {
        /// The destination placement count.
        placements: usize,
        /// The object-copy count.
        copies: usize,
    },
    /// An object-copy plan did not preserve placement source order.
    #[error(
        "minor-GC destination storage copy source mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcDestinationStorageCopySourceMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The source object expected by the placement plan.
        expected: GcHeapAddress,
        /// The source object found in the object-copy plan.
        actual: GcHeapAddress,
    },
    /// An object-copy plan carried a different copy/promote action.
    #[error(
        "minor-GC destination storage copy action mismatch for 0x{address:x}: expected {expected:?}, got {actual:?}",
        address = address.address_bits()
    )]
    MinorGcDestinationStorageCopyActionMismatch {
        /// The source object with mismatched copy action.
        address: GcHeapAddress,
        /// The action expected by the placement plan.
        expected: MinorGcSurvivorAction,
        /// The action found in the object-copy plan.
        actual: MinorGcSurvivorAction,
    },
    /// An object-copy plan carried a different destination address.
    #[error(
        "minor-GC destination storage copy destination mismatch for 0x{address:x}: expected 0x{expected:x}, got 0x{actual:x}",
        address = address.address_bits(),
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcDestinationStorageCopyDestinationMismatch {
        /// The source object with mismatched destination metadata.
        address: GcHeapAddress,
        /// The destination projected from the placement plan.
        expected: GcHeapAddress,
        /// The destination found in the object-copy plan.
        actual: GcHeapAddress,
    },
    /// An object-copy plan carried a different object size.
    #[error(
        "minor-GC destination storage copy size mismatch for 0x{address:x}: expected {expected}, got {actual}",
        address = address.address_bits()
    )]
    MinorGcDestinationStorageCopySizeMismatch {
        /// The source object with mismatched size metadata.
        address: GcHeapAddress,
        /// The size expected by the placement plan.
        expected: usize,
        /// The size found in the object-copy plan.
        actual: usize,
    },
    /// An object-copy plan carried a different object alignment.
    #[error(
        "minor-GC destination storage copy alignment mismatch for 0x{address:x}: expected {expected}, got {actual}",
        address = address.address_bits()
    )]
    MinorGcDestinationStorageCopyAlignmentMismatch {
        /// The source object with mismatched alignment metadata.
        address: GcHeapAddress,
        /// The alignment expected by the placement plan.
        expected: usize,
        /// The alignment found in the object-copy plan.
        actual: usize,
    },
    /// A planned object copy targeted bytes outside owned destination storage.
    #[error(
        "minor-GC destination storage range for {generation:?} destination 0x{destination:x} size {size_bytes} is outside base 0x{base:x} reserved {reserved_bytes} bytes",
        destination = destination.address_bits(),
        base = base.address_bits()
    )]
    MinorGcDestinationStorageRangeOutOfBounds {
        /// The destination generation being written.
        generation: HeapGeneration,
        /// The owned storage base address for the destination generation.
        base: GcHeapAddress,
        /// The planned destination object address.
        destination: GcHeapAddress,
        /// The planned object size in bytes.
        size_bytes: usize,
        /// The reserved destination bytes for this generation.
        reserved_bytes: usize,
    },
    /// Two planned object copies overlapped in owned destination storage.
    #[error(
        "minor-GC destination storage ranges overlap in {generation:?}: 0x{first:x} and 0x{second:x}",
        first = first.address_bits(),
        second = second.address_bits()
    )]
    MinorGcDestinationStorageRangeOverlap {
        /// The destination generation with overlapping ranges.
        generation: HeapGeneration,
        /// The first overlapping destination object.
        first: GcHeapAddress,
        /// The second overlapping destination object.
        second: GcHeapAddress,
    },
    /// The source-byte inventory length did not match the object-copy plan.
    #[error("minor-GC source-byte count {sources} does not match object-copy count {copies}")]
    MinorGcSourceObjectBytesCountMismatch {
        /// The planned object-copy count.
        copies: usize,
        /// The supplied source-byte count.
        sources: usize,
    },
    /// A source-byte entry was supplied for a different object.
    #[error(
        "minor-GC source-byte object mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcSourceObjectBytesSourceMismatch {
        /// The mismatched source-byte index.
        index: usize,
        /// The source object expected by the object-copy plan.
        expected: GcHeapAddress,
        /// The source object found in the source-byte inventory.
        actual: GcHeapAddress,
    },
    /// A source-byte slice had the wrong length for a planned object copy.
    #[error(
        "minor-GC source-byte length {actual} for 0x{address:x} at index {index} does not match planned size {expected}",
        address = address.address_bits()
    )]
    MinorGcSourceObjectBytesLengthMismatch {
        /// The mismatched source-byte index.
        index: usize,
        /// The source object whose bytes were supplied.
        address: GcHeapAddress,
        /// The planned object size.
        expected: usize,
        /// The supplied source byte length.
        actual: usize,
    },
    /// The minor-GC relocation destination plan length overflowed.
    #[error("minor-GC relocation destination length overflow")]
    MinorGcRelocationDestinationLengthOverflow,
    /// The minor-GC relocation destination plan could not reserve storage.
    #[error("failed to reserve {destinations} minor-GC relocation destinations")]
    MinorGcRelocationDestinationAllocationFailed {
        /// The requested relocation-destination capacity.
        destinations: usize,
    },
    /// A destination placement plan did not match the survivor count.
    #[error(
        "minor-GC relocation destination placement count {placements} does not match survivor count {survivors}"
    )]
    MinorGcRelocationDestinationPlacementLengthMismatch {
        /// The survivor count in the minor-GC plan.
        survivors: usize,
        /// The placement count in the destination-placement plan.
        placements: usize,
    },
    /// A destination placement plan did not preserve survivor source order.
    #[error("minor-GC relocation destination placement source mismatch: expected 0x{expected:x}, got 0x{actual:x}", expected = expected.address_bits(), actual = actual.address_bits())]
    MinorGcRelocationDestinationPlacementSourceMismatch {
        /// The survivor source expected at this position.
        expected: GcHeapAddress,
        /// The placement source found at this position.
        actual: GcHeapAddress,
    },
    /// A destination placement action did not match the survivor action.
    #[error(
        "minor-GC relocation destination placement action mismatch for 0x{address:x}: expected {expected:?}, got {actual:?}",
        address = address.address_bits()
    )]
    MinorGcRelocationDestinationPlacementActionMismatch {
        /// The survivor source with mismatched action metadata.
        address: GcHeapAddress,
        /// The action from the survivor plan.
        expected: MinorGcSurvivorAction,
        /// The action from the placement plan.
        actual: MinorGcSurvivorAction,
    },
    /// Materializing a relocation destination address overflowed.
    #[error("minor-GC relocation destination address overflowed for {generation:?} base 0x{base:x} offset {offset}", base = base.address_bits())]
    MinorGcRelocationDestinationAddressOverflow {
        /// The destination generation being materialized.
        generation: HeapGeneration,
        /// The destination-space base address.
        base: GcHeapAddress,
        /// The placement offset in bytes.
        offset: usize,
    },
    /// A materialized relocation destination violated object alignment.
    #[error("minor-GC relocation destination 0x{destination:x} for 0x{address:x} is not {align}-byte aligned in {generation:?}", destination = destination.address_bits(), address = address.address_bits())]
    MinorGcRelocationDestinationAlignmentMismatch {
        /// The survivor source being placed.
        address: GcHeapAddress,
        /// The destination generation being materialized.
        generation: HeapGeneration,
        /// The misaligned relocation destination.
        destination: GcHeapAddress,
        /// The required object alignment in bytes.
        align: usize,
    },
    /// The minor-GC relocation plan length overflowed.
    #[error("minor-GC relocation length overflow")]
    MinorGcRelocationLengthOverflow,
    /// The minor-GC relocation plan could not reserve storage.
    #[error("failed to reserve {relocations} minor-GC relocations")]
    MinorGcRelocationAllocationFailed {
        /// The requested relocation-plan capacity.
        relocations: usize,
    },
    /// The minor-GC object-copy plan length overflowed.
    #[error("minor-GC object-copy length overflow")]
    MinorGcObjectCopyLengthOverflow,
    /// The minor-GC object-copy plan could not reserve storage.
    #[error("failed to reserve {copies} minor-GC object copies")]
    MinorGcObjectCopyAllocationFailed {
        /// The requested object-copy-plan capacity.
        copies: usize,
    },
    /// A planned object-copy destination address range overflowed.
    #[error(
        "minor-GC object-copy destination range overflowed for {generation:?} destination 0x{destination:x} size {size_bytes}",
        destination = destination.address_bits()
    )]
    MinorGcObjectCopyDestinationAddressOverflow {
        /// The destination generation being written.
        generation: HeapGeneration,
        /// The planned destination object address.
        destination: GcHeapAddress,
        /// The planned object size in bytes.
        size_bytes: usize,
    },
    /// A planned object-copy source address range overflowed.
    #[error(
        "minor-GC object-copy source range overflowed for source 0x{address:x} size {size_bytes}",
        address = address.address_bits()
    )]
    MinorGcObjectCopySourceAddressOverflow {
        /// The planned source object address.
        address: GcHeapAddress,
        /// The planned object size in bytes.
        size_bytes: usize,
    },
    /// Two planned object-copy destination ranges overlapped.
    #[error(
        "minor-GC object-copy destination ranges overlap: {first_generation:?} 0x{first:x} and {second_generation:?} 0x{second:x}",
        first = first.address_bits(),
        second = second.address_bits()
    )]
    MinorGcObjectCopyDestinationRangeOverlap {
        /// The first destination generation.
        first_generation: HeapGeneration,
        /// The first overlapping destination object.
        first: GcHeapAddress,
        /// The second destination generation.
        second_generation: HeapGeneration,
        /// The second overlapping destination object.
        second: GcHeapAddress,
    },
    /// A planned object-copy destination range overlapped from-space bytes.
    #[error(
        "minor-GC object-copy destination 0x{destination:x} overlaps source 0x{source:x}",
        destination = destination.address_bits(),
        source = source_address.address_bits()
    )]
    MinorGcObjectCopyDestinationSourceRangeOverlap {
        /// The live from-space source whose bytes would be reused.
        source_address: GcHeapAddress,
        /// The destination object address that overlaps from-space bytes.
        destination: GcHeapAddress,
    },
    /// An object-copy plan received the wrong number of caller-owned byte
    /// buffers.
    #[error("minor-GC object byte-copy buffer count {buffers} does not match copy count {copies}")]
    MinorGcObjectByteCopyBufferLengthMismatch {
        /// The planned object-copy count.
        copies: usize,
        /// The supplied byte-buffer count.
        buffers: usize,
    },
    /// An object-copy byte buffer belonged to a different source object.
    #[error(
        "minor-GC object byte-copy source mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcObjectByteCopySourceMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The source object expected by the object-copy plan.
        expected: GcHeapAddress,
        /// The source object found in the caller-owned buffer.
        actual: GcHeapAddress,
    },
    /// An object-copy byte buffer belonged to a different destination object.
    #[error(
        "minor-GC object byte-copy destination mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcObjectByteCopyDestinationMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The destination object expected by the object-copy plan.
        expected: GcHeapAddress,
        /// The destination object found in the caller-owned buffer.
        actual: GcHeapAddress,
    },
    /// An object-copy source byte slice had the wrong length.
    #[error(
        "minor-GC object byte-copy source length {actual} for 0x{address:x} at index {index} does not match planned size {expected}",
        address = address.address_bits()
    )]
    MinorGcObjectByteCopySourceLengthMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The source object whose bytes were supplied.
        address: GcHeapAddress,
        /// The planned object size.
        expected: usize,
        /// The supplied source byte length.
        actual: usize,
    },
    /// An object-copy destination byte slice had the wrong length.
    #[error(
        "minor-GC object byte-copy destination length {actual} for 0x{address:x} at index {index} does not match planned size {expected}",
        address = address.address_bits()
    )]
    MinorGcObjectByteCopyDestinationLengthMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The destination object whose buffer was supplied.
        address: GcHeapAddress,
        /// The planned object size.
        expected: usize,
        /// The supplied destination byte length.
        actual: usize,
    },
    /// The minor-GC forwarding-pointer plan length overflowed.
    #[error("minor-GC forwarding-pointer length overflow")]
    MinorGcForwardingPointerLengthOverflow,
    /// The minor-GC forwarding-pointer plan could not reserve storage.
    #[error("failed to reserve {pointers} minor-GC forwarding pointers")]
    MinorGcForwardingPointerAllocationFailed {
        /// The requested forwarding-pointer-plan capacity.
        pointers: usize,
    },
    /// A forwarding-pointer plan received the wrong number of caller-owned
    /// slots.
    #[error(
        "minor-GC forwarding-pointer slot count {slots} does not match pointer count {pointers}"
    )]
    MinorGcForwardingPointerSlotLengthMismatch {
        /// The planned forwarding-pointer count.
        pointers: usize,
        /// The supplied forwarding-slot count.
        slots: usize,
    },
    /// A forwarding-pointer slot belonged to a different source object.
    #[error(
        "minor-GC forwarding-pointer slot source mismatch at index {index}: expected 0x{expected:x}, got 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    MinorGcForwardingPointerSlotSourceMismatch {
        /// The mismatched slot index.
        index: usize,
        /// The source object expected by the forwarding-pointer plan.
        expected: GcHeapAddress,
        /// The source object found in the caller-owned slot.
        actual: GcHeapAddress,
    },
    /// A forwarding-pointer slot was already occupied.
    #[error(
        "minor-GC forwarding-pointer slot for 0x{address:x} at index {index} is already occupied by {actual:?}",
        address = address.address_bits()
    )]
    MinorGcForwardingPointerSlotOccupied {
        /// The occupied slot index.
        index: usize,
        /// The source object whose slot was already occupied.
        address: GcHeapAddress,
        /// The already-installed forwarding value.
        actual: ResolvedValueGeneration,
    },
    /// A minor-GC commit plan received mismatched copy and forwarding counts.
    #[error(
        "minor-GC commit forwarding-pointer count {pointers} does not match object-copy count {copies}"
    )]
    MinorGcCommitForwardingPointerLengthMismatch {
        /// The object-copy count.
        copies: usize,
        /// The forwarding-pointer count.
        pointers: usize,
    },
    /// A minor-GC commit plan received a forwarding pointer for another copy.
    #[error(
        "minor-GC commit forwarding pointer mismatch at index {index}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitForwardingPointerMismatch {
        /// The mismatched copy index.
        index: usize,
        /// The forwarding pointer projected from the object-copy plan.
        expected: MinorGcForwardingPointer,
        /// The caller-supplied forwarding pointer.
        actual: MinorGcForwardingPointer,
    },
    /// A minor-GC commit plan referenced an uncopied rewrite source.
    #[error("minor-GC commit reference rewrite source is not copied: 0x{address:x}", address = address.address_bits())]
    MinorGcCommitReferenceRewriteSourceMissing {
        /// The missing object-copy source address.
        address: GcHeapAddress,
    },
    /// A minor-GC commit plan received a rewrite for another relocation.
    #[error("minor-GC commit reference rewrite mismatch at slot {slot} for 0x{address:x}: expected {expected:?}, got {actual:?}", address = address.address_bits())]
    MinorGcCommitReferenceRewriteMismatch {
        /// The mismatched reference slot.
        slot: usize,
        /// The rewrite source address.
        address: GcHeapAddress,
        /// The relocated value projected from the object-copy plan.
        expected: ResolvedValueGeneration,
        /// The caller-supplied replacement value.
        actual: ResolvedValueGeneration,
    },
    /// A minor-GC commit plan received a remembered-set refresh decision from
    /// another relocation map.
    #[error(
        "minor-GC commit remembered-set refresh mismatch for {original:?}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitRememberedSetRefreshMismatch {
        /// The remembered edge being refreshed.
        original: RememberedEdge,
        /// The refresh action projected from the object-copy plan.
        expected: MinorGcRememberedSetRefreshAction,
        /// The caller-supplied refresh action.
        actual: MinorGcRememberedSetRefreshAction,
    },
    /// A minor-GC commit plan received a dirty old-field rescan decision from
    /// another relocation map.
    #[error(
        "minor-GC commit old-field rescan mismatch for {original:?}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitOldFieldRescanMismatch {
        /// The remembered edge discovered by rescanning a dirty old field.
        original: RememberedEdge,
        /// The rescan action projected from the object-copy plan.
        expected: MinorGcRememberedSetRefreshAction,
        /// The caller-supplied old-field rescan action.
        actual: MinorGcRememberedSetRefreshAction,
    },
    /// A minor-GC commit plan tried to publish into a remembered set from
    /// another epoch.
    #[error(
        "minor-GC commit remembered-set publication epoch {actual} does not match source epoch {expected}"
    )]
    MinorGcCommitRememberedSetPublicationEpochMismatch {
        /// The epoch consumed by the commit plan.
        expected: RememberedSetEpoch,
        /// The epoch currently held by the caller-owned remembered set.
        actual: RememberedSetEpoch,
    },
    /// A minor-GC commit plan tried to publish over a different remembered-set
    /// snapshot length.
    #[error(
        "minor-GC commit remembered-set publication length {actual} does not match source length {expected}"
    )]
    MinorGcCommitRememberedSetPublicationLengthMismatch {
        /// The edge count consumed by the commit plan.
        expected: usize,
        /// The edge count currently held by the caller-owned remembered set.
        actual: usize,
    },
    /// A minor-GC commit plan tried to publish over a different remembered-set
    /// edge.
    #[error(
        "minor-GC commit remembered-set publication edge mismatch at index {index}: expected {expected:?}, got {actual:?}"
    )]
    MinorGcCommitRememberedSetPublicationEdgeMismatch {
        /// The mismatched remembered-set edge index.
        index: usize,
        /// The edge consumed by the commit plan.
        expected: RememberedEdge,
        /// The edge currently held by the caller-owned remembered set.
        actual: RememberedEdge,
    },
    /// The minor-GC reference rewrite plan length overflowed.
    #[error("minor-GC reference rewrite length overflow")]
    MinorGcReferenceRewriteLengthOverflow,
    /// The minor-GC reference rewrite plan could not reserve storage.
    #[error("failed to reserve {rewrites} minor-GC reference rewrites")]
    MinorGcReferenceRewriteAllocationFailed {
        /// The requested reference-rewrite capacity.
        rewrites: usize,
    },
    /// The caller-supplied reference slot index overflowed.
    #[error("minor-GC reference slot index overflow")]
    MinorGcReferenceSlotIndexOverflow,
    /// An unplanned young reference appeared in a commit reference buffer.
    #[error("minor-GC reference rewrite found unplanned young slot {slot}: 0x{address:x}", address = address.address_bits())]
    MinorGcReferenceRewriteUnplannedYoungSlot {
        /// The unplanned reference slot index.
        slot: usize,
        /// The young from-space address found in the slot.
        address: GcHeapAddress,
    },
    /// A planned reference rewrite targeted a slot outside the supplied buffer.
    #[error("minor-GC reference rewrite slot {slot} is out of bounds for {slots} slots")]
    MinorGcReferenceRewriteSlotOutOfBounds {
        /// The planned slot index.
        slot: usize,
        /// The number of caller-supplied reference slots.
        slots: usize,
    },
    /// A planned reference rewrite found different slot contents.
    #[error("minor-GC reference rewrite slot {slot} expected young 0x{expected:x}, found {actual:?}", expected = expected.address_bits())]
    MinorGcReferenceRewriteSlotMismatch {
        /// The planned slot index.
        slot: usize,
        /// The expected young from-space address.
        expected: GcHeapAddress,
        /// The actual slot contents.
        actual: ResolvedValueGeneration,
    },
    /// The minor-GC remembered-set refresh plan length overflowed.
    #[error("minor-GC remembered-set refresh length overflow")]
    MinorGcRememberedSetRefreshLengthOverflow,
    /// The minor-GC remembered-set refresh plan could not reserve storage.
    #[error("failed to reserve {refreshes} minor-GC remembered-set refreshes")]
    MinorGcRememberedSetRefreshAllocationFailed {
        /// The requested remembered-set refresh capacity.
        refreshes: usize,
    },
    /// The dirty old-field rescan plan length overflowed.
    #[error("minor-GC old-field rescan length overflow")]
    MinorGcOldFieldRescanLengthOverflow,
    /// The dirty old-field rescan plan could not reserve storage.
    #[error("failed to reserve {rescans} minor-GC old-field rescans")]
    MinorGcOldFieldRescanAllocationFailed {
        /// The requested old-field rescan capacity.
        rescans: usize,
    },
    /// A young frontier object had no age metadata.
    #[error("missing nursery age metadata for 0x{address:x}", address = address.address_bits())]
    MissingNurseryObjectAge {
        /// The young object missing nursery metadata.
        address: GcHeapAddress,
    },
    /// A young object appeared more than once in the nursery age table.
    #[error("duplicate nursery age metadata for 0x{address:x}", address = address.address_bits())]
    DuplicateNurseryObjectAge {
        /// The duplicated young object.
        address: GcHeapAddress,
    },
    /// A live young object had no field metadata.
    #[error("missing nursery field metadata for 0x{address:x}", address = address.address_bits())]
    MissingNurseryObjectFields {
        /// The young object missing field metadata.
        address: GcHeapAddress,
    },
    /// A young object appeared more than once in the nursery field table.
    #[error("duplicate nursery field metadata for 0x{address:x}", address = address.address_bits())]
    DuplicateNurseryObjectFields {
        /// The duplicated young object.
        address: GcHeapAddress,
    },
    /// A live survivor had no nursery layout metadata.
    #[error("missing nursery layout metadata for 0x{address:x}", address = address.address_bits())]
    MissingNurseryObjectLayout {
        /// The survivor missing layout metadata.
        address: GcHeapAddress,
    },
    /// A young object appeared more than once in the nursery layout table.
    #[error("duplicate nursery layout metadata for 0x{address:x}", address = address.address_bits())]
    DuplicateNurseryObjectLayout {
        /// The duplicated young object.
        address: GcHeapAddress,
    },
    /// A nursery layout referenced an object outside the survivor plan.
    #[error("nursery layout source is not live: 0x{address:x}", address = address.address_bits())]
    StaleNurseryObjectLayout {
        /// The non-survivor source address.
        address: GcHeapAddress,
    },
    /// A nursery layout had an invalid object size.
    #[error("invalid nursery object size {size_bytes} for 0x{address:x}", address = address.address_bits())]
    InvalidNurseryObjectSize {
        /// The object with invalid layout metadata.
        address: GcHeapAddress,
        /// The rejected size in bytes.
        size_bytes: usize,
    },
    /// A nursery layout had an invalid object alignment.
    #[error("invalid nursery object alignment {align} for 0x{address:x}", address = address.address_bits())]
    InvalidNurseryObjectAlignment {
        /// The object with invalid layout metadata.
        address: GcHeapAddress,
        /// The rejected alignment in bytes.
        align: usize,
    },
    /// A live survivor had no relocation destination metadata.
    #[error("missing minor-GC relocation destination for 0x{address:x}", address = address.address_bits())]
    MissingMinorGcRelocationDestination {
        /// The survivor missing relocation metadata.
        address: GcHeapAddress,
    },
    /// A survivor source appeared more than once in the relocation table.
    #[error("duplicate minor-GC relocation source for 0x{address:x}", address = address.address_bits())]
    DuplicateMinorGcRelocationSource {
        /// The duplicated survivor source.
        address: GcHeapAddress,
    },
    /// Two survivor sources were assigned the same relocation destination.
    #[error("duplicate minor-GC relocation destination 0x{address:x}", address = address.address_bits())]
    DuplicateMinorGcRelocationDestination {
        /// The duplicated relocation destination.
        address: GcHeapAddress,
    },
    /// A relocation source referenced an object outside the survivor plan.
    #[error("minor-GC relocation source is not live: 0x{address:x}", address = address.address_bits())]
    StaleMinorGcRelocationSource {
        /// The non-survivor source address.
        address: GcHeapAddress,
    },
    /// A survivor was assigned a destination that is still in from-space.
    #[error("minor-GC relocation for 0x{from:x} points into from-space at 0x{destination:x}", from = from.address_bits(), destination = destination.address_bits())]
    MinorGcRelocationDestinationInFromSpace {
        /// The source survivor being relocated.
        from: GcHeapAddress,
        /// The invalid destination address.
        destination: GcHeapAddress,
    },
    /// A young root or field reference had no relocation metadata.
    #[error("missing minor-GC reference relocation for 0x{address:x}", address = address.address_bits())]
    MissingMinorGcReferenceRelocation {
        /// The young reference missing relocation metadata.
        address: GcHeapAddress,
    },
}
