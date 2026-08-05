//! Owned destination storage for minor-GC copy and promotion plans.
//!
//! The main GC module builds precise survivor, placement, relocation, and copy
//! plans. This submodule owns the next step: aligned byte storage for the
//! planned nursery and old-generation destinations. It still does not mutate
//! live heap headers or root slots, but it gives later collector code concrete
//! destination buffers with stable relocation bases.

use crate::value::tag::POINTER_TAG_MASK;

use super::{
    GcHeapAddress, GenerationalGcError, HeapGeneration, MinorGcDestinationBases,
    MinorGcDestinationPlacementPlan, MinorGcObjectCopy, MinorGcObjectCopyPlan, MinorGcPlan,
    MinorGcRelocationDestinationPlan, MinorGcSurvivorAction,
};

mod validation;

use validation::{DestinationRange, validated_copies};

const MIN_DESTINATION_ALIGNMENT: usize = POINTER_TAG_MASK + 1;

/// Source bytes for one from-space nursery object in a minor-GC copy plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinorGcSourceObjectBytes<'a> {
    source: GcHeapAddress,
    bytes: &'a [u8],
}

impl<'a> MinorGcSourceObjectBytes<'a> {
    /// Creates source-byte metadata for one planned object copy.
    pub const fn new(source: GcHeapAddress, bytes: &'a [u8]) -> Self {
        Self { source, bytes }
    }

    /// Returns the from-space nursery object address.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the bytes read from the from-space nursery object.
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// A summary of object bytes copied into owned minor-GC destination storage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinorGcOwnedDestinationStorageCopyReport {
    object_copies: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    nursery_payload_bytes: usize,
    old_payload_bytes: usize,
}

impl MinorGcOwnedDestinationStorageCopyReport {
    /// Builds copy counts from a validated object-copy plan.
    ///
    /// This reports the copy/promote and payload-byte totals that
    /// [`MinorGcOwnedDestinationStorage::copy_from_sources`] would return after
    /// successfully applying `copy_plan`, without reading source bytes or
    /// mutating destination storage.
    pub fn from_object_copy_plan(copy_plan: &MinorGcObjectCopyPlan) -> Self {
        let mut report = Self::default();
        for copy in copy_plan.copies() {
            report.record(*copy);
        }
        report
    }

    fn record(&mut self, copy: MinorGcObjectCopy) {
        self.object_copies += 1;
        match copy.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery += 1;
                self.nursery_payload_bytes += copy.size_bytes();
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old += 1;
                self.old_payload_bytes += copy.size_bytes();
            }
        }
    }

    /// Returns the number of object payloads copied.
    pub const fn object_copies(self) -> usize {
        self.object_copies
    }

    /// Returns the number of survivors copied to next-nursery storage.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns the number of survivors promoted into old-generation storage.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns copied payload bytes written into next-nursery storage.
    pub const fn nursery_payload_bytes(self) -> usize {
        self.nursery_payload_bytes
    }

    /// Returns copied payload bytes written into old-generation storage.
    pub const fn old_payload_bytes(self) -> usize {
        self.old_payload_bytes
    }
}

/// Owned next-nursery and old-generation byte storage for one minor-GC plan.
#[derive(Debug)]
pub struct MinorGcOwnedDestinationStorage {
    placement_plan: MinorGcDestinationPlacementPlan,
    nursery: GenerationDestinationStorage,
    old: GenerationDestinationStorage,
}

impl MinorGcOwnedDestinationStorage {
    /// Allocates aligned destination storage for a placement plan.
    ///
    /// The returned storage owns separate byte buffers for the next nursery
    /// semispace and old-generation promotion destinations. Each buffer chooses
    /// an aligned interior base address that satisfies every placement assigned
    /// to that generation, so the returned [`MinorGcDestinationBases`] can be
    /// fed back into relocation-destination materialization.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if buffer length arithmetic overflows, if
    /// the owned byte buffers cannot be reserved, if aligning an allocated
    /// buffer address overflows, or if the aligned base unexpectedly fails heap
    /// address validation.
    pub fn from_placement_plan(
        placement_plan: &MinorGcDestinationPlacementPlan,
    ) -> Result<Self, GenerationalGcError> {
        let nursery_alignment = required_alignment(placement_plan, HeapGeneration::Young);
        let old_alignment = required_alignment(placement_plan, HeapGeneration::Old);
        let nursery = GenerationDestinationStorage::new(
            HeapGeneration::Young,
            placement_plan.nursery_reserved_bytes(),
            nursery_alignment,
        )?;
        let old = GenerationDestinationStorage::new(
            HeapGeneration::Old,
            placement_plan.old_reserved_bytes(),
            old_alignment,
        )?;

        Ok(Self {
            placement_plan: placement_plan.clone(),
            nursery,
            old,
        })
    }

    /// Returns the placement plan that sized this owned destination storage.
    pub fn placement_plan(&self) -> &MinorGcDestinationPlacementPlan {
        &self.placement_plan
    }

    /// Returns base addresses for materializing relocation destinations.
    pub const fn destination_bases(&self) -> MinorGcDestinationBases {
        MinorGcDestinationBases::new(self.nursery.base(), self.old.base())
    }

    /// Builds relocation-destination metadata using this storage's bases.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the stored placement plan no longer
    /// matches `survivor_plan`, or if materialized relocation destination
    /// validation fails.
    pub fn relocation_destination_plan(
        &self,
        survivor_plan: &MinorGcPlan,
    ) -> Result<MinorGcRelocationDestinationPlan, GenerationalGcError> {
        MinorGcRelocationDestinationPlan::from_placement_plan(
            survivor_plan,
            &self.placement_plan,
            self.destination_bases(),
        )
    }

    /// Copies planned source object bytes into the owned destination buffers.
    ///
    /// `sources` must be in the same order as `copy_plan.copies()`. The method
    /// first validates that `copy_plan` is the exact copy schedule for this
    /// storage's placement plan, then validates the full source inventory and
    /// every destination range before mutating storage, including rejection of
    /// overlapping destination ranges inside the same generation buffer.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if `copy_plan` does not match this
    /// storage's placement plan, if the source count, source order, or source
    /// byte lengths do not match `copy_plan`, if validation metadata cannot be
    /// reserved, if a destination range falls outside this storage, or if two
    /// planned copies overlap in the same destination buffer.
    pub fn copy_from_sources(
        &mut self,
        copy_plan: &MinorGcObjectCopyPlan,
        sources: &[MinorGcSourceObjectBytes<'_>],
    ) -> Result<MinorGcOwnedDestinationStorageCopyReport, GenerationalGcError> {
        let validated = validated_copies(self, copy_plan, sources)?;
        let mut report = MinorGcOwnedDestinationStorageCopyReport::default();
        for copy in validated {
            self.destination_slice_mut(copy.range)
                .copy_from_slice(copy.source_bytes);
            report.record(copy.copy);
        }
        Ok(report)
    }

    pub(super) fn validate_copy_from_sources(
        &self,
        copy_plan: &MinorGcObjectCopyPlan,
        sources: &[MinorGcSourceObjectBytes<'_>],
    ) -> Result<(), GenerationalGcError> {
        let _ = validated_copies(self, copy_plan, sources)?;
        Ok(())
    }

    /// Returns the reserved next-nursery destination bytes.
    pub fn nursery_destination_bytes(&self) -> &[u8] {
        self.nursery.destination_bytes()
    }

    /// Returns the reserved old-generation destination bytes.
    pub fn old_destination_bytes(&self) -> &[u8] {
        self.old.destination_bytes()
    }

    /// Returns the reserved destination bytes for a collection generation.
    pub fn generation_destination_bytes(&self, generation: HeapGeneration) -> Option<&[u8]> {
        match generation {
            HeapGeneration::Young => Some(self.nursery_destination_bytes()),
            HeapGeneration::Old => Some(self.old_destination_bytes()),
            HeapGeneration::Permanent => None,
        }
    }

    /// Returns bytes reserved for next-nursery destinations.
    pub const fn nursery_reserved_bytes(&self) -> usize {
        self.nursery.reserved_bytes()
    }

    /// Returns bytes reserved for old-generation promotion destinations.
    pub const fn old_reserved_bytes(&self) -> usize {
        self.old.reserved_bytes()
    }

    fn destination_range_for(
        &self,
        copy: MinorGcObjectCopy,
    ) -> Result<DestinationRange, GenerationalGcError> {
        let storage = self.storage_for_action(copy.action());
        let Some(offset) = copy
            .destination()
            .address_bits()
            .checked_sub(storage.base().address_bits())
        else {
            return Err(destination_range_out_of_bounds(storage, copy));
        };
        let Some(end) = offset.checked_add(copy.size_bytes()) else {
            return Err(destination_range_out_of_bounds(storage, copy));
        };
        if end > storage.reserved_bytes() {
            return Err(destination_range_out_of_bounds(storage, copy));
        }
        Ok(DestinationRange {
            generation: storage.generation(),
            start: offset,
            end,
        })
    }

    fn destination_slice_mut(&mut self, range: DestinationRange) -> &mut [u8] {
        match range.generation {
            HeapGeneration::Young => self.nursery.destination_slice_mut(range.start, range.end),
            HeapGeneration::Old => self.old.destination_slice_mut(range.start, range.end),
            HeapGeneration::Permanent => unreachable!("minor-GC destinations are young or old"),
        }
    }

    const fn storage_for_action(
        &self,
        action: MinorGcSurvivorAction,
    ) -> &GenerationDestinationStorage {
        match action {
            MinorGcSurvivorAction::CopyToNursery => &self.nursery,
            MinorGcSurvivorAction::PromoteToOld => &self.old,
        }
    }
}

#[derive(Debug)]
struct GenerationDestinationStorage {
    generation: HeapGeneration,
    bytes: Vec<u8>,
    base: GcHeapAddress,
    base_offset: usize,
    reserved_bytes: usize,
}

impl GenerationDestinationStorage {
    fn new(
        generation: HeapGeneration,
        reserved_bytes: usize,
        required_alignment: usize,
    ) -> Result<Self, GenerationalGcError> {
        let required_alignment = required_alignment.max(MIN_DESTINATION_ALIGNMENT);
        let storage_len = destination_storage_len(reserved_bytes, required_alignment, generation)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(storage_len).map_err(|_| {
            GenerationalGcError::MinorGcDestinationStorageAllocationFailed {
                generation,
                bytes: storage_len,
            }
        })?;
        bytes.resize(storage_len, 0);

        let allocation_address = bytes.as_ptr() as usize;
        let base_address =
            align_destination_base(allocation_address, required_alignment, generation)?;
        let base = GcHeapAddress::new(base_address)?;
        let base_offset = base_address.checked_sub(allocation_address).ok_or(
            GenerationalGcError::MinorGcDestinationStorageBaseAddressOverflow {
                generation,
                address_bits: allocation_address,
                align: required_alignment,
            },
        )?;

        Ok(Self {
            generation,
            bytes,
            base,
            base_offset,
            reserved_bytes,
        })
    }

    const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    const fn base(&self) -> GcHeapAddress {
        self.base
    }

    const fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    fn destination_bytes(&self) -> &[u8] {
        &self.bytes[self.base_offset..self.base_offset + self.reserved_bytes]
    }

    fn destination_slice_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        let start = self.base_offset + start;
        let end = self.base_offset + end;
        &mut self.bytes[start..end]
    }
}

fn required_alignment(
    placement_plan: &MinorGcDestinationPlacementPlan,
    generation: HeapGeneration,
) -> usize {
    placement_plan
        .placements()
        .iter()
        .filter(|placement| placement.destination_generation() == generation)
        .map(|placement| placement.align())
        .max()
        .unwrap_or(MIN_DESTINATION_ALIGNMENT)
        .max(MIN_DESTINATION_ALIGNMENT)
}

fn destination_storage_len(
    reserved_bytes: usize,
    required_alignment: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    let addressable_bytes = reserved_bytes.max(1);
    let alignment_slack = required_alignment - 1;
    addressable_bytes
        .checked_add(alignment_slack)
        .ok_or(GenerationalGcError::MinorGcDestinationStorageBytesOverflow { generation })
}

fn align_destination_base(
    address_bits: usize,
    required_alignment: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    let alignment_mask = required_alignment - 1;
    address_bits
        .checked_add(alignment_mask)
        .map(|address| address & !alignment_mask)
        .ok_or(
            GenerationalGcError::MinorGcDestinationStorageBaseAddressOverflow {
                generation,
                address_bits,
                align: required_alignment,
            },
        )
}

fn destination_range_out_of_bounds(
    storage: &GenerationDestinationStorage,
    copy: MinorGcObjectCopy,
) -> GenerationalGcError {
    GenerationalGcError::MinorGcDestinationStorageRangeOutOfBounds {
        generation: storage.generation(),
        base: storage.base(),
        destination: copy.destination(),
        size_bytes: copy.size_bytes(),
        reserved_bytes: storage.reserved_bytes(),
    }
}

#[cfg(test)]
mod tests;
