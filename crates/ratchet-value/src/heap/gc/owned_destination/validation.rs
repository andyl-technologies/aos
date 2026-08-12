//! Validation helpers for owned minor-GC destination storage.

use super::{MinorGcOwnedDestinationStorage, MinorGcSourceObjectBytes};
use crate::heap::gc::{
    GcHeapAddress, GenerationalGcError, HeapGeneration, MinorGcDestinationPlacement,
    MinorGcObjectCopy, MinorGcObjectCopyPlan, MinorGcSurvivorAction,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DestinationRange {
    pub(super) generation: HeapGeneration,
    pub(super) start: usize,
    pub(super) end: usize,
}

impl DestinationRange {
    fn overlaps(self, other: Self) -> bool {
        self.generation == other.generation && self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ValidatedDestinationCopy<'a> {
    pub(super) copy: MinorGcObjectCopy,
    pub(super) source_bytes: &'a [u8],
    pub(super) range: DestinationRange,
}

pub(super) fn validated_copies<'a>(
    storage: &MinorGcOwnedDestinationStorage,
    copy_plan: &MinorGcObjectCopyPlan,
    sources: &'a [MinorGcSourceObjectBytes<'a>],
) -> Result<Vec<ValidatedDestinationCopy<'a>>, GenerationalGcError> {
    validate_copy_plan_matches_storage(storage, copy_plan)?;
    if copy_plan.len() != sources.len() {
        return Err(GenerationalGcError::MinorGcSourceObjectBytesCountMismatch {
            copies: copy_plan.len(),
            sources: sources.len(),
        });
    }

    let mut validated = Vec::new();
    validated.try_reserve_exact(copy_plan.len()).map_err(|_| {
        GenerationalGcError::MinorGcDestinationStorageCopyPlanAllocationFailed {
            copies: copy_plan.len(),
        }
    })?;
    for (index, (copy, source)) in copy_plan.copies().iter().zip(sources).enumerate() {
        if copy.source() != source.source() {
            return Err(
                GenerationalGcError::MinorGcSourceObjectBytesSourceMismatch {
                    index,
                    expected: copy.source(),
                    actual: source.source(),
                },
            );
        }
        if copy.size_bytes() != source.bytes().len() {
            return Err(
                GenerationalGcError::MinorGcSourceObjectBytesLengthMismatch {
                    index,
                    address: copy.source(),
                    expected: copy.size_bytes(),
                    actual: source.bytes().len(),
                },
            );
        }
        validated.push(ValidatedDestinationCopy {
            copy: *copy,
            source_bytes: source.bytes(),
            range: storage.destination_range_for(*copy)?,
        });
    }
    validate_destination_ranges_do_not_overlap(&validated)?;
    Ok(validated)
}

fn validate_copy_plan_matches_storage(
    storage: &MinorGcOwnedDestinationStorage,
    copy_plan: &MinorGcObjectCopyPlan,
) -> Result<(), GenerationalGcError> {
    let placements = storage.placement_plan().placements();
    if placements.len() != copy_plan.len() {
        return Err(
            GenerationalGcError::MinorGcDestinationStorageCopyPlanLengthMismatch {
                placements: placements.len(),
                copies: copy_plan.len(),
            },
        );
    }

    for (index, (placement, copy)) in placements.iter().zip(copy_plan.copies()).enumerate() {
        validate_copy_matches_placement(storage, index, *placement, *copy)?;
    }
    Ok(())
}

fn validate_copy_matches_placement(
    storage: &MinorGcOwnedDestinationStorage,
    index: usize,
    placement: MinorGcDestinationPlacement,
    copy: MinorGcObjectCopy,
) -> Result<(), GenerationalGcError> {
    if placement.source() != copy.source() {
        return Err(
            GenerationalGcError::MinorGcDestinationStorageCopySourceMismatch {
                index,
                expected: placement.source(),
                actual: copy.source(),
            },
        );
    }
    if placement.action() != copy.action() {
        return Err(
            GenerationalGcError::MinorGcDestinationStorageCopyActionMismatch {
                address: placement.source(),
                expected: placement.action(),
                actual: copy.action(),
            },
        );
    }
    let expected_destination = destination_for_placement(storage, placement)?;
    if expected_destination != copy.destination() {
        return Err(
            GenerationalGcError::MinorGcDestinationStorageCopyDestinationMismatch {
                address: placement.source(),
                expected: expected_destination,
                actual: copy.destination(),
            },
        );
    }
    if placement.size_bytes() != copy.size_bytes() {
        return Err(
            GenerationalGcError::MinorGcDestinationStorageCopySizeMismatch {
                address: placement.source(),
                expected: placement.size_bytes(),
                actual: copy.size_bytes(),
            },
        );
    }
    if placement.align() != copy.align() {
        return Err(
            GenerationalGcError::MinorGcDestinationStorageCopyAlignmentMismatch {
                address: placement.source(),
                expected: placement.align(),
                actual: copy.align(),
            },
        );
    }
    Ok(())
}

fn destination_for_placement(
    storage: &MinorGcOwnedDestinationStorage,
    placement: MinorGcDestinationPlacement,
) -> Result<GcHeapAddress, GenerationalGcError> {
    let (generation, base) = match placement.action() {
        MinorGcSurvivorAction::CopyToNursery => {
            (HeapGeneration::Young, storage.destination_bases().nursery())
        }
        MinorGcSurvivorAction::PromoteToOld => {
            (HeapGeneration::Old, storage.destination_bases().old())
        }
    };
    let address_bits = base
        .address_bits()
        .checked_add(placement.offset_bytes())
        .ok_or(
            GenerationalGcError::MinorGcRelocationDestinationAddressOverflow {
                generation,
                base,
                offset: placement.offset_bytes(),
            },
        )?;
    GcHeapAddress::new(address_bits)
}

fn validate_destination_ranges_do_not_overlap(
    copies: &[ValidatedDestinationCopy<'_>],
) -> Result<(), GenerationalGcError> {
    for (index, copy) in copies.iter().enumerate() {
        for other in &copies[index + 1..] {
            if copy.range.overlaps(other.range) {
                return Err(GenerationalGcError::MinorGcDestinationStorageRangeOverlap {
                    generation: copy.range.generation,
                    first: copy.copy.destination(),
                    second: other.copy.destination(),
                });
            }
        }
    }
    Ok(())
}
