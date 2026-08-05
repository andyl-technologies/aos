//! Minor-GC plan validation and derivation helpers: the validate_* rules a
//! commit enforces before any byte moves, plus the frontier/survivor
//! derivation helpers they share.
//!
//! Moved verbatim from `heap/gc.rs` under the RFC-0007 §2 file-size cap; the
//! parent re-exports every public path.

//! Every helper is `pub(super)`: the commit pipeline (a sibling module)
//! resolves them through the parent's glob import, matching the pre-split
//! same-file visibility.

use super::*;

pub(super) fn validate_unique_nursery_objects(
    nursery_objects: &[NurseryObjectAge],
) -> Result<(), GenerationalGcError> {
    for (index, object) in nursery_objects.iter().enumerate() {
        if nursery_objects[index + 1..]
            .iter()
            .any(|other| other.address == object.address)
        {
            return Err(GenerationalGcError::DuplicateNurseryObjectAge {
                address: object.address,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_unique_nursery_fields(
    nursery_fields: &[NurseryObjectFields<'_>],
) -> Result<(), GenerationalGcError> {
    for (index, object) in nursery_fields.iter().enumerate() {
        if nursery_fields[index + 1..]
            .iter()
            .any(|other| other.address == object.address)
        {
            return Err(GenerationalGcError::DuplicateNurseryObjectFields {
                address: object.address,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_unique_nursery_layouts(
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for (index, object) in nursery_layouts.iter().enumerate() {
        if nursery_layouts[index + 1..]
            .iter()
            .any(|other| other.address == object.address)
        {
            return Err(GenerationalGcError::DuplicateNurseryObjectLayout {
                address: object.address,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_nursery_layout_values(
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for layout in nursery_layouts {
        if layout.size_bytes == 0 {
            return Err(GenerationalGcError::InvalidNurseryObjectSize {
                address: layout.address,
                size_bytes: layout.size_bytes,
            });
        }
        if layout.align == 0 || !layout.align.is_power_of_two() {
            return Err(GenerationalGcError::InvalidNurseryObjectAlignment {
                address: layout.address,
                align: layout.align,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_nursery_layout_sources_are_live(
    plan: &MinorGcPlan,
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for layout in nursery_layouts {
        if !plan
            .survivors()
            .iter()
            .any(|survivor| survivor.address() == layout.address)
        {
            return Err(GenerationalGcError::StaleNurseryObjectLayout {
                address: layout.address,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_unique_relocation_sources(
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for (index, destination) in destinations.iter().enumerate() {
        if destinations[index + 1..]
            .iter()
            .any(|other| other.source == destination.source)
        {
            return Err(GenerationalGcError::DuplicateMinorGcRelocationSource {
                address: destination.source,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_unique_relocation_destinations(
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for (index, destination) in destinations.iter().enumerate() {
        if destinations[index + 1..]
            .iter()
            .any(|other| other.destination == destination.destination)
        {
            return Err(GenerationalGcError::DuplicateMinorGcRelocationDestination {
                address: destination.destination,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_relocation_sources_are_live(
    plan: &MinorGcPlan,
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for destination in destinations {
        if !plan
            .survivors()
            .iter()
            .any(|survivor| survivor.address() == destination.source)
        {
            return Err(GenerationalGcError::StaleMinorGcRelocationSource {
                address: destination.source,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_relocation_destinations_are_not_sources(
    plan: &MinorGcPlan,
    destinations: &[MinorGcRelocationDestination],
) -> Result<(), GenerationalGcError> {
    for destination in destinations {
        if plan
            .survivors()
            .iter()
            .any(|survivor| survivor.address() == destination.destination)
        {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationInFromSpace {
                    from: destination.source,
                    destination: destination.destination,
                },
            );
        }
    }
    Ok(())
}

pub(super) fn validate_placement_plan_matches_survivor_plan(
    survivor_plan: &MinorGcPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<(), GenerationalGcError> {
    let survivors = survivor_plan.survivors();
    let placements = placement_plan.placements();
    if survivors.len() != placements.len() {
        return Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementLengthMismatch {
                survivors: survivors.len(),
                placements: placements.len(),
            },
        );
    }

    for (survivor, placement) in survivors.iter().zip(placements) {
        if survivor.address() != placement.source() {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationPlacementSourceMismatch {
                    expected: survivor.address(),
                    actual: placement.source(),
                },
            );
        }
        if survivor.action() != placement.action() {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationPlacementActionMismatch {
                    address: survivor.address(),
                    expected: survivor.action(),
                    actual: placement.action(),
                },
            );
        }
    }

    Ok(())
}

pub(super) fn validate_nursery_layout_sources_are_relocated(
    relocation_plan: &MinorGcRelocationPlan,
    nursery_layouts: &[NurseryObjectLayout],
) -> Result<(), GenerationalGcError> {
    for layout in nursery_layouts {
        if !relocation_plan
            .relocations()
            .iter()
            .any(|relocation| relocation.source() == layout.address)
        {
            return Err(GenerationalGcError::StaleNurseryObjectLayout {
                address: layout.address,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_relocation_destination_alignment(
    relocation: MinorGcRelocation,
    layout: NurseryObjectLayout,
) -> Result<(), GenerationalGcError> {
    if relocation.destination().address_bits() & (layout.align() - 1) != 0 {
        return Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: relocation.source(),
                generation: relocation.destination_generation(),
                destination: relocation.destination(),
                align: layout.align(),
            },
        );
    }
    Ok(())
}

pub(super) fn validate_object_copy_destination_ranges_are_disjoint(
    copies: &[MinorGcObjectCopy],
) -> Result<(), GenerationalGcError> {
    for (index, copy) in copies.iter().enumerate() {
        let copy_end = object_copy_destination_end(*copy)?;
        for other in &copies[index + 1..] {
            let other_end = object_copy_destination_end(*other)?;
            if copy.destination().address_bits() < other_end
                && other.destination().address_bits() < copy_end
            {
                return Err(
                    GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                        first_generation: copy.destination_generation(),
                        first: copy.destination(),
                        second_generation: other.destination_generation(),
                        second: other.destination(),
                    },
                );
            }
        }
    }
    Ok(())
}

pub(super) fn validate_object_copy_destinations_do_not_overlap_sources(
    copies: &[MinorGcObjectCopy],
) -> Result<(), GenerationalGcError> {
    for destination_copy in copies {
        let destination_end = object_copy_destination_end(*destination_copy)?;
        for source_copy in copies {
            let source_end = object_copy_source_end(*source_copy)?;
            if destination_copy.destination().address_bits() < source_end
                && source_copy.source().address_bits() < destination_end
            {
                return Err(
                    GenerationalGcError::MinorGcObjectCopyDestinationSourceRangeOverlap {
                        source_address: source_copy.source(),
                        destination: destination_copy.destination(),
                    },
                );
            }
        }
    }
    Ok(())
}

pub(super) fn object_copy_destination_end(
    copy: MinorGcObjectCopy,
) -> Result<usize, GenerationalGcError> {
    copy.destination()
        .address_bits()
        .checked_add(copy.size_bytes())
        .ok_or(
            GenerationalGcError::MinorGcObjectCopyDestinationAddressOverflow {
                generation: copy.destination_generation(),
                destination: copy.destination(),
                size_bytes: copy.size_bytes(),
            },
        )
}

pub(super) fn object_copy_source_end(
    copy: MinorGcObjectCopy,
) -> Result<usize, GenerationalGcError> {
    copy.source()
        .address_bits()
        .checked_add(copy.size_bytes())
        .ok_or(
            GenerationalGcError::MinorGcObjectCopySourceAddressOverflow {
                address: copy.source(),
                size_bytes: copy.size_bytes(),
            },
        )
}

pub(super) fn validate_object_byte_copy_buffers_match_plan(
    plan: &MinorGcObjectCopyPlan,
    buffers: &[MinorGcObjectByteCopyBuffer<'_>],
) -> Result<(), GenerationalGcError> {
    if plan.len() != buffers.len() {
        return Err(
            GenerationalGcError::MinorGcObjectByteCopyBufferLengthMismatch {
                copies: plan.len(),
                buffers: buffers.len(),
            },
        );
    }

    for (index, (copy, buffer)) in plan.copies().iter().zip(buffers).enumerate() {
        if copy.source() != buffer.source() {
            return Err(GenerationalGcError::MinorGcObjectByteCopySourceMismatch {
                index,
                expected: copy.source(),
                actual: buffer.source(),
            });
        }
        if copy.destination() != buffer.destination() {
            return Err(
                GenerationalGcError::MinorGcObjectByteCopyDestinationMismatch {
                    index,
                    expected: copy.destination(),
                    actual: buffer.destination(),
                },
            );
        }
        if copy.size_bytes() != buffer.source_bytes().len() {
            return Err(
                GenerationalGcError::MinorGcObjectByteCopySourceLengthMismatch {
                    index,
                    address: copy.source(),
                    expected: copy.size_bytes(),
                    actual: buffer.source_bytes().len(),
                },
            );
        }
        if copy.size_bytes() != buffer.destination_bytes().len() {
            return Err(
                GenerationalGcError::MinorGcObjectByteCopyDestinationLengthMismatch {
                    index,
                    address: copy.destination(),
                    expected: copy.size_bytes(),
                    actual: buffer.destination_bytes().len(),
                },
            );
        }
    }

    Ok(())
}

pub(super) fn validate_forwarding_slots_match_plan(
    plan: &MinorGcForwardingPointerPlan,
    slots: &[MinorGcForwardingSlot],
) -> Result<(), GenerationalGcError> {
    if plan.len() != slots.len() {
        return Err(
            GenerationalGcError::MinorGcForwardingPointerSlotLengthMismatch {
                pointers: plan.len(),
                slots: slots.len(),
            },
        );
    }

    for (index, (pointer, slot)) in plan.pointers().iter().zip(slots).enumerate() {
        if pointer.source() != slot.source() {
            return Err(
                GenerationalGcError::MinorGcForwardingPointerSlotSourceMismatch {
                    index,
                    expected: pointer.source(),
                    actual: slot.source(),
                },
            );
        }
        if let Some(actual) = slot.forwarded_value() {
            return Err(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
                index,
                address: slot.source(),
                actual,
            });
        }
    }

    Ok(())
}

pub(super) fn validate_reference_rewrite_slots_match_plan(
    plan: &MinorGcReferenceRewritePlan,
    references: &[ResolvedValueGeneration],
) -> Result<(), GenerationalGcError> {
    for rewrite in plan.rewrites() {
        validate_reference_rewrite_slot(*rewrite, references)?;
    }
    Ok(())
}

pub(super) fn validate_reference_rewrite_commit_slots_match_plan(
    plan: &MinorGcReferenceRewritePlan,
    references: &[ResolvedValueGeneration],
) -> Result<(), GenerationalGcError> {
    validate_reference_rewrite_slots_match_plan(plan, references)?;
    for (slot, reference) in references.iter().copied().enumerate() {
        if let ResolvedValueGeneration::Heap {
            address,
            generation: HeapGeneration::Young,
        } = reference
        {
            let planned = plan.rewrites().iter().any(|rewrite| rewrite.slot() == slot);
            if !planned {
                return Err(
                    GenerationalGcError::MinorGcReferenceRewriteUnplannedYoungSlot {
                        slot,
                        address,
                    },
                );
            }
        }
    }
    Ok(())
}

pub(super) fn copy_object_byte_buffers(buffers: &mut [MinorGcObjectByteCopyBuffer<'_>]) {
    for buffer in buffers {
        buffer
            .destination_bytes
            .copy_from_slice(buffer.source_bytes);
    }
}

pub(super) fn install_forwarding_slots(
    plan: &MinorGcForwardingPointerPlan,
    slots: &mut [MinorGcForwardingSlot],
) {
    for (pointer, slot) in plan.pointers.iter().zip(slots) {
        slot.forwarded = Some(pointer.forwarded_value());
    }
}

pub(super) fn apply_reference_rewrites(
    plan: &MinorGcReferenceRewritePlan,
    references: &mut [ResolvedValueGeneration],
) {
    for rewrite in plan.rewrites() {
        references[rewrite.slot()] = rewrite.replacement();
    }
}

pub(super) fn validate_forwarding_plan_matches_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    forwarding_pointers: &MinorGcForwardingPointerPlan,
) -> Result<(), GenerationalGcError> {
    if object_copies.len() != forwarding_pointers.len() {
        return Err(
            GenerationalGcError::MinorGcCommitForwardingPointerLengthMismatch {
                copies: object_copies.len(),
                pointers: forwarding_pointers.len(),
            },
        );
    }

    for (index, (copy, pointer)) in object_copies
        .copies()
        .iter()
        .zip(forwarding_pointers.pointers())
        .enumerate()
    {
        let expected = MinorGcForwardingPointer { copy: *copy };
        if *pointer != expected {
            return Err(
                GenerationalGcError::MinorGcCommitForwardingPointerMismatch {
                    index,
                    expected,
                    actual: *pointer,
                },
            );
        }
    }

    Ok(())
}

pub(super) fn validate_reference_rewrites_match_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    reference_rewrites: &MinorGcReferenceRewritePlan,
) -> Result<(), GenerationalGcError> {
    for rewrite in reference_rewrites.rewrites() {
        let copy = object_copy_for(object_copies, rewrite.source()).ok_or(
            GenerationalGcError::MinorGcCommitReferenceRewriteSourceMissing {
                address: rewrite.source(),
            },
        )?;
        let expected = copy.relocated_value();
        let actual = rewrite.replacement();
        if actual != expected {
            return Err(GenerationalGcError::MinorGcCommitReferenceRewriteMismatch {
                slot: rewrite.slot(),
                address: rewrite.source(),
                expected,
                actual,
            });
        }
    }

    Ok(())
}

pub(super) fn validate_remembered_set_refresh_matches_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    remembered_set_refresh: &MinorGcRememberedSetRefreshPlan,
) -> Result<(), GenerationalGcError> {
    for refresh in remembered_set_refresh.refreshes() {
        let expected = expected_remembered_edge_action(object_copies, refresh.original());
        let actual = refresh.action();
        if actual != expected {
            return Err(
                GenerationalGcError::MinorGcCommitRememberedSetRefreshMismatch {
                    original: refresh.original(),
                    expected,
                    actual,
                },
            );
        }
    }

    Ok(())
}

pub(super) fn validate_old_field_rescan_matches_object_copies(
    object_copies: &MinorGcObjectCopyPlan,
    old_field_rescan: &MinorGcOldFieldRescanPlan,
) -> Result<(), GenerationalGcError> {
    for rescan in old_field_rescan.rescans() {
        let expected = expected_remembered_edge_action(object_copies, rescan.original());
        let actual = rescan.action();
        if actual != expected {
            return Err(GenerationalGcError::MinorGcCommitOldFieldRescanMismatch {
                original: rescan.original(),
                expected,
                actual,
            });
        }
    }

    Ok(())
}

pub(super) fn validate_remembered_set_publication_source(
    expected: &MinorGcRememberedSetRefreshPlan,
    actual: &RememberedSet,
) -> Result<(), GenerationalGcError> {
    if actual.epoch() != expected.source_epoch() {
        return Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationEpochMismatch {
                expected: expected.source_epoch(),
                actual: actual.epoch(),
            },
        );
    }
    if actual.len() != expected.len() {
        return Err(
            GenerationalGcError::MinorGcCommitRememberedSetPublicationLengthMismatch {
                expected: expected.len(),
                actual: actual.len(),
            },
        );
    }
    for (index, (actual, expected)) in actual.edges().iter().zip(expected.refreshes()).enumerate() {
        let expected = expected.original();
        if *actual != expected {
            return Err(
                GenerationalGcError::MinorGcCommitRememberedSetPublicationEdgeMismatch {
                    index,
                    expected,
                    actual: *actual,
                },
            );
        }
    }
    Ok(())
}

pub(super) fn expected_remembered_edge_action(
    object_copies: &MinorGcObjectCopyPlan,
    original: RememberedEdge,
) -> MinorGcRememberedSetRefreshAction {
    match object_copy_for(object_copies, original.target()) {
        Some(copy) if copy.action() == MinorGcSurvivorAction::CopyToNursery => {
            MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                refreshed: RememberedEdge::new(original.source(), copy.destination()),
            }
        }
        Some(copy) => MinorGcRememberedSetRefreshAction::DropPromoted {
            destination: copy.destination(),
        },
        None => MinorGcRememberedSetRefreshAction::DropDead,
    }
}

pub(super) fn object_copy_for(
    object_copies: &MinorGcObjectCopyPlan,
    address: GcHeapAddress,
) -> Option<MinorGcObjectCopy> {
    object_copies
        .copies()
        .iter()
        .copied()
        .find(|copy| copy.source() == address)
}

pub(super) fn nursery_age_for(
    nursery_objects: &[NurseryObjectAge],
    address: GcHeapAddress,
) -> Result<NurseryObjectAge, GenerationalGcError> {
    nursery_objects
        .iter()
        .copied()
        .find(|object| object.address == address)
        .ok_or(GenerationalGcError::MissingNurseryObjectAge { address })
}

pub(super) fn nursery_layout_for(
    nursery_layouts: &[NurseryObjectLayout],
    address: GcHeapAddress,
) -> Result<NurseryObjectLayout, GenerationalGcError> {
    nursery_layouts
        .iter()
        .copied()
        .find(|object| object.address == address)
        .ok_or(GenerationalGcError::MissingNurseryObjectLayout { address })
}

pub(super) fn checked_add_destination_bytes(
    current: usize,
    size_bytes: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    current
        .checked_add(size_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationBytesOverflow { generation })
}

pub(super) fn checked_add_destination_total_bytes(
    nursery_bytes: usize,
    old_bytes: usize,
) -> Result<usize, GenerationalGcError> {
    nursery_bytes
        .checked_add(old_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationTotalBytesOverflow)
}

pub(super) fn align_destination_offset(
    offset: usize,
    align: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(
            GenerationalGcError::InvalidMinorGcDestinationPlacementAlignment { generation, align },
        );
    }
    let mask = align - 1;
    offset
        .checked_add(mask)
        .map(|offset| offset & !mask)
        .ok_or(GenerationalGcError::MinorGcDestinationPlacementBytesOverflow { generation })
}

pub(super) fn checked_add_destination_placement_bytes(
    offset: usize,
    size_bytes: usize,
    generation: HeapGeneration,
) -> Result<usize, GenerationalGcError> {
    offset
        .checked_add(size_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationPlacementBytesOverflow { generation })
}

pub(super) fn checked_add_destination_placement_total_bytes(
    nursery_reserved_bytes: usize,
    old_reserved_bytes: usize,
) -> Result<usize, GenerationalGcError> {
    nursery_reserved_bytes
        .checked_add(old_reserved_bytes)
        .ok_or(GenerationalGcError::MinorGcDestinationPlacementTotalBytesOverflow)
}

pub(super) fn materialized_destination_for(
    placement: MinorGcDestinationPlacement,
    bases: MinorGcDestinationBases,
) -> Result<GcHeapAddress, GenerationalGcError> {
    let (generation, base) = match placement.action() {
        MinorGcSurvivorAction::CopyToNursery => (HeapGeneration::Young, bases.nursery()),
        MinorGcSurvivorAction::PromoteToOld => (HeapGeneration::Old, bases.old()),
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
    let destination = GcHeapAddress::new(address_bits)?;
    validate_materialized_destination_alignment(placement, generation, destination)?;
    Ok(destination)
}

pub(super) fn validate_materialized_destination_alignment(
    placement: MinorGcDestinationPlacement,
    generation: HeapGeneration,
    destination: GcHeapAddress,
) -> Result<(), GenerationalGcError> {
    let align = placement.align();
    if align == 0 || !align.is_power_of_two() {
        return Err(
            GenerationalGcError::InvalidMinorGcDestinationPlacementAlignment { generation, align },
        );
    }
    if destination.address_bits() & (align - 1) != 0 {
        return Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: placement.source(),
                generation,
                destination,
                align,
            },
        );
    }
    Ok(())
}

pub(super) fn relocation_destination_for(
    destinations: &[MinorGcRelocationDestination],
    address: GcHeapAddress,
) -> Result<MinorGcRelocationDestination, GenerationalGcError> {
    destinations
        .iter()
        .copied()
        .find(|destination| destination.source == address)
        .ok_or(GenerationalGcError::MissingMinorGcRelocationDestination { address })
}

pub(super) fn relocation_for(
    relocation_plan: &MinorGcRelocationPlan,
    address: GcHeapAddress,
) -> Result<MinorGcRelocation, GenerationalGcError> {
    optional_relocation_for(relocation_plan, address)
        .ok_or(GenerationalGcError::MissingMinorGcReferenceRelocation { address })
}

pub(super) fn optional_relocation_for(
    relocation_plan: &MinorGcRelocationPlan,
    address: GcHeapAddress,
) -> Option<MinorGcRelocation> {
    relocation_plan
        .relocations()
        .iter()
        .copied()
        .find(|relocation| relocation.source() == address)
}

pub(super) fn validate_reference_rewrite_slot(
    rewrite: MinorGcReferenceRewrite,
    references: &[ResolvedValueGeneration],
) -> Result<(), GenerationalGcError> {
    let actual = references.get(rewrite.slot()).copied().ok_or(
        GenerationalGcError::MinorGcReferenceRewriteSlotOutOfBounds {
            slot: rewrite.slot(),
            slots: references.len(),
        },
    )?;
    let expected = ResolvedValueGeneration::young(rewrite.source());
    if actual != expected {
        return Err(GenerationalGcError::MinorGcReferenceRewriteSlotMismatch {
            slot: rewrite.slot(),
            expected: rewrite.source(),
            actual,
        });
    }
    Ok(())
}

pub(super) fn remembered_set_refresh_action(
    edge: RememberedEdge,
    relocation_plan: &MinorGcRelocationPlan,
) -> MinorGcRememberedSetRefreshAction {
    match optional_relocation_for(relocation_plan, edge.target()) {
        Some(relocation) if relocation.action() == MinorGcSurvivorAction::CopyToNursery => {
            MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
                refreshed: RememberedEdge::new(edge.source(), relocation.destination()),
            }
        }
        Some(relocation) => MinorGcRememberedSetRefreshAction::DropPromoted {
            destination: relocation.destination(),
        },
        None => MinorGcRememberedSetRefreshAction::DropDead,
    }
}

pub(super) fn nursery_fields_for<'a>(
    nursery_fields: &'a [NurseryObjectFields<'a>],
    address: GcHeapAddress,
) -> Result<&'a [ResolvedValueGeneration], GenerationalGcError> {
    nursery_fields
        .iter()
        .copied()
        .find(|object| object.address == address)
        .map(NurseryObjectFields::fields)
        .ok_or(GenerationalGcError::MissingNurseryObjectFields { address })
}

pub(super) fn expand_young_fields(
    frontier: &mut MinorGcFrontier,
    nursery_fields: &[NurseryObjectFields<'_>],
) -> Result<(), GenerationalGcError> {
    let mut index = 0usize;
    while let Some(address) = frontier.addresses.get(index).copied() {
        for field in nursery_fields_for(nursery_fields, address)? {
            if let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = *field
            {
                frontier.insert(address)?;
            }
        }
        index += 1;
    }
    Ok(())
}

pub(super) fn survivors_from_frontier(
    frontier: MinorGcFrontier,
    nursery_objects: &[NurseryObjectAge],
    promotion_policy: MinorGcPromotionPolicy,
) -> Result<MinorGcPlan, GenerationalGcError> {
    let mut survivors = Vec::new();
    for address in frontier.addresses {
        let age = nursery_age_for(nursery_objects, address)?;
        let next_survivals = age.survived_minor_collections.saturating_add(1);
        let action = promotion_policy.action_for_survivor(next_survivals);
        let survivors_len = survivors
            .len()
            .checked_add(1)
            .ok_or(GenerationalGcError::MinorGcSurvivorLengthOverflow)?;
        survivors.try_reserve_exact(1).map_err(|_| {
            GenerationalGcError::MinorGcSurvivorAllocationFailed {
                survivors: survivors_len,
            }
        })?;
        survivors.push(MinorGcSurvivor {
            address,
            previous_survivals: age.survived_minor_collections,
            next_survivals,
            action,
        });
    }

    Ok(MinorGcPlan { survivors })
}
